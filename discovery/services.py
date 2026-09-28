"""The discovery kind of remote operation: queue, read, recover and forget attempts.

Views call ``request_discovery`` to check a server again, and the removal page presents
``recorded_discovery``. ``servers.registration`` queues an attempt for a new alias with
``queue_discovery``, and calls ``forget_discovery`` when removing a server. The attempt's
lifecycle belongs to ``operations.lifecycle``, which claims it in the durable worker and
runs ``_discover``, the discovery step this module registers: it connects, collects and
publishes the snapshot. Remote access goes through ``discovery.ssh.connect_alias`` only.

The dashboard reads a server's discovery through ``read_discovery``, Activity through
``history`` and the server list through ``latest_attempt_statuses``. Every public entry
first recovers operations abandoned by a stopped worker, so no page shows an abandoned
attempt as queued or running and no abandoned attempt keeps its server busy. No other
module reads attempts or their snapshots through a server's related names.
"""

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import NamedTuple

from django.db import transaction
from django.db.models import OuterRef, QuerySet, Subquery
from django.utils import timezone

from operations import lifecycle
from operations.lifecycle import OperationBusy, recovers_first
from operations.models import RemoteOperation
from servers.models import Server

from . import ssh
from .models import DiscoveryAttempt
from .observations import collect
from .snapshot import (
    AttemptSnapshot,
    Snapshot,
    attempt_snapshots,
    has_snapshot,
    save_snapshot,
)

logger = logging.getLogger(__name__)

UNEXPECTED_FAILURE = (
    "Discovery stopped because of an unexpected error. Barectl did not record the error "
    "details, which could include remote output. The worker log names the error type."
)
INTERRUPTED_FAILURE = (
    "The discovery worker stopped before finishing this attempt. Barectl kept the previous "
    "snapshot, if any. Retry to run discovery again."
)
# Remote work is bounded: connecting by the ssh.CONNECT_TIMEOUT limits on each of its
# steps, and every command on the connection by ssh.SESSION_TIMEOUT. An attempt still
# active after this long was abandoned by its worker.
STALE_AFTER = timedelta(minutes=10)


class DiscoveryBusy(Exception):
    """The server already has an active remote operation, kept as ``operation``.

    The operation may be a discovery attempt or another kind, such as a plan preparation.
    """

    def __init__(self, operation: RemoteOperation) -> None:
        super().__init__()
        self.operation = operation


class ServerDiscovery(NamedTuple):
    """A server's discovery as its page reads it, after recovering abandoned operations."""

    # The latest attempt, or ``None`` before the first one was queued.
    attempt: DiscoveryAttempt | None
    # The snapshot the latest successful attempt published, whatever became of later ones.
    snapshot: Snapshot | None
    # Every recorded attempt, newest recorded first, with the snapshot it published.
    history: list[AttemptSnapshot]
    # The server's active remote operation of any kind, which blocks a new attempt.
    active: RemoteOperation | None


@recovers_first
def read_discovery(server: Server) -> ServerDiscovery:
    """The server's latest attempt, current snapshot and history in one recovered read."""
    recorded = _attempt_snapshots(server)
    # Only the latest successful attempt keeps its snapshot, so it is the current one.
    snapshot = next((published for _, published in recorded if published), None)
    return ServerDiscovery(
        recorded[0].attempt if recorded else None,
        snapshot,
        recorded,
        lifecycle.active_operation(server),
    )


@recovers_first
def latest_attempt_statuses(servers: QuerySet[Server]) -> list[tuple[Server, str | None]]:
    """Each of ``servers`` with its latest attempt's status, or None, in one query.

    Abandoned operations are recovered first.
    """
    latest = DiscoveryAttempt.objects.filter(server=OuterRef("pk")).values("status")[:1]
    return [
        (server, server.attempt_status)
        for server in servers.annotate(attempt_status=Subquery(latest))
    ]


@recovers_first
def history() -> list[AttemptSnapshot]:
    """Every server's recorded attempts for Activity, newest recorded first.

    Each comes with the snapshot it published. Abandoned operations are recovered first.
    """
    return _attempt_snapshots(None)


def _attempt_snapshots(server: Server | None) -> list[AttemptSnapshot]:
    """Recorded attempts, every server's or only ``server``'s, with their snapshots."""
    attempts = DiscoveryAttempt.objects.select_related("server")
    return attempt_snapshots(attempts if server is None else attempts.filter(server=server))


@recovers_first
def queue_discovery(server: Server) -> DiscoveryAttempt:
    """Queue verification and discovery; raise ``DiscoveryBusy`` if an operation is active.

    The database allows one queued, running or reconciling remote operation per server,
    so concurrent requests cannot both succeed. Stale operations that would otherwise
    block the server are recovered first. Raises ``Server.DoesNotExist`` when a concurrent
    request removed the server.
    """
    try:
        return lifecycle.queue(DiscoveryAttempt, server)
    except OperationBusy as busy:
        raise DiscoveryBusy(busy.operation) from None


def request_discovery(server: Server) -> RemoteOperation:
    """Queue refresh, retry or verification, or return the server's active operation.

    The active operation is the server's attempt when it is one. Recovers abandoned
    operations first through ``queue_discovery``. Raises ``Server.DoesNotExist`` when a
    concurrent request removed the server.
    """
    try:
        return queue_discovery(server)
    except DiscoveryBusy as busy:
        active = DiscoveryAttempt.objects.filter(pk=busy.operation.pk).first()
        return active or busy.operation


@dataclass(frozen=True)
class RecordedDiscovery:
    """A server's recorded discovery: what ``forget_discovery`` deletes, and what keeps it."""

    # An active remote operation of any kind protects the server, and is not forgotten.
    active: bool
    attempt_count: int
    has_snapshot: bool


@recovers_first
def recorded_discovery(server: Server) -> RecordedDiscovery:
    """The server's recorded discovery, after recovering abandoned operations."""
    return RecordedDiscovery(
        active=lifecycle.active_operation(server) is not None,
        attempt_count=DiscoveryAttempt.objects.filter(server=server).count(),
        has_snapshot=has_snapshot(server),
    )


@recovers_first
def forget_discovery(server: Server) -> None:
    """Delete the server's finished attempts, their snapshots and the worker's task records.

    Call inside the transaction that deletes the server. Abandoned attempts are recovered
    first, so they are forgotten too. Active attempts are kept: each protects its server,
    so the database refuses to delete the server while one remains.
    """
    lifecycle.forget(
        RemoteOperation.objects.filter(server=server, kind=RemoteOperation.Kind.DISCOVERY)
    )


def _discover(attempt: DiscoveryAttempt) -> None:
    """Connect, collect a snapshot, and publish it as the attempt succeeds."""
    with ssh.connect_alias(attempt.ssh_alias) as shell:
        collected = collect(shell)
        host_key = shell.host_key
    now = timezone.now()
    # Publish the snapshot and the outcome together. A recovery that already marked this
    # attempt interrupted wins: a stale worker never creates a snapshot after recovery.
    with transaction.atomic():
        if not lifecycle.succeed(attempt.pk, now, host_key=host_key):
            return
        save_snapshot(attempt, collected, now)
    logger.info("Discovery attempt %s succeeded", attempt.pk)


lifecycle.register(
    DiscoveryAttempt,
    _discover,
    interrupted=INTERRUPTED_FAILURE,
    unexpected=UNEXPECTED_FAILURE,
    stale_after=STALE_AFTER,
)
