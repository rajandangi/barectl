"""The discovery kind of remote operation.

docs/adr/0004-serialize-remote-operations-in-one-table.md

Every public entry recovers abandoned operations first (docs/ssh-connections.md#workflow).
No other module reads attempts or their snapshots through a server's related names.
"""

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import NamedTuple

from django.contrib.auth.models import User
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
# docs/ssh-connections.md#bounds-and-read-only-commands
STALE_AFTER = timedelta(minutes=10)


class DiscoveryBusy(Exception):
    """``operation`` is the server's active remote operation, of any kind."""

    def __init__(self, operation: RemoteOperation) -> None:
        super().__init__()
        self.operation = operation


class ServerDiscovery(NamedTuple):
    attempt: DiscoveryAttempt | None
    # The snapshot the latest successful attempt published, whatever became of later ones.
    snapshot: Snapshot | None
    # Every recorded attempt, newest recorded first, with the snapshot it published.
    history: list[AttemptSnapshot]
    # The server's active remote operation of any kind, which blocks a new attempt.
    active: RemoteOperation | None


@recovers_first
def read_discovery(server: Server) -> ServerDiscovery:
    recorded = _attempt_snapshots(server)
    # Only the latest successful attempt keeps its snapshot, so it is the current one.
    snapshot = next(
        (
            published
            for attempt, published in recorded
            if published
            and (
                attempt.connection is None
                or attempt.connection.revision == server.connection_revision
            )
        ),
        None,
    )
    return ServerDiscovery(
        recorded[0].attempt if recorded else None,
        snapshot,
        recorded,
        lifecycle.active_operation(server),
    )


@recovers_first
def latest_attempt_statuses(servers: QuerySet[Server]) -> list[tuple[Server, str | None]]:
    """Each of ``servers`` with its latest attempt's status, or None, in one query."""
    latest = DiscoveryAttempt.objects.filter(server=OuterRef("pk")).values("status")[:1]
    return [
        (server, server.attempt_status)
        for server in servers.annotate(attempt_status=Subquery(latest))
    ]


@recovers_first
def history() -> list[AttemptSnapshot]:
    """Every server's recorded attempts, newest recorded first."""
    return _attempt_snapshots(None)


def _attempt_snapshots(server: Server | None) -> list[AttemptSnapshot]:
    attempts = DiscoveryAttempt.objects.select_related("server")
    return attempt_snapshots(attempts if server is None else attempts.filter(server=server))


@recovers_first
def queue_discovery(
    server: Server, *, user: User | None = None, authority: str = "discovery.add_discoveryattempt"
) -> DiscoveryAttempt:
    """Raise ``DiscoveryBusy`` while the server has an active remote operation.

    Raises ``Server.DoesNotExist`` when a concurrent request removed the server.
    """
    try:
        return lifecycle.queue(
            DiscoveryAttempt,
            server,
            requested_by=user,
            authority=authority if user is not None else "",
        )
    except OperationBusy as busy:
        raise DiscoveryBusy(busy.operation) from None


def request_discovery(server: Server, *, user: User | None = None) -> RemoteOperation:
    """Queue an attempt, or return the server's active operation: its attempt when it is one.

    Raises ``Server.DoesNotExist`` when a concurrent request removed the server.
    """
    try:
        return queue_discovery(server, user=user)
    except DiscoveryBusy as busy:
        active = DiscoveryAttempt.objects.filter(pk=busy.operation.pk).first()
        return active or busy.operation


@dataclass(frozen=True)
class RecordedDiscovery:
    # An active remote operation of any kind protects the server, and is not forgotten.
    active: bool
    attempt_count: int
    has_snapshot: bool


@recovers_first
def recorded_discovery(server: Server) -> RecordedDiscovery:
    return RecordedDiscovery(
        active=lifecycle.active_operation(server) is not None,
        attempt_count=DiscoveryAttempt.objects.filter(server=server).count(),
        has_snapshot=has_snapshot(server),
    )


@recovers_first
def forget_discovery(server: Server) -> None:
    """Delete the server's finished attempts, their snapshots and the worker's task records.

    Call inside the transaction that deletes the server. Active attempts are kept: each
    protects its server, so the database refuses to delete the server while one remains.
    """
    lifecycle.forget(
        RemoteOperation.objects.filter(server=server, kind=RemoteOperation.Kind.DISCOVERY)
    )


def _discover(attempt: DiscoveryAttempt) -> None:
    _authorize(attempt)
    try:
        with ssh.connect_operation(attempt) as shell:
            collected = collect(shell)
            host_key = shell.host_key
    except ssh.UnknownHostKey as challenge:
        _authorize(attempt)
        DiscoveryAttempt.objects.filter(
            pk=attempt.pk, status=RemoteOperation.Status.RUNNING
        ).update(
            challenge_key_type=challenge.key_type,
            challenge_key_blob=challenge.key_blob,
            challenge_fingerprint=challenge.fingerprint,
            challenge_address=challenge.address,
            challenge_port=challenge.port,
        )
        raise
    now = timezone.now()
    # A recovery that already marked this attempt interrupted wins: a stale worker never
    # creates a snapshot after recovery.
    with transaction.atomic():
        _authorize(attempt)
        if not lifecycle.succeed(attempt.pk, now, host_key=host_key):
            return
        save_snapshot(attempt, collected, now)
    logger.info("Discovery attempt %s succeeded", attempt.pk)


def _authorize(attempt: DiscoveryAttempt) -> None:
    if attempt.connection is None:
        return
    if not Server.objects.filter(
        pk=attempt.server.pk, connection_revision=attempt.connection.revision
    ).exists():
        raise lifecycle.OperationRefused("The saved connection changed; request a new check.")
    if attempt.requested_by_id is not None:
        user = User.objects.filter(pk=attempt.requested_by_id).first()
        if (
            user is None
            or not user.is_active
            or not user.has_perms(
                ("servers.view_server", "discovery.add_discoveryattempt", attempt.authority)
            )
        ):
            raise lifecycle.OperationRefused(
                "Permission to check this server is no longer available."
            )
    elif attempt.authority or attempt.connection.mode != "alias":
        raise lifecycle.OperationRefused("The account that requested this check is unavailable.")


lifecycle.register(
    DiscoveryAttempt,
    _discover,
    interrupted=INTERRUPTED_FAILURE,
    unexpected=UNEXPECTED_FAILURE,
    stale_after=STALE_AFTER,
)
