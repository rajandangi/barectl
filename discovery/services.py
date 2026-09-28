"""The discovery attempt lifecycle: queue, claim, finish, recover and forget attempts.

Views call ``request_discovery`` to check a server again, and the removal page presents
``recorded_discovery``. ``servers.registration`` queues an attempt for a new alias with
``queue_discovery``, and calls ``forget_discovery`` when removing a server. The durable
worker calls ``run_attempt`` through the ``run_discovery`` task. Every change of an
attempt's state goes through ``_advance``. Remote access goes through
``discovery.ssh.connect_alias`` only.

The dashboard reads a server's discovery through ``read_discovery``, Activity through
``history`` and the server list through ``latest_attempt_statuses``. Every public entry
first recovers attempts abandoned by a stopped worker, through ``_recovers_first``, so no
page shows an abandoned attempt as queued or running and no abandoned attempt keeps its
server busy. No other module reads attempts or their snapshots through a server's related
names.

An attempt's life does not depend on what it does: ``run_attempt`` claims it, and ``_run``
runs its step, turns a failure into the operator-facing reason and finishes it.
``_discover`` is the discovery step: it connects, collects and publishes the snapshot.
"""

import functools
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import timedelta
from typing import NamedTuple

from django.db import IntegrityError, transaction
from django.db.models import OuterRef, QuerySet, Subquery
from django.tasks import TaskResultStatus
from django.utils import timezone
from django_tasks_db.models import DBTaskResult, DBTaskResultQuerySet

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
from .tasks import run_discovery

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
    """The server already has a queued or running attempt, kept as ``attempt``."""

    def __init__(self, attempt: DiscoveryAttempt) -> None:
        super().__init__()
        self.attempt = attempt


def _advance(
    attempts: QuerySet[DiscoveryAttempt],
    source: DiscoveryAttempt.Status,
    target: DiscoveryAttempt.Status,
    **changes: object,
) -> int:
    """Move those of ``attempts`` still in ``source`` to ``target``; return how many moved.

    Every change of an attempt's state goes through here. Filtering on the expected state
    makes each transition conditional, so of two processes moving the same attempt only
    the first succeeds, and a stale worker never overwrites a recovery or a newer result.
    """
    return attempts.filter(status=source).update(status=target, **changes)


def _tasks(attempt_ids: Iterable[int]) -> DBTaskResultQuerySet:
    """The worker's task records for ``attempt_ids``.

    Only this function knows how the database task backend stores an attempt's task.
    """
    return DBTaskResult.objects.filter(
        task_path=run_discovery.module_path, args_kwargs__args__0__in=list(attempt_ids)
    )


def _recover_stale_attempts() -> int:
    """Mark abandoned attempts as interrupted failures so servers are not stuck busy.

    A running attempt started more than ``STALE_AFTER`` ago was abandoned by a stopped
    worker. A queued attempt that old is treated the same way unless its task still waits
    for a worker, or a worker claimed that task recently and is about to claim the attempt.
    """
    now = timezone.now()
    cutoff = now - STALE_AFTER
    interrupted = {"finished_at": now, "failure": INTERRUPTED_FAILURE}
    recovered = _advance(
        DiscoveryAttempt.objects.filter(started_at__lt=cutoff),
        DiscoveryAttempt.Status.RUNNING,
        DiscoveryAttempt.Status.FAILED,
        **interrupted,
    )
    stale_queued = DiscoveryAttempt.objects.filter(
        status=DiscoveryAttempt.Status.QUEUED, queued_at__lt=cutoff
    )
    for pk in stale_queued.values_list("pk", flat=True):
        tasks = _tasks([pk])
        waiting = tasks.filter(status=TaskResultStatus.READY).exists()
        claiming = tasks.filter(status=TaskResultStatus.RUNNING, started_at__gte=cutoff).exists()
        if not waiting and not claiming:
            recovered += _advance(
                DiscoveryAttempt.objects.filter(pk=pk),
                DiscoveryAttempt.Status.QUEUED,
                DiscoveryAttempt.Status.FAILED,
                **interrupted,
            )
    if recovered:
        logger.info("Recovered %s interrupted discovery attempts", recovered)
    return recovered


def _recovers_first[**P, R](entry: Callable[P, R]) -> Callable[P, R]:
    """Make ``entry`` recover abandoned attempts before doing anything else.

    Every public function of this module recovers first, directly or through another, so
    none reads, queues or runs attempts while an abandoned one still looks queued or running.
    """

    @functools.wraps(entry)
    def recovering(*args: P.args, **kwargs: P.kwargs) -> R:
        _recover_stale_attempts()
        return entry(*args, **kwargs)

    return recovering


class ServerDiscovery(NamedTuple):
    """A server's discovery as its page reads it, after recovering abandoned attempts."""

    # The latest attempt, or ``None`` before the first one was queued.
    attempt: DiscoveryAttempt | None
    # The snapshot the latest successful attempt published, whatever became of later ones.
    snapshot: Snapshot | None
    # Every recorded attempt, newest recorded first, with the snapshot it published.
    history: list[AttemptSnapshot]


@_recovers_first
def read_discovery(server: Server) -> ServerDiscovery:
    """The server's latest attempt, current snapshot and history in one recovered read."""
    recorded = _attempt_snapshots(server)
    # Only the latest successful attempt keeps its snapshot, so it is the current one.
    snapshot = next((published for _, published in recorded if published), None)
    return ServerDiscovery(recorded[0].attempt if recorded else None, snapshot, recorded)


@_recovers_first
def latest_attempt_statuses(servers: QuerySet[Server]) -> list[tuple[Server, str | None]]:
    """Each of ``servers`` with its latest attempt's status, or None, in one query.

    Abandoned attempts are recovered first.
    """
    latest = DiscoveryAttempt.objects.filter(server=OuterRef("pk")).values("status")[:1]
    return [
        (server, server.attempt_status)
        for server in servers.annotate(attempt_status=Subquery(latest))
    ]


@_recovers_first
def history() -> list[AttemptSnapshot]:
    """Every server's recorded attempts for Activity, newest recorded first.

    Each comes with the snapshot it published. Abandoned attempts are recovered first.
    """
    return _attempt_snapshots(None)


def _attempt_snapshots(server: Server | None) -> list[AttemptSnapshot]:
    """Recorded attempts, every server's or only ``server``'s, with their snapshots."""
    attempts = DiscoveryAttempt.objects.select_related("server")
    return attempt_snapshots(attempts if server is None else attempts.filter(server=server))


@_recovers_first
def queue_discovery(server: Server) -> DiscoveryAttempt:
    """Queue verification and discovery; raise ``DiscoveryBusy`` if one is active.

    The database allows one queued or running attempt per server, so concurrent requests
    cannot both succeed. The task is enqueued in the same transaction as the attempt: the
    database task backend stores it in this database, so both are committed or neither is.
    Stale attempts that would otherwise block the server are recovered first. Raises
    ``Server.DoesNotExist`` when a concurrent request removed the server.
    """
    try:
        with transaction.atomic():
            attempt = DiscoveryAttempt.objects.create(server=server, ssh_alias=server.ssh_alias)
            run_discovery.enqueue(attempt.pk)
    except IntegrityError:
        active = DiscoveryAttempt.objects.filter(
            server=server, status__in=DiscoveryAttempt.ACTIVE
        ).first()
        if active is not None:
            raise DiscoveryBusy(active) from None
        if not Server.objects.filter(pk=server.pk).exists():
            # Removed by a concurrent request; neither the attempt nor its task was saved.
            raise Server.DoesNotExist from None
        raise
    return attempt


def request_discovery(server: Server) -> DiscoveryAttempt:
    """Queue refresh, retry or verification, or return the server's active attempt.

    Recovers abandoned attempts first through ``queue_discovery``. Raises
    ``Server.DoesNotExist`` when a concurrent request removed the server.
    """
    try:
        return queue_discovery(server)
    except DiscoveryBusy as busy:
        return busy.attempt


@dataclass(frozen=True)
class RecordedDiscovery:
    """A server's recorded discovery: what ``forget_discovery`` deletes, and what keeps it."""

    # A queued or running attempt protects the server, and is not forgotten.
    active: bool
    attempt_count: int
    has_snapshot: bool


@_recovers_first
def recorded_discovery(server: Server) -> RecordedDiscovery:
    """The server's recorded discovery, after recovering abandoned attempts."""
    attempts = DiscoveryAttempt.objects.filter(server=server)
    return RecordedDiscovery(
        active=attempts.filter(status__in=DiscoveryAttempt.ACTIVE).exists(),
        attempt_count=attempts.count(),
        has_snapshot=has_snapshot(server),
    )


@_recovers_first
def forget_discovery(server: Server) -> None:
    """Delete the server's finished attempts, their snapshots and the worker's task records.

    Call inside the transaction that deletes the server. Abandoned attempts are recovered
    first, so they are forgotten too. Active attempts are kept: each protects its server,
    so the database refuses to delete the server while one remains.
    """
    finished = DiscoveryAttempt.objects.filter(server=server).exclude(
        status__in=DiscoveryAttempt.ACTIVE
    )
    # Every task record naming a forgotten attempt goes, whatever became of the task,
    # except one a worker claimed recently: that worker saves the record when it finishes.
    # A claim older than the stale cutoff belongs to a stopped worker.
    _tasks(finished.values_list("pk", flat=True)).exclude(
        status=TaskResultStatus.RUNNING, started_at__gte=timezone.now() - STALE_AFTER
    ).delete()
    # Deleting an attempt deletes the snapshot it published.
    finished.delete()


@_recovers_first
def run_attempt(attempt_id: int) -> None:
    """Verify the connection and collect a snapshot. Called by the worker only.

    Recovering first catches other servers' abandoned attempts whenever the worker does real
    work. The current attempt is recent, so the stale cutoff never matches it.
    """
    claimed = _advance(
        DiscoveryAttempt.objects.filter(pk=attempt_id),
        DiscoveryAttempt.Status.QUEUED,
        DiscoveryAttempt.Status.RUNNING,
        started_at=timezone.now(),
    )
    if not claimed:
        # Removed with its server, recovered as interrupted, or already handled.
        return
    _run(attempt_id, _discover)


def _run(attempt_id: int, step: Callable[[DiscoveryAttempt], None]) -> None:
    """Run ``step`` on the claimed attempt, and record its failure if it raises.

    The step finishes a success itself, since it publishes its result with the outcome. A
    failure is recorded with the reason the operator sees: a refused connection's own
    message, or a fixed wording that quotes nothing remote.
    """
    try:
        step(DiscoveryAttempt.objects.select_related("server").get(pk=attempt_id))
    except ssh.ConnectionFailed as failure:
        _finish_failed(attempt_id, str(failure))
    except Exception as error:
        # Log the type only: a message or traceback could quote remote data.
        logger.error(
            "Discovery attempt %s failed unexpectedly: %s", attempt_id, type(error).__name__
        )
        _finish_failed(attempt_id, UNEXPECTED_FAILURE)
    except BaseException:
        # Forcing the worker to stop exits mid-task; record the interruption now rather
        # than leaving the server busy until recovery.
        _finish_failed(attempt_id, INTERRUPTED_FAILURE)
        raise


def _discover(attempt: DiscoveryAttempt) -> None:
    """Connect, collect a snapshot, and publish it as the attempt succeeds."""
    with ssh.connect_alias(attempt.ssh_alias) as shell:
        collected = collect(shell)
        host_key = shell.host_key
    now = timezone.now()
    # Publish the snapshot and the outcome together. A recovery that already marked this
    # attempt interrupted wins: a stale worker never creates a snapshot after recovery.
    with transaction.atomic():
        succeeded = _advance(
            DiscoveryAttempt.objects.filter(pk=attempt.pk),
            DiscoveryAttempt.Status.RUNNING,
            DiscoveryAttempt.Status.SUCCEEDED,
            finished_at=now,
            host_key=host_key,
        )
        if not succeeded:
            return
        save_snapshot(attempt, collected, now)
    logger.info("Discovery attempt %s succeeded", attempt.pk)


def _finish_failed(attempt_id: int, failure: str) -> None:
    _advance(
        DiscoveryAttempt.objects.filter(pk=attempt_id),
        DiscoveryAttempt.Status.RUNNING,
        DiscoveryAttempt.Status.FAILED,
        finished_at=timezone.now(),
        failure=failure,
    )
    # The sanitized reason is recorded on the attempt and shown in the dashboard.
    logger.info("Discovery attempt %s failed", attempt_id)
