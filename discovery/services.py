"""The discovery attempt lifecycle: queue, claim, finish, recover, and remove servers.

Views call ``save_server`` to register or edit a server, ``request_discovery`` to check it
again, and ``removal_summary`` and ``remove_server`` to remove it; the durable worker calls
``run_attempt`` through the ``run_discovery`` task. Every change of an attempt's state goes
through ``_advance``. Remote access goes through ``discovery.ssh.connect`` only.

Views read discovery through ``read_discovery``, ``activity`` and
``latest_attempt_statuses``, which first recover attempts abandoned by a stopped worker, so
no page shows an abandoned attempt as queued or running.
"""

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum, auto

from django.conf import settings
from django.db import DatabaseError, IntegrityError, transaction
from django.db.models import OuterRef, QuerySet, Subquery
from django.tasks import TaskResultStatus
from django.utils import timezone
from django_tasks_db.models import DBTaskResult, DBTaskResultQuerySet

from servers.models import Server
from servers.ssh_config import AliasUnusable, resolve_alias

from . import ssh
from .models import DiscoveryAttempt
from .observations import collect
from .snapshot import AttemptSnapshot, Snapshot, attempt_snapshots, current_snapshot, save_snapshot
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
# steps, and every command on the connection by ssh.ATTEMPT_TIMEOUT. An attempt still
# active after this long was abandoned by its worker.
STALE_AFTER = timedelta(minutes=10)


class SaveOutcome(Enum):
    """What ``save_server`` did with a registration or edit."""

    # Saved; the alias did not change, so no connection check was queued.
    SAVED = auto()
    # Saved with a new alias, and a connection check was queued with it.
    QUEUED = auto()
    # Nothing saved: another server was saved with this name or alias meanwhile.
    TAKEN = auto()
    # Nothing saved: a check with the current alias is active, so the alias must stay.
    BUSY = auto()


@dataclass(frozen=True)
class RemovalSummary:
    """What removing a server would delete, and whether discovery blocks it now."""

    # A queued or running attempt protects the server from removal.
    busy: bool
    attempt_count: int
    has_snapshot: bool


class RemovalBlocked(Exception):
    """The server has a queued or running attempt, so its registration must stay."""


class _Busy(Exception):
    """The server already has a queued or running attempt."""

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


@dataclass(frozen=True)
class ServerDiscovery:
    """A server's recorded discovery, read after recovering abandoned attempts."""

    server: Server
    # The latest attempt, or ``None`` before the first one was queued.
    attempt: DiscoveryAttempt | None
    # The snapshot the latest successful attempt published, whatever became of later ones.
    snapshot: Snapshot | None

    def history(self) -> list[AttemptSnapshot]:
        """Every recorded attempt for the server, newest first, with its published snapshot.

        Abandoned attempts were already recovered when the discovery was read.
        """
        return attempt_snapshots(self.server.discovery_attempts.all())


def read_discovery(server: Server) -> ServerDiscovery:
    """The server's latest attempt and current snapshot, after recovering abandoned ones."""
    _recover_stale_attempts()
    return ServerDiscovery(server, server.discovery_attempts.first(), current_snapshot(server))


def latest_attempt_statuses(servers: QuerySet[Server]) -> list[tuple[Server, str | None]]:
    """Each of ``servers`` with its latest attempt's status, or None, in one query.

    Abandoned attempts are recovered first.
    """
    _recover_stale_attempts()
    latest = DiscoveryAttempt.objects.filter(server=OuterRef("pk")).values("status")[:1]
    return [
        (server, server.attempt_status)
        for server in servers.annotate(attempt_status=Subquery(latest))
    ]


def activity() -> list[AttemptSnapshot]:
    """Every recorded attempt across servers, newest recorded first, with its snapshot.

    Abandoned attempts are recovered first.
    """
    _recover_stale_attempts()
    return attempt_snapshots(DiscoveryAttempt.objects.select_related("server"))


def _queue(server: Server) -> DiscoveryAttempt:
    """Queue verification and discovery; raise ``_Busy`` if one is active.

    The database allows one queued or running attempt per server, so concurrent requests
    cannot both succeed. The task is enqueued in the same transaction as the attempt: the
    database task backend stores it in this database, so both are committed or neither is.
    Stale attempts that would otherwise block the server are recovered first.
    """
    _recover_stale_attempts()
    try:
        with transaction.atomic():
            attempt = DiscoveryAttempt.objects.create(server=server, ssh_alias=server.ssh_alias)
            run_discovery.enqueue(attempt.pk)
    except IntegrityError:
        active = DiscoveryAttempt.objects.filter(
            server=server, status__in=DiscoveryAttempt.ACTIVE
        ).first()
        if active is not None:
            raise _Busy(active) from None
        if not Server.objects.filter(pk=server.pk).exists():
            # Removed by a concurrent request; neither the attempt nor its task was saved.
            raise Server.DoesNotExist from None
        raise
    return attempt


def request_discovery(server: Server) -> DiscoveryAttempt:
    """Queue refresh, retry or verification, or return the server's active attempt.

    Raises ``Server.DoesNotExist`` when a concurrent request removed the server.
    """
    try:
        return _queue(server)
    except _Busy as busy:
        return busy.attempt


def save_server(server: Server, previous_alias: str) -> SaveOutcome:
    """Save a registration or edit, queueing a connection check when the alias is new.

    ``previous_alias`` is the alias the server was loaded with, or empty for a new
    registration. The server and its attempt are saved together or not at all. Raises
    ``Server.DoesNotExist`` when a concurrent request removed the edited server; an edit
    only updates, so saving never registers a removed server again.
    """
    editing = server.pk is not None
    queue = server.ssh_alias != previous_alias
    try:
        with transaction.atomic():
            server.save(force_update=editing)
            if queue:
                _queue(server)
    except IntegrityError:
        return SaveOutcome.TAKEN
    except _Busy:
        return SaveOutcome.BUSY
    except DatabaseError:
        if editing and not Server.objects.filter(pk=server.pk).exists():
            raise Server.DoesNotExist from None
        raise
    return SaveOutcome.QUEUED if queue else SaveOutcome.SAVED


def removal_summary(server: Server) -> RemovalSummary:
    """What ``remove_server`` would delete, after recovering abandoned attempts."""
    _recover_stale_attempts()
    attempts = server.discovery_attempts
    return RemovalSummary(
        busy=attempts.filter(status__in=DiscoveryAttempt.ACTIVE).exists(),
        attempt_count=attempts.count(),
        has_snapshot=server.snapshots.exists(),
    )


def remove_server(server: Server) -> None:
    """Delete a registration with its attempts and snapshots; raise ``RemovalBlocked``.

    Only Barectl's own records are deleted. Nothing connects to the server, and the
    controller's SSH configuration, keys and known_hosts are never touched. Finished
    attempts are deleted first, together with the snapshots they published. An active
    attempt protects its server, so the database refuses the removal. The database also
    arbitrates an attempt created after that check: the server row cannot be deleted
    while any attempt references it. SQLite's immediate transactions serialize removal
    with concurrent requests, so one of them sees the other's committed result.
    """
    _recover_stale_attempts()
    try:
        with transaction.atomic():
            finished = DiscoveryAttempt.objects.filter(server=server).exclude(
                status__in=DiscoveryAttempt.ACTIVE
            )
            # The worker's records of finished tasks name the attempts they ran.
            _tasks(finished.values_list("pk", flat=True)).filter(
                status__in=(TaskResultStatus.SUCCESSFUL, TaskResultStatus.FAILED)
            ).delete()
            finished.delete()
            # Deleting through a queryset leaves the instance usable if the commit fails.
            Server.objects.filter(pk=server.pk).delete()
    except IntegrityError:
        # ProtectedError is an IntegrityError, and a concurrently queued attempt fails the
        # foreign key check at commit. Either way everything was rolled back.
        raise RemovalBlocked from None
    logger.info("Removed server %s and its discovery history", server.pk)


def run_attempt(attempt_id: int) -> None:
    """Verify the connection and collect a snapshot. Called by the worker only."""
    # Recover other servers' abandoned attempts whenever the worker does real work. The
    # current attempt is recent, so the stale cutoff never matches it.
    _recover_stale_attempts()
    claimed = _advance(
        DiscoveryAttempt.objects.filter(pk=attempt_id),
        DiscoveryAttempt.Status.QUEUED,
        DiscoveryAttempt.Status.RUNNING,
        started_at=timezone.now(),
    )
    if not claimed:
        # Removed with its server, recovered as interrupted, or already handled.
        return
    try:
        _discover(DiscoveryAttempt.objects.select_related("server").get(pk=attempt_id))
    except (AliasUnusable, ssh.ConnectionFailed) as failure:
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
    target = resolve_alias(settings.SSH_CONFIG_PATH, attempt.ssh_alias)
    with ssh.connect(target) as shell:
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
