"""Queue discovery attempts and run them in the worker.

Views call ``request_discovery``, or ``queue_discovery`` when an alias is chosen; the durable
worker calls ``run_attempt`` through the ``run_discovery`` task. Remote access goes through
``discovery.ssh.connect`` only.
"""

import datetime
import logging
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from servers.models import Server
from servers.ssh_config import AliasUnusable, resolve_alias

from . import ssh
from .models import DiscoveryAttempt, DiscoverySnapshot
from .observations import collect_os_release
from .tasks import run_discovery

logger = logging.getLogger(__name__)

UNEXPECTED_FAILURE = (
    "Discovery stopped because of an unexpected error. Barectl did not record the error "
    "details, which could include remote output. The worker log names the error type."
)
NEEDS_ALIAS = "Choose an SSH alias before verifying the connection."
INTERRUPTED_FAILURE = (
    "The discovery worker stopped before finishing this attempt. Barectl kept the previous "
    "snapshot, if any. Retry to run discovery again."
)
# Remote work is bounded (10s connect, 15s per command); 10 minutes marks an abandoned job.
STALE_AFTER = timedelta(minutes=10)


class DiscoveryUnavailable(Exception):
    """The server cannot be discovered in its current state."""


class DiscoveryBusy(Exception):
    """The server already has a queued or running attempt."""

    def __init__(self, attempt: DiscoveryAttempt) -> None:
        super().__init__()
        self.attempt = attempt


def recover_stale_attempts(now: datetime.datetime | None = None) -> int:
    """Mark abandoned queued/running attempts as failed so servers are not stuck busy.

    A running attempt older than ``STALE_AFTER`` is treated as interrupted by a stopped
    worker. A queued attempt older than ``STALE_AFTER`` is treated the same way unless a
    READY task waits for it or a recently claimed RUNNING task is in flight to claim it.
    Queued attempts with a READY task are left alone; restarting the worker runs them.

    Updates are conditional on the attempt still being active, so a live worker that just
    started cannot be marked stale, and a stale worker that later finishes cannot overwrite
    the recovery: finishing filters on still-RUNNING.
    """
    from django_tasks_db.models import DBTaskResult

    current = now or timezone.now()
    cutoff = current - STALE_AFTER
    recovered = 0
    running = DiscoveryAttempt.Status.RUNNING
    queued = DiscoveryAttempt.Status.QUEUED
    failed = DiscoveryAttempt.Status.FAILED

    stale_running = DiscoveryAttempt.objects.filter(
        status=running,
        started_at__lt=cutoff,
    ).update(status=failed, finished_at=current, failure=INTERRUPTED_FAILURE)
    recovered += stale_running
    # Workers set started_at when claiming; a RUNNING row without it never started cleanly.
    recovered += DiscoveryAttempt.objects.filter(
        status=running, started_at__isnull=True, queued_at__lt=cutoff
    ).update(status=failed, finished_at=current, failure=INTERRUPTED_FAILURE)

    stale_queued = DiscoveryAttempt.objects.filter(status=queued, queued_at__lt=cutoff)
    for attempt in stale_queued.only("pk"):
        base = DBTaskResult.objects.filter(
            task_path="discovery.tasks.run_discovery",
            args_kwargs__args__0=attempt.pk,
        )
        if base.filter(status="READY").exists():
            continue
        # A recently claimed task is in flight to claim this attempt; leave it.
        if base.filter(status="RUNNING", started_at__gte=cutoff).exists():
            continue
        updated = DiscoveryAttempt.objects.filter(pk=attempt.pk, status=queued).update(
            status=failed, finished_at=current, failure=INTERRUPTED_FAILURE
        )
        recovered += updated
    if recovered:
        logger.info("Recovered %s interrupted discovery attempts", recovered)
    return recovered


def queue_discovery(server: Server) -> DiscoveryAttempt:
    """Queue verification and discovery; raise ``DiscoveryBusy`` if one is active.

    The database allows one queued or running attempt per server, so concurrent requests
    cannot both succeed. The task is enqueued in the same transaction as the attempt: the
    database task backend stores it in this database, so both are committed or neither is.
    Stale attempts that would otherwise block the server are recovered first.
    """
    if server.needs_alias:
        raise DiscoveryUnavailable(NEEDS_ALIAS)
    recover_stale_attempts()
    try:
        with transaction.atomic():
            attempt = DiscoveryAttempt.objects.create(server=server, ssh_alias=server.ssh_alias)
            run_discovery.enqueue(attempt.pk)
    except IntegrityError:
        active = DiscoveryAttempt.objects.filter(
            server=server, status__in=DiscoveryAttempt.ACTIVE
        ).first()
        if active is None:
            raise
        raise DiscoveryBusy(active) from None
    return attempt


def _unavailable_reason(server: Server, latest: DiscoveryAttempt | None) -> str:
    """Why discovery cannot be requested, or "" when it can."""
    if server.needs_alias:
        return NEEDS_ALIAS
    return ""


def can_request_verification(server: Server, latest: DiscoveryAttempt | None) -> bool:
    """Refresh, retry or verification is offered whenever no attempt is active."""
    active = latest is not None and latest.is_active
    return not active and not _unavailable_reason(server, latest)


def request_discovery(server: Server) -> DiscoveryAttempt:
    """Queue refresh, retry or verification, or return the server's active attempt."""
    if reason := _unavailable_reason(server, server.discovery_attempts.first()):
        raise DiscoveryUnavailable(reason)
    try:
        return queue_discovery(server)
    except DiscoveryBusy as busy:
        return busy.attempt


def run_attempt(attempt_id: int) -> None:
    """Verify the connection and collect a snapshot. Called by the worker only."""
    # Recover other servers' abandoned jobs whenever the worker does real work, so a
    # restart that leaves jobs running does not keep those servers busy forever. The
    # current attempt is recent, so the global stale cutoff never matches it.
    recover_stale_attempts()
    claimed = DiscoveryAttempt.objects.filter(
        pk=attempt_id, status=DiscoveryAttempt.Status.QUEUED
    ).update(status=DiscoveryAttempt.Status.RUNNING, started_at=timezone.now())
    if not claimed:
        # Removed with its server, recovered as interrupted, or already handled.
        return
    attempt = DiscoveryAttempt.objects.select_related("server").get(pk=attempt_id)
    try:
        _discover(attempt)
    except (AliasUnusable, ssh.ConnectionFailed) as failure:
        _finish_failed(attempt, str(failure))
    except Exception as error:
        # Log the type only: a message or traceback could quote remote data.
        logger.error(
            "Discovery attempt %s failed unexpectedly: %s", attempt.pk, type(error).__name__
        )
        _finish_failed(attempt, UNEXPECTED_FAILURE)


def _discover(attempt: DiscoveryAttempt) -> None:
    target = resolve_alias(settings.SSH_CONFIG_PATH, attempt.ssh_alias)
    with ssh.connect(target) as shell:
        os_release = collect_os_release(shell)
        host_key = shell.host_key
    now = timezone.now()
    # Publish the snapshot and the outcome together. The update filters on still-RUNNING
    # so a recovery that already marked this attempt interrupted wins: a stale worker
    # never overwrites newer results or creates a snapshot after recovery.
    with transaction.atomic():
        updated = DiscoveryAttempt.objects.filter(
            pk=attempt.pk, status=DiscoveryAttempt.Status.RUNNING
        ).update(status=DiscoveryAttempt.Status.SUCCEEDED, finished_at=now, host_key=host_key)
        if not updated:
            return
        snapshot = DiscoverySnapshot.objects.create(
            server=attempt.server,
            attempt=attempt,
            collected_at=now,
            os_status=os_release.status,
            os_source=os_release.source,
            os_pretty_name=os_release.get("PRETTY_NAME"),
            os_name=os_release.get("NAME"),
            os_id=os_release.get("ID"),
            os_version_id=os_release.get("VERSION_ID"),
            os_warning=os_release.warning,
        )
        # A successful refresh replaces the current snapshot; history stays on attempts.
        DiscoverySnapshot.objects.filter(server=attempt.server).exclude(pk=snapshot.pk).delete()
    logger.info("Discovery attempt %s succeeded", attempt.pk)


def _finish_failed(attempt: DiscoveryAttempt, failure: str) -> None:
    DiscoveryAttempt.objects.filter(pk=attempt.pk, status=DiscoveryAttempt.Status.RUNNING).update(
        status=DiscoveryAttempt.Status.FAILED, finished_at=timezone.now(), failure=failure
    )
    # The sanitized reason is recorded on the attempt and shown in the dashboard.
    logger.info("Discovery attempt %s failed", attempt.pk)
