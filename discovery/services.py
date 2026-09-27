"""Queue discovery attempts and run them in the worker.

Views call ``request_discovery``, or ``queue_discovery`` when an alias is chosen; the durable
worker calls ``run_attempt`` through the ``run_discovery`` task. Remote access goes through
``discovery.ssh.connect`` only.
"""

import logging
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.tasks import TaskResultStatus
from django.utils import timezone
from django_tasks_db.models import DBTaskResult

from servers.models import Server
from servers.ssh_config import AliasUnusable, resolve_alias

from . import ssh
from .models import (
    ComponentObservation,
    DiscoveryAttempt,
    DiscoverySnapshot,
    NginxSiteObservation,
    PhpFpmPoolObservation,
)
from .observations import (
    collect_architecture,
    collect_cpu_count,
    collect_filesystem,
    collect_memory,
    collect_nginx_sites,
    collect_os_release,
    collect_php_pools,
    collect_web_stack,
)
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
# Remote work is bounded by ssh.CONNECT_TIMEOUT and ssh.COMMAND_TIMEOUT, so an attempt
# still active after this long was abandoned by its worker.
STALE_AFTER = timedelta(minutes=10)


class DiscoveryUnavailable(Exception):
    """The server cannot be discovered in its current state."""


class DiscoveryBusy(Exception):
    """The server already has a queued or running attempt."""

    def __init__(self, attempt: DiscoveryAttempt) -> None:
        super().__init__()
        self.attempt = attempt


def recover_stale_attempts() -> int:
    """Mark abandoned attempts as interrupted failures so servers are not stuck busy.

    A running attempt started more than ``STALE_AFTER`` ago was abandoned by a stopped
    worker. A queued attempt that old is treated the same way unless its task still waits
    for a worker, or a worker claimed that task recently and is about to claim the attempt.

    Each update applies only while the attempt is still active, and finishing applies
    only while it is still running, so a stale worker cannot overwrite the recovery.
    """
    now = timezone.now()
    cutoff = now - STALE_AFTER
    active = DiscoveryAttempt.objects.filter(status__in=DiscoveryAttempt.ACTIVE)
    interrupted = {
        "status": DiscoveryAttempt.Status.FAILED,
        "finished_at": now,
        "failure": INTERRUPTED_FAILURE,
    }
    recovered = active.filter(status=DiscoveryAttempt.Status.RUNNING, started_at__lt=cutoff).update(
        **interrupted
    )
    stale_queued = active.filter(status=DiscoveryAttempt.Status.QUEUED, queued_at__lt=cutoff)
    for pk in stale_queued.values_list("pk", flat=True):
        tasks = DBTaskResult.objects.filter(
            task_path=run_discovery.module_path, args_kwargs__args__0=pk
        )
        waiting = tasks.filter(status=TaskResultStatus.READY).exists()
        claiming = tasks.filter(status=TaskResultStatus.RUNNING, started_at__gte=cutoff).exists()
        if not waiting and not claiming:
            recovered += stale_queued.filter(pk=pk).update(**interrupted)
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


def _unavailable_reason(server: Server) -> str:
    """Why discovery cannot be requested, or "" when it can."""
    if server.needs_alias:
        return NEEDS_ALIAS
    return ""


def can_request_verification(server: Server, latest: DiscoveryAttempt | None) -> bool:
    """Refresh, retry or verification is offered whenever no attempt is active."""
    active = latest is not None and latest.is_active
    return not active and not _unavailable_reason(server)


def request_discovery(server: Server) -> DiscoveryAttempt:
    """Queue refresh, retry or verification, or return the server's active attempt."""
    if reason := _unavailable_reason(server):
        raise DiscoveryUnavailable(reason)
    try:
        return queue_discovery(server)
    except DiscoveryBusy as busy:
        return busy.attempt


def run_attempt(attempt_id: int) -> None:
    """Verify the connection and collect a snapshot. Called by the worker only."""
    # Recover other servers' abandoned attempts whenever the worker does real work. The
    # current attempt is recent, so the stale cutoff never matches it.
    recover_stale_attempts()
    claimed = DiscoveryAttempt.objects.filter(
        pk=attempt_id, status=DiscoveryAttempt.Status.QUEUED
    ).update(status=DiscoveryAttempt.Status.RUNNING, started_at=timezone.now())
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
        os_release = collect_os_release(shell)
        architecture = collect_architecture(shell)
        cpu = collect_cpu_count(shell)
        memory = collect_memory(shell)
        filesystem = collect_filesystem(shell)
        components = collect_web_stack(shell)
        sites = collect_nginx_sites(shell)
        pools = collect_php_pools(shell)
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
            arch_status=architecture.status,
            arch_value=architecture.value,
            arch_source=architecture.source,
            arch_warning=architecture.warning,
            cpu_status=cpu.status,
            cpu_count=cpu.count,
            cpu_source=cpu.source,
            cpu_warning=cpu.warning,
            memory_status=memory.status,
            memory_bytes=memory.total_bytes,
            memory_source=memory.source,
            memory_warning=memory.warning,
            filesystem_status=filesystem.status,
            filesystem_size_bytes=filesystem.size_bytes,
            filesystem_avail_bytes=filesystem.avail_bytes,
            filesystem_source=filesystem.source,
            filesystem_warning=filesystem.warning,
            nginx_site_files_status=sites.status,
            nginx_site_files_source=sites.source,
            nginx_site_files_warning=sites.warning,
            php_fpm_pools_status=pools.status,
            php_fpm_pools_source=pools.source,
            php_fpm_pools_warning=pools.warning,
        )
        ComponentObservation.objects.bulk_create(
            ComponentObservation(
                snapshot=snapshot,
                component=observed.component,
                package_status=observed.package_status,
                packages="\n".join(observed.packages),
                package_source=observed.package_source,
                package_warning=observed.package_warning,
                service_status=observed.service_status,
                units="\n".join(observed.units),
                service_source=observed.service_source,
                service_warning=observed.service_warning,
            )
            for observed in components
        )
        NginxSiteObservation.objects.bulk_create(
            NginxSiteObservation(
                snapshot=snapshot,
                name=site.name,
                status=site.status,
                server_names="\n".join(site.server_names),
                listens="\n".join(site.listens),
                source=site.source,
                warning=site.warning,
            )
            for site in sites.sites
        )
        PhpFpmPoolObservation.objects.bulk_create(
            PhpFpmPoolObservation(
                snapshot=snapshot,
                version=pool.version,
                name=pool.name,
                status=pool.status,
                listen=pool.listen,
                source=pool.source,
                warning=pool.warning,
            )
            for pool in pools.pools
        )
        # A successful refresh replaces the current snapshot; history stays on attempts.
        DiscoverySnapshot.objects.filter(server=attempt.server).exclude(pk=snapshot.pk).delete()
    logger.info("Discovery attempt %s succeeded", attempt.pk)


def _finish_failed(attempt_id: int, failure: str) -> None:
    DiscoveryAttempt.objects.filter(pk=attempt_id, status=DiscoveryAttempt.Status.RUNNING).update(
        status=DiscoveryAttempt.Status.FAILED, finished_at=timezone.now(), failure=failure
    )
    # The sanitized reason is recorded on the attempt and shown in the dashboard.
    logger.info("Discovery attempt %s failed", attempt_id)
