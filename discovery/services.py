"""Queue discovery attempts, run them in the worker, and remove servers between attempts.

Views call ``request_discovery``, or ``queue_discovery`` when an alias is chosen, and
``remove_server``; the durable worker calls ``run_attempt`` through the ``run_discovery``
task. Remote access goes through ``discovery.ssh.connect`` only.
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
    WebStackComponent,
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
INTERRUPTED_FAILURE = (
    "The discovery worker stopped before finishing this attempt. Barectl kept the previous "
    "snapshot, if any. Retry to run discovery again."
)
# Remote work is bounded: connecting by the ssh.CONNECT_TIMEOUT limits on each of its
# steps, and every command on the connection by ssh.ATTEMPT_TIMEOUT. An attempt still
# active after this long was abandoned by its worker.
STALE_AFTER = timedelta(minutes=10)


class DiscoveryBusy(Exception):
    """The server already has a queued or running attempt."""

    def __init__(self, attempt: DiscoveryAttempt) -> None:
        super().__init__()
        self.attempt = attempt


class RemovalBlocked(Exception):
    """The server has a queued or running attempt, so its registration must stay."""


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
    recover_stale_attempts()
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
    """Queue refresh, retry or verification, or return the server's active attempt."""
    try:
        return queue_discovery(server)
    except DiscoveryBusy as busy:
        return busy.attempt


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
    recover_stale_attempts()
    try:
        with transaction.atomic():
            finished = DiscoveryAttempt.objects.filter(server=server).exclude(
                status__in=DiscoveryAttempt.ACTIVE
            )
            # The worker's records of finished tasks name the attempts they ran.
            DBTaskResult.objects.filter(
                task_path=run_discovery.module_path,
                args_kwargs__args__0__in=list(finished.values_list("pk", flat=True)),
                status__in=(TaskResultStatus.SUCCESSFUL, TaskResultStatus.FAILED),
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
        # Site files and pools depend on their component's package observation.
        by_component = {observed.component: observed for observed in components}
        sites = collect_nginx_sites(shell, by_component[WebStackComponent.NGINX])
        pools = collect_php_pools(shell, by_component[WebStackComponent.PHP_FPM])
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
            nginx_site_files_status=sites.outcome,
            nginx_site_files_source=sites.source,
            nginx_site_files_warning=sites.warning,
            php_fpm_pools_status=pools.outcome,
            php_fpm_pools_source=pools.source,
            php_fpm_pools_warning=pools.warning,
        )
        ComponentObservation.objects.bulk_create(
            ComponentObservation(
                snapshot=snapshot,
                component=observed.component,
                package_status=observed.package.outcome,
                packages="\n".join(
                    f"{package.name} {package.version}" for package in observed.package.value
                ),
                package_source=observed.package.source,
                package_warning=observed.package.warning,
                service_status=observed.service.outcome,
                units="\n".join(observed.service.value),
                service_source=observed.service.source,
                service_warning=observed.service.warning,
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
            for site in sites.value
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
            for pool in pools.value
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
