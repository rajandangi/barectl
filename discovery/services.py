"""Queue discovery attempts and run them in the worker.

Views call ``request_discovery``; the durable worker calls ``run_attempt`` through the
``run_discovery`` task. Remote access goes through ``discovery.ssh.connect`` only.
"""

import logging

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


class DiscoveryUnavailable(Exception):
    """The server cannot be discovered in its current state."""


class DiscoveryBusy(Exception):
    """The server already has a queued or running attempt."""

    def __init__(self, attempt: DiscoveryAttempt) -> None:
        super().__init__()
        self.attempt = attempt


def queue_discovery(server: Server) -> DiscoveryAttempt:
    """Queue verification and discovery; raise ``DiscoveryBusy`` if one is active.

    The database allows one queued or running attempt per server, so concurrent requests
    cannot both succeed. The task is enqueued in the same transaction as the attempt: the
    database task backend stores it in this database, so both are committed or neither is.
    """
    if server.needs_alias:
        raise DiscoveryUnavailable("Choose an SSH alias before verifying the connection.")
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


def request_discovery(server: Server) -> DiscoveryAttempt:
    """Queue verification and discovery, or return the server's active attempt."""
    try:
        return queue_discovery(server)
    except DiscoveryBusy as busy:
        return busy.attempt


def run_attempt(attempt_id: int) -> None:
    """Verify the connection and collect a snapshot. Called by the worker only."""
    claimed = DiscoveryAttempt.objects.filter(
        pk=attempt_id, status=DiscoveryAttempt.Status.QUEUED
    ).update(status=DiscoveryAttempt.Status.RUNNING, started_at=timezone.now())
    if not claimed:
        # Removed with its server, or already handled.
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
    # Publish the snapshot and the outcome together.
    with transaction.atomic():
        updated = DiscoveryAttempt.objects.filter(
            pk=attempt.pk, status=DiscoveryAttempt.Status.RUNNING
        ).update(status=DiscoveryAttempt.Status.SUCCEEDED, finished_at=now, host_key=host_key)
        if not updated:
            return
        DiscoverySnapshot.objects.create(
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
    logger.info("Discovery attempt %s succeeded", attempt.pk)


def _finish_failed(attempt: DiscoveryAttempt, failure: str) -> None:
    DiscoveryAttempt.objects.filter(pk=attempt.pk, status=DiscoveryAttempt.Status.RUNNING).update(
        status=DiscoveryAttempt.Status.FAILED, finished_at=timezone.now(), failure=failure
    )
    # The sanitized reason is recorded on the attempt and shown in the dashboard.
    logger.info("Discovery attempt %s failed", attempt.pk)
