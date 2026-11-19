"""The discovery kind of remote operation.

docs/adr/0004-serialize-remote-operations-in-one-table.md

Legacy discovery entries recover abandoned operations first
(docs/ssh-connections.md#workflow). Operator refresh entries authorize a freshly
loaded account before recovery can change operation state.
No other module reads attempts or their snapshots through a server's related names.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import NamedTuple, TypedDict

from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import OuterRef, Q, QuerySet, Subquery
from django.utils import timezone

from operations import lifecycle
from operations.check_progress import CheckProgress, CheckReader, CheckStage
from operations.lifecycle import OperationBusy, recovers_first
from operations.models import RemoteOperation
from security import advisories, reachability
from servers.models import Server

from . import ssh
from .models import DiscoveryAttempt
from .observations import collect
from .snapshot import (
    AttemptSummary,
    BasicSnapshot,
    CollectedSnapshot,
    Snapshot,
    attempt_summaries,
    basic_snapshot_of,
    capacity_columns,
    has_snapshot,
    save_snapshot,
    snapshot_of,
)

logger = logging.getLogger(__name__)
CHANGE_REFRESH_AUTHORITY = "operations.view_changes"

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


@dataclass(frozen=True)
class SecurityVerification:
    completed_at: datetime
    report: dict[str, object]
    older: bool


class ServerDiscovery(NamedTuple):
    attempt: DiscoveryAttempt | None
    # The snapshot the latest successful attempt published, whatever became of later ones.
    snapshot: Snapshot | None
    # Every recorded attempt, newest recorded first, with a summary of its snapshot.
    history: list[AttemptSummary]
    # The server's active remote operation of any kind, which blocks a new attempt.
    active: RemoteOperation | None
    verification: SecurityVerification | None


@recovers_first
def read_discovery(server: Server) -> ServerDiscovery:
    recorded = _attempt_summaries(server)

    def current(item: AttemptSummary) -> bool:
        connection = item.attempt.connection
        return (connection is None and server.connection_revision == 0) or (
            connection is not None and connection.revision == server.connection_revision
        )

    attempt = next((item.attempt for item in recorded if current(item)), None)
    # The latest successful attempt matching the connection still holds the snapshot.
    published = next((item.attempt for item in recorded if item.snapshot and current(item)), None)
    verified = next(
        (
            item.attempt
            for item in recorded
            if current(item)
            and item.attempt.check_security
            and item.attempt.status == RemoteOperation.Status.SUCCEEDED
            and item.attempt.security_verification
            and item.attempt.finished_at is not None
        ),
        None,
    )
    return ServerDiscovery(
        attempt,
        snapshot_of(published) if published is not None else None,
        recorded,
        lifecycle.active_operation(server),
        SecurityVerification(
            verified.finished_at,
            verified.security_verification,
            attempt is not None and verified.pk != attempt.pk,
        )
        if verified is not None and verified.finished_at is not None
        else None,
    )


class ServerCapacity(NamedTuple):
    checked_at: datetime
    cpus: int | None
    ram: int | None
    storage: int | None


@recovers_first
def inventory_discovery(
    servers: QuerySet[Server],
) -> list[tuple[Server, str | None, ServerCapacity | None]]:
    """Read the latest attempt status and last successful capacity in the same query."""
    latest = (
        DiscoveryAttempt.objects.filter(server=OuterRef("pk"))
        .filter(
            Q(connection__revision=OuterRef("connection_revision"))
            | Q(connection__isnull=True, server__connection_revision=0)
        )
        .values("status")[:1]
    )
    capacity = capacity_columns()
    listed = servers.annotate(
        attempt_status=Subquery(latest),
        capacity_checked_at=capacity.checked_at,
        capacity_cpus=capacity.cpus,
        capacity_ram=capacity.ram,
        capacity_storage=capacity.storage,
    )
    return [
        (
            server,
            server.attempt_status,
            ServerCapacity(
                server.capacity_checked_at,
                server.capacity_cpus,
                server.capacity_ram,
                server.capacity_storage,
            )
            if server.capacity_checked_at is not None
            else None,
        )
        for server in listed
    ]


@recovers_first
def history() -> list[AttemptSummary]:
    """Every server's recorded attempts, newest recorded first."""
    return _attempt_summaries(None)


def _attempt_summaries(server: Server | None) -> list[AttemptSummary]:
    attempts = DiscoveryAttempt.objects.select_related("server", "connection")
    return attempt_summaries(attempts if server is None else attempts.filter(server=server))


@recovers_first
def queue_discovery(
    server: Server,
    *,
    user: User | None = None,
    authority: str = "discovery.add_discoveryattempt",
    expected_host_key: str = "",
    check_security: bool = False,
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
            expected_host_key=expected_host_key,
            check_security=check_security,
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


class RefreshNotFound(Exception):
    """The requested server or discovery operation is unavailable."""


class RefreshDisposition(StrEnum):
    ACCEPTED = "accepted"
    SHARED_ACTIVE = "shared_active"
    BUSY = "busy"


@dataclass(frozen=True)
class RefreshRequest:
    operation: RemoteOperation
    disposition: RefreshDisposition


class RefreshOperation(TypedDict):
    id: int
    kind: str
    status: str
    queued_at: str
    started_at: str | None
    finished_at: str | None


class RefreshProgress(TypedDict):
    stage: str | None
    reads: int
    updated_at: str | None
    elapsed_seconds: int
    waiting_for_worker: bool


class RefreshServer(TypedDict):
    id: int
    name: str


class RefreshStatus(TypedDict):
    version: int
    code: str
    server: RefreshServer
    operation: RefreshOperation
    progress: RefreshProgress
    snapshot: BasicSnapshot | None
    snapshot_availability: str
    message: str | None


def _refresh_actor(user: User) -> User:
    # A User instance can retain Django's permission cache across wait polls.
    actor = User.objects.filter(pk=user.pk, is_active=True).first()
    if actor is None or not actor.has_perms(
        ("servers.view_server", "discovery.add_discoveryattempt")
    ):
        raise PermissionDenied("Permission to refresh this server is unavailable.")
    return actor


def request_refresh(server_id: int, *, user: User, check_security: bool = False) -> RefreshRequest:
    """Submit the operator refresh, sharing an active attempt or naming a blocker."""
    actor = _refresh_actor(user)
    return _request_refresh_after_authorization(server_id, actor, check_security=check_security)


@recovers_first
def _request_refresh_after_authorization(
    server_id: int, actor: User, *, check_security: bool
) -> RefreshRequest:
    server = Server.objects.filter(pk=server_id).first()
    if server is None:
        raise RefreshNotFound
    try:
        queued = queue_discovery(server, user=actor, check_security=check_security)
        return RefreshRequest(queued, RefreshDisposition.ACCEPTED)
    except DiscoveryBusy as busy:
        attempt = DiscoveryAttempt.objects.filter(pk=busy.operation.pk).first()
        if attempt is not None and (not check_security or attempt.check_security):
            return RefreshRequest(attempt, RefreshDisposition.SHARED_ACTIVE)
        return RefreshRequest(busy.operation, RefreshDisposition.BUSY)
    except Server.DoesNotExist:
        raise RefreshNotFound from None


def read_refresh(operation_id: int, *, user: User) -> RefreshStatus:
    """Return an allowlisted status for one operation, with no cached fallback."""
    _refresh_actor(user)
    return _read_refresh_after_authorization(operation_id)


@recovers_first
def _read_refresh_after_authorization(operation_id: int) -> RefreshStatus:
    attempt = (
        DiscoveryAttempt.objects.select_related("server", "connection")
        .filter(pk=operation_id)
        .first()
    )
    if attempt is None:
        raise RefreshNotFound
    operation = attempt
    server = attempt.server
    now = timezone.now()
    elapsed_start = operation.started_at or operation.queued_at
    elapsed_end = operation.finished_at or now
    elapsed = max(0, int((elapsed_end - elapsed_start).total_seconds()))
    captured = attempt.connection
    connection_current = (
        server.connection_revision == 0
        if captured is None
        else captured.revision == server.connection_revision
    )
    snapshot = None
    snapshot_availability = "not_applicable"
    if operation.status == RemoteOperation.Status.SUCCEEDED:
        snapshot = basic_snapshot_of(attempt, connection_current=connection_current)
        snapshot_availability = "retained" if snapshot is not None else "replaced"
    if operation.status == RemoteOperation.Status.FAILED:
        code = (
            "stale_connection"
            if operation.failure == "The saved connection changed; request a new check."
            else "failed"
        )
    elif operation.status == RemoteOperation.Status.SUCCEEDED:
        code = "succeeded"
    else:
        code = "in_progress"
    return {
        "version": 1,
        "code": code,
        "server": {"id": server.pk, "name": server.name},
        "operation": {
            "id": operation.pk,
            "kind": operation.kind,
            "status": operation.status,
            "queued_at": operation.queued_at.isoformat(),
            "started_at": operation.started_at.isoformat() if operation.started_at else None,
            "finished_at": operation.finished_at.isoformat() if operation.finished_at else None,
        },
        "progress": {
            "stage": operation.check_stage or None,
            "reads": operation.check_reads,
            "updated_at": operation.check_updated_at.isoformat()
            if operation.check_updated_at
            else None,
            "elapsed_seconds": elapsed,
            "waiting_for_worker": operation.status == RemoteOperation.Status.QUEUED,
        },
        "snapshot": snapshot,
        "snapshot_availability": snapshot_availability,
        "message": (
            "The saved connection changed; request a new check."
            if code == "stale_connection"
            else "The refresh failed. Check the dashboard for details."
            if code == "failed"
            else None
        ),
    }


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
    progress = CheckProgress(attempt)
    progress.report(CheckStage.CONNECT)
    try:
        with ssh.connect_operation(attempt, expected_host_key=attempt.expected_host_key) as shell:
            collected = collect(
                CheckReader(shell, progress), releases=True, progress=progress.report
            )
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
    verification = _verify_security(attempt, collected) if attempt.check_security else None
    now = timezone.now()
    progress.report(CheckStage.SAVE)
    # A recovery that already marked this attempt interrupted wins: a stale worker never
    # creates a snapshot after recovery.
    with transaction.atomic():
        _authorize(attempt)
        if not lifecycle.succeed(attempt.pk, now, host_key=host_key):
            return
        save_snapshot(attempt, collected, now)
        if verification is not None:
            DiscoveryAttempt.objects.filter(pk=attempt.pk).update(
                security_verification=verification
            )
    logger.info("Discovery attempt %s succeeded", attempt.pk)


def _verify_security(attempt: DiscoveryAttempt, collected: CollectedSnapshot) -> dict[str, object]:
    _authorize(attempt)
    definition = attempt.connection
    peer = (
        (definition.address, definition.port)
        if definition is not None and definition.mode in {"agent", "keyfile"}
        else None
    )
    return {
        "reachability": reachability.check(peer, collected.security.value),
        "advisories": advisories.check(collected),
    }


def _authorize(attempt: DiscoveryAttempt) -> None:
    if attempt.connection is None and not attempt.authority and attempt.requested_by_id is None:
        return
    if (
        attempt.connection is not None
        and not Server.objects.filter(
            pk=attempt.server.pk, connection_revision=attempt.connection.revision
        ).exists()
    ):
        raise lifecycle.OperationRefused("The saved connection changed; request a new check.")
    if attempt.authority == CHANGE_REFRESH_AUTHORITY and attempt.requested_by_id is None:
        raise lifecycle.OperationRefused(
            "The automatic observation's original actor is unavailable."
        )
    if attempt.requested_by_id is not None:
        user = User.objects.filter(pk=attempt.requested_by_id).first()
        if (
            user is None
            or not user.is_active
            or not user.has_perms(
                ("servers.view_server", CHANGE_REFRESH_AUTHORITY)
                if attempt.authority == CHANGE_REFRESH_AUTHORITY
                else ("servers.view_server", "discovery.add_discoveryattempt", attempt.authority)
            )
        ):
            raise lifecycle.OperationRefused(
                "Permission to check this server is no longer available."
            )
    elif attempt.authority or (
        attempt.connection is not None and attempt.connection.mode != "alias"
    ):
        raise lifecycle.OperationRefused("The account that requested this check is unavailable.")


lifecycle.register(
    DiscoveryAttempt,
    _discover,
    interrupted=INTERRUPTED_FAILURE,
    unexpected=UNEXPECTED_FAILURE,
    stale_after=STALE_AFTER,
)
