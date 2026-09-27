"""What the dashboard shows about a server's discovery, read and decided in one place.

Views call ``server_state`` for a server's page and ``inventory`` for the server list, then
templates render the result. Both read the server's discovery, which recovers abandoned
attempts first, and the controller's alias catalogue, since an unusable alias outranks a
finished attempt's outcome. Templates never work out from an attempt whether to poll,
whether the snapshot may be out of date, or which action to offer.
"""

from dataclasses import dataclass
from enum import StrEnum, nonmember

from django.conf import settings
from django.db.models import QuerySet

from discovery.models import DiscoveryAttempt
from discovery.services import latest_attempt_statuses, read_discovery
from discovery.snapshot import AttemptSnapshot, Snapshot, attempt_snapshots

from .models import Server
from .ssh_config import AliasCatalog, load_aliases

AttemptStatus = DiscoveryAttempt.Status


class Status(StrEnum):
    """A server's connection status, as CONTEXT.md defines it, in the pages' wording."""

    # Templates compare with members, such as Status.QUEUED, as with Django's choices.
    do_not_call_in_templates = nonmember(True)

    UNAVAILABLE = "SSH alias unavailable"
    NOT_VERIFIED = "Not verified"
    QUEUED = "Connection check queued"
    RUNNING = "Checking connection"
    FAILED = "Connection failed"
    VERIFIED = "Verified"


_ATTEMPT_STATUS = {
    AttemptStatus.QUEUED: Status.QUEUED,
    AttemptStatus.RUNNING: Status.RUNNING,
    AttemptStatus.FAILED: Status.FAILED,
    AttemptStatus.SUCCEEDED: Status.VERIFIED,
}
# Announced in the page's live region when an attempt's state changes.
_ANNOUNCEMENTS = {
    AttemptStatus.QUEUED: "Connection check queued.",
    AttemptStatus.RUNNING: "Checking the connection.",
    AttemptStatus.FAILED: "The connection failed.",
    AttemptStatus.SUCCEEDED: "Connection verified. The new observations are ready.",
}


@dataclass(frozen=True)
class SnapshotNotice:
    """Why the shown snapshot may be out of date."""

    text: str
    # A failed check deserves more attention than one still in progress.
    emphasized: bool


_CHECK_FAILED = SnapshotNotice(
    "The latest connection check failed, so these observations may be out of date.",
    emphasized=True,
)
_CHECKING = SnapshotNotice(
    "A new connection check is running; these observations may be out of date.",
    emphasized=False,
)


def _connection_status(attempt_status: str | None, *, alias_usable: bool) -> Status:
    """The connection status for a server whose latest attempt has ``attempt_status``.

    An active check is reported even when the alias has since become unusable, since the
    check runs with the alias it was queued with. Registration alone never claims
    connectivity; only a completed check does.
    """
    if attempt_status in DiscoveryAttempt.ACTIVE:
        return _ATTEMPT_STATUS[AttemptStatus(attempt_status)]
    if not alias_usable:
        return Status.UNAVAILABLE
    return _ATTEMPT_STATUS[AttemptStatus(attempt_status)] if attempt_status else Status.NOT_VERIFIED


@dataclass(frozen=True)
class ServerRow:
    """One server in the inventory, with its connection status."""

    server: Server
    status: Status


@dataclass(frozen=True)
class DiscoveryState:
    """A server's discovery as the operator sees it on the server page."""

    server: Server
    # The latest attempt, or ``None`` before the first one was queued.
    attempt: DiscoveryAttempt | None
    # The snapshot the latest successful attempt published, whatever became of later ones.
    snapshot: Snapshot | None
    alias_usable: bool

    def history(self) -> list[AttemptSnapshot]:
        """Every recorded attempt for the server, newest first, with its published snapshot.

        Abandoned attempts were already recovered when the state was read.
        """
        return attempt_snapshots(self.server.discovery_attempts.all())

    @property
    def status(self) -> Status:
        """The connection status, shown in the Status row."""
        return _connection_status(
            self.attempt.status if self.attempt else None, alias_usable=self.alias_usable
        )

    @property
    def attempt_status(self) -> Status:
        """The latest attempt's state in the pages' wording, whatever the alias's state."""
        if self.attempt is None:
            return Status.NOT_VERIFIED
        return _ATTEMPT_STATUS[AttemptStatus(self.attempt.status)]

    @property
    def polling(self) -> bool:
        """Whether the page keeps asking for updates: only while a check is active."""
        return self.attempt is not None and self.attempt.is_active

    @property
    def can_request(self) -> bool:
        """Whether another check may be requested now, permissions aside."""
        return not self.polling

    @property
    def action_label(self) -> str:
        if self.attempt is not None and self.attempt.status == AttemptStatus.FAILED:
            return "Retry connection check"
        if self.attempt is not None and self.attempt.status == AttemptStatus.SUCCEEDED:
            return "Refresh observations"
        return "Verify connection"

    @property
    def snapshot_notice(self) -> SnapshotNotice | None:
        """Why the snapshot may be out of date, or ``None`` when nothing suggests it."""
        if self.attempt is None:
            return None
        if self.attempt.status == AttemptStatus.FAILED:
            return _CHECK_FAILED
        if self.polling:
            return _CHECKING
        return None

    def changed_since(self, shown: str | None) -> bool:
        """Whether the latest attempt's state differs from ``shown``, the one the page shows."""
        return self.attempt is not None and self.attempt.status != shown

    @property
    def announcement(self) -> str:
        """What the page's live region says when the state changes."""
        return _ANNOUNCEMENTS[AttemptStatus(self.attempt.status)] if self.attempt else ""


def _catalog(aliases: set[str]) -> AliasCatalog:
    # Read on every request: the operator may change the controller's configuration. Only
    # the aliases shown are resolved, not every Host entry.
    return load_aliases(settings.SSH_CONFIG_PATH, aliases)


def server_state(server: Server) -> DiscoveryState:
    """The server's discovery for its page, after recovering abandoned attempts."""
    attempt, snapshot = read_discovery(server)
    usable = server.ssh_alias in _catalog({server.ssh_alias})
    return DiscoveryState(server, attempt, snapshot, alias_usable=usable)


def inventory(servers: QuerySet[Server]) -> list[ServerRow]:
    """Each of ``servers`` with its connection status, after recovering abandoned attempts."""
    listed = latest_attempt_statuses(servers)
    catalog = _catalog({server.ssh_alias for server, _ in listed})
    return [
        ServerRow(server, _connection_status(status, alias_usable=server.ssh_alias in catalog))
        for server, status in listed
    ]
