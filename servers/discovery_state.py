"""What the dashboard shows about a server's discovery, read and decided in one place.

Views call ``server_state`` for a server's page, ``inventory`` for the server list and
``activity_rows`` for Activity, then templates render the result. Each read recovers abandoned
attempts first. The page and the list also read the controller's alias catalogue, since an
unusable alias outranks a finished attempt's outcome. Templates receive attempts as
``AttemptView``, in the pages' wording, and never work out from an attempt whether to poll,
whether the snapshot may be out of date, or which action to offer.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, nonmember
from functools import cached_property

from django.conf import settings
from django.db.models import QuerySet

from discovery.models import DiscoveryAttempt
from discovery.presentation import ShownObservation, SnapshotPresentation, present
from discovery.services import history, latest_attempt_statuses, read_discovery
from discovery.snapshot import AttemptSnapshot, Snapshot

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
_ACTIVE = tuple(_ATTEMPT_STATUS[status] for status in DiscoveryAttempt.ACTIVE)
# Announced in the page's live region when an attempt's state changes.
_ANNOUNCEMENTS = {
    Status.QUEUED: "Connection check queued.",
    Status.RUNNING: "Checking the connection.",
    Status.FAILED: "The connection failed.",
    Status.VERIFIED: "Connection verified. The new observations are ready.",
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


def _wording(stored: str) -> Status:
    """An attempt's stored state in the pages' wording."""
    return _ATTEMPT_STATUS[AttemptStatus(stored)]


def _connection_status(attempt_status: Status | None, *, alias_usable: bool) -> Status:
    """The connection status for a server whose latest attempt shows ``attempt_status``.

    An active check is reported even when the alias has since become unusable, since the
    check runs with the alias it was queued with. Registration alone never claims
    connectivity; only a completed check does.
    """
    if attempt_status in _ACTIVE:
        return attempt_status
    if not alias_usable:
        return Status.UNAVAILABLE
    return Status.NOT_VERIFIED if attempt_status is None else attempt_status


@dataclass(frozen=True)
class ServerRow:
    """One server in the inventory, with its connection status."""

    server: Server
    status: Status


@dataclass(frozen=True)
class AttemptView:
    """One discovery attempt as the pages show it, whichever page lists it."""

    server: Server
    # The attempt's own state; the alias's state never changes it.
    status: Status
    ssh_alias: str
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    failure: str
    host_key: str
    # The snapshot the attempt published, if it succeeded and is still the current one.
    snapshot: Snapshot | None

    @property
    def warnings(self) -> list[ShownObservation]:
        """The published snapshot's warnings about what could not be inspected."""
        return present(self.snapshot.collected).warnings if self.snapshot else []


def _view(recorded: AttemptSnapshot) -> AttemptView:
    attempt, snapshot = recorded
    return AttemptView(
        server=attempt.server,
        status=_wording(attempt.status),
        ssh_alias=attempt.ssh_alias,
        queued_at=attempt.queued_at,
        started_at=attempt.started_at,
        finished_at=attempt.finished_at,
        failure=attempt.failure,
        host_key=attempt.host_key,
        snapshot=snapshot,
    )


@dataclass(frozen=True)
class DiscoveryState:
    """A server's discovery as the operator sees it on the server page."""

    server: Server
    # The latest attempt, or ``None`` before the first one was queued.
    attempt: AttemptView | None
    # The snapshot the latest successful attempt published, whatever became of later ones.
    snapshot: Snapshot | None
    # Every recorded attempt for the server, newest recorded first.
    history: list[AttemptView]
    alias_usable: bool

    @cached_property
    def presentation(self) -> SnapshotPresentation | None:
        """The snapshot's observations as the page shows them."""
        return present(self.snapshot.collected) if self.snapshot else None

    @property
    def status(self) -> Status:
        """The connection status, shown in the Status row."""
        return _connection_status(
            self.attempt.status if self.attempt else None, alias_usable=self.alias_usable
        )

    @property
    def polling(self) -> bool:
        """Whether the page keeps asking for updates: only while a check is active."""
        return self.attempt is not None and self.attempt.status in _ACTIVE

    @property
    def can_request(self) -> bool:
        """Whether another check may be requested now, permissions aside."""
        return not self.polling

    @property
    def action_label(self) -> str:
        if self.attempt is not None and self.attempt.status == Status.FAILED:
            return "Retry connection check"
        if self.attempt is not None and self.attempt.status == Status.VERIFIED:
            return "Refresh observations"
        return "Verify connection"

    @property
    def snapshot_notice(self) -> SnapshotNotice | None:
        """Why the snapshot may be out of date, or ``None`` when nothing suggests it."""
        if self.attempt is None:
            return None
        if self.attempt.status == Status.FAILED:
            return _CHECK_FAILED
        if self.polling:
            return _CHECKING
        return None

    @property
    def shown(self) -> str:
        """The token a polling page sends back to say which state it shows."""
        return self.attempt.status.name if self.attempt else ""

    def changed_since(self, shown: str | None) -> bool:
        """Whether the latest attempt's state differs from ``shown``, the token the page sent."""
        return self.attempt is not None and self.shown != shown

    @property
    def announcement(self) -> str:
        """What the page's live region says when the state changes."""
        return _ANNOUNCEMENTS[self.attempt.status] if self.attempt else ""


def _catalog(aliases: set[str]) -> AliasCatalog:
    # Read on every request: the operator may change the controller's configuration. Only
    # the aliases shown are resolved, not every Host entry.
    return load_aliases(settings.SSH_CONFIG_PATH, aliases)


def server_state(server: Server) -> DiscoveryState:
    """The server's discovery for its page, after recovering abandoned attempts."""
    discovery = read_discovery(server)
    listed = [_view(recorded) for recorded in discovery.history]
    usable = server.ssh_alias in _catalog({server.ssh_alias})
    return DiscoveryState(
        server,
        listed[0] if listed else None,
        discovery.snapshot,
        listed,
        alias_usable=usable,
    )


def inventory(servers: QuerySet[Server]) -> list[ServerRow]:
    """Each of ``servers`` with its connection status, after recovering abandoned attempts."""
    listed = latest_attempt_statuses(servers)
    catalog = _catalog({server.ssh_alias for server, _ in listed})
    return [
        ServerRow(
            server,
            _connection_status(
                _wording(stored) if stored else None, alias_usable=server.ssh_alias in catalog
            ),
        )
        for server, stored in listed
    ]


def activity_rows() -> list[AttemptView]:
    """Every server's recorded attempts for Activity, after recovering abandoned attempts."""
    return [_view(recorded) for recorded in history()]
