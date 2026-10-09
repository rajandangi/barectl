"""docs/architecture.md#request-and-execution-flow"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, nonmember
from functools import cached_property
from typing import Literal

from django.conf import settings
from django.db.models import QuerySet

from discovery.models import ObservationOutcome, WebStackComponent
from discovery.presentation import (
    ShownApplication,
    ShownObservation,
    ShownSite,
    SnapshotPresentation,
    present,
    present_application,
    present_sites,
)
from discovery.services import history, latest_attempt_statuses, read_discovery
from discovery.snapshot import AttemptSnapshot, Snapshot
from operations.models import RemoteOperation

from .models import Server
from .ssh_config import AliasCatalog, load_aliases

AttemptStatus = RemoteOperation.Status


class Status(StrEnum):
    """A server's connection status, as GLOSSARY.md defines it, in the pages' wording."""

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
# Discovery is read-only and never reconciles, so an active attempt is queued or running.
_ACTIVE = (Status.QUEUED, Status.RUNNING)
_ANNOUNCEMENTS = {
    Status.QUEUED: "Connection check queued.",
    Status.RUNNING: "Checking the connection.",
    Status.FAILED: "The connection failed.",
    Status.VERIFIED: "Connection verified. The new observations are ready.",
}


@dataclass(frozen=True)
class SnapshotNotice:
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
    return _ATTEMPT_STATUS[AttemptStatus(stored)]


def _connection_status(attempt_status: Status | None, *, alias_usable: bool) -> Status:
    if attempt_status in _ACTIVE:
        return attempt_status
    if not alias_usable:
        return Status.UNAVAILABLE
    return Status.NOT_VERIFIED if attempt_status is None else attempt_status


@dataclass(frozen=True)
class ServerRow:
    server: Server
    status: Status


@dataclass(frozen=True)
class SitePage:
    """A site from its server's last complete observation, or why it cannot be shown."""

    identifier: str
    site: ShownSite | None
    # "missing" when the last complete collection confirms absence; "unknown" when no
    # complete observation can decide; empty when the site was found.
    absence: Literal["", "missing", "unknown"]
    # Why the observation may be out of date: a later check is in progress or failed.
    stale: SnapshotNotice | None = None

    @property
    def found(self) -> bool:
        return self.site is not None

    @property
    def current(self) -> bool:
        """Whether the site may be changed: found in an observation no later check doubts."""
        return self.found and self.stale is None


def site_page(state: DiscoveryState, identifier: str) -> SitePage:
    """Resolve ``identifier`` within ``state``'s last complete observation, if any.

    docs/dashboard-workflows.md#site-pages
    """
    snapshot = state.snapshot
    stale = state.snapshot_notice
    if snapshot is None:
        return SitePage(identifier, None, "unknown", stale)
    sites = snapshot.collected.sites
    if sites.outcome != ObservationOutcome.OBSERVED:
        return SitePage(identifier, None, "unknown", stale)
    for site in present_sites(sites).sites:
        if site.identifier == identifier:
            return SitePage(identifier, site, "", stale)
    return SitePage(identifier, None, "missing", stale)


def site_application(state: DiscoveryState, identifier: str) -> ShownApplication | None:
    """The passive WordPress evidence of ``identifier`` in the last complete observation.

    Only a caller that checked the application view permission may show it
    (docs/wordpress.md#passive-application-discovery).
    """
    snapshot = state.snapshot
    if snapshot is None:
        return None
    return next(
        (
            present_application(site)
            for site in snapshot.collected.sites.value
            if site.identifier == identifier
        ),
        None,
    )


@dataclass(frozen=True)
class AttemptView:
    operation_id: int
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
    def is_preparation(self) -> bool:
        """Activity lists plan preparations beside attempts; this tells them apart."""
        return False

    @property
    def is_apply(self) -> bool:
        """Activity lists apply runs beside attempts; this tells them apart."""
        return False

    @property
    def warnings(self) -> list[ShownObservation]:
        return present(self.snapshot.collected).warnings if self.snapshot else []


def _view(recorded: AttemptSnapshot) -> AttemptView:
    attempt, snapshot = recorded
    return AttemptView(
        operation_id=attempt.pk,
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
    server: Server
    # The latest attempt, or ``None`` before the first one was queued.
    attempt: AttemptView | None
    # The snapshot the latest successful attempt published, whatever became of later ones.
    snapshot: Snapshot | None
    # Every recorded attempt for the server, newest recorded first.
    history: list[AttemptView]
    alias_usable: bool
    # Another kind of remote operation, such as a plan preparation, is active for the
    # server. It blocks a check without the page naming what it is.
    other_active: bool = False

    @cached_property
    def presentation(self) -> SnapshotPresentation | None:
        return present(self.snapshot.collected) if self.snapshot else None

    @property
    def hosting_guidance(self) -> Literal["refresh", "inspect", "setup", "sites"]:
        if not self.alias_usable or self.snapshot is None or self.snapshot_notice is not None:
            return "refresh"
        components = {
            item.component: item
            for item in self.snapshot.collected.components
            if item.component in (WebStackComponent.NGINX, WebStackComponent.PHP_FPM)
        }
        if len(components) != 2 or any(
            item.package.outcome
            in (ObservationOutcome.INACCESSIBLE, ObservationOutcome.UNSUPPORTED)
            or item.service.outcome
            in (ObservationOutcome.INACCESSIBLE, ObservationOutcome.UNSUPPORTED)
            for item in components.values()
        ):
            return "inspect"
        if any(item.package.outcome == ObservationOutcome.ABSENT for item in components.values()):
            return "setup"
        return "sites"

    @property
    def status(self) -> Status:
        return _connection_status(
            self.attempt.status if self.attempt else None, alias_usable=self.alias_usable
        )

    @property
    def checking(self) -> bool:
        return self.attempt is not None and self.attempt.status in _ACTIVE

    @property
    def polling(self) -> bool:
        return self.checking or self.other_active

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
        if self.attempt is None:
            return None
        if self.attempt.status == Status.FAILED:
            return _CHECK_FAILED
        if self.checking:
            return _CHECKING
        return None

    @property
    def shown(self) -> str:
        """The token a polling page sends back to say which state it shows."""
        return self.attempt.status.name if self.attempt else ""

    @property
    def poll_token(self) -> str:
        """The token the polling request sends, which also says whether the server was busy.

        Only the attempt's part decides what is announced; the fragment itself is replaced
        on every poll, so the check action returns when another operation finishes.
        """
        return f"{self.shown}.busy" if self.other_active else self.shown

    def changed_since(self, shown: str | None) -> bool:
        """Whether the latest attempt's state differs from ``shown``, the token the page sent."""
        attempt_part = (shown or "").removesuffix(".busy")
        return self.attempt is not None and self.shown != attempt_part

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
    active = discovery.active
    return DiscoveryState(
        server,
        listed[0] if listed else None,
        discovery.snapshot,
        listed,
        alias_usable=usable,
        other_active=active is not None and active.kind != RemoteOperation.Kind.DISCOVERY,
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
