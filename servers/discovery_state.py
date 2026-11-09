"""docs/architecture.md#request-and-execution-flow"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, nonmember
from functools import cached_property
from typing import Literal

from django.conf import settings
from django.db.models import QuerySet
from django.utils import timezone

from contract.recognition import Recognition, recognize
from discovery.models import ObservationOutcome
from discovery.presentation import (
    ShownObservation,
    ShownSite,
    ShownSites,
    SnapshotPresentation,
    present,
    present_sites,
    summary_warnings,
)
from discovery.services import STALE_AFTER, history, latest_attempt_statuses, read_discovery
from discovery.snapshot import AttemptSummary, Observation, ObservedSite, Snapshot, SnapshotFacts
from operations.check_progress import CheckView, present_check
from operations.models import RemoteOperation
from operations.services import ServerChanges, read_changes

from .connections import connection_label
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
    if snapshot.collected.sites.outcome != ObservationOutcome.OBSERVED:
        return SitePage(identifier, None, "unknown", stale)
    site = state.shown_site(identifier)
    if site is not None:
        return SitePage(identifier, site, "", stale)
    return SitePage(identifier, None, "missing", stale)


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
    # A summary of the snapshot the attempt published, if it succeeded and still holds one.
    snapshot: SnapshotFacts | None

    connection_revision: int = 0
    original_target: str = ""
    check: CheckView | None = None

    @property
    def older_connection(self) -> bool:
        return self.connection_revision != self.server.connection_revision

    @property
    def worker_unavailable(self) -> bool:
        return self.status == Status.QUEUED and self.queued_at < timezone.now() - STALE_AFTER

    @property
    def collected_at(self) -> datetime | None:
        return self.snapshot.collected_at if self.snapshot else None

    @property
    def os_pretty_name(self) -> str:
        return self.snapshot.os_pretty_name if self.snapshot else ""

    @cached_property
    def warnings(self) -> tuple[ShownObservation, ...]:
        return summary_warnings(self.snapshot)


def _view(recorded: AttemptSummary) -> AttemptView:
    attempt, snapshot = recorded
    return AttemptView(
        operation_id=attempt.pk,
        server=attempt.server,
        status=_wording(attempt.status),
        ssh_alias=connection_label(attempt),
        queued_at=attempt.queued_at,
        started_at=attempt.started_at,
        finished_at=attempt.finished_at,
        failure=attempt.failure,
        host_key=attempt.host_key,
        snapshot=snapshot,
        connection_revision=attempt.connection.revision if attempt.connection else 0,
        original_target=(attempt.connection.target_label if attempt.connection else ""),
        check=present_check(attempt) if attempt.status in RemoteOperation.ACTIVE else None,
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
    # The server's change activity, read once with the rest of this read.
    changes: ServerChanges
    # Another kind of remote operation, such as a plan preparation, is active for the
    # server. It blocks a check without the page naming what it is.
    other_active: bool = False
    # That other operation, for pages that link to it.
    other_operation: RemoteOperation | None = None

    @cached_property
    def sites(self) -> ShownSites:
        """The site observations presented once for this read."""
        collected = (
            self.snapshot.collected.sites
            if self.snapshot is not None
            else Observation(ObservationOutcome.ABSENT, (), "", ())
        )
        return present_sites(collected)

    @cached_property
    def observed_sites(self) -> dict[str, ObservedSite]:
        """The snapshot's site rows keyed by identifier, for a section's own lookups."""
        if self.snapshot is None:
            return {}
        return {site.identifier: site for site in self.snapshot.collected.sites.value}

    def site(self, identifier: str) -> ObservedSite | None:
        """One site's observed row, without scanning the snapshot's site list."""
        return self.observed_sites.get(identifier)

    @cached_property
    def site_index(self) -> dict[str, ShownSite]:
        """The presented sites keyed by identifier, for the page's one site view."""
        return {site.identifier: site for site in self.sites.sites}

    def shown_site(self, identifier: str) -> ShownSite | None:
        return self.site_index.get(identifier)

    @cached_property
    def outside_contract(self) -> bool:
        """Whether a retained result line names a contract version this controller cannot act on.

        The version is native evidence from Jobs; discovery never writes a server-side
        marker (ADR 0042).
        """
        if self.snapshot is None:
            return False
        collected = self.snapshot.collected
        standing = collected.standing
        return (
            recognize(
                (change.contract for change in collected.jobs.value.changes),
                standing.standing.value if standing is not None else None,
            )
            is not Recognition.RECOGNIZED
        )

    @cached_property
    def presentation(self) -> SnapshotPresentation | None:
        return present(self.snapshot.collected) if self.snapshot else None

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
        token = self.shown
        if self.attempt is not None and self.attempt.check is not None:
            token = f"{token}~{self.attempt.check.token}"
        return f"{token}.busy" if self.other_active else token

    def changed_since(self, shown: str | None) -> bool:
        """Whether the latest attempt's state differs from ``shown``, the token the page sent."""
        attempt_part = (shown or "").removesuffix(".busy")
        status, _, progress = attempt_part.partition("~")
        return self.attempt is not None and (
            self.shown != status
            or bool(progress and self.attempt.check and self.attempt.check.token != progress)
        )

    @property
    def announcement(self) -> str:
        """What the page's live region says when the state changes."""
        if self.attempt is not None and self.attempt.check is not None:
            check = self.attempt.check
            return (
                f"{_ANNOUNCEMENTS[self.attempt.status]} {check.label}. "
                f"{check.reads} server reads finished."
            )
        return _ANNOUNCEMENTS[self.attempt.status] if self.attempt else ""


def _catalog(aliases: set[str]) -> AliasCatalog:
    # Read on every request: the operator may change the controller's configuration. Only
    # the aliases shown are resolved, not every Host entry.
    return load_aliases(settings.SSH_CONFIG_PATH, aliases)


def server_state(server: Server) -> DiscoveryState:
    """The server's discovery for its page, after recovering abandoned attempts."""
    discovery = read_discovery(server)
    listed = [_view(recorded) for recorded in discovery.history]
    usable = server.connection_mode != "alias" or server.ssh_alias in _catalog({server.ssh_alias})
    active = discovery.active
    return DiscoveryState(
        server,
        next(
            (
                item
                for item in listed
                if discovery.attempt is not None and item.operation_id == discovery.attempt.pk
            ),
            None,
        ),
        discovery.snapshot,
        listed,
        alias_usable=usable,
        changes=read_changes(server),
        other_active=active is not None and active.kind != RemoteOperation.Kind.DISCOVERY,
        other_operation=(
            active if active is not None and active.kind != RemoteOperation.Kind.DISCOVERY else None
        ),
    )


def inventory(servers: QuerySet[Server]) -> list[ServerRow]:
    """Each of ``servers`` with its connection status, after recovering abandoned attempts."""
    listed = latest_attempt_statuses(servers)
    catalog = _catalog(
        {server.ssh_alias for server, _ in listed if server.connection_mode == "alias"}
    )
    return [
        ServerRow(
            server,
            _connection_status(
                _wording(stored) if stored else None,
                alias_usable=server.connection_mode != "alias" or server.ssh_alias in catalog,
            ),
        )
        for server, stored in listed
    ]


def activity_rows() -> list[AttemptView]:
    """Every server's recorded attempts for Activity, after recovering abandoned attempts."""
    return [_view(recorded) for recorded in history()]
