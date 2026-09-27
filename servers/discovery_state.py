"""What the dashboard shows about a server's discovery, decided in one place.

Views build a ``DiscoveryState`` from the server's latest attempt, its current snapshot and
whether its alias is usable, then templates render it. Templates never work out from an
attempt whether to poll, whether the snapshot may be out of date, or which action to offer.
"""

from dataclasses import dataclass
from enum import StrEnum, nonmember

from discovery.models import DiscoveryAttempt
from discovery.snapshot import Snapshot

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
    AttemptStatus.SUCCEEDED: (
        "Connection verified. Operating system and capacity observations are ready."
    ),
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


def connection_status(attempt_status: str | None, *, alias_usable: bool) -> Status:
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
class DiscoveryState:
    """A server's discovery as the operator sees it on the server page."""

    attempt: DiscoveryAttempt | None
    snapshot: Snapshot | None
    alias_usable: bool

    @property
    def status(self) -> Status:
        """The connection status, shown in the Status row."""
        return connection_status(
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
