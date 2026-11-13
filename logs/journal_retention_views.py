"""Server Settings: the observed journal retention policy (#549).

docs/adr/0044-own-journald-log-retention-in-a-separate-drop-in.md. The card reads the latest
stored observation only; opening Settings issues no SSH. The change form and prepare route
land with #551.
"""

from dataclasses import dataclass

from django.contrib.auth.models import AnonymousUser, User

from operations import change_requirements, preparation
from servers.discovery_state import DiscoveryState
from servers.preparation import decide_for_server

from .journal_retention import (
    DISK_CAP_LABELS,
    MANAGED,
    MAX_AGE_LABELS,
    NOT_CHECKED,
    NOT_CONFIGURED,
    OUTSIDE,
)


@dataclass(frozen=True)
class JournalRetentionPanel:
    """One card state: what was observed, or that no current observation exists."""

    checked: bool
    state: str
    reason: str = ""
    disk_cap: str = ""
    max_age: str = ""
    disk_cap_label: str = ""
    max_age_label: str = ""
    gate_reason: str = ""

    @property
    def managed(self) -> bool:
        return self.checked and self.state == MANAGED

    @property
    def outside(self) -> bool:
        return self.checked and self.state == OUTSIDE

    @property
    def not_configured(self) -> bool:
        return self.checked and self.state == NOT_CONFIGURED


def context_for_server(
    state: DiscoveryState,
    user: User | AnonymousUser,
) -> dict[str, object]:
    snapshot = state.snapshot
    retention = snapshot.collected.journal_retention if snapshot is not None else None
    checked = snapshot is not None and state.snapshot_notice is None and retention is not None
    decision = (
        decide_for_server(state, user, change_requirements.JOURNAL_RETENTION)
        if isinstance(user, User)
        else preparation.Decision(False)
    )
    panel = JournalRetentionPanel(
        checked=checked,
        state=retention.state if checked and retention is not None else NOT_CHECKED,
        reason=retention.reason if checked and retention is not None else "",
        disk_cap=retention.disk_cap if checked and retention is not None else "",
        max_age=retention.max_age if checked and retention is not None else "",
        disk_cap_label=(
            DISK_CAP_LABELS.get(retention.disk_cap, retention.disk_cap)
            if checked and retention is not None
            else ""
        ),
        max_age_label=(
            MAX_AGE_LABELS.get(retention.max_age, retention.max_age)
            if checked and retention is not None
            else ""
        ),
        gate_reason=decision.sentence,
    )
    return {"journal_retention_panel": panel}
