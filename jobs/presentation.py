"""The one Jobs read: groups, plain words, details and coverage (Phase E #285).

Templates lay out this projection and never interpret a native observation. Change rows,
their details and their links need ``operations.view_changes``; without it the view keeps
the page, the last-checked time and a plain notice, and exposes no row text or count.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Final, Literal

from django.urls import reverse

from bootstrap.standing import Standing
from discovery.models import ObservationOutcome
from discovery.snapshot import Snapshot
from operations import engine
from operations.models import ChangeRun
from servers.models import Server

from .models import Coverage
from .observation import ObservedChange, ProviderCoverage

Group = Literal["attention", "running", "automatic", "recent"]

FORBIDDEN = "Your account may view this server but not its changes."
NOT_TARGET_STACK = "Jobs reads only servers that Barectl manages on its supported stack."
EMPTY = (
    "Jobs shows what the server itself says about Barectl's changes. Run a check to read "
    "it for the first time."
)
NO_OBSERVATION = "No Jobs observations have been read yet. Run a check to read them."
AUTOMATIC_EMPTY = "Automatic work will appear here when a later phase reads it."

_RESULT_LABELS: Final[dict[str, str]] = {
    "succeeded": "Finished",
    "partial": "Partly applied",
    "refused": "Refused",
    "failed": "Failed",
    "timed_out": "Timed out",
    "lock_busy": "Skipped because other work held the server",
}
_FAILED = frozenset({"partial", "refused", "failed", "timed_out", "lock_busy", ""})


@dataclass(frozen=True)
class CoverageNotice:
    """One provider's coverage, worded; ``oldest_at`` is the server's oldest held time."""

    text: str
    oldest_at: datetime | None = None


@dataclass(frozen=True)
class JobRow:
    key: str
    title: str
    sites: tuple[str, ...]
    summary: str
    result_class: str
    reason: str
    unit: str
    invocation: str
    started_at: datetime | None
    finished_at: datetime | None
    run_url: str = ""
    other_controller: bool = False
    needs_attention: bool = False
    running: bool = False

    @property
    def when(self) -> datetime | None:
        return self.finished_at or self.started_at

    @property
    def detail_lines(self) -> tuple[tuple[str, str], ...]:
        return (
            ("Unit", self.unit),
            ("Invocation", self.invocation or "Not reported"),
            ("Result class", self.result_class or "No result line"),
            ("Reason", self.reason or "Not reported"),
        )


@dataclass(frozen=True)
class JobGroup:
    key: Group
    title: str
    rows: tuple[JobRow, ...]
    empty: str = ""


@dataclass(frozen=True)
class JobsView:
    last_checked: datetime | None
    may_view_changes: bool
    target_stack: bool
    groups: tuple[JobGroup, ...] = ()
    notices: tuple[CoverageNotice, ...] = ()
    empty: str = ""
    automatic_empty: str = AUTOMATIC_EMPTY


def present(snapshot: Snapshot | None, server: Server, *, may_view_changes: bool) -> JobsView:
    """The section's groups, notices and details from one stored snapshot."""
    if snapshot is None:
        return JobsView(None, may_view_changes, True, empty=EMPTY)
    standing = snapshot.collected.standing
    target = standing is not None and standing.standing == Standing.TARGET_STACK
    if not may_view_changes:
        return JobsView(snapshot.collected_at, False, target)
    if not target:
        return JobsView(snapshot.collected_at, True, False)
    observation = snapshot.collected.jobs
    if observation.outcome != ObservationOutcome.OBSERVED:
        return JobsView(snapshot.collected_at, True, True, empty=NO_OBSERVATION)
    reading = observation.value
    rows = _rows(reading.changes, server)
    return JobsView(
        last_checked=snapshot.collected_at,
        may_view_changes=True,
        target_stack=True,
        groups=(
            JobGroup(
                "attention",
                "Needs attention",
                tuple(row for row in rows if row.needs_attention),
                "No Barectl changes need attention.",
            ),
            JobGroup(
                "running",
                "Running",
                tuple(row for row in rows if row.running),
                "No Barectl change was running when the server was last checked.",
            ),
            JobGroup("automatic", "Automatic work", ()),
            JobGroup(
                "recent",
                "Recent results",
                tuple(row for row in rows if not row.running),
                "No available Barectl change results.",
            ),
        ),
        notices=_notices(reading.coverage),
    )


def _rows(changes: tuple[ObservedChange, ...], server: Server) -> tuple[JobRow, ...]:
    runs = _local_runs(changes, server)
    return tuple(_row(change, runs.get((change.unit, change.invocation_id))) for change in changes)


def _local_runs(changes: tuple[ObservedChange, ...], server: Server) -> dict[tuple[str, str], int]:
    """The run this installation recorded for each unit and invocation, in one query."""
    units = {change.unit for change in changes}
    keys = {(change.unit, change.invocation_id) for change in changes}
    if not units:
        return {}
    found = ChangeRun.objects.filter(server=server, unit_name__in=units).values_list(
        "pk", "unit_name", "invocation_id"
    )
    return {
        (unit, invocation): pk
        for pk, unit, invocation in found
        if invocation and (unit, invocation) in keys
    }


def _row(change: ObservedChange, run_id: int | None) -> JobRow:
    kind = engine.kind_of(change.kind_slug) if change.kind_slug else None
    title = kind.label if kind is not None else "A Barectl change"
    summary = _summary(change)
    return JobRow(
        key=f"{change.unit}:{change.invocation_id}",
        title=title,
        sites=change.sites,
        summary=summary,
        result_class=change.result_class,
        reason=engine.reason_text(change.result_class, change.reason) if change.reason else "",
        unit=change.unit,
        invocation=change.invocation_id,
        started_at=change.started_at,
        finished_at=change.finished_at,
        run_url=reverse("run_detail", args=(run_id,)) if run_id is not None else "",
        other_controller=run_id is None,
        needs_attention=not change.running and change.result_class in _FAILED,
        running=change.running,
    )


def _summary(change: ObservedChange) -> str:
    if change.running:
        return "Running when the server was last checked."
    label = _RESULT_LABELS.get(change.result_class)
    if label is None:
        return "Could not confirm"
    if change.result_class == "refused":
        reason = engine.reason_text(change.result_class, change.reason)
        return f"{label}: {reason}" if reason else label
    return label


def _notices(coverage: tuple[ProviderCoverage, ...]) -> tuple[CoverageNotice, ...]:
    notices: list[CoverageNotice] = []
    for item in coverage:
        if item.state == Coverage.COMPLETE:
            continue
        if item.warning:
            notices.append(CoverageNotice(item.warning, item.oldest_at))
        if item.oldest_at is not None:
            notices.append(
                CoverageNotice(
                    "The server's retained change history starts",
                    item.oldest_at,
                )
            )
    return tuple(notices)
