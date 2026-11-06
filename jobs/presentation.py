"""The one Jobs read: groups, plain words, details and coverage (Phase E #285).

Templates lay out this projection and never interpret a native observation. Change rows,
their details and their links need ``operations.view_changes``; without it the view keeps
the page, the last-checked time and a plain notice, and exposes no row text or count.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from django.urls import reverse
from django.utils import timezone

from bootstrap.standing import Standing
from discovery.models import ObservationOutcome
from discovery.snapshot import Snapshot
from operations import engine
from operations.models import ChangeRun
from servers.models import Server

from . import results
from .automatic import AutomaticRow, automatic_work
from .backups import BackupRunRow, BackupTimerRow, BackupWork, backup_work
from .filters import Filtered, Filters, Selection, filter_recent, start_of_range
from .models import Coverage
from .observation import ObservedChange, ProviderCoverage
from .timezones import DisplayZone, resolve_zone

Group = Literal["attention", "running", "automatic", "recent"]

FORBIDDEN = "Your account may view this server but not its changes."
NOT_TARGET_STACK = "Jobs reads only servers that Barectl manages on its supported stack."
EMPTY = (
    "Jobs shows what the server itself says about Barectl's changes. Run a check to read "
    "it for the first time."
)
NO_OBSERVATION = "No Barectl change observations have been read yet. Run a check to read them."
ATTENTION_EMPTY = "No Barectl changes, automatic work or backups need attention."
AUTOMATIC_ATTENTION_EMPTY = "No automatic work or backups need attention."
AUTOMATIC_EMPTY = (
    "No scheduled tasks, queue workers, object cache or backup schedules were found on this server."
)
NOT_READ = "Automatic work is read by a full check of this server. Run a check to read it."
RECENT_EMPTY = "No available Barectl change or backup results."
FILTERED_EMPTY = "No available Barectl change or backup results match these filters."


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
    work_type: str = ""
    result_evidence: engine.ResultEvidence = engine.ResultEvidence.ABSENT

    @property
    def when(self) -> datetime | None:
        return self.finished_at or self.started_at

    @property
    def detail_lines(self) -> tuple[tuple[str, str], ...]:
        return (
            ("Unit", self.unit),
            ("Invocation", self.invocation or "Not reported"),
            (
                "Result class",
                (
                    engine.UNREADABLE_RESULT
                    if self.result_evidence is engine.ResultEvidence.UNREADABLE
                    else self.result_class or "No result line"
                ),
            ),
            ("Reason", self.reason or "Not reported"),
            ("Started", self.started_at.isoformat() if self.started_at else "Not reported"),
            ("Finished", self.finished_at.isoformat() if self.finished_at else "Not reported"),
        )


@dataclass(frozen=True)
class JobGroup:
    key: Group
    title: str
    rows: tuple[JobRow | AutomaticRow | BackupRunRow | BackupTimerRow, ...]
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
    zone: DisplayZone = field(default_factory=lambda: resolve_zone(None))
    filters: Filters | None = None


def present(
    snapshot: Snapshot | None,
    server: Server,
    *,
    may_view_changes: bool,
    selection: Selection | None = None,
    zone: DisplayZone | None = None,
    now: datetime | None = None,
) -> JobsView:
    """The section's groups, notices and details from one stored snapshot.

    ``selection`` and ``zone`` narrow only Recent results and the displayed times. They
    never change Needs attention, Running, what the server keeps or what it runs.
    """
    selected = selection if selection is not None else Selection()
    displayed = zone if zone is not None else resolve_zone(None)
    if snapshot is None:
        return JobsView(None, may_view_changes, True, empty=EMPTY, zone=displayed)
    standing = snapshot.collected.standing
    target = standing is not None and standing.standing == Standing.TARGET_STACK
    if not target:
        return JobsView(snapshot.collected_at, may_view_changes, False, zone=displayed)
    observation = snapshot.collected.jobs
    full_read = observation.outcome == ObservationOutcome.OBSERVED
    work = automatic_work(snapshot, server)
    backups = backup_work(snapshot, server)
    automatic_rows: tuple[AutomaticRow | BackupTimerRow, ...] = (*work.rows, *backups.timers)
    automatic_empty = _automatic_empty(full_read, work.warnings, automatic_rows, backups)
    automatic = JobGroup("automatic", "Automatic work", automatic_rows, automatic_empty)
    attention: tuple[JobRow | AutomaticRow | BackupRunRow, ...] = (
        *(row for row in work.rows if row.needs_attention),
        *(row for row in backups.runs if row.needs_attention),
    )
    provider_notices = tuple(
        CoverageNotice(text=text) for text in (*work.warnings, *backups.warnings)
    )
    attention_groups: tuple[JobGroup, ...] = (
        *(
            (JobGroup("attention", "Needs attention", attention, AUTOMATIC_ATTENTION_EMPTY),)
            if attention
            else ()
        ),
    )
    recent_backups = backups.runs
    if not may_view_changes:
        return JobsView(
            last_checked=snapshot.collected_at,
            may_view_changes=False,
            target_stack=True,
            groups=(
                *attention_groups,
                automatic,
                *(
                    (JobGroup("recent", "Recent results", recent_backups, RECENT_EMPTY),)
                    if recent_backups
                    else ()
                ),
            ),
            notices=provider_notices,
            automatic_empty=automatic_empty,
            zone=displayed,
        )
    if not full_read:
        return JobsView(
            last_checked=snapshot.collected_at,
            may_view_changes=True,
            target_stack=True,
            groups=(
                *attention_groups,
                automatic,
                *(
                    (JobGroup("recent", "Recent results", recent_backups, RECENT_EMPTY),)
                    if recent_backups
                    else ()
                ),
            ),
            notices=provider_notices,
            empty=NO_OBSERVATION,
            automatic_empty=automatic_empty,
            zone=displayed,
        )
    reading = observation.value
    rows = _rows(reading.changes, server)
    attention_rows = (
        *attention,
        *(row for row in rows if row.needs_attention),
    )
    checked_at = now if now is not None else timezone.now()
    filtered: Filtered[JobRow | BackupRunRow] = filter_recent(
        (*tuple(row for row in rows if not row.running), *recent_backups),
        selected,
        now=checked_at,
        zone=displayed.info,
    )
    notices = _notices(
        reading.coverage,
        range_start=start_of_range(selected, now=checked_at, zone=displayed.info),
    )
    if filtered.untimed:
        notices += (CoverageNotice(_untimed_notice(filtered.untimed)),)
    return JobsView(
        last_checked=snapshot.collected_at,
        may_view_changes=True,
        target_stack=True,
        groups=(
            JobGroup("attention", "Needs attention", attention_rows, ATTENTION_EMPTY),
            JobGroup(
                "running",
                "Running",
                tuple(row for row in rows if row.running),
                "No Barectl change was running when the server was last checked.",
            ),
            automatic,
            JobGroup(
                "recent",
                "Recent results",
                filtered.rows,
                FILTERED_EMPTY if selected.active else RECENT_EMPTY,
            ),
        ),
        notices=provider_notices + notices,
        automatic_empty=automatic_empty,
        zone=displayed,
        filters=filtered.filters,
    )


def _automatic_empty(
    full_read: bool,
    warnings: tuple[str, ...],
    rows: tuple[JobRow | AutomaticRow | BackupTimerRow, ...],
    backups: BackupWork,
) -> str:
    if warnings or backups.warnings:
        return ""
    if not full_read:
        return NOT_READ
    return "" if rows else AUTOMATIC_EMPTY


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
        reason=_reason(change),
        unit=change.unit,
        invocation=change.invocation_id,
        started_at=change.started_at,
        finished_at=change.finished_at,
        run_url=reverse("run_detail", args=(run_id,)) if run_id is not None else "",
        other_controller=run_id is None,
        needs_attention=not change.running and change.result_class in results.ATTENTION,
        running=change.running,
        work_type=change.kind_slug,
        result_evidence=change.result_evidence,
    )


def _reason(change: ObservedChange) -> str:
    if change.result_evidence is engine.ResultEvidence.UNREADABLE:
        return engine.UNREADABLE_RESULT_FAILURE
    return engine.reason_text(change.result_class, change.reason) if change.reason else ""


def _summary(change: ObservedChange) -> str:
    if change.running:
        return "Running when the server was last checked."
    if change.result_evidence is engine.ResultEvidence.UNREADABLE:
        return engine.UNREADABLE_RESULT
    label = results.label(change.result_class)
    if change.result_class == "refused":
        reason = engine.reason_text(change.result_class, change.reason)
        return f"{label}: {reason}" if reason else label
    return label


def _untimed_notice(count: int) -> str:
    if count == 1:
        return "1 result has no usable time and is not shown in this range."
    return f"{count} results have no usable time and are not shown in this range."


def _notices(
    coverage: tuple[ProviderCoverage, ...], *, range_start: datetime
) -> tuple[CoverageNotice, ...]:
    """Warnings and the start of the host's retained history when it misses the range."""
    notices: list[CoverageNotice] = []
    for item in coverage:
        if item.warning:
            notices.append(CoverageNotice(item.warning, item.oldest_at))
        if item.oldest_at is not None and (
            item.state != Coverage.COMPLETE or item.oldest_at > range_start
        ):
            notices.append(
                CoverageNotice(
                    "The server's retained change history starts",
                    item.oldest_at,
                )
            )
    return tuple(notices)
