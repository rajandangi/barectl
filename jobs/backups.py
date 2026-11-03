"""Backup runs and schedules in Jobs, from Phase D's stored observation (#286).

This module reads only the snapshot's existing backup observation: it runs no restic
command, lists no snapshot and contacts no storage. Only Phase D's safe result line reaches
Jobs, so a row holds counts, sizes, a short recovery point and a result class, never a path,
repository URL, credential or dump content.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar, Final

from django.urls import reverse

from backups import presentation as backup_presentation
from backups.observation import (
    BackupResult,
    BackupRun,
    BackupTimer,
    CleanupCounts,
    IntegrityFinding,
    ObservedBackup,
    OffsiteCopy,
)
from discovery.models import ObservationOutcome
from discovery.snapshot import Snapshot
from servers.models import Server

from . import results

CAPTURE: Final = "backup"
COPY: Final = "backup_copy"
CHECK: Final = "backup_check"
CLEANUP: Final = "backup_cleanup"
WORK_TITLE: Final[dict[str, str]] = {
    CAPTURE: "Backup",
    COPY: "Offsite copy",
    CHECK: "Backup check",
    CLEANUP: "Backup cleanup",
}
BACKUP_SCHEDULE: Final = "backup_schedule"
CHECK_SCHEDULE: Final = "backup_check_schedule"
CLEANUP_SCHEDULE: Final = "backup_cleanup_schedule"
TIMER_TITLE: Final[dict[str, str]] = {
    BACKUP_SCHEDULE: "Backup schedule",
    CHECK_SCHEDULE: "Backup check schedule",
    CLEANUP_SCHEDULE: "Backup cleanup schedule",
}
TIMER_WORK: Final[dict[str, str]] = {
    "backup": BACKUP_SCHEDULE,
    "check": CHECK_SCHEDULE,
    "cleanup": CLEANUP_SCHEDULE,
}
UNREADABLE: Final = "Barectl could not read this server's backups."
NO_BACKUPS: Final = "No backup runs or schedules were found on this server."
COULD_NOT_CONFIRM: Final = "Could not confirm this run finished."
NO_RESULT_LINE: Final = "The server kept no result line for this run."
TRUNCATED_RUNS: Final = "Some older backup runs are not shown, so this list is not complete."
TRUNCATED_TIMERS: Final = "Some backup schedules are not shown, so this list is not complete."
# Phase D's own wording differs for a few classes; the class-to-key mapping is shared.
_RESULT_LABELS: Final[dict[str, str]] = {
    "succeeded": "Finished",
    "partial": "Partly saved",
    "failed": "Failed",
    "refused": "Failed",
    "lock_busy": "Skipped",
    "": "Could not confirm",
}


@dataclass(frozen=True)
class BackupRunRow:
    """One run, with its plain result and its onsite and offsite findings kept apart."""

    key: str
    identifier: str
    work_type: str
    title: str
    summary: str
    result_class: str
    when: datetime | None
    findings: tuple[tuple[str, str], ...]
    detail_lines: tuple[tuple[str, str], ...]
    link_url: str
    needs_attention: bool = False
    attention_sentence: str = ""
    point: str = ""

    # Templates branch on this without importing the row type (jobs/presentation.py).
    is_backup: ClassVar[bool] = True
    running: ClassVar[bool] = False

    @property
    def sites(self) -> tuple[str, ...]:
        return (self.identifier,)


@dataclass(frozen=True)
class BackupTimerRow:
    """One site timer: On, Off, or not reported. A missing timer is never a schedule."""

    key: str
    identifier: str
    work_type: str
    location: str
    state: str
    next_run_at: datetime | None = None
    next_run_unknown: bool = False
    last_run_at: datetime | None = None
    link_url: str = ""
    link_label: str = ""
    needs_attention: bool = False
    attention_sentence: str = ""

    is_automatic: ClassVar[bool] = True

    @property
    def title(self) -> str:
        return TIMER_TITLE[self.work_type]

    @property
    def sites(self) -> tuple[str, ...]:
        return (self.identifier,)

    @property
    def summary(self) -> str:
        return self.state

    @property
    def result_class(self) -> str:
        return ""

    @property
    def detail_lines(self) -> tuple[tuple[str, str], ...]:
        lines: list[tuple[str, str]] = [
            ("Site", self.identifier),
            ("Type of work", self.title),
            ("State", self.state),
        ]
        if self.location:
            lines.append(("Location", "On this server" if self.location == "onsite" else "Offsite"))
        if self.next_run_at is not None:
            lines.append(("Next run", self.next_run_at.isoformat()))
        if self.last_run_at is not None:
            lines.append(("Last run", self.last_run_at.isoformat()))
        return tuple(lines)


@dataclass(frozen=True)
class BackupWork:
    runs: tuple[BackupRunRow, ...]
    timers: tuple[BackupTimerRow, ...]
    warnings: tuple[str, ...]
    empty: str


def backup_work(snapshot: Snapshot, server: Server) -> BackupWork:
    """Read the snapshot's existing backup observation; no native read is added."""
    observation = snapshot.collected.backups
    if not observation.observed:
        if observation.outcome == ObservationOutcome.ABSENT and not observation.warning:
            return BackupWork((), (), (), "")
        return BackupWork((), (), (observation.warning or UNREADABLE,), "")
    runs: list[BackupRunRow] = []
    timers: list[BackupTimerRow] = []
    warnings: list[str] = []
    for backup in observation.value:
        timers.extend(_timer_rows(backup, server))
        runs.extend(_run_row(backup, run, server) for run in backup.runs)
        if backup.runs_truncated:
            warnings.append(TRUNCATED_RUNS)
        if backup.timers_truncated:
            warnings.append(TRUNCATED_TIMERS)
    runs.sort(key=_order, reverse=True)
    timers.sort(key=lambda row: (row.identifier, _timer_order(row.work_type), row.location))
    return BackupWork(
        tuple(runs),
        tuple(timers),
        tuple(dict.fromkeys(warnings)),
        NO_BACKUPS if not runs and not timers else "",
    )


def _order(row: BackupRunRow) -> tuple[bool, float]:
    return (row.when is not None, row.when.timestamp() if row.when is not None else 0.0)


def _timer_order(work_type: str) -> int:
    return {
        BACKUP_SCHEDULE: 0,
        CHECK_SCHEDULE: 1,
        CLEANUP_SCHEDULE: 2,
    }[work_type]


def _timer_rows(backup: ObservedBackup, server: Server) -> list[BackupTimerRow]:
    if not (backup.enabled or backup.timers or backup.runs):
        return []
    found = {(timer.work, timer.location): timer for timer in backup.timers}
    offsite = backup.offsite is not None and backup.offsite.configured
    rows: list[BackupTimerRow] = []
    for work in ("backup", "check", "cleanup"):
        locations = [""] if work == "backup" else ["onsite"]
        if (work, "offsite") in found or (work != "backup" and offsite):
            locations.append("offsite")
        rows.extend(
            _timer_row(backup.identifier, work, location, found.get((work, location)), server)
            for location in locations
        )
    return rows


def _timer_row(
    identifier: str,
    work: str,
    location: str,
    timer: BackupTimer | None,
    server: Server,
) -> BackupTimerRow:
    work_type = TIMER_WORK[work]
    state = "Not reported" if timer is None else ("On" if timer.on else "Off")
    next_run = timer.next_at if timer is not None and timer.on else None
    return BackupTimerRow(
        key=f"{identifier}:{work}:{location or 'site'}:timer",
        identifier=identifier,
        work_type=work_type,
        location=location,
        state=state,
        next_run_at=next_run,
        next_run_unknown=(next_run is None) if timer is None or timer.on else False,
        last_run_at=timer.last_at if timer is not None else None,
        link_url=_schedule_url(server, identifier),
        link_label=f"Open {TIMER_TITLE[work_type].lower()}",
    )


def _run_row(backup: ObservedBackup, run: BackupRun, server: Server) -> BackupRunRow:
    work_type = {
        "capture": CAPTURE,
        "copy": COPY,
        "check": CHECK,
        "cleanup": CLEANUP,
    }[run.kind]
    title = WORK_TITLE[work_type]
    headline, detail = _sentences(backup, run)
    findings = _findings(run, backup)
    needs_attention = results.word(run.result_class).attention or (
        run.kind == "capture" and run.offsite == "failed"
    )
    summary = _summary(run)
    if run.result_class in ("failed", "refused") and detail:
        summary = f"Failed: {detail}"
    return BackupRunRow(
        key=f"{backup.identifier}:{run.kind}:{run.at}:{run.point}",
        identifier=backup.identifier,
        work_type=work_type,
        title=title,
        summary=summary,
        result_class=run.result_class,
        when=run.time,
        findings=findings,
        detail_lines=(
            ("Site", backup.identifier),
            ("Type of work", title),
            ("Result class", _RESULT_LABELS.get(run.result_class, run.result_class)),
            *((("Time", run.at),) if run.at else ()),
            *((("Recovery point", run.short_point),) if run.point else ()),
            *((("What happened", f"{headline} {detail}".strip()),) if needs_attention else ()),
            *findings,
        ),
        link_url=_backups_url(server, backup.identifier),
        needs_attention=needs_attention,
        attention_sentence=f"{headline} {detail}".strip() if needs_attention else "",
        point=run.point,
    )


def _sentences(backup: ObservedBackup, run: BackupRun) -> tuple[str, str]:
    if not run.result_class:
        return COULD_NOT_CONFIRM, NO_RESULT_LINE
    if run.kind == "capture":
        result = backup_presentation.result_view(
            BackupResult(
                run.result_class,
                run.reason,
                run.scope,
                run.origin,
                run.at,
                run.point,
                run.snapshots,
                run.size,
                run.offsite,
            ),
            backup.copy if backup.copy is not None and backup.copy.point == run.point else None,
        )
        return result.headline, result.detail
    if run.kind == "copy":
        copied = backup_presentation.copy_view(
            OffsiteCopy(run.result_class, run.reason, run.point, run.at)
        )
        if copied is None:
            return COULD_NOT_CONFIRM, NO_RESULT_LINE
        return copied.headline, copied.detail
    if run.kind == "check":
        finding = IntegrityFinding(
            run.location,
            run.result_class,
            run.reason,
            run.at,
            run.point,
            run.checked,
            run.snapshots,
            run.size,
            run.subset,
        )
        checked = backup_presentation.integrity_view(run.location, finding)
        return checked.headline, checked.detail
    cleaned = backup_presentation.cleanup_view(
        run.onsite,
        run.offsite_counts,
        result_class=run.result_class,
        reason=run.reason,
        at=run.at,
    )
    return cleaned.headline, cleaned.detail


def _summary(run: BackupRun) -> str:
    if not run.result_class:
        return "Could not confirm"
    if run.kind == "capture":
        if run.result_class == "succeeded":
            return "Finished"
        if run.result_class == "partial":
            return "Partly saved (some files unreadable)"
    if run.result_class == "succeeded":
        return "Finished"
    if run.result_class == "partial":
        return "Partly finished"
    if run.result_class == "lock_busy":
        return "Skipped because the repository was busy"
    return "Failed"


def _findings(  # noqa: C901 - one run's findings
    run: BackupRun, backup: ObservedBackup
) -> tuple[tuple[str, str], ...]:
    if not run.result_class:
        return (("Result", "Could not confirm"),)
    onsite_label = "On this server"
    offsite_label = "Offsite storage"
    if run.kind == "capture":
        onsite = (
            "Saved"
            if run.result_class in ("succeeded", "partial")
            else ("Skipped" if run.result_class == "lock_busy" else "Not saved")
        )
        if run.point:
            onsite += f" · {run.short_point}"
        if run.size:
            onsite += f" · {_size(run.size)}"
        offsite = {
            "copied": "Copy finished",
            "failed": "Copy failed",
        }.get(
            run.offsite,
            "Not copied"
            if backup.offsite is not None and backup.offsite.configured
            else "Not set up",
        )
        return ((onsite_label, onsite), (offsite_label, offsite))
    if run.kind == "copy":
        result = {
            "succeeded": "Copy finished",
            "lock_busy": "Copy skipped",
        }.get(run.result_class, "Copy failed")
        if run.point:
            result += f" · {run.short_point}"
        return ((offsite_label, result),)
    if run.kind == "check":
        label = onsite_label if run.location == "onsite" else offsite_label
        result = {
            "succeeded": "Verified" if run.point else "Healthy",
            "lock_busy": "Skipped",
        }.get(run.result_class, "Failed")
        if run.point:
            result += f" · {run.short_point}"
        if run.subset:
            result += f" · subset {run.subset}"
        if run.size:
            result += f" · {_size(run.size)}"
        return ((label, result),)
    return (
        (onsite_label, _counts(run.onsite)),
        (offsite_label, _counts(run.offsite_counts)),
    )


def _counts(counts: CleanupCounts | None) -> str:
    found = counts or CleanupCounts()
    return (
        f"Deleted {found.deleted}, kept {found.kept}, skipped {found.skipped}, "
        f"failed {found.failed}"
    )


def _size(value: int) -> str:
    units = ("bytes", "KB", "MB", "GB", "TB")
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.0f} {unit}" if unit == "bytes" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{value} bytes"


def _backups_url(server: Server, identifier: str) -> str:
    return reverse("site_backups", args=(server.pk, identifier)) + "#backups-heading"


def _schedule_url(server: Server, identifier: str) -> str:
    return reverse("site_backups", args=(server.pk, identifier)) + "#backup-schedule-heading"
