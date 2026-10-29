"""The Backups section's wording, from stored rows only (#396, #179)."""

from dataclasses import dataclass
from datetime import UTC, datetime

from django.utils import timezone

from discovery.snapshot import CollectedSnapshot, ObservedSite

from . import check, kit
from .models import BackupCheck
from .observation import ObservedBackup

SCOPE_LABELS = {
    "database": "Database only",
    "files": "Full site",
    "full": "Full site",
    "": "Database only",
}


@dataclass(frozen=True)
class LastBackupView:
    headline: str
    detail: str
    time_label: str
    result_class: str

    @property
    def failed(self) -> bool:
        return self.result_class in ("failed", "refused")


@dataclass(frozen=True)
class RecoveryPointView:
    time_label: str
    scope: str
    status: str
    live: bool
    keep: bool
    short_id: str
    point: str
    missing: tuple[str, ...] = ()
    incomplete: tuple[str, ...] = ()

    @property
    def restorable(self) -> bool:
        return self.status == "Saved here"

    @property
    def problem(self) -> str:
        if self.missing:
            return (
                "The "
                + " and ".join(self.missing)
                + " part is missing, so this point is incomplete."
            )
        if self.incomplete:
            return "This point is not complete."
        return ""


@dataclass(frozen=True)
class BackupsView:
    enabled: bool
    last: LastBackupView | None
    points: tuple[RecoveryPointView, ...]
    checked_at: datetime | None
    stale: bool
    check_problem: str
    checking: bool
    database: bool
    database_reason: str
    problems: tuple[str, ...]
    note: str
    gated: bool = False
    interrupted: bool = False

    @property
    def reopen(self) -> bool:
        return self.gated and self.interrupted


def backup_of(collected: CollectedSnapshot, identifier: str) -> ObservedBackup | None:
    return next(
        (row for row in collected.backups.value if row.identifier == identifier),
        None,
    )


def _when(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _label(value: datetime | None) -> str:
    if value is None:
        return "Time not recorded"
    return timezone.localtime(value).strftime("%-d %b %Y, %H:%M")


def last_view(backup: ObservedBackup | None) -> LastBackupView | None:
    if backup is None or backup.last is None:
        return None
    result = backup.last
    at = _when(result.at)
    scope = SCOPE_LABELS.get(result.scope, "Database only")
    if result.result_class == "succeeded":
        detail = (
            "The database and the site's files finished and their recovery point is kept here."
            if result.scope in ("full", "files")
            else "The database dump finished and its recovery point is kept here."
        )
        return LastBackupView(
            f"{scope} saved.",
            detail,
            _label(at),
            result.result_class,
        )
    if result.result_class == "partial" and result.reason == "backup_paused":
        return LastBackupView(
            "The full backup stopped after pausing the site.",
            "Visitors see a maintenance page until you reopen the site. Nothing after "
            "the pause ran.",
            _label(at),
            result.result_class,
        )
    if result.result_class == "partial":
        return LastBackupView(
            f"{scope} saved with warnings.",
            "Some data could not be read, so this point may be incomplete.",
            _label(at),
            result.result_class,
        )
    if result.result_class == "lock_busy":
        return LastBackupView(
            "The backup was skipped.",
            "The site was busy with another change, so nothing was captured.",
            _label(at),
            result.result_class,
        )
    if result.result_class == "refused":
        return LastBackupView(
            "The backup did not run.",
            _result_reason(result.reason),
            _label(at),
            result.result_class,
        )
    return LastBackupView(
        "The last backup failed.",
        _result_reason(result.reason),
        _label(at),
        result.result_class,
    )


def _result_reason(reason: str) -> str:
    return {
        "backup_dump": "The database dump failed, so nothing was saved.",
        "backup_files": "The site's files could not be copied, so the point is incomplete.",
        "backup_idle": "The site was still busy, so the full copy stopped before its files.",
        "backup_paused": "The site is paused because the full copy stopped partway.",
        "backup_disk": "The server was short of free space, so nothing was saved.",
        "backup_lock": "The site was busy, so the backup was skipped.",
        "backup_password": "The stored key did not open the backup, so nothing was saved.",
        "backup_repository": "The backup store could not be read, so nothing was saved.",
        "backup_verify": "Barectl could not confirm the recovery point afterwards.",
        "backup_partial": "Some data could not be read; the point may be incomplete.",
    }.get(reason, "Barectl could not finish the backup. Check again or read the run's record.")


def points_view(listing: dict[str, object]) -> tuple[RecoveryPointView, ...]:
    raw = listing.get("points")
    if not isinstance(raw, list):
        return ()
    rows = []
    for point in raw:
        if not isinstance(point, dict):
            continue
        when = point.get("time")
        complete = point.get("complete") is True
        missing = point.get("missing")
        incomplete = point.get("incomplete")
        rows.append(
            RecoveryPointView(
                _label(_when(str(when))) if isinstance(when, str) else "Time not recorded",
                SCOPE_LABELS.get(str(point.get("scope", "")), "Database only"),
                "Saved here" if complete else "Incomplete",
                point.get("live") is True,
                point.get("keep") is True,
                str(point.get("short", "")),
                str(point.get("point", "")),
                tuple(str(item) for item in missing) if isinstance(missing, list) else (),
                tuple(str(item) for item in incomplete) if isinstance(incomplete, list) else (),
            )
        )
    return tuple(rows)


def view(
    site: ObservedSite | None,
    collected: CollectedSnapshot | None,
    identifier: str,
    latest_check: BackupCheck | None,
    *,
    checking: bool,
    gated: bool = False,
) -> BackupsView:
    backup = backup_of(collected, identifier) if collected is not None else None
    enabled = backup is not None and backup.enabled
    interrupted = bool(
        gated
        and backup is not None
        and backup.last is not None
        and backup.last.scope in ("full", "files")
        and backup.last.reason
        in {
            "backup_paused",
            "backup_dump",
            "backup_files",
            "backup_idle",
            "backup_gate",
            "backup_verify",
            "backup_partial",
            "automation_restore",
        }
    )
    points: tuple[RecoveryPointView, ...] = ()
    checked_at: datetime | None = None
    stale = False
    check_problem = ""
    if latest_check is not None:
        listing = latest_check.listing
        checked_at = latest_check.checked_at
        outcome = listing.get("outcome") if isinstance(listing, dict) else None
        if outcome == "observed":
            points = points_view(listing)
        else:
            check_problem = str(listing.get("problem", "")) if isinstance(listing, dict) else ""
        stale = check.stale(latest_check)
    note = ""
    if not enabled:
        note = "This site is not backed up."
    elif backup is not None and backup.last is None:
        note = "Backups are enabled. No recovery point has been taken yet."
    return BackupsView(
        enabled,
        last_view(backup),
        points,
        checked_at,
        stale,
        check_problem,
        checking,
        backup.database if backup is not None else False,
        (backup.database_problem if backup is not None else "")
        or "This site has no site database.",
        backup.problems if backup is not None else (),
        note,
        gated,
        interrupted,
    )


def kit_lines(server_name: str, identifier: str, collected: CollectedSnapshot | None) -> list[str]:
    backup = backup_of(collected, identifier) if collected is not None else None
    return kit.lines(
        server_name=server_name,
        identifier=identifier,
        restic_version=backup.restic_version if backup is not None else "",
    )
