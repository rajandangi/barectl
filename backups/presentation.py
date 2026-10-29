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
class OffsiteView:
    label: str
    bucket: str
    prefix: str


@dataclass(frozen=True)
class CopyView:
    headline: str
    detail: str
    time_label: str
    failed: bool
    point: str = ""


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
    offsite_status: str = "Offsite storage not set up"
    parts: tuple[str, ...] = ()

    @property
    def restorable(self) -> bool:
        return self.status == "Saved here"

    @property
    def has_database(self) -> bool:
        return "database" in self.parts

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
    offsite: OffsiteView | None = None
    copy: CopyView | None = None
    restore: bool = False

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


def last_view(backup: ObservedBackup | None) -> LastBackupView | None:  # noqa: C901 - one result
    if backup is None or backup.last is None:
        return None
    result = backup.last
    at = _when(result.at)
    scope = SCOPE_LABELS.get(result.scope, "Database only")
    if result.reason.startswith("restore_"):
        if result.result_class == "succeeded":
            return LastBackupView(
                "Database restored.",
                "The recovery point's data was imported and the site answered again.",
                _label(at),
                result.result_class,
            )
        if result.reason == "restore_paused":
            return LastBackupView(
                "The restore stopped after pausing the site.",
                "Visitors see a maintenance page until you reopen the site. Nothing after "
                "the pause ran.",
                _label(at),
                result.result_class,
            )
        return LastBackupView(
            "The restore did not finish.",
            _result_reason(result.reason),
            _label(at),
            result.result_class,
        )
    if result.result_class == "succeeded":
        detail = (
            "The database and the site's files finished and their recovery point is kept here."
            if result.scope in ("full", "files")
            else "The database dump finished and its recovery point is kept here."
        )
        if result.offsite == "failed" or (
            backup.copy is not None and backup.copy.point == result.point and not backup.copy.copied
        ):
            return LastBackupView(
                "Saved here, offsite copy failed.",
                "The recovery point is kept on this server. Its offsite copy did not finish, "
                "so copy it offsite again when the storage is reachable.",
                _label(at),
                result.result_class,
            )
        if result.offsite == "copied":
            detail += " It was also copied to offsite storage."
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
        "backup_offsite": (
            "The onsite recovery point is saved, but the offsite copy did not finish."
        ),
        "schedule_timer": "Systemd did not report the new backup timer as active.",
        "schedule_units": "The backup schedule's units are not in the reviewed state.",
        "schedule_install": "The backup schedule could not be installed on the server.",
        "restore_site": "The site's account could not be read, so nothing was restored.",
        "restore_repository": "The backup store could not be read, so nothing was restored.",
        "restore_evidence": "The site changed before the restore, so nothing was restored.",
        "restore_lock": "The site was busy, so the restore was skipped.",
        "restore_disk": "The server was short of free space, so nothing was restored.",
        "restore_point": "The recovery point is missing or incomplete, so nothing was restored.",
        "restore_engine": (
            "The recovery point was made by a different database version, so nothing was restored."
        ),
        "restore_target": "The site's database changed, so nothing was restored.",
        "restore_safety": "The safety backup failed, so nothing was overwritten.",
        "restore_gate": "The maintenance page could not be published, so the data was not changed.",
        "restore_idle": "The site was still busy, so the data was not changed.",
        "restore_import": "The import did not finish, so the data may be partly replaced.",
        "restore_data": "The import finished but its data checks did not pass.",
        "restore_readiness": "The data was imported but the site did not answer its check.",
        "restore_open": "The maintenance page could not be removed, so the site stays paused.",
    }.get(reason, "Barectl could not finish the backup. Check again or read the run's record.")


def points_view(
    listing: dict[str, object], copy: CopyView | None = None, *, configured: bool = False
) -> tuple[RecoveryPointView, ...]:
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
        parts = point.get("parts")
        point_id = str(point.get("point", ""))
        rows.append(
            RecoveryPointView(
                _label(_when(str(when))) if isinstance(when, str) else "Time not recorded",
                SCOPE_LABELS.get(str(point.get("scope", "")), "Database only"),
                "Saved here" if complete else "Incomplete",
                point.get("live") is True,
                point.get("keep") is True,
                str(point.get("short", "")),
                point_id,
                tuple(str(item) for item in missing) if isinstance(missing, list) else (),
                tuple(str(item) for item in incomplete) if isinstance(incomplete, list) else (),
                offsite_status=_point_offsite(point_id, copy, configured),
                parts=tuple(str(item) for item in parts) if isinstance(parts, list) else (),
            )
        )
    return tuple(rows)


def _point_offsite(point: str, copy: CopyView | None, configured: bool) -> str:
    if not configured:
        return "Offsite storage not set up"
    if copy is None or not copy.point:
        return "Not copied offsite"
    if copy.point != point:
        return "Not copied offsite"
    return "Offsite copy failed" if copy.failed else "Copied offsite"


def copy_view(copy: object | None) -> CopyView | None:
    from .observation import OffsiteCopy

    if not isinstance(copy, OffsiteCopy):
        return None
    at = _when(copy.at)
    if copy.copied:
        headline = "Offsite copy kept."
        detail = "The offsite repository holds this recovery point as well."
    elif copy.result_class == "lock_busy":
        headline = "The offsite copy was skipped."
        detail = "Another copy held the repository lock, so nothing was uploaded."
    else:
        headline = "Offsite copy failed."
        detail = (
            "The recovery point saved on this server is unchanged. Copy it offsite again when "
            "the storage is reachable."
        )
    return CopyView(headline, detail, _label(at), not copy.copied, copy.point)


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
    restore = bool(
        gated
        and backup is not None
        and backup.last is not None
        and backup.last.reason.startswith("restore_")
    )
    interrupted = restore or bool(
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
    copy = copy_view(backup.copy if backup is not None else None)
    offsite = (
        OffsiteView(backup.offsite.label, backup.offsite.bucket, backup.offsite.prefix)
        if backup is not None and backup.offsite is not None and backup.offsite.configured
        else None
    )
    if latest_check is not None:
        listing = latest_check.listing
        checked_at = latest_check.checked_at
        outcome = listing.get("outcome") if isinstance(listing, dict) else None
        if outcome == "observed":
            points = points_view(listing, copy, configured=offsite is not None)
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
        offsite,
        copy,
        restore,
    )


def kit_lines(server_name: str, identifier: str, collected: CollectedSnapshot | None) -> list[str]:
    backup = backup_of(collected, identifier) if collected is not None else None
    offsite = backup.offsite if backup is not None else None
    return kit.lines(
        server_name=server_name,
        identifier=identifier,
        restic_version=backup.restic_version if backup is not None else "",
        provider=offsite.label if offsite is not None and offsite.configured else "",
        endpoint=offsite.endpoint if offsite is not None and offsite.configured else "",
        bucket=offsite.bucket if offsite is not None and offsite.configured else "",
        prefix=offsite.prefix if offsite is not None and offsite.configured else "",
        sites=tuple(row.identifier for row in collected.backups.value)
        if collected is not None
        else (),
    )
