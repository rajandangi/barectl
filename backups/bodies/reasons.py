"""The result reasons the backup, restore, reopen and integrity bodies print (#495, #502).

The vocabulary belongs to the fragments that print it: the capture helpers in
:mod:`backups.bodies.native`, the backup and restore entry points, the shared site
fragments they stage, and the scheduled integrity body. The engine's own admission reasons
and the server-wide precondition reasons are declared once elsewhere and need not be
repeated here.
"""

from typing import Final

from operations.models import Result
from operations.reasons import ResultReason, register_body
from sites.bodies.reasons import SITE_REASONS

BACKUP_SITE: Final = ResultReason(
    "backup_site",
    {
        Result.REFUSED: (
            "The site's Linux account could not be read, so the backup stopped before "
            "changing anything. Run discovery and prepare a new review."
        ),
    },
)
BACKUP_REPOSITORY: Final = ResultReason(
    "backup_repository",
    {
        Result.REFUSED: (
            "The site's backup repository could not be read or created, so nothing was "
            "captured. Read the run's journal on the server, then prepare a new review."
        ),
    },
)
BACKUP_PASSWORD: Final = ResultReason(
    "backup_password",
    {
        Result.REFUSED: (
            "The recovery passphrase did not open the site's repository, so nothing was "
            "captured. Prepare a new review and type the passphrase you stored."
        ),
    },
)
BACKUP_LOCK: Final = ResultReason(
    "backup_lock",
    {
        Result.REFUSED: (
            "The site was busy with another change before the backup started, so the backup "
            "was skipped. Prepare a new review after that change finishes."
        ),
        Result.LOCK_BUSY: (
            "Barectl's mutation lock on the server was held by another change, so the backup "
            "stopped before it started. Prepare a new review after that change finishes."
        ),
    },
)
BACKUP_DISK: Final = ResultReason(
    "backup_disk",
    {
        Result.REFUSED: (
            "The server does not have the free space the review keeps in reserve, so nothing "
            "was captured and no older backup was removed. Free space, then prepare a new "
            "review."
        ),
    },
)
BACKUP_DUMP: Final = ResultReason(
    "backup_dump",
    {
        Result.REFUSED: (
            "The database dump failed, so restic saved no recovery point. Check the site's "
            "database and prepare a new review."
        ),
        Result.PARTIAL: (
            "The database capture stopped and left no complete database snapshot, so the "
            "full recovery point is incomplete. Read the run's journal, then reopen the site "
            "and prepare a new review."
        ),
    },
)
BACKUP_VERIFY: Final = ResultReason(
    "backup_verify",
    {
        Result.FAILED: (
            "The capture finished but no complete recovery point could be verified in the "
            "repository. Read the run's journal on the server and prepare a new review."
        ),
        Result.PARTIAL: (
            "The capture finished but the complete point could not be verified, so the site "
            "stays paused. Reopen site remains meaningful; read the run's journal, then "
            "prepare a new review."
        ),
    },
)
BACKUP_PARTIAL: Final = ResultReason(
    "backup_partial",
    {
        Result.PARTIAL: (
            "Some of the capture could not be read back, so this recovery point may be "
            "incomplete. Read the run's journal on the server, then prepare a new review."
        ),
    },
)
BACKUP_FILES: Final = ResultReason(
    "backup_files",
    {
        Result.PARTIAL: (
            "The site's files could not be copied, so the point is incomplete and the site "
            "stays paused. Read the run's journal, then reopen the site and prepare a new "
            "review."
        ),
    },
)
BACKUP_IDLE: Final = ResultReason(
    "backup_idle",
    {
        Result.PARTIAL: (
            "The site's running work did not finish within the reviewed wait, so the files "
            "were not copied and the site stays paused. Read the run's journal, then reopen "
            "the site."
        ),
    },
)
BACKUP_PAUSED: Final = ResultReason(
    "backup_paused",
    {
        Result.PARTIAL: (
            "The full backup stopped after pausing the site, before it captured the database "
            "or files. Nothing was captured; Reopen site remains meaningful and removes the "
            "maintenance page."
        ),
    },
)
BACKUP_GATE: Final = ResultReason(
    "backup_gate",
    {
        Result.REFUSED: (
            "Barectl could not publish the maintenance page because the site's Caddy file is "
            "not the reviewed open file, so nothing was captured. If the site was already "
            "paused, reopen it; read the run's journal, then prepare a new review."
        ),
        Result.PARTIAL: (
            "The recovery point was captured, but Barectl could not remove the maintenance "
            "page, so the site stays paused. Reopen site remains meaningful."
        ),
    },
)
BACKUP_KEY: Final = ResultReason(
    "backup_key",
    {
        Result.REFUSED: (
            "The server key could not be added or did not open the repository, so units "
            "cannot take backups yet. The passphrase still opens it. Prepare a new review to "
            "finish."
        ),
        Result.PARTIAL: (
            "The repository exists but the server key is not proven, so scheduled units "
            "cannot take backups yet. The passphrase still opens it. Prepare a new review to "
            "finish."
        ),
    },
)
BACKUP_CHECK: Final = ResultReason(
    "backup_check",
    {
        Result.PARTIAL: (
            "The site's backups are enabled, but Barectl could not install or start every "
            "weekly integrity check, so the checks are only partly applied. Read the run's "
            "journal on the server, then prepare a new review to finish."
        ),
    },
)
BACKUP_UNKNOWN: Final = ResultReason(
    "backup_unknown",
    {
        Result.FAILED: (
            "The backup tool reported an error Barectl does not recognize, so nothing is "
            "recorded as saved. Read the run's journal on the server and prepare a new review."
        ),
    },
)
OFFSITE_COPY: Final = ResultReason(
    "offsite_copy",
    {
        Result.FAILED: (
            "The offsite copy did not finish. The recovery point saved on this server is "
            "unchanged; copy it offsite again when the storage is reachable."
        ),
    },
)
OFFSITE_KEY: Final = ResultReason(
    "offsite_key",
    {
        Result.FAILED: (
            "The offsite access keys or recovery passphrase could not be used, so nothing "
            "was copied. Prepare a new review and type the values again."
        ),
    },
)
OFFSITE_REPOSITORY: Final = ResultReason(
    "offsite_repository",
    {
        Result.FAILED: (
            "An offsite repository could not be initialised or opened. The copies already in "
            "the bucket are unchanged. Check the bucket and keys, then prepare a new review."
        ),
    },
)
RESTIC_RUNTIME_CONFIG: Final = ResultReason(
    "runtime_config",
    {
        Result.REFUSED: (
            "The runtime configuration step could not be written or verified, so the run "
            "stopped before changing anything. Check the run's journal on the server, then "
            "prepare a new review."
        ),
    },
)

RESTORE_SITE: Final = ResultReason(
    "restore_site",
    {
        Result.REFUSED: (
            "The site's Linux account could not be read, so the restore stopped before "
            "changing anything. Run discovery and prepare a new review."
        ),
    },
)
RESTORE_REPOSITORY: Final = ResultReason(
    "restore_repository",
    {
        Result.REFUSED: (
            "The site's backup repository could not be read, so nothing was restored. Read "
            "the run's journal on the server, then prepare a new review."
        ),
    },
)
RESTORE_EVIDENCE: Final = ResultReason(
    "restore_evidence",
    {
        Result.REFUSED: (
            "The site's reviewed files changed before the run started, so nothing was "
            "restored. Run discovery and prepare a new review."
        ),
    },
)
RESTORE_LOCK: Final = ResultReason(
    "restore_lock",
    {
        Result.REFUSED: (
            "The site was busy with another change before the restore started, so the restore "
            "was skipped. Prepare a new review after that change finishes."
        ),
        Result.LOCK_BUSY: (
            "Barectl's mutation lock on the server was held by another change, so the restore "
            "stopped before it started. Prepare a new review after that change finishes."
        ),
    },
)
RESTORE_DISK: Final = ResultReason(
    "restore_disk",
    {
        Result.REFUSED: (
            "The server does not have the free space the review keeps in reserve, so nothing "
            "was restored. Free space, then prepare a new review."
        ),
    },
)
RESTORE_POINT: Final = ResultReason(
    "restore_point",
    {
        Result.REFUSED: (
            "The recovery point is missing or incomplete, so nothing was restored. Check "
            "backups and prepare a new review."
        ),
    },
)
RESTORE_ENGINE: Final = ResultReason(
    "restore_engine",
    {
        Result.REFUSED: (
            "The recovery point was made by a different database version than this site uses, "
            "so nothing was restored. Prepare a new review from a matching point."
        ),
    },
)
RESTORE_TARGET: Final = ResultReason(
    "restore_target",
    {
        Result.REFUSED: (
            "The site's database changed since the review, so nothing was restored. Prepare a "
            "new review against the current site."
        ),
    },
)
RESTORE_DUMP: Final = ResultReason(
    "restore_dump",
    {
        Result.REFUSED: (
            "The recovery point's database copy was truncated, so nothing was restored and "
            "the site still serves. Prepare a new review from a complete point."
        ),
    },
)
RESTORE_SAFETY: Final = ResultReason(
    "restore_safety",
    {
        Result.REFUSED: (
            "The safety backup could not be taken or checked, so nothing was overwritten. "
            "Read the run's journal and prepare a new review."
        ),
    },
)
RESTORE_GATE: Final = ResultReason(
    "restore_gate",
    {
        Result.REFUSED: (
            "Barectl could not publish the maintenance page, so the site's database was not "
            "changed. Read the run's journal, then prepare a new review."
        ),
    },
)
RESTORE_PAUSED: Final = ResultReason(
    "restore_paused",
    {
        Result.PARTIAL: (
            "The restore stopped after pausing the site, before it imported the database or "
            "replaced any files. Reopen site remains meaningful and removes the maintenance "
            "page; prepare a new review after that."
        ),
    },
)
RESTORE_IDLE: Final = ResultReason(
    "restore_idle",
    {
        Result.PARTIAL: (
            "The site's running requests or background work did not finish within the "
            "reviewed wait, so the database was not changed and the site stays paused. Reopen "
            "site removes the maintenance page."
        ),
    },
)
RESTORE_FILES: Final = ResultReason(
    "restore_files",
    {
        Result.REFUSED: (
            "The recovery point's files could not be staged safely, so nothing was replaced."
        ),
        Result.PARTIAL: (
            "The site's files could not be placed into a new release, so they may be partly "
            "restored and the site stays paused. Reopen site remains meaningful; read the "
            "run's journal, then prepare a new review."
        ),
    },
)
RESTORE_CONFIG: Final = ResultReason(
    "restore_config",
    {
        Result.PARTIAL: (
            "The site's files were placed, but Barectl could not re-create the site's "
            "configuration, so it stays paused. Reopen site remains meaningful; read the "
            "run's journal, then prepare a new review."
        ),
    },
)
RESTORE_IMPORT: Final = ResultReason(
    "restore_import",
    {
        Result.PARTIAL: (
            "The database import did not finish after the site was paused, so the data may be "
            "partly replaced. Read the run's journal, then reopen the site and check what "
            "remained."
        ),
    },
)
RESTORE_DATA: Final = ResultReason(
    "restore_data",
    {
        Result.PARTIAL: (
            "The import finished but its data checks did not pass, so the site stays paused. "
            "Read the run's journal, then reopen the site and check the data."
        ),
    },
)
RESTORE_READINESS: Final = ResultReason(
    "restore_readiness",
    {
        Result.PARTIAL: (
            "The data was imported but the site did not answer its readiness check, so it "
            "stays paused. Read the run's journal, then reopen the site and check the "
            "application."
        ),
    },
)
RESTORE_OPEN: Final = ResultReason(
    "restore_open",
    {
        Result.PARTIAL: (
            "The restore reached its reopen step, but Barectl could not prove the site serves "
            "again, so it stays paused. Reopen site removes the maintenance page; read the "
            "run's journal, then prepare a new review."
        ),
    },
)
RESTORE_DONE: Final = ResultReason(
    "restore_done",
    {
        Result.SUCCEEDED: ("The recovery point was restored and the site serves its files again."),
    },
)
SITE_REOPEN: Final = ResultReason(
    "site_reopen",
    {
        Result.PARTIAL: (
            "Barectl could not prove the site serves its files again after reopening it, so "
            "it may still show the maintenance page. Read the run's journal, then prepare a "
            "new review."
        ),
    },
)

INTEGRITY_PACK: Final = ResultReason(
    "integrity_pack",
    {
        Result.FAILED: (
            "restic found a damaged or missing pack file in this site's repository, so a "
            "recovery point may be incomplete. Check the run's journal, then prepare a new "
            "review."
        ),
    },
)
INTEGRITY_READBACK: Final = ResultReason(
    "integrity_readback",
    {
        Result.FAILED: (
            "The repository passed its check, but Barectl could not read the newest recovery "
            "point back through restic dump. Check the run's journal, then prepare a new "
            "review."
        ),
    },
)
INTEGRITY_OFFSITE: Final = ResultReason(
    "integrity_offsite",
    {
        Result.REFUSED: (
            "The offsite location is not configured or its credentials could not be read, so "
            "this check was skipped. Set up offsite storage again, then wait for the next "
            "check."
        ),
    },
)

INTEGRITY_REASONS: Final = (
    BACKUP_REPOSITORY,
    BACKUP_PASSWORD,
    BACKUP_LOCK,
    BACKUP_UNKNOWN,
    INTEGRITY_PACK,
    INTEGRITY_READBACK,
    INTEGRITY_OFFSITE,
)
ENABLE_REASONS: Final = (
    BACKUP_SITE,
    BACKUP_KEY,
    BACKUP_CHECK,
    RESTIC_RUNTIME_CONFIG,
    *INTEGRITY_REASONS,
)
BACKUP_REASONS: Final = (
    BACKUP_SITE,
    BACKUP_REPOSITORY,
    BACKUP_PASSWORD,
    BACKUP_DISK,
    BACKUP_LOCK,
    BACKUP_DUMP,
    BACKUP_VERIFY,
    BACKUP_PARTIAL,
    BACKUP_UNKNOWN,
    OFFSITE_COPY,
    OFFSITE_KEY,
    OFFSITE_REPOSITORY,
)
FULL_REASONS: Final = (
    *SITE_REASONS,
    BACKUP_SITE,
    BACKUP_REPOSITORY,
    BACKUP_DISK,
    BACKUP_LOCK,
    BACKUP_DUMP,
    BACKUP_VERIFY,
    BACKUP_PARTIAL,
    BACKUP_FILES,
    BACKUP_IDLE,
    BACKUP_PAUSED,
    BACKUP_GATE,
    OFFSITE_COPY,
    OFFSITE_KEY,
    OFFSITE_REPOSITORY,
)
RESTORE_REASONS: Final = (
    *SITE_REASONS,
    RESTORE_SITE,
    RESTORE_REPOSITORY,
    RESTORE_EVIDENCE,
    RESTORE_LOCK,
    RESTORE_DISK,
    RESTORE_POINT,
    RESTORE_ENGINE,
    RESTORE_TARGET,
    RESTORE_DUMP,
    RESTORE_SAFETY,
    RESTORE_GATE,
    RESTORE_PAUSED,
    RESTORE_IDLE,
    RESTORE_FILES,
    RESTORE_CONFIG,
    RESTORE_IMPORT,
    RESTORE_DATA,
    RESTORE_READINESS,
    RESTORE_OPEN,
    RESTORE_DONE,
)
REOPEN_REASONS: Final = (*SITE_REASONS, SITE_REOPEN)

# The scheduled integrity check is a native body, not a change kind: the units run it
# directly, so its vocabulary is registered the same way a kind's body would be.
register_body(
    "backup_integrity",
    INTEGRITY_REASONS,
    sources=("backups/bodies/integrity.py",),
)
