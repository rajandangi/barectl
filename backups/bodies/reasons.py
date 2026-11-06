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
        Result.REFUSED: (
            "The offsite access keys or recovery passphrase could not be read, so the storage "
            "setting was not changed and nothing was copied. Prepare a new review and type the "
            "values again."
        ),
        Result.FAILED: (
            "The offsite access keys or recovery passphrase could not be used, so nothing "
            "was copied. Prepare a new review and type the values again."
        ),
    },
)
OFFSITE_REPOSITORY: Final = ResultReason(
    "offsite_repository",
    {
        Result.REFUSED: (
            "The onsite repository or its server key is not the reviewed one, so the offsite "
            "copy stopped before it started. The recovery point saved on this server is "
            "unchanged; run discovery and prepare a new review."
        ),
        Result.FAILED: (
            "An offsite repository could not be initialised or opened. The copies already in "
            "the bucket are unchanged. Check the bucket and keys, then prepare a new review."
        ),
    },
)
OFFSITE_BUCKET: Final = ResultReason(
    "offsite_bucket",
    {
        Result.REFUSED: (
            "The bucket did not answer a write and a listing with the reviewed keys, so the "
            "offsite storage setting was not written and no site repository was initialised. "
            "Check the bucket, its region and the access keys, then prepare a new review."
        ),
        Result.FAILED: (
            "The bucket did not answer the final write-and-list check after the storage files "
            "were written, so the offsite setting may be partly applied. The copies already in "
            "the bucket are unchanged; check the bucket and keys, then prepare a new review."
        ),
    },
)
OFFSITE_REMOVE: Final = ResultReason(
    "offsite_remove",
    {
        Result.REFUSED: (
            "The confirmation did not name this server's bucket, or the storage keys could not "
            "be read, so the offsite setting was not removed. Type the bucket name shown in "
            "the review and prepare again."
        ),
        Result.FAILED: (
            "The removal step stopped: Barectl could not delete every offsite setting file, "
            "or the setting was not the reviewed one. The copies already in the bucket are "
            "unchanged; read the run's journal on the server, then prepare a new review."
        ),
    },
)

CONNECT_REVIEW: Final = ResultReason(
    "connect_review",
    {
        Result.FAILED: (
            "The review did not carry a supported storage config, source-site list or file "
            "path, so nothing was connected. Run discovery and prepare a new review."
        ),
    },
)
CONNECT_KEY: Final = ResultReason(
    "connect_key",
    {
        Result.REFUSED: (
            "The access keys or recovery passphrase could not be read or are not usable, so "
            "the source repositories were not opened and nothing was connected. Prepare a new "
            "review and type the values again."
        ),
        Result.FAILED: (
            "The source repositories were read, but Barectl could not write this server's "
            "root-only storage files, so the connection is not complete. Check the run's "
            "journal, then prepare a new review."
        ),
    },
)
CONNECT_SETTINGS: Final = ResultReason(
    "connect_settings",
    {
        Result.REFUSED: (
            "This server already has different offsite settings, so Barectl did not overwrite "
            "them and nothing was connected. Remove the connected storage first, then prepare "
            "a new review."
        ),
    },
)
CONNECT_REPOSITORY: Final = ResultReason(
    "connect_repository",
    {
        Result.REFUSED: (
            "A source repository does not exist under the reviewed bucket and prefix, so "
            "nothing was connected. Check the source site names and the recovery kit, then "
            "prepare a new review."
        ),
        Result.FAILED: (
            "A source repository could not be read or its listing was not in the reviewed "
            "form, so this server's settings were left as they were. Check the bucket and "
            "keys, then prepare a new review."
        ),
    },
)
CONNECT_PASSWORD: Final = ResultReason(
    "connect_password",
    {
        Result.REFUSED: (
            "The recovery passphrase did not open a source repository, so nothing was "
            "connected. Prepare a new review and type the passphrase from the recovery kit."
        ),
    },
)

PASSPHRASE_REVIEW: Final = ResultReason(
    "passphrase_review",
    {
        Result.FAILED: (
            "The review did not carry a supported config, site list or file path, so no "
            "repository was reopened and no passphrase was replaced. Run discovery and prepare "
            "a new review."
        ),
    },
)
PASSPHRASE_VALUE: Final = ResultReason(
    "passphrase_value",
    {
        Result.REFUSED: (
            "The current or new recovery passphrase is missing, too short, or the same as the "
            "other, so no repository was changed. Prepare a new review and type both "
            "passphrases again."
        ),
    },
)
PASSPHRASE_KEY: Final = ResultReason(
    "passphrase_key",
    {
        Result.REFUSED: (
            "The server's backup key directory or key file is outside supported ownership or "
            "permissions, so no passphrase was replaced. Repair it through ordinary "
            "administration, then prepare a new review."
        ),
        Result.FAILED: (
            "A repository's key list could not be read, or the new key could not be added and "
            "proven, so the passphrase is only partly replaced. Read the run's journal on the "
            "server, then prepare a new review."
        ),
    },
)
PASSPHRASE_REPOSITORY: Final = ResultReason(
    "passphrase_repository",
    {
        Result.REFUSED: (
            "A reviewed site repository or its server key could not be read, so no passphrase "
            "was replaced. Run discovery and prepare a new review."
        ),
    },
)
PASSPHRASE_OLD: Final = ResultReason(
    "passphrase_old",
    {
        Result.REFUSED: (
            "The current passphrase did not open a repository, so no key was added and nothing "
            "was changed. Prepare a new review and type the passphrase you stored."
        ),
        Result.FAILED: (
            "The current passphrase still opened a repository after its key was removed, or an "
            "old key could not be removed, so the passphrase may be partly replaced. Read the "
            "run's journal on the server, then prepare a new review."
        ),
    },
)
PASSPHRASE_NEW: Final = ResultReason(
    "passphrase_new",
    {
        Result.FAILED: (
            "The new passphrase did not open every reviewed repository after the keys were "
            "added, so the old passphrase was left in place. Prepare a new review and type both "
            "passphrases again."
        ),
    },
)
PASSPHRASE_SERVER_KEY: Final = ResultReason(
    "passphrase_server_key",
    {
        Result.FAILED: (
            "A site's server key no longer opens its repository after the passphrase change, "
            "so scheduled backups may not run. Read the run's journal on the server, then "
            "prepare a new review to restore the key."
        ),
    },
)

EXPORT_STAGE: Final = ResultReason(
    "export_stage",
    {
        Result.REFUSED: (
            "Barectl could not create or admit the private staging directory for the export, "
            "so nothing left the server. Check the server's filesystem and prepare a new "
            "review."
        ),
    },
)
EXPORT_FILES: Final = ResultReason(
    "export_files",
    {
        Result.REFUSED: (
            "Barectl could not restore or read the point's files into the export stage, so "
            "nothing was exported. Check the run's journal on the server, then prepare a new "
            "review."
        ),
    },
)
EXPORT_SIZE: Final = ResultReason(
    "export_size",
    {
        Result.REFUSED: (
            "The export's files or database exceeded the reviewed size bound, so Barectl "
            "discarded the stage and nothing left the server. Choose a smaller recovery point "
            "or free space, then prepare a new review."
        ),
    },
)
EXPORT_DATABASE: Final = ResultReason(
    "export_database",
    {
        Result.REFUSED: (
            "Barectl could not dump the point's database or its version did not match the "
            "site, so nothing was exported. Check the site's database and prepare a new "
            "review."
        ),
    },
)
EXPORT_EVIDENCE: Final = ResultReason(
    "export_evidence",
    {
        Result.REFUSED: (
            "The export review's point, snapshots, engine or repository evidence was not the "
            "reviewed one, so nothing left the server. Run discovery and prepare a new review."
        ),
    },
)
EXPORT_REPOSITORY: Final = ResultReason(
    "export_repository",
    {
        Result.REFUSED: (
            "The onsite repository, its server key or the pinned backup tool could not be "
            "read, so nothing was exported. Check the run's journal on the server, then "
            "prepare a new review."
        ),
    },
)
EXPORT_LOCK: Final = ResultReason(
    "export_lock",
    {
        Result.REFUSED: (
            "Another copy or cleanup held the site's repository lock, so the export stopped "
            "before staging anything. Prepare a new review after it finishes."
        ),
    },
)
EXPORT_SECRET: Final = ResultReason(
    "export_secret",
    {
        Result.REFUSED: (
            "The archive contained the site's private configuration or its secret bytes, so "
            "Barectl discarded it and nothing left the server. Check the run's journal on the "
            "server, then prepare a new review."
        ),
    },
)

CLEANUP_CLOCK: Final = ResultReason(
    "cleanup_clock",
    {
        Result.REFUSED: (
            "The server's clock was not synchronized, so cleanup did not run and no recovery "
            "point was deleted. Wait for the clock to synchronize; the next scheduled cleanup "
            "will run."
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


SCHEDULE_TIMER: Final = ResultReason(
    "schedule_timer",
    {
        Result.PARTIAL: (
            "Systemd did not report the backup timer as active after the schedule was "
            "installed, so the reviewed run time may not happen. Read the run's journal on "
            "the server, then prepare a new review."
        ),
    },
)
SCHEDULE_UNITS: Final = ResultReason(
    "schedule_units",
    {
        Result.PARTIAL: (
            "The backup schedule's units are not in the reviewed state, so the schedule is "
            "partly applied. Read the run's journal on the server, then prepare a new review "
            "of what remains."
        ),
    },
)
SCHEDULE_INSTALL: Final = ResultReason(
    "schedule_install",
    {
        Result.REFUSED: (
            "The backup schedule could not be installed on the server, so no run time was "
            "saved. Check the site's backups and prepare a new review."
        ),
    },
)
REMOVED_BACKUP: Final = ResultReason(
    "removed_backup",
    {
        Result.FAILED: (
            "Barectl could not delete every kept repository or key for the removed site, so "
            "some backups stay where they are. Read the run's journal on the server, then "
            "prepare a new review of what remains."
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
OFFSITE_SETUP_REASONS: Final = (
    BACKUP_LOCK,
    OFFSITE_KEY,
    OFFSITE_BUCKET,
    OFFSITE_REPOSITORY,
    OFFSITE_REMOVE,
)
OFFSITE_COPY_REASONS: Final = (
    BACKUP_LOCK,
    OFFSITE_KEY,
    OFFSITE_REPOSITORY,
    OFFSITE_COPY,
)
CONNECT_REASONS: Final = (
    CONNECT_REVIEW,
    CONNECT_KEY,
    CONNECT_SETTINGS,
    CONNECT_REPOSITORY,
    CONNECT_PASSWORD,
)
PASSPHRASE_REASONS: Final = (
    PASSPHRASE_REVIEW,
    PASSPHRASE_VALUE,
    PASSPHRASE_KEY,
    PASSPHRASE_REPOSITORY,
    PASSPHRASE_OLD,
    PASSPHRASE_NEW,
    PASSPHRASE_SERVER_KEY,
)
RESTORE_CORE_REASONS: Final = (
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
RESTORE_REASONS: Final = (*SITE_REASONS, *RESTORE_CORE_REASONS)
EXPORT_BODY_REASONS: Final = (
    EXPORT_STAGE,
    EXPORT_FILES,
    EXPORT_SIZE,
    EXPORT_DATABASE,
    EXPORT_EVIDENCE,
    EXPORT_REPOSITORY,
    EXPORT_LOCK,
    EXPORT_SECRET,
)
# Export stages the restore body's admission and restore helpers, so it carries those
# reasons too. They are the declarations restore already owns, reused rather than repeated.
EXPORT_REASONS: Final = (*EXPORT_BODY_REASONS, *RESTORE_CORE_REASONS)
RETENTION_BODY_REASONS: Final = (
    BACKUP_SITE,
    BACKUP_VERIFY,
    BACKUP_LOCK,
    BACKUP_UNKNOWN,
    CLEANUP_CLOCK,
)
RETENTION_KIND_REASONS: Final = (*SITE_REASONS, *RETENTION_BODY_REASONS)
REOPEN_REASONS: Final = (*SITE_REASONS, SITE_REOPEN)

# The scheduled integrity check is a native body, not a change kind: the units run it
# directly, so its vocabulary is registered the same way a kind's body would be.
register_body(
    "backup_integrity",
    INTEGRITY_REASONS,
    sources=("backups/bodies/integrity.py",),
)
# The scheduled retention cleanup is the same shape: its units run the retention body
# directly, so its clock and failure reasons need the same registration.
register_body(
    "backup_retention_cleanup",
    RETENTION_BODY_REASONS,
    sources=("backups/bodies/retention.py",),
)

SCHEDULE_REASONS: Final = (
    *SITE_REASONS,
    BACKUP_SITE,
    BACKUP_REPOSITORY,
    BACKUP_LOCK,
    BACKUP_UNKNOWN,
    BACKUP_DISK,
    BACKUP_VERIFY,
    SCHEDULE_TIMER,
    SCHEDULE_UNITS,
    SCHEDULE_INSTALL,
)
REMOVED_REASONS: Final = (
    BACKUP_LOCK,
    OFFSITE_KEY,
    REMOVED_BACKUP,
)
