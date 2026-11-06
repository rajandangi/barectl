"""The one result-reason vocabulary for every change body (#495).

A body's composer declares the reasons its staged text can print, next to that text. A
kind's vocabulary is the union of the fragments it stages plus the engine's admission
prelude, which is declared once here for every kind. ``register_kind`` merges those
declarations, indexes every sentence by reason and execution outcome, and refuses a
duplicate reason with conflicting wording.

Reading stays permissive by construction: the accepted set is every registered kind's
reasons plus the retired set, so another controller can read a line printed by a body it
did not stage and an older refusal never becomes unreadable evidence
(docs/adr/0035-one-change-engine-with-effect-derived-consent.md).
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from . import native
from .models import Result

REPOSITORY: Final = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class ResultReason:
    """One fixed wire reason and one plain sentence per outcome it is paired with.

    Most reasons carry one sentence. The case that proves the shape is a lock reason that
    reads as a refusal before changes in one outcome and as contention in another.
    """

    name: str
    sentences: Mapping[Result, str]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]*", self.name):
            raise ValueError(f"Not a result reason name: {self.name!r}")
        if not self.sentences:
            raise ValueError(f"Result reason {self.name!r} declares no sentence.")
        for outcome, sentence in self.sentences.items():
            if not isinstance(outcome, Result):
                raise ValueError(f"Result reason {self.name!r} names an unknown outcome.")
            if not sentence.strip():
                raise ValueError(
                    f"Result reason {self.name!r} has no sentence for {outcome.value!r}."
                )

    @property
    def outcomes(self) -> frozenset[Result]:
        return frozenset(self.sentences)

    def sentence(self, outcome: Result) -> str:
        return self.sentences.get(outcome, "")


# The generic sentence for an outcome whose reason has no sentence of its own.
OUTCOME_SENTENCES: Final[dict[Result, str]] = {
    Result.REFUSED: "The run stopped before changing anything.",
    Result.LOCK_BUSY: "Another change held Barectl's mutation lock on the server, so the run stopped before changing anything. Prepare a new review after that change finishes.",  # noqa: E501
    Result.PARTIAL: "The run stopped after changing the server, so the change is partly applied and no rollback happens. Read the unit's journal on the server, then prepare a new review of what remains.",  # noqa: E501
    Result.FAILED: "The run failed without reporting how far it got, so what changed is unknown and no rollback happens. Read the unit's journal on the server, then prepare a new review before any later change.",  # noqa: E501
    Result.TIMED_OUT: f"The run reached its {native.RUNTIME_MAX} limit and systemd stopped it; what changed is unknown and no rollback happens. Read the unit's journal on the server, then prepare a new review.",  # noqa: E501
}

AFFECTED_SITES_CHANGED: Final = (
    "Affected sites changed, review again: the sites this shared change reaches differ "
    "from the reviewed list, so the run stopped before changing anything."
)
_RELOAD_FAILURE: Final = (
    "Barectl could not restart every running PHP master and site proxy, so discovery may "
    "report them outside supported settings until the server is restarted. Read the run's "
    "journal on the server, then prepare a new review."
)

# The sentences accepted before the migration, kept for outcomes that pair the reason
# before the area's own declaration lands. Ticket #506 deletes this table.
_LEGACY_SENTENCES: Final[dict[str, str]] = {
    "runtime_cache": "The locked runtime closure is unavailable from the signed cache. Nothing changed.",  # noqa: E501
    "apt_active": "Package maintenance still has processes. Wait for it to finish and review again.",  # noqa: E501
    "apt_unreadable": "Package maintenance process state could not be read. Review again.",
    "unsafe_lock": "The lock directory /run/lock/barectl or its lock file is not a root-owned private directory with an empty lock file, so the run stopped before changing anything. Remove it through ordinary administration, then prepare again.",  # noqa: E501
    "boot": "The server restarted after the change was reviewed, so the run stopped before changing anything. Prepare a new review.",  # noqa: E501
    "deadline": "The review's admission deadline had passed on the server's clock when the run started, so it stopped before changing anything. Prepare a new review.",  # noqa: E501
    "active_run": "Another barectl run still had processes on the server, so this run stopped before changing anything. Prepare a new review after it finishes.",  # noqa: E501
    "revert_active": "A firewall or sign-in change is inside its confirmation window, or its put-back has not finished. The server keeps the change it can restore on its own, so this run stopped before changing anything. Wait for the window to close, then prepare again.",  # noqa: E501
    "revert_preimage": "Barectl could not save the previous access settings, so it stopped before changing anything. Check the run's journal on the server, then prepare again.",  # noqa: E501
    "revert_arm": "Barectl could not arm the automatic put-back, so it stopped before changing anything.",  # noqa: E501
    "firewall_ports": "The server's SSH ports changed or no longer agree, so the run stopped before changing the firewall. Prepare a new review.",  # noqa: E501
    "firewall_outside": "Another packet filter or a rule outside the supported shape appeared on the server, so the run stopped before changing the firewall.",  # noqa: E501
    "firewall_package": "The firewall's package transaction did not match the reviewed one, so the run stopped before changing the firewall. Prepare a new review.",  # noqa: E501
    "firewall_standard": "The rule to remove is no longer an extra allowance, or the standard web and SSH allowances were asked for. The run stopped before changing the firewall. Prepare a new review.",  # noqa: E501
    "firewall_apply": "The firewall change stopped partway. The server restores the previous firewall on its own; check the run's journal if it does not.",  # noqa: E501
    "firewall_verify": "The firewall did not read back as the reviewed change. The server restores the previous firewall on its own; check the run's journal if it does not.",  # noqa: E501
    "sign_in_syntax": "OpenSSH rejected the configuration. The server restores the previous sign-in settings on its own.",  # noqa: E501
    "sign_in_reload": "SSH could not reload. The server restores the previous sign-in settings on its own.",  # noqa: E501
    "sign_in_verify": "The effective sign-in settings do not match the reviewed policy. The server restores the previous settings on its own.",  # noqa: E501
    "sign_in_apply": "The sign-in change stopped partway. The server restores the previous settings on its own.",  # noqa: E501
    "active_backup": "This site's scheduled backup still had processes on the server, so this run stopped before changing anything. Prepare a new review after it finishes.",  # noqa: E501
    "capacity": "The server kept too many finished barectl runs when this run held the lock, so it stopped before changing anything. Clear finished runs with a reviewed cleanup, then prepare again.",  # noqa: E501
    "affected_sites": AFFECTED_SITES_CHANGED,
    "evidence": "The reviewed evidence changed on the server, so the run stopped before changing anything. Prepare a new review.",  # noqa: E501
    "release_absent": "The release this change names is no longer retained on the server, so the run stopped before changing anything. Prepare a new review from the current release list.",  # noqa: E501
    "database_engine": "The server's resolved package set differs from the reviewed one, so Barectl stopped before changing packages. Prepare a new review.",  # noqa: E501
    "database_reload": "The database engine change was applied, but " + _RELOAD_FAILURE,
    "valkey_server": "The server's resolved package set differs from the reviewed one, so Barectl stopped before changing packages. Prepare a new review.",  # noqa: E501
    "valkey_mask": "Valkey was installed, but Barectl could not stop and mask the distribution's shared service, so it may still run. Read the run's journal on the server, stop and mask valkey-server.service through ordinary administration, then prepare a new review.",  # noqa: E501
    "valkey_reload": "Valkey was installed and masked, but " + _RELOAD_FAILURE,
    "site_readiness": "The site did not answer its readiness path as required: the home page must answer below 500, and a path other than / must answer exactly 200. Check the site's code or choose another path, then prepare a new review.",  # noqa: E501
    "readiness_publish": "Barectl could not publish and verify the site's new readiness path, so the previous Caddy file is still serving. Check the run's journal, then prepare a new review.",  # noqa: E501
    "site_pool": "Barectl could not prove the site's new PHP settings after reloading its own master, so it restored the previous pool. Check the run's journal, then prepare a new review.",  # noqa: E501
    "object_cache": "The object cache change stopped before it finished. Nothing on the server was rolled back; read the run's journal, then prepare a new review that proposes only what remains.",  # noqa: E501
    "object_cache_instance": "The site's own cache instance did not start or is not the reviewed shape. Read the run's journal on the server, then prepare a new review.",  # noqa: E501
    "object_cache_wiring": "The cache instance is running, but Barectl could not finish the site's WordPress connection. Read the run's journal, then prepare a new review.",  # noqa: E501
    "object_cache_plugin": "The pinned Redis Object Cache plugin could not be installed, activated or connected. Read the run's journal on the server, then prepare a new review.",  # noqa: E501
    "object_cache_verify": "The object cache changed, but the site did not report the reviewed state afterwards. Read the run's journal, then prepare a new review that proposes only what remains.",  # noqa: E501
    "site_client": "Barectl could not prove the site's cache PHP client after restarting its own master. Check the run's journal, then prepare a new review.",  # noqa: E501
    "logrotate_missing": "This server does not run logrotate, so the run stopped before changing anything. Install and enable it with ordinary administration, check the server again, then prepare a new review.",  # noqa: E501
    "rotation_invalid": "logrotate refused the reviewed rotation file, so Barectl did not keep it. Check the run's journal, then prepare a new review.",  # noqa: E501
    "automatic_updates_package": "The reviewed unattended-upgrades package transaction did not match the server's resolved one, so Barectl stopped before further changes. Prepare a new review.",  # noqa: E501
    "automatic_updates_configure": "Ubuntu's automatic-update settings were not accepted. Read the server again before preparing a new review.",  # noqa: E501
    "automatic_updates_verify": "The automatic-update settings did not read back as reviewed. Read the server again before preparing a new review.",  # noqa: E501
    "automatic_updates_settings": "The server's customized automatic-update settings changed during the run, so Barectl stopped without overwriting them. Check them through ordinary administration.",  # noqa: E501
    "automatic_updates_failed": "The automatic-updates change stopped before reporting its outcome. Read the server again before preparing a new review.",  # noqa: E501
    "updates_refresh": "Ubuntu's package lists were not refreshed, so nothing was installed. Check the server's configured Ubuntu archive, then prepare a new review.",  # noqa: E501
    "updates_refresh_failed": "The package-list refresh stopped before reporting its outcome. Read the server again before preparing a new review.",  # noqa: E501
    "updates_transaction": "The server's resolved package transaction differs from the reviewed one, so Barectl stopped before changing packages. Check for updates and prepare a new review.",  # noqa: E501
    "updates_hold": "A reviewed package is now held with apt-mark hold, so Barectl stopped before changing packages. Release the hold through ordinary administration, then prepare a new review.",  # noqa: E501
    "updates_conffile": "A reviewed package's configuration file differs from the package's own copy, so Barectl stopped before changing packages. Restore or confirm it through ordinary administration, then prepare a new review.",  # noqa: E501
    "updates_pending": "Ubuntu's package database has an unfinished package state, so Barectl stopped before changing packages. Finish it through ordinary administration, then prepare a new review.",  # noqa: E501
    "updates_verify": "The reviewed packages were installed, but a package version or the package database did not read back as expected. Read the server again before preparing a new review.",  # noqa: E501
    "updates_failed": "The updates change stopped before reporting its outcome. Read the server again before preparing a new review that proposes only what remains.",  # noqa: E501
    "restart_work": "A site backup, copy, check or cleanup, or Ubuntu's package maintenance, still had processes on the server, so the restart stopped before changing anything. Prepare a new review after it finishes.",  # noqa: E501
    "restart_evidence": "The packages that asked for a restart changed after the review, so the restart stopped before changing anything. Read the server again and prepare a new review.",  # noqa: E501
    "restart_apply": "The restart stopped before asking the server to start again. Read the server through ordinary administration and prepare a new review.",  # noqa: E501
    "site_database": "The site's own PHP master did not answer as the site user through its driver, or the database catalog changed, so Barectl stopped before creating the binding. Prepare a new review.",  # noqa: E501
    "site_database_driver": "The site's own PHP master did not load its driver or answer as the site user, so Barectl stopped before creating the binding. Check the site's PHP master, then prepare a new review.",  # noqa: E501
    "laravel_source": "The site's repository or branch could not be resolved to a commit without fetch, so the run stopped before changing anything. Check the repository and branch, then prepare a new review.",  # noqa: E501
    "laravel_fetch": "The reviewed commit could not be fetched, so the run stopped before switching code. The previous release is still serving.",  # noqa: E501
    "laravel_composer": "The release's dependencies could not be installed in isolation, so the run stopped before switching code. The previous release is still serving.",  # noqa: E501
    "laravel_platform": "The release requires a PHP version or extension the site's runtime does not provide, so the run stopped before switching code. The previous release is still serving.",  # noqa: E501
    "laravel_migrations": "A migration failed or the schema could not be verified, so Barectl kept the maintenance page up and did not open the new release or reactivate older code. Read the run's journal on the server, then prepare a new review.",  # noqa: E501
    "laravel_gate": "Barectl could not establish the maintenance page, so the run stopped before changing code. Review again.",  # noqa: E501
    "laravel_readiness": "The new release did not answer its readiness check, so it was not opened to visitors. The maintenance page is still up; read the run's journal and prepare a new review.",  # noqa: E501
    "laravel_disk": "The server lacks the free space the review stated, so the run stopped before changing anything. Free space on the server, then prepare a new review.",  # noqa: E501
    "laravel_release": "The new release could not be published in the site's release layout, so the run stopped before switching code. The previous release is still serving.",  # noqa: E501
    "laravel_shared": "The site's shared environment, storage or cache is missing or unsafe, so the run stopped before switching code. The previous release is still serving.",  # noqa: E501
    "laravel_environment": "The site's environment file changed, is outside the supported layout or could not be rewritten safely, so nothing changed. Run discovery and prepare a new review.",  # noqa: E501
    "laravel_config": "The environment changed, but Laravel's cached configuration could not be rebuilt, so the site may still serve the previous configuration. Check the run's journal, then prepare a new review.",  # noqa: E501
    "laravel_environment_managed": "The selected environment key is managed by the site's object cache, so nothing changed. Change the object cache setting instead.",  # noqa: E501
    "laravel_worker": "The environment changed, but a running worker did not restart cleanly. The new configuration is written; check the worker and restart it from Settings.",  # noqa: E501
    "wordpress_settings": "The private WordPress configuration changed, is outside the supported grammar or could not be rewritten safely, so nothing changed. Run discovery and prepare a new review.",  # noqa: E501
    "settings_secret": "The confidential value could not be used, so nothing changed. Prepare a new review and type the value again.",  # noqa: E501
    "wordpress_archive": "The pinned WordPress archive could not be downloaded, so the run stopped before installing application files. Check the run's journal, then prepare a new review.",  # noqa: E501
    "wordpress_archive_digest": "The downloaded WordPress archive did not match the pinned size or SHA-256, so it was discarded and nothing was installed. Check the server's network and prepare a new review.",  # noqa: E501
    "wordpress_extract": "The pinned WordPress archive could not be extracted safely, so no application files were published. Check the run's journal, then prepare a new review.",  # noqa: E501
    "wordpress_configuration": "The private WordPress configuration is missing or outside the supported grammar, so Barectl did not overwrite it. Correct it through ordinary administration, then prepare a new review.",  # noqa: E501
    "wordpress_install": "WordPress did not complete its installation, so the maintenance gate is still up. Read the run's journal on the server, then prepare a new review.",  # noqa: E501
    "wordpress_tables": "The site's WordPress tables already exist without a complete installation, so Barectl did not reinstall into them. Inspect the database through ordinary administration and prepare a new review.",  # noqa: E501
    "wordpress_gate": "Barectl could not establish the maintenance gate, so the run stopped before installing application files. Review again.",  # noqa: E501
    "wordpress_publish": "Barectl could not publish the verified site route, so the maintenance gate stays up. Read the run's journal and prepare a new review.",  # noqa: E501
    "wordpress_readiness": "The site did not answer its home, login and permalink pages over HTTPS, so Barectl restored the maintenance gate. Read the run's journal and prepare a new review.",  # noqa: E501
    "wordpress_create": "The run stopped after changing the server, so the WordPress installation is partly applied and the maintenance gate stays up. Read the unit's journal on the server, then prepare a new review of what remains.",  # noqa: E501
    "wordpress_secret": "The confidential administrator password could not be used, so nothing changed. Prepare a new review and type the password again.",  # noqa: E501
    "wordpress_password": "Barectl did not set a new password: WordPress has no user with that login, the user is not an administrator, or the value cannot be a password. The site is unchanged. Check the username and prepare a new review.",  # noqa: E501
    "wordpress_password_unverified": "The password update ran, but Barectl could not confirm it: WordPress did not store the new password, or its sign-in page did not accept it. The password may have changed, so try signing in before preparing another review.",  # noqa: E501
    "wordpress_checksums": "Barectl compared the installed WordPress core with the official checksums for the reviewed version and found files that do not match. Nothing on the server changed. Inspect the site through ordinary administration and replace the affected files from the official release.",  # noqa: E501
    "wordpress_checksums_unavailable": "Barectl could not compare the WordPress core with the official checksums: the checksum service could not be reached or WP-CLI could not read the site. Nothing on the server changed. Check the server's network access and prepare a new review.",  # noqa: E501
    "certificate_email": "Barectl could not publish, reload and verify the reviewed certificate contact email. The previous main configuration was restored where it had been replaced. Check the run's journal on the server, then prepare a new review.",  # noqa: E501
    "automation": "Barectl could not change the site's scheduled tasks, so nothing more was changed. Check the run's journal on the server, then prepare a new review.",  # noqa: E501
    "automation_site": "The site's account, files or private configuration were not the reviewed ones, so the run stopped before changing anything. Run discovery again and prepare a new review.",  # noqa: E501
    "automation_start": "Barectl could not start the site's scheduled task. Nothing was handed over: page loads still run cron. Check the run's journal, then prepare a new review.",  # noqa: E501
    "automation_tick": "The first scheduled run did not finish successfully within the reviewed wait, so Barectl did not hand cron over and page loads still run it. The server task stays installed and reports its next result; prepare a new review to finish.",  # noqa: E501
    "automation_configuration": "Barectl could not set or clear the site's cron setting in the private WordPress configuration. Check the run's journal, then prepare a new review.",  # noqa: E501
    "automation_units": "Barectl could not remove the site's scheduled task, so it may still be installed. Check the run's journal, then prepare a new review.",  # noqa: E501
    "queue_workers": "Barectl could not change the site's queue workers, so the run stopped. The site may be partly changed; check the run's journal on the server, then prepare a new review.",  # noqa: E501
    "queue_workers_site": "The site's account, current release or private files were not the reviewed ones, so the run stopped before changing anything. Run discovery again and prepare a new review.",  # noqa: E501
    "queue_workers_activation": "The site's current release changed before the workers could start, so the run stopped without changing them. Deploy again, then prepare a new review.",  # noqa: E501
    "queue_workers_environment": "Barectl could not write the site's retry interval, so no worker was started. Check the run's journal, then prepare a new review.",  # noqa: E501
    "queue_workers_start": "Barectl could not confirm that every queue worker process is running. Check the run's journal, then prepare a new review.",  # noqa: E501
    "queue_workers_stop": "Barectl could not confirm that every queue worker stopped. Check the run's journal, then prepare a new review.",  # noqa: E501
    "automation_scheduler": "The site's Laravel files, account or scheduler units were not the reviewed ones, so the run stopped before changing anything. Run discovery again and prepare a new review.",  # noqa: E501
    "automation_run": "The scheduler started one run, but it did not finish successfully. Nothing else was changed. Scheduled tasks shows the run's result; check the application and prepare a new review.",  # noqa: E501
    "automation_running": "The scheduler run is still going after the reviewed wait, so Barectl stopped waiting. It keeps running on the server; Scheduled tasks shows its result when it finishes.",  # noqa: E501
    "automation_fence": "The site's background work did not stop within its budget, so the run stopped before changing anything and the site's background work stays paused. Check the run's journal, then prepare a new review.",  # noqa: E501
    "automation_restore": "The change verified, but Barectl could not prove the site's background work started again, so it stays paused and the change is partly applied. Check the run's journal, then prepare a new review.",  # noqa: E501
    "backup_site": "The site's Linux account could not be read, so the backup stopped before changing anything. Run discovery and prepare a new review.",  # noqa: E501
    "backup_repository": "The site's backup repository could not be read or created, so nothing was captured. Read the run's journal on the server, then prepare a new review.",  # noqa: E501
    "backup_password": "The recovery passphrase did not open the site's repository, so nothing was captured. Prepare a new review and type the passphrase you stored.",  # noqa: E501
    "backup_key": "The server key could not be added or did not open the repository, so units cannot take backups yet. The passphrase still opens it. Prepare a new review to finish.",  # noqa: E501
    "backup_dump": "The database dump failed, so restic saved no recovery point. Check the site's database and prepare a new review.",  # noqa: E501
    "backup_disk": "The server does not have the free space the review keeps in reserve, so nothing was captured and no older backup was removed. Free space, then prepare a new review.",  # noqa: E501
    "backup_lock": "The site was busy with another change, so the backup was skipped. Prepare a new review after that change finishes.",  # noqa: E501
    "backup_verify": "The capture finished but no complete recovery point could be verified in the repository. Read the run's journal on the server and prepare a new review.",  # noqa: E501
    "backup_unknown": "The backup tool reported an error Barectl does not recognize, so nothing is recorded as saved. Read the run's journal on the server and prepare a new review.",  # noqa: E501
    "backup_files": "The site's files could not be copied, so the point is incomplete and the site stays paused. Read the run's journal, then reopen the site and prepare a new review.",  # noqa: E501
    "backup_idle": "The site's running work did not finish within the reviewed wait, so the files were not copied and the site stays paused. Read the run's journal, then reopen the site.",  # noqa: E501
    "backup_paused": "The full backup stopped after pausing the site. Nothing after that ran. Reopen the site, then prepare a new review.",  # noqa: E501
    "backup_gate": "Barectl could not publish or remove the maintenance page, so the site stays paused. Read the run's journal, then reopen the site.",  # noqa: E501
    "offsite_bucket": "The bucket did not answer a write and a listing with the reviewed keys, so Barectl did not keep the offsite storage setting. Check the bucket and keys, then prepare a new review.",  # noqa: E501
    "offsite_repository": "An offsite repository could not be initialised or opened. The copies already in the bucket are unchanged. Check the bucket and keys, then prepare a new review.",  # noqa: E501
    "offsite_key": "The offsite access keys or recovery passphrase could not be used, so nothing was copied. Prepare a new review and type the values again.",  # noqa: E501
    "offsite_copy": "The offsite copy did not finish. The recovery point saved on this server is unchanged; copy it offsite again when the storage is reachable.",  # noqa: E501
    "offsite_remove": "Barectl could not remove the offsite setting from the server. The copies already in the bucket are unchanged. Check the run's journal and prepare a new review.",  # noqa: E501
    "site_reopen": "Barectl could not prove that the site serves its files again, so it may still show the maintenance page. Read the run's journal and prepare a new review.",  # noqa: E501
    "removed_backup": "Barectl could not delete the removed site's backups, so they stay where they are. Read the run's journal on the server, then prepare a new review.",  # noqa: E501
    "restore_site": "The site's Linux account could not be read, so the restore stopped before changing anything. Run discovery and prepare a new review.",  # noqa: E501
    "restore_repository": "The site's backup repository could not be read, so nothing was restored. Read the run's journal on the server, then prepare a new review.",  # noqa: E501
    "restore_evidence": "The site's reviewed files changed before the run started, so nothing was restored. Run discovery and prepare a new review.",  # noqa: E501
    "restore_lock": "The site was busy with another change, so the restore was skipped. Prepare a new review after that change finishes.",  # noqa: E501
    "restore_disk": "The server does not have the free space the review keeps in reserve, so nothing was restored. Free space, then prepare a new review.",  # noqa: E501
    "restore_point": "The recovery point is missing or incomplete, so nothing was restored. Check backups and prepare a new review.",  # noqa: E501
    "restore_engine": "The recovery point was made by a different database version than this site uses, so nothing was restored. Prepare a new review from a matching point.",  # noqa: E501
    "restore_target": "The site's database changed since the review, so nothing was restored. Prepare a new review against the current site.",  # noqa: E501
    "restore_dump": "The recovery point's database copy was truncated, so nothing was restored and the site still serves. Prepare a new review from a complete point.",  # noqa: E501
    "restore_safety": "The safety backup could not be taken or checked, so nothing was overwritten. Read the run's journal and prepare a new review.",  # noqa: E501
    "restore_gate": "Barectl could not publish the maintenance page, so the site's database was not changed. Read the run's journal, then prepare a new review.",  # noqa: E501
    "restore_paused": "The restore stopped after pausing the site. Nothing after that ran. Reopen the site, then prepare a new review.",  # noqa: E501
    "restore_idle": "The site's running requests or background work did not finish within the reviewed wait, so the database was not changed and the site stays paused. Reopen the site.",  # noqa: E501
    "restore_import": "The database import did not finish, so the site stays paused and the data may be partly replaced. Read the run's journal, then reopen the site and check what remained.",  # noqa: E501
    "restore_data": "The import finished but its data checks did not pass, so the site stays paused. Read the run's journal, then reopen the site and check the data.",  # noqa: E501
    "restore_readiness": "The data was imported but the site did not answer its readiness check, so it stays paused. Read the run's journal, then reopen the site and check the application.",  # noqa: E501
    "restore_open": "Barectl could not remove the maintenance page, so the site stays paused. Read the run's journal and prepare a new review.",  # noqa: E501
}

# Sentences that the old caller selected before the table above. They are the exact words
# the run screens showed, so the prefactor changes nothing visible.
_LEGACY_SPECIAL: Final[dict[tuple[str, Result], str]] = {
    ("sign_in_syntax", Result.REFUSED): (
        "OpenSSH rejected the existing configuration before Barectl changed anything."
    ),
    ("sign_in_apply", Result.REFUSED): (
        "Barectl could not prepare the sign-in file before changing the server."
    ),
    ("sign_in_apply", Result.FAILED): (
        "The sign-in file write may have changed the server. The server is restoring "
        "the previous settings on its own."
    ),
}

# Every reason accepted before the migration. Area tickets replace this fallback with
# declarations; #506 deletes it and keeps the genuinely retired names below.
LEGACY_REASONS: Final[frozenset[str]] = frozenset(
    {
        "",
        "active_run",
        "affected_sites",
        "apt_active",
        "apt_unreadable",
        "automatic_updates_configure",
        "automatic_updates_failed",
        "automatic_updates_package",
        "automatic_updates_settings",
        "automatic_updates_verify",
        "automation",
        "automation_configuration",
        "automation_fence",
        "automation_restore",
        "automation_run",
        "automation_running",
        "automation_scheduler",
        "automation_site",
        "automation_start",
        "automation_tick",
        "automation_units",
        "backup_disk",
        "backup_dump",
        "backup_files",
        "backup_gate",
        "backup_idle",
        "backup_key",
        "backup_lock",
        "backup_offsite",
        "backup_partial",
        "backup_password",
        "backup_paused",
        "backup_repository",
        "backup_site",
        "backup_unknown",
        "backup_verify",
        "boot",
        "capacity",
        "certificate_email",
        "cleanup",
        "database_engine",
        "database_reload",
        "deadline",
        "download",
        "evidence",
        "firewall_apply",
        "firewall_outside",
        "firewall_package",
        "firewall_ports",
        "firewall_standard",
        "firewall_verify",
        "foreign_stack",
        "foundation",
        "headroom",
        "installer_digest",
        "laravel_composer",
        "laravel_config",
        "laravel_disk",
        "laravel_environment",
        "laravel_environment_managed",
        "laravel_fetch",
        "laravel_gate",
        "laravel_migrations",
        "laravel_platform",
        "laravel_readiness",
        "laravel_release",
        "laravel_shared",
        "laravel_source",
        "laravel_worker",
        "logrotate_missing",
        "nix_incomplete",
        "object_cache",
        "object_cache_instance",
        "object_cache_plugin",
        "object_cache_verify",
        "object_cache_wiring",
        "offsite_bucket",
        "offsite_copy",
        "offsite_key",
        "offsite_remove",
        "offsite_repository",
        "platform",
        "precondition",
        "privilege",
        "queue_workers",
        "queue_workers_activation",
        "queue_workers_environment",
        "queue_workers_site",
        "queue_workers_start",
        "queue_workers_stop",
        "readiness_publish",
        "release_absent",
        "removed_backup",
        "restart_apply",
        "restart_evidence",
        "restart_work",
        "restore_config",
        "restore_data",
        "restore_disk",
        "restore_done",
        "restore_dump",
        "restore_engine",
        "restore_evidence",
        "restore_files",
        "restore_gate",
        "restore_idle",
        "restore_import",
        "restore_lock",
        "restore_open",
        "restore_paused",
        "restore_point",
        "restore_readiness",
        "restore_repository",
        "restore_safety",
        "restore_site",
        "restore_target",
        "revert_active",
        "revert_arm",
        "revert_preimage",
        "rotation_invalid",
        "runtime_cache",
        "runtime_config",
        "runtime_realise",
        "runtime_start",
        "schedule_install",
        "schedule_timer",
        "schedule_units",
        "settings_secret",
        "sign_in_apply",
        "sign_in_reload",
        "sign_in_syntax",
        "sign_in_verify",
        "site_caddy",
        "site_client",
        "site_create",
        "site_database",
        "site_database_after",
        "site_database_database",
        "site_database_driver",
        "site_database_principal",
        "site_database_privileges",
        "site_database_probe",
        "site_database_proof",
        "site_database_schema",
        "site_readiness",
        "site_remove",
        "site_remove_accounts",
        "site_remove_caddy",
        "site_remove_certificate",
        "site_remove_configuration",
        "site_remove_database",
        "site_remove_evidence",
        "site_remove_files",
        "site_remove_gate",
        "site_remove_services",
        "site_remove_verify",
        "site_reopen",
        "unsafe_lock",
        "updates_conffile",
        "updates_failed",
        "updates_hold",
        "updates_pending",
        "updates_refresh",
        "updates_refresh_failed",
        "updates_transaction",
        "updates_verify",
        "valkey_mask",
        "valkey_reload",
        "valkey_server",
        "wordpress_archive",
        "wordpress_archive_digest",
        "wordpress_checksums",
        "wordpress_checksums_unavailable",
        "wordpress_configuration",
        "wordpress_create",
        "wordpress_extract",
        "wordpress_gate",
        "wordpress_install",
        "wordpress_password",
        "wordpress_password_unverified",
        "wordpress_publish",
        "wordpress_readiness",
        "wordpress_secret",
        "wordpress_settings",
        "wordpress_tables",
    }
)

# Reasons no current body prints: recognized when read, never produced fresh.
RETIRED: Final[frozenset[str]] = frozenset()


# The engine's own admission prelude, declared once for every kind. Every reason here is
# paired with a refusal before changes unless a kind's own body also pairs it.
def _admission(name: str, *outcomes: Result) -> ResultReason:
    sentence = _LEGACY_SENTENCES.get(name)
    if sentence is None:
        raise ValueError(f"Admission reason {name!r} has no sentence.")
    return ResultReason(name, dict.fromkeys(outcomes, sentence))


ADMISSION: Final[tuple[ResultReason, ...]] = (
    _admission("unsafe_lock", Result.REFUSED, Result.PARTIAL),
    _admission("boot", Result.REFUSED, Result.PARTIAL),
    _admission("deadline", Result.REFUSED, Result.PARTIAL),
    _admission("active_run", Result.REFUSED, Result.PARTIAL),
    _admission("revert_active", Result.REFUSED, Result.PARTIAL),
    _admission("capacity", Result.REFUSED, Result.PARTIAL),
    _admission("affected_sites", Result.REFUSED, Result.PARTIAL),
    _admission("apt_active", Result.REFUSED, Result.PARTIAL),
    _admission("apt_unreadable", Result.REFUSED, Result.PARTIAL),
    _admission("evidence", Result.REFUSED, Result.PARTIAL),
    ResultReason(
        "active_backup",
        {
            Result.REFUSED: (
                "This site's scheduled backup still had processes on the server, so this run "
                "stopped before changing anything. Prepare a new review after it finishes."
            ),
            Result.PARTIAL: (
                "This site's scheduled backup still had processes on the server, so this run "
                "stopped before changing anything. Prepare a new review after it finishes."
            ),
        },
    ),
)

_INDEX: Final[dict[tuple[str, Result], str]] = {}
_KIND_REASONS: Final[dict[str, tuple[ResultReason, ...]]] = {}
_BODY_VOCABULARIES: Final[dict[str, tuple[tuple[ResultReason, ...], tuple[str, ...]]]] = {}
_ACCEPTED: Final[set[str]] = set(LEGACY_REASONS) | {""}


def _index(reason: ResultReason) -> None:
    for outcome, sentence in reason.sentences.items():
        key = (reason.name, outcome)
        declared = _INDEX.get(key)
        if declared is not None and declared != sentence:
            raise ValueError(
                "Two composers declare different wording for result reason "
                f"{reason.name!r} and outcome {outcome.value!r}."
            )
        _INDEX[key] = sentence


def register_kind(kind: object) -> None:
    """Merge one kind's body vocabulary with the admission prelude and index it."""
    declared = tuple(getattr(kind, "reasons", ()) or ())
    slug = str(getattr(kind, "slug", ""))
    _KIND_REASONS[slug] = declared
    _KIND_BY_SLUG[slug] = kind
    for reason in (*ADMISSION, *declared):
        _index(reason)
    _ACCEPTED.update(reason.name for reason in (*ADMISSION, *declared))
    _ACCEPTED.update(LEGACY_REASONS)


def accepted(reason: str) -> bool:
    """Whether the parser recognizes ``reason`` as a result reason."""
    return reason in _ACCEPTED


def accepted_reasons() -> frozenset[str]:
    return frozenset(_ACCEPTED)


def sentence(outcome: Result, reason: str) -> str:
    """The one sentence for a reason and outcome; never keyed by kind."""
    specific = _INDEX.get((reason, outcome))
    if specific:
        return specific
    special = _LEGACY_SPECIAL.get((reason, outcome))
    if special:
        return special
    legacy = _LEGACY_SENTENCES.get(reason)
    if legacy and outcome in (Result.REFUSED, Result.PARTIAL):
        return legacy
    return OUTCOME_SENTENCES.get(outcome, "")


# The manifest -------------------------------------------------------------------------------

_PAIR_CLASS_FIRST = re.compile(
    r'"class"\s*:\s*"([a-z_]+)"[^\n}]*?"reason"\s*:\s*"([a-z][a-z0-9_]*)"'
)
_PAIR_REASON_FIRST = re.compile(
    r'"reason"\s*:\s*"([a-z][a-z0-9_]*)"[^\n}]*?"class"\s*:\s*"([a-z_]+)"'
)
_REFUSED = re.compile(r"(?m)(?:^|[;&|{])\s*refused\s+([a-z][a-z0-9_]*)\s*(?:;|$)")
_FAIL = re.compile(
    r"(?m)(?:^|[;&|{])\s*fail\s+(refused|partial|failed|lock_busy|timed_out)"
    r"\s+([a-z][a-z0-9_]*)\s*(?:;|$)"
)
_CALL = re.compile(r'\b(refused|failed)\("([a-z][a-z0-9_]*)"\)')
_EXPORT = re.compile(r'ExportRefused\("([a-z][a-z0-9_]*)"\)')
_RESULT = re.compile(
    r'result\(\s*"(refused|partial|failed|lock_busy|timed_out|succeeded)"\s*,\s*'
    r'"([a-z][a-z0-9_]*)"'
)
_DOCUMENT_RESULT = re.compile(r'document_result\([^,]+,\s*"([a-z_]+)",\s*"([a-z][a-z0-9_]*)"')


def printed_pairs(text: str) -> dict[str, set[str]]:
    """The reason names a body text can print, and the classes paired with each."""
    pairs: dict[str, set[str]] = {}

    def add(reason: str, result_class: str) -> None:
        pairs.setdefault(reason, set()).add(result_class)

    for match in _PAIR_CLASS_FIRST.finditer(text):
        add(match.group(2), match.group(1))
    for match in _PAIR_REASON_FIRST.finditer(text):
        add(match.group(1), match.group(2))
    for match in _REFUSED.finditer(text):
        add(match.group(1), "refused")
    for match in _FAIL.finditer(text):
        add(match.group(2), match.group(1))
    for match in _CALL.finditer(text):
        add(match.group(2), match.group(1))
    for match in _EXPORT.finditer(text):
        add(match.group(1), "refused")
    for match in _RESULT.finditer(text):
        add(match.group(2), match.group(1))
    for match in _DOCUMENT_RESULT.finditer(text):
        add(match.group(2), match.group(1))
    return pairs


def _body_declared() -> dict[str, ResultReason]:
    return {
        reason.name: reason
        for declared, _sources in _BODY_VOCABULARIES.values()
        for reason in declared
    }


def register_body(
    name: str,
    declared: tuple[ResultReason, ...],
    sources: tuple[str, ...] = (),
) -> None:
    """Register a non-kind composer's vocabulary, such as a scheduled integrity body."""
    _BODY_VOCABULARIES[name] = (tuple(declared), tuple(sources))
    for reason in declared:
        _index(reason)
    _ACCEPTED.update(reason.name for reason in declared)


def _vocabulary_errors(
    label: str,
    declared: tuple[ResultReason, ...],
    sources: tuple[str, ...],
    shared: dict[str, ResultReason],
) -> list[str]:
    errors: list[str] = []
    by_name = {**shared, **{reason.name: reason for reason in (*ADMISSION, *declared)}}
    declared_names = set(by_name)
    text_all = ""
    for source in sources:
        path = REPOSITORY / source
        try:
            text = path.read_text()
        except OSError:
            errors.append(f"{source}: body source could not be read.")
            continue
        text_all += text
        for reason, classes in printed_pairs(text).items():
            if reason not in by_name:
                errors.append(
                    f"{source}: prints result reason {reason!r}, which its composer "
                    "does not declare."
                )
                continue
            for result_class in classes:
                try:
                    outcome = Result(result_class)
                except ValueError:
                    continue
                if reason in declared_names and outcome not in by_name[reason].outcomes:
                    errors.append(
                        f"{source}: reason {reason!r} is paired with {result_class!r}, "
                        "which its declaration does not carry."
                    )
    for declared_reason in declared:
        if declared_reason.name not in text_all and declared_reason.name not in RETIRED:
            errors.append(
                f"{label}: composer declares {declared_reason.name!r}, which its body text "
                "cannot print."
            )
        errors.extend(
            f"{declared_reason.name!r}: no sentence for outcome {outcome.value!r}."
            for outcome in declared_reason.outcomes
            if not declared_reason.sentence(outcome)
        )
    return errors


def manifest_errors() -> list[str]:
    """Every drift between a declared vocabulary and its composed text.

    Database-free and filesystem-only, so the fast gate can call it on every run. The
    message names the file, reason and outcome that drifted.
    """
    shared = _body_declared()
    errors: list[str] = []
    for slug, declared in _KIND_REASONS.items():
        kind = _KIND_BY_SLUG.get(slug)
        sources = tuple(getattr(kind, "body_sources", ()) or ())
        if kind is not None and sources:
            errors.extend(_vocabulary_errors(slug, declared, sources, shared))
    for name, (declared, sources) in _BODY_VOCABULARIES.items():
        if sources:
            errors.extend(_vocabulary_errors(name, declared, sources, shared))
    return errors


_KIND_BY_SLUG: Final[dict[str, object]] = {}
