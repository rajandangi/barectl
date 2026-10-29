"""The plain words the confirm and run screens show for each change kind (#179).

Presentation only. A kind with no entry falls back to its own label and its stage names,
so a later ticket adds its kind's words here without touching the engine, a review, a
body or a stage. Nothing in this module decides eligibility, consent or an outcome.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final


class Home(StrEnum):
    """Where a change starts, so its confirm screen can go back there."""

    SERVER = "server"
    SERVER_SITES = "server_sites"
    SERVER_SETTINGS = "server_settings"
    SERVER_SITE_CREATE = "server_site_create"
    SITE = "site"
    SITE_BACKUPS = "site_backups"


@dataclass(frozen=True)
class ChangeWords:
    """One kind's wording: ``{server}``, ``{site}`` and ``{selection}`` are filled in."""

    title: str
    summary: tuple[str, ...]
    action: str
    steps: dict[str, str] = field(default_factory=dict)
    home: Home = Home.SERVER
    # The action offered once the change succeeded, where it leads, and the permission
    # reading that page needs.
    after: str = ""
    after_home: Home = Home.SERVER
    after_permission: str = ""


_ENGINE_LABELS: Final[dict[str, str]] = {"mariadb": "MariaDB", "postgresql": "PostgreSQL"}


def selection_label(selection: str) -> str:
    """A runtime or engine selection in words: ``php85`` is PHP 8.5, ``mariadb`` MariaDB."""
    if selection.startswith("php") and len(selection) == 5 and selection[3:].isdigit():
        return f"PHP {selection[3]}.{selection[4]}"
    if selection.startswith("nodejs_"):
        return f"Node.js {selection.removeprefix('nodejs_')}"
    return _ENGINE_LABELS.get(selection, selection)


_WORDS: Final[dict[str, ChangeWords]] = {
    "set_up_log_rotation": ChangeWords(
        title="Set up log rotation for {site}",
        summary=(
            ("Barectl will write {site}'s own rotation file and test it before keeping it."),
            (
                "The site's error and slow-request logs are rotated daily or at 20 MiB, "
                "keeping five compressed files for fourteen days."
            ),
            "The visit log and the application's own daily log keep their own rotation.",
        ),
        action="Set up rotation",
        steps={
            "preflight": "Checking the server",
            "publish": "Writing the rotation file",
            "verify": "Verifying",
        },
        home=Home.SITE,
        after="Open the logs",
        after_home=Home.SITE,
    ),
    "host_foundation": ChangeWords(
        title="Set up {server}",
        summary=(
            (
                "Barectl will install the web server and the tools it uses on {server}, "
                "and keep its logs across reboots."
            ),
            "It downloads a few packages and takes a few minutes.",
            "No sites change.",
        ),
        action="Set up server",
        steps={
            "preflight": "Checking the server",
            "Nix": "Installing",
            "catalog": "Installing the site tools",
            "Caddy": "Starting the web server",
            "journald": "Keeping logs",
            "verify": "Verifying",
        },
        home=Home.SERVER,
        after="Create site",
        after_home=Home.SERVER_SITE_CREATE,
        after_permission="operations.change_site",
    ),
    "add_runtime": ChangeWords(
        title="Add {selection} to {server}",
        summary=(
            "Barectl will install {selection} on {server}.",
            "Sites keep the versions they already have until you choose the new one.",
        ),
        action="Add {selection}",
        steps={
            "preflight": "Checking the server",
            "realise": "Installing",
            "configure": "Preparing {selection}",
            "validate": "Checking {selection} starts",
            "verify": "Verifying",
        },
        home=Home.SERVER,
        after="Create site",
        after_home=Home.SERVER_SITE_CREATE,
        after_permission="operations.change_site",
    ),
    "create_http_site": ChangeWords(
        title="Create {site}",
        summary=(
            (
                "Barectl will create an account and folders for {site}, start {selection} "
                "for it, and serve a placeholder page over HTTP."
            ),
        ),
        action="Create site",
        steps={
            "preflight": "Checking the server",
            "account": "Creating the account and folders",
            "layout": "Preparing the site folders",
            "pool": "Starting PHP",
            "caddy": "Adding the site to the web server",
            "verify": "Checking the site answers",
        },
        home=Home.SERVER_SITES,
        after="Open the site",
        after_home=Home.SITE,
    ),
    "set_site_php": ChangeWords(
        title="Switch {site} to {selection}",
        summary=(
            "{site} keeps serving while Barectl switches it to {selection}.",
            (
                "If the new version lacks something the site uses, the change stops "
                "before anything moves."
            ),
        ),
        action="Switch version",
        steps={
            "preflight": "Checking the server",
            "target": "Preparing the new version",
            "admission": "Holding new requests",
            "persist": "Saving the setting",
            "drain": "Finishing current requests",
            "commands": "Switching the site over",
            "verify": "Checking the site answers",
        },
        home=Home.SITE,
        after="Back to the site",
        after_home=Home.SITE,
    ),
    "set_site_object_cache": ChangeWords(
        title="Turn on the object cache for {site}",
        summary=(
            (
                "{site} gets its own private cache. A WordPress site gets the pinned cache "
                "plugin; a Laravel site's cache store points at it, its cached configuration "
                "is rebuilt and any running workers restart."
            ),
            "No other site can read, clear or fill this cache.",
            (
                "The site keeps serving; WordPress may refuse a request while its cache "
                "connection and plugin are prepared."
            ),
        ),
        action="Turn on object cache",
        steps={
            "preflight": "Checking the server",
            "instance": "Starting the site's cache",
            "wiring": "Connecting WordPress",
            "plugin": "Installing the cache plugin",
            "environment": "Pointing the site at its cache",
            "config": "Rebuilding the site's configuration",
            "workers": "Restarting the site's workers",
            "disconnect": "Disconnecting the site",
            "stop": "Stopping the site's cache",
            "verify": "Checking the cache connects",
        },
        home=Home.SITE,
        after="Back to the site",
        after_home=Home.SITE,
    ),
    "set_site_node": ChangeWords(
        title="Switch {site} to {selection}",
        summary=(
            "{site} keeps serving while Barectl switches its Node.js version to {selection}.",
            (
                "If the new version lacks something the site uses, the change stops "
                "before anything moves."
            ),
        ),
        action="Switch version",
        steps={
            "preflight": "Checking the server",
            "links": "Switching the Node.js commands",
            "verify": "Checking the site answers",
        },
        home=Home.SITE,
        after="Back to the site",
        after_home=Home.SITE,
    ),
    "install_database_engine": ChangeWords(
        title="Install {selection} on {server}",
        summary=(
            "Barectl will install {selection} on {server} and start it.",
            "Sites do not use a database until you give one to a site.",
        ),
        action="Install database",
        steps={
            "preflight": "Checking the server",
            "install": "Installing",
            "start": "Starting the database",
            "harden": "Securing the database",
            "verify": "Verifying",
        },
        home=Home.SERVER_SETTINGS,
        after="Create site",
        after_home=Home.SERVER_SITE_CREATE,
        after_permission="operations.change_site",
    ),
    "install_valkey": ChangeWords(
        title="Install Valkey on {server}",
        summary=(
            "Barectl will install Valkey on {server} and keep one shared cache from running.",
            "Each site that uses the object cache later gets its own private cache.",
        ),
        action="Install Valkey",
        steps={
            "preflight": "Checking the server",
            "install": "Installing",
            "mask": "Stopping the shared cache",
            "recover": "Restarting the site services",
            "verify": "Verifying",
        },
        home=Home.SERVER_SETTINGS,
    ),
    "create_wordpress_site": ChangeWords(
        title="Create {site}",
        summary=(
            (
                "Barectl will create an account and folders for {site}, install WordPress "
                "and its database, and serve the site."
            ),
        ),
        action="Create WordPress site",
        steps={
            "preflight": "Checking the server",
            "site": "Creating the account and folders",
            "gate": "Checking the site",
            "database": "Preparing the database",
            "download": "Downloading WordPress",
            "configure": "Configuring WordPress",
            "install": "Installing WordPress",
            "publish": "Publishing the site",
            "verify": "Checking the site answers",
        },
        home=Home.SERVER_SITES,
        after="Open the site",
        after_home=Home.SITE,
    ),
    "create_laravel_site": ChangeWords(
        title="Create {site}",
        summary=(
            (
                "Barectl will create an account and folders for {site}, fetch the "
                "repository, install its dependencies, prepare the database and serve the "
                "application."
            ),
        ),
        action="Create Laravel site",
        steps={
            "preflight": "Checking the server",
            "account": "Creating the account and folders",
            "layout": "Preparing the site folders",
            "pool": "Starting PHP",
            "caddy": "Adding the site to the web server",
            "laravel": "Fetching the repository",
            "principal": "Preparing the database user",
            "database": "Preparing the database",
            "privileges": "Granting database access",
            "schema": "Running migrations",
            "verify": "Checking the site answers",
        },
        home=Home.SERVER_SITES,
        after="Open the site",
        after_home=Home.SITE,
    ),
    "set_wordpress_server_cron": ChangeWords(
        title="Change scheduled tasks for {site}",
        summary=(
            (
                "WordPress normally runs scheduled events when someone visits a page. "
                "Barectl can run them on the server every minute as the site's own account, "
                "or give them back to page loads."
            ),
            "Page loads keep running scheduled events until one server run has succeeded.",
            (
                "Each run is limited to fifteen minutes, and a slow run delays the next one "
                "instead of overlapping it."
            ),
        ),
        action="Continue",
        steps={
            "preflight": "Checking the site",
            "install": "Starting the scheduled task",
            "tick": "Waiting for one successful run",
            "configuration": "Changing when scheduled events run",
            "verify": "Checking it works",
        },
        home=Home.SITE,
        after="Back to the site",
        after_home=Home.SITE,
    ),
    "set_laravel_scheduler": ChangeWords(
        title="Change scheduled tasks for {site}",
        summary=(
            (
                "Laravel runs the tasks in the site's schedule from the server, every "
                "minute, as the site's own account and from its current release."
            ),
            (
                "Each run is limited to one hour; a slow run delays the next one instead of "
                "overlapping it, and missed runs while the server is down are not caught up."
            ),
            "Run now starts one run immediately so you can check the schedule after a deploy.",
        ),
        action="Continue",
        steps={
            "preflight": "Checking the site",
            "install": "Changing the scheduled task",
            "run": "Running the schedule once",
            "verify": "Checking it works",
        },
        home=Home.SITE,
        after="Back to the site",
        after_home=Home.SITE,
    ),
    "enable_backups": ChangeWords(
        title="Enable backups for {site}",
        summary=(
            (
                "Barectl installs its pinned backup tool and keeps an encrypted copy of this "
                "site on the server."
            ),
            (
                "You choose a recovery passphrase. Barectl adds it to the site's backups and "
                "never stores it. Keep it with the printed recovery kit, somewhere other "
                "than this server and Barectl."
            ),
            ("Barectl cannot take the first backup until you confirm you stored both."),
        ),
        action="Enable backups",
        steps={
            "preflight": "Checking the site",
            "restic": "Installing the backup tool",
            "repository": "Creating the encrypted copy",
            "keys": "Adding your passphrase and the server's key",
            "verify": "Checking it opens",
        },
        home=Home.SITE_BACKUPS,
        after="Back to backups",
        after_home=Home.SITE_BACKUPS,
    ),
    "set_up_offsite_storage": ChangeWords(
        title="Set up offsite backup storage",
        summary=(
            (
                "Barectl will connect this server's encrypted backups to a bucket on Amazon S3 "
                "or Cloudflare R2 and check it can be written and listed before saving."
            ),
            (
                "The access keys and the recovery passphrase live only in private files on "
                "this server; Barectl never stores them."
            ),
            (
                "Object lock and immutability are not configured. S3 Object Lock and bucket "
                "locks are provider features outside Barectl."
            ),
        ),
        action="Set up storage",
        steps={
            "preflight": "Checking the server",
            "credentials": "Checking the keys",
            "bucket": "Checking the bucket",
            "repositories": "Preparing each site's offsite copy",
            "verify": "Verifying",
        },
        home=Home.SERVER_SETTINGS,
        after="Back to Server Settings",
        after_home=Home.SERVER_SETTINGS,
    ),
    "remove_offsite_storage": ChangeWords(
        title="Remove offsite backup storage",
        summary=(
            "Barectl will forget this server's offsite storage setting and its keys.",
            (
                "It deletes no offsite copy: everything already in the bucket stays there. "
                "Existing recovery points on this server are unchanged."
            ),
        ),
        action="Remove storage",
        steps={
            "preflight": "Checking the server",
            "remove": "Removing the setting",
            "verify": "Verifying",
        },
        home=Home.SERVER_SETTINGS,
        after="Back to Server Settings",
        after_home=Home.SERVER_SETTINGS,
    ),
    "copy_offsite_again": ChangeWords(
        title="Copy a recovery point of {site} offsite again",
        summary=(
            "Barectl will copy one existing recovery point from this server to offsite storage.",
            (
                "The recovery point saved on this server is unchanged. If the copy fails, "
                "copy it again when the storage is reachable."
            ),
        ),
        action="Copy offsite again",
        steps={
            "preflight": "Checking the recovery point",
            "lock": "Waiting for the copy lock",
            "copy": "Copying offsite",
            "verify": "Checking the offsite copy",
        },
        home=Home.SITE_BACKUPS,
        after="Back to backups",
        after_home=Home.SITE_BACKUPS,
    ),
    "back_up_now": ChangeWords(
        title="Back up the database of {site}",
        summary=(
            "Barectl copies this site's database into its encrypted backups on the server.",
            (
                "The copy is taken without pausing the site. A database dump that fails "
                "creates no recovery point."
            ),
            "Barectl keeps some free space on the server and never deletes older copies.",
        ),
        action="Back up now",
        steps={
            "preflight": "Checking the site",
            "backup": "Copying the database",
            "verify": "Checking the recovery point",
        },
        home=Home.SITE_BACKUPS,
        after="Back to backups",
        after_home=Home.SITE_BACKUPS,
    ),
    "back_up_full_site": ChangeWords(
        title="Back up all of {site}",
        summary=(
            (
                "Barectl copies this site's database and files into one encrypted recovery "
                "point on the server."
            ),
            (
                "Visitors see a short maintenance page while the copy is taken. The site's "
                "scheduled tasks and queue workers are stopped first and started again when "
                "the copy finishes."
            ),
            (
                "Logs, caches, sessions, temporary files, other releases and server settings "
                "are left out."
            ),
            (
                "If the copy stops partway, the site stays paused until you reopen it. "
                "Barectl never deletes older copies to make room."
            ),
        ),
        action="Back up now",
        steps={
            "preflight": "Checking the site",
            "gate": "Pausing the site",
            "drain": "Finishing requests already running",
            "backup-database": "Copying the database",
            "backup-files": "Copying the files",
            "verify": "Checking the recovery point",
            "open": "Reopening the site",
        },
        home=Home.SITE_BACKUPS,
        after="Back to backups",
        after_home=Home.SITE_BACKUPS,
    ),
    "restore_database": ChangeWords(
        title="Restore {site}",
        summary=(
            (
                "Barectl replaces what you chose with the recovery point you selected. The "
                "review says exactly what is replaced; other sites are not touched."
            ),
            (
                "The site shows a maintenance page while the data is restored and checked. If "
                "the restore stops partway, the site stays paused until you reopen it."
            ),
        ),
        action="Restore",
        steps={
            "preflight": "Checking the site",
            "check": "Checking the recovery point",
            "safety": "Taking a safety backup",
            "stage": "Preparing the files privately",
            "gate": "Pausing the site",
            "drain": "Letting requests finish",
            "import": "Restoring the database",
            "files": "Restoring the files",
            "config": "Re-creating the server configuration",
            "checks": "Checking the data",
            "readiness": "Checking the site answers",
            "open": "Reopening the site",
        },
        home=Home.SITE_BACKUPS,
        after="Back to backups",
        after_home=Home.SITE_BACKUPS,
    ),
    "reopen_site": ChangeWords(
        title="Reopen {site}",
        summary=(
            "Barectl removes the maintenance page so visitors reach the site again.",
            (
                "The site's background work stays off. Open Scheduled tasks or Queue workers "
                "to choose what runs again."
            ),
        ),
        action="Reopen site",
        steps={
            "preflight": "Checking the site",
            "publish": "Reopening the site",
            "verify": "Verifying",
        },
        home=Home.SITE_BACKUPS,
        after="Back to backups",
        after_home=Home.SITE_BACKUPS,
    ),
    "set_laravel_queue_workers": ChangeWords(
        title="Change queue workers for {site}",
        summary=(
            (
                "Barectl can run this site's queued jobs in the background on the server, "
                "or stop them, without Supervisor or a hand-written service file."
            ),
            (
                "Start sets the retry interval a little above each job's timeout, then starts "
                "one process per reviewed process. The workers return after a reboot."
            ),
            (
                "Stop keeps them stopped after a reboot. Restart lets each process finish "
                "the job it is running before it starts again."
            ),
            (
                "A crash or a forced stop can leave a job to be retried, so your jobs must be "
                "safe to repeat."
            ),
        ),
        action="Continue",
        steps={
            "preflight": "Checking the site",
            "environment": "Saving the retry interval",
            "units": "Saving the worker definition",
            "start": "Starting the workers",
            "restart": "Restarting the workers",
            "stop": "Stopping the workers",
            "verify": "Checking it works",
        },
        home=Home.SITE,
        after="Back to the site",
        after_home=Home.SITE,
    ),
}


def words_for(kind_slug: str) -> ChangeWords | None:
    return _WORDS.get(kind_slug)


def step_label(words: ChangeWords | None, stage: str, selection: str) -> str:
    """A stage in plain words, or the stage's own name when the kind has no wording."""
    if words is None:
        return stage
    return words.steps.get(stage, stage).replace("{selection}", selection_label(selection))
