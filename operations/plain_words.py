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
}


def words_for(kind_slug: str) -> ChangeWords | None:
    return _WORDS.get(kind_slug)


def step_label(words: ChangeWords | None, stage: str, selection: str) -> str:
    """A stage in plain words, or the stage's own name when the kind has no wording."""
    if words is None:
        return stage
    return words.steps.get(stage, stage).replace("{selection}", selection_label(selection))
