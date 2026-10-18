"""Read Laravel sites, releases and shared state through native evidence.

The read runs as root during change preparation and authorized observation, never in
unprivileged passive discovery, and never executes application code or Git. It reads the
site's release directories, the ``current`` link and a release's Git metadata only.
"""

import importlib.resources
import json
import re
import shlex
from typing import TYPE_CHECKING, Final, cast

from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native
from sites import observation as site_observation

if TYPE_CHECKING:
    from discovery.models import SiteState
    from discovery.snapshot import Observation, ObservedRelease

LARAVEL_IMPORT: Final = (
    "from sites.bodies.common import (\n"
    "    canonical,\n"
    "    current_bytes,\n"
    "    open_site_lock,\n"
    "    reload_caddy,\n"
    "    replace_caddy,\n"
    "    result,\n"
    "    safe,\n"
    "    same_site_lock,\n"
    "    setting,\n"
    "    site_account,\n"
    "    stage,\n"
    ")\n"
)
LARAVEL_SOURCE: Final = (
    site_observation.COMMON_SOURCE
    + "\n"
    + importlib.resources.files("laravel.bodies")
    .joinpath("common.py")
    .read_text()
    .replace(LARAVEL_IMPORT, "")
)
READ_SOURCE: Final = LARAVEL_SOURCE + "\nlaravel_read()\n"
READ_COMMAND: Final = site_observation.python_command(READ_SOURCE, ())

_INVENTORY_KEYS: Final = {
    "version",
    "sites",
}
_SITE_KEYS: Final = {
    "identifier",
    "application",
    "current",
    "repository",
    "branch",
    "php_requirement",
    "releases",
    "shared",
    "problem",
}
_RELEASE_KEYS: Final = {"name", "commit", "created", "state", "repository", "branch"}
_SHARED_KEYS: Final = {"environment", "storage", "cache"}
_NAME: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_REQUIREMENT: Final = re.compile(r"[A-Za-z0-9 ^~<>=.,|@*+-]{0,100}")


def read_command() -> str:
    return "sh -c " + shlex.quote("; ".join([*native.read_lock_steps(), "exec " + READ_COMMAND]))


def read(shell: RemoteShell) -> dict[str, object] | None:
    result = run_root(shell, read_command())
    if result.exit_status or result.truncated:
        return None
    try:
        value: object = json.loads(result.stdout)
    except ValueError:
        return None
    if not isinstance(value, dict) or not valid_inventory(value):
        return None
    return value


def valid_inventory(value: dict[str, object]) -> bool:
    if set(value) != _INVENTORY_KEYS or value.get("version") != 1:
        return False
    sites = value.get("sites")
    return isinstance(sites, list) and len(sites) <= 64 and all(valid_site(row) for row in sites)


def valid_site(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != _SITE_KEYS:
        return False
    if value["application"] not in ("plain", "laravel"):
        return False
    if not isinstance(value["problem"], str) or len(value["problem"]) > 1000:
        return False
    if not isinstance(value["repository"], str) or len(value["repository"]) > 512:
        return False
    if not isinstance(value["branch"], str) or len(value["branch"]) > 256:
        return False
    if value["current"] != "" and not (
        isinstance(value["current"], str) and _NAME.fullmatch(value["current"])
    ):
        return False
    if not isinstance(value["php_requirement"], str) or not _REQUIREMENT.fullmatch(
        value["php_requirement"]
    ):
        return False
    releases = value["releases"]
    if not isinstance(releases, list) or len(releases) > 64:
        return False
    if not all(valid_release(entry) for entry in releases):
        return False
    shared = value["shared"]
    return (
        isinstance(shared, dict)
        and set(shared) == _SHARED_KEYS
        and all(type(flag) is bool for flag in shared.values())
    )


def valid_release(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != _RELEASE_KEYS:
        return False
    if not isinstance(value["name"], str) or not _NAME.fullmatch(value["name"]):
        return False
    if value["state"] not in ("complete", "partial", "unsupported"):
        return False
    return type(value["created"]) is int and value["created"] >= 0


def site(value: dict[str, object], identifier: str) -> dict[str, object] | None:
    for row in cast(list[dict[str, object]], value["sites"]):
        if row["identifier"] == identifier:
            return row
    return None


def resolve_command(identifier: str, repository: str, branch: str) -> str:
    """A fixed read that resolves a branch or tag to an exact commit as the site user."""
    account = "s" + identifier
    home = f"/var/www/{identifier}"
    script = "; ".join(
        [
            *native.read_lock_steps(),
            "exec "
            + shlex.join(
                [
                    "/usr/sbin/runuser",
                    "-u",
                    account,
                    "--",
                    "/usr/bin/env",
                    f"HOME={home}",
                    "LC_ALL=C",
                    "GIT_CONFIG_NOSYSTEM=1",
                    "GIT_TERMINAL_PROMPT=0",
                    "/usr/bin/git",
                    "ls-remote",
                    repository,
                    branch,
                ]
            ),
        ]
    )
    return "sh -c " + shlex.quote(script)


def resolve(shell: RemoteShell, identifier: str, repository: str, branch: str) -> str | None:
    if not repository or not branch:
        return None
    result = run_root(shell, resolve_command(identifier, repository, branch))
    if result.exit_status or result.truncated:
        return None
    head: str | None = None
    tag: str | None = None
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or re.fullmatch(r"[0-9a-f]{40}", fields[0]) is None:
            continue
        if fields[1] == f"refs/heads/{branch}":
            head = fields[0]
        elif fields[1] == f"refs/tags/{branch}" or fields[1] == f"refs/tags/{branch}^{{}}":
            tag = tag or fields[0]
    return head or tag


def _release_rows(row: dict[str, object]) -> list[dict[str, object]]:
    raw = row.get("releases")
    return [entry for entry in raw if isinstance(entry, dict)] if isinstance(raw, list) else []


def _release_state(value: str) -> SiteState:
    from discovery.models import SiteState

    return {
        "complete": SiteState.MANAGED,
        "partial": SiteState.PARTLY_APPLIED,
    }.get(value, SiteState.NOT_FOLLOWING)


def observed_releases(shell: RemoteShell) -> Observation[tuple[ObservedRelease, ...]]:
    """Reconstruct every site's retained releases from the native layout."""
    from discovery.models import ObservationOutcome, SiteState  # noqa: F401
    from discovery.snapshot import Observation, ObservedRelease

    source = ("/var/www",)
    value = read(shell)
    if value is None:
        return Observation(
            ObservationOutcome.INACCESSIBLE,
            source,
            "The release layout could not be reconstructed.",
            (),
        )
    records: list[ObservedRelease] = []
    for row in cast(list[dict[str, object]], value["sites"]):
        identifier = str(row["identifier"])
        current = str(row["current"])
        for entry in _release_rows(row):
            name = str(entry["name"])
            records.append(
                ObservedRelease(
                    identifier,
                    name,
                    str(entry["commit"]),
                    int(str(entry["created"])),
                    _release_state(str(entry["state"])),
                    name == current,
                )
            )
    return Observation(ObservationOutcome.OBSERVED, source, "", tuple(records))
