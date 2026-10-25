"""The verified-activation evidence Start and Restart need (Phase C #266).

One bounded privileged read of the site's CLI build, its database and its own health
endpoint. The review turns it into plain refusals; nothing here is stored in the snapshot
because a precondition is checked at review and again by the native body.
"""

import importlib.resources
import json
import shlex
from typing import Final

from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native
from sites.observation import python_command

SOURCE: Final = (
    importlib.resources.files("automation.bodies").joinpath("worker_read.py").read_text()
)
MAX_SITES: Final = 1
MAX_PENDING: Final = 256


def command(identifier: str, host: str) -> str:
    return "sh -c " + shlex.quote(
        "; ".join(
            [
                *native.read_lock_steps(),
                "exec " + python_command(SOURCE, (identifier, host)),
            ]
        )
    )


def read(shell: RemoteShell, identifier: str, host: str) -> dict[str, object] | None:
    result = run_root(shell, command(identifier, host))
    if result.exit_status or result.truncated:
        return None
    try:
        value: object = json.loads(result.stdout)
    except ValueError:
        return None
    if not isinstance(value, dict) or not valid(value, identifier):
        return None
    return value


def valid(value: dict[str, object], identifier: str) -> bool:
    if set(value) != {"version", "sites"} or value.get("version") != 1:
        return False
    sites = value.get("sites")
    if not isinstance(sites, list) or len(sites) > MAX_SITES:
        return False
    for row in sites:
        if not isinstance(row, dict) or set(row) != {
            "identifier",
            "pcntl",
            "jobs",
            "pending",
            "migrations_readable",
            "http",
        }:
            return False
        pending = row["pending"]
        if (
            row["identifier"] != identifier
            or type(row["pcntl"]) is not bool
            or type(row["jobs"]) is not bool
            or type(row["migrations_readable"]) is not bool
            or type(row["http"]) is not int
            or not 0 <= row["http"] <= 599
            or not isinstance(pending, list)
            or len(pending) > MAX_PENDING
            or not all(isinstance(name, str) and len(name) <= 200 for name in pending)
        ):
            return False
    return len(sites) == 1


def site(value: dict[str, object] | None) -> dict[str, object] | None:
    if value is None:
        return None
    sites = value.get("sites")
    if not isinstance(sites, list) or not sites:
        return None
    row = sites[0]
    return row if isinstance(row, dict) else None


def ready(value: dict[str, object] | None) -> tuple[bool, str]:
    """Whether the reviewed activation passes, with the one plain refusal otherwise."""
    row = site(value)
    if row is None:
        return False, "The site's current release could not be verified as ready."
    if not row["migrations_readable"]:
        return False, "The site's recorded migrations could not be read."
    pending = row["pending"]
    if isinstance(pending, list) and pending:
        return (
            False,
            (
                "The site's current release has migrations that were not recorded. Deploy "
                "again before starting background work."
            ),
        )
    if not row["jobs"]:
        return (
            False,
            "The site's database has no jobs table, so the database queue cannot run.",
        )
    if not row["pcntl"]:
        return (
            False,
            (
                "The site's PHP command-line build does not load the process extension the "
                "queue timeout needs."
            ),
        )
    if row["http"] != 200:
        return (
            False,
            "The site's current release did not answer its health check, so it is not verified.",
        )
    return True, ""


__all__ = ["command", "read", "ready", "site", "valid"]
