"""Read a WordPress site's extra constants through bounded native files.

The read runs as root during full discovery and change preparation, never in the browser.
It reports each constant's name and the digest computed on the server, never its value
(Phase B #383, ADR 0032).
"""

import importlib.resources
import json
import re
import shlex
from typing import Final

from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native
from sites import observation as site_observation

READ_SOURCE: Final = (
    importlib.resources.files("wordpress").joinpath("convention.py").read_text()
    + "\n"
    + """
import hashlib
import json
import pathlib
import pwd
import stat
import sys


def _private(path):
    try:
        info = path.lstat()
    except OSError:
        return ""
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_mode & 0o077
    ):
        return ""
    try:
        account = pwd.getpwnam("s" + path.parent.parent.name)
    except KeyError:
        return ""
    if info.st_uid != account.pw_uid or info.st_size > 65536:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return ""


def settings_read():
    sites = []
    root = pathlib.Path("/var/www")
    try:
        entries = sorted(root.iterdir())
    except OSError:
        entries = []
    for entry in entries:
        if not entry.is_dir() or entry.is_symlink():
            continue
        identifier = entry.name
        if IDENTIFIER.fullmatch(identifier) is None:
            continue
        text = _private(entry / "private" / "wp-config.php")
        if not text or private_configuration_problem(text, identifier):
            continue
        sites.append(
            {
                "identifier": identifier,
                "digest": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "constants": constant_details(text, identifier),
            }
        )
    sys.stdout.write(
        json.dumps({"version": 1, "sites": sites}, sort_keys=True, separators=(",", ":")) + "\\n"
    )
    sys.stdout.flush()


settings_read()
"""
)
READ_COMMAND: Final = site_observation.python_command(READ_SOURCE, ())

_IDENTIFIER: Final = re.compile(r"[a-z][a-z0-9]{2,23}")
_DIGEST: Final = re.compile(r"[0-9a-f]{64}")
_KEY: Final = re.compile(r"[A-Z][A-Z0-9_]{0,63}")


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
    if set(value) != {"version", "sites"} or value.get("version") != 1:
        return False
    sites = value.get("sites")
    return isinstance(sites, list) and len(sites) <= 64 and all(valid_site(row) for row in sites)


def valid_site(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {"identifier", "digest", "constants"}:
        return False
    identifier, digest, constants = value["identifier"], value["digest"], value["constants"]
    return (
        isinstance(identifier, str)
        and _IDENTIFIER.fullmatch(identifier) is not None
        and isinstance(digest, str)
        and _DIGEST.fullmatch(digest) is not None
        and isinstance(constants, list)
        and len(constants) <= 128
        and all(
            isinstance(row, dict)
            and set(row) == {"key", "digest"}
            and isinstance(row["key"], str)
            and _KEY.fullmatch(row["key"]) is not None
            and isinstance(row["digest"], str)
            and _DIGEST.fullmatch(row["digest"]) is not None
            for row in constants
        )
    )


def site(value: dict[str, object], identifier: str) -> dict[str, object] | None:
    sites = value.get("sites")
    if not isinstance(sites, list):
        return None
    for row in sites:
        if isinstance(row, dict) and row.get("identifier") == identifier:
            return row
    return None
