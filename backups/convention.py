"""The backup convention: fixed paths, unit names, tags and result lines.

Phase D [#396](https://github.com/rajandangi/barectl/issues/396), ADR 0031 and ADR 0037.
This module is standard library only: the controller and the native bodies asserted from
the same source share it (docs/quality.md#python-typing-policy).
"""

import re
from typing import Final

MARKER: Final = "barectl"
SITE_IDENTIFIER: Final = re.compile(r"[a-z][a-z0-9]{2,23}")
POINT: Final = re.compile(r"[0-9a-f]{16}")
TAG: Final = re.compile(r"[a-z0-9:_-]{1,48}")

PROFILE_ROOT: Final = "/nix/var/nix/profiles/barectl"
RESTIC_ENTRY: Final = "restic"
RESTIC_PROFILE: Final = f"{PROFILE_ROOT}/{RESTIC_ENTRY}"
RESTIC_BIN: Final = f"{RESTIC_PROFILE}/bin/restic"
REPOSITORY_ROOT: Final = "/var/lib/barectl-backups"
KEY_ROOT: Final = "/etc/barectl/backups"
CACHE_DIR: Final = "/var/cache/barectl/restic"
# Every capture keeps this much of the repository filesystem free. The review states it.
HEADROOM_BYTES: Final = 1024 * 1024 * 1024

# A recovery point's scope is what it restores: its database, its files, or both. A full
# point without a site database has no database part, so it is a files-scope point.
SCOPES: Final = ("database", "files", "full")
PARTS: Final = ("database", "files")
ORIGINS: Final = ("manual", "scheduled", "safety")
POINT_TAG: Final = "point:"

RESULT_PREFIX: Final = "barectl-result "


def site_directory(identifier: str) -> str:
    if SITE_IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a site identifier.")
    return f"{REPOSITORY_ROOT}/{identifier}"


def repository(identifier: str) -> str:
    return f"{site_directory(identifier)}/onsite"


def server_key(identifier: str) -> str:
    if SITE_IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a site identifier.")
    return f"{KEY_ROOT}/{identifier}.key"


def database_name(identifier: str) -> str:
    if SITE_IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a site identifier.")
    return "s" + identifier


def dump_argv(identifier: str, engine: str) -> list[str]:
    """The dump client, run as the site's own Linux user over the local socket."""
    database = database_name(identifier)
    if engine == "mariadb":
        return [
            "/usr/sbin/runuser",
            "-u",
            "s" + identifier,
            "--",
            "/usr/bin/mariadb-dump",
            "--single-transaction",
            "--quick",
            "--no-tablespaces",
            "--routines",
            "--events",
            "--triggers",
            database,
        ]
    if engine == "postgresql":
        return [
            "/usr/sbin/runuser",
            "-u",
            "s" + identifier,
            "--",
            "/usr/bin/pg_dump",
            "--no-owner",
            "--no-privileges",
            database,
        ]
    raise ValueError("Unknown database engine.")


def dump_filename(identifier: str) -> str:
    return database_name(identifier) + ".sql"


def tags(
    identifier: str,
    scope: str,
    *,
    part: str | None = None,
    origin: str,
    live: bool,
    point: str,
    complete: bool = True,
) -> tuple[str, ...]:
    if scope not in SCOPES or origin not in ORIGINS or POINT.fullmatch(point) is None:
        raise ValueError("Not a reviewed capture.")
    selected = scope if part is None else part
    if (
        selected not in PARTS
        or (scope == "full" and part is None)
        or (scope in ("database", "files") and part is not None and part != scope)
    ):
        raise ValueError("Not a reviewed capture.")
    values = (
        MARKER,
        f"site:{identifier}",
        f"scope:{scope}",
        f"part:{selected}",
        f"origin:{origin}",
        "capture:live" if live else "capture:paused",
        POINT_TAG + point,
    )
    return (*values, "complete") if complete else values


def expected_parts(scope: str) -> tuple[str, ...]:
    """The parts a restorable point of this scope must carry."""
    if scope == "full":
        return ("database", "files")
    if scope == "files":
        return ("files",)
    return ("database",)
