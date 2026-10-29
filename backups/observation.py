"""Read and recognise a site's backups from native evidence (Phase D #396).

One bounded root read answers the restic profile, each site's root-only repository and
server key, whether its site database exists, and the newest safe result line in the
journal. The controller validates the answer strictly; no page runs restic or opens a
repository.
"""

import importlib.resources
import json
import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Final

from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native
from runtimes.catalog import Architecture, load
from sites import observation as site_observation

from . import convention

if TYPE_CHECKING:
    from discovery.snapshot import ObservedSite

READ_SOURCE: Final = (
    importlib.resources.files("databases").joinpath("binding.py").read_text()
    + "\n"
    + importlib.resources.files("backups.bodies").joinpath("observe.py").read_text()
)
MAX_SITES: Final = 64
MAX_PROBLEMS: Final = 8
MAX_POINTS: Final = 500
CLASSES: Final = frozenset({"succeeded", "partial", "failed", "refused", "lock_busy"})
POINT: Final = re.compile(r"[0-9a-f]{16}")
DIGEST: Final = re.compile(r"[0-9a-f]{64}")
ISO: Final = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|[+-][0-9]{2}:[0-9]{2})"
)


@dataclass(frozen=True)
class BackupResult:
    """One safe result line the unit printed, as discovery read it."""

    result_class: str
    reason: str
    scope: str
    origin: str
    at: str
    point: str
    snapshots: int
    size: int
    # Whether the capture's offsite copy finished: "" when offsite is not configured.
    offsite: str = ""

    @property
    def time(self) -> datetime | None:
        try:
            return datetime.fromisoformat(self.at)
        except ValueError:
            return None

    @property
    def succeeded(self) -> bool:
        return self.result_class == "succeeded" or self.result_class == "partial"


@dataclass(frozen=True)
class ConnectedSource:
    """One source site repository a connected offsite storage opened read-only (#408).

    ``points`` is the bounded listing last read when the storage was connected. It is a
    stale observation for the page, never authority: a restore re-lists the repository under
    its lock before it changes anything.
    """

    identifier: str
    rows: tuple[dict[str, object], ...] = ()
    problem: str = ""

    @property
    def read(self) -> bool:
        return not self.problem

    def points(self) -> tuple[dict[str, object], ...]:
        """The bounded recovery points in the last listing, grouped per part."""
        from . import check

        parsed = check.parse_listing(json.dumps(list(self.rows)))
        return tuple(check.points(parsed)) if parsed is not None else ()


@dataclass(frozen=True)
class OffsiteStorage:
    """The server's non-secret offsite location and whether its files are supported."""

    provider: str = ""
    bucket: str = ""
    region: str = ""
    endpoint: str = ""
    prefix: str = ""
    prune: bool = False
    problem: str = ""
    # The source sites a Connect existing backup storage review opened read-only (#408).
    sources: tuple[ConnectedSource, ...] = ()

    @property
    def configured(self) -> bool:
        return bool(self.provider) and not self.problem

    @property
    def label(self) -> str:
        return convention.PROVIDER_LABELS.get(self.provider, self.provider)


@dataclass(frozen=True)
class OffsiteCopy:
    """One copy run's safe result line, read from the journal."""

    result_class: str
    reason: str
    point: str
    at: str

    @property
    def copied(self) -> bool:
        return self.result_class == "succeeded"


@dataclass(frozen=True)
class IntegrityFinding:
    """One weekly integrity run's safe result line for one location (#405)."""

    location: str
    result_class: str
    reason: str
    at: str
    point: str
    checked: int
    snapshots: int
    size: int
    subset: str

    @property
    def time(self) -> datetime | None:
        try:
            return datetime.fromisoformat(self.at)
        except ValueError:
            return None

    @property
    def verified(self) -> bool:
        """Only a successful read-back of a named point makes it verified."""
        return self.result_class == "succeeded" and bool(self.point)


@dataclass(frozen=True)
class ObservedBackup:
    """One site's backup setup, from one snapshot's native evidence."""

    identifier: str
    profile: str = ""
    repository: bool = False
    key: bool = False
    problems: tuple[str, ...] = ()
    database: bool = False
    database_problem: str = ""
    last: BackupResult | None = None
    offsite: OffsiteStorage | None = None
    copy: OffsiteCopy | None = None
    integrity: tuple[IntegrityFinding, ...] = ()

    @property
    def enabled(self) -> bool:
        return bool(self.profile) and self.repository and self.key and not self.problems

    @property
    def restic_version(self) -> str:
        if not self.profile:
            return ""
        build = next(
            (
                item
                for item in load().builds
                if item.entry == convention.RESTIC_ENTRY and item.path == self.profile
            ),
            None,
        )
        return build.version if build is not None else ""


@dataclass(frozen=True)
class BackupReading:
    observations: tuple[ObservedBackup, ...] = ()
    warning: str = ""
    outcome: str = "observed"
    source: tuple[str, ...] = field(default_factory=tuple)
    offsite: OffsiteStorage | None = None
    offsite_outcome: str = "absent"


def known_profiles(architecture: Architecture | None) -> tuple[str, ...]:
    if architecture is None:
        return ()
    return tuple(
        build.path
        for build in load().builds
        if build.entry == convention.RESTIC_ENTRY and build.architecture == architecture
    )


def offered_restic(architecture: Architecture | None) -> tuple[str, str]:
    if architecture is None:
        return "", ""
    build = next(
        (item for item in load().offered(architecture) if item.entry == convention.RESTIC_ENTRY),
        None,
    )
    return (build.path, build.version) if build is not None else ("", "")


def read_command(identifiers: Sequence[str], engine: str, architecture: Architecture | None) -> str:
    payload = json.dumps(
        {
            "engine": engine,
            "sites": list(identifiers),
            "known": list(known_profiles(architecture)),
        },
        separators=(",", ":"),
    )
    command = site_observation.python_command(READ_SOURCE, (payload,))
    return "sh -c " + shlex_quote("; ".join([*native.read_lock_steps(), "exec " + command]))


def shlex_quote(value: str) -> str:
    import shlex

    return shlex.quote(value)


def read(
    shell: RemoteShell, identifiers: Sequence[str], engine: str, architecture: Architecture | None
) -> dict[str, object] | None:
    result = run_root(shell, read_command(identifiers, engine, architecture))
    if result.exit_status or result.truncated:
        return None
    try:
        value: object = json.loads(result.stdout)
    except ValueError:
        return None
    if not isinstance(value, dict) or not valid(value, identifiers):
        return None
    return value


REMOVED_LIMIT: Final = 8
REMOVED_NAME: Final = re.compile(r"[a-z][a-z0-9]{2,23}")

# The repositories a removed site leaves behind are evidence no passive read names: the
# read above answers for observed sites only. One bounded root read lists every repository
# a site once had; the controller intersects it with the sites it observed (Phase D #407).
REMOVED_SCRIPT: Final = (
    'for d in /var/lib/barectl-backups/*; do [ -d "$d/onsite" ] || continue; '
    '[ -f "$d/onsite/config" ] || continue; n=${d##*/}; '
    '[ -f "/etc/barectl/backups/$n.key" ] || continue; printf "%s\\n" "$n"; done '
    "| LC_ALL=C sort | /usr/bin/head -c 4097"
)


def removed_command() -> str:
    return "sh -c " + shlex.quote("; ".join([*native.read_lock_steps(), "exec " + REMOVED_SCRIPT]))


def removed(shell: RemoteShell, current: Sequence[str]) -> tuple[str, ...] | None:
    """The site identifiers whose repository remains but whose site no longer exists."""
    result = run_root(shell, removed_command())
    if result.exit_status or result.truncated or len(result.stdout) > 4096:
        return None
    names = [line for line in result.stdout.splitlines() if line]
    if (
        len(names) > REMOVED_LIMIT
        or not all(REMOVED_NAME.fullmatch(name) is not None for name in names)
        or names != sorted(set(names))
    ):
        return None
    present = set(current)
    return tuple(name for name in names if name not in present)


def valid(value: dict[str, object], identifiers: Sequence[str]) -> bool:
    if value.get("version") != 1 or set(value) not in (
        {"version", "sites"},
        {"version", "sites", "offsite"},
    ):
        return False
    if "offsite" in value and not (value["offsite"] is None or _valid_offsite(value["offsite"])):
        return False
    rows = value.get("sites")
    return (
        isinstance(rows, list)
        and len(rows) == len(identifiers)
        and [row.get("identifier") for row in rows if isinstance(row, dict)] == list(identifiers)
        and all(_valid_site(row) for row in rows)
    )


_SITE_KEYS = {
    "identifier",
    "profile",
    "repository",
    "key",
    "problems",
    "database",
    "database_problem",
    "last",
}


INTEGRITY_LOCATIONS: Final = ("onsite", "offsite")
INTEGRITY_SUBSET: Final = re.compile(r"[0-9]{1,3}/[0-9]{1,3}\Z")


def _valid_site(value: object) -> bool:
    if not isinstance(value, dict) or not set(value) <= _SITE_KEYS | {"copy", "integrity"}:
        return False
    if not set(value) >= _SITE_KEYS:
        return False
    if "copy" in value and not (value["copy"] is None or _valid_copy(value["copy"])):
        return False
    if "integrity" in value and not _valid_integrity(value["integrity"]):
        return False
    return (
        isinstance(value["identifier"], str)
        and convention.SITE_IDENTIFIER.fullmatch(value["identifier"]) is not None
        and isinstance(value["profile"], str)
        and (value["profile"] == "" or value["profile"].startswith("/nix/store/"))
        and type(value["repository"]) is bool
        and type(value["key"]) is bool
        and isinstance(value["problems"], list)
        and len(value["problems"]) <= MAX_PROBLEMS
        and all(isinstance(item, str) and len(item) <= 200 for item in value["problems"])
        and type(value["database"]) is bool
        and isinstance(value["database_problem"], str)
        and len(value["database_problem"]) <= 500
        and (value["last"] is None or _valid_result(value["last"]))
    )


_OFFSITE_KEYS = {
    "provider",
    "bucket",
    "region",
    "endpoint",
    "prefix",
    "prune",
    "problem",
}


def _valid_offsite(value: object) -> bool:
    if (
        not isinstance(value, dict)
        or set(value)
        not in (
            _OFFSITE_KEYS,
            _OFFSITE_KEYS | {"sites"},
            _OFFSITE_KEYS | {"sites", "sources"},
        )
        or not _valid_sources(value.get("sites"), value.get("sources"))
    ):
        return False
    return bool(
        isinstance(value["provider"], str)
        and value["provider"] in ("", *convention.PROVIDERS)
        and isinstance(value["bucket"], str)
        and len(value["bucket"]) <= 63
        and isinstance(value["region"], str)
        and len(value["region"]) <= 32
        and isinstance(value["endpoint"], str)
        and len(value["endpoint"]) <= 200
        and isinstance(value["prefix"], str)
        and len(value["prefix"]) <= 200
        and type(value["prune"]) is bool
        and isinstance(value["problem"], str)
        and len(value["problem"]) <= 500
    )


def _valid_sources(sites: object, sources: object) -> bool:
    if sites is None and sources is None:
        return True
    if (
        not isinstance(sites, list)
        or len(sites) > MAX_SITES
        or not all(
            isinstance(site, str) and convention.SITE_IDENTIFIER.fullmatch(site) for site in sites
        )
        or len(set(sites)) != len(sites)
    ):
        return False
    if sources is None:
        return True
    return bool(
        isinstance(sources, list)
        and len(sources) <= MAX_SITES
        and all(
            isinstance(row, dict)
            and set(row) == {"site", "rows", "problem"}
            and isinstance(row["site"], str)
            and row["site"] in sites
            and isinstance(row["rows"], list)
            and len(row["rows"]) <= MAX_POINTS
            and all(isinstance(point, dict) for point in row["rows"])
            and isinstance(row["problem"], str)
            and len(row["problem"]) <= 500
            for row in sources
        )
        and len({row["site"] for row in sources}) == len(sources)
    )


_FINDING_KEYS = {
    "location",
    "class",
    "reason",
    "at",
    "point",
    "checked",
    "snapshots",
    "bytes",
    "subset",
}


def _valid_integrity(value: object) -> bool:
    if value is None:
        return True
    if not isinstance(value, dict) or set(value) != {"onsite", "offsite"}:
        return False
    return all(
        item is None or (isinstance(item, dict) and _valid_finding(item, location))
        for location, item in value.items()
    )


def _valid_finding(value: dict[str, object], location: str) -> bool:
    return bool(
        set(value) == _FINDING_KEYS
        and value["location"] == location
        and value["class"] in CLASSES
        and isinstance(value["reason"], str)
        and len(value["reason"]) <= 500
        and isinstance(value["at"], str)
        and (value["at"] == "" or ISO.fullmatch(value["at"]) is not None)
        and isinstance(value["point"], str)
        and (value["point"] == "" or POINT.fullmatch(value["point"]) is not None)
        and type(value["checked"]) is int
        and 0 <= value["checked"] <= 10_000
        and type(value["snapshots"]) is int
        and 0 <= value["snapshots"] <= 16
        and type(value["bytes"]) is int
        and value["bytes"] >= 0
        and isinstance(value["subset"], str)
        and (value["subset"] == "" or INTEGRITY_SUBSET.fullmatch(value["subset"]) is not None)
    )


def _valid_copy(value: object) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value) == {"class", "reason", "point", "at"}
        and value["class"] in ("succeeded", "partial", "failed", "refused", "lock_busy")
        and isinstance(value["reason"], str)
        and len(value["reason"]) <= 500
        and isinstance(value["point"], str)
        and (value["point"] == "" or POINT.fullmatch(value["point"]) is not None)
        and isinstance(value["at"], str)
        and (value["at"] == "" or ISO.fullmatch(value["at"]) is not None)
    )


_RESULT_KEYS = {"class", "reason", "scope", "origin", "at", "point", "snapshots", "bytes"}


def _valid_result(value: object) -> bool:
    if not isinstance(value, dict) or set(value) not in (_RESULT_KEYS, _RESULT_KEYS | {"offsite"}):
        return False
    if "offsite" in value and value["offsite"] not in ("", "copied", "failed"):
        return False
    return bool(
        value["class"] in CLASSES
        and isinstance(value["reason"], str)
        and len(value["reason"]) <= 500
        and (value["scope"] == "" or value["scope"] in convention.SCOPES)
        and (value["origin"] == "" or value["origin"] in convention.ORIGINS)
        and (value["at"] == "" or (isinstance(value["at"], str) and ISO.fullmatch(value["at"])))
        and (
            value["point"] == ""
            or (isinstance(value["point"], str) and POINT.fullmatch(value["point"]))
        )
        and type(value["snapshots"]) is int
        and 0 <= value["snapshots"] <= 16
        and type(value["bytes"]) is int
        and value["bytes"] >= 0
    )


def observations(
    value: dict[str, object] | None, sites: Sequence[ObservedSite]
) -> tuple[ObservedBackup, ...] | None:
    if value is None:
        return None
    rows = value.get("sites")
    if not isinstance(rows, list):
        return None
    by_identifier = {str(row["identifier"]): row for row in rows if isinstance(row, dict)}
    offsite = offsite_of(value)
    result: list[ObservedBackup] = []
    for site in sites:
        if not site.identifier:
            continue
        row = by_identifier.get(site.identifier)
        if row is None:
            continue
        result.append(_observation(row, offsite))
    return tuple(result)


def one(value: dict[str, object] | None, identifier: str) -> ObservedBackup | None:
    """One site's backup setup from one read, without a site observation to name it."""
    if value is None:
        return None
    rows = value.get("sites")
    if not isinstance(rows, list):
        return None
    row = next(
        (item for item in rows if isinstance(item, dict) and item.get("identifier") == identifier),
        None,
    )
    return _observation(row, offsite_of(value)) if isinstance(row, dict) else None


def _observation(row: dict[str, object], offsite: OffsiteStorage | None) -> ObservedBackup:
    last = row.get("last")
    copy = row.get("copy")
    problems = row.get("problems")
    return ObservedBackup(
        str(row["identifier"]),
        str(row["profile"]),
        bool(row["repository"]),
        bool(row["key"]),
        tuple(str(item) for item in problems) if isinstance(problems, list) else (),
        bool(row["database"]),
        str(row["database_problem"]),
        _result(last) if isinstance(last, dict) else None,
        offsite,
        _copy(copy) if isinstance(copy, dict) else None,
        integrity_of(row),
    )


def integrity_of(row: dict[str, object]) -> tuple[IntegrityFinding, ...]:
    """Every location's newest integrity finding on one observed site, if any."""
    value = row.get("integrity")
    if not isinstance(value, dict):
        return ()
    findings: list[IntegrityFinding] = []
    for location in INTEGRITY_LOCATIONS:
        item = value.get(location)
        if isinstance(item, dict):
            finding = finding_of(item, location)
            if finding is not None:
                findings.append(finding)
    return tuple(findings)


def finding_of(value: object, location: str) -> IntegrityFinding | None:
    if not isinstance(value, dict) or not _valid_finding(value, location):
        return None
    return IntegrityFinding(
        location,
        str(value["class"]),
        str(value["reason"]),
        str(value["at"]),
        str(value["point"]),
        int(str(value["checked"])),
        int(str(value["snapshots"])),
        int(str(value["bytes"])),
        str(value["subset"]),
    )


def offsite_of(value: dict[str, object] | None) -> OffsiteStorage | None:
    raw = value.get("offsite") if isinstance(value, dict) else None
    if not isinstance(raw, dict):
        return None
    return OffsiteStorage(
        str(raw["provider"]),
        str(raw["bucket"]),
        str(raw["region"]),
        str(raw["endpoint"]),
        str(raw["prefix"]),
        raw["prune"] is True,
        str(raw["problem"]),
        _sources_of(raw),
    )


def _sources_of(raw: dict[str, object]) -> tuple[ConnectedSource, ...]:
    rows = raw.get("sources")
    if not isinstance(rows, list):
        return ()
    result: list[ConnectedSource] = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("site"), str):
            continue
        rows = row.get("rows")
        result.append(
            ConnectedSource(
                str(row["site"]),
                tuple(item for item in rows if isinstance(item, dict))
                if isinstance(rows, list)
                else (),
                str(row.get("problem", "")),
            )
        )
    return tuple(result)


def _copy(value: dict[str, object]) -> OffsiteCopy:
    return OffsiteCopy(
        str(value["class"]),
        str(value["reason"]),
        str(value["point"]),
        str(value["at"]),
    )


def _result(value: dict[str, object]) -> BackupResult:
    return BackupResult(
        str(value["class"]),
        str(value["reason"]),
        str(value["scope"]),
        str(value["origin"]),
        str(value["at"]),
        str(value["point"]),
        int(str(value["snapshots"])),
        int(str(value["bytes"])),
        str(value.get("offsite", "")),
    )


def reading(
    shell: RemoteShell,
    sites: Sequence[ObservedSite],
    engine: str,
    architecture: Architecture | None,
) -> BackupReading:
    identifiers = tuple(site.identifier for site in sites if site.identifier)
    if not identifiers:
        return BackupReading()
    value = read(shell, identifiers, engine, architecture)
    if value is None:
        return BackupReading(
            (),
            "Backups could not be read from the server.",
            "inaccessible",
            ("/var/lib/barectl-backups", "/etc/barectl/backups"),
        )
    rows = observations(value, sites)
    offsite = offsite_of(value)
    return BackupReading(
        rows or (),
        "",
        "observed",
        ("/var/lib/barectl-backups", "/etc/barectl/backups"),
        offsite,
        "observed" if offsite is not None else "absent",
    )
