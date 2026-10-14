"""Bounded native runtime reconstruction; catalogue path equality owns identity."""

import base64
import importlib.resources
import json
import re
import shlex
from dataclasses import dataclass
from typing import Final

from discovery.root_read import run_root
from discovery.ssh import RemoteShell

from .catalog import Architecture, architecture_of, load
from .configuration import MANDATORY, PROBE, UNIT, render

_EXPECTED_FILES: Final = {
    entry: {
        key: base64.b64encode(value.encode()).decode()
        for key, value in (("master", render(entry).master), ("pool", render(entry).pool))
    }
    for entry in ("php84", "php85")
}
READ_SOURCE: Final = (
    importlib.resources.files("runtimes.bodies")
    .joinpath("read.py")
    .read_text()
    .replace(
        "EXPECTED_FILES: dict[str, dict[str, str]] = {}",
        "EXPECTED_FILES: dict[str, dict[str, str]] = " + repr(_EXPECTED_FILES),
    )
)


@dataclass(frozen=True)
class RuntimeObservation:
    entry: str
    path: str
    generation: str
    version: str
    extensions: tuple[str, ...]
    master_state: str
    protections: tuple[tuple[str, str], ...]
    problem: str

    @property
    def manageable(self) -> bool:
        return not self.problem


def read_command(selection: str, architecture: Architecture) -> str:
    fcgi = next(b for b in load().offered(architecture) if b.entry == "fcgi")
    return (
        "python3 -c "
        + shlex.quote(READ_SOURCE)
        + " "
        + " ".join(
            shlex.quote(arg)
            for arg in (
                selection,
                fcgi.path,
                base64.b64encode(PROBE.encode()).decode(),
                base64.b64encode(UNIT.encode()).decode(),
            )
        )
    )


def read(
    shell: RemoteShell, selection: str, architecture: Architecture
) -> dict[str, object] | None:
    result = run_root(shell, read_command(selection, architecture))
    if result.exit_status or result.truncated:
        return None
    try:
        value: object = json.loads(result.stdout)
    except ValueError:
        return None
    if not isinstance(value, dict) or set(value) != {
        "version",
        "architecture",
        "boot",
        "uptime",
        "digest",
        "admissible",
        "runtimes",
    }:
        return None
    if type(value["admissible"]) is not bool:
        return None
    if (
        type(value["version"]) is not int
        or value["version"] != 1
        or architecture_of(str(value["architecture"])) != architecture
    ):
        return None
    if (
        not isinstance(value["digest"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["digest"]) is None
    ):
        return None
    if not isinstance(value["boot"], str) or re.fullmatch(r"[0-9a-f-]{36}", value["boot"]) is None:
        return None
    if type(value["uptime"]) is not int or value["uptime"] < 0:
        return None
    rows = value["runtimes"]
    if (
        not isinstance(rows, list)
        or len(rows) > 64
        or not all(isinstance(row, dict) for row in rows)
    ):
        return None
    return value


def _text(row: dict[str, object], key: str) -> str:
    value = row.get(key)
    return value if isinstance(value, str) and len(value) <= 32768 else ""


def observations(value: object, architecture: Architecture) -> tuple[RuntimeObservation, ...]:
    if not isinstance(value, list):
        return ()
    rows = []
    for item in value:
        if not isinstance(item, dict):
            continue
        row: dict[str, object] = item
        entry, path = _text(row, "entry"), _text(row, "path")
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", entry):
            continue
        build = load().identify(architecture, path)
        problem = ""
        version = ""
        extensions: tuple[str, ...] = ()
        protections: tuple[tuple[str, str], ...] = ()
        state = "Profile only"
        if build is None or build.entry != entry:
            problem = "Unknown profile store path. Barectl cannot change this runtime or its pools."
        else:
            version = build.version
            if build.kind.value == "php":
                state, extensions, protections, problem = _php(row, entry, version)
        rows.append(
            RuntimeObservation(
                entry,
                path,
                _text(row, "generation"),
                version,
                extensions,
                state,
                protections,
                problem,
            )
        )
    return tuple(rows)


def _php(
    row: dict[str, object], entry: str, version: str
) -> tuple[str, tuple[str, ...], tuple[tuple[str, str], ...], str]:
    unit = _text(row, "unit")
    state = next(
        (line.partition("=")[2] for line in unit.splitlines() if line.startswith("ActiveState=")),
        "Unavailable",
    )
    failure = (
        "Protection fault. Pool changes on this master are blocked until "
        "its native configuration and live protections match."
    )
    files = row.get("files")
    expected = render(entry)
    if not isinstance(files, dict):
        return state, (), (), failure
    for path, content in (
        (f"/etc/php-fpm/{entry}/php.ini", expected.ini),
        (f"/etc/php-fpm/{entry}/php-fpm.conf", expected.master),
        (f"/etc/php-fpm/{entry}/pools/diagnostic.conf", expected.pool),
        ("/etc/systemd/system/php-fpm@.service", expected.unit),
    ):
        metadata = files.get(path)
        if (
            not isinstance(metadata, dict)
            or metadata.get("uid") != 0
            or metadata.get("type") != 32768
            or metadata.get("mode") not in (0o600, 0o644)
            or metadata.get("bytes") != base64.b64encode(content.encode()).decode()
        ):
            return state, (), (), failure
    if (
        "PHP_INI_SCAN_DIR" in unit
        or f"/nix/var/nix/profiles/barectl/{entry}/bin/php-fpm" not in unit
        or state != "active"
    ):
        return state, (), (), failure
    if not _master_identity(row):
        return state, (), (), failure
    live = _live(row, version)
    if live is None:
        return state, (), (), failure
    ini, opcache, raw_extensions = live
    extensions = tuple(raw_extensions)
    protections = tuple((key, str(ini.get(key, "Unavailable"))) for key in MANDATORY)
    if not _protected(ini, opcache, extensions):
        return state, extensions, protections, failure
    return state, extensions, protections, ""


def _live(
    row: dict[str, object], version: str
) -> tuple[dict[str, object], dict[str, object], list[str]] | None:
    response = _text(row, "response")
    header, separator, body = response.replace("\r\n", "\n").partition("\n\n")
    if not separator or any(
        line.lower().startswith("status:") and line.strip() != "Status: 200 OK"
        for line in header.splitlines()
    ):
        return None
    try:
        data: object = json.loads(body)
    except ValueError:
        return None
    if (
        not isinstance(data, dict)
        or set(data) != {"version", "sapi", "php", "parent", "uid", "extensions", "ini", "opcache"}
        or type(data["version"]) is not int
        or data["version"] != 1
        or type(data["parent"]) is not int
        or data["parent"] != row.get("master_pid")
        or data["sapi"] != "fpm-fcgi"
        or data["php"] != version
    ):
        return None
    identity = row.get("identity")
    if (
        not isinstance(identity, list)
        or len(identity) != 5
        or type(identity[0]) is not int
        or identity[0] <= 0
        or type(data.get("uid")) is not int
        or data["uid"] != identity[0]
    ):
        return None
    ini, opcache, raw_extensions = data["ini"], data["opcache"], data["extensions"]
    if (
        not isinstance(ini, dict)
        or not isinstance(opcache, dict)
        or not isinstance(raw_extensions, list)
        or len(raw_extensions) > 128
        or not all(
            isinstance(e, str) and re.fullmatch(r"[A-Za-z0-9_ -]{1,64}", e) for e in raw_extensions
        )
    ):
        return None
    return ini, opcache, raw_extensions


def _protected(
    ini: dict[str, object], opcache: dict[str, object], extensions: tuple[str, ...]
) -> bool:
    if "Zend OPcache" not in extensions:
        return False
    for key, expected_value in MANDATORY.items():
        actual = ini.get(key)
        if key == "expose_php":
            if actual not in ("", "0"):
                return False
        elif actual != expected_value:
            return False
        if key != "expose_php":
            expected: object = True if expected_value == "1" else expected_value
            if opcache.get(key) != expected:
                return False
    return True


def _master_identity(row: dict[str, object]) -> bool:
    expected = _text(row, "expected_executable")
    return (
        expected.startswith("/nix/store/")
        and expected.endswith("/bin/php-fpm")
        and _text(row, "master_executable") == expected
        and row.get("socket_owned") is True
        and row.get("same_invocation") is True
    )
