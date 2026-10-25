"""Read a site's queue-worker units as root (Phase C #266).

Appended to :mod:`automation.workers`, :mod:`automation.duplicates`,
:mod:`automation.worker_duplicates` and run as one bounded privileged command during full
discovery. It reads unit files, ``systemctl show`` properties, the automation slice's
processes, and the crontab, Supervisor and unit files that could run a second worker. It
never runs PHP or Artisan and never reads a private site file.
"""

import json
import pathlib
import re
import stat
import subprocess
import sys

from automation.duplicates import foreign_unit_problem
from automation.worker_duplicates import crontab_problem, supervisor_problem
from automation.workers import WORKER_ROLES

SYSTEMD_DIRECTORY = "/etc/systemd/system"
RUNTIME_DIRECTORY = "/run/systemd/system"
SITE_ROOT = "/var/www"
MAX_FILE_BYTES = 16384
MAX_SCAN_BYTES = 262144
TEXT_BUDGET = 40000
MAX_SITES = 16
SYSTEMCTL_TIMEOUT = 10
SHOW_PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "Result",
    "ExecMainStatus",
    "ExecMainStartTimestamp",
    "ExecMainExitTimestamp",
    "NRestarts",
    "ControlGroup",
)
SITE_NAME = re.compile(r"barectl-site-([a-z][a-z0-9]{2,23})-(?:queue[1-4])\.service\Z")
CRON_USER = re.compile(r"s([a-z][a-z0-9]{2,23})\Z")


def _read(path: pathlib.Path, limit: int = MAX_SCAN_BYTES) -> str:
    try:
        info = path.lstat()
    except OSError:
        return ""
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _read_small(path: pathlib.Path) -> str:
    return _read(path, MAX_FILE_BYTES)


def _files(directory: str | pathlib.Path) -> list[pathlib.Path]:
    try:
        return sorted(pathlib.Path(directory).iterdir())
    except OSError:
        return []


def _laravel_sites() -> set[str]:
    sites = set()
    for entry in _files(SITE_ROOT):
        if entry.is_symlink() or not entry.is_dir():
            continue
        if (entry / "current" / "artisan").is_file() and (entry / "bin" / "php").exists():
            sites.add(entry.name)
    return sites


def _named_sites() -> set[str]:
    sites = set()
    for entry in _files(SYSTEMD_DIRECTORY):
        match = SITE_NAME.fullmatch(entry.name)
        if match is not None:
            sites.add(match.group(1))
    return sites


def _crontabs() -> tuple[dict[str, str], list[str]]:
    own = {}
    for entry in _files("/var/spool/cron/crontabs"):
        match = CRON_USER.fullmatch(entry.name)
        if match is not None:
            own[match.group(1)] = _read(entry)
    shared = [
        _read(path)
        for path in (pathlib.Path("/etc/crontab"), *_files("/etc/cron.d"))
        if path.is_file()
    ]
    return own, shared


def _supervisor() -> list[str]:
    paths = (
        pathlib.Path("/etc/supervisor/supervisord.conf"),
        *_files("/etc/supervisor/conf.d"),
    )
    return [_read(path) for path in paths if path.is_file()]


def _foreign_units() -> dict[str, str]:
    units = {}
    for directory in (SYSTEMD_DIRECTORY, RUNTIME_DIRECTORY):
        for entry in _files(directory):
            if not entry.name.endswith(".service") or entry.name.startswith("barectl-"):
                continue
            text = _read_small(entry)
            if text:
                units[entry.name] = text
    return units


def _duplicate(
    identifier: str,
    own_crontabs: dict[str, str],
    shared_crontabs: list[str],
    supervisor: list[str],
    foreign: dict[str, str],
) -> str:
    sources = [(own_crontabs.get(identifier, ""), True)]
    sources += [(text, False) for text in shared_crontabs]
    for text, own in sources:
        if problem := crontab_problem(text, identifier, own_crontab=own):
            return problem
    for text in supervisor:
        if problem := supervisor_problem(text, identifier):
            return problem
    for name, text in foreign.items():
        if problem := foreign_unit_problem(name, text, identifier):
            return problem
    return ""


def _show(name: str) -> dict[str, str] | None:
    command = ["systemctl", "show", "--no-pager", "--timestamp=unix"]
    for prop in SHOW_PROPERTIES:
        command += ["-p", prop]
    command.append(name)
    try:
        completed = subprocess.run(  # noqa: S603 - fixed native argv
            command, capture_output=True, text=True, timeout=SYSTEMCTL_TIMEOUT, check=False
        )
    except OSError, subprocess.TimeoutExpired:
        return None
    if completed.returncode:
        return None
    values = dict.fromkeys(SHOW_PROPERTIES, "")
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in SHOW_PROPERTIES and len(value) <= 200:
            values[key] = value
    if values["Id"] != name or not values["LoadState"]:
        return None
    return values


def _slice_populated(control_group: str) -> bool:
    if not control_group:
        return False
    try:
        events = pathlib.Path("/sys/fs/cgroup" + control_group) / "cgroup.events"
        return "populated 1" in events.read_text(encoding="utf-8")
    except OSError:
        return False


def _unit_files(identifier: str) -> list[dict[str, str]]:
    units = []
    slice_path = pathlib.Path(f"{SYSTEMD_DIRECTORY}/barectl-site-{identifier}.slice")
    if text := _read_small(slice_path):
        units.append({"name": f"barectl-site-{identifier}.slice", "kind": "slice", "text": text})
    for role in WORKER_ROLES:
        name = f"barectl-site-{identifier}-{role}.service"
        path = pathlib.Path(f"{SYSTEMD_DIRECTORY}/{name}")
        if text := _read_small(path):
            units.append({"name": name, "kind": "service", "text": text})
    return units


def _records() -> dict[str, object]:
    own_crontabs, shared = _crontabs()
    supervisor = _supervisor()
    foreign = _foreign_units()
    budget = TEXT_BUDGET
    rows = []
    for identifier in sorted(_laravel_sites() | _named_sites())[:MAX_SITES]:
        units = _unit_files(identifier)
        size = sum(len(unit["text"]) for unit in units)
        unreadable = False
        if size > budget:
            units, unreadable = [], True
        budget -= size
        show = {}
        for role in WORKER_ROLES:
            values = _show(f"barectl-site-{identifier}-{role}.service")
            if values is None:
                unreadable = True
            show[role] = values
        slice_values = _show(f"barectl-site-{identifier}.slice")
        if slice_values is None:
            unreadable = True
        rows.append(
            {
                "identifier": identifier,
                "units": units,
                "show": show,
                "slice": slice_values,
                "slice_populated": _slice_populated((slice_values or {}).get("ControlGroup", "")),
                "unreadable": unreadable,
                "duplicate": _duplicate(identifier, own_crontabs, shared, supervisor, foreign),
            }
        )
    return {"version": 1, "sites": rows}


def main() -> None:
    sys.stdout.write(json.dumps(_records(), sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
