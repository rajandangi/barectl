"""Read one server's automation evidence as root (Phase C #357).

Appended to the convention and duplicate matchers and run as one bounded privileged command
during full discovery. It reads unit files, ``systemctl show`` fields, the automation
slice's process count, and the crontab, Supervisor and unit files that could run a second
scheduler. It never runs PHP, WP-CLI or Artisan and never reads a private site file.
"""

import json
import pathlib
import re
import stat
import subprocess
import sys

from automation.convention import (
    ROLE_WPCRON,
    ROLES,
    SITE_IDENTIFIER,
    WORKER_ROLES,
    service_name,
    slice_file,
    slice_name,
    timer_name,
    unit_file,
)
from automation.duplicates import (
    crontab_problem,
    foreign_unit_problem,
    schedule_crontab_problem,
    schedule_supervisor_problem,
    supervisor_problem,
)

SYSTEMD_DIRECTORY = "/etc/systemd/system"
RUNTIME_DIRECTORY = "/run/systemd/system"
SITE_ROOT = "/var/www"
MAX_FILE_BYTES = 16384
MAX_SCAN_BYTES = 262144
TEXT_BUDGET = 40000
MAX_SITES = 64
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
    "LastTriggerUSec",
    "NextElapseUSecRealtime",
    "ControlGroup",
    "RefuseManualStart",
)
SHOW_NAMES = ("service", "timer")
SITE_NAME = re.compile(
    r"barectl-site-([a-z][a-z0-9]{2,23})-(?:[a-z][a-z0-9]{2,20})\.(?:service|timer)\Z"
)
CRON_USER = re.compile(r"s([a-z][a-z0-9]{2,23})\Z")


def _read(path: pathlib.Path, limit: int = MAX_SCAN_BYTES) -> str:
    """A bounded regular file's text, or empty for anything Barectl must not follow."""
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


def _application_sites() -> set[str]:
    """Every WordPress or Laravel site, recognised without running either application."""
    sites = set()
    for entry in _files(SITE_ROOT):
        if entry.is_symlink() or not entry.is_dir():
            continue
        if SITE_IDENTIFIER.fullmatch(entry.name) is None:
            continue
        if (entry / "bin" / "wp").exists() or (entry / "current" / "artisan").is_file():
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
    """The crontab text for each account, and the system cron files."""
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
) -> dict[str, str]:
    """A second scheduler for each role, or an empty sentence when there is none."""
    # A site's own crontab runs as its account, so naming the site is not required there.
    sources = [(own_crontabs.get(identifier, ""), True)]
    sources += [(text, False) for text in shared_crontabs]
    duplicates = {
        ROLE_WPCRON: next(
            (
                found
                for text, own in sources
                if (found := crontab_problem(text, identifier, own_crontab=own))
            ),
            "",
        ),
        "schedule": next(
            (
                found
                for text, own in sources
                if (found := schedule_crontab_problem(text, identifier, own_crontab=own))
            ),
            "",
        ),
    }
    for role in ROLES:
        duplicates.setdefault(role, "")
    duplicates[ROLE_WPCRON] = duplicates[ROLE_WPCRON] or next(
        (found for text in supervisor if (found := supervisor_problem(text, identifier))), ""
    )
    duplicates["schedule"] = duplicates["schedule"] or next(
        (found for text in supervisor if (found := schedule_supervisor_problem(text, identifier))),
        "",
    )
    for name, text in foreign.items():
        if problem := foreign_unit_problem(name, text, identifier):
            for role in ROLES:
                duplicates[role] = duplicates[role] or problem
    return duplicates


def _show(name: str) -> dict[str, str] | None:
    """The properties systemd reports for ``name``, or ``None`` when it cannot be read."""
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
    slice_path = pathlib.Path(slice_file(identifier))
    if text := _read_small(slice_path):
        units.append({"name": slice_name(identifier), "kind": "slice", "text": text})
    for role in ROLES:
        for kind in ("service", "timer"):
            name = (
                service_name(identifier, role)
                if kind == "service"
                else timer_name(identifier, role)
            )
            path = pathlib.Path(unit_file(identifier, role, kind))
            if text := _read_small(path):
                units.append({"name": name, "kind": kind, "text": text})
    return units


def _records() -> dict[str, object]:
    own_crontabs, shared = _crontabs()
    supervisor = _supervisor()
    foreign = _foreign_units()
    budget = TEXT_BUDGET
    rows = []
    for identifier in sorted(_application_sites() | _named_sites())[:MAX_SITES]:
        units = _unit_files(identifier)
        size = sum(len(unit["text"]) for unit in units)
        unreadable: list[str] = []
        if size > budget:
            units, unreadable = [], list(ROLES)
        budget -= size
        roles: dict[str, dict[str, dict[str, str] | None]] = {}
        present_roles = {
            role
            for role in ROLES
            if any(
                unit["name"].startswith(f"{service_name(identifier, role)[:-8]}-") for unit in units
            )
        }
        for role in ROLES:
            if role in WORKER_ROLES and role not in present_roles:
                # A WordPress or workerless site costs no extra systemctl calls.
                roles[role] = {"service": None, "timer": None}
                continue
            values: dict[str, dict[str, str] | None] = {}
            for kind in SHOW_NAMES:
                name = (
                    service_name(identifier, role)
                    if kind == "service"
                    else timer_name(identifier, role)
                )
                shown = _show(name)
                if shown is None and role not in unreadable:
                    unreadable.append(role)
                values[kind] = shown
            roles[role] = values
        slice_values = _show(slice_name(identifier))
        if slice_values is None:
            unreadable = list(ROLES)
        rows.append(
            {
                "identifier": identifier,
                "units": units,
                "roles": roles,
                "slice": slice_values,
                "slice_populated": _slice_populated((slice_values or {}).get("ControlGroup", "")),
                "unreadable": unreadable,
                "duplicates": _duplicate(identifier, own_crontabs, shared, supervisor, foreign),
            }
        )
    return {"version": 2, "sites": rows}


def main() -> None:
    sys.stdout.write(json.dumps(_records(), sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
