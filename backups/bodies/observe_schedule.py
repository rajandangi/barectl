"""Read a site's fixed backup schedule from native evidence (#402).

One bounded root read answers the site's backup slice, service and timer files, the runtime
payload and the systemd properties that report whether the timer is on and when it next
elapses. It validates nothing and runs nothing: the controller recognises the fixed shape.
"""

import json
import pathlib
import re
import stat
import subprocess
import sys

from backups.convention import (
    SCHEDULE_ROOT,
    schedule_unit_file,
    schedule_unit_name,
)

MAX_FILE_BYTES = 16384
MAX_SITES = 64
IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}\Z")
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
SYSTEMCTL_TIMEOUT = 10


def _read(path: pathlib.Path) -> str | None:
    """A bounded regular root-owned file's text; ``None`` for anything else."""
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
        return None
    if info.st_uid != 0 or info.st_mode & 0o022:
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


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


def _timers(identifier: str) -> list[dict[str, object]]:
    """The timer's systemd ``list-timers`` answer, which reports its next elapse."""
    command = [
        "systemctl",
        "list-timers",
        "--all",
        "--no-pager",
        "--full",
        "--output=json",
        schedule_unit_name(identifier, "timer"),
    ]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed native argv
            command, capture_output=True, text=True, timeout=SYSTEMCTL_TIMEOUT, check=False
        )
    except OSError, subprocess.TimeoutExpired:
        return []
    if completed.returncode:
        return []
    try:
        value = json.loads(completed.stdout or "[]")
    except ValueError:
        return []
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def _slice_populated(control_group: str) -> bool:
    if not control_group:
        return False
    try:
        events = pathlib.Path("/sys/fs/cgroup" + control_group) / "cgroup.events"
        return "populated 1" in events.read_text(encoding="utf-8")
    except OSError:
        return False


def _row(identifier: str) -> dict[str, object]:
    units: dict[str, str | None] = {}
    for kind in ("slice", "service", "timer"):
        units[kind] = _read(pathlib.Path(schedule_unit_file(identifier, kind)))
    payload = _read(pathlib.Path(f"{SCHEDULE_ROOT}/{identifier}.json"))
    script = _read(pathlib.Path(f"{SCHEDULE_ROOT}/{identifier}.sh"))
    slice_show = _show(schedule_unit_name(identifier, "slice"))
    service_show = _show(schedule_unit_name(identifier, "service"))
    timer_show = _show(schedule_unit_name(identifier, "timer"))
    return {
        "identifier": identifier,
        "units": units,
        "payload": payload,
        "script": script,
        "show": {"slice": slice_show, "service": service_show, "timer": timer_show},
        "timers": _timers(identifier),
        "slice_populated": _slice_populated((slice_show or {}).get("ControlGroup", "")),
    }


def main() -> None:
    payload = json.loads(sys.argv[1])
    sites = payload.get("sites")
    if (
        not isinstance(sites, list)
        or len(sites) > MAX_SITES
        or not all(isinstance(site, str) and IDENTIFIER.fullmatch(site) for site in sites)
    ):
        raise SystemExit(1)
    sys.stdout.write(
        json.dumps(
            {"version": 1, "sites": [_row(identifier) for identifier in sites]},
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
