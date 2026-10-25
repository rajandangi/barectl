"""Read and recognise per-site background work from native evidence (Phase C #357).

One bounded root read per full discovery answers the unit files, the systemd properties, the
automation slice's processes and the second-scheduler files. The controller validates the
answer strictly and applies the pure projection in :mod:`automation.status`; a page never
reads the server.
"""

import importlib.resources
import json
import shlex
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native
from sites import observation as site_observation
from sites.bodies.common import SITE_GATED

from . import convention
from .status import ScheduleEvidence, ScheduleStatus, project

if TYPE_CHECKING:
    from discovery.snapshot import Observation, ObservedSetting, ObservedSite


def _without_imports(text: str) -> str:
    kept: list[str] = []
    skipping = False
    for line in text.splitlines():
        if line.startswith(
            ("from automation.convention import", "from automation.duplicates import")
        ):
            skipping = line.rstrip().endswith("(")
            continue
        if skipping:
            skipping = not line.strip().endswith(")")
            continue
        kept.append(line)
    return "\n".join(kept)


READ_SOURCE: Final = (
    importlib.resources.files("automation").joinpath("convention.py").read_text()
    + "\n"
    + importlib.resources.files("automation").joinpath("duplicates.py").read_text()
    + "\n"
    + _without_imports(
        importlib.resources.files("automation.bodies").joinpath("observe.py").read_text()
    )
)
READ_COMMAND: Final = site_observation.python_command(READ_SOURCE, ())
SHOW_PROPERTIES: Final = frozenset(
    {
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
    }
)
MAX_TEXT: Final = 16384
MAX_SITES: Final = 64
ENABLED_STATES: Final = frozenset({"enabled", "enabled-runtime", "static", "indirect"})
TIMESTAMP: Final = "@"


@dataclass(frozen=True)
class ObservedSchedule:
    """One role of one site, as the snapshot stores and every page reads."""

    identifier: str
    role: str
    status: ScheduleStatus
    problem: str = ""
    duplicate: str = ""
    disable_wp_cron: str = ""
    installed: bool = False
    timer_active: bool = False
    timer_enabled: bool = False
    service_active: bool = False
    masked: bool = False
    result: str = ""
    exec_status: int = 0
    last_start_us: int = 0
    last_exit_us: int = 0
    last_trigger_us: int = 0
    next_elapse_us: int = 0
    slice_populated: bool = False

    @property
    def timer_present(self) -> bool:
        return self.installed

    @property
    def service_present(self) -> bool:
        return self.installed

    @property
    def evidence(self) -> ScheduleEvidence:
        return ScheduleEvidence(
            identifier=self.identifier,
            role=self.role,
            installed=self.installed,
            problems=(self.problem,) if self.problem else (),
            timer_active=self.timer_active,
            timer_enabled=self.timer_enabled,
            service_active=self.service_active,
            masked=self.masked,
            result=self.result,
            exec_status=self.exec_status,
            last_start_us=self.last_start_us,
            last_exit_us=self.last_exit_us,
            last_trigger_us=self.last_trigger_us,
            next_elapse_us=self.next_elapse_us,
            slice_populated=self.slice_populated,
            disable_wp_cron=self.disable_wp_cron,
            duplicate=self.duplicate,
        )


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
    if not isinstance(value, dict) or not valid(value):
        return None
    return value


def valid(value: dict[str, object]) -> bool:
    if set(value) != {"version", "sites"} or value.get("version") != 1:
        return False
    sites = value.get("sites")
    return (
        isinstance(sites, list)
        and len(sites) <= MAX_SITES
        and all(_valid_site(row) for row in sites)
    )


def _valid_site(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "identifier",
        "units",
        "show",
        "slice_populated",
        "unreadable",
        "duplicate",
    }:
        return False
    identifier, units, show = value["identifier"], value["units"], value["show"]
    return (
        isinstance(identifier, str)
        and convention.SITE_IDENTIFIER.fullmatch(identifier) is not None
        and isinstance(units, list)
        and len(units) <= 2 * len(convention.ROLES) + 1
        and all(_valid_unit(unit) for unit in units)
        and isinstance(show, dict)
        and set(show) == {"service", "timer", "slice"}
        and all(row is None or _valid_show(row) for row in show.values())
        and type(value["slice_populated"]) is bool
        and type(value["unreadable"]) is bool
        and isinstance(value["duplicate"], str)
        and len(value["duplicate"]) <= 200
    )


def _valid_unit(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {"name", "kind", "text"}:
        return False
    return (
        isinstance(value["name"], str)
        and len(value["name"]) <= 120
        and value["kind"] in ("service", "timer", "slice")
        and isinstance(value["text"], str)
        and len(value["text"]) <= MAX_TEXT
    )


def _valid_show(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == SHOW_PROPERTIES
        and all(isinstance(item, str) and len(item) <= 200 for item in value.values())
    )


def observations(
    value: dict[str, object] | None,
    *,
    sites: tuple[ObservedSite, ...],
    disable_wp_cron: dict[str, str],
) -> tuple[ObservedSchedule, ...] | None:
    """Project each site's wpcron role; ``None`` when the native answer is unavailable."""
    if value is None:
        return None
    rows = value.get("sites")
    if not isinstance(rows, list):
        return None
    by_identifier = {
        str(row["identifier"]): row
        for row in rows
        if isinstance(row, dict) and row.get("identifier")
    }
    gated = {site.identifier for site in sites if SITE_GATED in site.missing}
    schedules: list[ObservedSchedule] = []
    for site in sites:
        identifier = site.identifier
        if not identifier:
            continue
        row = by_identifier.get(identifier)
        schedules.append(
            _project(
                identifier,
                row,
                disable_wp_cron.get(identifier, ""),
                identifier in gated,
            )
        )
    return tuple(schedules)


def schedule_for(
    value: dict[str, object] | None,
    identifier: str,
    *,
    disable_wp_cron: str = "",
    gate: bool = False,
) -> ObservedSchedule:
    """One site's projected schedule from an already validated native answer."""
    rows = value.get("sites") if value is not None else None
    if not isinstance(rows, list):
        return _project(identifier, None, disable_wp_cron, gate)
    row = next(
        (item for item in rows if isinstance(item, dict) and item.get("identifier") == identifier),
        None,
    )
    return _project(identifier, row, disable_wp_cron, gate)


def _project(
    identifier: str, row: dict[str, object] | None, disable: str, gate: bool
) -> ObservedSchedule:
    role = convention.ROLE_WPCRON
    if row is None:
        evidence = ScheduleEvidence(
            identifier=identifier,
            role=role,
            readable=False,
            disable_wp_cron=disable,
            gate=gate,
        )
        return _stored(evidence, project(evidence))
    unreadable = bool(row.get("unreadable"))
    units = row.get("units")
    unit_rows = units if isinstance(units, list) else []
    problems: list[str] = []
    present: set[str] = set()
    for unit in unit_rows:
        if not isinstance(unit, dict):
            continue
        kind = str(unit.get("kind", ""))
        name = str(unit.get("name", ""))
        if kind not in ("service", "timer", "slice"):
            continue
        shape = convention.parse_unit(name, str(unit.get("text", "")), identifier, role, kind)
        if not shape.supported:
            problems.append(shape.problem)
        present.add(kind)
    show = row.get("show")
    shows = show if isinstance(show, dict) else {}
    service = _values(shows.get("service"))
    timer = _values(shows.get("timer"))
    slice_values = _values(shows.get("slice"))
    if service is None or timer is None or slice_values is None:
        unreadable = True
        service, timer = {}, {}
    evidence = ScheduleEvidence(
        identifier=identifier,
        role=role,
        readable=not unreadable,
        installed=bool(present),
        problems=tuple(dict.fromkeys(problems)),
        timer_present="timer" in present,
        timer_active=timer.get("ActiveState") == "active",
        timer_enabled=timer.get("UnitFileState") in ENABLED_STATES,
        service_present="service" in present,
        service_active=service.get("ActiveState") in ("active", "activating"),
        masked=(service.get("LoadState") == "masked" or timer.get("LoadState") == "masked"),
        result=service.get("Result", ""),
        exec_status=_int(service.get("ExecMainStatus", "0")),
        last_start_us=_timestamp(service.get("ExecMainStartTimestamp", "")),
        last_exit_us=_timestamp(service.get("ExecMainExitTimestamp", "")),
        last_trigger_us=_timestamp(timer.get("LastTriggerUSec", "")),
        next_elapse_us=_timestamp(timer.get("NextElapseUSecRealtime", "")),
        slice_populated=bool(row.get("slice_populated")),
        disable_wp_cron=disable,
        duplicate=str(row.get("duplicate", "")),
        gate=gate,
    )
    return _stored(evidence, project(evidence))


def _stored(evidence: ScheduleEvidence, status: ScheduleStatus) -> ObservedSchedule:
    return ObservedSchedule(
        identifier=evidence.identifier,
        role=evidence.role,
        status=status,
        problem=evidence.problem,
        duplicate=evidence.duplicate,
        disable_wp_cron=evidence.disable_wp_cron,
        installed=evidence.installed,
        timer_active=evidence.timer_active,
        timer_enabled=evidence.timer_enabled,
        service_active=evidence.service_active,
        masked=evidence.masked,
        result=evidence.result,
        exec_status=evidence.exec_status,
        last_start_us=evidence.last_start_us,
        last_exit_us=evidence.last_exit_us,
        last_trigger_us=evidence.last_trigger_us,
        next_elapse_us=evidence.next_elapse_us,
        slice_populated=evidence.slice_populated,
    )


def _values(value: object) -> dict[str, str] | None:
    if not isinstance(value, dict) or not _valid_show(value):
        return None
    return {str(key): str(item) for key, item in value.items()}


def _int(value: str) -> int:
    return int(value) if value.isdigit() and len(value) <= 9 else 0


def _timestamp(value: str) -> int:
    """``systemctl --timestamp=unix`` reports seconds; store microseconds throughout."""
    text = value.removeprefix(TIMESTAMP)
    return int(text) * 1_000_000 if text.isdigit() and len(text) <= 20 else 0


def cron_values(settings: Observation[tuple[ObservedSetting, ...]]) -> dict[str, str]:
    """Each WordPress site's DISABLE_WP_CRON value from the stored settings inventory."""
    return {
        row.identifier: row.value
        for row in settings.value
        if row.application == "wordpress" and row.key == "DISABLE_WP_CRON" and row.value
    }
