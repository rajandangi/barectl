"""Read and recognise a site's queue workers from native evidence (Phase C #266).

One bounded root read per full discovery answers the worker unit files, their systemd
properties, the automation slice's processes and the second-worker files. The controller
validates the answer strictly and applies the pure projection in
:mod:`automation.worker_status`; a page never reads the server.
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

from . import workers
from .convention import SITE_IDENTIFIER
from .worker_status import WorkerEvidence, WorkerStatus, project

if TYPE_CHECKING:
    from discovery.snapshot import ObservedSite


def _without_imports(text: str) -> str:
    kept: list[str] = []
    skipping = False
    for line in text.splitlines():
        if line.startswith(
            (
                "from automation.",
                "from .duplicates import",
                "from .worker_duplicates import",
                "from .workers import",
            )
        ):
            skipping = line.rstrip().endswith("(")
            continue
        if skipping:
            skipping = not line.strip().endswith(")")
            continue
        kept.append(line)
    return "\n".join(kept)


READ_SOURCE: Final = "\n".join(
    (
        importlib.resources.files("automation").joinpath("convention.py").read_text(),
        importlib.resources.files("automation").joinpath("duplicates.py").read_text(),
        _without_imports(
            importlib.resources.files("automation").joinpath("workers.py").read_text()
        ),
        _without_imports(
            importlib.resources.files("automation").joinpath("worker_duplicates.py").read_text()
        ),
        _without_imports(
            importlib.resources.files("automation.bodies")
            .joinpath("observe_workers.py")
            .read_text()
        ),
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
        "NRestarts",
        "ControlGroup",
    }
)
ENABLED_STATES: Final = frozenset({"enabled", "enabled-runtime", "static", "indirect"})
MAX_TEXT: Final = 16384
MAX_SITES: Final = 16


@dataclass(frozen=True)
class ObservedWorker:
    """One site's worker definition and process states, as the snapshot stores them."""

    identifier: str
    status: WorkerStatus
    definition: workers.WorkerDefinition | None = None
    processes: int = 0
    active_processes: int = 0
    installed: bool = False
    enabled: bool = False
    masked: bool = False
    result: str = ""
    exec_status: int = 0
    start_limited: bool = False
    last_start_us: int = 0
    last_exit_us: int = 0
    nrestarts: int = 0
    slice_populated: bool = False
    duplicate: str = ""
    problem: str = ""

    @property
    def queues(self) -> tuple[str, ...]:
        return self.definition.queues if self.definition is not None else ()

    @property
    def timeout(self) -> int:
        return self.definition.timeout if self.definition is not None else 0

    @property
    def evidence(self) -> WorkerEvidence:
        return WorkerEvidence(
            identifier=self.identifier,
            installed=self.installed,
            enabled=self.enabled,
            masked=self.masked,
            processes=self.processes,
            active_processes=self.active_processes,
            result=self.result,
            exec_status=self.exec_status,
            start_limited=self.start_limited,
            last_start_us=self.last_start_us,
            last_exit_us=self.last_exit_us,
            nrestarts=self.nrestarts,
            slice_populated=self.slice_populated,
            duplicate=self.duplicate,
            problems=(self.problem,) if self.problem else (),
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
        "slice",
        "slice_populated",
        "unreadable",
        "duplicate",
    }:
        return False
    identifier, units, show = value["identifier"], value["units"], value["show"]
    return (
        isinstance(identifier, str)
        and SITE_IDENTIFIER.fullmatch(identifier) is not None
        and isinstance(units, list)
        and len(units) <= 1 + len(workers.WORKER_ROLES)
        and all(_valid_unit(unit) for unit in units)
        and isinstance(show, dict)
        and set(show) == set(workers.WORKER_ROLES)
        and all(row is None or _valid_show(row) for row in show.values())
        and (value["slice"] is None or _valid_show(value["slice"]))
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
        and value["kind"] in ("service", "slice")
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
    laravel: frozenset[str],
) -> tuple[ObservedWorker, ...] | None:
    """Project every Laravel site; ``None`` when the native answer is unavailable."""
    if value is None:
        return None
    rows = value.get("sites")
    if not isinstance(rows, list):
        return None
    gated = {site.identifier for site in sites if SITE_GATED in site.missing}
    projected: list[ObservedWorker] = []
    for site in sites:
        if site.identifier not in laravel:
            continue
        projected.append(worker_for(value, site.identifier, gate=site.identifier in gated))
    return tuple(projected)


def worker_for(
    value: dict[str, object] | None,
    identifier: str,
    *,
    gate: bool = False,
) -> ObservedWorker:
    """One site's projected worker from an already validated native answer."""
    rows = value.get("sites") if value is not None else None
    if not isinstance(rows, list):
        evidence = WorkerEvidence(identifier=identifier, readable=False, gate=gate)
        return _stored(evidence, project(evidence))
    row = next(
        (item for item in rows if isinstance(item, dict) and item.get("identifier") == identifier),
        None,
    )
    return _project(identifier, row, gate)


def _project(identifier: str, row: dict[str, object] | None, gate: bool) -> ObservedWorker:
    if row is None:
        evidence = WorkerEvidence(identifier=identifier, gate=gate)
        return _stored(evidence, project(evidence))
    unreadable = bool(row.get("unreadable"))
    raw_units = row.get("units")
    unit_rows = raw_units if isinstance(raw_units, list) else []
    units = tuple(
        (str(unit.get("kind", "")), str(unit.get("name", "")), str(unit.get("text", "")))
        for unit in unit_rows
        if isinstance(unit, dict)
    )
    shape = workers.read_worker_shape(identifier, units)
    shows = row.get("show")
    show_rows = shows if isinstance(shows, dict) else {}
    values: dict[str, dict[str, str]] = {}
    for role in shape.roles:
        value = show_rows.get(role)
        parsed = _values(value)
        if parsed is None:
            unreadable = True
            continue
        values[role] = parsed
    slice_values = _values(row.get("slice"))
    present = bool(shape.roles)
    results = [values[role].get("Result", "") for role in shape.roles if role in values]
    start_limited = any(result == "start-limit-hit" for result in results)
    result = "start-limit-hit" if start_limited else next((r for r in results if r), "")
    evidence = WorkerEvidence(
        identifier=identifier,
        readable=not unreadable,
        installed=present,
        enabled=present
        and all(
            values.get(role, {}).get("UnitFileState") in ENABLED_STATES for role in shape.roles
        ),
        masked=any(values.get(role, {}).get("LoadState") == "masked" for role in shape.roles)
        or (slice_values is not None and slice_values.get("LoadState") == "masked"),
        processes=shape.processes,
        active_processes=sum(
            1
            for role in shape.roles
            if values.get(role, {}).get("ActiveState") in ("active", "activating")
        ),
        result=result,
        exec_status=next(
            (
                _int(values[role].get("ExecMainStatus", "0"))
                for role in shape.roles
                if _int(values.get(role, {}).get("ExecMainStatus", "0"))
            ),
            0,
        ),
        start_limited=start_limited,
        last_start_us=max(
            (
                _timestamp(values[role].get("ExecMainStartTimestamp", ""))
                for role in shape.roles
                if _timestamp(values.get(role, {}).get("ExecMainStartTimestamp", ""))
            ),
            default=0,
        ),
        last_exit_us=max(
            (
                _timestamp(values[role].get("ExecMainExitTimestamp", ""))
                for role in shape.roles
                if _timestamp(values.get(role, {}).get("ExecMainExitTimestamp", ""))
            ),
            default=0,
        ),
        nrestarts=max(
            (_int(values.get(role, {}).get("NRestarts", "0")) for role in shape.roles),
            default=0,
        ),
        slice_populated=bool(row.get("slice_populated")),
        duplicate=str(row.get("duplicate", "")),
        gate=gate,
        problems=shape.problems,
    )
    return _stored(evidence, project(evidence), shape.definition)


def _stored(
    evidence: WorkerEvidence,
    status: WorkerStatus,
    definition: workers.WorkerDefinition | None = None,
) -> ObservedWorker:
    return ObservedWorker(
        identifier=evidence.identifier,
        status=status,
        definition=definition,
        processes=evidence.processes,
        active_processes=evidence.active_processes,
        installed=evidence.installed,
        enabled=evidence.enabled,
        masked=evidence.masked,
        result=evidence.result,
        exec_status=evidence.exec_status,
        start_limited=evidence.start_limited,
        last_start_us=evidence.last_start_us,
        last_exit_us=evidence.last_exit_us,
        nrestarts=evidence.nrestarts,
        slice_populated=evidence.slice_populated,
        duplicate=evidence.duplicate,
        problem=evidence.problem,
    )


def _values(value: object) -> dict[str, str] | None:
    if not isinstance(value, dict) or not _valid_show(value):
        return None
    return {str(key): str(item) for key, item in value.items()}


def _int(value: str) -> int:
    return int(value) if value.isdigit() and len(value) <= 9 else 0


def _timestamp(value: str) -> int:
    text = value.removeprefix("@")
    return int(text) * 1_000_000 if text.isdigit() and len(text) <= 20 else 0
