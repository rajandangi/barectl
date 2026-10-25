"""A Laravel site's one database queue-worker definition (Phase C #266, ADR 0036).

This module owns the definition's bounds, its retry and stop arithmetic, the rendered
``queue1`` to ``queue4`` services and the supported hand-edit shape. It runs nothing; the
review, the native body, discovery and the pages share it. The schedule convention in
:mod:`automation.convention` keeps the names, the slice and the site identity.
"""

import re
from dataclasses import dataclass
from typing import Final

from automation.convention import (
    KILL_MODE,
    WORKER_ROLES,
    account,
    digest,
    directives_map,
    parse_unit,
    render_slice,
    role_of,
    service_name,
    site_directory,
    slice_name,
)

ROLE_PREFIX: Final = "queue"
WORKER_ROLE: Final = re.compile(r"queue([1-4])\Z")
QUEUE_NAME: Final = re.compile(r"[a-z0-9_-]{1,32}\Z")
MAX_QUEUES: Final = 8
MIN_PROCESSES: Final = 1
MAX_PROCESSES: Final = 4
MIN_TIMEOUT: Final = 30
MAX_TIMEOUT: Final = 900
DEFAULT_TIMEOUT: Final = 60
# Laravel's documented worker defaults for one process.
SLEEP: Final = "3"
TRIES: Final = "3"
MAX_TIME: Final = "3600"
CONNECTION: Final = "database"
RESTART: Final = "always"
RESTART_SEC: Final = "5s"
START_LIMIT_INTERVAL: Final = "60s"
START_LIMIT_BURST: Final = 5
# Laravel requires --timeout several seconds below retry_after; the job must also finish
# before the worker's own stop budget, so retry_after = timeout + 30 and the stop budget
# = timeout + 15 stay on opposite sides of the job limit.
RETRY_MARGIN: Final = 30
STOP_MARGIN: Final = 15
RETRY_AFTER_KEY: Final = "DB_QUEUE_RETRY_AFTER"
INSTALL_TARGET: Final = "multi-user.target"


@dataclass(frozen=True)
class WorkerDefinition:
    """The reviewed worker: queue names in priority order, processes and job timeout."""

    queues: tuple[str, ...]
    processes: int
    timeout: int

    @property
    def queue_argument(self) -> str:
        return ",".join(self.queues)

    @property
    def retry_after(self) -> int:
        return self.timeout + RETRY_MARGIN

    @property
    def stop_seconds(self) -> int:
        return self.timeout + STOP_MARGIN

    @property
    def roles(self) -> tuple[str, ...]:
        return WORKER_ROLES[: self.processes]

    def document(self) -> dict[str, object]:
        return {
            "queues": list(self.queues),
            "processes": self.processes,
            "timeout": self.timeout,
        }


def process_of(role: str) -> int | None:
    match = WORKER_ROLE.fullmatch(role)
    return int(match.group(1)) if match is not None else None


def parse_queues(value: str) -> tuple[str, ...]:
    """Queue names from a comma or whitespace separated field, in priority order."""
    names = tuple(name for name in re.split(r"[,\s]+", value.strip()) if name)
    if not names:
        raise ValueError("Type at least one queue name.")
    if len(names) > MAX_QUEUES:
        raise ValueError(f"Use at most {MAX_QUEUES} queue names.")
    for name in names:
        if QUEUE_NAME.fullmatch(name) is None:
            raise ValueError("Queue names use lowercase letters, digits, hyphens and underscores.")
    if len(set(names)) != len(names):
        raise ValueError("Each queue name appears once.")
    return names


def parse_definition(queues: str, processes: object, timeout: object) -> WorkerDefinition:
    """A validated definition from the form's own strings; raises ``ValueError``."""
    if type(processes) is not int or not MIN_PROCESSES <= processes <= MAX_PROCESSES:
        raise ValueError(f"Choose between {MIN_PROCESSES} and {MAX_PROCESSES} worker processes.")
    if type(timeout) is not int or not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise ValueError(f"Choose a job timeout from {MIN_TIMEOUT} to {MAX_TIMEOUT} seconds.")
    return WorkerDefinition(parse_queues(queues), processes, timeout)


def checked_definition(value: object) -> WorkerDefinition:
    """A definition from a stored document, strict about every field."""
    if not isinstance(value, dict) or set(value) != {"queues", "processes", "timeout"}:
        raise ValueError("The reviewed queue-worker definition is not valid.")
    queues, processes, timeout = value["queues"], value["processes"], value["timeout"]
    if not isinstance(queues, list) or not all(isinstance(name, str) for name in queues):
        raise ValueError("The reviewed queue-worker definition is not valid.")
    if type(processes) is not int or type(timeout) is not int:
        raise ValueError("The reviewed queue-worker definition is not valid.")
    return parse_definition(",".join(queues), processes, timeout)


def render_worker_service(identifier: str, process: int, definition: WorkerDefinition) -> str:
    """One process's ``Type=exec`` service in the site's slice and identity."""
    directory = site_directory(identifier)
    account_name = account(identifier)
    return (
        "[Unit]\n"
        f"Description=Barectl queue worker {process} for {identifier}\n"
        f"ConditionPathIsDirectory={directory}/current\n"
        f"ConditionFileIsExecutable={directory}/bin/php\n"
        f"StartLimitIntervalSec={START_LIMIT_INTERVAL}\n"
        f"StartLimitBurst={START_LIMIT_BURST}\n"
        "\n"
        "[Service]\n"
        "Type=exec\n"
        f"User={account_name}\n"
        f"Group={account_name}\n"
        f"WorkingDirectory={directory}/current\n"
        f"Slice={slice_name(identifier)}\n"
        f"Restart={RESTART}\n"
        f"RestartSec={RESTART_SEC}\n"
        f"KillMode={KILL_MODE}\n"
        f"TimeoutStopSec={definition.stop_seconds}s\n"
        f"ExecStart={directory}/bin/php artisan queue:work {CONNECTION} "
        f"--queue={definition.queue_argument} --sleep={SLEEP} --tries={TRIES} "
        f"--max-time={MAX_TIME} --timeout={definition.timeout}\n"
        "\n"
        "[Install]\n"
        f"WantedBy={INSTALL_TARGET}\n"
    )


def render_worker_units(
    identifier: str, definition: WorkerDefinition
) -> list[tuple[str, str, str]]:
    """``(kind, name, text)`` for the slice and every reviewed process."""
    units = [("slice", slice_name(identifier), render_slice(identifier))]
    for process, role in enumerate(definition.roles, start=1):
        units.append(
            (
                "service",
                service_name(identifier, role),
                render_worker_service(identifier, process, definition),
            )
        )
    return units


def expected_units(identifier: str, definition: WorkerDefinition) -> dict[str, str]:
    """Each rendered file's digest keyed by role (``slice`` for the shared slice)."""
    return {
        "slice": digest(render_slice(identifier)),
        **{
            role: digest(render_worker_service(identifier, process, definition))
            for process, role in enumerate(definition.roles, start=1)
        },
    }


@dataclass(frozen=True)
class WorkerUnitShape:
    """One installed process unit, read by its semantic settings."""

    name: str
    role: str
    present: bool
    supported: bool
    problem: str = ""
    definition: WorkerDefinition | None = None


def _allowed() -> frozenset[tuple[str, str]]:
    return frozenset(
        {
            ("Unit", "Description"),
            ("Unit", "ConditionPathIsDirectory"),
            ("Unit", "ConditionFileIsExecutable"),
            ("Unit", "StartLimitIntervalSec"),
            ("Unit", "StartLimitBurst"),
            ("Service", "Type"),
            ("Service", "User"),
            ("Service", "Group"),
            ("Service", "WorkingDirectory"),
            ("Service", "Slice"),
            ("Service", "Restart"),
            ("Service", "RestartSec"),
            ("Service", "KillMode"),
            ("Service", "TimeoutStopSec"),
            ("Service", "ExecStart"),
            ("Install", "WantedBy"),
        }
    )


def parse_worker_service(name: str, text: str, identifier: str, process: int) -> WorkerUnitShape:
    """Recognise one process unit, adopting a queue list, count or timeout in bounds.

    A supported hand edit keeps every semantic setting the convention owns; a changed
    command, account, restart policy or an unknown directive is reported once.
    """
    role = f"{ROLE_PREFIX}{process}"
    if name != service_name(identifier, role):
        return WorkerUnitShape(name, role, True, False, "This is not a Barectl queue worker.")
    found = directives_map(text)
    if found is None:
        return WorkerUnitShape(
            name, role, True, False, "The queue worker has unsupported settings."
        )
    for (section, key), value in found.items():
        if (section, key) not in _allowed():
            return WorkerUnitShape(
                name,
                role,
                True,
                False,
                f"The queue worker has an unsupported setting: {section}>{key}.",
            )
        _ = value
    fixed = {
        ("Service", "Type"): "exec",
        ("Service", "User"): account(identifier),
        ("Service", "Group"): account(identifier),
        ("Service", "WorkingDirectory"): f"{site_directory(identifier)}/current",
        ("Service", "Slice"): slice_name(identifier),
        ("Service", "Restart"): RESTART,
        ("Service", "RestartSec"): RESTART_SEC,
        ("Unit", "StartLimitIntervalSec"): START_LIMIT_INTERVAL,
        ("Unit", "StartLimitBurst"): str(START_LIMIT_BURST),
        ("Service", "KillMode"): KILL_MODE,
        ("Install", "WantedBy"): INSTALL_TARGET,
        ("Unit", "ConditionPathIsDirectory"): f"{site_directory(identifier)}/current",
        ("Unit", "ConditionFileIsExecutable"): f"{site_directory(identifier)}/bin/php",
    }
    for directive, expected_value in fixed.items():
        if found.get(directive) != expected_value:
            return WorkerUnitShape(
                name,
                role,
                True,
                False,
                (
                    f"The queue worker setting {directive[0]}>{directive[1]} was changed "
                    "outside Barectl."
                ),
            )
    definition = _definition_from(found, identifier)
    if definition is None:
        return WorkerUnitShape(
            name,
            role,
            True,
            False,
            "The queue worker command was changed outside Barectl.",
        )
    expected = directives_map(render_worker_service(identifier, process, definition))
    if expected is None or found != expected:
        return WorkerUnitShape(
            name, role, True, False, "The queue worker settings were changed outside Barectl."
        )
    return WorkerUnitShape(name, role, True, True, definition=definition)


def _definition_from(found: dict[tuple[str, str], str], identifier: str) -> WorkerDefinition | None:
    command = found.get(("Service", "ExecStart"), "")
    directory = site_directory(identifier)
    prefix = f"{directory}/bin/php artisan queue:work {CONNECTION} "
    if not command.startswith(prefix):
        return None
    arguments = command.removeprefix(prefix).split()
    flags: dict[str, str] = {}
    for argument in arguments:
        name, separator, value = argument.partition("=")
        if not separator or name in flags:
            return None
        flags[name] = value
    if set(flags) != {
        "--queue",
        "--sleep",
        "--tries",
        "--max-time",
        "--timeout",
    }:
        return None
    if flags["--sleep"] != SLEEP or flags["--tries"] != TRIES or flags["--max-time"] != MAX_TIME:
        return None
    timeout = flags["--timeout"]
    if not timeout.isdigit() or not MIN_TIMEOUT <= int(timeout) <= MAX_TIMEOUT:
        return None
    try:
        definition = WorkerDefinition(parse_queues(flags["--queue"]), 1, int(timeout))
    except ValueError:
        return None
    if found.get(("Service", "TimeoutStopSec")) != f"{definition.stop_seconds}s":
        return None
    return definition


@dataclass(frozen=True)
class WorkerShape:
    """The definition read from every installed process unit, or what blocks it."""

    definition: WorkerDefinition | None
    processes: int
    roles: tuple[str, ...]
    problems: tuple[str, ...]
    digests: dict[str, str]


def read_worker_shape(  # noqa: C901 - one shape for four roles
    identifier: str, units: tuple[tuple[str, str, str], ...]
) -> WorkerShape:
    """Recognise the slice and each ``queueN`` service; adopt edits inside the bounds."""
    problems: list[str] = []
    digests: dict[str, str] = {"slice": "absent"}
    shapes: list[WorkerUnitShape] = []
    for kind, name, text in units:
        if kind == "slice":
            shape = parse_unit(name, text, identifier, "", "slice")
            if not shape.supported:
                problems.append(shape.problem)
                continue
            if digests["slice"] != "absent":
                problems.append("The automation slice is duplicated.")
                continue
            digests["slice"] = digest(text)
        elif kind == "timer":
            if role_of(name, identifier) in WORKER_ROLES:
                problems.append("A queue worker has a schedule outside Barectl.")
        elif kind == "service" and role_of(name, identifier) in WORKER_ROLES:
            role = role_of(name, identifier) or ""
            process = process_of(role)
            if process is None:
                continue
            parsed = parse_worker_service(name, text, identifier, process)
            if not parsed.supported:
                problems.append(parsed.problem)
                continue
            if role in digests:
                problems.append("The queue worker files are duplicated.")
                continue
            digests[role] = digest(text)
            shapes.append(parsed)
    shapes.sort(key=lambda shape: process_of(shape.role) or 0)
    roles = tuple(shape.role for shape in shapes)
    expected = WORKER_ROLES[: len(roles)]
    if roles and roles != expected:
        problems.append("The queue worker processes are not numbered from one.")
    definitions = {shape.definition for shape in shapes if shape.definition is not None}
    if len(definitions) > 1:
        problems.append("The queue worker processes use different settings.")
    definition = None
    if len(definitions) == 1 and not problems:
        found = definitions.pop()
        definition = WorkerDefinition(found.queues, len(roles), found.timeout)
    return WorkerShape(
        definition if not problems else None,
        len(roles),
        roles,
        tuple(dict.fromkeys(problems)),
        digests,
    )


__all__ = [
    "DEFAULT_TIMEOUT",
    "MAX_PROCESSES",
    "MAX_QUEUES",
    "MAX_TIMEOUT",
    "MIN_PROCESSES",
    "MIN_TIMEOUT",
    "RETRY_AFTER_KEY",
    "RETRY_MARGIN",
    "STOP_MARGIN",
    "WORKER_ROLES",
    "WorkerDefinition",
    "WorkerShape",
    "WorkerUnitShape",
    "checked_definition",
    "expected_units",
    "parse_definition",
    "parse_queues",
    "parse_worker_service",
    "process_of",
    "read_worker_shape",
    "render_worker_service",
    "render_worker_units",
]
