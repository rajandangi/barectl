"""The per-site automation convention (docs/automation.md, ADR 0036).

One site's background work is a root-owned systemd slice, one oneshot service per role and
a timer carrying the same name as its service. This module is the single definition of the
names, the paths, the rendered unit text and the supported hand-edit shape, shared by the
controller's review, the native body and native discovery. It runs nothing.
"""

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

SITE_IDENTIFIER: Final = re.compile(r"[a-z][a-z0-9]{2,23}\Z")
ROLE: Final = re.compile(r"[a-z][a-z0-9]{2,20}\Z")
ROLE_WPCRON: Final = "wpcron"
ROLE_SCHEDULE: Final = "schedule"
# One Laravel queue process per role. They share the scheduled roles' slice and identity;
# their service text is owned by automation.workers (Phase C #266).
WORKER_ROLES: Final = tuple(f"queue{process}" for process in range(1, 5))
ROLES: Final = (ROLE_WPCRON, ROLE_SCHEDULE, *WORKER_ROLES)
# A site starts one worker process per reviewed process count (#266). The role carries its
# position so every installed ``queue<N>`` unit is found from the convention, never from a
# second naming scheme (docs/automation.md).
QUEUE_PROCESSES: Final = (1, 2, 3, 4)
QUEUE_ROLE: Final = re.compile(r"queue([1-9][0-9]{0,2})\Z")
SYSTEMD_DIRECTORY: Final = "/etc/systemd/system"
SLICE_TEMPLATE: Final = "barectl-site-{identifier}.slice"
UNIT_TEMPLATE: Final = "barectl-site-{identifier}-{role}"
SITE_DIRECTORY: Final = "/var/www/{identifier}"
# docs/adr/0036: one calendar elapse per minute at second zero, never a catch-up burst and
# never a burst after a run that overran the next elapse.
ON_CALENDAR: Final = "*-*-* *:*:00"
ACCURACY: Final = "1s"
RANDOMIZED_DELAY: Final = "0"
WPCRON_TIMEOUT: Final = "15min"
SCHEDULE_TIMEOUT: Final = "1h"
# The whole process tree is killed, so a plugin that forks cannot outlive its tick.
KILL_MODE: Final = "control-group"
# The longest a turn-on waits for one successful run before leaving the timer installed and
# the constant unset (it stays inside the change engine's watch limit).
TICK_BUDGET_SECONDS: Final = 150
# A fence waits at least this long and never longer than a worker's longest declared stop
# budget (the job timeout plus its fifteen-second margin).
FENCE_BUDGET_SECONDS: Final = 30
MAX_FENCE_BUDGET_SECONDS: Final = 915
# The systemd unit-file states that mean an installed role was on.
ENABLED_STATES: Final = frozenset({"enabled", "enabled-runtime", "static", "indirect"})
MAX_UNIT_BYTES: Final = 16384
FENCE_SITE_KEYS: Final = frozenset(
    {"identifier", "slice", "timers", "services", "resume", "budget_seconds"}
)
_TIME_UNITS: Final = {
    "us": 0.000001,
    "ms": 0.001,
    "s": 1.0,
    "min": 60.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
    "w": 604800.0,
    "M": 2629800.0,
    "y": 31557600.0,
}
_TIME_PART: Final = re.compile(r"(\d+)(us|ms|s|min|m|h|d|w|M|y)?")


@dataclass(frozen=True)
class Renderable:
    """One automation unit the convention can render and recognise."""

    role: str
    command: str
    executable: str
    timeout: str


WPCRON: Final = Renderable(
    ROLE_WPCRON,
    # WP-CLI does not read the site's private root from ``current``; the public root is.
    "{directory}/bin/wp --path={directory}/current/public cron event run --due-now",
    "{directory}/bin/wp",
    WPCRON_TIMEOUT,
)
SCHEDULE: Final = Renderable(
    ROLE_SCHEDULE,
    # The absolute paths keep the selected runtime and the release the ``current`` link
    # points at, even if systemd's working directory is ever changed.
    "{directory}/bin/php {directory}/current/artisan schedule:run",
    "{directory}/bin/php",
    SCHEDULE_TIMEOUT,
)
RENDERABLE: Final = {renderable.role: renderable for renderable in (WPCRON, SCHEDULE)}


def checked_identifier(identifier: str) -> str:
    if SITE_IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a valid site identifier.")
    return identifier


def checked_role(role: str) -> str:
    if role not in RENDERABLE:
        raise ValueError("Not a supported automation role.")
    return role


def slice_name(identifier: str) -> str:
    return SLICE_TEMPLATE.format(identifier=checked_identifier(identifier))


def unit_basename(identifier: str, role: str) -> str:
    checked_identifier(identifier)
    if ROLE.fullmatch(role) is None:
        raise ValueError("Not a valid automation role.")
    return UNIT_TEMPLATE.format(identifier=identifier, role=role)


def service_name(identifier: str, role: str) -> str:
    return unit_basename(identifier, role) + ".service"


def timer_name(identifier: str, role: str) -> str:
    return unit_basename(identifier, role) + ".timer"


def unit_file(identifier: str, role: str, kind: str) -> str:
    if kind == "service":
        name = service_name(identifier, role)
    elif kind == "timer":
        name = timer_name(identifier, role)
    else:
        raise ValueError("Not a systemd unit kind.")
    return f"{SYSTEMD_DIRECTORY}/{name}"


def slice_file(identifier: str) -> str:
    return f"{SYSTEMD_DIRECTORY}/{slice_name(identifier)}"


def site_directory(identifier: str) -> str:
    return SITE_DIRECTORY.format(identifier=checked_identifier(identifier))


def account(identifier: str) -> str:
    return "s" + checked_identifier(identifier)


def role_of(name: str, identifier: str) -> str | None:
    """The role a unit name of this site carries, or ``None`` for another unit."""
    prefix = f"barectl-site-{checked_identifier(identifier)}-"
    if not name.startswith(prefix):
        return None
    remainder, _, kind = name.removeprefix(prefix).partition(".")
    if kind not in ("service", "timer") or ROLE.fullmatch(remainder) is None:
        return None
    return remainder


def queue_role(index: int) -> str:
    """The role of one reviewed worker process."""
    if index not in QUEUE_PROCESSES:
        raise ValueError("Not a reviewed queue process.")
    return f"queue{index}"


def queue_index(role: str) -> int | None:
    """The process number a role carries, or ``None`` for another role."""
    match = QUEUE_ROLE.fullmatch(role)
    if match is None:
        return None
    index = int(match.group(1))
    return index if index in QUEUE_PROCESSES else None


def queue_roles(names: Iterable[str], identifier: str) -> tuple[str, ...]:
    """Every ``queue<N>`` service role among a site's unit names, in process order."""
    found: set[str] = set()
    for name in names:
        base = name.rsplit("/", 1)[-1]
        role = role_of(base, identifier)
        if role is None or not base.endswith(".service") or queue_index(role) is None:
            continue
        found.add(role)
    return tuple(sorted(found, key=lambda role: queue_index(role) or 0))


def render_slice(identifier: str) -> str:
    return f"[Unit]\nDescription=Barectl background work for {identifier}\n\n[Slice]\n"


def render_service(identifier: str, role: str) -> str:
    renderable = RENDERABLE[checked_role(role)]
    directory = site_directory(identifier)
    return (
        "[Unit]\n"
        f"Description=Barectl {role} for {identifier}\n"
        f"ConditionPathIsDirectory={directory}/current\n"
        f"ConditionFileIsExecutable={renderable.executable.format(directory=directory)}\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"User={account(identifier)}\n"
        f"Group={account(identifier)}\n"
        f"WorkingDirectory={directory}/current\n"
        f"Slice={slice_name(identifier)}\n"
        f"TimeoutStartSec={renderable.timeout}\n"
        f"KillMode={KILL_MODE}\n"
        f"ExecStart={renderable.command.format(directory=directory)}\n"
    )


def render_timer(identifier: str, role: str) -> str:
    checked_role(role)
    return (
        "[Unit]\n"
        f"Description=Barectl {role} schedule for {identifier}\n"
        "\n"
        "[Timer]\n"
        f"OnCalendar={ON_CALENDAR}\n"
        f"AccuracySec={ACCURACY}\n"
        f"RandomizedDelaySec={RANDOMIZED_DELAY}\n"
        "Persistent=false\n"
        "DeferReactivation=yes\n"
        f"Unit={service_name(identifier, role)}\n"
        f"Slice={slice_name(identifier)}\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def render(identifier: str, role: str, kind: str) -> str:
    if kind == "slice":
        return render_slice(identifier)
    if kind == "service":
        return render_service(identifier, role)
    if kind == "timer":
        return render_timer(identifier, role)
    raise ValueError("Not a systemd unit kind.")


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class UnitShape:
    """Whether an installed unit is the convention's shape or an edit Barectl does not read."""

    name: str
    kind: str
    present: bool
    supported: bool
    problem: str = ""


def parse_unit(name: str, text: str, identifier: str, role: str, kind: str) -> UnitShape:
    """Recognise a unit by its semantic directives, ignoring comments and directive order.

    A supported hand edit reorders directives or changes a comment. Any other change is
    reported once and blocks only the changes that depend on it.
    """
    expected_name = (
        slice_name(identifier)
        if kind == "slice"
        else (service_name(identifier, role) if kind == "service" else timer_name(identifier, role))
    )
    if kind not in ("service", "timer", "slice") or name != expected_name:
        return UnitShape(name, kind, True, False, "This is not a Barectl background task.")
    expected = directives_map(render(identifier, role, kind))
    found = directives_map(text)
    if expected is None or found is None:
        return UnitShape(name, kind, True, False, "The background task has unsupported settings.")
    allowed = _allowed_directives(kind)
    for section, key in found:
        if (section, key) not in allowed:
            return UnitShape(
                name,
                kind,
                True,
                False,
                f"The background task has an unsupported setting: {section}>{key}.",
            )
        if expected.get((section, key)) != found[(section, key)]:
            return UnitShape(
                name,
                kind,
                True,
                False,
                f"The background task setting {section}>{key} was changed outside Barectl.",
            )
    if set(found) != set(expected):
        return UnitShape(
            name, kind, True, False, "The background task is missing a required setting."
        )
    return UnitShape(name, kind, True, True)


def _allowed_directives(kind: str) -> frozenset[tuple[str, str]]:
    common = {("Unit", "Description")}
    if kind == "slice":
        return frozenset(common)
    if kind == "service":
        return frozenset(
            common
            | {
                ("Unit", "ConditionPathIsDirectory"),
                ("Unit", "ConditionFileIsExecutable"),
                ("Service", "Type"),
                ("Service", "User"),
                ("Service", "Group"),
                ("Service", "WorkingDirectory"),
                ("Service", "Slice"),
                ("Service", "TimeoutStartSec"),
                ("Service", "KillMode"),
                ("Service", "ExecStart"),
            }
        )
    return frozenset(
        common
        | {
            ("Timer", "OnCalendar"),
            ("Timer", "AccuracySec"),
            ("Timer", "RandomizedDelaySec"),
            ("Timer", "Persistent"),
            ("Timer", "DeferReactivation"),
            ("Timer", "Unit"),
            ("Timer", "Slice"),
            ("Install", "WantedBy"),
        }
    )


def _directives(text: str) -> list[tuple[str, str, str]] | None:
    """The unit's semantic settings, or ``None`` for text systemd would not read as one."""
    if len(text.encode("utf-8", "replace")) > MAX_UNIT_BYTES:
        return None
    found: list[tuple[str, str, str]] = []
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        key, separator, value = line.partition("=")
        if not separator or not section or not key.strip() or raw.endswith("\\"):
            return None
        found.append((section, key.strip(), value.strip()))
    return found


def directives_map(text: str) -> dict[tuple[str, str], str] | None:
    found = _directives(text)
    return None if found is None else {(section, key): value for section, key, value in found}


def time_span_seconds(value: str) -> int | None:
    """A systemd time span in whole seconds, or ``None`` when it is not one."""
    text = value.strip()
    if not text or text == "infinity":
        return None
    total = 0.0
    position = 0
    while position < len(text):
        match = _TIME_PART.match(text, position)
        if match is None:
            return None
        total += int(match.group(1)) * _TIME_UNITS[match.group(2) or "s"]
        position = match.end()
        while position < len(text) and text[position].isspace():
            position += 1
    seconds = int(total)
    return seconds if total == seconds else None


def checked_fence_plan(value: object) -> list[dict[str, object]] | None:
    """The sites of one reviewed automation plan, or ``None`` when it declared nothing.

    The engine and every staged body validate the same closed document here, so they
    cannot disagree about what a plan may contain (docs/automation.md#fencing).
    """
    if value is None:
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "sites"}
        or value.get("version") != 1
        or not isinstance(value.get("sites"), list)
    ):
        raise ValueError("The reviewed automation plan is not valid.")
    sites: list[dict[str, object]] = []
    for entry in value["sites"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("identifier"), str):
            raise ValueError("The reviewed automation plan is not valid.")
        sites.append(checked_fence_site(entry, str(entry["identifier"])))
    return sites


def checked_fence_site(value: object, identifier: str) -> dict[str, object]:
    """One site's reviewed fence, validated exactly against the closed shape."""
    if not isinstance(value, dict) or set(value) != FENCE_SITE_KEYS:
        raise ValueError("The reviewed automation plan is not valid.")
    slice_value = value.get("slice")
    timers = _fence_names(value.get("timers"), identifier, "timer")
    services = _fence_names(value.get("services"), identifier, "service")
    resume = _fence_names(value.get("resume"), identifier, "")
    budget = value.get("budget_seconds")
    if (
        value.get("identifier") != identifier
        or slice_value != slice_name(identifier)
        or type(budget) is not int
        or not FENCE_BUDGET_SECONDS <= budget <= MAX_FENCE_BUDGET_SECONDS
        or not set(resume) <= {*timers, *services}
    ):
        raise ValueError("The reviewed automation plan is not valid.")
    return {
        "identifier": identifier,
        "slice": slice_name(identifier),
        "timers": list(timers),
        "services": list(services),
        "resume": list(resume),
        "budget_seconds": budget,
    }


def _fence_names(value: object, identifier: str, suffix: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(name, str) for name in value):
        raise ValueError("The reviewed automation plan is not valid.")
    names = tuple(str(name) for name in value)
    if len(set(names)) != len(names):
        raise ValueError("The reviewed automation plan is not valid.")
    for name in names:
        if (suffix and not name.endswith("." + suffix)) or role_of(name, identifier) is None:
            raise ValueError("The reviewed automation plan is not valid.")
    return names
