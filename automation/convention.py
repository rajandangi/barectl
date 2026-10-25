"""The per-site automation convention (docs/automation.md, ADR 0036).

One site's background work is a root-owned systemd slice, one oneshot service per role and
a timer carrying the same name as its service. This module is the single definition of the
names, the paths, the rendered unit text and the supported hand-edit shape, shared by the
controller's review, the native body and native discovery. It runs nothing.
"""

import hashlib
import re
from dataclasses import dataclass
from typing import Final

SITE_IDENTIFIER: Final = re.compile(r"[a-z][a-z0-9]{2,23}\Z")
ROLE: Final = re.compile(r"[a-z][a-z0-9]{2,20}\Z")
ROLE_WPCRON: Final = "wpcron"
ROLE_SCHEDULE: Final = "schedule"
ROLES: Final = (ROLE_WPCRON, ROLE_SCHEDULE)
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
MAX_UNIT_BYTES: Final = 16384


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
