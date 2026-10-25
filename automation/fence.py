"""The fence a site change declares, and its restore set (docs/adr/0036, Phase C #395).

A review reads the site's automation evidence once and records which units to stop, which to
start again and how long it may wait. The body-side helpers in
:mod:`automation.bodies.units` apply the plan after the kind's site lock and before its own
mutation; this module only plans. Nothing here writes a "fenced" marker: the runtime mask the
body leaves behind is the whole record, and discovery reads it as "paused by an unfinished
change".
"""

from dataclasses import dataclass
from typing import Final

from discovery.ssh import RemoteShell

from . import convention, observation

# The longest a change waits for a fence to drain, in seconds (docs/adr/0036). It is at least
# the longest ``TimeoutStopSec`` any automation role declares; a role that raises its own
# raises this with it.
FENCE_BUDGET_SECONDS: Final = 30
# The changes that pause a site's background work while they run. The specification names
# this set (docs/automation.md#fencing): every change to a site's code, schema, runtime,
# settings or files. A change that is not listed here never reads or touches automation.
FENCING: Final = frozenset(
    {
        "set_site_php",
        "set_site_node",
        "set_site_pool",
        "deploy_laravel_site",
        "rollback_laravel_site",
        "edit_laravel_environment",
        "edit_wordpress_settings",
        "remove_site",
        "update_catalog",
        "set_site_object_cache",
    }
)
# The site changes the specification excludes, plus the change that owns the units itself.
# Resetting an administrator password and verifying core files touch no code, schema,
# runtime or file that background work reads; turning server cron on or off already stops,
# starts and removes its own units in the one order that keeps page loads covered.
NO_FENCE: Final = frozenset(
    {
        "reset_wordpress_password",
        "verify_wordpress_core",
        "set_wordpress_server_cron",
        "set_laravel_scheduler",
        "set_laravel_queue_workers",
    }
)
# What a review says when it cannot read the site's background work: the change would not
# know what to pause, so it stops before changing anything.
UNREADABLE_REFUSAL: Final = (
    "The site's background work could not be read, so this change would not know what to "
    "pause. Check the server again, then prepare a new review."
)
# The systemd unit-file states that mean an installed role was on.
ENABLED: Final = frozenset({"enabled", "enabled-runtime", "static", "indirect"})


def _was_on(properties: dict[str, str]) -> bool:
    """Whether one unit was on: enabled, and not left fenced by an unfinished change."""
    return (
        properties.get("UnitFileState") in ENABLED
        and properties.get("LoadState") != "masked"
        and properties.get("UnitFileState") not in ("masked", "masked-runtime")
        and properties.get("RefuseManualStart") != "yes"
    )


@dataclass(frozen=True)
class FencePlan:
    """One site's units to stop, the slice to prove empty, and the work to start again."""

    identifier: str
    timers: tuple[str, ...]
    services: tuple[str, ...]
    resume: tuple[str, ...]
    budget_seconds: int = FENCE_BUDGET_SECONDS

    def document(self) -> dict[str, object]:
        """The reviewed, non-secret plan a body validates and applies."""
        return {
            "identifier": self.identifier,
            "slice": convention.slice_name(self.identifier),
            "timers": list(self.timers),
            "services": list(self.services),
            "resume": list(self.resume),
            "budget_seconds": self.budget_seconds,
        }


def fenced_sites(kind_slug: str, sites: tuple[str, ...]) -> tuple[str, ...]:
    """The sites one reviewed change pauses, or nothing for a change outside the set."""
    return sites if kind_slug in FENCING else ()


def plan(shell: RemoteShell, sites: tuple[str, ...]) -> dict[str, object] | None:
    """Read the named sites' background work and declare what this change pauses.

    ``None`` means the server's automation evidence could not be read: the caller refuses
    rather than fencing blind, because a stopped unit is not a fence.
    """
    if not sites:
        return {"version": 1, "sites": []}
    value = observation.read(shell)
    if value is None:
        return None
    return plan_from(value, sites)


def checked(document: dict[str, object]) -> dict[str, object] | None:
    """The stored fence, validated exactly, for a kind that stages a closed payload.

    ``None`` means the review declared nothing to pause (a change outside the fence set).
    The body re-validates the same plan from scratch with :mod:`automation.bodies.units`.
    """
    value = document.get("automation_fence")
    if value is None:
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "sites"}
        or value.get("version") != 1
        or not isinstance(value.get("sites"), list)
    ):
        raise ValueError("The change's automation plan is not valid.")
    for entry in value["sites"]:
        if not isinstance(entry, dict):
            raise ValueError("The change's automation plan is not valid.")
        identifier = entry.get("identifier")
        budget = entry.get("budget_seconds")
        if (
            not isinstance(identifier, str)
            or convention.SITE_IDENTIFIER.fullmatch(identifier) is None
            or type(budget) is not int
            or not 1 <= budget <= 300
        ):
            raise ValueError("The change's automation plan is not valid.")
        plan = FencePlan(
            identifier,
            _names(entry.get("timers"), identifier, "timer"),
            _names(entry.get("services"), identifier, "service"),
            _names(entry.get("resume"), identifier, ""),
            budget,
        )
        units = {*plan.timers, *plan.services}
        if not set(plan.resume) <= units or plan.document() != entry:
            raise ValueError("The change's automation plan is not valid.")
    return value


def _names(value: object, identifier: str, suffix: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(name, str) for name in value):
        raise ValueError("The change's automation plan is not valid.")
    names = [str(name) for name in value]
    if len(set(names)) != len(names):
        raise ValueError("The change's automation plan is not valid.")
    for name in names:
        if (suffix and not name.endswith("." + suffix)) or (
            convention.role_of(name, identifier) is None
        ):
            raise ValueError("The change's automation plan is not valid.")
    return tuple(names)


def plan_from(value: dict[str, object], sites: tuple[str, ...]) -> dict[str, object] | None:
    """The reviewed plan from one validated automation read (docs/automation.md#fencing)."""
    rows = value.get("sites")
    if not isinstance(rows, list):
        return None
    by_identifier = {
        str(row["identifier"]): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("identifier"), str)
    }
    plans: list[dict[str, object]] = []
    for identifier in sorted(set(sites)):
        row = by_identifier.get(identifier)
        if row is None:
            # The read lists every site with units, WordPress files or an automation unit.
            # A site it does not list has no automation to pause.
            continue
        site = _site_plan(row, identifier)
        if site is None:
            return None
        if site.timers or site.services:
            plans.append(site.document())
    return {"version": 1, "sites": plans}


def _site_plan(  # noqa: C901 - one read into one plan
    row: dict[str, object], identifier: str
) -> FencePlan | None:
    """One site's plan, or ``None`` when the read did not carry every installed role."""
    if row.get("unreadable"):
        return None
    units = row.get("units")
    if not isinstance(units, list):
        return None
    present: dict[str, set[str]] = {}
    for unit in units:
        if not isinstance(unit, dict):
            continue
        name, kind = unit.get("name"), unit.get("kind")
        if not isinstance(name, str) or kind not in ("service", "timer"):
            continue
        role = convention.role_of(name, identifier)
        if role is None:
            continue
        present.setdefault(role, set()).add(kind)
    timers: list[str] = []
    services: list[str] = []
    starting: list[str] = []
    for role in sorted(present):
        properties = observation.role_show(row, role)
        if properties is None:
            # The role is installed but the read carried no properties for it. Starting it
            # again would be a guess, and leaving it stopped silently would be worse.
            return None
        timer_properties, service_properties = properties
        timer = convention.timer_name(identifier, role)
        service = convention.service_name(identifier, role)
        has_timer = "timer" in present[role]
        has_service = "service" in present[role]
        if has_timer:
            timers.append(timer)
        if has_service:
            services.append(service)
        if has_timer and _was_on(timer_properties):
            starting.append(timer)
        elif not has_timer and has_service and _was_on(service_properties):
            starting.append(service)
    return FencePlan(
        identifier,
        tuple(sorted(timers)),
        tuple(sorted(services)),
        # Services start before timers, so a worker is running when its timer fires.
        tuple(sorted(starting, key=lambda name: (name.endswith(".timer"), name))),
    )
