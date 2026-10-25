"""Native helpers for a site's automation units, shared by every body that needs them.

docs/adr/0036-run-site-automation-in-per-site-slices-without-the-global-lock.md. The body
that writes units owns them; the fence helpers are called by other kinds after their site
lock and before their own mutation. Nothing here takes the global mutation lock.
"""

import contextlib
import pathlib
import re
import sys
import time
from types import SimpleNamespace

from automation.convention import (
    SYSTEMD_DIRECTORY,
    digest,
    render,
    role_of,
    service_name,
    slice_name,
    timer_name,
    unit_file,
)
from sites.bodies.common import replace_site_file, run, safe

NAME = re.compile(
    r"barectl-site-[a-z][a-z0-9]{2,23}(?:-[a-z][a-z0-9]{2,20})?\.(?:service|timer|slice)\Z"
)
POLL_SECONDS = 0.25


# A runtime drop-in that refuses a manual start. On systemd 259 a runtime mask of an
# already-loaded unit changes nothing until the unit is loaded again, so the mask alone
# cannot keep a manual ``systemctl start`` out while the change runs. The drop-in is read
# by discovery as native evidence of the pause and cleared by restore (docs/adr/0036).
FENCE_DROPIN = "50-barectl-fence.conf"


def systemctl(*arguments: str) -> str:
    return run(["/usr/bin/systemctl", *arguments])


def fence_dropin(name: str) -> pathlib.Path:
    return pathlib.Path("/run/systemd/system") / (_checked_unit(name) + ".d") / FENCE_DROPIN


def write_dropin(name: str) -> None:
    path = fence_dropin(name)
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    path.write_text("[Unit]\nRefuseManualStart=yes\n", encoding="utf-8")


def clear_dropin(name: str) -> None:
    path = fence_dropin(name)
    path.unlink(missing_ok=True)
    with contextlib.suppress(OSError):
        path.parent.rmdir()


def daemon_reload() -> None:
    systemctl("daemon-reload")


def current_text(path: pathlib.Path) -> str | None:
    """The published file's text, or ``None`` when it is absent; refuses an unsafe file."""
    if path.is_symlink():
        raise ValueError("An automation file is not a regular root-owned file.")
    if not path.exists():
        return None
    if not safe(str(path), directory=False):
        raise ValueError("An automation file is not a regular root-owned file.")
    return path.read_text(encoding="utf-8")


def publish_unit_file(path: str, text: str, expected: str | None) -> None:
    """Replace ``path`` with ``text`` only if it is still the reviewed ``expected`` text."""
    target = pathlib.Path(path)
    if current_text(target) != expected or not safe(str(target.parent), directory=True):
        raise ValueError("The reviewed automation evidence changed before publication.")
    replace_site_file(target, text, expected)


def remove_unit_file(path: str, expected: str | None) -> None:
    target = pathlib.Path(path)
    if current_text(target) != expected:
        raise ValueError("The reviewed automation evidence changed before removal.")
    if target.exists():
        target.unlink()


def unit_digests(identifier: str, role: str) -> dict[str, str]:
    """Each rendered file's digest, or ``absent``; the reviewed preimage the body rechecks."""
    values: dict[str, str] = {}
    for kind in ("slice", "service", "timer"):
        path = pathlib.Path(
            f"{SYSTEMD_DIRECTORY}/{slice_name(identifier)}"
            if kind == "slice"
            else unit_file(identifier, role, kind)
        )
        text = current_text(path)
        values[kind] = "absent" if text is None else digest(text)
    return values


def _path(identifier: str, role: str, kind: str) -> str:
    return (
        f"{SYSTEMD_DIRECTORY}/{slice_name(identifier)}"
        if kind == "slice"
        else unit_file(identifier, role, kind)
    )


def _reviewed_preimage(path: str, reviewed: str) -> str | None:
    """The live text when it is still the reviewed preimage, else a refusal."""
    text = current_text(pathlib.Path(path))
    now = "absent" if text is None else digest(text)
    if now != reviewed:
        raise ValueError("The reviewed automation evidence changed before publication.")
    return text


def publish_units(identifier: str, role: str, expected: dict[str, str]) -> None:
    for kind in ("slice", "service", "timer"):
        path = _path(identifier, role, kind)
        preimage = _reviewed_preimage(path, expected.get(kind, ""))
        publish_unit_file(path, render(identifier, role, kind), preimage)


def remove_units(identifier: str, role: str, expected: dict[str, str]) -> None:
    for kind in ("service", "timer", "slice"):
        path = _path(identifier, role, kind)
        remove_unit_file(path, _reviewed_preimage(path, expected.get(kind, "")))
    daemon_reload()
    with contextlib.suppress(ValueError):
        # The unit is no longer loaded, so there is no failed state left to clear.
        systemctl("reset-failed", timer_name(identifier, role))


def enable_timer(timer: str) -> None:
    systemctl("enable", timer)
    systemctl("start", timer)


def disable_and_stop(identifier: str, role: str) -> None:
    """Stop the timer before its service, then the slice (docs/adr/0036)."""
    timer, service = timer_name(identifier, role), service_name(identifier, role)
    systemctl("disable", "--now", timer)
    if load_state(service) != "not-found":
        systemctl("stop", service)
    if load_state(slice_name(identifier)) != "not-found":
        systemctl("stop", slice_name(identifier))


def load_state(name: str) -> str:
    completed = systemctl("show", "--value", "-p", "LoadState", name)
    return completed.strip()


def active_state(name: str) -> str:
    return systemctl("show", "--value", "-p", "ActiveState", name).strip()


def unit_file_state(name: str) -> str:
    return systemctl("show", "--value", "-p", "UnitFileState", name).strip()


def properties(name: str) -> dict[str, str]:
    text = systemctl(
        "show",
        "--no-pager",
        "--timestamp=unix",
        "-p",
        "ActiveState",
        "-p",
        "SubState",
        "-p",
        "Result",
        "-p",
        "ExecMainStatus",
        "-p",
        "ExecMainStartTimestamp",
        "-p",
        "ExecMainExitTimestamp",
        "-p",
        "LastTriggerUSec",
        "-p",
        "NextElapseUSecRealtime",
        name,
    )
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    return values


def timestamp(value: str) -> int:
    text = value.removeprefix("@")
    return int(text) if text.isdigit() and len(text) <= 20 else 0


def wait_for_tick(identifier: str, role: str, budget_seconds: int) -> bool:
    """Wait for one run started after this call to finish successfully, within ``budget``.

    The timer fires at second zero; a manual start is not used, so the run that gates the
    hand-over is the same run the server will repeat every minute.
    """
    service = service_name(identifier, role)
    deadline = time.monotonic() + budget_seconds
    baseline = timestamp(properties(service).get("ExecMainStartTimestamp", ""))
    started = False
    while time.monotonic() < deadline:
        values = properties(service)
        start = timestamp(values.get("ExecMainStartTimestamp", ""))
        if start > baseline:
            started = True
            if values.get("ActiveState") in ("inactive", "failed"):
                ok = values.get("Result") == "success" and values.get("ExecMainStatus") == "0"
                if not ok:
                    sys.stderr.write(
                        "barectl-problem first run "
                        f"state={values.get('ActiveState')} result={values.get('Result')} "
                        f"status={values.get('ExecMainStatus')}\n"
                    )
                return ok
        elif started:
            return False
        time.sleep(2)
    return False


def timer_ready(identifier: str, role: str) -> bool:
    timer = timer_name(identifier, role)
    return active_state(timer) == "active" and unit_file_state(timer) in (
        "enabled",
        "enabled-runtime",
        "static",
        "indirect",
    )


def slice_events(name: str) -> pathlib.Path | None:
    """The loaded slice's ``cgroup.events``, or ``None`` when systemd has no such slice.

    A slice's own name nests it: ``barectl-site-<id>.slice`` lives under the parent slices
    systemd derives from its dashes, so the path is read from the live control group rather
    than assumed under ``system.slice`` (docs/adr/0036).
    """
    control_group = systemctl("show", "--value", "-p", "ControlGroup", name).strip()
    if not control_group.startswith("/") or ".." in control_group or "\n" in control_group:
        return None
    return pathlib.Path("/sys/fs/cgroup" + control_group) / "cgroup.events"


def slice_empty(name: str) -> bool:
    events = slice_events(name)
    if events is None:
        return True
    try:
        return "populated 1" not in events.read_text(encoding="utf-8")
    except OSError:
        return True


def wait_slice_empty(name: str, budget_seconds: int) -> bool:
    deadline = time.monotonic() + budget_seconds
    while time.monotonic() < deadline:
        if slice_empty(name):
            return True
        time.sleep(POLL_SECONDS)
    return slice_empty(name)


def _checked_unit(name: object) -> str:
    if not isinstance(name, str) or NAME.fullmatch(name) is None:
        raise ValueError("Not an automation unit name.")
    return name


def _checked_plan(document: object, identifier: str) -> SimpleNamespace | None:
    """One site's reviewed fence from the change's document, or ``None`` for nothing to pause."""
    if not isinstance(document, dict):
        raise ValueError("The reviewed change is not valid.")
    fence = document.get("automation_fence")
    if fence is None:
        return None
    if not isinstance(fence, dict) or set(fence) != {"version", "sites"} or fence["version"] != 1:
        raise ValueError("The reviewed automation plan is not valid.")
    entries = fence["sites"]
    if not isinstance(entries, list):
        raise ValueError("The reviewed automation plan is not valid.")
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("The reviewed automation plan is not valid.")
        if entry.get("identifier") != identifier:
            continue
        return _checked_site(entry, identifier)
    return None


def _checked_site(document: dict[str, object], identifier: str) -> SimpleNamespace:
    expected = {"identifier", "slice", "timers", "services", "resume", "budget_seconds"}
    slice_value = document.get("slice")
    timers, services, resume = (
        document.get("timers"),
        document.get("services"),
        document.get("resume"),
    )
    budget = document.get("budget_seconds")
    if (
        set(document) != expected
        or document.get("identifier") != identifier
        or not isinstance(slice_value, str)
        or not isinstance(timers, list)
        or not isinstance(services, list)
        or not isinstance(resume, list)
        or type(budget) is not int
        or not 1 <= budget <= 300
        or not all(isinstance(name, str) for name in (*timers, *services, *resume))
    ):
        raise ValueError("The reviewed automation plan is not valid.")
    plan = SimpleNamespace(
        slice=_checked_unit(slice_value),
        timers=[_checked_unit(name) for name in timers if isinstance(name, str)],
        services=[_checked_unit(name) for name in services if isinstance(name, str)],
        resume=[_checked_unit(name) for name in resume if isinstance(name, str)],
        budget_seconds=budget,
    )
    units_of_site = [*plan.timers, *plan.services]
    if (
        plan.slice != slice_name(identifier)
        or len(set(units_of_site)) != len(units_of_site)
        or any(role_of(name, identifier) is None for name in units_of_site)
        or not set(plan.resume) <= set(units_of_site)
    ):
        raise ValueError("The reviewed automation plan is not valid.")
    return plan


def fence(  # noqa: C901 - one reviewed stop sequence
    document: object, identifier: str, *, gate: bool = False
) -> bool:
    """Stop a site's background work and prove its slice has no processes.

    Call it after the kind's site lock and before its own mutation. A runtime mask keeps the
    work from starting again, including from a boot, until :func:`restore` clears it. When the
    change enters a persistent maintenance gate, ``gate`` also removes boot activation, so a
    reboot during the gate cannot restart work.
    """
    plan = _checked_plan(document, identifier)
    if plan is None:
        return True
    try:
        for name in [*plan.timers, *plan.services]:
            if load_state(name) != "not-found":
                systemctl("mask", "--runtime", name)
                write_dropin(name)
        # A loaded unit keeps its old unit-file state, and would start from the copy it
        # loaded, until systemd reads the fence's drop-in. Reload before the stops.
        daemon_reload()
        if gate:
            for name in plan.timers:
                # A stopped unit is not a reboot fence: drop the timer's boot activation too.
                run(["/usr/bin/systemctl", "disable", name], check=False)
        for name in plan.timers:
            if load_state(name) != "not-found":
                systemctl("stop", name)
        for name in plan.services:
            if load_state(name) != "not-found":
                systemctl("stop", name)
        if load_state(plan.slice) != "not-found":
            systemctl("stop", plan.slice)
    except OSError, ValueError, KeyError:
        return False
    return wait_slice_empty(plan.slice, plan.budget_seconds)


def restore(document: object, identifier: str) -> bool:
    """Clear the fence and start exactly the reviewed resume set, then prove it is active.

    A failed or unknown change never reaches here, so its work stays fenced. A change that
    cannot prove one resumed unit is active reports partial and leaves the rest stopped.
    """
    plan = _checked_plan(document, identifier)
    if plan is None:
        return True
    try:
        for name in [*plan.timers, *plan.services]:
            if load_state(name) == "masked":
                systemctl("unmask", "--runtime", name)
            clear_dropin(name)
        daemon_reload()
        for name in plan.resume:
            if name.endswith(".timer"):
                systemctl("enable", name)
            else:
                # An always-on worker carries its own install section; a oneshot service is
                # started by its timer and has none.
                run(["/usr/bin/systemctl", "enable", name], check=False)
            systemctl("start", name)
        return all(_active(name) for name in plan.resume)
    except OSError, ValueError, KeyError:
        return False


def _active(name: str) -> bool:
    if name.endswith(".timer"):
        return active_state(name) == "active" and unit_file_state(name) in (
            "enabled",
            "enabled-runtime",
            "static",
            "indirect",
        )
    return active_state(name) in ("active", "activating")


def reviewed_units(document: object, identifier: str) -> list[str]:
    """The reviewed unit names of one site: its timers, its services and its slice."""
    plan = _checked_plan(document, identifier)
    if plan is None:
        return []
    return [*plan.timers, *plan.services, plan.slice]


def forget(document: object, identifier: str) -> None:
    """Clear the fence's masks once its unit files are gone, as site removal does."""
    plan = _checked_plan(document, identifier)
    if plan is None:
        return
    for name in [*plan.timers, *plan.services]:
        clear_dropin(name)
        for action in ("unmask --runtime", "reset-failed"):
            run(["/usr/bin/systemctl", *action.split(), name], check=False)
    run(["/usr/bin/systemctl", "daemon-reload"], check=False)


def _role(name: str, identifier: str) -> str:
    role = role_of(name, identifier)
    if role is None:
        raise ValueError("Not an automation unit of this site.")
    return role


__all__ = [
    "_role",
    "active_state",
    "daemon_reload",
    "disable_and_stop",
    "enable_timer",
    "fence",
    "fence_dropin",
    "forget",
    "load_state",
    "properties",
    "publish_unit_file",
    "publish_units",
    "remove_unit_file",
    "remove_units",
    "restore",
    "reviewed_units",
    "slice_empty",
    "systemctl",
    "timer_ready",
    "unit_digests",
    "unit_file_state",
    "wait_for_tick",
    "wait_slice_empty",
]
