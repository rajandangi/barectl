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


def systemctl(*arguments: str) -> str:
    return run(["/usr/bin/systemctl", *arguments])


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


def publish(path: str, text: str, expected: str | None) -> None:
    """Replace ``path`` with ``text`` only if it is still the reviewed ``expected`` text."""
    target = pathlib.Path(path)
    if current_text(target) != expected or not safe(str(target.parent), directory=True):
        raise ValueError("The reviewed automation evidence changed before publication.")
    replace_site_file(target, text, expected)


def remove(path: str, expected: str | None) -> None:
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
        publish(path, render(identifier, role, kind), preimage)


def remove_units(identifier: str, role: str, expected: dict[str, str]) -> None:
    for kind in ("service", "timer", "slice"):
        path = _path(identifier, role, kind)
        remove(path, _reviewed_preimage(path, expected.get(kind, "")))
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


def start_and_wait(identifier: str, role: str, budget_seconds: int) -> str:
    """Start one installed oneshot service and wait for its result.

    Returns systemd's ``Result`` when the run finished (``success``, ``timeout`` or a
    failure), or ``running`` when it is still in progress at the reviewed budget. The
    timer is never touched, so a Run now adds no unit and changes no schedule.
    """
    service = service_name(identifier, role)
    systemctl("start", "--no-block", service)
    deadline = time.monotonic() + budget_seconds
    while time.monotonic() < deadline:
        values = properties(service)
        if values.get("ActiveState") in ("inactive", "failed"):
            return values.get("Result") or "failed"
        time.sleep(1)
    return "running"


def timer_ready(identifier: str, role: str) -> bool:
    timer = timer_name(identifier, role)
    return active_state(timer) == "active" and unit_file_state(timer) in (
        "enabled",
        "enabled-runtime",
        "static",
        "indirect",
    )


def slice_events(name: str) -> pathlib.Path:
    return pathlib.Path("/sys/fs/cgroup/system.slice") / name / "cgroup.events"


def slice_empty(name: str) -> bool:
    try:
        return "populated 1" not in slice_events(name).read_text(encoding="utf-8")
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


def _checked_plan(document: object) -> SimpleNamespace:
    if not isinstance(document, dict):
        raise ValueError("The reviewed automation plan is not valid.")
    slice_value = document.get("slice")
    timers = document.get("timers")
    services = document.get("services")
    resume = document.get("resume")
    budget = document.get("budget_seconds")
    if (
        not isinstance(slice_value, str)
        or not isinstance(timers, list)
        or not isinstance(services, list)
        or not isinstance(resume, list)
        or type(budget) is not int
        or not 1 <= budget <= 300
        or not all(isinstance(name, str) for name in (*timers, *services, *resume))
    ):
        raise ValueError("The reviewed automation plan is not valid.")
    return SimpleNamespace(
        slice=_checked_unit(slice_value),
        timers=[_checked_unit(name) for name in timers if isinstance(name, str)],
        services=[_checked_unit(name) for name in services if isinstance(name, str)],
        resume=[_checked_unit(name) for name in resume if isinstance(name, str)],
        budget_seconds=budget,
    )


def fence(document: object) -> bool:
    """Stop a site's background work and prove its slice has no processes.

    Call it after the kind's site lock and before its own mutation. A mask keeps the work
    from starting again, including from a boot, until :func:`restore` clears it.
    """
    plan = _checked_plan(document)
    for name in [*plan.timers, *plan.services]:
        if load_state(name) != "not-found":
            systemctl("mask", "--runtime", name)
    for name in plan.timers:
        if load_state(name) != "not-found":
            systemctl("stop", name)
    for name in plan.services:
        if load_state(name) != "not-found":
            systemctl("stop", name)
    if load_state(plan.slice) != "not-found":
        systemctl("stop", plan.slice)
    return wait_slice_empty(plan.slice, plan.budget_seconds)


def restore(document: object) -> bool:
    """Clear the fence and start exactly the reviewed resume set."""
    plan = _checked_plan(document)
    for name in [*plan.timers, *plan.services]:
        if load_state(name) == "masked":
            systemctl("unmask", "--runtime", name)
    for name in plan.resume:
        systemctl("enable", name)
        systemctl("start", name)
    return True


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
    "load_state",
    "properties",
    "publish",
    "publish_units",
    "remove",
    "remove_units",
    "restore",
    "slice_empty",
    "start_and_wait",
    "systemctl",
    "timer_ready",
    "unit_digests",
    "unit_file_state",
    "wait_for_tick",
    "wait_slice_empty",
]
