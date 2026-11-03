"""A stored Jobs observation for the Django and browser tests (Phase E #285)."""

import json
from dataclasses import replace
from datetime import datetime
from typing import Final

from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from discovery import ssh
from discovery.fakes import COLLECTED, HOST_KEY, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome
from discovery.recorded import Recorded, ReplayShell, Transcript
from discovery.snapshot import Observation, save_snapshot
from operations import native
from servers.models import Server

from . import observation
from .models import Coverage
from .observation import JobReading, ObservedChange, ProviderCoverage


def change(
    *,
    unit: str,
    invocation: str = "a" * 32,
    kind_slug: str = "create_http_site",
    sites: tuple[str, ...] = ("alpha",),
    result_class: str = "succeeded",
    reason: str = "",
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    running: bool = False,
) -> ObservedChange:
    return ObservedChange(
        unit=unit,
        invocation_id=invocation,
        kind_slug=kind_slug,
        sites=sites,
        result_class=result_class,
        reason=reason,
        started_at=started_at,
        finished_at=finished_at,
        running=running,
        active_state="active" if running else "inactive",
        sub_state="running" if running else "dead",
    )


def evidence(
    *,
    state: str = Coverage.COMPLETE,
    warning: str = "",
    oldest_at: datetime | None = None,
) -> tuple[ProviderCoverage, ...]:
    return (ProviderCoverage("barectl_changes", state, warning, oldest_at),)


def record_jobs(
    server: Server,
    *,
    changes: tuple[ObservedChange, ...] = (),
    coverage: tuple[ProviderCoverage, ...] | None = None,
    collected_at: datetime | None = None,
) -> None:
    """A target-stack snapshot whose Jobs observation is ``changes``."""
    record_reading(
        server,
        JobReading(changes, coverage if coverage is not None else evidence()),
        collected_at=collected_at,
    )


def record_reading(
    server: Server, reading: JobReading, *, collected_at: datetime | None = None
) -> None:
    collected = replace(
        COLLECTED,
        components=(),
        standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
        jobs=Observation(ObservationOutcome.OBSERVED, ("journalctl",), "", reading),
    )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    from sites.ui_testing import attach_current_connection

    attach_current_connection(server, attempt)
    save_snapshot(attempt, collected, collected_at or timezone.now())


BOOT: Final = "0f7a3c1e-6f4a-4a09-9f9f-3a0a9a9a9a9a"
UNIT: Final = "barectl-apply-" + "a" * 32 + ".service"
OTHER_UNIT: Final = "barectl-apply-" + "b" * 32 + ".service"
INVOCATION: Final = "1" * 32
OTHER_INVOCATION: Final = "2" * 32
SECRET: Final = "seeded-secret-value"  # noqa: S105 - a canary, not a credential


def retained(
    unit: str,
    invocation: str,
    *,
    active: str = "active",
    sub: str = "running",
    result: str = "success",
    populated: int = 1,
) -> str:
    return "\n".join(
        (
            BOOT,
            f"Id={unit}",
            "LoadState=loaded",
            f"ActiveState={active}",
            f"SubState={sub}",
            f"Result={result}",
            "ExecMainCode=1",
            "ExecMainStatus=0",
            f"InvocationID={invocation}",
            f"populated {populated}",
        )
    )


def line(
    message: str,
    *,
    unit: str = UNIT,
    invocation: str = INVOCATION,
    usec: int | None = 1_762_000_000_000_000,
) -> str:
    value = {
        "MESSAGE": message,
        "_SYSTEMD_UNIT": unit,
        "_SYSTEMD_INVOCATION_ID": invocation,
    }
    if usec is not None:
        value["__REALTIME_TIMESTAMP"] = str(usec)
    return json.dumps(value)


def result_line(
    *,
    result_class: str = "succeeded",
    reason: str = "",
    kind: str = "",
    sites: tuple[str, ...] = (),
) -> str:
    document: dict[str, object] = {"class": result_class, "reason": reason}
    if kind:
        document["change_kind"] = kind
    if sites:
        document["sites"] = list(sites)
    return "barectl-result " + json.dumps(document, separators=(",", ":"))


def journal_shell(
    *,
    units: str,
    history: str,
    oldest: str = "",
    root: str = "0",
    authorized: bool = True,
) -> ReplayShell:
    commands: list[tuple[str, Recorded]] = [
        (native.RETAINED_STATES, Recorded(ssh.CommandResult(0, units))),
        ("id -u", Recorded(ssh.CommandResult(0, f"{root}\n"))),
        (observation.HISTORY_COMMAND, Recorded(ssh.CommandResult(0, history))),
        (observation.OLDEST_COMMAND, Recorded(ssh.CommandResult(0, oldest))),
    ]
    if root != "0":
        argv = ["/usr/bin/sh", "-c", observation.HISTORY_COMMAND]
        commands.append(
            (
                native.authorization(argv),
                Recorded(ssh.CommandResult(0 if authorized else 1, "")),
            )
        )
        if authorized:
            commands.append(
                (native.privileged(argv, root=False), Recorded(ssh.CommandResult(0, history)))
            )
        argv = ["/usr/bin/sh", "-c", observation.OLDEST_COMMAND]
        commands.append(
            (
                native.authorization(argv),
                Recorded(ssh.CommandResult(0 if authorized else 1, "")),
            )
        )
        if authorized:
            commands.append(
                (native.privileged(argv, root=False), Recorded(ssh.CommandResult(0, oldest)))
            )
    return ReplayShell(Transcript("jobs-test", {}, "26.04", "x86_64", HOST_KEY, tuple(commands)))
