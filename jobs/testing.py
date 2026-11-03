"""A stored Jobs observation for the Django and browser tests (Phase E #285)."""

import json
from dataclasses import replace
from datetime import datetime
from typing import Final

from django.utils import timezone

from automation.observation import ObservedSchedule
from automation.status import ScheduleStatus
from automation.worker_observation import ObservedWorker
from automation.worker_status import WorkerStatus
from automation.workers import WorkerDefinition
from backups.observation import BackupRun, BackupTimer, ObservedBackup, OffsiteStorage
from bootstrap.standing import HostJudgment, Standing
from discovery import ssh
from discovery.fakes import COLLECTED, HOST_KEY, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome
from discovery.recorded import Recorded, ReplayShell, Transcript
from discovery.snapshot import Observation, ObservedCache, save_snapshot
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
    schedules: tuple[ObservedSchedule, ...] = (),
    workers: tuple[ObservedWorker, ...] = (),
    cache: tuple[ObservedCache, ...] = (),
    automation_warning: str = "",
    workers_warning: str = "",
    cache_warning: str = "",
    backups: tuple[ObservedBackup, ...] = (),
    backups_warning: str = "",
) -> None:
    """A target-stack snapshot whose Jobs observation is ``changes``."""
    record_reading(
        server,
        JobReading(changes, coverage if coverage is not None else evidence()),
        collected_at=collected_at,
        schedules=schedules,
        workers=workers,
        cache=cache,
        automation_warning=automation_warning,
        workers_warning=workers_warning,
        cache_warning=cache_warning,
        backups=backups,
        backups_warning=backups_warning,
    )


def record_reading(
    server: Server,
    reading: JobReading,
    *,
    collected_at: datetime | None = None,
    schedules: tuple[ObservedSchedule, ...] = (),
    workers: tuple[ObservedWorker, ...] = (),
    cache: tuple[ObservedCache, ...] = (),
    automation_warning: str = "",
    workers_warning: str = "",
    cache_warning: str = "",
    backups: tuple[ObservedBackup, ...] = (),
    backups_warning: str = "",
) -> None:
    source = ("/etc/systemd/system",)
    collected = replace(
        COLLECTED,
        components=(),
        standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
        automation=_observed(schedules, automation_warning, source),
        workers=_observed(workers, workers_warning, source),
        cache=_observed(cache, cache_warning, ("/etc/valkey", "/var/www")),
        jobs=Observation(ObservationOutcome.OBSERVED, ("journalctl",), "", reading),
        backups=_observed(
            backups, backups_warning, ("/var/lib/barectl-backups", "/etc/barectl/backups")
        ),
    )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    from sites.ui_testing import attach_current_connection

    attach_current_connection(server, attempt)
    save_snapshot(attempt, collected, collected_at or timezone.now())


def _observed[T](
    value: tuple[T, ...], warning: str, source: tuple[str, ...]
) -> Observation[tuple[T, ...]]:
    if warning:
        return Observation(ObservationOutcome.INACCESSIBLE, source, warning, ())
    return Observation(ObservationOutcome.OBSERVED, source, "", value)


def scheduled(
    *,
    identifier: str = "alpha",
    role: str = "wpcron",
    status: ScheduleStatus = ScheduleStatus.SUCCEEDED,
    next_elapse_us: int = 1_762_000_000_000_000,
) -> ObservedSchedule:
    return ObservedSchedule(
        identifier=identifier,
        role=role,
        status=status,
        next_elapse_us=next_elapse_us,
        installed=status != ScheduleStatus.OFF,
    )


def worker(
    *,
    identifier: str = "alpha",
    status: WorkerStatus = WorkerStatus.RUNNING,
    definition: WorkerDefinition | None = None,
) -> ObservedWorker:
    return ObservedWorker(
        identifier=identifier,
        status=status,
        definition=definition or WorkerDefinition(("default",), 2, 60),
        processes=2,
        active_processes=2 if status == WorkerStatus.RUNNING else 0,
        installed=True,
        enabled=status != WorkerStatus.OFF,
    )


def cache(
    *,
    identifier: str = "alpha",
    state: str = "on",
    problem: str = "",
) -> ObservedCache:
    return ObservedCache(
        identifier,
        state,
        64 if state != "off" else None,
        problem,
    )


def run(
    *,
    kind: str = "capture",
    result_class: str = "succeeded",
    reason: str = "",
    at: datetime | None = None,
    point: str = "0123456789abcdef",
    scope: str = "database",
    origin: str = "scheduled",
    snapshots: int = 1,
    size: int = 4096,
    offsite: str = "",
    location: str = "",
    checked: int = 0,
    subset: str = "",
    onsite: tuple[int, int, int, int] | None = None,
    offsite_counts: tuple[int, int, int, int] | None = None,
) -> BackupRun:
    from backups.observation import CleanupCounts

    def counts(values: tuple[int, int, int, int] | None) -> CleanupCounts | None:
        return CleanupCounts(*values) if values is not None else None

    return BackupRun(
        kind,
        result_class,
        reason,
        (at or timezone.now()).isoformat(),
        point,
        scope,
        origin,
        snapshots,
        size,
        offsite,
        location,
        checked,
        subset,
        counts(onsite),
        counts(offsite_counts),
    )


def timer(
    *,
    work: str = "backup",
    location: str = "",
    on: bool = True,
    next_elapse_us: int = 1_762_000_000_000_000,
    last_trigger_us: int = 0,
) -> BackupTimer:
    from backups.observation import BackupTimer

    return BackupTimer(work, location, on, next_elapse_us, last_trigger_us)


def backup(
    *,
    identifier: str = "alpha",
    enabled: bool = True,
    runs: tuple[BackupRun, ...] = (),
    timers: tuple[BackupTimer, ...] = (),
    offsite: OffsiteStorage | None = None,
    runs_truncated: bool = False,
    timers_truncated: bool = False,
) -> ObservedBackup:
    return ObservedBackup(
        identifier,
        "/nix/store/rac858616ds2w2z3db69kp80vr9s8mkp-restic-0.18.1" if enabled else "",
        enabled,
        enabled,
        (),
        True,
        "",
        None,
        offsite,
        None,
        (),
        runs,
        timers,
        runs_truncated,
        timers_truncated,
    )


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
        (native.RUNNING_STATES, Recorded(ssh.CommandResult(0, units))),
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
