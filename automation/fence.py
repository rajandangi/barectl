"""The fence a site change declares, and its restore set (docs/adr/0036, Phase C #395).

A review reads the site's automation evidence from the discovery snapshot and records which
units to stop, which to start again and how long it may wait. The body-side helpers in
:mod:`automation.bodies.units` apply the plan after the kind's site lock and before its own
mutation; this module only plans. Nothing here is wired into another kind yet.
"""

from dataclasses import dataclass
from typing import Final

from discovery.snapshot import CollectedSnapshot

from . import convention, workers
from .status import ScheduleStatus
from .worker_status import WorkerStatus

# The longest a change waits for a fence to drain, in seconds (docs/adr/0036).
FENCE_BUDGET_SECONDS: Final = 30
# A run in any of these states was on, and resumes after the change verifies.
RESUMABLE: Final = frozenset(
    {
        ScheduleStatus.WAITING,
        ScheduleStatus.RUNNING,
        ScheduleStatus.SUCCEEDED,
        ScheduleStatus.FAILED,
        ScheduleStatus.TIMED_OUT,
        ScheduleStatus.SKIPPED,
        ScheduleStatus.PAUSED,
    }
)
RESUMABLE_WORKERS: Final = frozenset(
    {
        WorkerStatus.RUNNING,
        WorkerStatus.RESTARTING,
        WorkerStatus.PAUSED,
    }
)


@dataclass(frozen=True)
class FencePlan:
    """The units a change stops and the slice it proves empty."""

    identifier: str
    slice: str
    timers: tuple[str, ...]
    services: tuple[str, ...]
    budget_seconds: int = FENCE_BUDGET_SECONDS


@dataclass(frozen=True)
class RestorePlan:
    """The fence plus exactly the work the review declared to resume."""

    fence: FencePlan
    resume: tuple[str, ...]

    def document(self) -> dict[str, object]:
        """The reviewed, non-secret plan a body validates and applies."""
        return {
            "slice": self.fence.slice,
            "timers": list(self.fence.timers),
            "services": list(self.fence.services),
            "resume": list(self.resume),
            "budget_seconds": self.fence.budget_seconds,
        }


def review_fence_plan(  # noqa: C901 - schedules and workers together
    collected: CollectedSnapshot, identifier: str
) -> RestorePlan | None:
    """The resume set at review time, or ``None`` when the site's work cannot be read.

    A fresh controller never guesses: when the evidence is unavailable the caller refuses
    the change instead of fencing blind.
    """
    if collected.automation.outcome.value != "observed":
        return None
    schedules = tuple(row for row in collected.automation.value if row.identifier == identifier)
    worker_rows = tuple(row for row in collected.workers.value if row.identifier == identifier)
    if not schedules and not worker_rows:
        return None
    timers: list[str] = []
    services: list[str] = []
    resume: list[str] = []
    for worker in worker_rows:
        if not worker.installed:
            continue
        roles = (
            worker.definition.roles
            if worker.definition is not None
            else workers.WORKER_ROLES[: worker.processes]
        )
        for role in roles:
            service = convention.service_name(identifier, role)
            services.append(service)
            if worker.enabled and worker.status in RESUMABLE_WORKERS:
                resume.append(service)
    for schedule in schedules:
        if not schedule.installed:
            continue
        timer = convention.timer_name(identifier, schedule.role)
        service = convention.service_name(identifier, schedule.role)
        if schedule.timer_active or schedule.timer_enabled:
            timers.append(timer)
        if schedule.service_present:
            services.append(service)
        if schedule.status in RESUMABLE and schedule.timer_enabled:
            resume.append(timer)
        elif schedule.status in RESUMABLE and schedule.service_present:
            resume.append(service)
    return RestorePlan(
        FencePlan(identifier, convention.slice_name(identifier), tuple(timers), tuple(services)),
        tuple(resume),
    )
