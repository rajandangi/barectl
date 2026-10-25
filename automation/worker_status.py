"""The one pure projection of a Laravel site's queue workers (Phase C #266).

Every screen and the Phase E Jobs view read this interpretation of native evidence. A
deliberate Stop is Off, not an alarm; only work systemd gave up on needs the operator.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from .status import FAILED_RESULTS

# systemd's result after Restart=always exhausts StartLimitBurst inside the interval.
START_LIMIT_RESULT: Final = "start-limit-hit"


class WorkerStatus(StrEnum):
    OFF = "off"
    RUNNING = "running"
    RESTARTING = "restarting"
    STOPPED_AFTER_CRASHES = "stopped_after_crashes"
    PAUSED = "paused"
    OFF_MAINTENANCE = "off_maintenance"
    UNCONFIRMED = "unconfirmed"


STATUS_SENTENCE: Final[dict[WorkerStatus, str]] = {
    WorkerStatus.OFF: "Off",
    WorkerStatus.RUNNING: "On, running",
    WorkerStatus.RESTARTING: "On, restarting after a crash",
    WorkerStatus.STOPPED_AFTER_CRASHES: "Stopped after repeated crashes",
    WorkerStatus.PAUSED: "Paused while a change finishes",
    WorkerStatus.OFF_MAINTENANCE: "Off while the site is in maintenance",
    WorkerStatus.UNCONFIRMED: "Could not confirm",
}

ATTENTION_STATUSES: Final = frozenset(
    {
        WorkerStatus.RESTARTING,
        WorkerStatus.STOPPED_AFTER_CRASHES,
        WorkerStatus.UNCONFIRMED,
    }
)


@dataclass(frozen=True)
class WorkerEvidence:
    """What discovery reads about one site's worker processes."""

    identifier: str
    readable: bool = True
    installed: bool = False
    enabled: bool = False
    masked: bool = False
    processes: int = 0
    active_processes: int = 0
    result: str = ""
    exec_status: int = 0
    start_limited: bool = False
    last_start_us: int = 0
    last_exit_us: int = 0
    nrestarts: int = 0
    slice_populated: bool = False
    duplicate: str = ""
    gate: bool = False
    problems: tuple[str, ...] = ()

    @property
    def problem(self) -> str:
        if self.problems:
            return self.problems[0]
        return self.duplicate


def project(evidence: WorkerEvidence) -> WorkerStatus:
    if not evidence.readable:
        return WorkerStatus.UNCONFIRMED
    if evidence.masked:
        return WorkerStatus.PAUSED
    if evidence.gate and evidence.installed and not evidence.enabled:
        return WorkerStatus.OFF_MAINTENANCE
    if evidence.start_limited or evidence.result == START_LIMIT_RESULT:
        return WorkerStatus.STOPPED_AFTER_CRASHES
    if evidence.active_processes > 0:
        return WorkerStatus.RUNNING
    if evidence.enabled and evidence.installed and evidence.result in FAILED_RESULTS:
        return WorkerStatus.RESTARTING
    return WorkerStatus.OFF


def attention_problem(evidence: WorkerEvidence, status: WorkerStatus) -> str:
    """The one sentence an attention row shows, or an empty string."""
    if status == WorkerStatus.STOPPED_AFTER_CRASHES:
        return f"Queue workers for {evidence.identifier} stopped after repeated crashes."
    if status == WorkerStatus.RESTARTING:
        return f"Queue workers for {evidence.identifier} restarted after a crash."
    if status == WorkerStatus.UNCONFIRMED:
        return f"Barectl could not confirm the queue workers for {evidence.identifier}."
    if evidence.duplicate and not evidence.installed:
        return evidence.duplicate
    return ""


__all__ = [
    "ATTENTION_STATUSES",
    "START_LIMIT_RESULT",
    "STATUS_SENTENCE",
    "WorkerEvidence",
    "WorkerStatus",
    "attention_problem",
    "project",
]
