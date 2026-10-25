"""The one pure projection of a site's background work (docs/automation.md#status).

Every screen and later the Jobs view read this interpretation of native evidence; templates
never decide a state. Nothing here reads the server, remembers history or treats an absent
observation as success.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

MINUTE_MICROSECONDS: Final = 60_000_000
FAILED_RESULTS: Final = frozenset({"exit-code", "signal", "core-dump", "watchdog", "oom-kill"})
TIMEOUT_RESULTS: Final = frozenset({"timeout"})


class ScheduleStatus(StrEnum):
    OFF = "off"
    WAITING = "waiting"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"
    PAUSED = "paused"
    OFF_MAINTENANCE = "off_maintenance"
    NO_CRON = "no_cron"
    UNCONFIRMED = "unconfirmed"


# The plain sentences a page shows; no native term appears here (docs/dashboard-workflows.md).
STATUS_SENTENCE: Final[dict[ScheduleStatus, str]] = {
    ScheduleStatus.OFF: "Off",
    ScheduleStatus.WAITING: "On, waiting for its first run",
    ScheduleStatus.RUNNING: "A run is in progress",
    ScheduleStatus.SUCCEEDED: "On, the last run succeeded",
    ScheduleStatus.FAILED: "On, the last run failed",
    ScheduleStatus.TIMED_OUT: "On, the last run timed out",
    ScheduleStatus.SKIPPED: "On, a run took too long so the next one was skipped",
    ScheduleStatus.PAUSED: "Paused by an unfinished change",
    ScheduleStatus.OFF_MAINTENANCE: "Background work is off while the site is in maintenance",
    ScheduleStatus.NO_CRON: "No cron is running",
    ScheduleStatus.UNCONFIRMED: "Could not confirm",
}

# Paused and Off during maintenance are not failures, but they always need one safe next
# action, so the Overview's attention banner carries them (docs/automation.md#status).
ATTENTION_STATUSES: Final = frozenset(
    {
        ScheduleStatus.FAILED,
        ScheduleStatus.TIMED_OUT,
        ScheduleStatus.SKIPPED,
        ScheduleStatus.PAUSED,
        ScheduleStatus.OFF_MAINTENANCE,
        ScheduleStatus.NO_CRON,
        ScheduleStatus.UNCONFIRMED,
    }
)


@dataclass(frozen=True)
class ScheduleEvidence:
    """What discovery reads about one role of one site.

    ``readable`` False means the native read could not answer at all, so every other field
    is unknown rather than empty and the projection must not guess.
    """

    identifier: str
    role: str = "wpcron"
    readable: bool = True
    installed: bool = False
    problems: tuple[str, ...] = ()
    timer_present: bool = False
    timer_active: bool = False
    timer_enabled: bool = False
    service_active: bool = False
    masked: bool = False
    result: str = ""
    exec_status: int = 0
    last_start_us: int = 0
    last_exit_us: int = 0
    last_trigger_us: int = 0
    next_elapse_us: int = 0
    # The site's automation slice still has processes.
    slice_populated: bool = False
    # The WordPress private configuration's DISABLE_WP_CRON value: "true", "false" or "".
    disable_wp_cron: str = ""
    # A second scheduler already running this site's cron, in plain words.
    duplicate: str = ""
    # The site's maintenance page is in place.
    gate: bool = False

    @property
    def problem(self) -> str:
        if self.problems:
            return self.problems[0]
        return self.duplicate


def spanned_a_calendar_elapse(evidence: ScheduleEvidence) -> bool:
    """Whether the last run's start and end cross a wall-clock minute boundary.

    A tick that elapsed while the service was active did not run; systemd does not start a
    second instance of an active unit. The comparison is timestamp arithmetic, never
    controller history.
    """
    return (
        evidence.last_start_us > 0
        and evidence.last_exit_us >= evidence.last_start_us
        and evidence.last_exit_us // MINUTE_MICROSECONDS
        > evidence.last_start_us // MINUTE_MICROSECONDS
    )


def project(evidence: ScheduleEvidence) -> ScheduleStatus:  # noqa: C901 - the one projection
    """The single interpretation of a schedule's native state."""
    if not evidence.readable:
        return ScheduleStatus.UNCONFIRMED
    if evidence.masked:
        return ScheduleStatus.PAUSED
    if evidence.gate and evidence.installed and not evidence.timer_enabled:
        return ScheduleStatus.OFF_MAINTENANCE
    if evidence.service_active:
        return ScheduleStatus.RUNNING
    if evidence.result in TIMEOUT_RESULTS:
        return ScheduleStatus.TIMED_OUT
    if evidence.result in FAILED_RESULTS:
        return ScheduleStatus.FAILED
    if evidence.last_exit_us > 0 and spanned_a_calendar_elapse(evidence):
        return ScheduleStatus.SKIPPED
    if evidence.result == "success" and evidence.last_exit_us > 0:
        return ScheduleStatus.SUCCEEDED
    if evidence.timer_active and evidence.timer_enabled:
        return ScheduleStatus.WAITING
    if evidence.disable_wp_cron == "true" and not evidence.timer_present:
        return ScheduleStatus.NO_CRON
    return ScheduleStatus.OFF


def attention_problem(evidence: ScheduleEvidence, status: ScheduleStatus) -> str:
    """The one sentence an attention row shows, or an empty string when nothing is wrong.

    A deliberate Off is not an alarm. A paused or maintenance stop is: it is native evidence
    that background work is not running, and the operator needs one safe next action
    (docs/automation.md#status).
    """
    if status == ScheduleStatus.PAUSED:
        return (
            f"Background work for {evidence.identifier} is paused by an unfinished change, "
            "so its scheduled tasks are not running."
        )
    if status == ScheduleStatus.OFF_MAINTENANCE:
        return f"Background work for {evidence.identifier} is off while the site is in maintenance."
    if status in (ScheduleStatus.FAILED, ScheduleStatus.TIMED_OUT):
        return f"Scheduled tasks for {evidence.identifier} {STATUS_SENTENCE[status].lower()}."
    if status == ScheduleStatus.SKIPPED:
        return (
            f"Scheduled tasks for {evidence.identifier} skipped a run because the previous "
            "run took longer than a minute."
        )
    if status == ScheduleStatus.NO_CRON:
        return (
            f"Page loads no longer run cron for {evidence.identifier}, and no server cron "
            "is running."
        )
    if status == ScheduleStatus.UNCONFIRMED:
        return f"Barectl could not confirm the scheduled tasks for {evidence.identifier}."
    if evidence.duplicate and not evidence.timer_present:
        return evidence.duplicate
    return ""
