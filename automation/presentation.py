"""Plain scheduled-task wording for the Overview, Settings and attention banner.

Every sentence comes from the stored projection in :mod:`automation.status`; templates and
views decide nothing and no native term appears on the default path.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from discovery.snapshot import CollectedSnapshot

from .observation import ObservedSchedule
from .status import ATTENTION_STATUSES, STATUS_SENTENCE, ScheduleStatus, attention_problem

LABEL: Final = "Scheduled tasks"
ROLE_WPCRON: Final = "wpcron"


@dataclass(frozen=True)
class ScheduleView:
    """One plain line about a site's scheduled work."""

    identifier: str
    label: str
    state: str
    last_run: str
    checked_at: datetime | None
    detail: str
    attention: bool
    on: bool
    running: bool = False


def schedule_view(
    identifier: str,
    row: ObservedSchedule | None,
    checked_at: datetime | None,
) -> ScheduleView:
    """The one line for a site, including the honest "could not confirm" state."""
    if row is None:
        return ScheduleView(
            identifier,
            LABEL,
            STATUS_SENTENCE[ScheduleStatus.UNCONFIRMED],
            "",
            checked_at,
            "",
            False,
            False,
        )
    return ScheduleView(
        identifier=identifier,
        label=LABEL,
        state=STATUS_SENTENCE[row.status],
        last_run=_last_run(row),
        checked_at=checked_at,
        detail=attention_problem(row.evidence, row.status) or row.problem,
        attention=row.status in ATTENTION_STATUSES or bool(row.duplicate and not row.timer_present),
        on=row.status
        in {
            ScheduleStatus.WAITING,
            ScheduleStatus.RUNNING,
            ScheduleStatus.SUCCEEDED,
            ScheduleStatus.FAILED,
            ScheduleStatus.TIMED_OUT,
            ScheduleStatus.SKIPPED,
        },
        running=row.service_active,
    )


def _last_run(row: ObservedSchedule) -> str:
    if row.service_active:
        return "a run is in progress"
    moment = _moment(row.last_exit_us)
    if not moment:
        return ""
    if row.status == ScheduleStatus.TIMED_OUT:
        return f"the last run timed out at {moment}"
    if row.status == ScheduleStatus.FAILED:
        return f"the last run failed at {moment}"
    if row.status == ScheduleStatus.SKIPPED:
        return f"the last run ended at {moment}, and the next one was skipped"
    if row.status == ScheduleStatus.SUCCEEDED:
        return f"the last run succeeded at {moment}"
    return ""


def _moment(microseconds: int) -> str:
    if not microseconds:
        return ""
    return datetime.fromtimestamp(microseconds / 1_000_000, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")


def lines(
    collected: CollectedSnapshot, identifier: str, checked_at: datetime | None
) -> tuple[ScheduleView, ...]:
    """Every scheduled role of one site, or one "could not confirm" line for WordPress."""
    found = tuple(
        schedule_view(identifier, row, checked_at)
        for row in collected.automation.value
        if row.identifier == identifier
    )
    return found or (schedule_view(identifier, None, checked_at),)


def findings(collected: CollectedSnapshot) -> tuple[tuple[str, str, str], ...]:
    """``(identifier, finding, action)`` for work that needs the operator.

    Deliberate Off, Paused and maintenance states are not alarms (docs/automation.md).
    """
    found: list[tuple[str, str, str]] = []
    for row in collected.automation.value:
        problem = attention_problem(row.evidence, row.status)
        if problem:
            found.append(
                (
                    row.identifier,
                    problem,
                    "Open scheduled tasks"
                    if row.status != ScheduleStatus.UNCONFIRMED
                    else "Check the site again",
                )
            )
    return tuple(found)
