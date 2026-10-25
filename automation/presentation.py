"""Plain scheduled-task wording for the Overview, Settings and attention banner.

Every sentence comes from the stored projection in :mod:`automation.status`; templates and
views decide nothing and no native term appears on the default path.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

from discovery.snapshot import CollectedSnapshot

from .observation import ObservedSchedule
from .status import ATTENTION_STATUSES, STATUS_SENTENCE, ScheduleStatus, attention_problem

if TYPE_CHECKING:
    from servers.models import Server

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


def schedule_view(
    identifier: str,
    row: ObservedSchedule | None,
    checked_at: datetime | None,
    paused_by: str = "",
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
    detail = attention_problem(row.evidence, row.status) or row.problem
    if row.status == ScheduleStatus.PAUSED and paused_by:
        detail = f"{detail} {paused_by}"
    return ScheduleView(
        identifier=identifier,
        label=LABEL,
        state=STATUS_SENTENCE[row.status],
        last_run=_last_run(row),
        checked_at=checked_at,
        detail=detail,
        attention=row.status in ATTENTION_STATUSES or bool(row.duplicate and not row.timer_present),
        on=row.status
        in {
            ScheduleStatus.WAITING,
            ScheduleStatus.RUNNING,
            ScheduleStatus.SUCCEEDED,
            ScheduleStatus.SKIPPED,
        },
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
    collected: CollectedSnapshot,
    identifier: str,
    checked_at: datetime | None,
    paused_by: str = "",
) -> tuple[ScheduleView, ...]:
    """Every scheduled role of one site, or one "could not confirm" line for WordPress."""
    found = tuple(
        schedule_view(identifier, row, checked_at, paused_by)
        for row in collected.automation.value
        if row.identifier == identifier
    )
    return found or (schedule_view(identifier, None, checked_at),)


def paused_change(server: Server | int, identifier: str) -> str:
    """The newest change to this site that did not finish, from this device's own history.

    A fresh controller keeps no history of another one and shows only native evidence, so
    this names nothing rather than guessing what was on (docs/adr/0036).
    """
    from operations.engine import kind_of
    from operations.models import ChangeRun, Result, Verification

    rows = (
        ChangeRun.objects.filter(server=server)
        .select_related("review")
        .order_by("-queued_at", "-pk")[:20]
    )
    for run in rows:
        review = run.review
        if identifier not in review.affected_sites:
            continue
        if run.execution == Result.SUCCEEDED and run.verification == Verification.PASSED:
            return ""
        change = kind_of(review.kind_slug)
        label = change.label if change is not None else "A change"
        started = run.started_at
        moment = started.strftime("%Y-%m-%d %H:%M UTC") if started else ""
        return (
            f"The last change to this site, {label.lower()}"
            + (f" started {moment}" if moment else "")
            + ", has not finished."
        )
    return ""


@dataclass(frozen=True)
class FenceSummary:
    """What one review pauses and starts again, in the operator's words (#395)."""

    pauses: tuple[str, ...]
    resumes: tuple[str, ...]

    @property
    def pauses_nothing(self) -> bool:
        return not self.pauses

    @property
    def starts_nothing(self) -> bool:
        return not self.resumes


def fence_summary(document: dict[str, object]) -> FenceSummary | None:
    """The review's fence in plain words, or ``None`` for a change that never fences.

    A server-wide change names no site, so its plan has no sites and the review says that
    plainly. No native term appears on this path (docs/dashboard-workflows.md).
    """
    plan = document.get("automation_fence")
    if plan is None:
        return None
    entries = plan.get("sites") if isinstance(plan, dict) else None
    if not isinstance(entries, list):
        return FenceSummary((), ())
    pauses: list[str] = []
    resumes: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("identifier"), str):
            continue
        identifier = str(entry["identifier"])
        for name in _strings(entry.get("timers")) + _strings(entry.get("services")):
            label = f"{identifier}'s {_work(name, identifier)}"
            if label not in pauses:
                pauses.append(label)
        for name in _strings(entry.get("resume")):
            label = f"{identifier}'s {_work(name, identifier)}"
            if label not in resumes:
                resumes.append(label)
    return FenceSummary(tuple(pauses), tuple(resumes))


def _strings(value: object) -> list[str]:
    return [str(item) for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _work(unit: str, identifier: str) -> str:
    """One unit's plain name: the work it does, never its kind or its timer."""
    role = unit.removeprefix(f"barectl-site-{identifier}-").partition(".")[0]
    return "queue workers" if role.startswith("queue") else "scheduled tasks"


def findings(collected: CollectedSnapshot) -> tuple[tuple[str, str, str], ...]:
    """``(identifier, finding, action)`` for work that needs the operator.

    A deliberate Off is not an alarm; a paused or maintenance stop is, because background
    work is not running and the operator needs one safe next action.
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
