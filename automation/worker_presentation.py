"""Plain queue-worker wording for the Overview, Settings and attention banner.

Every sentence comes from the stored projection in :mod:`automation.worker_status`;
templates and views decide nothing and no native term appears on the default path.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Final

from discovery.snapshot import CollectedSnapshot

from .worker_observation import ObservedWorker
from .worker_status import (
    ATTENTION_STATUSES,
    STATUS_SENTENCE,
    WorkerStatus,
    attention_problem,
)

LABEL: Final = "Queue workers"


@dataclass(frozen=True)
class WorkerView:
    """One plain line about a site's queue workers."""

    identifier: str
    label: str
    state: str
    detail: str
    checked_at: datetime | None
    attention: bool
    on: bool
    queues: str
    processes: int
    timeout: int


def worker_view(
    identifier: str,
    row: ObservedWorker | None,
    checked_at: datetime | None,
) -> WorkerView:
    if row is None:
        return WorkerView(
            identifier,
            LABEL,
            STATUS_SENTENCE[WorkerStatus.UNCONFIRMED],
            "",
            checked_at,
            False,
            False,
            "",
            0,
            0,
        )
    return WorkerView(
        identifier=identifier,
        label=LABEL,
        state=STATUS_SENTENCE[row.status],
        detail=attention_problem(row.evidence, row.status) or row.problem,
        checked_at=checked_at,
        attention=row.status in ATTENTION_STATUSES or bool(row.duplicate and not row.installed),
        on=row.status in {WorkerStatus.RUNNING, WorkerStatus.RESTARTING},
        queues=", ".join(row.queues),
        processes=row.processes,
        timeout=row.timeout,
    )


def lines(
    collected: CollectedSnapshot, identifier: str, checked_at: datetime | None
) -> tuple[WorkerView, ...]:
    found = tuple(
        worker_view(identifier, row, checked_at)
        for row in collected.workers.value
        if row.identifier == identifier
    )
    return found or (worker_view(identifier, None, checked_at),)


def row_for(collected: CollectedSnapshot, identifier: str) -> ObservedWorker | None:
    return next(
        (row for row in collected.workers.value if row.identifier == identifier),
        None,
    )


def findings(collected: CollectedSnapshot) -> tuple[tuple[str, str, str], ...]:
    """``(identifier, finding, action)`` for worker work that needs the operator."""
    found: list[tuple[str, str, str]] = []
    for row in collected.workers.value:
        problem = attention_problem(row.evidence, row.status)
        if problem:
            found.append(
                (
                    row.identifier,
                    problem,
                    "Start the queue workers"
                    if row.status == WorkerStatus.STOPPED_AFTER_CRASHES
                    else "Open queue workers",
                )
            )
    return tuple(found)
