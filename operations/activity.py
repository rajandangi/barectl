"""Activity: this controller's record of every check and change, newest first (#369).

A read over the existing rows for the Activity pages. It adds no model, migration or
service: discovery attempts come from ``servers.discovery_state`` and changes from the
operations models, each in a fixed number of queries however many rows there are.
"""

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from django.urls import reverse

from discovery.presentation import ShownObservation
from servers.discovery_state import AttemptView
from servers.discovery_state import Status as CheckStatus
from servers.models import Server

from . import engine
from .models import ChangePreparation, ChangeReview, ChangeRun, RemoteOperation, Result

Kind = Literal["check", "change"]

# The words each recorded state gets on the list. A preparation's own outcome names a
# review step, which Activity leaves to the confirm screen.
_PREPARATION_STATUS = {
    RemoteOperation.Status.QUEUED: "Preparing",
    RemoteOperation.Status.RUNNING: "Preparing",
    RemoteOperation.Status.RECONCILING: "Preparing",
    RemoteOperation.Status.FAILED: "Failed",
}
_RUN_STATUS = {
    RemoteOperation.Status.QUEUED: "Applying",
    RemoteOperation.Status.RUNNING: "Applying",
    RemoteOperation.Status.RECONCILING: "Checking the result",
    RemoteOperation.Status.SUCCEEDED: "Applied",
    RemoteOperation.Status.FAILED: "Failed",
}


@dataclass(frozen=True)
class ActivityRow:
    """One recorded check or change, worded for the Activity list."""

    kind: Kind
    # Stable identity, so a poll's token changes with the rows and their states.
    key: str
    server_id: int
    server_name: str
    title: str
    status: str
    happened_at: datetime
    # The confirm screen before the change is applied, the run once there is one.
    url: str
    site: str = ""
    failure: str = ""
    finished_at: datetime | None = None
    collected_at: datetime | None = None
    prepared_at: datetime | None = None
    warnings: tuple[ShownObservation, ...] = ()
    active: bool = False


@dataclass(frozen=True)
class Activity:
    """The rows a page lists, and whether it follows them."""

    rows: list[ActivityRow] = field(default_factory=list)

    @property
    def polling(self) -> bool:
        return any(row.active for row in self.rows)

    @property
    def token(self) -> str:
        """What a poll sends back, so an unchanged list announces nothing."""
        states = "|".join(f"{row.key}:{row.status}" for row in self.rows)
        return hashlib.sha256(states.encode()).hexdigest()[:16]


def check_rows(attempts: Iterable[AttemptView]) -> list[ActivityRow]:
    return [_check_row(attempt) for attempt in attempts]


def change_rows(server: Server | None = None) -> list[ActivityRow]:
    """The recorded changes of one server, or of every server, newest first."""
    preparations = ChangePreparation.objects.select_related(
        "server", "review", "review__run"
    ).order_by("-queued_at", "-pk")
    if server is not None:
        preparations = preparations.filter(server=server)
    return [_change_row(preparation) for preparation in preparations]


def newest_first(rows: Iterable[ActivityRow], *, site: str = "") -> list[ActivityRow]:
    """``rows`` narrowed to ``site`` when one is chosen, newest first."""
    return sorted(
        (row for row in rows if not site or row.site == site),
        key=lambda row: (row.happened_at, row.server_name, row.key),
        reverse=True,
    )


def _check_row(attempt: AttemptView) -> ActivityRow:
    return ActivityRow(
        kind="check",
        key=f"check-{attempt.operation_id}",
        server_id=attempt.server.pk,
        server_name=attempt.server.name,
        title="Check the connection",
        status=str(attempt.status),
        happened_at=attempt.queued_at,
        url=reverse("server_advanced", args=[attempt.server.pk]),
        failure=attempt.failure,
        finished_at=attempt.finished_at,
        collected_at=attempt.snapshot.collected_at if attempt.snapshot else None,
        warnings=tuple(attempt.warnings),
        active=attempt.status in (CheckStatus.QUEUED, CheckStatus.RUNNING),
    )


def _change_row(preparation: ChangePreparation) -> ActivityRow:
    review = _review(preparation)
    run = _run(review)
    server = preparation.server
    site = preparation.inputs.get("identifier")
    return ActivityRow(
        kind="change",
        key=f"change-{preparation.pk}",
        server_id=preparation.server_id or 0,
        server_name=server.name if server is not None else preparation.ssh_alias,
        title=_title(preparation),
        status=_status(preparation, review, run),
        happened_at=run.queued_at if run is not None else preparation.queued_at,
        url=reverse(
            "run_detail" if run is not None else "change_detail",
            args=[run.pk if run is not None else preparation.pk],
        ),
        site=site if isinstance(site, str) else "",
        failure=(run.failure if run is not None else preparation.failure),
        prepared_at=preparation.queued_at if run is not None else None,
        active=(preparation.status in RemoteOperation.ACTIVE)
        or (run is not None and run.status in RemoteOperation.ACTIVE),
    )


def _review(preparation: ChangePreparation) -> ChangeReview | None:
    try:
        return preparation.review
    except ChangeReview.DoesNotExist:
        return None


def _run(review: ChangeReview | None) -> ChangeRun | None:
    if review is None:
        return None
    try:
        return review.run
    except ChangeRun.DoesNotExist:
        return None


def _status(
    preparation: ChangePreparation, review: ChangeReview | None, run: ChangeRun | None
) -> str:
    if run is not None:
        if run.status == RemoteOperation.Status.FAILED and run.execution == Result.OUTCOME_UNKNOWN:
            return "Result unknown"
        return _RUN_STATUS[RemoteOperation.Status(run.status)]
    status = RemoteOperation.Status(preparation.status)
    if status != RemoteOperation.Status.SUCCEEDED:
        return _PREPARATION_STATUS[status]
    if review is None:
        return "Prepared"
    if not review.eligible:
        return "Refused"
    return "Nothing to change" if review.no_changes else "Prepared"


def _title(preparation: ChangePreparation) -> str:
    """The change in plain words when the presentation layer has them (#364).

    A kind the confirm and run screens have no words for yet shows its own label.
    """
    from . import presentation

    plain_change = getattr(presentation, "plain_change", None)
    kind = engine.kind_of(preparation.kind_slug)
    label = kind.label if kind is not None else preparation.kind_slug
    if plain_change is None:
        return label
    server_name = (
        preparation.server.name if preparation.server is not None else preparation.ssh_alias
    )
    words = plain_change(preparation.kind_slug, label, preparation, server_name)
    return str(getattr(words, "title", label))
