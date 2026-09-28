"""What the pages show about plan preparations and their plans, in the pages' wording.

Templates receive ``PreparationView`` and never read stored states or decide themselves
whether a plan is eligible, expired or still being prepared.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, nonmember

from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from operations.models import RemoteOperation

from .models import (
    ConfigurationPlan,
    PackageTransition,
    PlanEffect,
    PlanEvidence,
    PlanPreparation,
    PlanRefusal,
    PlanRootPackage,
)

Status = RemoteOperation.Status


class Outcome(StrEnum):
    """A preparation's state in the pages' wording."""

    do_not_call_in_templates = nonmember(True)

    QUEUED = "Preparation queued"
    RUNNING = "Preparing plan"
    ELIGIBLE = "Ready for review"
    NO_CHANGES = "No changes needed"
    REFUSED = "Refused"
    FAILED = "Preparation failed"


_ANNOUNCEMENTS = {
    Outcome.QUEUED: "Plan preparation queued.",
    Outcome.RUNNING: "Preparing the plan.",
    Outcome.ELIGIBLE: "The plan is ready for review.",
    Outcome.NO_CHANGES: "The plan is ready: no changes are needed.",
    Outcome.REFUSED: "The plan was refused. The reasons are listed.",
    Outcome.FAILED: "Plan preparation failed.",
}


@dataclass(frozen=True)
class PlanReview:
    """A stored plan with everything its review shows."""

    plan: ConfigurationPlan
    roots: list[PlanRootPackage]
    transitions: list[PackageTransition]
    effects: list[PlanEffect]
    postconditions: list[str]
    refusals: list[PlanRefusal]
    evidence: list[PlanEvidence]

    @property
    def expired(self) -> bool:
        """Whether the controller's estimate of the admission deadline has passed.

        The server's monotonic clock decides admission; this estimate only tells the
        operator that a new preparation is needed.
        """
        return timezone.now() >= self.plan.admission_expires_at


@dataclass(frozen=True)
class PreparationView:
    """One plan preparation as the server page, the plan page and Activity show it."""

    operation_id: int
    server_id: int
    server_name: str
    action_label: str
    outcome: Outcome
    ssh_alias: str
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    failure: str
    review: PlanReview | None

    @property
    def active(self) -> bool:
        return self.outcome in {Outcome.QUEUED, Outcome.RUNNING}

    @property
    def failed(self) -> bool:
        return self.outcome == Outcome.FAILED

    @property
    def announcement(self) -> str:
        return _ANNOUNCEMENTS[self.outcome]

    @property
    def is_preparation(self) -> bool:
        """Activity lists preparations beside discovery attempts; this tells them apart."""
        return True


def view(preparation: PlanPreparation) -> PreparationView:
    review = _review(preparation)
    return PreparationView(
        operation_id=preparation.pk,
        server_id=preparation.server_id,
        server_name=preparation.server.name,
        action_label=preparation.get_action_display(),
        outcome=_outcome(preparation.status, review),
        ssh_alias=preparation.ssh_alias,
        queued_at=preparation.queued_at,
        started_at=preparation.started_at,
        finished_at=preparation.finished_at,
        failure=preparation.failure,
        review=review,
    )


def _review(preparation: PlanPreparation) -> PlanReview | None:
    try:
        plan = preparation.plan
    except ObjectDoesNotExist:
        return None
    return PlanReview(
        plan,
        list(plan.roots.all()),
        list(plan.transitions.all()),
        list(plan.effects.all()),
        [item.text for item in plan.postconditions.all()],
        list(plan.refusals.all()),
        list(plan.evidence.all()),
    )


def _outcome(status: str, review: PlanReview | None) -> Outcome:
    match Status(status):
        case Status.QUEUED:
            return Outcome.QUEUED
        case Status.RUNNING | Status.RECONCILING:
            return Outcome.RUNNING
        case Status.FAILED:
            return Outcome.FAILED
        case Status.SUCCEEDED:
            if review is None or not review.plan.eligible:
                return Outcome.REFUSED
            return Outcome.NO_CHANGES if review.plan.no_changes else Outcome.ELIGIBLE
