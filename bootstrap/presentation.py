"""What the pages show about plan preparations, plans and apply runs, in the pages' wording.

Templates receive ``PreparationView`` and ``ApplyView`` and never read stored states or
decide themselves whether a plan is eligible, expired, invalidated or still being
prepared, or what an apply run's execution established.
"""

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum, nonmember

from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from operations.models import RemoteOperation

from .models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PackageTransition,
    PlanEffect,
    PlanEvidence,
    PlanNativeUnit,
    PlanPreparation,
    PlanRefusal,
    PlanRootPackage,
    Verification,
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
    # The finished bootstrap units a cleanup plan clears.
    units: list[PlanNativeUnit] = field(default_factory=list)
    # A later package metadata refresh may have changed the indexes this package plan
    # was reviewed against.
    invalidated: bool = False
    # The run that applied this revision, if one was requested.
    apply_run_id: int | None = None

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

    @property
    def is_apply(self) -> bool:
        return False


def view(preparation: PlanPreparation, refreshes: Iterable[datetime] = ()) -> PreparationView:
    """``preparation`` as the pages show it.

    ``refreshes`` are when the server's metadata refreshes that may have changed its
    package indexes were dispatched; a package plan collected before one is invalidated.
    """
    review = _review(preparation, refreshes)
    server = preparation.server
    return PreparationView(
        operation_id=preparation.pk,
        server_id=preparation.server_id or 0,
        server_name=server.name if server is not None else "",
        action_label=preparation.get_action_display(),
        outcome=_outcome(preparation.status, review),
        ssh_alias=preparation.ssh_alias,
        queued_at=preparation.queued_at,
        started_at=preparation.started_at,
        finished_at=preparation.finished_at,
        failure=preparation.failure,
        review=review,
    )


def _review(preparation: PlanPreparation, refreshes: Iterable[datetime]) -> PlanReview | None:
    try:
        plan = preparation.plan
    except ObjectDoesNotExist:
        return None
    try:
        apply_run_id: int | None = plan.apply_run.pk
    except ObjectDoesNotExist:
        apply_run_id = None
    return PlanReview(
        plan,
        list(plan.roots.all()),
        list(plan.transitions.all()),
        list(plan.effects.all()),
        [item.text for item in plan.postconditions.all()],
        list(plan.refusals.all()),
        list(plan.evidence.all()),
        list(plan.native_units.all()),
        invalidated=plan.action in {Action.NGINX, Action.PHP}
        and any(dispatched > plan.collected_at for dispatched in refreshes),
        apply_run_id=apply_run_id,
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


class ApplyOutcome(StrEnum):
    """An apply run's lifecycle state in the pages' wording."""

    do_not_call_in_templates = nonmember(True)

    QUEUED = "Apply queued"
    RUNNING = "Applying"
    RECONCILING = "Outcome being reconciled"
    SUCCEEDED = "Applied and verified"
    FAILED = "Apply failed"
    UNKNOWN = "Outcome unknown"


_APPLY_OUTCOMES = {
    Status.QUEUED: ApplyOutcome.QUEUED,
    Status.RUNNING: ApplyOutcome.RUNNING,
    Status.RECONCILING: ApplyOutcome.RECONCILING,
    Status.SUCCEEDED: ApplyOutcome.SUCCEEDED,
    Status.FAILED: ApplyOutcome.FAILED,
}
_APPLY_ANNOUNCEMENTS = {
    ApplyOutcome.QUEUED: "Apply queued.",
    ApplyOutcome.RUNNING: "Applying the plan.",
    ApplyOutcome.RECONCILING: "The apply outcome is uncertain and is being reconciled.",
    ApplyOutcome.SUCCEEDED: "The plan was applied and verified.",
    ApplyOutcome.FAILED: "The apply run failed. The reason is shown.",
    ApplyOutcome.UNKNOWN: "The run was closed with its outcome unknown.",
}


@dataclass(frozen=True)
class ApplyView:
    """One apply run as its page, the server page and Activity show it.

    Everything here comes from the run's own record, so it is shown the same way after
    the plan and the server's registration were removed.
    """

    operation_id: int
    # ``None`` once the server's registration was removed; the copied name remains.
    server_id: int | None
    server_name: str
    ssh_alias: str
    # ``None`` once the plan was deleted with the registration.
    plan_id: int | None
    plan_number: int
    action_label: str
    intent: str
    effects: list[str]
    requested_by: str
    outcome: ApplyOutcome
    execution: Execution
    verification: Verification
    unit_name: str
    invocation_id: str
    boot_id: str
    reviewed_host_key: str
    host_key: str
    queued_at: datetime
    dispatched_at: datetime | None
    acknowledged_at: datetime | None
    finished_at: datetime | None
    failure: str
    # The plan's action, which decides the permission applying and acknowledging need.
    action: str = ""
    # A check was asked for and has not finished yet.
    check_pending: bool = False
    # An acknowledgement that the outcome is unknown waits for its check.
    closure_pending: bool = False
    # Why the latest acknowledgement could not close the run.
    closure_blocked: str = ""
    unknown_acknowledged_by: str = ""
    unknown_acknowledged_at: datetime | None = None
    # When the server's current discovery snapshot was collected, if it has one.
    snapshot_collected_at: datetime | None = None
    snapshot_known: bool = field(default=False)
    # The reviewed package transitions or units to clear, copied when the run was queued.
    changes: list[str] = field(default_factory=list)

    @property
    def active(self) -> bool:
        return self.outcome in {
            ApplyOutcome.QUEUED,
            ApplyOutcome.RUNNING,
            ApplyOutcome.RECONCILING,
        }

    @property
    def reconciling(self) -> bool:
        return self.outcome == ApplyOutcome.RECONCILING

    @property
    def failed(self) -> bool:
        return self.outcome == ApplyOutcome.FAILED

    @property
    def unknown(self) -> bool:
        """Closed without native evidence of the run: it may have changed the server."""
        return self.outcome == ApplyOutcome.UNKNOWN

    @property
    def native_record_missing(self) -> bool:
        """Reconciling, and the latest check found no unit with the run's name."""
        return self.reconciling and self.execution == Execution.NOT_FOUND

    @property
    def polling(self) -> bool:
        """Whether the run's page follows it: the worker is on it or a check is pending."""
        return self.active and (not self.reconciling or self.check_pending)

    @property
    def token(self) -> str:
        """Which state the page shows, sent back by its polls."""
        return f"{self.outcome.name}.{self.execution}.{int(self.check_pending)}"

    @property
    def execution_label(self) -> str:
        return Execution(self.execution).label

    @property
    def verification_label(self) -> str:
        return Verification(self.verification).label

    @property
    def refused_before_changes(self) -> bool:
        return self.execution in Execution.refused_before_changes()

    @property
    def snapshot_freshness(self) -> str:
        """Whether discovery's current snapshot was collected after this run finished."""
        if not self.snapshot_known:
            return "The server's registration was removed; no snapshot is kept."
        if self.snapshot_collected_at is None:
            return "The server has no discovery snapshot."
        if self.finished_at is None or self.snapshot_collected_at < self.finished_at:
            return (
                "The current discovery snapshot was collected before this run finished, so it "
                "does not show its effects. Check the connection to collect a new one."
            )
        return "The current discovery snapshot was collected after this run finished."

    @property
    def announcement(self) -> str:
        return _APPLY_ANNOUNCEMENTS[self.outcome]

    @property
    def is_preparation(self) -> bool:
        return False

    @property
    def is_apply(self) -> bool:
        """Activity lists apply runs beside other operations; this tells them apart."""
        return True


def apply_view(run: ApplyRun, snapshot: datetime | None = None) -> ApplyView:
    """``run`` as the pages show it, with its server's current snapshot time if known."""
    return ApplyView(
        operation_id=run.pk,
        server_id=run.server_id,
        server_name=run.server_name,
        ssh_alias=run.ssh_alias,
        plan_id=run.plan_id,
        plan_number=run.plan_number,
        action_label=run.get_action_display(),
        intent=run.intent,
        effects=run.effects.splitlines(),
        requested_by=run.requested_by_name,
        outcome=_apply_outcome(run),
        execution=Execution(run.execution),
        verification=Verification(run.verification),
        unit_name=run.unit_name,
        invocation_id=run.invocation_id,
        boot_id=run.boot_id,
        reviewed_host_key=run.reviewed_host_key,
        host_key=run.host_key,
        queued_at=run.queued_at,
        dispatched_at=run.dispatched_at,
        acknowledged_at=run.acknowledged_at,
        finished_at=run.finished_at,
        failure=run.failure,
        action=run.action,
        check_pending=run.check_requested_at is not None,
        closure_pending=run.closure_requested_at is not None,
        closure_blocked=run.closure_blocked,
        unknown_acknowledged_by=run.unknown_acknowledged_by_name,
        unknown_acknowledged_at=run.unknown_acknowledged_at,
        snapshot_collected_at=snapshot,
        snapshot_known=run.server_id is not None,
        changes=run.reviewed_changes.splitlines(),
    )


def _apply_outcome(run: ApplyRun) -> ApplyOutcome:
    if run.status == Status.FAILED and run.execution == Execution.OUTCOME_UNKNOWN:
        return ApplyOutcome.UNKNOWN
    return _APPLY_OUTCOMES[Status(run.status)]
