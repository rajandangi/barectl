"""Templates receive view dataclasses and never read stored states or decide themselves
whether a review is eligible or expired, what a run's result established, or what consent
applying needs."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum, nonmember
from typing import TYPE_CHECKING

from django.core.exceptions import ObjectDoesNotExist
from django.urls import reverse
from django.utils import timezone

from . import engine
from .consent import Scope, permissions_for
from .models import ChangeReview, ChangeRun, Consent, RemoteOperation, Result, Verification

if TYPE_CHECKING:
    from .services import ChangeRow

Status = RemoteOperation.Status


class PreparationOutcome(StrEnum):
    do_not_call_in_templates = nonmember(True)

    QUEUED = "Preparation queued"
    RUNNING = "Reviewing the change"
    ELIGIBLE = "Ready for review"
    NO_CHANGES = "No changes needed"
    REFUSED = "Refused"
    FAILED = "Preparation failed"


class RunOutcome(StrEnum):
    do_not_call_in_templates = nonmember(True)

    QUEUED = "Apply queued"
    RUNNING = "Applying"
    RECONCILING = "Outcome being reconciled"
    SUCCEEDED = "Applied and verified"
    FAILED = "Apply failed"
    UNKNOWN = "Outcome unknown"


_SCOPE_LABELS = {
    Scope.SITE: "One site",
    Scope.SHARED: "Shared",
    Scope.SERVER: "Whole server",
}


@dataclass(frozen=True)
class ReviewView:
    """The review's typed core and the kind's document, worded for templates."""

    review: ChangeReview
    consent_label: str
    permissions: tuple[str, ...]
    affected_sites: list[str]
    # (scope label, text) per declared effect.
    effects: list[tuple[str, str]]
    stages: list[str]
    postconditions: list[str]
    refusals: list[str]
    details: list[tuple[str, str]] = field(default_factory=list)
    targets: list[dict[str, object]] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)
    note: str = ""
    run_id: int | None = None
    expired: bool = False
    connection_changed: bool = False
    # The connection the review was made over, as its server's pages name it.
    connection: str = ""
    # The acknowledgement the kind requires before apply, or an empty string.
    acknowledgement: str = ""
    # The change writes a secret through the confidential input channel.
    writes_secrets: bool = False

    @property
    def eligible(self) -> bool:
        return self.review.eligible

    @property
    def no_changes(self) -> bool:
        return self.review.no_changes

    @property
    def shared(self) -> bool:
        return self.review.consent == Consent.SHARED

    @property
    def requires_acknowledgement(self) -> bool:
        return bool(self.acknowledgement)


@dataclass(frozen=True)
class ChangeView:
    operation_id: int
    server_id: int
    server_name: str
    kind_label: str
    outcome: PreparationOutcome
    queued_at: datetime
    failure: str
    review: ReviewView | None = None
    kind_slug: str = ""

    @property
    def active(self) -> bool:
        return self.outcome in {PreparationOutcome.QUEUED, PreparationOutcome.RUNNING}


def review_view(review: ChangeReview) -> ReviewView:
    from operations.lifecycle import connection_current
    from servers.connections import connection_label

    document = review.document
    raw_details = document.get("details", [])
    details = (
        [
            (item["label"], item["value"])
            for item in raw_details
            if isinstance(item, dict)
            and isinstance(item.get("label"), str)
            and isinstance(item.get("value"), str)
        ]
        if isinstance(raw_details, list)
        else []
    )
    stages = [str(stage) for stage in document.get("stages", [])]
    targets = [dict(target) for target in document.get("targets", [])]
    kept = [str(item) for item in document.get("kept", [])]
    try:
        run_id: int | None = review.run.pk
    except ObjectDoesNotExist:
        run_id = None
    return ReviewView(
        review=review,
        consent_label=Consent(review.consent).label,
        permissions=permissions_for(Consent(review.consent), writes_secrets=review.writes_secrets),
        affected_sites=[str(site) for site in review.affected_sites],
        effects=[
            (_SCOPE_LABELS[Scope(effect["scope"])], str(effect["text"]))
            for effect in review.effects
        ],
        stages=stages,
        postconditions=[str(item) for item in document.get("postconditions", [])],
        refusals=[str(item) for item in document.get("refusals", [])],
        details=details,
        targets=targets,
        kept=kept,
        note=str(document.get("note", "")),
        run_id=run_id,
        expired=timezone.now() >= review.admission_expires_at,
        connection_changed=review.preparation is None or not connection_current(review.preparation),
        connection=(
            connection_label(review.preparation)
            if review.preparation is not None
            else review.ssh_alias
        ),
        acknowledgement=review.acknowledgement,
        writes_secrets=review.writes_secrets,
    )


def change_view(row: ChangeRow) -> ChangeView:
    preparation = row.preparation
    review = review_view(row.review) if row.review is not None else None
    outcome = PreparationOutcome.FAILED
    if preparation.status == Status.QUEUED:
        outcome = PreparationOutcome.QUEUED
    elif preparation.status in {Status.RUNNING, Status.RECONCILING}:
        outcome = PreparationOutcome.RUNNING
    elif preparation.status == Status.SUCCEEDED and review is not None:
        if not review.eligible:
            outcome = PreparationOutcome.REFUSED
        else:
            outcome = (
                PreparationOutcome.NO_CHANGES if review.no_changes else PreparationOutcome.ELIGIBLE
            )
    return ChangeView(
        operation_id=preparation.pk,
        server_id=preparation.server_id or 0,
        server_name=preparation.server.name if preparation.server is not None else "",
        kind_label=row.kind_label,
        outcome=outcome,
        queued_at=preparation.queued_at,
        failure=preparation.failure,
        review=review,
        kind_slug=preparation.kind_slug,
    )


_RUN_OUTCOMES = {
    Status.QUEUED: RunOutcome.QUEUED,
    Status.RUNNING: RunOutcome.RUNNING,
    Status.RECONCILING: RunOutcome.RECONCILING,
    Status.SUCCEEDED: RunOutcome.SUCCEEDED,
    Status.FAILED: RunOutcome.FAILED,
}


@dataclass(frozen=True)
class RunView:
    run: ChangeRun
    outcome: RunOutcome
    kind_label: str
    consent_label: str
    requested_by: str

    @property
    def succeeded(self) -> bool:
        return self.outcome == RunOutcome.SUCCEEDED

    @property
    def reconciling(self) -> bool:
        return self.outcome == RunOutcome.RECONCILING

    @property
    def failed(self) -> bool:
        return self.outcome == RunOutcome.FAILED

    @property
    def unknown(self) -> bool:
        return self.outcome == RunOutcome.UNKNOWN

    @property
    def active(self) -> bool:
        return self.outcome in {RunOutcome.QUEUED, RunOutcome.RUNNING, RunOutcome.RECONCILING}

    @property
    def native_record_missing(self) -> bool:
        return self.reconciling and self.run.execution == Result.NOT_FOUND

    @property
    def reached_server(self) -> bool:
        """The unit is gone without a result line, but its journal kept reviewed stages."""
        return self.native_record_missing and bool(self.run.progress_stage)

    @property
    def polling(self) -> bool:
        """Whether the run's page follows it: the worker is on it or a check is pending."""
        return self.active and (not self.reconciling or self.run.check_requested_at is not None)

    @property
    def token(self) -> str:
        pending = int(self.run.check_requested_at is not None)
        stage = self.run.progress_stage.encode().hex()
        return f"{self.outcome.name}.{self.run.execution}.{pending}.{stage}"

    @property
    def execution_label(self) -> str:
        if self.reconciling and self.run.execution == Result.RUNNING:
            return "Running when last inspected; Check outcome inspects it again"
        if self.reached_server:
            return "Reached the server; no result line, and systemd no longer has its unit"
        if self.unknown and self.run.progress_stage:
            return "Outcome unknown: the run reached the server but reported no result"
        return Result(self.run.execution).label

    @property
    def verification_label(self) -> str:
        return Verification(self.run.verification).label

    @property
    def refused_before_changes(self) -> bool:
        return self.run.execution in Result.refused_before_changes()

    @property
    def consent(self) -> Consent:
        return Consent(self.run.review.consent)

    @property
    def review(self) -> ChangeReview:
        return self.run.review


def run_view(run: ChangeRun) -> RunView:
    kind = engine.kind_of(run.review.kind_slug)
    outcome = (
        RunOutcome.UNKNOWN
        if run.status == Status.FAILED and run.execution == Result.OUTCOME_UNKNOWN
        else _RUN_OUTCOMES[Status(run.status)]
    )
    return RunView(
        run=run,
        outcome=outcome,
        kind_label=kind.label if kind is not None else run.review.kind_slug,
        consent_label=Consent(run.review.consent).label,
        requested_by=run.requested_by_name,
    )


@dataclass(frozen=True)
class BlockingOperation:
    """Another remote operation of the server that keeps a page from offering a change."""

    label: str
    url: str
    reconciling: bool


def blocking_operation(operation: RemoteOperation | None) -> BlockingOperation | None:
    if operation is None or operation.kind == RemoteOperation.Kind.DISCOVERY:
        return None
    if operation.kind == RemoteOperation.Kind.CHANGE_APPLY:
        label, url = f"change run {operation.pk}", reverse("run_detail", args=[operation.pk])
    else:
        label = f"change preparation {operation.pk}"
        url = reverse("change_detail", args=[operation.pk])
    return BlockingOperation(label, url, operation.status == Status.RECONCILING)
