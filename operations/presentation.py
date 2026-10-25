"""Templates receive view dataclasses and never read stored states or decide themselves
whether a review is eligible or expired, what a run's result established, or what consent
applying needs."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum, nonmember
from typing import TYPE_CHECKING

from django.core.exceptions import ObjectDoesNotExist
from django.urls import reverse
from django.utils import timezone

from . import engine, plain_words
from .consent import Scope, permissions_for
from .models import (
    ChangePreparation,
    ChangeReview,
    ChangeRun,
    Consent,
    RemoteOperation,
    Result,
    Verification,
)

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
class PlainChange:
    """A change in the words the confirm screen and Progress show by default (#179)."""

    title: str
    summary: tuple[str, ...]
    action: str
    home_url: str
    after_label: str = ""
    after_url: str = ""


@dataclass(frozen=True)
class PlainStep:
    label: str
    state_label: str
    current: bool = False


@dataclass(frozen=True)
class NextAction:
    """The one action a run's Progress offers: a form POST or a plain link."""

    label: str
    kind: str
    url: str


@dataclass(frozen=True)
class PlainRun:
    title: str
    result: str
    sentence: str
    steps: tuple[PlainStep, ...]
    next: NextAction | None = None


def _subject(inputs: Mapping[str, object], server_name: str) -> tuple[str, str]:
    """The site an operator named, or the server, and the site identifier when known."""
    names = inputs.get("names")
    if isinstance(names, list) and names and isinstance(names[0], str):
        identifier = inputs.get("identifier")
        return names[0], identifier if isinstance(identifier, str) else ""
    identifier = inputs.get("identifier")
    if isinstance(identifier, str) and identifier:
        return identifier, identifier
    return server_name, ""


def _home_url(home: plain_words.Home, server_id: int | None, identifier: str) -> str:
    if server_id is None:
        return reverse("servers")
    if home is plain_words.Home.SERVER_SITES:
        return reverse("server_sites", args=[server_id])
    if home is plain_words.Home.SERVER_SETTINGS:
        return reverse("server_settings", args=[server_id])
    if home is plain_words.Home.SITE:
        return (
            reverse("site_detail", args=[server_id, identifier])
            if identifier
            else reverse("server_sites", args=[server_id])
        )
    return reverse("server_detail", args=[server_id])


def plain_change(
    kind_slug: str, kind_label: str, preparation: ChangePreparation | None, server_name: str
) -> PlainChange:
    inputs = preparation.inputs if preparation is not None else {}
    server_id = preparation.server_id if preparation is not None else None
    site, identifier = _subject(inputs, server_name)
    raw_selection = inputs.get("selection")
    selection = plain_words.selection_label(raw_selection) if isinstance(raw_selection, str) else ""
    words = plain_words.words_for(kind_slug)
    if words is None:
        return PlainChange(
            title=kind_label,
            summary=(),
            action=kind_label,
            home_url=_home_url(plain_words.Home.SERVER, server_id, identifier),
        )
    values = {"server": server_name, "site": site, "selection": selection}
    return PlainChange(
        title=words.title.format(**values),
        summary=tuple(sentence.format(**values) for sentence in words.summary),
        action=words.action.format(**values),
        home_url=_home_url(words.home, server_id, identifier),
        after_label=words.after,
        after_url=_home_url(words.after_home, server_id, identifier) if words.after else "",
    )


def _steps(
    kind_slug: str,
    stages: list[str],
    selection: str,
    *,
    reached: str,
    finished: bool,
    stopped: bool,
) -> tuple[PlainStep, ...]:
    words = plain_words.words_for(kind_slug)
    index = stages.index(reached) if reached in stages else -1
    steps: list[PlainStep] = []
    for position, stage in enumerate(stages):
        label = plain_words.step_label(words, stage, selection)
        if finished or (index >= 0 and position < index):
            steps.append(PlainStep(label, "Done"))
        elif index >= 0 and position == index:
            steps.append(PlainStep(label, "Stopped here" if stopped else "In progress", True))
        else:
            steps.append(PlainStep(label, "Not started"))
    return tuple(steps)


def _raw_selection(review: ChangeReview) -> str:
    preparation = review.preparation
    selection = preparation.inputs.get("selection") if preparation is not None else ""
    return selection if isinstance(selection, str) else ""


def _run_next(run: ChangeRun, outcome: RunOutcome, after: PlainChange) -> NextAction | None:
    preparation_id = run.review.preparation_id
    if outcome == RunOutcome.RECONCILING:
        return NextAction("Check what happened", "check", reverse("run_check", args=[run.pk]))
    if outcome == RunOutcome.SUCCEEDED and after.after_url:
        return NextAction(after.after_label, "link", after.after_url)
    if outcome == RunOutcome.FAILED and preparation_id is not None:
        return NextAction(
            "Try again", "again", reverse("change_prepare_again", args=[preparation_id])
        )
    if outcome == RunOutcome.UNKNOWN:
        return NextAction("Open the server", "link", after.home_url)
    return None


def plain_run(run: ChangeRun, outcome: RunOutcome, kind_label: str) -> PlainRun:
    review = run.review
    server_name = run.server_name or run.ssh_alias
    after = plain_change(review.kind_slug, kind_label, review.preparation, server_name)
    document = review.document
    stages = [str(stage) for stage in document.get("stages", [])]
    selection = _raw_selection(review)
    stopped = outcome in {RunOutcome.FAILED, RunOutcome.UNKNOWN}
    steps = _steps(
        review.kind_slug,
        stages,
        selection,
        reached=run.progress_stage,
        finished=outcome == RunOutcome.SUCCEEDED,
        stopped=stopped,
    )
    result, sentence = _run_words(outcome, server_name, run)
    return PlainRun(
        title=after.title,
        result=result,
        sentence=sentence,
        steps=steps,
        next=_run_next(run, outcome, after),
    )


def _run_words(outcome: RunOutcome, server_name: str, run: ChangeRun) -> tuple[str, str]:
    if outcome == RunOutcome.QUEUED:
        return "Queued", f"Barectl will start this change on {server_name} in a moment."
    if outcome == RunOutcome.RUNNING:
        return (
            "Working",
            (
                f"Barectl is changing {server_name} now. The change continues on the "
                "server if you close this page."
            ),
        )
    if outcome == RunOutcome.SUCCEEDED:
        return "Done", "Barectl finished this change and checked it on the server."
    if outcome == RunOutcome.RECONCILING:
        return "Checking what happened", run.failure
    return ("Outcome unknown" if outcome == RunOutcome.UNKNOWN else "Stopped"), run.failure


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
    # The exact value the operator types before a destructive apply, and its label.
    confirmation: str = ""
    confirmation_label: str = ""
    # The change writes a secret through the confidential input channel.
    writes_secrets: bool = False
    # The secret's wording on the confirm screen, and whether it offers a browser-generated
    # value (docs/wordpress.md; Phase B #380).
    secret_label: str = "Confidential value"  # noqa: S105 - a label, not a secret
    secret_generate: bool = False
    # One input per changed settings key, instead of the single secret above (Phase B #383).
    secret_fields: list[dict[str, object]] = field(default_factory=list)

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
    plain: PlainChange = field(default_factory=lambda: PlainChange("", (), "", ""))

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
        confirmation=review.confirmation,
        confirmation_label=(
            str(document.get("confirmation_label", "Type the value to confirm."))
            if isinstance(document.get("confirmation_label", ""), str)
            else "Type the value to confirm."
        ),
        writes_secrets=review.writes_secrets,
        secret_label=(
            str(document.get("secret_label", "Confidential value"))
            if isinstance(document.get("secret_label", "Confidential value"), str)
            else "Confidential value"
        ),
        secret_generate=document.get("secret_generate") is True,
        secret_fields=[
            {
                "key": str(item["key"]),
                "secret": item.get("secret") is not False,
                "label": str(item.get("label", item["key"])),
            }
            for item in (
                document.get("secret_fields", [])
                if isinstance(document.get("secret_fields"), list)
                else []
            )
            if isinstance(item, dict) and isinstance(item.get("key"), str)
        ],
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
        plain=plain_change(
            preparation.kind_slug,
            row.kind_label,
            preparation,
            preparation.server.name if preparation.server is not None else "",
        ),
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
    plain: PlainRun = field(default_factory=lambda: PlainRun("", "", "", ()))

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
    kind_label = kind.label if kind is not None else run.review.kind_slug
    outcome = (
        RunOutcome.UNKNOWN
        if run.status == Status.FAILED and run.execution == Result.OUTCOME_UNKNOWN
        else _RUN_OUTCOMES[Status(run.status)]
    )
    return RunView(
        run=run,
        outcome=outcome,
        kind_label=kind_label,
        consent_label=Consent(run.review.consent).label,
        requested_by=run.requested_by_name,
        plain=plain_run(run, outcome, kind_label),
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
