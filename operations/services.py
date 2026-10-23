"""The change engine's application services: what views call and what the worker runs
(docs/adr/0035-one-change-engine-with-effect-derived-consent.md)."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from django.contrib.auth.models import AbstractBaseUser, User
from django.db import IntegrityError, transaction
from django.utils import timezone

from operations import confidential, lifecycle, native
from operations.lifecycle import OperationBusy, recovers_first
from operations.models import (
    CONFIDENTIAL_LIFETIME,
    ChangePreparation,
    ChangeReview,
    ChangeRun,
    Consent,
    RemoteOperation,
)

from . import engine
from .consent import permissions_for
from .inputs import decode_inputs

if TYPE_CHECKING:
    from servers.models import Server

Status = RemoteOperation.Status

BUSY = (
    "Barectl is running another remote operation for this server. Apply the change after "
    "it finishes, if its admission deadline has not passed."
)
ONLY_REVIEWED = "Only an eligible review with changes can be applied."
EXPIRED = "This review's admission deadline has passed. Prepare a new review."
SHARED_ACKNOWLEDGEMENT = (
    "This change touches shared resources. Confirm the listed affected sites to apply it."
)
ACKNOWLEDGEMENT_REQUIRED = (
    "This change requires the acknowledgement shown on its review. Confirm it to apply."
)
CONFIRMATION_REQUIRED = (
    "This change requires the value shown on its review to be typed exactly. Type it to apply."
)
CONFIDENTIAL_REQUIRED = "Type the confidential value this change writes, then apply it again."
CONFIDENTIAL_INVALID = "That confidential value cannot be accepted. Type a different value."
REVOKED = "Your account is no longer allowed to apply this change, so nothing was sent."


@recovers_first
def request_prepare(
    server: Server,
    user: AbstractBaseUser,
    kind_slug: str,
    *,
    inputs: Mapping[str, object] | None = None,
) -> ChangePreparation | None:
    """Queue a preparation of the kind, or return ``None`` if an operation is active.

    Raises ``ValueError`` for an unknown kind and ``Server.DoesNotExist`` when a
    concurrent request removed the server.
    """
    kind = engine.kind_of(kind_slug)
    if kind is None:
        raise ValueError("Unknown kind of change.")
    intent = decode_inputs(
        dict(inputs) if inputs is not None else {"version": 1}, kind.input_choices, kind.input_shape
    )
    try:
        return lifecycle.queue(
            ChangePreparation,
            server,
            kind_slug=kind_slug,
            requested_by=user,
            inputs=intent.document(),
        )
    except OperationBusy:
        return None


@dataclass(frozen=True)
class ChangeRow:
    """One preparation of the server's changes section, with its review once made."""

    preparation: ChangePreparation
    review: ChangeReview | None

    @property
    def kind_label(self) -> str:
        kind = engine.kind_of(self.preparation.kind_slug)
        return kind.label if kind is not None else self.preparation.kind_slug

    @property
    def active(self) -> bool:
        return self.preparation.status in RemoteOperation.ACTIVE

    @property
    def run_id(self) -> int | None:
        if self.review is None:
            return None
        try:
            return self.review.run.pk
        except ChangeRun.DoesNotExist:
            return None


@dataclass(frozen=True)
class ServerChanges:
    rows: list[ChangeRow]
    # The server's newest run of the engine, including one whose review is gone.
    latest_run: ChangeRun | None

    @property
    def polling(self) -> bool:
        return any(row.active for row in self.rows) or (
            self.latest_run is not None and self.latest_run.status in RemoteOperation.ACTIVE
        )


def _row(preparation: ChangePreparation) -> ChangeRow:
    try:
        review: ChangeReview | None = preparation.review
    except ChangeReview.DoesNotExist:
        review = None
    return ChangeRow(preparation, review)


@recovers_first
def read_changes(server: Server) -> ServerChanges:
    preparations = list(
        ChangePreparation.objects.filter(server=server)
        .select_related("review")
        .order_by("-queued_at", "-pk")
    )
    latest_run = ChangeRun.objects.filter(server=server).first()
    return ServerChanges([_row(preparation) for preparation in preparations], latest_run)


@recovers_first
def read_change(operation_id: int) -> ChangeRow | None:
    preparation = ChangePreparation.objects.select_related("review").filter(pk=operation_id).first()
    if preparation is None:
        return None
    return _row(preparation)


@dataclass(frozen=True)
class ApplyRequest:
    """What ``request_apply`` did: the run for the review, or why there is none."""

    run: ChangeRun | None
    problem: str = ""


@recovers_first
def request_apply(
    review: ChangeReview,
    user: User,
    *,
    acknowledged: bool = False,
    confirmation: str = "",
    secret: bytes | None = None,
) -> ApplyRequest:
    """Queue the run of the reviewed change, or return the run already recorded for it.

    A change that writes a secret carries one sealed value, which the worker opens and the
    server clears once sent (docs/adr/0032-keep-secrets-in-private-native-files.md).
    Repeated requests for one review converge on its one run. Raises ``Server.DoesNotExist``
    when a concurrent request removed the server.
    """
    existing = getattr(review, "run", None)
    if existing is not None:
        return ApplyRequest(existing)
    fields, problem = _confidential_fields(review, secret)
    if problem:
        return ApplyRequest(None, problem)
    if not user.is_active or not user.has_perms(
        permissions_for(Consent(review.consent), writes_secrets=review.writes_secrets)
    ):
        return ApplyRequest(None, REVOKED)
    problem = _refusal(review, acknowledged=acknowledged, confirmation=confirmation)
    if problem:
        return ApplyRequest(None, problem)
    preparation = review.preparation
    if preparation is None or preparation.server is None:
        return ApplyRequest(
            None, "This review's server registration is no longer recorded, so nothing was sent."
        )
    server = preparation.server
    now = timezone.now()
    sites_acknowledged = review.consent == Consent.SHARED
    try:
        with transaction.atomic():
            if not lifecycle.connection_current(preparation):
                return ApplyRequest(None, "The connection changed. Prepare a new review.")
            run = lifecycle.queue(
                ChangeRun,
                server,
                review=review,
                requested_by=user,
                requested_by_name=user.get_username(),
                server_name=server.name,
                unit_name=native.new_unit_name(),
                sites_acknowledged_by=user if sites_acknowledged else None,
                sites_acknowledged_at=now if sites_acknowledged else None,
                **fields,
            )
    except OperationBusy, IntegrityError:
        existing = ChangeRun.objects.filter(review=review).first()
        if existing is not None:
            return ApplyRequest(existing)
        return ApplyRequest(None, BUSY)
    return ApplyRequest(run)


def _confidential_fields(
    review: ChangeReview, secret: bytes | None
) -> tuple[dict[str, object], str]:
    """The run's sealed secret fields, or why the submitted value cannot be used."""
    if not review.writes_secrets:
        return ({}, CONFIDENTIAL_INVALID) if secret else ({}, "")
    if not secret:
        return {}, CONFIDENTIAL_REQUIRED
    try:
        return {
            "secret_sealed": confidential.seal(secret),
            "secret_expires_at": timezone.now() + CONFIDENTIAL_LIFETIME,
        }, ""
    except ValueError:
        return {}, CONFIDENTIAL_INVALID


def _refusal(review: ChangeReview, *, acknowledged: bool, confirmation: str = "") -> str:
    if review.preparation is None or not lifecycle.connection_current(review.preparation):
        return "The connection changed. Prepare a new review before applying."
    if not review.eligible or review.no_changes:
        return ONLY_REVIEWED
    if timezone.now() >= review.admission_expires_at:
        return EXPIRED
    if review.consent == Consent.SHARED and not acknowledged:
        return SHARED_ACKNOWLEDGEMENT
    if review.acknowledgement and not acknowledged:
        return ACKNOWLEDGEMENT_REQUIRED
    if review.confirmation and confirmation != review.confirmation:
        return CONFIRMATION_REQUIRED
    return ""


@recovers_first
def request_check(operation_id: int) -> bool:
    """Ask the worker to check a reconciling run's outcome; return whether it was asked."""
    run = ChangeRun.objects.filter(pk=operation_id).first()
    return run is not None and lifecycle.check(run)


@recovers_first
def request_closure(operation_id: int, user: User) -> bool:
    """Record ``user``'s acknowledgement that the run's outcome is unknown, and ask a check
    to close it; return whether the run was still reconciling without native evidence.

    The acknowledgement alone closes nothing: the check closes the run only with the
    proofs ``engine._close_unknown`` establishes, and uses the acknowledgement once.
    """
    run = ChangeRun.objects.filter(pk=operation_id).first()
    if run is None or not _may_close(user, run):
        return False
    now = timezone.now()
    with transaction.atomic():
        acknowledged = ChangeRun.objects.filter(
            pk=operation_id,
            status=Status.RECONCILING,
            execution="not_found",
        ).update(
            unknown_acknowledged_by=user,
            unknown_acknowledged_by_name=user.get_username(),
            unknown_acknowledged_at=now,
            closure_requested_at=now,
            closure_blocked="",
        )
    return bool(acknowledged) and lifecycle.check(run)


def _may_close(user: User, run: ChangeRun) -> bool:
    review = run.review
    return user.is_active and user.has_perms(
        permissions_for(Consent(review.consent), writes_secrets=review.writes_secrets)
    )


@recovers_first
def read_run(operation_id: int) -> ChangeRun | None:
    return ChangeRun.objects.select_related("review").filter(pk=operation_id).first()


@recovers_first
def forget_changes(server: Server) -> None:
    """Call inside the transaction that deletes the server. Active preparations are kept
    and protect the server, so the database refuses the removal while one remains.

    A review no run applied goes with its preparation; a run's protected reference keeps
    its own review for the run's audit.
    """
    ChangeReview.objects.filter(run__isnull=True, preparation__server=server).delete()
    lifecycle.forget(
        RemoteOperation.objects.filter(server=server, kind=RemoteOperation.Kind.CHANGE_PREPARATION)
    )


@recovers_first
def keep_run_audit(server: Server) -> None:
    """Keep the server's finished change runs as audit without the server.

    Call inside the transaction that deletes the server. Active runs stay attached and
    protect the server, so the database refuses the removal while one remains.
    """
    lifecycle.detach(
        RemoteOperation.objects.filter(server=server, kind=RemoteOperation.Kind.CHANGE_APPLY)
    )
