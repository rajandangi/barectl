"""The TLS actions' place in configuration plans (bootstrap.actions)."""

import hashlib
import secrets
from dataclasses import dataclass

from bootstrap.actions import Authority
from bootstrap.models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanPreparation,
    Verification,
)
from bootstrap.native import UnitEvidence
from bootstrap.review import Draft
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites import inspection
from sites.names import IDENTIFIER

from . import admission, apply, renewal, setup, setup_apply
from .models import PlanChallenge, PlanRenewalFile, PlanRenewalObservation, TlsRequest
from .presentation import ChallengeReview, SetupReview, challenge_review, setup_review

_VIEW = ("servers.view_server", "tls.view_tlsplan")
AUTHORITY = Authority(
    view=_VIEW,
    prepare=(*_VIEW, "tls.prepare_tlsplan"),
    apply=(*_VIEW, "tls.apply_tlsplan"),
)
INVALID_REQUEST = (
    "The stored TLS request is not a valid site identifier, so Barectl read nothing from the "
    "server. Prepare a new plan."
)
MISSING_REQUEST = (
    "The TLS request of this preparation is not recorded, so Barectl read nothing from the server."
)


@dataclass(frozen=True)
class ChallengeHandler:
    actions: frozenset[str] = frozenset({Action.TLS_CHALLENGE})
    authority: Authority = AUTHORITY
    applicable: bool = True
    review_template: str = "tls/_challenge_review.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        request = TlsRequest.objects.filter(preparation=preparation).first()
        if request is None:
            raise OperationRefused(MISSING_REQUEST)
        if not IDENTIFIER.fullmatch(request.identifier):
            raise OperationRefused(INVALID_REQUEST)
        token = secrets.token_hex(16)
        evidence = inspection.inspect(shell, request.identifier, token)
        return admission.review(request.identifier, token, evidence)

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        paths = getattr(draft, "paths", None)
        if not isinstance(draft, admission.ChallengeDraft) or not draft.proposes or not paths:
            return
        PlanChallenge.objects.create(
            plan=plan,
            identifier=paths.identifier,
            php_version=paths.php,
            names="\n".join(draft.names),
            ipv6=draft.ipv6,
            probe_token=draft.token,
            preimage=draft.preimage,
            preimage_sha256=hashlib.sha256(draft.preimage.encode()).hexdigest(),
            content=draft.content,
            content_sha256=hashlib.sha256(draft.content.encode()).hexdigest(),
            creates_letsencrypt=draft.creates_letsencrypt,
            creates_backups=draft.creates_backups,
            payload_bytes=draft.payload_bytes,
        )

    def prefetch(self) -> tuple[str, ...]:
        return ("challenge",)

    def review(self, plan: ConfigurationPlan) -> ChallengeReview | None:
        return challenge_review(plan)

    def reviewed_changes(self, plan: ConfigurationPlan) -> str:
        return apply.reviewed_changes(plan)

    def copy_audit(self, plan: ConfigurationPlan, run: ApplyRun) -> None:
        apply.copy_audit(plan, run)

    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        return apply.payload(run, plan)

    def admit(self, shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
        apply.admit(shell, run, root=root)

    def execution(self, evidence: UnitEvidence) -> Execution:
        return apply.execution(evidence)

    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification:
        return apply.verify(shell, run)

    def failure(self, run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
        return apply.failure(run, execution, exit_status)

    def verification_failure(self, run: ApplyRun) -> str:
        return apply.verification_failure(run)

    def audit(self, run: ApplyRun) -> list[str]:
        return apply.audit(run)


@dataclass(frozen=True)
class SetupHandler:
    """docs/tls.md#certbot-renewal-setup"""

    actions: frozenset[str] = frozenset({Action.CERTBOT})
    authority: Authority = AUTHORITY
    applicable: bool = True
    review_template: str = "tls/_setup_review.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        if not TlsRequest.objects.filter(preparation=preparation).exists():
            raise OperationRefused(MISSING_REQUEST)
        return setup.prepare(shell)

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if not isinstance(draft, setup.SetupDraft):
            return
        if draft.observed:
            fields = {key: value[:60] for key, value in draft.observed.items()}
            PlanRenewalObservation.objects.create(plan=plan, **fields)
        if draft.no_changes or not draft.eligible:
            return
        PlanRenewalFile.objects.bulk_create(
            PlanRenewalFile(
                plan=plan,
                position=position,
                role=file.role,
                path=file.path,
                mode=file.mode,
                content=file.content,
                content_sha256=file.sha256,
                exists=file.path not in draft.publishes,
            )
            for position, file in enumerate(renewal.files())
        )

    def prefetch(self) -> tuple[str, ...]:
        return ("renewal_files",)

    def review(self, plan: ConfigurationPlan) -> SetupReview | None:
        return setup_review(plan)

    def reviewed_changes(self, plan: ConfigurationPlan) -> str:
        return setup_apply.reviewed_changes(plan)

    def copy_audit(self, plan: ConfigurationPlan, run: ApplyRun) -> None:
        setup_apply.copy_audit(plan, run)

    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        return setup_apply.payload(run, plan)

    def admit(self, shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
        setup_apply.admit(shell, run, root=root)

    def execution(self, evidence: UnitEvidence) -> Execution:
        return setup_apply.execution(evidence)

    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification:
        return setup_apply.verify(shell, run)

    def failure(self, run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
        return setup_apply.failure(run, execution, exit_status)

    def verification_failure(self, run: ApplyRun) -> str:
        return setup_apply.verification_failure(run)

    def audit(self, run: ApplyRun) -> list[str]:
        return setup_apply.audit(run)


HANDLER = ChallengeHandler()
SETUP_HANDLER = SetupHandler()
