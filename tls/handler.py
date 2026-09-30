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

from . import admission, apply
from .models import PlanChallenge, TlsRequest
from .presentation import ChallengeReview, challenge_review

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


HANDLER = ChallengeHandler()
