"""The TLS actions' place in configuration plans (bootstrap.actions)."""

import hashlib
import secrets
from dataclasses import dataclass

from bootstrap import apply as bootstrap_apply
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

from . import (
    activation,
    activation_apply,
    admission,
    apply,
    issuance,
    issuance_apply,
    readiness,
    renewal,
    setup,
    setup_apply,
    staging,
    staging_apply,
)
from .models import (
    PlanChallenge,
    PlanRenewalFile,
    PlanRenewalObservation,
    PlanTlsActivation,
    PlanTlsIssuance,
    PlanTlsReadiness,
    PlanTlsStaging,
    ReadinessName,
    TlsRequest,
)
from .presentation import (
    ActivationReview,
    ChallengeReview,
    IssuanceReview,
    ReadinessReview,
    SetupReview,
    StagingReview,
    activation_review,
    challenge_review,
    issuance_review,
    readiness_review,
    setup_review,
    staging_review,
)

_VIEW = ("servers.view_server", "tls.view_tlsplan")
AUTHORITY = Authority(
    view=_VIEW,
    prepare=(*_VIEW, "tls.prepare_tlsplan"),
    apply=(*_VIEW, "tls.apply_tlsplan"),
)
ISSUANCE_AUTHORITY = Authority(
    view=_VIEW,
    prepare=(*_VIEW, "tls.prepare_tlsplan"),
    apply=(*_VIEW, "tls.issue_certificate"),
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


@dataclass(frozen=True)
class ReadinessHandler:
    """docs/tls.md#readiness: a read-only preparation, never applied."""

    actions: frozenset[str] = frozenset({Action.TLS_READINESS})
    authority: Authority = AUTHORITY
    applicable: bool = False
    review_template: str = "tls/_readiness_review.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        return readiness.prepare(preparation, shell)

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if not isinstance(draft, readiness.ReadinessDraft) or not draft.php_version:
            return
        PlanTlsReadiness.objects.create(
            plan=plan,
            identifier=draft.identifier,
            php_version=draft.php_version,
            authority=draft.authority["directory"],
            authority_name=draft.authority["name"],
            webroot=draft.webroot,
            ipv6=draft.ipv6,
        )
        if draft.inputs is not None:
            ReadinessName.objects.bulk_create(
                ReadinessName(
                    plan=plan,
                    position=position,
                    name=record.name,
                    a="\n".join(record.a),
                    aaaa="\n".join(record.aaaa),
                    cname=record.cname,
                    caa="\n".join(record.caa),
                    problem=record.problem,
                )
                for position, record in enumerate(draft.inputs.names)
            )

    def prefetch(self) -> tuple[str, ...]:
        return ("readiness", "readiness_names")

    def review(self, plan: ConfigurationPlan) -> ReadinessReview | None:
        return readiness_review(plan) if plan.action in self.actions else None

    def reviewed_changes(self, plan: ConfigurationPlan) -> str:
        return ""

    def copy_audit(self, plan: ConfigurationPlan, run: ApplyRun) -> None:
        """Never applied."""

    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        raise OperationRefused(bootstrap_apply.NOT_APPLICABLE)

    def admit(self, shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
        raise OperationRefused(bootstrap_apply.NOT_APPLICABLE)

    def execution(self, evidence: UnitEvidence) -> Execution:
        return evidence.execution

    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification:
        return Verification.NOT_APPLICABLE

    def failure(self, run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
        return bootstrap_apply.NOT_APPLICABLE

    def verification_failure(self, run: ApplyRun) -> str:
        return bootstrap_apply.NOT_APPLICABLE

    def audit(self, run: ApplyRun) -> list[str]:
        return []


@dataclass(frozen=True)
class StagingHandler:
    """docs/tls.md#staging"""

    actions: frozenset[str] = frozenset({Action.TLS_STAGING})
    authority: Authority = AUTHORITY
    applicable: bool = True
    review_template: str = "tls/_staging_review.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        return staging.prepare(preparation, shell)

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if not isinstance(draft, staging.StagingDraft) or not draft.eligible:
            return
        if draft.payload_bytes is None:
            return
        PlanTlsStaging.objects.create(
            plan=plan,
            identifier=draft.identifier,
            php_version=draft.php_version,
            names="\n".join(draft.names),
            webroot=draft.webroot,
            authority=draft.authority["directory"],
            authority_name=draft.authority["name"],
            email=draft.email,
            cert_name=f"s{draft.identifier}",
            payload_bytes=draft.payload_bytes,
        )
        if draft.inputs is not None:
            ReadinessName.objects.bulk_create(
                ReadinessName(
                    plan=plan,
                    position=position,
                    name=record.name,
                    a="\n".join(record.a),
                    aaaa="\n".join(record.aaaa),
                    cname=record.cname,
                    caa="\n".join(record.caa),
                    problem=record.problem,
                )
                for position, record in enumerate(draft.inputs.names)
            )

    def prefetch(self) -> tuple[str, ...]:
        return ("staging", "readiness_names")

    def review(self, plan: ConfigurationPlan) -> StagingReview | None:
        return staging_review(plan)

    def reviewed_changes(self, plan: ConfigurationPlan) -> str:
        return staging_apply.reviewed_changes(plan)

    def copy_audit(self, plan: ConfigurationPlan, run: ApplyRun) -> None:
        staging_apply.copy_audit(plan, run)

    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        return staging_apply.payload(run, plan)

    def admit(self, shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
        staging_apply.admit(shell, run, root=root)

    def execution(self, evidence: UnitEvidence) -> Execution:
        return staging_apply.execution(evidence)

    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification:
        return staging_apply.verify(shell, run)

    def failure(self, run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
        return staging_apply.failure(run, execution, exit_status)

    def verification_failure(self, run: ApplyRun) -> str:
        return staging_apply.verification_failure(run)

    def audit(self, run: ApplyRun) -> list[str]:
        return staging_apply.audit(run)


READINESS_HANDLER = ReadinessHandler()
STAGING_HANDLER = StagingHandler()


@dataclass(frozen=True)
class IssuanceHandler:
    """docs/tls.md#issuance"""

    actions: frozenset[str] = frozenset({Action.TLS_ISSUANCE})
    authority: Authority = ISSUANCE_AUTHORITY
    applicable: bool = True
    review_template: str = "tls/_issuance_review.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        return issuance.prepare(preparation, shell)

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if not isinstance(draft, issuance.IssuanceDraft) or not draft.eligible:
            return
        if draft.payload_bytes is None and not draft.existing:
            return
        PlanTlsIssuance.objects.create(
            plan=plan,
            identifier=draft.identifier,
            php_version=draft.php_version,
            names="\n".join(draft.names),
            webroot=draft.webroot,
            authority=draft.authority["directory"],
            authority_name=draft.authority["name"],
            email=draft.email,
            cert_name=draft.identifier,
            account=draft.account,
            payload_bytes=draft.payload_bytes,
        )
        if draft.inputs is not None:
            ReadinessName.objects.bulk_create(
                ReadinessName(
                    plan=plan,
                    position=position,
                    name=record.name,
                    a="\n".join(record.a),
                    aaaa="\n".join(record.aaaa),
                    cname=record.cname,
                    caa="\n".join(record.caa),
                    problem=record.problem,
                )
                for position, record in enumerate(draft.inputs.names)
            )

    def prefetch(self) -> tuple[str, ...]:
        return ("issuance", "readiness_names")

    def review(self, plan: ConfigurationPlan) -> IssuanceReview | None:
        return issuance_review(plan)

    def reviewed_changes(self, plan: ConfigurationPlan) -> str:
        return issuance_apply.reviewed_changes(plan)

    def copy_audit(self, plan: ConfigurationPlan, run: ApplyRun) -> None:
        issuance_apply.copy_audit(plan, run)

    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        return issuance_apply.payload(run, plan)

    def admit(self, shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
        issuance_apply.admit(shell, run, root=root)

    def execution(self, evidence: UnitEvidence) -> Execution:
        return issuance_apply.execution(evidence)

    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification:
        return issuance_apply.verify(shell, run)

    def failure(self, run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
        return issuance_apply.failure(run, execution, exit_status)

    def verification_failure(self, run: ApplyRun) -> str:
        return issuance_apply.verification_failure(run)

    def audit(self, run: ApplyRun) -> list[str]:
        return issuance_apply.audit(run)


ISSUANCE_HANDLER = IssuanceHandler()


@dataclass(frozen=True)
class ActivationHandler:
    """docs/tls.md#activation"""

    actions: frozenset[str] = frozenset({Action.TLS_ACTIVATION})
    authority: Authority = AUTHORITY
    applicable: bool = True
    review_template: str = "tls/_activation_review.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        return activation.prepare(preparation, shell)

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if not isinstance(draft, activation.ActivationDraft) or not draft.eligible:
            return

        def sha(value: str) -> str:
            return hashlib.sha256(value.encode()).hexdigest()

        PlanTlsActivation.objects.create(
            plan=plan,
            identifier=draft.identifier,
            php_version=draft.php_version,
            names="\n".join(draft.names),
            ipv6=draft.ipv6,
            preimage=draft.preimage,
            preimage_sha256=sha(draft.preimage),
            https_content=draft.https_content,
            https_sha256=sha(draft.https_content),
            redirect_content=draft.redirect_content,
            redirect_sha256=sha(draft.redirect_content),
            redirect_only=draft.redirect_only,
            fingerprint=draft.certificate,
            not_after=draft.not_after,
            default_content=draft.default_content,
            default_sha256=sha(draft.default_content),
            creates_default=not draft.default_exists,
            payload_bytes=draft.payload_bytes,
        )

    def prefetch(self) -> tuple[str, ...]:
        return ("activation",)

    def review(self, plan: ConfigurationPlan) -> ActivationReview | None:
        return activation_review(plan)

    def reviewed_changes(self, plan: ConfigurationPlan) -> str:
        return activation_apply.reviewed_changes(plan)

    def copy_audit(self, plan: ConfigurationPlan, run: ApplyRun) -> None:
        activation_apply.copy_audit(plan, run)

    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        return activation_apply.payload(run, plan)

    def admit(self, shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
        activation_apply.admit(shell, run, root=root)

    def execution(self, evidence: UnitEvidence) -> Execution:
        return activation_apply.execution(evidence)

    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification:
        return activation_apply.verify(shell, run)

    def failure(self, run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
        return activation_apply.failure(run, execution, exit_status)

    def verification_failure(self, run: ApplyRun) -> str:
        return activation_apply.verification_failure(run)

    def audit(self, run: ApplyRun) -> list[str]:
        return activation_apply.audit(run)


ACTIVATION_HANDLER = ActivationHandler()
