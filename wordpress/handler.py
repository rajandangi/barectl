"""The WordPress actions' place in configuration plans (bootstrap.actions).

docs/wordpress.md#wp-cli-setup. The tool setup reuses bootstrap's own permission
contract: it grants no present or future WordPress execution, which later workflows
define separately.
"""

from dataclasses import dataclass

from bootstrap.actions import BOOTSTRAP, Authority
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

from . import setup, setup_apply, setup_native
from .models import PlanWpcliTool
from .presentation import SetupReview, setup_review

AUTHORITY: Authority = BOOTSTRAP


@dataclass(frozen=True)
class SetupHandler:
    """docs/wordpress.md#wp-cli-setup"""

    actions: frozenset[str] = frozenset({Action.WPCLI})
    authority: Authority = AUTHORITY
    applicable: bool = True
    review_template: str = "wordpress/_setup_review.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        return setup.prepare(shell)

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if not isinstance(draft, setup.SetupDraft) or not draft.eligible:
            return
        if draft.payload_bytes is None and not draft.installed:
            return
        PlanWpcliTool.objects.create(
            plan=plan,
            version=setup_native.VERSION,
            phar_url=setup_native.PHAR_URL,
            signature_url=setup_native.SIGNATURE_URL,
            key_url=setup_native.KEY_URL,
            fingerprint=setup_native.FINGERPRINT,
            sha256=setup_native.SHA256,
            path=setup_native.PHAR,
            creates_directory=draft.creates_directory,
            exists=draft.installed,
            payload_bytes=draft.payload_bytes,
        )

    def prefetch(self) -> tuple[str, ...]:
        return ("wpcli_tool",)

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


SETUP_HANDLER = SetupHandler()
