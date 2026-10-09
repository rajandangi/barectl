"""The WordPress actions' place in configuration plans (bootstrap.actions).

docs/wordpress.md#wp-cli-setup. The tool setup reuses bootstrap's own permission
contract: it grants no present or future WordPress execution, which later workflows
define separately.
"""

from dataclasses import dataclass

from bootstrap.actions import BOOTSTRAP, Authority, Completion
from bootstrap.models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanPreparation,
    Verification,
)
from bootstrap.native import Limits, UnitEvidence
from bootstrap.review import Draft
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites.names import IDENTIFIER

from . import (
    inspection,
    inspection_apply,
    install,
    install_apply,
    maintenance,
    maintenance_apply,
    plans,
    runtime,
    runtime_apply,
    setup,
    setup_apply,
    setup_native,
)
from .inspection_presentation import InspectionReviewView, ResultView, inspection_review, result_of
from .maintenance_presentation import (
    MaintenanceResultView,
    MaintenanceReviewView,
    maintenance_result_of,
    maintenance_review,
)
from .models import PlanWpcliTool, RunWordpressInstall, WordpressRequest
from .presentation import (
    InstallReview,
    RuntimeReview,
    SetupReview,
    install_review,
    runtime_review,
    setup_review,
)

AUTHORITY: Authority = BOOTSTRAP
_VIEW_PLANS = ("servers.view_server", "wordpress.view_wordpressplan")
# docs/wordpress.md#review-permissions: WordPress plans have their own viewers, preparers and
# installers. Preparing starts from a site's page, so it needs the site's observation too.
INSTALL_AUTHORITY = Authority(
    view=_VIEW_PLANS,
    prepare=(*_VIEW_PLANS, "wordpress.prepare_wordpressplan", "discovery.view_siteobservation"),
    apply=(*_VIEW_PLANS, "wordpress.install_wordpress"),
)


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


MISSING_REQUEST = (
    "The WordPress request of this preparation is not recorded, or it is not a valid site "
    "identifier, so Barectl read nothing from the server."
)


@dataclass(frozen=True)
class RuntimeHandler:
    """docs/wordpress.md#php-runtime"""

    actions: frozenset[str] = frozenset({Action.PHP_WORDPRESS})
    authority: Authority = AUTHORITY
    applicable: bool = True
    review_template: str = "wordpress/_runtime_review.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        request = WordpressRequest.objects.filter(preparation=preparation).first()
        if request is None or not IDENTIFIER.fullmatch(request.identifier):
            raise OperationRefused(MISSING_REQUEST)
        return runtime.prepare(shell, request.identifier)

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if isinstance(draft, runtime.RuntimeDraft):
            plans.save_runtime(plan, draft)

    def prefetch(self) -> tuple[str, ...]:
        return ("wordpress_runtime", "runtime_capabilities", "driver_pools")

    def review(self, plan: ConfigurationPlan) -> RuntimeReview | None:
        return runtime_review(plan)

    def reviewed_changes(self, plan: ConfigurationPlan) -> str:
        return runtime_apply.reviewed_changes(plan)

    def copy_audit(self, plan: ConfigurationPlan, run: ApplyRun) -> None:
        runtime_apply.copy_audit(plan, run)

    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        return runtime_apply.payload(run, plan)

    def admit(self, shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
        runtime_apply.admit(shell, run, root=root)

    def execution(self, evidence: UnitEvidence) -> Execution:
        return runtime_apply.execution(evidence)

    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification:
        return runtime_apply.verify(shell, run)

    def failure(self, run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
        return runtime_apply.failure(run, execution, exit_status)

    def verification_failure(self, run: ApplyRun) -> str:
        return runtime_apply.verification_failure(run)

    def audit(self, run: ApplyRun) -> list[str]:
        return runtime_apply.audit(run)


@dataclass(frozen=True)
class InstallHandler:
    """docs/wordpress.md#installation-review and #applying-an-installation: the review is
    the immutable intent an apply run consumes, and applying it runs the reviewed native
    body under the shared mutation lock."""

    actions: frozenset[str] = frozenset({Action.WORDPRESS_INSTALL})
    authority: Authority = INSTALL_AUTHORITY
    applicable: bool = True
    review_template: str = "wordpress/_install_review.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        return install.prepare(preparation, shell)

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if isinstance(draft, install.InstallDraft):
            plans.save_install(plan, draft)

    def prefetch(self) -> tuple[str, ...]:
        return ("wordpress_install",)

    def review(self, plan: ConfigurationPlan) -> InstallReview | None:
        return install_review(plan)

    def reviewed_changes(self, plan: ConfigurationPlan) -> str:
        return install_apply.reviewed_changes(plan)

    def copy_audit(self, plan: ConfigurationPlan, run: ApplyRun) -> None:
        install_apply.copy_audit(plan, run)

    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        return install_apply.payload(run, plan)

    def limits(self, run: ApplyRun) -> Limits:
        return install_apply.limits(run)

    def admit(self, shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
        install_apply.admit(shell, run, root=root)

    def execution(self, evidence: UnitEvidence) -> Execution:
        return install_apply.execution(evidence)

    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification:
        return install_apply.verify(shell, run)

    def failure(self, run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
        return install_apply.failure(run, execution, exit_status)

    def verification_failure(self, run: ApplyRun) -> str:
        return install_apply.verification_failure(run)

    def audit(self, run: ApplyRun) -> list[str]:
        return install_apply.audit(run)

    def completion(self, run: ApplyRun) -> Completion | None:
        """The required password step and the application's addresses, once the run is
        verified. Installation never delivers a password, so this is not a login claim."""
        row = RunWordpressInstall.objects.filter(run=run).first()
        if run.verification != Verification.PASSED or row is None:
            return None
        return Completion(
            url=f"{row.url}/",
            label=f"Open {row.url}/",
            observed=False,
            note=(
                "WordPress is installed and answers over HTTPS as of the run's verification, "
                "which is not a live health check."
            ),
            permission=INSTALL_AUTHORITY.view,
            heading="Administrator password setup required",
            command=install.password_command(
                row.identifier, row.php_version, row.canonical_name, row.admin_login
            ),
            links=((f"{row.url}/", "Home page"), (f"{row.url}/wp-admin/", "WordPress dashboard")),
        )


# docs/wordpress.md#review-permissions: running application code is its own permission,
# separate from viewing or preparing plans and from installing.
INSPECT_AUTHORITY = Authority(
    view=_VIEW_PLANS,
    prepare=INSTALL_AUTHORITY.prepare,
    apply=(*_VIEW_PLANS, "wordpress.inspect_wordpress"),
)


@dataclass(frozen=True)
class InspectionHandler:
    """docs/wordpress.md#inspecting-wordpress: the review is the immutable intent an apply
    run consumes, and applying it runs the reviewed native body under the shared mutation
    lock; the run retains a bounded typed result."""

    actions: frozenset[str] = frozenset({Action.WORDPRESS_INSPECT})
    authority: Authority = INSPECT_AUTHORITY
    applicable: bool = True
    review_template: str = "wordpress/_inspection_review.html"
    result_template: str = "wordpress/_inspection_result.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        return inspection.prepare(preparation, shell)

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if isinstance(draft, inspection.InspectionDraft):
            plans.save_inspection(plan, draft)

    def prefetch(self) -> tuple[str, ...]:
        return ("wordpress_inspection",)

    def review(self, plan: ConfigurationPlan) -> InspectionReviewView | None:
        return inspection_review(plan)

    def reviewed_changes(self, plan: ConfigurationPlan) -> str:
        return inspection_apply.reviewed_changes(plan)

    def copy_audit(self, plan: ConfigurationPlan, run: ApplyRun) -> None:
        inspection_apply.copy_audit(plan, run)

    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        return inspection_apply.payload(run, plan)

    def limits(self, run: ApplyRun) -> Limits:
        return inspection_apply.limits(run)

    def admit(self, shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
        inspection_apply.admit(shell, run, root=root)

    def execution(self, evidence: UnitEvidence) -> Execution:
        return inspection_apply.execution(evidence)

    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification:
        return inspection_apply.verify(shell, run)

    def failure(self, run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
        return inspection_apply.failure(run, execution, exit_status)

    def verification_failure(self, run: ApplyRun) -> str:
        return inspection_apply.verification_failure(run)

    def audit(self, run: ApplyRun) -> list[str]:
        return inspection_apply.audit(run)

    def result(self, run: ApplyRun) -> ResultView | None:
        return result_of(run)


# docs/wordpress.md#review-permissions: maintenance changes application state, so it is its own
# permission; diagnostic permission alone grants no mutation.
MAINTAIN_AUTHORITY = Authority(
    view=_VIEW_PLANS,
    prepare=INSTALL_AUTHORITY.prepare,
    apply=(*_VIEW_PLANS, "wordpress.maintain_wordpress"),
)


@dataclass(frozen=True)
class MaintenanceHandler:
    """docs/wordpress.md#maintaining-wordpress: the review is the immutable intent an apply
    run consumes, and applying it runs the reviewed native body under the shared mutation
    lock; the run retains a bounded typed result."""

    actions: frozenset[str] = frozenset({Action.WORDPRESS_MAINTAIN})
    authority: Authority = MAINTAIN_AUTHORITY
    applicable: bool = True
    review_template: str = "wordpress/_maintenance_review.html"
    result_template: str = "wordpress/_maintenance_result.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        return maintenance.prepare(preparation, shell)

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if isinstance(draft, maintenance.MaintenanceDraft):
            plans.save_maintenance(plan, draft)

    def prefetch(self) -> tuple[str, ...]:
        return ("wordpress_maintenance",)

    def review(self, plan: ConfigurationPlan) -> MaintenanceReviewView | None:
        return maintenance_review(plan)

    def reviewed_changes(self, plan: ConfigurationPlan) -> str:
        return maintenance_apply.reviewed_changes(plan)

    def copy_audit(self, plan: ConfigurationPlan, run: ApplyRun) -> None:
        maintenance_apply.copy_audit(plan, run)

    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        return maintenance_apply.payload(run, plan)

    def limits(self, run: ApplyRun) -> Limits:
        return maintenance_apply.limits(run)

    def admit(self, shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
        maintenance_apply.admit(shell, run, root=root)

    def execution(self, evidence: UnitEvidence) -> Execution:
        return maintenance_apply.execution(evidence)

    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification:
        return maintenance_apply.verify(shell, run)

    def failure(self, run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
        return maintenance_apply.failure(run, execution, exit_status)

    def verification_failure(self, run: ApplyRun) -> str:
        return maintenance_apply.verification_failure(run)

    def audit(self, run: ApplyRun) -> list[str]:
        return maintenance_apply.audit(run)

    def result(self, run: ApplyRun) -> MaintenanceResultView | None:
        return maintenance_result_of(run)


SETUP_HANDLER = SetupHandler()
RUNTIME_HANDLER = RuntimeHandler()
INSTALL_HANDLER = InstallHandler()
INSPECTION_HANDLER = InspectionHandler()
MAINTENANCE_HANDLER = MaintenanceHandler()
