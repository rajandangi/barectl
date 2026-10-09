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
    finish,
    finish_apply,
    install,
    install_apply,
    plans,
    runtime,
    runtime_apply,
    setup,
    setup_apply,
    setup_native,
)
from .models import PlanWpcliTool, RunWordpressFinish, RunWordpressInstall, WordpressRequest
from .presentation import (
    FinishReview,
    InstallReview,
    RuntimeReview,
    SetupReview,
    finish_review,
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


@dataclass(frozen=True)
class FinishHandler:
    """docs/wordpress.md#finishing-a-partial-installation: the review is the immutable intent
    an apply run consumes. It uses the installation's permissions, because it completes the
    same installation."""

    actions: frozenset[str] = frozenset({Action.WORDPRESS_FINISH})
    authority: Authority = INSTALL_AUTHORITY
    applicable: bool = True
    review_template: str = "wordpress/_finish_review.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        return finish.prepare(preparation, shell)

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if isinstance(draft, finish.FinishDraft):
            plans.save_finish(plan, draft)

    def prefetch(self) -> tuple[str, ...]:
        return ("wordpress_finish",)

    def review(self, plan: ConfigurationPlan) -> FinishReview | None:
        return finish_review(plan)

    def reviewed_changes(self, plan: ConfigurationPlan) -> str:
        return finish_apply.reviewed_changes(plan)

    def copy_audit(self, plan: ConfigurationPlan, run: ApplyRun) -> None:
        finish_apply.copy_audit(plan, run)

    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        return finish_apply.payload(run, plan)

    def limits(self, run: ApplyRun) -> Limits:
        return finish_apply.limits(run)

    def admit(self, shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
        finish_apply.admit(shell, run, root=root)

    def execution(self, evidence: UnitEvidence) -> Execution:
        return finish_apply.execution(evidence)

    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification:
        return finish_apply.verify(shell, run)

    def failure(self, run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
        return finish_apply.failure(run, execution, exit_status)

    def verification_failure(self, run: ApplyRun) -> str:
        return finish_apply.verification_failure(run)

    def audit(self, run: ApplyRun) -> list[str]:
        return finish_apply.audit(run)

    def completion(self, run: ApplyRun) -> Completion | None:
        """The application's addresses once the run is verified, with the required password
        step only when this run created the administrator."""
        row = RunWordpressFinish.objects.filter(run=run).first()
        if run.verification != Verification.PASSED or row is None:
            return None
        return Completion(
            url=f"{row.url}/",
            label=f"Open {row.url}/",
            observed=False,
            note=(
                "WordPress is complete and answers over HTTPS as of the run's verification, "
                "which is not a live health check."
            ),
            permission=INSTALL_AUTHORITY.view,
            heading="Administrator password setup required" if row.runs_install else "",
            command=(
                install.password_command(
                    row.identifier, row.php_version, row.canonical_name, row.admin_login
                )
                if row.runs_install
                else ""
            ),
            links=((f"{row.url}/", "Home page"), (f"{row.url}/wp-admin/", "WordPress dashboard")),
        )


SETUP_HANDLER = SetupHandler()
RUNTIME_HANDLER = RuntimeHandler()
INSTALL_HANDLER = InstallHandler()
FINISH_HANDLER = FinishHandler()
