"""The database actions' place in configuration plans (bootstrap.actions)."""

from dataclasses import dataclass

from bootstrap import apply as bootstrap_apply
from bootstrap import inspection as bootstrap_inspection
from bootstrap.actions import Authority
from bootstrap.evidence import Unreadable, parse_socket_listeners
from bootstrap.models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEvidence,
    PlanPreparation,
    Verification,
)
from bootstrap.native import UnitEvidence
from bootstrap.profiles import DRIVER_ACTIONS
from bootstrap.review import Draft
from discovery.models import DatabaseEngine
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites import native as site_native
from sites.convention import SitePaths

from . import admission, apply, binding, drivers, inspection
from .models import DatabaseRequest
from .plans import save_binding, save_driver, save_inspection
from .presentation import (
    BindingReview,
    DriverReview,
    InspectionReview,
    binding_review,
    driver_review,
    inspection_review,
)

_VIEW = ("servers.view_server", "databases.view_databaseplan")
AUTHORITY = Authority(
    view=_VIEW,
    prepare=(*_VIEW, "databases.prepare_databaseplan"),
    apply=(*_VIEW, "databases.apply_databaseplan"),
)
MISSING_REQUEST = (
    "The database request of this preparation is not recorded, or it is not a valid site "
    "identifier and engine, so Barectl read nothing from the server."
)


@dataclass(frozen=True)
class DriverHandler:
    """docs/databases.md#php-database-drivers"""

    actions: frozenset[str] = DRIVER_ACTIONS
    authority: Authority = AUTHORITY
    applicable: bool = True
    review_template: str = "databases/_driver_review.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        request = DatabaseRequest.objects.filter(preparation=preparation).first()
        if request is not None and request.identifier:
            try:
                binding.principal(request.identifier)
            except ValueError:
                raise OperationRefused(MISSING_REQUEST) from None
        return drivers.prepare(
            shell,
            Action(preparation.action),
            php_version=request.php_version if request is not None else "",
            php_supply=request.php_supply if request is not None else "ubuntu",
            identifier=request.identifier if request is not None else "",
        )

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if isinstance(draft, drivers.DriverDraft):
            save_driver(plan, draft)

    def prefetch(self) -> tuple[str, ...]:
        return ("driver_pools",)

    def review(self, plan: ConfigurationPlan) -> DriverReview | None:
        return driver_review(plan) if plan.action in self.actions else None

    def reviewed_changes(self, plan: ConfigurationPlan) -> str:
        return bootstrap_apply.reviewed_changes(plan)

    def copy_audit(self, plan: ConfigurationPlan, run: ApplyRun) -> None:
        """The reviewed pools are part of the run's effects, which the run copies."""

    def payload(self, run: ApplyRun, plan: ConfigurationPlan) -> str:
        sockets = tuple(plan.driver_pools.filter(default=False).values_list("socket", flat=True))
        return bootstrap_apply.package_payload(
            run, plan, sockets=sockets, preconditions=_site_preconditions(plan)
        )

    def admit(self, shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
        """Verification reads nothing that needs privilege."""

    def execution(self, evidence: UnitEvidence) -> Execution:
        return evidence.execution

    def verify(self, shell: RemoteShell, run: ApplyRun) -> Verification:
        verification = bootstrap_apply.verify_profile(shell, run)
        plan = run.plan
        if verification != Verification.PASSED or plan is None:
            return verification
        try:
            for socket in plan.driver_pools.values_list("socket", flat=True):
                result = shell.run(bootstrap_inspection.socket_listeners(socket))
                if result.exit_status != 0 or result.truncated:
                    return Verification.UNAVAILABLE
                if socket not in parse_socket_listeners(result.stdout):
                    return Verification.FAILED
        except Unreadable:
            return Verification.UNAVAILABLE
        return Verification.PASSED

    def failure(self, run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
        return bootstrap_apply.package_failure(run, execution)

    def verification_failure(self, run: ApplyRun) -> str:
        return bootstrap_apply.package_verification_failure(run)

    def audit(self, run: ApplyRun) -> list[str]:
        return []


def _site_preconditions(plan: ConfigurationPlan) -> tuple[tuple[str, str], ...]:
    request = DatabaseRequest.objects.filter(preparation=plan.preparation).first()
    if request is None or not request.identifier:
        return ()
    pool = plan.driver_pools.filter(name=request.identifier, default=False).first()
    digest = (
        plan.evidence.filter(kind=PlanEvidence.Kind.SITE_REVALIDATION)
        .values_list("fingerprint", flat=True)
        .first()
    )
    if pool is None or not digest or not plan.php_version:
        raise OperationRefused(bootstrap_apply.EVIDENCE_FAILURE)
    try:
        selected = SitePaths(request.identifier, plan.php_version, revision=4)
        paths = (
            selected
            if selected.socket == pool.socket
            else SitePaths(request.identifier, plan.php_version)
        )
        if paths.socket != pool.socket:
            raise ValueError("The reviewed site socket differs.")
        return ((site_native.site_digest(paths), digest),)
    except ValueError:
        raise OperationRefused(bootstrap_apply.EVIDENCE_FAILURE) from None


@dataclass(frozen=True)
class BindingHandler:
    """docs/databases.md#database-bindings"""

    actions: frozenset[str] = frozenset(binding.BY_ACTION)
    authority: Authority = AUTHORITY
    applicable: bool = True
    review_template: str = "databases/_binding_review.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        request = DatabaseRequest.objects.filter(preparation=preparation).first()
        spec = binding.BY_ACTION.get(preparation.action)
        if request is None or spec is None or request.engine != spec.engine:
            raise OperationRefused(MISSING_REQUEST)
        try:
            binding.principal(request.identifier)
        except ValueError:
            raise OperationRefused(MISSING_REQUEST) from None
        return admission.prepare(shell, request.identifier, DatabaseEngine(request.engine))

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if isinstance(draft, admission.BindingDraft):
            save_binding(plan, draft)

    def prefetch(self) -> tuple[str, ...]:
        return ("binding", "binding_statements")

    def review(self, plan: ConfigurationPlan) -> BindingReview | None:
        return binding_review(plan) if plan.action in self.actions else None

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
class InspectionHandler:
    """docs/databases.md#privileged-inspection: a read-only preparation, never applied."""

    actions: frozenset[str] = frozenset({Action.DATABASE_INSPECTION})
    authority: Authority = AUTHORITY
    applicable: bool = False
    review_template: str = "databases/_inspection.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        return inspection.prepare(shell)

    def save(self, plan: ConfigurationPlan, draft: Draft) -> None:
        if isinstance(draft, inspection.InspectionDraft):
            save_inspection(plan, draft)

    def prefetch(self) -> tuple[str, ...]:
        return ("catalog_observations",)

    def review(self, plan: ConfigurationPlan) -> InspectionReview | None:
        return inspection_review(plan) if plan.action in self.actions else None

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


DRIVERS = DriverHandler()
BINDINGS = BindingHandler()
INSPECTION = InspectionHandler()
