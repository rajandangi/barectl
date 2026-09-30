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
    PlanPreparation,
    Verification,
)
from bootstrap.native import UnitEvidence
from bootstrap.profiles import DRIVER_ACTIONS
from bootstrap.review import Draft
from discovery.ssh import RemoteShell

from . import drivers
from .plans import save_driver
from .presentation import DriverReview, driver_review

_VIEW = ("servers.view_server", "databases.view_databaseplan")
AUTHORITY = Authority(
    view=_VIEW,
    prepare=(*_VIEW, "databases.prepare_databaseplan"),
    apply=(*_VIEW, "databases.apply_databaseplan"),
)


@dataclass(frozen=True)
class DriverHandler:
    """docs/databases.md#php-database-drivers"""

    actions: frozenset[str] = DRIVER_ACTIONS
    authority: Authority = AUTHORITY
    applicable: bool = True
    review_template: str = "databases/_driver_review.html"

    def prepare(self, preparation: PlanPreparation, shell: RemoteShell) -> Draft:
        return drivers.prepare(shell, Action(preparation.action))

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
        return bootstrap_apply.package_payload(run, plan, sockets=sockets)

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


DRIVERS = DriverHandler()
