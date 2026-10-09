"""What the maintenance review and result pages show (docs/wordpress.md#maintaining-wordpress).

Templates receive these views and never decide what a stored state means.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Final

from bootstrap.models import ApplyRun, ConfigurationPlan, Execution

from . import maintenance_native
from .inspection_presentation import REASONS as INSPECTION_REASONS
from .maintenance_models import (
    MaintenanceResult,
    Operation,
    PlanWordpressMaintenance,
    RunWordpressMaintenance,
)

REASONS: Final = {
    key: INSPECTION_REASONS[key]
    for key in (
        "overflow",
        "output",
        "timeout",
        "failed",
        "skipped",
        "journal_missing",
        "journal_unreadable",
        "extra",
        "invalid",
    )
} | {"error": "WP-CLI reported an error"}


@dataclass(frozen=True)
class MaintenanceReviewView:
    """What a maintenance review shows beside the common plan facts."""

    maintenance: PlanWordpressMaintenance
    observed_at: datetime

    @property
    def operation_label(self) -> str:
        return Operation(self.maintenance.operation).label

    @property
    def command(self) -> str:
        return maintenance_native.COMMANDS[Operation(self.maintenance.operation)]

    @property
    def loads_extensions(self) -> bool:
        return maintenance_native.LOADS_EXTENSIONS[Operation(self.maintenance.operation)]

    @property
    def rewrite(self) -> bool:
        return self.maintenance.operation == Operation.REWRITE

    @property
    def mu_plugins(self) -> list[str]:
        return self.maintenance.names("mu-plugin")

    @property
    def dropins(self) -> list[str]:
        return self.maintenance.names("dropin")

    @property
    def themes(self) -> list[str]:
        return self.maintenance.names("theme")

    @property
    def authority(self) -> str:
        """docs/wordpress.md#review-permissions"""
        return (
            "Viewing this review needs the permission to view WordPress plans, preparing it the "
            "permission to prepare them, and running it the separate permission to run "
            "WordPress maintenance. The permission to run an explicit inspection, to install, "
            "to finish, and access to the site, its database, its certificate, the "
            "application's passive evidence or the bootstrap plans grant none of these."
        )


def maintenance_review(plan: ConfigurationPlan) -> MaintenanceReviewView | None:
    review = getattr(plan, "wordpress_maintenance", None)
    return None if review is None else MaintenanceReviewView(review, plan.collected_at)


@dataclass(frozen=True)
class MaintenanceResultView:
    """A run's retained result, or the fact that none was retrieved."""

    row: RunWordpressMaintenance
    result: MaintenanceResult | None
    executed: bool

    @property
    def operation_label(self) -> str:
        return Operation(self.row.operation).label

    @property
    def available(self) -> bool:
        return self.result is not None and self.result.state == MaintenanceResult.State.AVAILABLE

    @property
    def rewrite(self) -> bool:
        return self.row.operation == Operation.REWRITE

    @property
    def reason(self) -> str:
        if self.result is None:
            return "the result was not retrieved because the run's verification could not read it"
        return REASONS.get(self.result.why, "the reason is not recorded")


def maintenance_result_of(run: ApplyRun) -> MaintenanceResultView | None:
    row = RunWordpressMaintenance.objects.filter(run=run).first()
    if row is None:
        return None
    result = MaintenanceResult.objects.filter(run=run).first()
    executed = run.execution == Execution.SUCCEEDED
    if result is None and not executed:
        return None
    return MaintenanceResultView(row, result, executed)


def latest_maintenance_result(server_id: int, identifier: str) -> MaintenanceResultView | None:
    """The newest retained result of a site on a server, for its page."""
    result = (
        MaintenanceResult.objects.filter(
            run__server_id=server_id, run__wordpress_maintenance__identifier=identifier
        )
        .select_related("run")
        .order_by("-retrieved_at", "-pk")
        .first()
    )
    return None if result is None else maintenance_result_of(result.run)
