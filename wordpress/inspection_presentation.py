"""What the inspection's review and result pages show (docs/wordpress.md#inspecting-wordpress).

Templates receive these views and never decide what a stored state means.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Final

from bootstrap.models import ApplyRun, ConfigurationPlan, Execution

from . import inspection_native
from .inspection_models import (
    InspectionItem,
    InspectionResult,
    Operation,
    PlanWordpressInspection,
    RunWordpressInspection,
)

REASONS: Final = {
    "overflow": "the output was larger than the bounded record allows",
    "output": "a command printed something other than its exact expected output",
    "timeout": "a command ran past its time limit",
    "failed": "a command failed or its status could not be read",
    "catalog": "the official checksum catalog was not available for this release or version",
    "skipped": "it was not run, because an earlier step used the time budget",
    "not_installed": "WP-CLI reports WordPress as not installed",
    "journal_missing": "the native journal holds no result record for this run, for example "
    "because it was rotated or vacuumed",
    "journal_unreadable": "the native journal could not be read",
    "extra": "the journal holds more than one result record for this run",
    "invalid": "the record the journal holds is not the fixed result grammar",
}
STATUS_LABELS: Final = {
    "active": "Active",
    "inactive": "Inactive",
    "active-network": "Network active",
    "must-use": "Must-use (loaded automatically)",
    "dropin": "Drop-in (loaded automatically)",
    "parent": "Parent theme",
}


@dataclass(frozen=True)
class InspectionReviewView:
    """What an inspection review shows beside the common plan facts."""

    inspection: PlanWordpressInspection
    observed_at: datetime

    @property
    def operation_label(self) -> str:
        return Operation(self.inspection.operation).label

    @property
    def commands(self) -> list[str]:
        return list(inspection_native.COMMANDS[Operation(self.inspection.operation)])

    @property
    def runs_application(self) -> bool:
        return inspection_native.RUNS_APPLICATION[Operation(self.inspection.operation)]

    @property
    def mu_plugins(self) -> list[str]:
        return self.inspection.names("mu-plugin")

    @property
    def dropins(self) -> list[str]:
        return self.inspection.names("dropin")

    @property
    def plugin_slugs(self) -> list[str]:
        return self.inspection.names("plugin")

    @property
    def themes(self) -> list[str]:
        return self.inspection.names("theme")

    @property
    def authority(self) -> str:
        """docs/wordpress.md#review-permissions"""
        return (
            "Viewing this review needs the permission to view WordPress plans, preparing it the "
            "permission to prepare them, and running it the separate permission to run an "
            "explicit WordPress inspection. Access to the site, its database, its certificate, "
            "the application's passive evidence, installation or the bootstrap plans grants "
            "none of these."
        )


def inspection_review(plan: ConfigurationPlan) -> InspectionReviewView | None:
    review = getattr(plan, "wordpress_inspection", None)
    return None if review is None else InspectionReviewView(review, plan.collected_at)


@dataclass(frozen=True)
class ItemView:
    item: InspectionItem

    @property
    def status_label(self) -> str:
        return STATUS_LABELS.get(self.item.status, self.item.status)

    @property
    def reason(self) -> str:
        return REASONS.get(self.item.why, "") if self.item.why else ""


@dataclass(frozen=True)
class ResultView:
    """A run's retained result, or the fact that none was retrieved."""

    row: RunWordpressInspection
    result: InspectionResult | None
    items: tuple[InspectionItem, ...]
    executed: bool

    @property
    def operation_label(self) -> str:
        return Operation(self.row.operation).label

    @property
    def available(self) -> bool:
        return self.result is not None and self.result.state == InspectionResult.State.AVAILABLE

    @property
    def reason(self) -> str:
        if self.result is None:
            return "the result was not retrieved because the run's verification could not read it"
        return REASONS.get(self.result.why, "the reason is not recorded")

    @property
    def integrity_reason(self) -> str:
        return reason_text(self.result.integrity_why) if self.result is not None else ""

    @property
    def files(self) -> list[tuple[str, str]]:
        if self.result is None:
            return []
        return [
            (kind, path)
            for line in self.result.files.splitlines()
            for kind, _, path in [line.partition(" ")]
        ]

    def _kind(self, *kinds: str) -> list[ItemView]:
        return [ItemView(item) for item in self.items if item.kind in kinds]

    @property
    def plugins(self) -> list[ItemView]:
        return self._kind("plugin")

    @property
    def automatic(self) -> list[ItemView]:
        return self._kind("mu-plugin", "dropin")

    @property
    def themes(self) -> list[ItemView]:
        return self._kind("theme")

    @property
    def mismatches(self) -> int:
        return sum(1 for item in self.items if item.verdict == InspectionResult.Integrity.MISMATCH)

    @property
    def matches(self) -> int:
        return sum(1 for item in self.items if item.verdict == InspectionResult.Integrity.MATCH)

    @property
    def unavailable(self) -> int:
        return sum(
            1 for item in self.items if item.verdict == InspectionResult.Integrity.UNAVAILABLE
        )


def reason_text(code: str) -> str:
    return REASONS.get(code, "the reason is not recorded")


def result_of(run: ApplyRun) -> ResultView | None:
    row = RunWordpressInspection.objects.filter(run=run).first()
    if row is None:
        return None
    result = InspectionResult.objects.filter(run=run).first()
    executed = run.execution == Execution.SUCCEEDED
    if result is None and not executed:
        return None
    items = tuple(InspectionItem.objects.filter(result=result)) if result is not None else ()
    return ResultView(row, result, items, executed)


def latest_result(server_id: int, identifier: str) -> ResultView | None:
    """The newest retained result of a site on a server, for its page."""
    result = (
        InspectionResult.objects.filter(
            run__server_id=server_id, run__wordpress_inspection__identifier=identifier
        )
        .select_related("run")
        .order_by("-retrieved_at", "-pk")
        .first()
    )
    return None if result is None else result_of(result.run)
