"""What a database plan's review shows beside the common plan facts (bootstrap.presentation)."""

from dataclasses import dataclass

from django.core.exceptions import ObjectDoesNotExist

from bootstrap.models import ConfigurationPlan
from discovery.models import DatabaseEngine

from . import binding
from .models import (
    PlanCatalogObservation,
    PlanDatabaseBinding,
    PlanDatabaseStatement,
    PlanDriverPool,
)

AUTHORITY_TEXT = (
    "Viewing needs Barectl's permission to view database plans, preparing its permission to "
    "prepare them, and applying its permission to apply them; bootstrap and site permissions "
    "grant none of these. On the server, preparation read as root or through noninteractive "
    "sudo; applying needs the same for systemd-run and for the read that verifies it."
)


@dataclass(frozen=True)
class DriverReview:
    pools: list[PlanDriverPool]
    php_version: str = ""
    php_supply: str = "ubuntu"
    authority: str = AUTHORITY_TEXT


@dataclass(frozen=True)
class BindingReview:
    record: PlanDatabaseBinding
    statements: list[PlanDatabaseStatement]
    authority: str = AUTHORITY_TEXT

    @property
    def connection(self) -> str:
        return binding.connection_text(DatabaseEngine(self.record.engine), self.record.identifier)


@dataclass(frozen=True)
class InspectionReview:
    observations: list[PlanCatalogObservation]
    authority: str = AUTHORITY_TEXT


def driver_review(plan: ConfigurationPlan) -> DriverReview:
    return DriverReview(list(plan.driver_pools.all()), plan.php_version, plan.php_supply)


def binding_review(plan: ConfigurationPlan) -> BindingReview | None:
    try:
        record = plan.binding
    except ObjectDoesNotExist:
        return None
    return BindingReview(record, list(plan.binding_statements.all()))


def inspection_review(plan: ConfigurationPlan) -> InspectionReview:
    return InspectionReview(list(plan.catalog_observations.all()))
