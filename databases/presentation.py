"""What a database plan's review shows beside the common plan facts (bootstrap.presentation)."""

from dataclasses import dataclass

from bootstrap.models import ConfigurationPlan

from .models import PlanDriverPool

AUTHORITY_TEXT = (
    "Viewing needs Barectl's permission to view database plans, preparing its permission to "
    "prepare them, and applying its permission to apply them; bootstrap and site permissions "
    "grant none of these. On the server, preparation read as root or through noninteractive "
    "sudo; applying needs the same for systemd-run."
)


@dataclass(frozen=True)
class DriverReview:
    pools: list[PlanDriverPool]
    authority: str = AUTHORITY_TEXT


def driver_review(plan: ConfigurationPlan) -> DriverReview:
    return DriverReview(list(plan.driver_pools.all()))
