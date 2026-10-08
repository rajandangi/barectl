"""What a WP-CLI setup review shows beside the common plan facts."""

from dataclasses import dataclass
from datetime import datetime

from bootstrap.models import ConfigurationPlan
from databases.models import PlanDriverPool

from .models import PlanRuntimeCapability, PlanWordpressRuntime, PlanWpcliTool


@dataclass(frozen=True)
class SetupReview:
    tool: PlanWpcliTool

    @property
    def authority(self) -> str:
        """docs/wordpress.md#permissions"""
        return (
            "The tool setup uses Barectl's bootstrap permissions: viewing needs the "
            "permission to view configuration plans, preparing its permission to prepare "
            "them, and applying its permission to apply them. None of these grants any "
            "WordPress execution, which later workflows guard separately."
        )


def setup_review(plan: ConfigurationPlan) -> SetupReview | None:
    tool = getattr(plan, "wpcli_tool", None)
    return None if tool is None else SetupReview(tool)


@dataclass(frozen=True)
class RuntimeReview:
    """What a WordPress PHP runtime review shows beside the common plan facts."""

    runtime: PlanWordpressRuntime
    capabilities: tuple[PlanRuntimeCapability, ...]
    observed_at: datetime
    pools: tuple[PlanDriverPool, ...]

    @property
    def authority(self) -> str:
        """docs/wordpress.md#permissions"""
        return (
            "The runtime plan uses Barectl's bootstrap permissions: viewing needs the "
            "permission to view configuration plans, preparing its permission to prepare "
            "them, and applying its permission to apply them. None of these grants any "
            "WordPress execution, which later workflows guard separately."
        )

    @property
    def planned(self) -> tuple[PlanRuntimeCapability, ...]:
        return tuple(item for item in self.capabilities if item.state == item.State.PLANNED)


def runtime_review(plan: ConfigurationPlan) -> RuntimeReview | None:
    review = getattr(plan, "wordpress_runtime", None)
    if review is None:
        return None
    return RuntimeReview(
        review,
        tuple(plan.runtime_capabilities.all()),
        plan.collected_at,
        tuple(plan.driver_pools.all()),
    )
