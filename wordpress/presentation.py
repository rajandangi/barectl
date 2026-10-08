"""What a WP-CLI setup review shows beside the common plan facts."""

from dataclasses import dataclass

from bootstrap.models import ConfigurationPlan

from .models import PlanWpcliTool


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
