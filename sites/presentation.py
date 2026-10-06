"""What a site plan's review shows beside the common plan facts (bootstrap.presentation)."""

from dataclasses import dataclass

from django.core.exceptions import ObjectDoesNotExist

from bootstrap.models import ConfigurationPlan

from .models import PlanAccountChange, PlanDirectoryChange, PlanFileChange, PlanSite


@dataclass(frozen=True)
class SiteReview:
    site: PlanSite
    names: list[str]
    files: list[PlanFileChange]
    directories: list[PlanDirectoryChange]
    account: PlanAccountChange | None

    @property
    def authority(self) -> str:
        """docs/sites.md#permissions"""
        return (
            "Viewing needs Barectl's permission to view site plans, preparing its permission "
            "to prepare them, and applying its permission to apply them; bootstrap "
            "permissions grant none of these. On the server, preparation read as root or "
            "through noninteractive sudo; applying needs the same for systemd-run and for "
            "the read that verifies the site afterwards."
        )


def site_review(plan: ConfigurationPlan) -> SiteReview | None:
    try:
        site = plan.site
    except ObjectDoesNotExist:
        return None
    try:
        account: PlanAccountChange | None = plan.site_account
    except ObjectDoesNotExist:
        account = None
    return SiteReview(
        site,
        [item.name for item in plan.site_names.all()],
        list(plan.site_files.filter(preimage_absent=True)),
        list(plan.site_directories.all()),
        account,
    )
