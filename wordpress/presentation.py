"""What a WP-CLI setup review shows beside the common plan facts."""

from dataclasses import dataclass
from datetime import datetime

from bootstrap.models import ConfigurationPlan
from databases.models import PlanDriverPool
from discovery.models import DatabaseEngine
from discovery.presentation import ShownSite

from . import install
from .models import (
    PlanRuntimeCapability,
    PlanWordpressInstall,
    PlanWordpressRuntime,
    PlanWpcliTool,
)


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


@dataclass(frozen=True)
class InstallReview:
    """What a WordPress installation review shows beside the common plan facts."""

    install: PlanWordpressInstall
    observed_at: datetime

    @property
    def password_step(self) -> str:
        """The terminal step that sets the first password (docs/wordpress.md#first-login)."""
        item = self.install
        return install.password_command(
            item.identifier, item.php_version, item.canonical_name, item.admin_login
        )

    @property
    def aliases(self) -> list[str]:
        return [name for name in self.install.names.split() if name != self.install.canonical_name]

    @property
    def authority(self) -> str:
        """docs/wordpress.md#review-permissions"""
        return (
            "Viewing this review needs the permission to view WordPress plans, preparing it "
            "the permission to prepare them, and installing from it the permission to install "
            "WordPress. Access to the site, its database, its certificate or the bootstrap "
            "plans grants none of these."
        )


def install_review(plan: ConfigurationPlan) -> InstallReview | None:
    review = getattr(plan, "wordpress_install", None)
    return None if review is None else InstallReview(review, plan.collected_at)


@dataclass(frozen=True)
class Prerequisite:
    """One prerequisite of an installation, as it was last observed and when."""

    label: str
    # "met", "unmet" or "unknown": unknown is evidence that is missing or not viewable.
    state: str
    text: str
    observed_at: datetime | None = None
    # Where the operator prepares an unmet prerequisite.
    url: str = ""
    link: str = ""

    @property
    def state_label(self) -> str:
        return {"met": "Observed", "unmet": "Not met", "unknown": "Not established"}[self.state]


def site_prerequisites(
    site: ShownSite,
    *,
    observed_at: datetime | None,
    runtime: tuple[PlanWordpressRuntime, tuple[PlanRuntimeCapability, ...], datetime] | None,
    tool: tuple[PlanWpcliTool, datetime] | None,
    plans_visible: bool,
    urls: dict[str, str],
) -> list[Prerequisite]:
    """The facts an installation stands on, each from its own latest observation.

    The review itself rereads every one of them; these tell the operator what to prepare
    first and when it was last seen. Plan-derived facts show only to accounts that may view
    those plans.
    """
    items = [
        Prerequisite(
            "Convention site",
            "met" if site.complete else "unmet",
            (
                f"Site {site.identifier} follows the site convention on PHP {site.php_version}"
                f" and serves {', '.join(site.domains)}."
                if site.complete
                else f"Site {site.identifier} is {site.verdict.lower()}."
            ),
            observed_at,
        ),
        _database(site, observed_at, urls),
        Prerequisite(
            "HTTPS",
            "met" if site.certificate.present else "unmet",
            (
                "A certificate is observed for this site."
                if site.certificate.present
                else "No certificate is observed for this site."
            ),
            observed_at,
            "" if site.certificate.present else urls["https"],
            "" if site.certificate.present else "Prepare the site's HTTPS",
        ),
    ]
    items.append(_runtime(runtime, plans_visible))
    items.append(_tool(tool, plans_visible, urls))
    return items


def _database(site: ShownSite, observed_at: datetime | None, urls: dict[str, str]) -> Prerequisite:
    engine = site.database_engine
    if engine == DatabaseEngine.MARIADB:
        return Prerequisite(
            "MariaDB binding",
            "met",
            "The MariaDB binding follows the database convention.",
            observed_at,
        )
    if engine is not None:
        return Prerequisite(
            "MariaDB binding",
            "unmet",
            f"The site has a {engine.label} binding. WordPress needs MariaDB, and Barectl "
            "converts no engine.",
            observed_at,
        )
    return Prerequisite(
        "MariaDB binding",
        "unmet",
        "No complete MariaDB binding is observed.",
        observed_at,
        urls["database"],
        "Prepare the site's MariaDB database",
    )


def _runtime(
    runtime: tuple[PlanWordpressRuntime, tuple[PlanRuntimeCapability, ...], datetime] | None,
    plans_visible: bool,
) -> Prerequisite:
    label = "PHP runtime"
    if not plans_visible:
        return Prerequisite(
            label, "unknown", "Needs the permission to view configuration plans to show."
        )
    if runtime is None:
        return Prerequisite(
            label, "unknown", "No runtime plan has read the selected CLI and PHP-FPM yet."
        )
    review, capabilities, at = runtime
    pending = [item for item in capabilities if item.state != item.State.ENABLED]
    if pending:
        return Prerequisite(
            label,
            "unmet",
            f"PHP {review.php_version}: {len(pending)} baseline capabilities are not yet "
            "enabled in both the CLI and PHP-FPM.",
            at,
        )
    return Prerequisite(
        label,
        "met",
        f"PHP {review.php_version}: every baseline capability loads in the CLI and PHP-FPM.",
        at,
    )


def _tool(
    tool: tuple[PlanWpcliTool, datetime] | None, plans_visible: bool, urls: dict[str, str]
) -> Prerequisite:
    label = "WP-CLI"
    if not plans_visible:
        return Prerequisite(
            label, "unknown", "Needs the permission to view configuration plans to show."
        )
    if tool is None:
        return Prerequisite(
            label,
            "unknown",
            "No setup review has read the tool yet.",
            None,
            urls["wpcli"],
            "Prepare the authenticated WP-CLI setup",
        )
    row, at = tool
    if row.exists:
        return Prerequisite(label, "met", f"WP-CLI {row.version} is installed.", at)
    return Prerequisite(
        label,
        "unmet",
        f"WP-CLI {row.version} is not installed.",
        at,
        urls["wpcli"],
        "Prepare the authenticated WP-CLI setup",
    )
