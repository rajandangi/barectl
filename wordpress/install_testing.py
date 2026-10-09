"""A prepared site for the WordPress installation review's tests (docs/wordpress.md).

The simulated server answers every workflow the review stands on: a complete convention
site with HTTPS, a satisfied MariaDB binding, the WordPress runtime baseline, WP-CLI and
the review's own fixed reads.
"""

from dataclasses import replace
from typing import override

from django.utils import timezone

from bootstrap.fakes import WORDPRESS_DRIVERS
from bootstrap.models import ConfigurationPlan, PlanPreparation
from databases.fakes import DatabaseServer
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import (
    DatabaseEngine,
    DiscoveryAttempt,
    ObservationOutcome,
    SiteStage,
    SiteState,
    WebStackComponent,
)
from discovery.snapshot import (
    Observation,
    ObservedCertificate,
    ObservedDatabase,
    ObservedSite,
    Package,
    SiteAccount,
    WebStackComponentObservation,
    save_snapshot,
)
from servers.testing import HTMX_FRAGMENT
from sites.convention import Stage
from sites.fakes import SiteTestCase
from tls.fakes import NAMES, TlsServer

from .fakes import InstallationServer, WpcliServer, issued_lineage

VIEW = ("view_server", "view_siteobservation", "view_wordpressplan")
PREPARE = (*VIEW, "prepare_wordpressplan")
FORM = {
    "wordpress-canonical_name": "www.shop.example.com",
    "wordpress-title": "Shop & Sons",
    "wordpress-admin_login": "owner",
    "wordpress-admin_email": "owner@example.com",
}
ADDRESS = "/servers/{pk}/sites/shop/wordpress/install/prepare/"
POLL = "/servers/{pk}/sites/shop/wordpress/install/"


class InstallTestCase(SiteTestCase):
    """A complete convention site shop with HTTPS, a satisfied MariaDB binding, the WordPress
    runtime baseline and WP-CLI, ready for an installation review."""

    tls: TlsServer
    database: DatabaseServer
    wpcli: WpcliServer
    state: InstallationServer

    @override
    def setUp(self) -> None:
        super().setUp()
        self.site.add_site("shop", NAMES)
        self.site.add_activated("shop", Stage.REDIRECT)
        self.site.drivers = WORDPRESS_DRIVERS
        self.database = DatabaseServer(self.site)
        self.database.satisfy("sshop")
        self.tls = TlsServer(self.site)
        self.tls.production = issued_lineage(NAMES)
        self.wpcli = WpcliServer()
        self.wpcli.install()
        self.state = InstallationServer()
        self.record_php_snapshot()

    @override
    def record_php_snapshot(self) -> None:
        attempt = record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED)
        component = WebStackComponentObservation(
            WebStackComponent.PHP_FPM,
            Observation(
                ObservationOutcome.OBSERVED,
                ("dpkg-query",),
                "",
                (Package(f"php{self.site.php}-fpm", self.packaging.php_version),),
            ),
            Observation(ObservationOutcome.OBSERVED, ("systemctl",), "", ()),
        )
        sites: tuple[ObservedSite, ...] = ()
        if getattr(self, "state", None) is not None and "shop" in self.site.sites:
            sites = (
                ObservedSite(
                    "shop",
                    NAMES,
                    self.site.php,
                    SiteAccount(1003, 1003, "/var/www/shop", "/usr/sbin/nologin"),
                    SiteState.MANAGED,
                    ObservationOutcome.OBSERVED,
                    database=ObservedDatabase(
                        DatabaseEngine.MARIADB, ObservationOutcome.OBSERVED, conforms=True
                    ),
                    stage=SiteStage.REDIRECT,
                    certificate=ObservedCertificate(ObservationOutcome.OBSERVED, conforms=True),
                ),
            )
        collected = replace(
            COLLECTED,
            components=(*COLLECTED.components, component),
            sites=Observation(ObservationOutcome.OBSERVED, (), "", sites),
        )
        save_snapshot(attempt, collected, timezone.now())

    def sign_in_as(self, *codenames: str) -> None:
        """Sign in with exactly ``codenames``, dropping the permissions earlier steps gave."""
        self.user.user_permissions.clear()
        self.sign_in_with(*codenames)

    def answer_all(self) -> None:
        self.database.answer(self.remote)
        self.tls.answer(self.remote)
        self.wpcli.answer(self.remote)
        self.state.answer(self.remote)

    @override
    def assert_read_only(self) -> None:
        from bootstrap.fakes import PREPARATION_READ_ONLY
        from databases.fakes import database_read_only
        from discovery.fakes import READ_ONLY
        from sites.fakes import site_read_only

        from .fakes import wpcli_read_only

        for command in self.remote.commands:
            self.assertTrue(
                READ_ONLY.fullmatch(command)
                or PREPARATION_READ_ONLY.fullmatch(command)
                or site_read_only(command)
                or database_read_only(command)
                or wpcli_read_only(command)
                or self.state.owns(command)
                or self.tls_read(command),
                f"Not a read-only command: {command}",
            )

    def tls_read(self, command: str) -> bool:
        """TLS' fixed lineage reads, which only open certificates."""
        return "openssl x509" in command and "-noout" in command

    def review(
        self, form: dict[str, str] | None = None, *, perms: tuple[str, ...] = PREPARE
    ) -> PlanPreparation:
        self.sign_in_with(*perms)
        self.answer_all()
        response = self.client.post(
            ADDRESS.format(pk=self.server.pk), form or FORM, headers=HTMX_FRAGMENT
        )
        self.assertEqual(response.status_code, 200)
        self.run_worker()
        return PlanPreparation.objects.latest("queued_at", "pk")

    def reviewed(self, form: dict[str, str] | None = None) -> ConfigurationPlan:
        preparation = self.review(form)
        plan = ConfigurationPlan.objects.filter(preparation=preparation).first()
        if plan is None:
            raise AssertionError(f"No plan: {preparation.status} {preparation.failure}")
        return plan

    def texts(self, plan: ConfigurationPlan) -> str:
        return " ".join(plan.refusals.values_list("text", flat=True))
