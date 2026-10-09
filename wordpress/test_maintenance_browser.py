"""WordPress maintenance from the site page to its retained result, in Chromium against the
production asset build (docs/wordpress.md#maintaining-wordpress).

Real views, the worker, persistence and rendering run; only remote execution is simulated.
"""

import re
import tempfile
from typing import override

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from playwright.sync_api import expect

from bootstrap.fakes import WORDPRESS_DRIVERS, NativeSystemd
from bootstrap.models import Action, ApplyRun, ConfigurationPlan
from dashboard.browser_testing import PASSWORD, BrowserTestCase, DevelopmentAssets
from databases.fakes import DatabaseServer
from discovery.fakes import FakeServer, run_worker
from discovery.models import (
    SiteCertificateObservation,
    SiteDatabaseObservation,
    SiteObservation,
)
from discovery.services import request_discovery
from servers.models import Server
from sites.convention import Application, Stage
from sites.fakes import SiteServer
from tls.fakes import TlsServer

from . import maintenance_fakes, qualification_testing
from .fakes import WpcliServer, issued_lineage
from .inspection_testing import CANONICAL
from .maintenance_models import MaintenanceResult, Operation

NAMES = ("shop.example.com", CANONICAL)


@tag("browser")
class MaintenanceBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    @override
    def setUp(self) -> None:
        super().setUp()
        self.enterContext(qualification_testing.simulated_servers_qualified())

    def work(self, *paths: str) -> None:
        """Run the worker while the page's polls of ``paths`` are held back."""
        for path in paths:
            self.page.route(f"**{path}**", lambda route: route.fulfill(status=204))
        run_worker()
        for path in paths:
            self.page.unroute(f"**{path}**")

    def serve(self) -> tuple[Server, NativeSystemd, maintenance_fakes.MaintenanceServer]:
        for codename in (
            "view_siteobservation",
            "view_siteapplicationobservation",
            "view_configurationplan",
            "view_wordpressplan",
            "prepare_wordpressplan",
            "maintain_wordpress",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        remote = FakeServer()
        site = SiteServer()
        site.add_site("shop", NAMES)
        site.add_activated("shop", Stage.REDIRECT, Application.WORDPRESS, CANONICAL)
        site.drivers = WORDPRESS_DRIVERS
        database = DatabaseServer(site)
        database.satisfy("sshop")
        tls = TlsServer(site)
        tls.production = issued_lineage(NAMES)
        wpcli = WpcliServer()
        wpcli.install()
        application = maintenance_fakes.MaintenanceServer(canonical=CANONICAL)
        systemd = NativeSystemd()
        for fake in (database, tls, wpcli, application, systemd):
            fake.answer(remote)
        self.enterContext(remote.substituted())
        server = Server.objects.get(name="Production")
        request_discovery(server)
        run_worker()
        self.observe(server)
        return server, systemd, application

    def observe(self, server: Server) -> None:
        """Record the site in the server's latest snapshot, as a connection check would."""
        snapshot = server.snapshots.order_by("-collected_at", "-pk").first()
        if snapshot is None:
            raise AssertionError("The server has no snapshot.")
        observation = SiteObservation.objects.create(
            snapshot=snapshot,
            identifier="shop",
            server_names="\n".join(NAMES),
            php_version="8.3",
            state="managed",
            outcome="observed",
            stage="redirect",
        )
        SiteDatabaseObservation.objects.create(
            site=observation, engine="mariadb", status="observed", conforms=True, source=""
        )
        SiteCertificateObservation.objects.create(
            site=observation, status="observed", conforms=True, source=""
        )

    def prepare(self, operation_label: str, shown: str) -> None:
        page = self.page
        section = page.locator("#site-wordpress-maintenance")
        choice = section.get_by_label(operation_label)
        choice.focus()
        page.keyboard.press("Space")
        expect(choice).to_be_checked()
        button = section.get_by_role("button", name="Prepare WordPress maintenance review")
        button.focus()
        with page.expect_response(lambda response: response.url.endswith("/maintenance/prepare/")):
            page.keyboard.press("Enter")
        self.work("/wordpress/maintenance/?shown=")
        expect(section).to_contain_text("Ready for review", timeout=10_000)
        expect(section).to_contain_text(shown)

    def test_maintenance_is_reviewed_applied_and_its_result_shown(self) -> None:
        server, systemd, application = self.serve()
        page = self.page
        self.sign_in()
        page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/wordpress/")
        section = page.locator("#site-wordpress-maintenance")
        expect(section.get_by_role("heading", name="Maintain WordPress", level=2)).to_be_visible()
        expect(section).to_contain_text("Maintenance runs WordPress and changes application state.")
        expect(section).to_contain_text("is not a live-site cache repair")
        # The cache flush is reviewed with its honest default, and offers no live-site claim.
        self.prepare("Flush object cache", "wp cache flush")
        expect(section).to_contain_text("clears the cache of its own command-line process")
        expect(section.get_by_role("button", name=re.compile(r"^Apply"))).to_have_count(0)
        # The soft rewrite flush is reviewed with its application-hook effects.
        self.prepare("Flush rewrite rules", "wp rewrite flush")
        expect(section).to_contain_text("skip flags deliberately left off")
        expect(section).to_contain_text("loader.php")
        section.get_by_role("link", name=re.compile("Open this plan")).click()
        expect(page.locator("#apply-confirmation")).to_contain_text(
            re.compile(r"Apply plan \d+, WordPress maintenance, revision \d+, to Production")
        )
        page.set_viewport_size({"width": 320, "height": 740})
        self.assertEqual(
            page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            ),
            0,
        )
        page.set_viewport_size({"width": 1280, "height": 720})
        # Inspection, installation and plan access alone neither prepare nor run maintenance.
        observer = get_user_model().objects.create_user("observer", password=PASSWORD)
        for codename in (
            "view_server",
            "view_siteobservation",
            "view_wordpressplan",
            "prepare_wordpressplan",
            "inspect_wordpress",
            "install_wordpress",
            "view_configurationplan",
            "apply_configurationplan",
        ):
            observer.user_permissions.add(Permission.objects.get(codename=codename))
        self.client.force_login(observer)
        plan = ConfigurationPlan.objects.filter(action=Action.WORDPRESS_MAINTAIN).latest("pk")
        self.assertEqual(self.client.post(f"/plans/{plan.pk}/apply/").status_code, 403)
        self.assertEqual(systemd.submissions, [])
        # The maintainer applies it with the keyboard and follows the run to its outcome.
        self.client.force_login(self.user)
        application.records[Operation.REWRITE] = maintenance_fakes.project(
            Operation.REWRITE, maintenance_fakes.REWRITE_EMPTY
        )
        apply = page.get_by_role("button", name=re.compile(r"^Apply plan \d+$"))
        apply.focus()
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Apply queued", level=2)).to_be_visible()
        self.work("/status/")
        expect(page.get_by_role("heading", name="Applied and verified", level=2)).to_be_visible(
            timeout=10_000
        )
        result = page.locator("#maintenance-result")
        expect(result).to_contain_text("Result: Flush rewrite rules")
        expect(result.locator("#maintenance-rewrite-outcome")).to_contain_text(
            "WordPress stores no rewrite rules"
        )
        expect(result).to_contain_text("(server clock)")
        expect(page.locator("#apply-audit")).to_contain_text("Run WP-CLI 2.12.0 as sshop")
        self.assertEqual(len(systemd.submissions), 1)
        run = ApplyRun.objects.get()
        self.assertEqual(MaintenanceResult.objects.get(run=run).rules, "empty")
        # The site page shows the retained result.
        self.observe(server)
        page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/wordpress/")
        expect(page.locator("#site-wordpress-maintenance")).to_contain_text(
            "Latest maintenance result"
        )
        self.assertEqual(len(self.console_errors), 0)


@tag("browser")
class DevelopmentMaintenanceBrowserTests(DevelopmentAssets, MaintenanceBrowserTests):
    pass
