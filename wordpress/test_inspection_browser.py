"""An explicit WordPress inspection from the site page to its retained result, in Chromium
against the production asset build (docs/wordpress.md#inspecting-wordpress).

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

from . import inspection_fakes, qualification_testing
from .fakes import WpcliServer, issued_lineage
from .inspection_models import InspectionResult, Operation
from .inspection_testing import CANONICAL

NAMES = ("shop.example.com", CANONICAL)


@tag("browser")
class InspectionBrowserTests(BrowserTestCase):
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

    def serve(self) -> tuple[Server, NativeSystemd, inspection_fakes.InspectionServer]:
        for codename in (
            "view_siteobservation",
            "view_siteapplicationobservation",
            "view_configurationplan",
            "view_wordpressplan",
            "prepare_wordpressplan",
            "inspect_wordpress",
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
        application = inspection_fakes.InspectionServer(canonical=CANONICAL)
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

    def test_an_inspection_is_reviewed_applied_and_its_result_shown(self) -> None:
        server, systemd, application = self.serve()
        page = self.page
        self.sign_in()
        page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/wordpress/")
        passive = page.locator("#site-application-heading")
        expect(passive).to_be_visible()
        section = page.locator("#site-wordpress-inspection")
        expect(section.get_by_role("heading", name="Inspect WordPress", level=2)).to_be_visible()
        expect(section).to_contain_text("This is an explicit operation, not passive evidence.")
        expect(section).to_contain_text("Use it to find core files that differ")
        # Choose the diagnostic with the keyboard and prepare its review.
        core = section.get_by_label("Verify core checksums")
        core.focus()
        page.keyboard.press("Space")
        expect(core).to_be_checked()
        button = section.get_by_role("button", name="Prepare WordPress inspection review")
        button.focus()
        with page.expect_response(lambda response: response.url.endswith("/inspection/prepare/")):
            page.keyboard.press("Enter")
        self.work("/wordpress/inspection/?shown=")
        expect(section).to_contain_text("Ready for review", timeout=10_000)
        expect(section).to_contain_text("wp core verify-checksums")
        expect(section).to_contain_text("runs before WordPress loads")
        expect(section.get_by_role("button", name=re.compile(r"^Apply"))).to_have_count(0)
        section.get_by_role("link", name=re.compile("Open this plan")).click()
        expect(page.locator("#apply-confirmation")).to_contain_text(
            re.compile(r"Apply plan \d+, WordPress inspection, revision \d+, to Production")
        )
        page.set_viewport_size({"width": 320, "height": 740})
        self.assertEqual(
            page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            ),
            0,
        )
        page.set_viewport_size({"width": 1280, "height": 720})
        # Site, plan and passive-evidence access alone neither prepare nor run an inspection.
        observer = get_user_model().objects.create_user("observer", password=PASSWORD)
        for codename in (
            "view_server",
            "view_siteobservation",
            "view_siteapplicationobservation",
            "view_configurationplan",
            "prepare_configurationplan",
            "apply_configurationplan",
        ):
            observer.user_permissions.add(Permission.objects.get(codename=codename))
        self.client.force_login(observer)
        self.assertEqual(
            self.client.post(
                f"/servers/{server.pk}/sites/shop/wordpress/inspection/prepare/"
            ).status_code,
            403,
        )
        plan = ConfigurationPlan.objects.get(action=Action.WORDPRESS_INSPECT)
        self.assertEqual(self.client.get(f"/plans/{plan.pk}/").status_code, 403)
        self.assertEqual(self.client.post(f"/plans/{plan.pk}/apply/").status_code, 403)
        self.assertEqual(systemd.submissions, [])
        # The inspector applies it with the keyboard and follows the run to its outcome.
        self.client.force_login(self.user)
        application.records[Operation.CORE] = inspection_fakes.project(
            Operation.CORE,
            inspection_fakes.core_outputs(
                1,
                "",
                "Warning: File doesn't verify against checksum: wp-includes/load.php\n"
                "Error: WordPress installation doesn't verify against checksums.\n",
            ),
            "7.1.3",
        )
        apply = page.get_by_role("button", name=re.compile(r"^Apply plan \d+$"))
        apply.focus()
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Apply queued", level=2)).to_be_visible()
        self.work("/status/")
        expect(page.get_by_role("heading", name="Applied and verified", level=2)).to_be_visible(
            timeout=10_000
        )
        result = page.locator("#inspection-result")
        expect(result).to_contain_text("Result: Verify core checksums")
        verdict = result.locator("#inspection-core-verdict")
        expect(verdict).to_contain_text("Differs from the official checksums")
        expect(verdict).to_contain_text("evidence to investigate, not proof of compromise")
        expect(result).to_contain_text("wp-includes/load.php")
        expect(result).to_contain_text("(server clock)")
        expect(page.locator("#apply-audit")).to_contain_text("Run WP-CLI 2.12.0 as sshop")
        self.assertEqual(len(systemd.submissions), 1)
        run = ApplyRun.objects.get()
        self.assertEqual(InspectionResult.objects.get(run=run).integrity, "mismatch")
        # The site page shows the retained result apart from the passive evidence.
        self.observe(server)
        page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/wordpress/")
        expect(page.locator("#site-wordpress-inspection")).to_contain_text(
            "Latest explicit inspection result"
        )
        self.assertEqual(len(self.console_errors), 0)


@tag("browser")
class DevelopmentInspectionBrowserTests(DevelopmentAssets, InspectionBrowserTests):
    pass
