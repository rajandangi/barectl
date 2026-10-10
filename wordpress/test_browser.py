"""WordPress workflows from the dashboard in Chromium, against a simulated server, with the
production asset build and again with the Vite development server
(docs/v0.4-qualification.md#browser-journeys).

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

from bootstrap.fakes import WORDPRESS_DRIVERS, NativeSystemd, UbuntuServer
from bootstrap.models import Action, ConfigurationPlan
from dashboard.browser_testing import PASSWORD, BrowserTestCase, DevelopmentAssets
from databases.fakes import DatabaseServer
from discovery.fakes import FakeServer, add_site, mariadb_rows, run_worker
from discovery.services import request_discovery
from servers.models import Server
from sites.convention import Stage
from sites.fakes import SiteServer
from tls.fakes import TlsServer as TlsFakeServer

from . import qualification_testing, setup_native
from .fakes import ApplicationServer, WpcliServer


@tag("browser")
class ProductionWordpressBrowserTests(BrowserTestCase):
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
        """Run the worker while the page's polls of ``paths`` are held back, then release them.

        The polls would otherwise race the worker for the database; the next poll delivers
        what the worker recorded.
        """
        for path in paths:
            self.page.route(f"**{path}**", lambda route: route.fulfill(status=204))
        run_worker()
        for path in paths:
            self.page.unroute(f"**{path}**")

    def apply_with_keyboard(self) -> None:
        page = self.page
        apply = page.get_by_role("button", name=re.compile(r"^Apply plan \d+$"))
        apply.focus()
        self.assertNotEqual(self.css(".barectl-apply .usa-button:focus", "outline-style"), "none")
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Apply queued", level=2)).to_be_visible()

    def test_the_authenticated_wp_cli_tool_is_prepared_applied_and_verified(self) -> None:
        for codename in (
            "view_configurationplan",
            "prepare_configurationplan",
            "apply_configurationplan",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        remote = FakeServer()
        UbuntuServer().answer(remote)
        wpcli = WpcliServer()
        wpcli.answer(remote)
        systemd = NativeSystemd()
        systemd.answer(remote)
        systemd.on_submit = wpcli.install
        self.enterContext(remote.substituted())
        page = self.page
        self.sign_in()
        page.get_by_role("link", name="Production").click()
        page.get_by_role("navigation", name="Server sections").get_by_role(
            "link", name="Advanced", exact=True
        ).click()
        section = page.locator("#wordpress-plans")
        with page.expect_response(lambda response: response.url.endswith("/wp-cli/prepare/")):
            section.get_by_role("button", name="Prepare WP-CLI setup plan").click()
        self.work("/wordpress/?shown=")
        expect(section).to_contain_text("Ready for review", timeout=10_000)
        expect(section).to_contain_text(f"WP-CLI {setup_native.VERSION}")
        expect(section).to_contain_text(setup_native.FINGERPRINT)
        section.get_by_role("link", name=re.compile("Open this plan")).click()
        expect(page.locator("#apply-confirmation")).to_contain_text(
            re.compile(r"Apply plan \d+, WP-CLI tool setup, revision \d+, to Production")
        )
        # Preparing without the permission is refused before anything is queued.
        observer = get_user_model().objects.create_user("observer", password=PASSWORD)
        observer.user_permissions.add(Permission.objects.get(codename="view_server"))
        observer.user_permissions.add(Permission.objects.get(codename="view_configurationplan"))
        self.client.force_login(observer)
        server = Server.objects.get(name="Production")
        self.assertEqual(
            self.client.post(f"/servers/{server.pk}/wordpress/wp-cli/prepare/").status_code,
            403,
        )
        self.client.force_login(self.user)
        self.apply_with_keyboard()
        self.work("/status/")
        expect(page.get_by_role("heading", name="Applied and verified", level=2)).to_be_visible(
            timeout=10_000
        )
        audit = page.locator("#apply-audit")
        expect(audit).to_contain_text(f"Authenticate WP-CLI {setup_native.VERSION}")
        expect(audit).to_contain_text(f"Publish {setup_native.PHAR}")
        self.assertEqual(len(systemd.submissions), 1)
        self.assertEqual(len(self.console_errors), 0)

    def test_a_fresh_controller_shows_the_reconstructed_wordpress_application(self) -> None:
        for codename in ("view_siteobservation", "view_siteapplicationobservation"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        remote = FakeServer()
        add_site(remote, "alpha", ("alpha.test", "www.alpha.test"))
        remote.catalogs.mariadb["salpha"] = mariadb_rows("salpha")
        applications = ApplicationServer(remote)
        applications.as_root()
        applications.install("alpha", ("alpha.test", "www.alpha.test"))
        self.enterContext(remote.substituted())
        server = Server.objects.get(name="Production")
        request_discovery(server)
        run_worker()
        page = self.page
        self.sign_in()
        page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/alpha/overview/")
        nav = page.get_by_role("navigation", name="Site sections")
        link = nav.get_by_role("link", name="WordPress", exact=True)
        link.focus()
        page.keyboard.press("Enter")
        expect(link).to_have_attribute("aria-current", "page")
        section = page.get_by_role("region", name="WordPress application")
        expect(section).to_contain_text("Installed.")
        expect(section).to_contain_text("The qualified release.")
        expect(section).to_contain_text("All 12 core tables with their required columns")
        expect(section).to_contain_text("Collected")
        expect(section).to_contain_text("Barectl did not run WordPress, WP-CLI or any plugin")
        expect(section.get_by_role("button")).to_have_count(0)
        page.reload()
        expect(page.get_by_role("region", name="WordPress application")).to_be_visible()
        # The evidence needs its own permission: without it there is neither link nor page.
        observer = get_user_model().objects.create_user("observer", password=PASSWORD)
        for codename in ("view_server", "view_siteobservation"):
            observer.user_permissions.add(Permission.objects.get(codename=codename))
        self.client.force_login(observer)
        wordpress = f"/servers/{server.pk}/sites/alpha/wordpress/"
        self.assertEqual(self.client.get(wordpress).status_code, 403)
        self.assertNotContains(
            self.client.get(f"/servers/{server.pk}/sites/alpha/overview/"), wordpress
        )
        page.set_viewport_size({"width": 320, "height": 740})
        self.assertEqual(
            page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            ),
            0,
        )
        self.assertEqual(len(self.console_errors), 0)

    def test_the_wordpress_php_runtime_is_prepared_applied_and_verified_from_the_site(
        self,
    ) -> None:
        from discovery.models import SiteObservation

        for codename in (
            "view_siteobservation",
            "view_configurationplan",
            "prepare_configurationplan",
            "apply_configurationplan",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        remote = FakeServer()
        site = SiteServer()
        site.add_site("shop", ("shop.example.com",))
        site.answer(remote)
        systemd = NativeSystemd()
        systemd.answer(remote)

        def installed() -> None:
            site.drivers = WORDPRESS_DRIVERS
            site.answer(remote)

        systemd.on_submit = installed
        self.enterContext(remote.substituted())
        server = Server.objects.get(name="Production")
        request_discovery(server)
        run_worker()
        SiteObservation.objects.create(
            snapshot=server.snapshots.get(),
            identifier="shop",
            server_names="shop.example.com",
            php_version="8.5",
            state="managed",
            outcome="observed",
        )
        page = self.page
        self.sign_in()
        page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/wordpress/")
        section = page.locator("#site-wordpress-runtime")
        expect(section.get_by_role("heading", name="PHP runtime", level=2)).to_be_visible()
        expect(section).to_contain_text("PHP 8.5")
        expect(section).to_contain_text("No WordPress runtime plans for this site yet")
        expect(
            section.get_by_role("link", name="Prepare the site's MariaDB database")
        ).to_be_visible()
        prepare = section.get_by_role("button", name="Prepare WordPress PHP runtime plan")
        prepare.focus()
        with page.expect_response(lambda response: response.url.endswith("/runtime/prepare/")):
            page.keyboard.press("Enter")
        self.work("/wordpress/runtime/?shown=")
        expect(section).to_contain_text("Ready for review", timeout=10_000)
        table = section.get_by_role(
            "table", name="Baseline capabilities in the selected CLI and PHP-FPM"
        )
        expect(table).to_contain_text("MySQL database access (mysqli)")
        expect(table).to_contain_text("Installed by this plan")
        expect(section).to_contain_text("php8.5-gd")
        section.get_by_role("link", name=re.compile("Open this plan")).click()
        expect(page.locator("#apply-confirmation")).to_contain_text(
            re.compile(r"Apply plan \d+, WordPress PHP extensions, revision \d+, to Production")
        )
        page.wait_for_load_state("load")
        page.set_viewport_size({"width": 320, "height": 740})
        self.assertEqual(
            page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            ),
            0,
        )
        page.set_viewport_size({"width": 1280, "height": 720})
        # Viewing alone neither prepares nor applies.
        observer = get_user_model().objects.create_user("observer", password=PASSWORD)
        for codename in ("view_server", "view_siteobservation", "view_configurationplan"):
            observer.user_permissions.add(Permission.objects.get(codename=codename))
        self.client.force_login(observer)
        self.assertEqual(
            self.client.post(
                f"/servers/{server.pk}/sites/shop/wordpress/runtime/prepare/"
            ).status_code,
            403,
        )
        self.client.force_login(self.user)
        self.apply_with_keyboard()
        self.work("/status/")
        expect(page.get_by_role("heading", name="Applied and verified", level=2)).to_be_visible(
            timeout=10_000
        )
        audit = page.locator("#apply-audit")
        expect(audit).to_contain_text("Install php8.5-gd")
        expect(audit).to_contain_text("list every baseline capability")
        expect(audit).to_contain_text("temporary probe confirmed")
        self.assertEqual(len(systemd.submissions), 1)
        self.assertEqual(len(self.console_errors), 0)

    def test_a_wordpress_installation_is_reviewed_applied_and_completed_from_the_site(
        self,
    ) -> None:
        from discovery.models import (
            SiteCertificateObservation,
            SiteDatabaseObservation,
            SiteObservation,
        )
        from wordpress.fakes import InstallationServer, issued_lineage
        from wordpress.models import PlanWordpressInstall

        names = ("shop.example.com", "www.shop.example.com")
        for codename in (
            "view_siteobservation",
            "view_configurationplan",
            "view_wordpressplan",
            "prepare_wordpressplan",
            "install_wordpress",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        remote = FakeServer()
        site = SiteServer()
        site.add_site("shop", names)
        site.add_activated("shop", Stage.REDIRECT)
        site.drivers = WORDPRESS_DRIVERS
        database = DatabaseServer(site)
        database.satisfy("sshop")
        tls = TlsFakeServer(site)
        tls.production = issued_lineage(names)
        wpcli = WpcliServer()
        wpcli.install()
        state = InstallationServer()
        systemd = NativeSystemd()

        def applied() -> None:
            state.applied = True

        systemd.on_submit = applied
        for fake in (database, tls, wpcli, state, systemd):
            fake.answer(remote)
        self.enterContext(remote.substituted())
        server = Server.objects.get(name="Production")
        request_discovery(server)
        run_worker()
        observation = SiteObservation.objects.create(
            snapshot=server.snapshots.get(),
            identifier="shop",
            server_names="\n".join(names),
            php_version="8.5",
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
        page = self.page
        self.sign_in()
        page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/wordpress/")
        section = page.locator("#site-wordpress-install")
        expect(section.get_by_role("heading", name="Install WordPress", level=2)).to_be_visible()
        table = section.get_by_role("table", name="Prerequisites as last observed")
        expect(table).to_contain_text("Convention site")
        expect(table).to_contain_text("MariaDB binding")
        expect(table).to_contain_text("Observed.")
        expect(section).to_contain_text("Applying a review is a separate action")
        # An invalid request names its field and queues nothing.
        section.get_by_label("Canonical HTTPS name").fill("https://www.shop.example.com:8443/blog")
        section.get_by_label("Site title").fill("Shop & Sons")
        section.get_by_label("Administrator login").fill("owner")
        section.get_by_label("Administrator email").fill("owner@example.com")
        with page.expect_response(lambda response: response.url.endswith("/install/prepare/")):
            page.keyboard.press("Enter")
        expect(section).to_contain_text("Only the standard HTTPS port is supported")
        # The refused form is an ordinary 422 response, which the browser reports.
        self.assertIn("status of 422", self.console_errors.pop())
        self.assertEqual(PlanWordpressInstall.objects.count(), 0)
        section.get_by_label("Canonical HTTPS name").fill("www.shop.example.com")
        button = section.get_by_role("button", name="Prepare WordPress installation review")
        button.focus()
        with page.expect_response(lambda response: response.url.endswith("/install/prepare/")):
            page.keyboard.press("Enter")
        self.work("/wordpress/install/?shown=")
        expect(section).to_contain_text("Ready for review", timeout=10_000)
        expect(section).to_contain_text("https://www.shop.example.com/")
        expect(section).to_contain_text("Administrator password setup required")
        expect(section).to_contain_text("--prompt=user_pass --skip-email")
        expect(section).to_contain_text("never submitted twice")
        expect(section.get_by_role("button", name=re.compile(r"^Apply"))).to_have_count(0)
        section.get_by_role("link", name=re.compile("Open this plan")).click()
        expect(page.locator("#apply-confirmation")).to_contain_text(
            re.compile(r"Apply plan \d+, WordPress installation review, revision \d+, to Prod")
        )
        page.wait_for_load_state("load")
        page.set_viewport_size({"width": 320, "height": 740})
        self.assertEqual(
            page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            ),
            0,
        )
        page.set_viewport_size({"width": 1280, "height": 720})
        # Site, plan and bootstrap access alone neither prepare nor view a review.
        observer = get_user_model().objects.create_user("observer", password=PASSWORD)
        for codename in (
            "view_server",
            "view_siteobservation",
            "view_configurationplan",
            "prepare_configurationplan",
            "apply_configurationplan",
        ):
            observer.user_permissions.add(Permission.objects.get(codename=codename))
        self.client.force_login(observer)
        self.assertEqual(
            self.client.post(
                f"/servers/{server.pk}/sites/shop/wordpress/install/prepare/"
            ).status_code,
            403,
        )
        plan = ConfigurationPlan.objects.get(action=Action.WORDPRESS_INSTALL)
        self.assertEqual(self.client.get(f"/plans/{plan.pk}/").status_code, 403)
        self.assertEqual(self.client.post(f"/plans/{plan.pk}/apply/").status_code, 403)
        self.assertEqual(systemd.submissions, [])
        # The installer applies it with the keyboard and follows the run to its outcome.
        self.client.force_login(self.user)
        self.apply_with_keyboard()
        self.work("/status/")
        expect(page.get_by_role("heading", name="Applied and verified", level=2)).to_be_visible(
            timeout=10_000
        )
        completion = page.locator("#run-completion")
        expect(completion).to_contain_text("Administrator password setup required")
        expect(completion).to_contain_text("--prompt=user_pass --skip-email")
        expect(completion).to_contain_text("not a live health check")
        expect(completion.get_by_role("link", name="Home page")).to_have_attribute(
            "href", "https://www.shop.example.com/"
        )
        expect(completion.get_by_role("link", name="WordPress dashboard")).to_have_attribute(
            "href", "https://www.shop.example.com/wp-admin/"
        )
        audit = page.locator("#apply-audit")
        expect(audit).to_contain_text("Publish the provisioning gate")
        expect(audit).to_contain_text("Verified")
        self.assertEqual(len(systemd.submissions), 1)
        self.assertEqual(len(self.console_errors), 0)

    def test_a_partial_wordpress_installation_is_finished_from_the_site(self) -> None:
        from discovery.models import (
            SiteCertificateObservation,
            SiteDatabaseObservation,
            SiteObservation,
        )
        from sites.convention import Application
        from wordpress.fakes import issued_lineage
        from wordpress.finish_fakes import FinishServer
        from wordpress.models import PlanWordpressFinish

        names = ("shop.example.com", "www.shop.example.com")
        for codename in (
            "view_siteobservation",
            "view_configurationplan",
            "view_wordpressplan",
            "prepare_wordpressplan",
            "install_wordpress",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        remote = FakeServer()
        site = SiteServer()
        site.add_site("shop", names)
        site.add_activated("shop", Stage.REDIRECT, Application.WORDPRESS_GATE, names[1])
        site.drivers = WORDPRESS_DRIVERS
        database = DatabaseServer(site)
        database.satisfy("sshop")
        tls = TlsFakeServer(site)
        tls.production = issued_lineage(names)
        wpcli = WpcliServer()
        wpcli.install()
        state = FinishServer()
        state.leave("configuration")
        systemd = NativeSystemd()

        def applied() -> None:
            state.applied = True

        systemd.on_submit = applied
        for fake in (database, tls, wpcli, state, systemd):
            fake.answer(remote)
        self.enterContext(remote.substituted())
        server = Server.objects.get(name="Production")
        request_discovery(server)
        run_worker()
        observation = SiteObservation.objects.create(
            snapshot=server.snapshots.get(),
            identifier="shop",
            server_names="\n".join(names),
            php_version="8.5",
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
        page = self.page
        self.sign_in()
        page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/wordpress/")
        section = page.locator("#site-wordpress-finish")
        expect(
            section.get_by_role("heading", name="Finish a partial WordPress installation", level=2)
        ).to_be_visible()
        expect(section).to_contain_text("It needs no record of the earlier run")
        expect(section).to_contain_text("No Finish review for this site yet")
        # An invalid optional field names itself and queues nothing.
        section.get_by_label("Site title").fill("Shop & Sons")
        section.get_by_label("Administrator login").fill("A B")
        section.get_by_label("Administrator email").fill("owner@example.com")
        button = section.get_by_role("button", name="Prepare Finish review")
        button.focus()
        with page.expect_response(lambda response: response.url.endswith("/finish/prepare/")):
            page.keyboard.press("Enter")
        expect(section).to_contain_text("Enter 3 to 60")
        self.assertIn("status of 422", self.console_errors.pop())
        self.assertEqual(PlanWordpressFinish.objects.count(), 0)
        section.get_by_label("Administrator login").fill("owner")
        button.focus()
        with page.expect_response(lambda response: response.url.endswith("/finish/prepare/")):
            page.keyboard.press("Enter")
        self.work("/wordpress/finish/?shown=")
        expect(section).to_contain_text("Ready for review", timeout=10_000)
        expect(section).to_contain_text("https://www.shop.example.com/")
        expect(section).to_contain_text("Keeps the existing supported")
        expect(section).to_contain_text("Administrator password setup required")
        expect(section).to_contain_text("never submitted twice")
        expect(section.get_by_role("button", name=re.compile(r"^Apply"))).to_have_count(0)
        section.get_by_role("link", name=re.compile("Open this plan")).click()
        expect(page.locator("#apply-confirmation")).to_contain_text(
            re.compile(r"Apply plan \d+, WordPress installation Finish, revision \d+, to Prod")
        )
        page.wait_for_load_state("load")
        page.set_viewport_size({"width": 320, "height": 740})
        self.assertEqual(
            page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            ),
            0,
        )
        page.set_viewport_size({"width": 1280, "height": 720})
        # Installation-review access alone neither prepares nor applies a Finish.
        observer = get_user_model().objects.create_user("observer", password=PASSWORD)
        for codename in (
            "view_server",
            "view_siteobservation",
            "view_configurationplan",
            "prepare_configurationplan",
            "apply_configurationplan",
        ):
            observer.user_permissions.add(Permission.objects.get(codename=codename))
        self.client.force_login(observer)
        self.assertEqual(
            self.client.post(
                f"/servers/{server.pk}/sites/shop/wordpress/finish/prepare/"
            ).status_code,
            403,
        )
        plan = ConfigurationPlan.objects.get(action=Action.WORDPRESS_FINISH)
        self.assertEqual(self.client.get(f"/plans/{plan.pk}/").status_code, 403)
        self.assertEqual(self.client.post(f"/plans/{plan.pk}/apply/").status_code, 403)
        self.assertEqual(systemd.submissions, [])
        self.client.force_login(self.user)
        self.apply_with_keyboard()
        self.work("/status/")
        expect(page.get_by_role("heading", name="Applied and verified", level=2)).to_be_visible(
            timeout=10_000
        )
        completion = page.locator("#run-completion")
        expect(completion).to_contain_text("Administrator password setup required")
        expect(completion).to_contain_text("--prompt=user_pass --skip-email")
        expect(completion.get_by_role("link", name="WordPress dashboard")).to_have_attribute(
            "href", "https://www.shop.example.com/wp-admin/"
        )
        audit = page.locator("#apply-audit")
        expect(audit).to_contain_text("Verify that the provisioning gate")
        expect(audit).to_contain_text("Keep the existing loader")
        expect(audit).to_contain_text("Verified")
        self.assertEqual(len(systemd.submissions), 1)
        self.assertEqual(len(self.console_errors), 0)


@tag("browser")
class DevelopmentWordpressBrowserTests(DevelopmentAssets, ProductionWordpressBrowserTests):
    pass
