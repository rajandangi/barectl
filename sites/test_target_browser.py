import tempfile
from typing import override

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from playwright.sync_api import expect

from dashboard.browser_testing import BrowserTestCase
from servers.models import Server
from sites.ui_testing import record_http_sites, record_shaped_sites, record_wordpress_sites


@tag("browser")
class HttpSiteBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    def test_keyboard_creation_keeps_the_edited_identifier_and_validation_focus(self) -> None:
        server = Server.objects.get(name="Production")
        record_http_sites(server)
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/sites/")
        link = self.page.get_by_role("link", name="Create a site on Production", exact=True)
        link.focus()
        self.page.keyboard.press("Enter")
        form = self.page.locator("#http-site-create")
        names = form.get_by_label("DNS names", exact=True)
        names.fill("shop.example.com")
        identifier = form.get_by_label("Site identifier", exact=True)
        expect(identifier).to_have_value("shop")
        identifier.fill("myshop")
        names.fill("second.example.com")
        expect(identifier).to_have_value("myshop")
        identifier.fill("apply")
        php = form.get_by_label("PHP runtime", exact=True)
        php.select_option("php85")
        expect(
            form.get_by_role("button", name="Step 1: install PHP 8.5", exact=True)
        ).to_be_visible()
        php.select_option("php84")
        button = form.get_by_role("button", name="Prepare HTTP site review", exact=True)
        button.focus()
        self.page.keyboard.press("Enter")
        expect(
            self.page.get_by_text("apply is reserved; choose another identifier.")
        ).to_be_visible()
        expect(
            self.page.get_by_role("heading", name="Create HTTP site", exact=True)
        ).to_be_focused()
        expect(form.get_by_label("Site identifier", exact=True)).to_have_value("apply")
        self.assertEqual(len(self.console_errors), 1)
        self.assertIn("status of 422", self.console_errors.pop())
        self.page.set_viewport_size({"width": 375, "height": 812})
        self.assert_theme_and_components_initialized()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )

    def test_operator_prepares_the_laravel_site_change_without_ssh(self) -> None:
        from unittest import mock

        from operations.services import read_changes

        server = Server.objects.get(name="Production")
        record_http_sites(server, engine="mariadb")
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/")
            form = self.page.locator("#laravel-site-create")
            form.get_by_label("Primary domain", exact=True).fill("shop.example.com")
            form.get_by_label("Repository", exact=True).fill("https://github.com/acme/shop.git")
            expect(form.get_by_label("Branch or tag", exact=True)).to_have_value("main")
            form.get_by_label("PHP runtime", exact=True).select_option("php84")
            button = form.get_by_role("button", name="Prepare Laravel site review", exact=True)
            button.focus()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role("heading", name="Create Laravel site: review", exact=True)
            ).to_be_visible()
        rows = read_changes(server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0].preparation.inputs,
            {
                "version": 1,
                "identifier": "shop",
                "names": ["shop.example.com"],
                "selection": "php84",
                "https": True,
                "repository": "https://github.com/acme/shop.git",
                "branch": "main",
            },
        )

    def test_operator_prepares_the_wordpress_site_change_in_five_fields(self) -> None:
        from unittest import mock

        from operations.services import read_changes

        server = Server.objects.get(name="Production")
        record_wordpress_sites(server)
        for codename in ("view_siteobservation", "view_changes", "change_site", "manage_secrets"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/")
            form = self.page.locator("#wordpress-site-create")
            form.get_by_label("Primary domain", exact=True).fill("shop.example.com")
            form.get_by_label("Site title", exact=True).fill("Shop")
            form.get_by_label("Administrator username", exact=True).fill("shopadmin")
            form.get_by_label("Administrator email", exact=True).fill("admin@example.com")
            form.get_by_label("PHP runtime", exact=True).select_option("php84")
            button = form.get_by_role("button", name="Prepare WordPress site review", exact=True)
            button.focus()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role("heading", name="Create WordPress site: review", exact=True)
            ).to_be_visible()
        rows = read_changes(server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0].preparation.inputs,
            {
                "version": 1,
                "identifier": "shop",
                "names": ["shop.example.com"],
                "selection": "php84",
                "https": True,
                "title": "Shop",
                "admin_username": "shopadmin",
                "admin_email": "admin@example.com",
            },
        )

    def test_operator_installs_a_missing_engine_first_and_keeps_the_create_answers(
        self,
    ) -> None:
        from unittest import mock

        from operations.services import read_changes
        from sites.ui_testing import record_step_run

        server = Server.objects.get(name="Production")
        record_wordpress_sites(server, engine="")
        for codename in ("view_siteobservation", "view_changes", "change_site", "manage_secrets"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        self.page.set_viewport_size({"width": 320, "height": 740})
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/")
            form = self.page.locator("#wordpress-site-create")
            expect(form.get_by_text("Step 1: install MariaDB on this server")).to_be_visible()
            form.get_by_label("Primary domain", exact=True).fill("shop.example.com")
            form.get_by_label("Site title", exact=True).fill("Shop")
            form.get_by_label("Administrator username", exact=True).fill("shopadmin")
            form.get_by_label("Administrator email", exact=True).fill("admin@example.com")
            form.get_by_label("PHP runtime", exact=True).select_option("php84")
            self.assertEqual(
                self.page.evaluate(
                    "document.documentElement.scrollWidth - document.documentElement.clientWidth"
                ),
                0,
            )
            step = form.get_by_role("button", name="Step 1: install MariaDB", exact=True)
            step.focus()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role("heading", name="Install database engine: review", exact=True)
            ).to_be_visible()
        rows = read_changes(server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].preparation.inputs, {"version": 1, "selection": "mariadb"})
        run = record_step_run(rows[0].preparation)
        # The worker's refresh observes MariaDB before the operator continues.
        record_wordpress_sites(server)
        self.page.goto(f"{self.live_server_url}/runs/{run.pk}/")
        expect(self.page.get_by_text("Step 1 is complete.")).to_be_visible()
        link = self.page.get_by_role("link", name="Continue creating the WordPress site")
        link.focus()
        self.page.keyboard.press("Enter")
        form = self.page.locator("#wordpress-site-create")
        expect(form.get_by_label("Primary domain", exact=True)).to_have_value("shop.example.com")
        expect(form.get_by_label("Site title", exact=True)).to_have_value("Shop")
        expect(form.get_by_label("Administrator email", exact=True)).to_have_value(
            "admin@example.com"
        )
        expect(form.get_by_label("PHP runtime", exact=True)).to_have_value("php84")
        self.assertEqual(
            self.page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            ),
            0,
        )
        button = form.get_by_role("button", name="Prepare WordPress site review", exact=True)
        button.focus()
        self.page.keyboard.press("Enter")
        expect(
            self.page.get_by_role("heading", name="Create WordPress site: review", exact=True)
        ).to_be_visible()
        rows = read_changes(server).rows
        self.assertEqual(rows[0].preparation.kind_slug, "create_wordpress_site")
        self.assertEqual(rows[0].preparation.inputs["title"], "Shop")
        self.assertEqual(rows[0].preparation.inputs["admin_email"], "admin@example.com")

    def test_operator_changes_domains_and_https_from_settings_with_a_keyboard(self) -> None:
        from unittest import mock

        from operations.services import read_changes

        server = Server.objects.get(name="Production")
        record_http_sites(server)
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/alpha/settings/")
            expect(
                self.page.get_by_role("heading", name="Domains and HTTPS", exact=True)
            ).to_be_visible()
            names = self.page.get_by_label("DNS names", exact=True)
            names.fill("alpha.example.com www.example.com")
            https = self.page.get_by_label("Serve over HTTPS", exact=True)
            expect(https).not_to_be_checked()
            https.check()
            expect(https).to_be_checked()
            button = self.page.get_by_role(
                "button", name="Prepare domains and HTTPS review", exact=True
            )
            button.focus()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role(
                    "heading", name="Change domains and HTTPS: review", exact=True
                )
            ).to_be_visible()
        rows = read_changes(server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0].preparation.inputs,
            {
                "version": 1,
                "identifier": "alpha",
                "names": ["alpha.example.com", "www.example.com"],
                "https": True,
            },
        )
        self.assert_theme_and_components_initialized()
        self.page.set_viewport_size({"width": 320, "height": 812})
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )
        self.assertEqual(self.console_errors, [])

    def test_overview_links_the_site_address_without_ssh(self) -> None:
        from unittest import mock

        server = Server.objects.get(name="Production")
        record_http_sites(server)
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/alpha/overview/")
            address = self.page.get_by_role("link", name="http://alpha.example.com")
            expect(address).to_be_visible()
            expect(address).to_have_attribute("href", "http://alpha.example.com")
        self.assert_theme_and_components_initialized()
        self.assertEqual(self.console_errors, [])

    def test_operator_resets_a_wordpress_password_through_the_confidential_channel(
        self,
    ) -> None:
        from unittest import mock

        from operations.services import read_changes

        server = Server.objects.get(name="Production")
        record_wordpress_sites(server)
        for codename in (
            "view_siteobservation",
            "view_changes",
            "change_site",
            "manage_secrets",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/overview/")
            self.page.get_by_role("link", name="WordPress", exact=True).click()
            expect(
                self.page.get_by_role("heading", name="Reset administrator password", exact=True)
            ).to_be_visible()
            self.page.get_by_label("Administrator username", exact=True).fill("shopadmin")
            button = self.page.get_by_role("button", name="Review password reset", exact=True)
            button.focus()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role(
                    "heading", name="Reset WordPress administrator password: review", exact=True
                )
            ).to_be_visible()
        rows = read_changes(server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0].preparation.inputs,
            {"version": 1, "identifier": "shop", "admin_username": "shopadmin"},
        )
        self.page.set_viewport_size({"width": 320, "height": 800})
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )
        self.assert_theme_and_components_initialized()
        self.assertEqual(self.console_errors, [])

    def test_attention_and_recognition_read_at_phone_width(self) -> None:
        server = Server.objects.get(name="Production")
        record_shaped_sites(server)
        self.user.user_permissions.add(Permission.objects.get(codename="view_siteobservation"))
        self.sign_in()
        self.page.set_viewport_size({"width": 375, "height": 812})
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/")
        attention = self.page.get_by_role("region", name="Needs attention")
        expect(attention.get_by_role("listitem")).to_have_count(5)
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )
        link = attention.get_by_role("link", name="Finish the runtime change", exact=True)
        link.focus()
        self.page.keyboard.press("Enter")
        expect(self.page).to_have_url(
            f"{self.live_server_url}/servers/{server.pk}/sites/delta/runtime/"
        )
        for tab, table in (("web", "Caddy site files"), ("php", "PHP-FPM site pools")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/stack/?tab={tab}")
            expect(self.page.get_by_role("table", name=table)).to_be_visible()
            self.assertEqual(
                self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
            )
        self.assert_theme_and_components_initialized()
        self.assertEqual(self.console_errors, [])

    def test_discovery_poll_leaves_the_creation_field_focused(self) -> None:
        from django.utils import timezone

        from discovery.fakes import record_attempt
        from discovery.models import DiscoveryAttempt

        server = Server.objects.get(name="Production")
        record_http_sites(server)
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        attempt = record_attempt(server, DiscoveryAttempt.Status.QUEUED)
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/")
        field = self.page.locator("#http-site-create").get_by_label("DNS names", exact=True)
        field.focus()
        with self.page.expect_response(lambda response: "/discovery/?" in response.url):
            attempt.status = DiscoveryAttempt.Status.FAILED
            attempt.finished_at = timezone.now()
            attempt.save(update_fields=("status", "finished_at"))
        expect(self.page.locator("#discovery")).not_to_have_attribute("hx-trigger", "every 2s")
        expect(field).to_be_focused()

    def test_operator_prepares_the_real_registered_site_change_without_ssh(self) -> None:
        from unittest import mock

        from operations.services import read_changes

        server = Server.objects.get(name="Production")
        record_http_sites(server)
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/")
            form = self.page.locator("#http-site-create")
            form.get_by_label("DNS names", exact=True).fill("shop.example.com www.shop.example.com")
            form.get_by_label("PHP runtime", exact=True).select_option("php84")
            expect(form.get_by_label("Serve over HTTP only", exact=True)).not_to_be_checked()
            button = form.get_by_role("button", name="Prepare HTTP site review", exact=True)
            button.focus()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role("heading", name="Create PHP site: review", exact=True)
            ).to_be_visible()
        rows = read_changes(server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0].preparation.inputs,
            {
                "version": 1,
                "identifier": "shop",
                "names": ["shop.example.com", "www.shop.example.com"],
                "selection": "php84",
                "https": True,
            },
        )
        expect(
            self.page.get_by_role("heading", name="Preparation queued", exact=True)
        ).to_be_visible()
