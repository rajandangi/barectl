import tempfile
from typing import override

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from playwright.sync_api import expect

from dashboard.browser_testing import BrowserTestCase
from servers.models import Server
from sites.ui_testing import record_http_sites, record_shaped_sites


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
        form.get_by_label("PHP runtime", exact=True).select_option("php84")
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
        record_http_sites(server)
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
