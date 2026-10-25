"""Server and site pages as an operator meets them (#372, docs/dashboard-workflows.md)."""

import tempfile
from typing import override

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from playwright.sync_api import expect

from servers.models import Server
from sites.ui_testing import record_http_sites

from .browser_testing import BrowserTestCase as BrowserTestCase


@tag("browser")
class ResourceLayoutBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    @override
    def setUp(self) -> None:
        super().setUp()
        for codename in (
            "view_siteobservation",
            "add_server",
            "add_discoveryattempt",
            "change_shared",
            "change_site",
            "view_changes",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.server = Server.objects.get(name="Production")
        record_http_sites(self.server)
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/servers/{self.server.pk}/")

    def test_server_page_opens_on_sites_with_one_status_line(self) -> None:
        page = self.page
        expect(page.get_by_role("heading", name="Production", level=1)).to_be_visible()
        expect(page.locator("#connection-status")).to_have_text("Ready")
        expect(page.get_by_role("link", name="Create site")).to_be_visible()
        current = page.locator("nav[aria-label='Server sections'] a[aria-current='page']")
        expect(current).to_have_text("Sites")
        self.assertEqual(
            page.locator(
                "main .usa-button:not(.usa-button--outline):not(.usa-button--unstyled)"
            ).count(),
            1,
        )
        self.assert_no_native_terms()

    def test_advanced_is_two_activations_from_the_server(self) -> None:
        page = self.page
        page.get_by_role("navigation", name="Server sections").get_by_role(
            "link", name="Advanced"
        ).click()
        expect(page.get_by_role("heading", name="Web stack and services")).to_be_visible()
        expect(page.get_by_text("Discovery history")).to_be_visible()

    def test_site_overview_shows_the_site_and_logs_hold_the_detail(self) -> None:
        page = self.page
        page.get_by_role("link", name="alpha.example.com").first.click()
        expect(page.get_by_role("heading", name="alpha.example.com", level=1)).to_be_visible()
        expect(page.get_by_role("link", name="http://alpha.example.com")).to_be_visible()
        expect(page.get_by_text("PHP version")).to_be_visible()
        expect(page.get_by_text("8.4")).to_be_visible()
        expect(page.get_by_text("Last checked")).to_be_visible()
        expect(page.get_by_text("/var/www/alpha/current/public")).to_be_visible()
        self.assert_no_native_terms(allowed=("caddy",))
        page.get_by_role("navigation", name="Site sections").get_by_role(
            "link", name="Logs"
        ).click()
        expect(page.get_by_role("heading", name="Installed runtime diagnostics")).to_be_visible()
        expect(page.get_by_text("Diagnostic master state")).to_be_visible()
        expect(page.get_by_text("Site file")).to_be_visible()

    def test_narrow_layout_and_keyboard_order(self) -> None:
        page = self.page
        page.set_viewport_size({"width": 320, "height": 740})
        self.assertEqual(
            page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            ),
            0,
        )
        page.set_viewport_size({"width": 1280, "height": 900})
        page.reload()
        page.get_by_role("navigation", name="Server sections").get_by_role(
            "link", name="Sites"
        ).focus()
        page.keyboard.press("Tab")
        expect(
            page.get_by_role("navigation", name="Server sections").get_by_role(
                "link", name="Activity"
            )
        ).to_be_focused()
