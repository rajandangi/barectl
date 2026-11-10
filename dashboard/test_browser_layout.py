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
            "view_evidence",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.server = Server.objects.get(name="Production")
        self.server.address = "203.0.113.10"
        self.server.save(update_fields=["address"])
        record_http_sites(self.server)
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/servers/{self.server.pk}/")

    def test_server_page_opens_on_sites_with_one_status_line(self) -> None:
        page = self.page
        expect(page.get_by_role("heading", name="Production", level=1)).to_be_visible()
        expect(page.locator("#connection-status")).to_have_text("Ready")
        summary = page.get_by_role("region", name="Server details", exact=True)
        expect(summary).to_be_visible()
        expect(summary).to_contain_text("Ubuntu 26.04.1 LTS")
        expect(summary).to_contain_text("Memory")
        expect(summary).to_contain_text("Storage")
        summary_box = summary.bounding_box()
        navigation_box = page.get_by_role("navigation", name="Server sections").bounding_box()
        if summary_box is None or navigation_box is None:
            self.fail("The server summary and navigation must be visible.")
        self.assertLess(summary_box["y"] + summary_box["height"], navigation_box["y"])
        self.context.grant_permissions(["clipboard-read", "clipboard-write"])
        copy_address = page.get_by_role("button", name="Copy server address", exact=True)
        copy_address.focus()
        page.keyboard.press("Enter")
        expect(page.get_by_role("status").filter(has_text="Address copied")).to_be_visible()
        self.assertEqual(page.evaluate("navigator.clipboard.readText()"), "203.0.113.10")
        page.evaluate(
            "() => { navigator.clipboard.writeText = "
            "() => Promise.reject(new DOMException('Denied')); }"
        )
        copy_address.click()
        expect(page.get_by_role("status").filter(has_text="copy it manually")).to_be_visible()
        self.assertEqual(page.evaluate("window.getSelection().toString()"), "203.0.113.10")
        expect(page.get_by_role("link", name="Create site")).to_be_visible()
        current = page.locator("nav[aria-label='Server sections'] a[aria-current='page']")
        expect(current).to_have_text("Sites")
        expect(current).to_have_css("display", "block")
        expect(current).to_have_css("font-weight", "700")
        expect(page.locator("nav[aria-label='Server sections'] .usa-sidenav")).to_have_css(
            "list-style-type", "none"
        )
        self.assertEqual(
            page.locator(
                "main .usa-button:not(.usa-button--outline):not(.usa-button--unstyled)"
            ).count(),
            1,
        )
        self.assert_no_native_terms()
        self.user.user_permissions.add(Permission.objects.get(codename="change_server"))
        page.get_by_role("navigation", name="Primary").get_by_role(
            "link", name="Servers", exact=True
        ).click()
        expect(page.get_by_role("columnheader", name="Actions", exact=True)).to_be_visible()
        row = page.get_by_role("row").filter(has_text="Production")
        expect(row).to_contain_text("203.0.113.10")
        expect(row).to_contain_text("3.8 GB")
        expect(row).to_contain_text("50.0 GB")
        page.get_by_role("link", name="Edit connection for Production", exact=True).click()
        expect(page.get_by_role("heading", name="Edit Production", level=1)).to_be_visible()
        page.get_by_role("link", name="Cancel", exact=True).click()
        expect(page.get_by_role("heading", name="Servers", level=1)).to_be_visible()
        frame = page.locator(".barectl-server-list")
        expect(frame).to_have_css("border-top-width", "1px")
        expect(frame).to_have_css("overflow", "clip")
        page.set_viewport_size({"width": 320, "height": 800})
        expect(row.get_by_text("Root disk", exact=True)).to_be_visible()
        expect(row.get_by_role("rowheader")).to_have_css("padding-top", "0px")
        expect(row.get_by_role("rowheader")).to_have_css("border-top-width", "0px")
        expect(row.get_by_role("link", name="Edit connection for Production")).to_be_visible()
        self.assertEqual(
            page.evaluate("document.documentElement.scrollWidth"),
            page.evaluate("window.innerWidth"),
        )

    def test_advanced_is_two_activations_from_the_server(self) -> None:
        page = self.page
        page.evaluate("window.barectlNavigationTest = 'same-document'")
        advanced = page.get_by_role("navigation", name="Server sections").get_by_role(
            "link", name="Advanced"
        )
        advanced.focus()
        page.keyboard.press("Enter")
        expect(page.get_by_role("region", name="Server details", exact=True)).to_be_visible()
        expect(page.get_by_role("heading", name="Web stack and services")).to_be_visible()
        self.assertEqual(page.evaluate("window.barectlNavigationTest"), "same-document")
        expect(advanced).to_be_focused()
        expect(page.get_by_text("Discovery history")).to_be_visible()
        evidence = page.get_by_role("button", name="Host checks", exact=True)
        expect(evidence).to_have_attribute("aria-expanded", "false")
        expect(page.locator("#advanced-host-evidence")).to_be_hidden()
        evidence.focus()
        page.keyboard.press("Enter")
        expect(page.locator("#advanced-host-evidence")).to_be_visible()
        expect(evidence).to_have_attribute("aria-expanded", "true")
        expect(page.get_by_text("Connection record", exact=True)).to_have_count(0)
        expect(page.get_by_text("Commands used", exact=True)).to_have_count(0)
        page.evaluate("window.barectlStackTest = 'same-page'")
        for label, key in (
            ("Services", "services"),
            ("PHP versions", "php"),
            ("Software catalog", "catalog"),
            ("Web server", "web"),
        ):
            link = page.get_by_role("navigation", name="Stack sections").get_by_role(
                "link", name=label, exact=True
            )
            link.focus()
            page.keyboard.press("Enter")
            expect(link).to_have_attribute("aria-current", "page")
            expect(link).to_be_focused()
            expect(page).to_have_url(
                f"{self.live_server_url}/servers/{self.server.pk}/advanced/?tab={key}"
            )
            self.assertEqual(page.evaluate("window.barectlStackTest"), "same-page")
            expect(page.locator("#advanced-host-evidence")).to_be_visible()
        page.get_by_role("button", name="Discovery history", exact=True).click()
        expect(page.locator("#discovery-history-content")).to_be_visible()
        page.set_viewport_size({"width": 320, "height": 740})
        self.assertEqual(
            page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            ),
            0,
        )

    def test_site_overview_shows_the_site_and_logs_hold_the_detail(self) -> None:
        page = self.page
        page.get_by_role("link", name="alpha.example.com").first.click()
        expect(page.get_by_role("heading", name="alpha.example.com", level=1)).to_be_visible()
        current = page.locator("nav[aria-label='Site sections'] a[aria-current='page']")
        expect(current).to_have_css("display", "block")
        expect(current).to_have_css("font-weight", "700")
        expect(page.get_by_role("link", name="http://alpha.example.com")).to_be_visible()
        expect(page.get_by_text("PHP version")).to_be_visible()
        expect(page.get_by_text("8.4")).to_be_visible()
        expect(page.get_by_text("Last checked")).to_be_visible()
        expect(page.get_by_text("/var/www/alpha/current/public")).to_be_visible()
        self.assert_no_native_terms(allowed=("caddy",))
        page.evaluate("window.barectlNavigationTest = 'same-document'")
        logs = page.get_by_role("navigation", name="Site sections").get_by_role("link", name="Logs")
        logs.focus()
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Logs", level=2)).to_be_visible()
        self.assertEqual(page.evaluate("window.barectlNavigationTest"), "same-document")
        expect(logs).to_be_focused()
        expect(page.get_by_role("link", name="PHP errors")).to_be_visible()
        page.locator("summary", has_text="Advanced").click()
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
                "link", name="Security"
            )
        ).to_be_focused()
        page.keyboard.press("Tab")
        expect(
            page.get_by_role("navigation", name="Server sections").get_by_role("link", name="Jobs")
        ).to_be_focused()
