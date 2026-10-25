"""docs/quality.md#before-every-push"""

import re
import tempfile
from typing import ClassVar, override
from urllib.parse import urlsplit

from django.contrib.auth.models import Permission
from django.contrib.staticfiles.handlers import StaticFilesHandler
from django.core.management import call_command
from django.test import override_settings, tag
from playwright.sync_api import (
    expect,
)

from discovery.fakes import (
    FakeServer,
    run_worker,
)
from discovery.models import DiscoveryAttempt
from discovery.services import request_discovery
from servers.models import Server

from .browser_testing import DESTRUCTIVE, PRIMARY_BLUE, serve_development_assets
from .browser_testing import BrowserTestCase as BrowserTestCase


@tag("browser")
class ProductionAssetBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    def test_sign_in_errors_are_announced_and_focused(self) -> None:
        page = self.page
        page.goto(f"{self.live_server_url}/accounts/login/")
        page.get_by_role("button", name="Sign in").click()
        summary = page.locator("#sign-in-errors")
        expect(summary).to_be_focused()
        expect(summary).to_contain_text("Username: This field is required.")
        expect(page.get_by_label("Username")).to_have_attribute("aria-invalid", "true")
        expect(page.get_by_label("Password")).to_have_accessible_description(
            "This field is required."
        )
        page.get_by_label("Username").fill("operator")
        page.get_by_label("Password").fill("wrong")
        page.get_by_role("button", name="Sign in").click()
        expect(page.locator("#sign-in-errors")).to_be_focused()
        expect(page.locator("#sign-in-errors")).to_contain_text("Please enter a correct username")

    def test_production_assets_theme_and_fonts_are_self_hosted(self) -> None:
        self.sign_in()
        self.assert_theme_and_components_initialized()

        origin = urlsplit(self.live_server_url).netloc
        self.assertEqual({urlsplit(r.url).netloc for r in self.requests}, {origin})
        fonts = [r.url for r in self.requests if r.resource_type == "font"]
        self.assertTrue(fonts)
        self.assertTrue(all("/static/dist/assets/inter-latin" in url for url in fonts))
        self.assertFalse([r.url for r in self.requests if "@vite" in r.url])

    def test_keyboard_navigation_and_visible_focus(self) -> None:
        page = self.page
        self.many_servers()
        self.sign_in()
        page.reload()
        page.keyboard.press("Tab")
        skip = page.get_by_role("link", name="Skip to main content")
        expect(skip).to_be_focused()
        expect(skip).to_be_in_viewport()
        page.keyboard.press("Enter")
        expect(page.locator("#main-content")).to_be_focused()

        search = page.get_by_role("searchbox", name="Search servers")
        search.focus()
        self.assertNotEqual(self.css("#id_q", "outline-style"), "none")
        self.assertEqual(self.css("#id_q", "outline-color"), PRIMARY_BLUE)
        page.keyboard.press("Tab")
        expect(page.get_by_role("button", name="Search")).to_be_focused()
        self.assertNotEqual(self.css(".barectl-search .usa-button", "outline-style"), "none")

    def test_htmx_search_updates_fragments_and_history(self) -> None:
        page = self.page
        self.many_servers()
        self.sign_in()
        page.evaluate("window.barectlDocument = 'initial'")
        self.assert_single_table_binding()

        # Repeated fragment updates keep one USWDS binding per table.
        for query, visible, hidden in (
            ("stage", "stage.example.net", "web.example.com"),
            ("web", "web.example.com", "stage.example.net"),
            ("example", "web.example.com", "no-such-host"),
        ):
            self.search(query)
            expect(page.locator("#server-results")).to_contain_text(visible)
            expect(page.locator("#server-results")).not_to_contain_text(hidden)
            self.assert_single_table_binding()
        expect(page).to_have_url(f"{self.live_server_url}/?q=example")
        expect(page.get_by_role("status")).to_have_text("2 of 11 servers match “example”.")
        self.assertEqual(page.evaluate("window.barectlDocument"), "initial")

        fragment_requests = [r for r in self.requests if r.headers.get("hx-request") == "true"]
        self.assertEqual(len(fragment_requests), 3)
        for request in fragment_requests:
            # hx-headers:inherited on <body> reaches the search form's requests.
            self.assertTrue(request.headers.get("x-csrftoken"))

        self.search("missing")
        expect(page.locator("#server-results")).to_contain_text("No matching servers")

        # Back navigation reloads the authenticated page for the previous URL.
        page.go_back()
        expect(page).to_have_url(f"{self.live_server_url}/?q=example")
        expect(page.locator("#server-results")).to_contain_text("stage.example.net")
        self.assertIsNone(page.evaluate("window.barectlDocument ?? null"))
        self.assert_single_table_binding()

    def test_signed_out_history_does_not_reveal_inventory(self) -> None:
        page = self.page
        self.many_servers()
        self.sign_in()
        self.search("web")
        page.get_by_role("button", name="Sign out").click()
        expect(page).to_have_url(f"{self.live_server_url}/accounts/login/")
        page.go_back()
        expect(page).to_have_url(f"{self.live_server_url}/accounts/login/?next=/%3Fq%3Dweb")
        expect(page.locator("body")).not_to_contain_text("web.example.com")

    def test_expired_session_redirects_htmx_requests_to_sign_in(self) -> None:
        page = self.page
        self.many_servers()
        self.sign_in()
        self.context.clear_cookies()
        page.get_by_role("searchbox", name="Search servers").fill("web")
        page.get_by_role("searchbox", name="Search servers").press("Enter")
        expect(page).to_have_url(f"{self.live_server_url}/accounts/login/?next=/%3Fq%3Dweb")
        expect(page.locator("#server-results")).to_have_count(0)
        expect(page.get_by_role("heading", name="Sign in to Barectl")).to_be_visible()

    def test_responsive_layout_and_mobile_menu(self) -> None:
        for width in (320, 768, 1280):
            with self.subTest(width=width):
                self.context.close()
                self.open_context(width=width, height=800)
                self.sign_in()
                overflow = self.page.evaluate(
                    "document.documentElement.scrollWidth - document.documentElement.clientWidth"
                )
                self.assertEqual(overflow, 0)

        page = self.page
        page.set_viewport_size({"width": 375, "height": 740})
        menu = page.get_by_role("button", name="Menu", exact=True)
        expect(menu).to_be_visible()
        expect(page.get_by_role("button", name="Sign out")).to_be_hidden()
        menu.focus()
        page.keyboard.press("Enter")
        nav = page.get_by_role("navigation", name="Primary")
        expect(nav).to_be_visible()
        expect(page.get_by_role("button", name="Close menu")).to_be_focused()
        expect(nav.get_by_role("link", name="Servers")).to_have_attribute("aria-current", "page")
        page.keyboard.press("Escape")
        expect(nav).to_be_hidden()
        expect(menu).to_be_focused()

    def test_server_sections_preserve_context_with_keyboard_reload_and_back(self) -> None:
        self.user.user_permissions.add(Permission.objects.get(codename="view_siteobservation"))
        page = self.page
        self.sign_in()
        page.get_by_role("link", name="Production").click()
        nav = page.get_by_role("navigation", name="Server sections")
        for section in ("Sites", "Activity", "Settings", "Advanced"):
            link = nav.get_by_role("link", name=section, exact=True)
            link.focus()
            page.keyboard.press("Enter")
            expect(nav.get_by_role("link", name=section, exact=True)).to_have_attribute(
                "aria-current", "page"
            )
            expect(page.get_by_role("heading", name="Production", level=1)).to_be_visible()
            page.reload()
            expect(nav.get_by_role("link", name=section, exact=True)).to_have_attribute(
                "aria-current", "page"
            )
        page.go_back()
        expect(nav.get_by_role("link", name="Settings", exact=True)).to_have_attribute(
            "aria-current", "page"
        )
        page.go_forward()
        expect(nav.get_by_role("link", name="Advanced", exact=True)).to_have_attribute(
            "aria-current", "page"
        )
        page.set_viewport_size({"width": 320, "height": 740})
        self.assertEqual(
            page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            ),
            0,
        )

    def test_removal_is_confirmed_and_blocked_during_discovery(self) -> None:
        for codename in ("delete_server", "add_discoveryattempt"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        remote = FakeServer()
        self.enterContext(remote.substituted())
        server = Server.objects.get(name="Production")
        request_discovery(server)
        page = self.page
        self.sign_in()
        page.get_by_role("link", name="Production").click()
        page.get_by_role("navigation", name="Server sections").get_by_role(
            "link", name="Settings", exact=True
        ).click()
        remove = page.get_by_role("link", name="Remove Production")
        self.assertEqual(self.css(".barectl-button--destructive-outline", "color"), DESTRUCTIVE)
        remove.focus()
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Remove Production", level=1)).to_be_visible()
        # A queued check blocks removal; the page offers no removal control.
        blocked = page.locator("#removal-blocked")
        expect(blocked).to_be_focused()
        expect(blocked).to_contain_text("Remote operation in progress")
        expect(page.get_by_role("button", name="Remove server")).to_have_count(0)

        run_worker()
        page.reload()
        expect(page.locator("#removal-blocked")).to_have_count(0)
        expect(page.locator("main")).to_contain_text("1 discovery attempt and the latest snapshot")
        confirm = page.get_by_role("button", name="Remove server")
        self.assertEqual(self.css(".barectl-button--destructive", "background-color"), DESTRUCTIVE)
        connections = len(remote.targets)
        confirm.focus()
        self.assertNotEqual(self.css(".barectl-button--destructive", "outline-style"), "none")
        page.keyboard.press("Enter")

        expect(page.get_by_role("heading", name="Servers", level=1)).to_be_visible()
        expect(page.locator(".barectl-messages")).to_contain_text(
            "Removed Production and its local history from Barectl."
        )
        expect(page.get_by_role("row", name=re.compile("^Production"))).to_have_count(0)
        expect(page.get_by_role("row", name=re.compile("^Staging"))).to_have_count(1)
        self.assertEqual(len(remote.targets), connections)
        self.assertFalse(DiscoveryAttempt.objects.exists())

        page.set_viewport_size({"width": 320, "height": 740})
        page.goto(f"{self.live_server_url}/servers/{Server.objects.get(name='Staging').pk}/remove/")
        overflow = page.evaluate(
            "document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        self.assertEqual(overflow, 0)


@tag("browser")
class DevelopmentAssetBrowserTests(BrowserTestCase):
    """The same pages with modules from the Vite development server, as `npm run dev` runs.

    Django's static files finders serve the repository's own static files, as runserver does.
    """

    static_handler = StaticFilesHandler
    vite_origin: ClassVar[str]

    @classmethod
    @override
    def serve_assets(cls) -> None:
        serve_development_assets(cls)

    def test_development_modules_style_and_initialize_the_interface(self) -> None:
        self.sign_in()
        self.assert_theme_and_components_initialized()
        # Modules, styles and fonts come from Vite; nothing from the production build.
        vite = [r.url for r in self.requests if urlsplit(r.url).netloc == self.vite_origin]
        self.assertTrue(any("/@vite/client" in url for url in vite))
        fonts = [r.url for r in self.requests if r.resource_type == "font"]
        self.assertTrue(fonts)
        self.assertTrue(all(urlsplit(url).netloc == self.vite_origin for url in fonts))
        self.assertFalse([r.url for r in self.requests if "/static/dist/" in r.url])

    def test_htmx_fragments_keep_one_component_binding(self) -> None:
        page = self.page
        self.many_servers()
        self.sign_in()
        self.assert_single_table_binding()
        for query, visible in (("stage", "stage.example.net"), ("web", "web.example.com")):
            self.search(query)
            expect(page.locator("#server-results")).to_contain_text(visible)
            self.assert_single_table_binding()
