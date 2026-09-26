"""Browser acceptance path against the production asset build.

Run `npm run build` first. The test collects static files into a temporary STATIC_ROOT and
serves them without the Vite development server, as a deployment would.
Set BARECTL_BROWSER_EXECUTABLE to use an installed Chromium instead of Playwright's download.
"""

import os
import tempfile
from typing import ClassVar, override
from unittest import mock
from urllib.parse import urlsplit

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import LiveServerTestCase, override_settings, tag
from playwright.sync_api import (
    Browser,
    BrowserContext,
    ConsoleMessage,
    Error,
    Page,
    Playwright,
    Request,
    expect,
    sync_playwright,
)

from servers.models import Server

PASSWORD = "correct-horse-battery-staple"  # noqa: S105 - disposable test account
SORTABLE_COLUMNS = 3
CRIMSON = "rgb(220, 20, 60)"
PRIMARY_BLUE = "rgb(0, 56, 147)"
PAGE_BACKGROUND = "rgb(248, 246, 240)"


@tag("browser")
class ProductionAssetBrowserTests(LiveServerTestCase):
    playwright: ClassVar[Playwright]
    browser: ClassVar[Browser]
    context: BrowserContext
    page: Page
    requests: list[Request]
    console_errors: list[str]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        # Playwright's sync API runs an event loop on this thread, but the test's database
        # calls stay synchronous. Django documents this switch for such environments.
        cls.enterClassContext(mock.patch.dict(os.environ, {"DJANGO_ALLOW_ASYNC_UNSAFE": "true"}))
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)
        super().setUpClass()
        # Class cleanups also run when setup fails, so Playwright's event loop never leaks
        # into later test classes.
        cls.playwright = sync_playwright().start()
        cls.addClassCleanup(cls.playwright.stop)
        executable = os.environ.get("BARECTL_BROWSER_EXECUTABLE") or None
        cls.browser = cls.playwright.chromium.launch(executable_path=executable)
        cls.addClassCleanup(cls.browser.close)

    @override
    def setUp(self) -> None:
        user = get_user_model().objects.create_user("operator", password=PASSWORD)
        user.user_permissions.add(Permission.objects.get(codename="view_server"))
        Server.objects.create(name="Production", hostname="web.example.com", ssh_user="deploy")
        Server.objects.create(name="Staging", hostname="stage.example.net", ssh_user="deploy")
        self.open_context(width=1280, height=900)

    @override
    def tearDown(self) -> None:
        self.context.close()
        self.assertEqual(self.console_errors, [])

    def open_context(self, *, width: int, height: int) -> None:
        self.context = self.browser.new_context(viewport={"width": width, "height": height})
        self.page = self.context.new_page()
        self.requests = []
        self.console_errors = []
        self.page.on("request", self.record_request)
        self.page.on("console", self.record_console)
        self.page.on("pageerror", self.record_page_error)

    def record_request(self, request: Request) -> None:
        self.requests.append(request)

    def record_console(self, message: ConsoleMessage) -> None:
        if message.type in {"error", "warning"}:
            self.console_errors.append(message.text)

    def record_page_error(self, error: Error) -> None:
        self.console_errors.append(str(error))

    def sign_in(self, next_path: str = "/") -> None:
        page = self.page
        page.goto(f"{self.live_server_url}{next_path}")
        expect(page).to_have_url(f"{self.live_server_url}/accounts/login/?next={next_path}")
        # Type through the keyboard, as an operator would.
        expect(page.get_by_label("Username")).to_be_focused()
        page.keyboard.type("operator")
        page.keyboard.press("Tab")
        page.keyboard.type(PASSWORD)
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Servers", level=1)).to_be_visible()
        # Scripts evaluated by the test can otherwise observe layout before stylesheets load.
        page.wait_for_load_state("load")

    def css(self, selector: str, prop: str) -> str:
        value: str = self.page.locator(selector).first.evaluate(
            "(el, prop) => getComputedStyle(el).getPropertyValue(prop)", prop
        )
        return value

    def assert_single_table_binding(self) -> None:
        """Sorting once toggles once; a duplicate USWDS binding would toggle twice."""
        page = self.page
        expect(page.locator(".usa-table__header__button")).to_have_count(SORTABLE_COLUMNS)
        name = page.locator("th[data-sortable]").first
        name.locator("button").click()
        expect(name).to_have_attribute("aria-sort", "ascending")
        name.locator("button").click()
        expect(name).to_have_attribute("aria-sort", "descending")
        expect(page.locator(".usa-table__announcement-region")).to_contain_text("descending")

    def search(self, query: str) -> None:
        field = self.page.get_by_role("searchbox", name="Search servers")
        field.fill(query)
        with self.page.expect_response(lambda r: urlsplit(r.url).path == "/") as info:
            field.press("Enter")
        self.assertEqual(info.value.request.headers["hx-request-type"], "partial")

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
        page = self.page
        self.sign_in()
        page.evaluate("document.fonts.ready")
        self.assertTrue(page.evaluate("document.fonts.check('600 16px Inter')"))
        self.assertIn("Inter", self.css("body", "font-family"))
        self.assertEqual(self.css("body", "background-color"), PAGE_BACKGROUND)
        self.assertEqual(self.css(".barectl-header", "border-top-color"), CRIMSON)
        self.assertEqual(self.css(".usa-button--outline", "color"), PRIMARY_BLUE)
        self.assertEqual(page.evaluate("window.htmx.version"), "4.0.0")
        # The initializer ran before paint and saw USWDS report ready at the load event.
        expect(page.locator("html")).not_to_have_class("usa-js-loading")
        self.assertTrue(page.evaluate("window.uswdsPresent"))

        origin = urlsplit(self.live_server_url).netloc
        self.assertEqual({urlsplit(r.url).netloc for r in self.requests}, {origin})
        fonts = [r.url for r in self.requests if r.resource_type == "font"]
        self.assertTrue(fonts)
        self.assertTrue(all("/static/dist/assets/inter-latin" in url for url in fonts))
        self.assertFalse([r.url for r in self.requests if "@vite" in r.url])

    def test_keyboard_navigation_and_visible_focus(self) -> None:
        page = self.page
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
        expect(page.get_by_role("status")).to_have_text("2 of 2 servers match “example”.")
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
        self.sign_in()
        self.search("web")
        page.get_by_role("button", name="Sign out").click()
        expect(page).to_have_url(f"{self.live_server_url}/accounts/login/")
        page.go_back()
        expect(page).to_have_url(f"{self.live_server_url}/accounts/login/?next=/%3Fq%3Dweb")
        expect(page.locator("body")).not_to_contain_text("web.example.com")

    def test_expired_session_redirects_htmx_requests_to_sign_in(self) -> None:
        page = self.page
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
