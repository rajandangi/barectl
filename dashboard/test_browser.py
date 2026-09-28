"""Browser acceptance paths against the production asset build and the Vite dev server.

Run `npm run build` first. The production tests collect static files into a temporary
STATIC_ROOT and serve them without the Vite development server, as a deployment would. The
development tests start Vite on a free port and load modules from it, as `npm run dev` does.
Set BARECTL_BROWSER_EXECUTABLE to use an installed Chromium instead of Playwright's download.
"""

import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import ClassVar, override
from unittest import mock
from urllib.parse import urlsplit

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, User
from django.contrib.staticfiles.handlers import StaticFilesHandler
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

from discovery.fakes import STALE, FakeServer, record_attempt, run_worker
from discovery.models import DiscoveryAttempt
from discovery.services import request_discovery
from servers.models import Server

PASSWORD = "correct-horse-battery-staple"  # noqa: S105 - disposable test account
SORTABLE_COLUMNS = 3
CRIMSON = "rgb(220, 20, 60)"
PRIMARY_BLUE = "rgb(0, 56, 147)"
PAGE_BACKGROUND = "rgb(248, 246, 240)"
DESTRUCTIVE = "rgb(165, 28, 48)"
SSH_CONFIG = """\
Host web.example.com stage.example.net db-1
  User deploy
Host *.internal
  User ops
"""


class BrowserTestCase(LiveServerTestCase):
    """A signed-in operator's browser against the live server, with one asset integration."""

    playwright: ClassVar[Playwright]
    browser: ClassVar[Browser]
    user: User
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
        # A disposable controller SSH configuration; the operator's own file is never read.
        ssh_config = Path(cls.enterClassContext(tempfile.TemporaryDirectory())) / "config"
        ssh_config.write_text(SSH_CONFIG, encoding="utf-8")
        cls.enterClassContext(override_settings(SSH_CONFIG_PATH=str(ssh_config)))
        cls.serve_assets()
        super().setUpClass()
        # Class cleanups also run when setup fails, so Playwright's event loop never leaks
        # into later test classes.
        cls.playwright = sync_playwright().start()
        cls.addClassCleanup(cls.playwright.stop)
        executable = os.environ.get("BARECTL_BROWSER_EXECUTABLE") or None
        cls.browser = cls.playwright.chromium.launch(executable_path=executable)
        cls.addClassCleanup(cls.browser.close)

    @classmethod
    def serve_assets(cls) -> None:
        """Prepare the frontend assets and the settings that select them."""
        raise NotImplementedError

    @override
    def setUp(self) -> None:
        self.user = get_user_model().objects.create_user("operator", password=PASSWORD)
        self.user.user_permissions.add(Permission.objects.get(codename="view_server"))
        Server.objects.create(name="Production", ssh_alias="web.example.com")
        Server.objects.create(name="Staging", ssh_alias="stage.example.net")
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

    def assert_theme_and_components_initialized(self) -> None:
        page = self.page
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

    def test_registration_and_editing_use_accessible_alias_controls(self) -> None:
        for codename in ("add_server", "change_server"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        page = self.page
        self.sign_in()
        page.get_by_role("link", name="Add server").click()
        expect(page.get_by_role("heading", name="Add server", level=1)).to_be_visible()
        alias = page.get_by_role("combobox", name="SSH alias")
        # Only concrete aliases are offered; there are no connection or key inputs.
        expect(alias.locator("option")).to_have_text(
            ["- Select an alias -", "db-1", "stage.example.net", "web.example.com"]
        )
        expect(page.locator("form.barectl-card input:not([type=hidden])")).to_have_count(1)
        expect(page.get_by_role("list", name="Host entries not offered")).to_contain_text(
            "*.internal: A pattern, not a single server."
        )

        page.get_by_role("button", name="Register server").click()
        summary = page.locator("#server-form-errors")
        expect(summary).to_be_focused()
        expect(summary).to_contain_text("SSH alias: Choose the SSH alias for this server.")
        expect(alias).to_have_attribute("aria-invalid", "true")
        expect(alias).to_have_accessible_description(
            re.compile(
                r"Connection settings, keys and host trust stay there\. "
                r"Choose the SSH alias for this server\.$"
            )
        )
        summary.get_by_role("link", name="Name: Enter a name for this server.").click()
        name = page.get_by_role("textbox", name="Name")
        expect(name).to_be_focused()

        page.keyboard.type("Database")
        page.keyboard.press("Tab")
        expect(alias).to_be_focused()
        self.assertNotEqual(self.css("#id_ssh_alias", "outline-style"), "none")
        alias.select_option("db-1")
        page.get_by_role("button", name="Register server").click()
        expect(page.get_by_role("heading", name="Database", level=1)).to_be_visible()
        expect(page.locator(".barectl-messages")).to_contain_text(
            "Registered Database with SSH alias db-1. Barectl queued a connection check."
        )
        # Registration queues a check; no worker runs here, so it stays queued.
        expect(page.locator("#discovery")).to_contain_text("Connection check queued")

        page.get_by_role("link", name="Edit Database").click()
        expect(page.get_by_role("heading", name="Edit Database", level=1)).to_be_visible()
        expect(alias).to_have_value("db-1")
        name.fill("Primary database")
        page.get_by_role("button", name="Save changes").click()
        expect(page.get_by_role("heading", name="Primary database", level=1)).to_be_visible()
        page.get_by_role("link", name="Servers", exact=True).first.click()
        row = page.get_by_role("row", name=re.compile("^Primary database"))
        expect(row).to_contain_text("db-1")
        expect(row).to_contain_text("Connection check queued")

        # Long configuration paths and entry names wrap instead of widening the page.
        page.set_viewport_size({"width": 320, "height": 740})
        page.goto(f"{self.live_server_url}/servers/add/")
        overflow = page.evaluate(
            "document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        self.assertEqual(overflow, 0)

    def test_connection_check_progress_updates_in_place(self) -> None:
        self.user.user_permissions.add(Permission.objects.get(codename="add_discoveryattempt"))
        remote = FakeServer()
        self.enterContext(remote.substituted())
        page = self.page
        self.sign_in()
        page.get_by_role("link", name="Production").click()
        expect(page.get_by_role("heading", name="Production", level=1)).to_be_visible()
        page.evaluate("window.barectlDocument = 'initial'")
        discovery = page.locator("#discovery")
        status = page.locator("#connection-status")
        expect(discovery).to_contain_text("Not verified.")
        expect(status).to_have_text("Not verified")

        verify = page.get_by_role("button", name="Verify connection")
        verify.focus()
        page.keyboard.press("Enter")
        expect(discovery).to_contain_text("Connection check queued")
        expect(status).to_have_text("Connection check queued")
        # The pressed button is gone; focus moves to the section it updated.
        expect(page.get_by_role("heading", name="Connection", level=2)).to_be_focused()
        announcement = page.locator("#discovery-announcement")
        expect(announcement).to_have_text("Connection check queued.")

        # The worker runs outside any request; polling shows its result without a reload.
        run_worker()
        expect(discovery).to_contain_text("Ubuntu 24.04.3 LTS", timeout=10_000)
        expect(discovery).to_contain_text("This is a snapshot, not live status.")
        for heading in ("Web stack", "Nginx site files", "PHP-FPM pools"):
            expect(discovery.get_by_role("heading", name=heading, level=2)).to_be_visible()
        expect(announcement).to_contain_text("Connection verified.")
        expect(status).to_have_text("Verified")
        self.assertEqual(page.evaluate("window.barectlDocument"), "initial")
        polls = [r for r in self.requests if "/discovery/" in r.url]
        self.assertTrue(polls)
        self.assertTrue(all(r.headers.get("hx-request-type") == "partial" for r in polls))
        # Polling stops once the attempt has finished.
        count = len(polls)
        page.wait_for_timeout(2500)
        self.assertEqual(len([r for r in self.requests if "/discovery/" in r.url]), count)

        page.set_viewport_size({"width": 320, "height": 740})
        overflow = page.evaluate(
            "document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        self.assertEqual(overflow, 0)

    def test_failed_refresh_keeps_snapshot_and_retry_recovers(self) -> None:
        self.user.user_permissions.add(Permission.objects.get(codename="add_discoveryattempt"))
        remote = FakeServer()
        self.enterContext(remote.substituted())
        request_discovery(Server.objects.get(name="Production"))
        run_worker()
        page = self.page
        self.sign_in()
        page.get_by_role("link", name="Production").click()
        discovery = page.locator("#discovery")
        status = page.locator("#connection-status")
        announcement = page.locator("#discovery-announcement")
        expect(status).to_have_text("Verified")

        page.get_by_role("button", name="Refresh observations").click()
        expect(announcement).to_have_text("Connection check queued.")
        expect(page.get_by_role("heading", name="Connection", level=2)).to_be_focused()
        expect(discovery).to_contain_text("these observations may be out of date")
        expect(page.get_by_role("button", name="Refresh observations")).to_have_count(0)

        remote.failure = "Barectl could not reach the SSH service configured for web."
        run_worker()
        expect(announcement).to_have_text("The connection failed.", timeout=10_000)
        expect(status).to_have_text("Connection failed")
        expect(discovery.get_by_role("heading", name="Connection failed")).to_be_visible()
        expect(discovery).to_contain_text("could not reach the SSH service")
        # The last successful snapshot stays, labelled as possibly out of date.
        expect(discovery).to_contain_text("Ubuntu 24.04.3 LTS")
        expect(discovery).to_contain_text("The latest connection check failed")

        remote.failure = ""
        page.get_by_role("button", name="Retry connection check").click()
        expect(announcement).to_have_text("Connection check queued.")
        run_worker()
        expect(announcement).to_contain_text("Connection verified.", timeout=10_000)
        expect(status).to_have_text("Verified")
        expect(discovery).not_to_contain_text("may be out of date")
        expect(page.get_by_role("button", name="Refresh observations")).to_be_visible()

    def test_activity_and_history_review_recorded_attempts(self) -> None:
        self.user.user_permissions.add(Permission.objects.get(codename="add_discoveryattempt"))
        remote = FakeServer()
        self.enterContext(remote.substituted())
        page = self.page
        self.sign_in()
        page.get_by_role("link", name="Production").click()
        expect(page.get_by_role("heading", name="Production", level=1)).to_be_visible()
        history = page.locator("#discovery-history")
        expect(history).to_contain_text("No discovery attempts yet.")

        page.get_by_role("button", name="Verify connection").focus()
        # Wait for the queueing POST: the worker would otherwise race it for the database.
        with page.expect_response(lambda response: response.url.endswith("/verify/")):
            page.keyboard.press("Enter")
        # The pressed button is gone; focus moves to the section it updated.
        expect(page.get_by_role("heading", name="Connection", level=2)).to_be_focused()
        # The queued attempt joins the history through the same fragment response.
        expect(history).to_contain_text("Connection check queued")

        # The page's polls would also race the worker; silence them while it runs,
        # then let the next poll deliver the finished attempt.
        page.route("**/discovery/", lambda route: route.fulfill(status=204))
        run_worker()
        page.unroute("**/discovery/")
        discovery = page.locator("#discovery")
        expect(discovery).to_contain_text("Ubuntu 24.04.3 LTS", timeout=10_000)
        expect(history).to_contain_text("Verified")
        # The final poll removed the trigger; no discovery poll is scheduled now.
        expect(discovery).not_to_have_attribute("hx-trigger", ".*")

        remote.failure = "Barectl could not reach the SSH service configured for web."
        with page.expect_response(lambda response: response.url.endswith("/verify/")):
            page.get_by_role("button", name="Refresh observations").click()
        page.route("**/discovery/", lambda route: route.fulfill(status=204))
        run_worker()
        page.unroute("**/discovery/")
        expect(page.locator("#discovery-announcement")).to_have_text(
            "The connection failed.", timeout=10_000
        )
        # The failed refresh stays visible beside the snapshot it did not replace.
        expect(discovery).to_contain_text("The latest connection check failed")
        expect(discovery).to_contain_text("could not reach the SSH service")
        expect(history).to_contain_text("could not reach the SSH service")
        # Repeated out-of-band swaps replace the section; they never stack a second one.
        expect(page.locator("#discovery-history")).to_have_count(1)
        rows = history.get_by_role("row")
        expect(rows).to_have_count(3)
        expect(rows.nth(1)).to_contain_text("Connection failed")
        expect(rows.nth(2)).to_contain_text("Verified")

        nav = page.get_by_role("navigation", name="Primary")
        nav.get_by_role("link", name="Activity").click()
        expect(page.get_by_role("heading", name="Activity", level=1)).to_be_visible()
        expect(nav.get_by_role("link", name="Activity")).to_have_attribute("aria-current", "page")
        activity_rows = page.get_by_role("row")
        expect(activity_rows).to_have_count(3)
        expect(activity_rows.nth(1)).to_contain_text("could not reach the SSH service")
        expect(activity_rows.nth(1)).to_contain_text("Connection failed")
        expect(activity_rows.nth(2)).to_contain_text("Verified")
        expect(page.get_by_role("columnheader", name="Snapshot collected")).to_be_visible()
        expect(page.locator("body")).to_contain_text("not live status")
        # The attempts table scrolls inside its container; the page never scrolls sideways.
        page.set_viewport_size({"width": 320, "height": 740})
        expect(page.get_by_role("row")).to_have_count(3)
        overflow = page.evaluate(
            "document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        self.assertEqual(overflow, 0)
        page.set_viewport_size({"width": 1280, "height": 900})

        nav.get_by_role("link", name="Servers").click()
        expect(nav.get_by_role("link", name="Servers")).to_have_attribute("aria-current", "page")
        # The inventory table's components still work after navigating away and back.
        self.assert_single_table_binding()

    def test_polling_recovers_an_abandoned_check(self) -> None:
        self.user.user_permissions.add(Permission.objects.get(codename="add_discoveryattempt"))
        server = Server.objects.get(name="Production")
        attempt = request_discovery(server)
        # A worker claimed the attempt and was then killed.
        record_attempt(attempt, DiscoveryAttempt.Status.RUNNING)
        page = self.page
        self.sign_in()
        page.get_by_role("link", name="Production").click()
        discovery = page.locator("#discovery")
        expect(discovery).to_contain_text("Checking connection")

        record_attempt(attempt, DiscoveryAttempt.Status.RUNNING, age=STALE)
        expect(page.locator("#discovery-announcement")).to_have_text(
            "The connection failed.", timeout=10_000
        )
        expect(page.locator("#connection-status")).to_have_text("Connection failed")
        expect(discovery).to_contain_text("stopped before finishing")
        expect(page.get_by_role("button", name="Retry connection check")).to_be_visible()

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
        remove = page.get_by_role("link", name="Remove Production")
        self.assertEqual(self.css(".barectl-button--destructive-outline", "color"), DESTRUCTIVE)
        remove.focus()
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Remove Production", level=1)).to_be_visible()
        # A queued check blocks removal; the page offers no removal control.
        blocked = page.locator("#removal-blocked")
        expect(blocked).to_be_focused()
        expect(blocked).to_contain_text("Discovery in progress")
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
            "Removed Production and its discovery history from Barectl."
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


def _stop(process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


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
        # A free port, so a developer's own `npm run dev` on the default port is unaffected.
        port = _free_port()
        url = f"http://localhost:{port}"
        log = cls.enterClassContext(tempfile.TemporaryFile())
        vite = subprocess.Popen(  # noqa: S603 - the project's own pinned Vite binary
            [settings.BASE_DIR / "node_modules" / ".bin" / "vite"],
            cwd=settings.BASE_DIR,
            env={**os.environ, "BARECTL_VITE_DEV_PORT": str(port)},
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        cls.addClassCleanup(_stop, vite)
        deadline = time.monotonic() + 30
        while True:
            try:
                with urllib.request.urlopen(f"{url}/@vite/client", timeout=1):  # noqa: S310
                    break
            except OSError as error:
                if vite.poll() is not None or time.monotonic() > deadline:
                    log.seek(0)
                    output = log.read().decode(errors="replace")
                    raise RuntimeError(f"Vite did not start on {url}:\n{output}") from error
                time.sleep(0.2)
        cls.enterClassContext(override_settings(VITE_DEV_SERVER_URL=url))
        cls.vite_origin = urlsplit(url).netloc

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
        self.sign_in()
        self.assert_single_table_binding()
        for query, visible in (("stage", "stage.example.net"), ("web", "web.example.com")):
            self.search(query)
            expect(page.locator("#server-results")).to_contain_text(visible)
            self.assert_single_table_binding()
