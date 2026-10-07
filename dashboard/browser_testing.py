"""Shared live-browser fixtures for production and development assets."""

import contextlib
import os
import signal
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
from django.test import LiveServerTestCase, override_settings
from django.utils import timezone
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

from discovery.fakes import FakeServer, record_attempt
from discovery.models import DiscoveryAttempt
from discovery.observations import collect
from discovery.snapshot import save_snapshot
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
    vite_origin: ClassVar[str]
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

    def record_installed_php(self) -> None:
        server = Server.objects.get(name="Production")
        attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
        save_snapshot(attempt, collect(FakeServer()), timezone.now())

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


def _stop(process: subprocess.Popen[bytes]) -> None:
    # `vp dev` serves from a child process, so stop its whole session.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


def serve_development_assets(cls: type[BrowserTestCase]) -> None:
    # A free port, so a developer's own `npm run dev` on the default port is unaffected.
    port = _free_port()
    url = f"http://localhost:{port}"
    log = cls.enterClassContext(tempfile.TemporaryFile())
    vite = subprocess.Popen(  # noqa: S603 - the project's own pinned Vite+ binary
        [settings.BASE_DIR / "node_modules" / ".bin" / "vp", "dev"],
        cwd=settings.BASE_DIR,
        env={**os.environ, "BARECTL_VITE_DEV_PORT": str(port)},
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
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
