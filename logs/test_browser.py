"""Journey: a PHP error line from the site page in two activations (Phase C #389)."""

import tempfile
from time import sleep
from typing import override

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from playwright.sync_api import expect

from dashboard.browser_testing import BrowserTestCase
from logs.models import LogRead
from logs.read import LogLine, LogPage
from logs.testing import record_background_site, record_log_site
from servers.models import Server


@tag("browser")
class SiteLogsBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    def grant_logs(self) -> None:
        for codename in ("view_siteobservation", "view_changes", "view_evidence"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))

    def test_a_php_error_line_is_two_activations_from_the_site_page(self) -> None:
        server = Server.objects.get(name="Production")
        record_log_site(
            server,
            page=LogPage(
                "observed",
                (
                    LogLine(
                        time="2026-10-25 08:00:00",
                        raw="PHP warning: the browser journey reached this line",
                    ),
                ),
                rotation="supported",
            ),
        )
        self.grant_logs()
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/alpha/")
        activations = 0
        self.page.get_by_role("navigation", name="Site sections").get_by_role(
            "link", name="Logs", exact=True
        ).click()
        activations += 1
        self.assert_no_native_terms()
        self.page.get_by_role("link", name="PHP errors", exact=True).click()
        activations += 1
        expect(
            self.page.get_by_text("PHP warning: the browser journey reached this line")
        ).to_be_visible()
        self.assert_no_native_terms()
        self.assertEqual(activations, 2)
        self.page.set_viewport_size({"width": 320, "height": 740})
        self.page.goto(
            f"{self.live_server_url}/servers/{server.pk}/sites/alpha/logs/?log=php_errors"
        )
        expect(self.page.get_by_role("heading", name="PHP errors", level=3)).to_be_visible()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )

    def wait_for_reads(self, count: int) -> None:
        for _ in range(100):
            if LogRead.objects.filter(source="queue_workers").count() >= count:
                return
            sleep(0.1)
        raise AssertionError("the live panel queued no read")

    def test_a_journal_live_view_stays_plain_and_reachable_at_phone_width(self) -> None:
        server = Server.objects.get(name="Production")
        record_background_site(
            server,
            application="laravel",
            workers=1,
            page=LogPage(
                "observed",
                (LogLine(raw="worker started", time="2026-10-25 08:00:00"),),
                newest="live:s=one",
                at_end=True,
            ),
        )
        self.grant_logs()
        self.sign_in()
        self.page.goto(
            f"{self.live_server_url}/servers/{server.pk}/sites/alpha/logs/?log=queue_workers&live=1"
        )
        expect(self.page.get_by_role("heading", name="Queue workers", level=3)).to_be_visible()
        expect(
            self.page.get_by_text("Following new lines while this page is visible.")
        ).to_be_visible()
        self.assert_no_native_terms()
        # The open panel asks for its first live page through the explicit poll POST.
        self.wait_for_reads(1)
        self.page.get_by_role("link", name="Stop following").focus()
        self.page.keyboard.press("Enter")
        expect(self.page.get_by_role("link", name="Follow new lines")).to_be_visible()
        # Closing the panel removes the element that carries the polling interval.
        self.assertEqual(self.page.locator("[hx-trigger*='every 2s']").count(), 0)
        self.page.set_viewport_size({"width": 320, "height": 740})
        self.page.goto(
            f"{self.live_server_url}/servers/{server.pk}/sites/alpha/logs/?log=queue_workers&live=1"
        )
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )
