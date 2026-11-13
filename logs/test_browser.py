"""Journey: a PHP error line from the site page in two activations (Phase C #389)."""

import tempfile
from dataclasses import replace
from time import sleep
from typing import override

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from django.utils import timezone
from playwright.sync_api import expect

from dashboard.browser_testing import BrowserTestCase
from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt
from discovery.snapshot import current_snapshot, save_snapshot
from logs.journal_retention import MANAGED, RetentionObservation
from logs.models import LogRead
from logs.read import LogLine, LogPage
from logs.testing import record_background_site, record_log_site
from servers.models import Server
from sites.ui_testing import record_http_sites


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


@tag("browser")
class JournalRetentionBrowserTests(BrowserTestCase):
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
            "view_server",
            "view_siteobservation",
            "view_changes",
            "view_evidence",
            "change_site",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.server = Server.objects.get(name="Production")

    def store_retention(self, retention: RetentionObservation) -> None:
        record_http_sites(self.server)
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            raise AssertionError("No setup snapshot.")
        attempt = record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED)
        save_snapshot(
            attempt,
            replace(snapshot.collected, journal_retention=retention),
            timezone.now(),
        )

    def test_the_card_shows_the_managed_policy_at_320_pixels(self) -> None:
        self.store_retention(RetentionObservation(MANAGED, "", "2G", "3months"))
        self.sign_in()
        page = self.page
        page.set_viewport_size({"width": 320, "height": 740})
        page.goto(f"{self.live_server_url}/servers/{self.server.pk}/settings/")
        expect(page.get_by_role("heading", name="Log retention", level=3)).to_be_visible()
        expect(page.get_by_text("2 GiB (2G)")).to_be_visible()
        expect(page.get_by_text("3 months (3months)")).to_be_visible()
        self.assert_no_native_terms()
        self.assertEqual(page.locator("#journal-retention form").count(), 0)
        self.assertEqual(
            page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )

    def test_the_site_logs_pointer_reaches_the_server_setting_at_320_pixels(self) -> None:
        record_log_site(self.server)
        self.sign_in()
        page = self.page
        page.set_viewport_size({"width": 320, "height": 740})
        page.goto(f"{self.live_server_url}/servers/{self.server.pk}/sites/alpha/")
        page.get_by_role("navigation", name="Site sections").get_by_role(
            "link", name="Logs", exact=True
        ).click()
        pointer = page.get_by_role("link", name="Server Settings > Server logs")
        expect(pointer).to_be_visible()
        self.assert_no_native_terms()
        pointer.click()
        expect(page).to_have_url(
            f"{self.live_server_url}/servers/{self.server.pk}/settings/#journal-retention"
        )
        expect(page.get_by_role("heading", name="Log retention", level=3)).to_be_visible()
        self.assertEqual(
            page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )
