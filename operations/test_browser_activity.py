"""Journey 6: Activity lists every check and change (#179, #369)."""

import tempfile
from datetime import timedelta
from typing import override

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from playwright.sync_api import expect

from dashboard.browser_testing import BrowserTestCase
from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt
from operations.activity_testing import record_change, record_run
from servers.models import Server
from sites.ui_testing import record_http_sites


@tag("browser")
class ActivityBrowserTests(BrowserTestCase):
    production: Server
    staging: Server

    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    @override
    def setUp(self) -> None:
        super().setUp()
        for codename in ("view_changes", "view_siteobservation", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.production = Server.objects.get(name="Production")
        self.staging = Server.objects.get(name="Staging")

    def test_a_check_and_a_change_are_listed_newest_first_in_plain_words(self) -> None:
        record_attempt(self.production, DiscoveryAttempt.Status.SUCCEEDED, age=timedelta(hours=2))
        preparation = record_change(self.staging, age=timedelta(hours=1))
        run = record_run(preparation, age=timedelta(minutes=10))
        page = self.page
        self.sign_in()
        page.goto(f"{self.live_server_url}/activity/")
        expect(page.get_by_role("heading", name="Activity", level=1)).to_be_visible()
        rows = page.get_by_role("row")
        expect(rows).to_have_count(3)
        # The change on Staging is newer than the check on Production.
        expect(rows.nth(1)).to_contain_text("Staging")
        expect(rows.nth(1)).to_contain_text("Applied")
        expect(rows.nth(2)).to_contain_text("Production")
        expect(rows.nth(2)).to_contain_text("Check the connection")
        expect(rows.nth(2)).to_contain_text("Verified")
        self.assert_no_native_terms()
        # The row reaches its run in one activation.
        page.locator(f'#activity-rows a[href="/runs/{run.pk}/"]').click()
        expect(page).to_have_url(f"{self.live_server_url}/runs/{run.pk}/")

    def test_the_server_filter_and_the_server_page_narrow_the_same_list(self) -> None:
        record_attempt(self.production, DiscoveryAttempt.Status.SUCCEEDED)
        record_change(self.staging)
        page = self.page
        self.sign_in()
        page.goto(f"{self.live_server_url}/activity/")
        page.get_by_label("Server").select_option(label="Staging")
        page.get_by_role("button", name="Show").click()
        rows = page.get_by_role("row")
        expect(rows).to_have_count(2)
        expect(rows.nth(1)).to_contain_text("Set up")
        expect(rows.nth(1)).not_to_contain_text("Check the connection")
        # The server's own Activity shows the same rows, narrowed to that server.
        page.get_by_role("navigation", name="Primary").get_by_role("link", name="Servers").click()
        page.get_by_role("link", name="Production").click()
        page.get_by_role("navigation", name="Server sections").get_by_role(
            "link", name="Activity"
        ).click()
        rows = page.get_by_role("row")
        expect(rows).to_have_count(2)
        expect(rows.nth(1)).to_contain_text("Check the connection")
        expect(rows.nth(1)).not_to_contain_text("Set up")
        self.assert_no_native_terms()

    def test_a_site_s_activity_lists_its_rows_from_the_same_list(self) -> None:
        record_http_sites(self.production)
        preparation = record_change(self.production, kind_slug="create_http_site", site="alpha")
        run = record_run(preparation)
        page = self.page
        self.sign_in()
        page.goto(f"{self.live_server_url}/servers/{self.production.pk}/sites/alpha/activity/")
        expect(page.get_by_role("heading", name="Activity for alpha")).to_be_visible()
        rows = page.get_by_role("row")
        expect(rows).to_have_count(2)
        expect(rows.nth(1)).to_contain_text("Applied")
        expect(rows.nth(1)).to_contain_text("alpha")
        self.assert_no_native_terms()
        page.locator(f'#activity-rows a[href="/runs/{run.pk}/"]').click()
        expect(page).to_have_url(f"{self.live_server_url}/runs/{run.pk}/")

    def test_activity_reads_without_sideways_scrolling_at_320_pixels(self) -> None:
        record_attempt(self.production, DiscoveryAttempt.Status.FAILED)
        record_change(self.staging, site="shop", kind_slug="create_http_site")
        page = self.page
        self.sign_in()
        page.goto(f"{self.live_server_url}/activity/")
        page.set_viewport_size({"width": 320, "height": 740})
        expect(page.get_by_role("row")).to_have_count(3)
        overflow = page.evaluate(
            "document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        self.assertEqual(overflow, 0)
