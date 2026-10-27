"""Journey: Backups on a site, from not backed up through an explicit check (#396)."""

import tempfile
from typing import override

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from playwright.sync_api import expect

from dashboard.browser_testing import BrowserTestCase
from operations.models import ChangePreparation
from servers.models import Server

from . import check
from .testing import record_backups, result


@tag("browser")
class BackupsBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    def sign_in_operator(self) -> None:
        for codename in (
            "view_siteobservation",
            "view_changes",
            "change_site",
            "change_shared",
            "manage_secrets",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()

    def test_a_site_is_enabled_checked_and_captured_from_its_backups_section(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=False)
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        expect(self.page.get_by_role("heading", name="Backups", level=2)).to_be_visible()
        expect(self.page.get_by_text("This site is not backed up.")).to_be_visible()
        self.assert_no_native_terms()
        self.page.get_by_role("button", name="Enable backups").click()
        expect(self.page.get_by_role("heading", name="Enable backups for shop")).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "enable_backups")
        self.assertEqual(preparation.inputs, {"version": 1, "identifier": "shop"})
        self.assert_no_native_terms()
        self.page.set_viewport_size({"width": 320, "height": 800})
        expect(self.page.get_by_role("heading", name="Enable backups for shop")).to_be_visible()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )

    def test_a_capture_and_the_kit_are_offered_and_the_capture_starts(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result())
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        expect(self.page.get_by_role("button", name="Back up now")).to_be_visible()
        self.assert_no_native_terms()
        self.page.get_by_role("link", name="Recovery kit").click()
        expect(self.page.get_by_role("heading", name="Recovery kit", level=1)).to_be_visible()
        expect(self.page.get_by_text("Onsite repository:")).to_be_visible()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        self.page.get_by_role("button", name="Back up now").click()
        expect(
            self.page.get_by_role("heading", name="Back up the database of shop")
        ).to_be_visible()
        capture = ChangePreparation.objects.get(server=server)
        self.assertEqual(capture.kind_slug, "back_up_now")
        self.assert_no_native_terms()

    def test_check_backups_queues_one_explicit_read(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result())
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        self.page.get_by_role("button", name="Check backups").click()
        expect(
            self.page.get_by_text("Barectl is checking the recovery points now.")
        ).to_be_visible()
        self.assertIsNotNone(check.active(server, "shop"))
        self.assertIsNone(check.latest_check(server, "shop"))
