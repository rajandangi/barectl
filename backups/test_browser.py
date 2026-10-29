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
from .testing import point, record_backups, record_points, record_schedule, result


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
            "change_destructive",
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

    def test_full_site_is_chosen_and_its_review_names_the_pause(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result())
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        self.page.get_by_label("What to copy").select_option("full")
        self.page.get_by_role("button", name="Back up now").click()
        expect(self.page.get_by_role("heading", name="Back up all of shop")).to_be_visible()
        capture = ChangePreparation.objects.get(server=server)
        self.assertEqual(capture.kind_slug, "back_up_full_site")
        self.assert_no_native_terms()

    def test_a_schedule_is_set_through_its_review(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result())
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        expect(self.page.get_by_role("heading", name="Schedule")).to_be_visible()
        self.page.get_by_label("How often").select_option("weekly")
        self.page.get_by_label("UTC time").fill("04:30")
        self.page.get_by_label("What the schedule copies").select_option("full")
        self.page.get_by_role("button", name="Set backup schedule").click()
        expect(
            self.page.get_by_role("heading", name="Change the backup schedule of shop")
        ).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "set_backup_schedule")
        self.assertEqual(preparation.inputs["frequency"], "weekly")
        self.assertEqual(preparation.inputs["at"], "04:30")
        self.assert_no_native_terms()

    def test_a_schedule_shows_the_next_run_and_turns_off(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result())
        record_schedule(server, identifier="shop")
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        expect(self.page.get_by_text("Daily at 03:00 UTC")).to_be_visible()
        expect(self.page.get_by_text("Next run:")).to_be_visible()
        self.assert_no_native_terms()
        self.page.get_by_role("button", name="Turn off backup schedule").click()
        expect(
            self.page.get_by_role("heading", name="Change the backup schedule of shop")
        ).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "set_backup_schedule")
        self.assertEqual(preparation.inputs, {"version": 1, "identifier": "shop", "state": "off"})

    def test_offsite_storage_is_set_up_from_server_settings(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result())
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/settings/")
        expect(self.page.get_by_role("heading", name="Backup storage", level=2)).to_be_visible()
        self.page.get_by_label("Bucket").first.fill("barectl-backups")
        self.page.get_by_label("Region").fill("us-east-1")
        self.page.get_by_role("button", name="Set up Amazon S3").click()
        expect(
            self.page.get_by_role("heading", name="Set up offsite backup storage")
        ).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "set_up_offsite_storage")
        self.assert_no_native_terms()

    def test_the_offsite_copy_result_is_shown_beside_the_onsite_point(self) -> None:
        from backups.observation import OffsiteCopy, OffsiteStorage

        server = Server.objects.get(name="Production")
        storage = OffsiteStorage(
            "s3",
            "barectl-backups",
            "us-east-1",
            "https://s3.us-east-1.amazonaws.com",
            "barectl/0123456789abcdef",
        )
        record_backups(
            server,
            enabled=True,
            last=result(point="0123456789abcdef"),
            offsite=storage,
            copy=OffsiteCopy("failed", "offsite_copy", "0123456789abcdef", ""),
        )
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        expect(self.page.get_by_text("Saved here, offsite copy failed.")).to_be_visible()
        expect(self.page.get_by_text("Offsite copy failed.", exact=False).first).to_be_visible()
        self.assert_no_native_terms()

    def test_a_gated_site_offers_one_reopen_action(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(
            server,
            enabled=True,
            gated=True,
            last=result(result_class="partial", scope="full", reason="backup_paused"),
        )
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        expect(
            self.page.get_by_text(
                "This stopped after pausing the site for a full backup. Nothing after it ran."
            )
        ).to_be_visible()
        self.page.get_by_role("button", name="Reopen site").click()
        expect(self.page.get_by_role("heading", name="Reopen shop")).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "reopen_site")
        self.assert_no_native_terms()
        self.page.set_viewport_size({"width": 320, "height": 800})
        expect(self.page.get_by_role("heading", name="Reopen shop")).to_be_visible()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )

    def test_a_listed_point_restores_its_database_through_its_confirmation(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result())
        record_points(server, (point(),))
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        expect(self.page.get_by_text("Saved here")).to_be_visible()
        self.assert_no_native_terms()
        self.page.get_by_role("button", name="Restore", exact=True).click()
        expect(
            self.page.get_by_role("heading", name="Restore the database of shop")
        ).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "restore_database")
        self.assertEqual(
            preparation.inputs,
            {"version": 1, "identifier": "shop", "point": "0123456789abcdef"},
        )
        self.assert_no_native_terms()
        self.page.set_viewport_size({"width": 320, "height": 800})
        expect(
            self.page.get_by_role("heading", name="Restore the database of shop")
        ).to_be_visible()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )

    def test_a_gated_restore_offers_the_same_one_reopen_action(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(
            server,
            enabled=True,
            gated=True,
            last=result(result_class="partial", reason="restore_paused"),
        )
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        expect(
            self.page.get_by_text(
                "This stopped after pausing the site to restore its database. Nothing after it ran."
            )
        ).to_be_visible()
        self.page.get_by_role("button", name="Reopen site").click()
        expect(self.page.get_by_role("heading", name="Reopen shop")).to_be_visible()
        self.assert_no_native_terms()
