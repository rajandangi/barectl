"""Journey: Backups on a site, from not backed up through an explicit check (#396)."""

import pathlib
import tempfile
from datetime import timedelta
from typing import override

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from django.utils import timezone
from playwright.sync_api import expect

from dashboard.browser_testing import BrowserTestCase
from operations.models import ChangePreparation
from servers.models import Server

from . import check, observation
from .testing import integrity as finding
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

    def test_a_missed_schedule_is_shown_as_skipped(self) -> None:
        server = Server.objects.get(name="Production")
        old = observation.BackupResult(
            "succeeded",
            "",
            "database",
            "scheduled",
            (timezone.now() - timedelta(hours=48)).isoformat(),
            "0123456789abcdef",
            1,
            4096,
        )
        record_backups(server, enabled=True, last=old)
        record_schedule(
            server,
            next_elapse_us=int((timezone.now() - timedelta(hours=1)).timestamp() * 1_000_000),
        )
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        expect(self.page.get_by_text("The scheduled backup was skipped.")).to_be_visible()
        expect(self.page.get_by_text("Database only saved.")).to_have_count(0)
        self.assert_no_native_terms()

    def test_a_removed_repository_offers_delete(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result())
        record_points(
            server,
            (),
            removed=(
                {
                    "identifier": "gone",
                    "points": [point(scope="full", parts=("database", "files"))],
                    "problem": "",
                },
            ),
        )
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        self.page.get_by_role("button", name="Delete these backups").click()
        expect(self.page.get_by_role("heading", name="Delete removed-site backups")).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "delete_removed_backups")
        self.assert_no_native_terms()

    def test_offsite_storage_is_set_up_from_server_settings(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result())
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/settings/")
        expect(self.page.get_by_role("heading", name="Backup storage", level=2)).to_be_visible()
        self.page.locator("#backup-storage-s3-bucket").fill("barectl-backups")
        self.page.locator("#backup-storage-s3-region").fill("us-east-1")
        self.page.get_by_role("button", name="Set up Amazon S3").click()
        expect(
            self.page.get_by_role("heading", name="Set up offsite backup storage")
        ).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "set_up_offsite_storage")
        self.assert_no_native_terms()

    def test_existing_backup_storage_is_connected_from_server_settings(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result())
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/settings/")
        expect(
            self.page.get_by_role("heading", name="Connect existing backup storage")
        ).to_be_visible()
        self.page.locator("#connect-s3-bucket").fill("barectl-backups")
        self.page.locator("#connect-s3-region").fill("us-east-1")
        self.page.locator("#connect-s3-prefix").fill("barectl/0123456789abcdef")
        self.page.locator("#connect-s3-sites").fill("shop")
        self.page.get_by_role("button", name="Connect existing backup storage").click()
        expect(
            self.page.get_by_role("heading", name="Connect existing backup storage")
        ).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "connect_existing_backup_storage")
        self.assert_no_native_terms()

    def test_the_recovery_passphrase_is_replaced_from_server_settings(self) -> None:
        from backups.observation import OffsiteStorage

        server = Server.objects.get(name="Production")
        record_backups(
            server,
            enabled=True,
            last=result(),
            offsite=OffsiteStorage(
                "s3",
                "barectl-backups",
                "us-east-1",
                "https://s3.us-east-1.amazonaws.com",
                "barectl/0123456789abcdef",
            ),
        )
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/settings/")
        self.page.get_by_role("button", name="Replace recovery passphrase").click()
        expect(self.page.get_by_role("heading", name="Replace recovery passphrase")).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "replace_recovery_passphrase")
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

    def test_the_integrity_finding_is_shown_apart_from_the_capture_result(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result(), integrity=(finding(),))
        record_points(server, (point(),), identifier="shop")
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        expect(self.page.get_by_role("heading", name="Integrity")).to_be_visible()
        expect(self.page.get_by_text("The newest recovery point was read back.")).to_be_visible()
        expect(self.page.get_by_text("Database only saved.")).to_be_visible()
        expect(self.page.get_by_text("On this server,", exact=False).first).to_be_visible()
        self.assert_no_native_terms()
        self.page.set_viewport_size({"width": 320, "height": 800})
        expect(self.page.get_by_role("heading", name="Integrity")).to_be_visible()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )

    def test_a_corrupted_pack_is_its_own_finding_and_leaves_the_capture_result(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(
            server,
            enabled=True,
            last=result(),
            integrity=(finding(result_class="failed", reason="integrity_pack", point=""),),
        )
        record_points(server, (point(),), identifier="shop")
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        expect(self.page.get_by_text("The last check found damaged data.")).to_be_visible()
        expect(self.page.get_by_text("Database only saved.")).to_be_visible()
        expect(self.page.get_by_text("Not verified")).to_be_visible()
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
        expect(self.page.get_by_role("heading", name="Restore shop")).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "restore_database")
        self.assertEqual(
            preparation.inputs,
            {"version": 1, "identifier": "shop", "point": "0123456789abcdef"},
        )
        self.assert_no_native_terms()
        self.page.set_viewport_size({"width": 320, "height": 800})
        expect(self.page.get_by_role("heading", name="Restore shop")).to_be_visible()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )

    def test_files_only_is_chosen_and_warns_about_the_database(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result(scope="full"))
        record_points(server, (point(scope="full", parts=("database", "files")),))
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        self.page.get_by_label("What to restore").select_option("files")
        self.page.get_by_role("button", name="Restore", exact=True).click()
        expect(self.page.get_by_role("heading", name="Restore shop")).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "restore_database")
        self.assertEqual(
            preparation.inputs,
            {
                "version": 1,
                "identifier": "shop",
                "point": "0123456789abcdef",
                "scope": "files",
            },
        )
        self.assert_no_native_terms()

    def test_full_site_is_chosen_and_restores_files_and_database(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result(scope="full"))
        record_points(server, (point(scope="full", parts=("database", "files")),))
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        self.page.get_by_label("What to restore").select_option("full")
        self.page.get_by_role("button", name="Restore", exact=True).click()
        expect(self.page.get_by_role("heading", name="Restore shop")).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "restore_database")
        self.assertEqual(preparation.inputs["scope"], "full")
        self.assert_no_native_terms()
        self.page.set_viewport_size({"width": 320, "height": 800})
        expect(self.page.get_by_role("heading", name="Restore shop")).to_be_visible()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )

    def test_a_wordpress_full_point_restores_through_its_review(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result(scope="full"), application="wordpress")
        record_points(server, (point(scope="full", parts=("database", "files")),))
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        self.page.get_by_label("What to restore").select_option("full")
        self.page.get_by_role("button", name="Restore", exact=True).click()
        expect(self.page.get_by_role("heading", name="Restore shop")).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "restore_database")
        self.assertEqual(preparation.inputs["scope"], "full")
        self.assert_no_native_terms()
        self.page.set_viewport_size({"width": 320, "height": 800})
        expect(self.page.get_by_role("heading", name="Restore shop")).to_be_visible()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )

    def test_a_laravel_full_point_restores_through_its_review(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result(scope="full"), application="laravel")
        record_points(server, (point(scope="full", parts=("database", "files")),))
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        self.page.get_by_label("What to restore").select_option("full")
        self.page.get_by_role("button", name="Restore", exact=True).click()
        expect(self.page.get_by_role("heading", name="Restore shop")).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "restore_database")
        self.assertEqual(preparation.inputs["scope"], "full")
        self.assert_no_native_terms()
        self.page.set_viewport_size({"width": 320, "height": 800})
        expect(self.page.get_by_role("heading", name="Restore shop")).to_be_visible()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )

    def test_retention_is_chosen_and_its_destructive_review_is_shown(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result())
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        expect(self.page.get_by_role("heading", name="Keep backups for")).to_be_visible()
        self.page.get_by_label("How long to keep recovery points").select_option("14")
        self.page.get_by_role("button", name="Set retention").click()
        expect(self.page.get_by_role("heading", name="Set retention")).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "set_backup_retention")
        self.assertEqual(preparation.inputs, {"version": 1, "identifier": "shop", "days": 14})
        self.assert_no_native_terms()
        self.page.set_viewport_size({"width": 320, "height": 800})
        expect(self.page.get_by_role("heading", name="Set retention")).to_be_visible()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )

    def test_a_recovery_point_is_kept_from_its_row(self) -> None:
        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result())
        record_points(server, (point(),))
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        self.page.get_by_role("button", name="Keep", exact=True).click()
        expect(self.page.get_by_role("heading", name="Keep recovery point")).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "keep_recovery_point")
        self.assertEqual(
            preparation.inputs,
            {"version": 1, "identifier": "shop", "point": "0123456789abcdef"},
        )
        self.assert_no_native_terms()

    def test_an_export_is_prepared_and_downloaded_from_its_recovery_point(self) -> None:
        from datetime import timedelta

        from django.utils import timezone

        from . import downloads
        from .bodies import export as export_body
        from .models import BackupExport

        server = Server.objects.get(name="Production")
        record_backups(server, enabled=True, last=result())
        record_points(server, (point(scope="full", parts=("database", "files")),))
        self.sign_in_operator()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        expect(self.page.get_by_text("Saved here")).to_be_visible()
        self.assert_no_native_terms()
        self.page.get_by_role("button", name="Export", exact=True).click()
        expect(self.page.get_by_role("heading", name="Export", level=1)).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "export_recovery_point")
        self.assertEqual(
            preparation.inputs,
            {"version": 1, "identifier": "shop", "point": "0123456789abcdef"},
        )
        self.assert_no_native_terms()
        self.page.set_viewport_size({"width": 320, "height": 800})
        expect(self.page.get_by_role("heading", name="Export", level=1)).to_be_visible()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )
        self.page.set_viewport_size({"width": 1280, "height": 800})

        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(override_settings(EXPORT_STAGING_PATH=directory))
        token = "d" * 32
        staged = downloads.local_root(token)
        staged.mkdir(parents=True)
        (staged / export_body.FILES_NAME).write_bytes(b"tar-content")
        (staged / export_body.DATABASE_NAME).write_bytes(b"dump-content")
        BackupExport.objects.create(
            server=server,
            identifier="shop",
            point="0123456789abcdef",
            token=token,
            files_bytes=11,
            database_bytes=12,
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/backups/")
        self.assert_no_native_terms()
        with self.page.expect_download() as download_info:
            self.page.get_by_role("link", name="Download files").click()
        download = download_info.value
        self.assertEqual(download.suggested_filename, "shop-0123456789abcdef-files.tar")
        self.assertEqual(pathlib.Path(download.path()).read_bytes(), b"tar-content")
        url = f"{self.live_server_url}/servers/{server.pk}/backups/exports/{token}/database/"
        response = self.page.request.get(url)
        self.assertEqual(response.status, 200)
        self.assertIn("no-store", response.headers["cache-control"])
        self.assertEqual(response.body(), b"dump-content")

        BackupExport.objects.filter(token=token).update(
            expires_at=timezone.now() - timedelta(minutes=1)
        )
        expired = self.page.request.get(url)
        self.assertEqual(expired.status, 404)

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
                "This stopped after pausing the site to restore it. Nothing after it ran."
            )
        ).to_be_visible()
        self.page.get_by_role("button", name="Reopen site").click()
        expect(self.page.get_by_role("heading", name="Reopen shop")).to_be_visible()
        self.assert_no_native_terms()
