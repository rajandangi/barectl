"""The Backups section asks the one preparation gate (spec #507, #512)."""

from html import unescape
from typing import TYPE_CHECKING

from django.contrib.messages import get_messages
from django.utils import timezone

from operations.fakes import ChangeTestCase
from operations.models import ChangePreparation
from servers.models import Server

from . import reopen, schedule
from .models import BackupRetention
from .observation import BackupResult, OffsiteStorage
from .testing import point, record_backups, record_points, result

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse

PERMISSIONS = (
    "view_server",
    "view_changes",
    "view_siteobservation",
    "change_site",
    "change_destructive",
    "change_shared",
    "manage_secrets",
)
BASE = ("view_server", "view_changes", "view_siteobservation", "change_site")
POINT = "0123456789abcdef"
SOURCE = "beta"
DESTRUCTIVE_SENTENCE = "Changing this needs the destructive-change permission."
SHARED_SENTENCE = "Changing this needs the shared-change permission."
SECRET_SENTENCE = "Changing this needs the manage-secrets permission."  # noqa: S105


def storage() -> OffsiteStorage:
    return OffsiteStorage(
        "s3",
        "barectl-test",
        "us-east-1",
        "https://s3.us-east-1.amazonaws.com",
        "barectl/abc",
    )


def removed(*identifiers: str) -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "identifier": identifier,
            "points": [point(scope="full", parts=("database", "files"))],
            "problem": "",
        }
        for identifier in identifiers
    )


class BackupsGateTests(ChangeTestCase):
    def store(
        self,
        *,
        gated: bool = False,
        enabled: bool = True,
        last: BackupResult | None = None,
        points: tuple[dict[str, object], ...] = (),
        removed_points: tuple[dict[str, object], ...] = (),
        offsite: OffsiteStorage | None = None,
        permissions: tuple[str, ...] = PERMISSIONS,
    ) -> Server:
        record_backups(self.server, gated=gated, enabled=enabled, last=last, offsite=offsite)
        if points or removed_points:
            record_points(self.server, points, removed=removed_points)
        self.sign_in_with(*permissions)
        return self.server

    def backups_page(self, server: Server) -> _MonkeyPatchedWSGIResponse:
        return self.client.get(f"/servers/{server.pk}/sites/shop/backups/")

    def act(
        self, server: Server, path: str, data: dict[str, str] | None = None
    ) -> _MonkeyPatchedWSGIResponse:
        return self.client.post(f"/servers/{server.pk}/sites/shop/backups/{path}/", data or {})

    def messages(self, response: _MonkeyPatchedWSGIResponse) -> list[str]:
        return [str(message) for message in get_messages(response.wsgi_request)]

    def assert_sentence(self, page: _MonkeyPatchedWSGIResponse, sentence: str) -> None:
        self.assertIn(sentence, unescape(page.content.decode()))

    def test_a_paused_site_offers_reopening_and_withholds_open_site_changes(self) -> None:
        sentence = "This site's backups are paused; reopen it before changing it."
        server = self.store(
            gated=True,
            last=result(result_class="partial", scope="full", reason="backup_paused"),
            points=(point(),),
            removed_points=removed(SOURCE),
            offsite=storage(),
        )
        BackupRetention.objects.create(
            server=server,
            identifier="shop",
            installed=True,
            days=14,
            checked_at=timezone.now(),
        )
        page = self.backups_page(server)
        self.assert_sentence(page, sentence)
        self.assertContains(page, "Reopen site")
        for path in (
            "backups/back-up/prepare/",
            "backups/schedule/prepare/",
            "backups/copy/prepare/",
            "backups/keep/prepare/",
            "backups/restore/prepare/",
            "backups/export/prepare/",
            "backups/retention/prepare/",
            "backups/retention/disable/prepare/",
            "backups/removed/delete/prepare/",
        ):
            with self.subTest(path=path):
                self.assertNotContains(page, path)

        for path, data in (
            ("back-up/prepare", {"scope": "full"}),
            (
                "schedule/prepare",
                {"state": "on", "frequency": "daily", "at": "03:00", "scope": "full"},
            ),
            ("copy/prepare", {"point": POINT}),
            ("keep/prepare", {"point": POINT}),
            ("restore/prepare", {"point": POINT}),
            ("export/prepare", {"point": POINT}),
            ("retention/prepare", {"days": "7"}),
            ("retention/disable/prepare", {}),
            ("removed/delete/prepare", {"source": SOURCE}),
        ):
            with self.subTest(path=path):
                ChangePreparation.objects.all().delete()
                response = self.act(server, path, data)
                self.assertEqual(response.status_code, 302)
                self.assertFalse(ChangePreparation.objects.exists())
                self.assertIn(sentence, self.messages(response))

        response = self.act(server, "reopen/prepare")
        self.assertEqual(response.status_code, 302)
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, reopen.SLUG)

    def test_a_gated_site_with_an_open_gate_withholds_with_the_gate_sentence(self) -> None:
        sentence = "This site's maintenance gate is in place; reopen it before changing it."
        server = self.store(gated=True, last=result())
        page = self.backups_page(server)
        self.assert_sentence(page, sentence)
        self.assertNotContains(page, "Reopen site")
        self.assertNotContains(page, "backups/back-up/prepare/")

        response = self.act(server, "back-up/prepare", {"scope": "full"})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ChangePreparation.objects.exists())
        self.assertIn(sentence, self.messages(response))

        response = self.act(server, "back-up-first/prepare")
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ChangePreparation.objects.exists())
        self.assertIn(sentence, self.messages(response))

    def test_an_account_without_manage_secrets_cannot_enable_backups(self) -> None:
        server = self.store(enabled=False, permissions=BASE)
        page = self.backups_page(server)
        self.assertContains(page, SECRET_SENTENCE)
        self.assertNotContains(page, "backups/enable/prepare/")

        response = self.act(server, "enable/prepare")
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ChangePreparation.objects.exists())
        self.assertIn(SECRET_SENTENCE, self.messages(response))

    def test_a_managed_site_offers_every_backup_action(self) -> None:
        server = self.store(points=(point(),), removed_points=removed(SOURCE), offsite=storage())
        BackupRetention.objects.create(
            server=server,
            identifier="shop",
            installed=True,
            days=14,
            checked_at=timezone.now(),
        )
        page = self.backups_page(server)
        for path in (
            "backups/back-up/prepare/",
            "backups/schedule/prepare/",
            "backups/copy/prepare/",
            "backups/keep/prepare/",
            "backups/restore/prepare/",
            "backups/export/prepare/",
            "backups/retention/prepare/",
            "backups/retention/disable/prepare/",
            "backups/removed/delete/prepare/",
        ):
            with self.subTest(path=path):
                self.assertContains(page, path)

    def test_an_account_without_destructive_is_withheld_with_that_reason(self) -> None:
        server = self.store(points=(point(),), removed_points=removed(SOURCE), permissions=BASE)
        page = self.backups_page(server)
        self.assert_sentence(page, DESTRUCTIVE_SENTENCE)
        self.assertContains(page, "Backups of a removed site")
        for path in (
            "backups/restore/prepare/",
            "backups/retention/prepare/",
            "backups/removed/delete/prepare/",
        ):
            with self.subTest(path=path):
                self.assertNotContains(page, path)
        for path, data in (
            ("restore/prepare", {"point": POINT}),
            ("retention/prepare", {"days": "7"}),
            ("removed/delete/prepare", {"source": SOURCE}),
        ):
            with self.subTest(path=path):
                ChangePreparation.objects.all().delete()
                response = self.act(server, path, data)
                self.assertEqual(response.status_code, 302)
                self.assertFalse(ChangePreparation.objects.exists())
                self.assertIn(DESTRUCTIVE_SENTENCE, self.messages(response))

    def test_an_account_without_shared_is_withheld_with_that_reason(self) -> None:
        server = self.store(points=(point(),), permissions=BASE)
        page = self.backups_page(server)
        self.assert_sentence(page, SHARED_SENTENCE)
        self.assertNotContains(page, "backups/export/prepare/")

        response = self.act(server, "export/prepare", {"point": POINT})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ChangePreparation.objects.exists())
        self.assertIn(SHARED_SENTENCE, self.messages(response))

    def test_the_schedule_card_and_post_withhold_together_on_a_paused_site(self) -> None:
        sentence = "This site's backups are paused; reopen it before changing it."
        server = self.store(
            gated=True,
            last=result(result_class="partial", scope="full", reason="backup_paused"),
        )
        page = self.backups_page(server)
        self.assert_sentence(page, sentence)
        self.assertNotContains(page, "backups/schedule/prepare/")

        response = self.act(
            server,
            "schedule/prepare",
            {"state": "on", "frequency": "daily", "at": "03:00", "scope": "full"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ChangePreparation.objects.exists())
        self.assertIn(sentence, self.messages(response))

    def test_the_schedule_card_and_post_are_offered_on_an_open_site(self) -> None:
        server = self.store()
        page = self.backups_page(server)
        self.assertContains(page, "backups/schedule/prepare/")

        response = self.act(
            server,
            "schedule/prepare",
            {"state": "on", "frequency": "weekly", "at": "04:30", "scope": "full"},
        )
        self.assertEqual(response.status_code, 302)
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, schedule.SLUG)

    def test_reopening_withholds_on_a_site_with_no_gate(self) -> None:
        server = self.store()
        response = self.act(server, "reopen/prepare")
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ChangePreparation.objects.exists())
        self.assertIn(
            "This site is not gated, so there is nothing to reopen.",
            self.messages(response),
        )

    def test_enable_is_offered_and_prepares_with_the_manage_secrets_permission(self) -> None:
        server = self.store(enabled=False)
        page = self.backups_page(server)
        self.assertContains(page, "backups/enable/prepare/")

        response = self.act(server, "enable/prepare")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(ChangePreparation.objects.get(server=server).kind_slug, "enable_backups")

    def test_a_site_without_backups_offers_only_enable(self) -> None:
        server = self.store(enabled=False)
        page = self.backups_page(server)
        self.assertContains(page, "backups/enable/prepare/")
        for path in (
            "backups/back-up/prepare/",
            "backups/schedule/prepare/",
            "backups/keep/prepare/",
            "backups/restore/prepare/",
            "backups/export/prepare/",
            "backups/retention/prepare/",
        ):
            with self.subTest(path=path):
                self.assertNotContains(page, path)
