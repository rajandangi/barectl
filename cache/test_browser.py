"""#391's browser journey: install Valkey from Server Settings in three activations."""

import tempfile
from typing import override

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from django.utils import timezone
from playwright.sync_api import expect

from dashboard.browser_testing import BrowserTestCase
from operations.consent import DeclaredEffect, Scope
from operations.engine import ReviewDraft, save_review
from operations.fakes import BOOT_ID
from operations.models import ChangePreparation, ChangeRun, RemoteOperation
from servers.models import Server
from sites.ui_testing import record_http_sites


@tag("browser")
class ValkeyInstallBrowserTests(BrowserTestCase):
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
            "view_siteobservation",
            "change_shared",
            "change_site",
            "view_changes",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.server = Server.objects.get(name="Production")
        Server.objects.exclude(pk=self.server.pk).delete()
        record_http_sites(self.server)
        self.activations = 0
        self.sign_in()

    def activate(self, action: object) -> None:
        self.activations += 1
        if self.activations > 3:
            self.fail(f"A fourth activation was needed: {action}")
        action()  # type: ignore[operator]

    def review(self, preparation: ChangePreparation) -> None:
        save_review(
            preparation,
            ReviewDraft(
                kind=preparation.kind_slug,
                intent="Install Valkey.",
                effects=(
                    DeclaredEffect(
                        Scope.SERVER,
                        "Install Valkey (valkey-server 9.0.4-0ubuntu0.2, 1.6 MB download) from "
                        "the Ubuntu archive and stop and mask the distribution's shared "
                        "service.",
                    ),
                ),
                stages=("preflight", "install", "mask", "recover", "verify"),
                boot_id=BOOT_ID,
                uptime_centiseconds=500000,
            ),
            host_key="ssh-ed25519 key",
            collected_at=timezone.now(),
            sites_digest="",
        )
        ChangePreparation.objects.filter(pk=preparation.pk).update(
            status=RemoteOperation.Status.SUCCEEDED
        )

    def test_install_valkey_in_three_activations_without_native_terms(self) -> None:
        page = self.page
        page.goto(f"{self.live_server_url}/servers/{self.server.pk}/settings/")
        self.assert_no_native_terms()
        self.activate(page.get_by_role("button", name="Install Valkey", exact=True).click)

        preparation = ChangePreparation.objects.get(kind_slug="install_valkey")
        self.review(preparation)
        page.reload()
        tick = page.get_by_label("I understand this change touches shared resources", exact=False)
        self.activate(tick.check)
        self.activate(page.get_by_role("button", name="Install Valkey", exact=True).click)

        run = ChangeRun.objects.get(review__preparation=preparation)
        expect(page).to_have_url(f"{self.live_server_url}/runs/{run.pk}/")
        self.assertEqual(run.review.consent, "shared")

    def test_server_settings_keeps_one_primary_button(self) -> None:
        page = self.page
        page.goto(f"{self.live_server_url}/servers/{self.server.pk}/settings/")
        selector = "main .usa-button:not(.usa-button--outline):not(.usa-button--unstyled)"
        self.assertLessEqual(page.locator(selector).count(), 1)
