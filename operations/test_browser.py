"""The confirm screen and the run page in a browser: plain words by default, the full
record under Show details and Logs, and keyboard-only confirmation (#179, #364)."""

import tempfile
from datetime import timedelta
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
from operations.models import (
    ChangePreparation,
    ChangeReview,
    ChangeRun,
    RemoteOperation,
    Result,
    Verification,
)
from servers.models import Server

STAGES = ("preflight", "Nix", "catalog", "Caddy", "journald", "verify")


def prepare(
    server: Server, *, shared_sites: tuple[str, ...] = (), expired: bool = False
) -> ChangePreparation:
    preparation = ChangePreparation.objects.create(
        server=server,
        kind_slug="host_foundation",
        requested_by=None,
        status=RemoteOperation.Status.SUCCEEDED,
        ssh_alias=server.ssh_alias,
    )
    expires = timezone.now() - timedelta(minutes=1) if expired else None
    review = save_review(
        preparation,
        ReviewDraft(
            kind="host_foundation",
            intent="Set up the server's web stack.",
            effects=(DeclaredEffect(Scope.SHARED, "Install the web stack.", shared_sites),),
            stages=STAGES,
            boot_id=BOOT_ID,
            uptime_centiseconds=500000,
            document={"version": 1, "details": [{"label": "Web server", "value": "Installed"}]},
        ),
        host_key="ssh-ed25519 key",
        collected_at=timezone.now(),
        sites_digest="",
    )
    if expires is not None:
        ChangeReview.objects.filter(pk=review.pk).update(admission_expires_at=expires)
    return preparation


@tag("browser")
class ConfirmAndRunBrowserTests(BrowserTestCase):
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
            "view_changes",
            "change_site",
            "change_shared",
            "change_destructive",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.server = Server.objects.get(name="Production")

    def test_a_shared_confirmation_is_plain_and_needs_the_tick_box(self) -> None:
        preparation = prepare(self.server, shared_sites=("alpha", "beta"))
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/changes/{preparation.pk}/")
        expect(self.page.get_by_role("heading", name="Set up Production", level=1)).to_be_visible()
        expect(self.page.get_by_text("This change also touches these sites:")).to_be_visible()
        expect(self.page.get_by_text("alpha, beta").first).to_be_visible()
        self.assert_no_native_terms()
        # Show details is a closed accordion holding the full review.
        details = self.page.get_by_role("button", name="Show details", exact=True)
        expect(details).to_have_attribute("aria-expanded", "false")
        expect(self.page.locator("#show-details")).to_be_hidden()
        details.click()
        expect(details).to_have_attribute("aria-expanded", "true")
        expect(self.page.get_by_text("Consent level")).to_be_visible()
        # The tick box is required: without it the browser submits nothing.
        apply = self.page.get_by_role("button", name="Set up server", exact=True)
        apply.click()
        self.page.wait_for_load_state("load")
        expect(self.page.get_by_role("heading", name="Set up Production", level=1)).to_be_visible()
        self.assertFalse(ChangeRun.objects.exists())
        # A keyboard operator ticks it and confirms.
        tick = self.page.get_by_label(
            "I understand this change touches shared resources", exact=False
        )
        tick.focus()
        self.page.keyboard.press("Space")
        expect(tick).to_be_checked()
        apply.press("Enter")
        run = ChangeRun.objects.get(review__preparation=preparation)
        self.assertEqual(self.page.url, f"{self.live_server_url}/runs/{run.pk}/")
        expect(self.page.get_by_role("heading", name="Queued")).to_be_visible()

    def test_an_expired_confirmation_offers_check_again(self) -> None:
        preparation = prepare(self.server, expired=True)
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/changes/{preparation.pk}/")
        expect(self.page.get_by_text("This confirmation is out of date.")).to_be_visible()
        expect(self.page.get_by_role("button", name="Set up server", exact=True)).to_have_count(0)
        self.page.get_by_role("button", name="Check again", exact=True).click()
        expect(self.page.get_by_text("Checking the server…")).to_be_visible()
        self.assertEqual(ChangePreparation.objects.count(), 2)

    def test_progress_marks_the_current_step_and_logs_hold_the_native_record(self) -> None:
        preparation = prepare(self.server)
        review = ChangeReview.objects.get(preparation=preparation)
        run = ChangeRun.objects.create(
            server=self.server,
            review=review,
            requested_by=self.user,
            requested_by_name="operator",
            server_name=self.server.name,
            unit_name="barectl-apply-" + "a" * 32 + ".service",
            status=RemoteOperation.Status.RUNNING,
            execution=Result.SUBMITTED,
            verification=Verification.PENDING,
            progress_stage="Nix",
        )
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/runs/{run.pk}/")
        expect(self.page.get_by_role("heading", name="Set up Production", level=1)).to_be_visible()
        expect(self.page.get_by_role("heading", name="Working")).to_be_visible()
        current = self.page.locator("li[aria-current='step']")
        expect(current).to_have_count(1)
        expect(current).to_contain_text("Installing")
        expect(current).to_contain_text("In progress")
        self.assert_no_native_terms()
        self.page.get_by_role("link", name="Logs", exact=True).click()
        expect(self.page.get_by_role("heading", name="Logs", level=2)).to_be_visible()
        expect(self.page.get_by_text("Systemd unit")).to_be_visible()
        self.assertIn(run.unit_name, self.page.content())
        expect(self.page.get_by_text("Invocation")).to_be_visible()
