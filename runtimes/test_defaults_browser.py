import contextlib
import re
import tempfile
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from django.utils import timezone
from playwright.sync_api import expect

from dashboard.browser_testing import BrowserTestCase
from discovery.fakes import record_attempt, run_worker
from discovery.models import DiscoveryAttempt
from discovery.observations import collect
from discovery.recorded import ReplayShell, load
from discovery.snapshot import save_snapshot
from operations.models import ChangePreparation, ChangeReview, Consent
from servers.models import Server


@tag("browser")
class DefaultCommandBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    def test_keyboard_changes_an_installed_default_from_server_settings(self) -> None:
        server = Server.objects.get(name="Production")
        transcript = load("runtime-defaults-26.04")
        attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
        save_snapshot(attempt, collect(ReplayShell(transcript)), timezone.now())
        for codename in ("view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/settings/")
        self.assert_no_native_terms()
        selection = self.page.get_by_label("Default PHP version", exact=True)
        expect(selection).to_have_value("php85")
        selection.select_option("php84")
        button = self.page.get_by_role("button", name="Change default PHP", exact=True)
        button.focus()
        self.page.keyboard.press("Enter")
        expect(self.page).to_have_url(re.compile(r".*/changes/\d+/$"))
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.inputs, {"version": 1, "selection": "php84"})
        with mock.patch(
            "discovery.ssh.connect_operation",
            return_value=contextlib.nullcontext(ReplayShell(transcript)),
        ):
            run_worker()
        self.page.reload()
        review = ChangeReview.objects.get(preparation=preparation)
        self.assertTrue(review.eligible, review.document)
        self.assertEqual(review.consent, Consent.SHARED)
        expect(self.page.get_by_role("button", name="Set default PHP", exact=True)).to_have_count(0)
        self.user.user_permissions.add(Permission.objects.get(codename="change_shared"))
        self.page.reload()
        expect(self.page.get_by_role("button", name="Set default PHP", exact=True)).to_be_visible()
        self.page.set_viewport_size({"width": 375, "height": 812})
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/settings/")
        expect(
            self.page.get_by_role("button", name="Change default PHP", exact=True)
        ).to_be_visible()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )
