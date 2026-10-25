"""Keyboard changes a site's Node.js version from Settings with Site consent."""

import contextlib
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
class SiteNodeBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    def test_keyboard_changes_site_node_from_settings_without_shared_permission(self) -> None:
        server = Server.objects.get(name="Production")
        transcript = load("site-node-26.04")
        save_snapshot(
            record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED),
            collect(ReplayShell(transcript)),
            timezone.now(),
        )
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/s7node/settings/")
        self.assert_no_native_terms()
        expect(self.page.get_by_role("heading", name="Node.js version", level=2)).to_be_visible()
        change = self.page.get_by_role("link", name="Change Node.js version", exact=True)
        change.focus()
        self.page.keyboard.press("Enter")
        expect(self.page.locator("#change-node")).to_be_visible()
        self.page.locator("label[for='site-node-nodejs_24']").click()
        expect(self.page.locator("#site-node-nodejs_24")).to_be_checked()
        button = self.page.get_by_role("button", name="Continue", exact=True)
        button.focus()
        self.page.keyboard.press("Enter")
        expect(
            self.page.get_by_role("heading", name="Switch s7node to Node.js 24", level=1)
        ).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(
            preparation.inputs, {"version": 1, "identifier": "s7node", "selection": "nodejs_24"}
        )
        with mock.patch(
            "discovery.ssh.connect_operation",
            return_value=contextlib.nullcontext(ReplayShell(transcript)),
        ):
            run_worker()
        self.page.reload()
        review = ChangeReview.objects.get(preparation=preparation)
        self.assertTrue(review.eligible, review.document)
        self.assertEqual(review.consent, Consent.SITE)
        expect(self.page.get_by_role("button", name="Switch version", exact=True)).to_be_visible()
        self.page.set_viewport_size({"width": 375, "height": 812})
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/s7node/settings/")
        expect(
            self.page.get_by_role("link", name="Change Node.js version", exact=True)
        ).to_be_visible()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )
