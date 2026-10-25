import re
import tempfile
from dataclasses import replace
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from django.utils import timezone
from playwright.sync_api import expect

from bootstrap.standing import HostJudgment, Standing
from dashboard.browser_testing import BrowserTestCase
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome
from discovery.snapshot import Observation, save_snapshot
from operations.models import ChangePreparation
from runtimes.catalog import Architecture
from runtimes.catalog import load as load_catalog
from runtimes.observation import RuntimeObservation
from servers.models import Server


@tag("browser")
class RuntimeSettingsBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    def record_installed_php84(self, server: Server) -> None:
        build = next(
            item for item in load_catalog().offered(Architecture.X86_64) if item.entry == "php84"
        )
        collected = replace(
            COLLECTED,
            sites=Observation(ObservationOutcome.OBSERVED, ("caddy adapt",), "", ()),
            standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
            runtimes=(
                RuntimeObservation(
                    "php84",
                    build.path,
                    "php84-1-link",
                    build.version,
                    (),
                    "active",
                    (),
                    "",
                ),
            ),
        )
        attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
        save_snapshot(attempt, collected, timezone.now())

    def test_site_operator_adds_a_missing_version_from_server_settings(self) -> None:
        server = Server.objects.get(name="Production")
        self.record_installed_php84(server)
        for codename in ("view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/settings/")
            expect(self.page.get_by_text("PHP 8.4", exact=True)).to_be_visible()
            self.assert_no_native_terms()
            button = self.page.get_by_role("button", name="Add PHP 8.5", exact=True)
            expect(button).to_be_visible()
            button.focus()
            self.page.keyboard.press("Enter")
            expect(self.page).to_have_url(re.compile(r".*/changes/\d+/$"))
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "add_runtime")
        self.assertEqual(preparation.inputs, {"version": 1, "selection": "php85"})
        self.page.set_viewport_size({"width": 375, "height": 812})
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/settings/")
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )

    def test_site_operator_queues_an_unused_runtime_removal_from_advanced(self) -> None:
        server = Server.objects.get(name="Production")
        self.record_installed_php84(server)
        for codename in ("view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/advanced/?tab=php")
        button = self.page.get_by_role("button", name="Remove runtime php84", exact=True)
        expect(button).to_be_visible()
        button.focus()
        self.page.keyboard.press("Enter")
        expect(self.page).to_have_url(re.compile(r".*/changes/\d+/$"))
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.inputs, {"version": 1, "selection": "php84"})
        self.assertEqual(preparation.kind_slug, "remove_runtime")

    def test_native_runtime_detail_is_two_activations_from_settings(self) -> None:
        server = Server.objects.get(name="Production")
        self.record_installed_php84(server)
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/settings/")
        self.assert_no_native_terms()
        expect(self.page.get_by_text("Master state", exact=True)).to_have_count(0)
        self.page.get_by_role("navigation", name="Server sections").get_by_role(
            "link", name="Advanced", exact=True
        ).click()
        self.page.get_by_role("link", name="PHP runtimes", exact=True).click()
        expect(self.page.get_by_text("Master state", exact=True)).to_be_visible()
