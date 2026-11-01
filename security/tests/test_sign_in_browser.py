"""The SSH sign-in action works through its rendered Security form (#308, #179)."""

import re
import tempfile
from dataclasses import replace
from typing import override

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from django.utils import timezone
from playwright.sync_api import expect

from dashboard.browser_testing import BrowserTestCase
from discovery.fakes import COLLECTED
from discovery.models import DiscoveryAttempt, ObservationOutcome
from discovery.snapshot import Observation, save_snapshot
from operations.models import ChangePreparation
from security.observation import SshState
from security.testing import check, ok_state
from servers.models import Server


@tag("browser")
class SignInBrowserTests(BrowserTestCase):
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
            "view_server",
            "view_siteobservation",
            "view_changes",
            "change_site",
            "change_shared",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.server = Server.objects.create(name="SSH", ssh_alias="ssh.example.com")
        attempt = DiscoveryAttempt.objects.create(
            server=self.server,
            ssh_alias=self.server.ssh_alias,
            status=DiscoveryAttempt.Status.SUCCEEDED,
        )
        state = replace(
            ok_state(),
            ssh=check(
                SshState(
                    "yes",
                    "no",
                    "yes",
                    (22,),
                    (22,),
                    ("deploy",),
                    "yes",
                    (22,),
                    (),
                    True,
                    True,
                    ("deploy", "root"),
                )
            ),
        )
        save_snapshot(
            attempt,
            replace(COLLECTED, security=Observation(ObservationOutcome.OBSERVED, (), "", state)),
            timezone.now(),
        )
        self.sign_in()

    def test_keyboard_control_at_320_pixels_prepares_the_change(self) -> None:
        page = self.page
        page.set_viewport_size({"width": 320, "height": 740})
        page.goto(f"{self.live_server_url}/servers/{self.server.pk}/security/")
        self.assert_no_native_terms()
        button = page.get_by_role("button", name="Require key sign-in")
        button.focus()
        page.keyboard.press("Enter")
        expect(page).to_have_url(re.compile(r"/changes/\d+/$"))
        preparation = ChangePreparation.objects.get(server=self.server)
        self.assertEqual(preparation.kind_slug, "require_key_sign_in")
        self.assertEqual(preparation.inputs, {"version": 1, "selection": "on"})
        self.assertEqual(
            page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            ),
            0,
        )
