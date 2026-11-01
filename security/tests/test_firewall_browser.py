"""The extra-port controls work by keyboard at a phone width (Phase E #306, #179)."""

import tempfile
from dataclasses import replace
from typing import override

from django.core.management import call_command
from django.test import override_settings, tag
from django.utils import timezone
from playwright.sync_api import expect

from dashboard.browser_testing import BrowserTestCase
from discovery.fakes import COLLECTED
from discovery.models import DiscoveryAttempt, ObservationOutcome
from discovery.snapshot import Observation, save_snapshot
from security.observation import (
    FirewallState,
    SshState,
    parse_ufw_added,
)
from security.testing import check, ok_state
from servers.models import Server


@tag("browser")
class FirewallPanelBrowserTests(BrowserTestCase):
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
            from django.contrib.auth.models import Permission

            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.server = Server.objects.create(name="Firewall", ssh_alias="firewall.example.com")
        rules = parse_ufw_added(
            "\n".join(
                (
                    "allow 22/tcp",
                    "allow 80/tcp",
                    "allow 443/tcp",
                    "allow 443/udp",
                    "allow 8080/tcp",
                )
            ),
            (22,),
        )
        state = replace(
            ok_state(),
            firewall=check(
                FirewallState(
                    True, True, "deny", "allow", "deny", True, "on (low)", rules, (), True
                )
            ),
            ssh=check(SshState("no", "no", "prohibit-password", (22,), (), (), "yes", (22,))),
        )
        attempt = DiscoveryAttempt.objects.create(
            server=self.server,
            ssh_alias=self.server.ssh_alias,
            status=DiscoveryAttempt.Status.SUCCEEDED,
        )
        save_snapshot(
            attempt,
            replace(
                COLLECTED,
                security=Observation(ObservationOutcome.OBSERVED, ("a read",), "", state),
            ),
            timezone.now(),
        )
        self.sign_in()

    def test_the_extra_port_controls_work_by_keyboard_at_320_pixels(self) -> None:
        page = self.page
        page.set_viewport_size({"width": 320, "height": 740})
        page.goto(f"{self.live_server_url}/servers/{self.server.pk}/security/")
        expect(page.get_by_text("Extra ports")).to_be_visible()
        self.assert_no_native_terms()
        summary = page.get_by_text("Allow another port")
        summary.focus()
        page.keyboard.press("Enter")
        expect(page.get_by_label("Port or range")).to_be_visible()
        page.get_by_label("Port or range").fill("5432")
        expect(page.get_by_role("button", name="Allow port", exact=True)).to_be_visible()
        self.assertEqual(
            page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            ),
            0,
        )
