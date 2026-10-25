"""The four-place shell and installation Settings, driven as an operator (#362)."""

import tempfile
from typing import override

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from playwright.sync_api import expect

from servers.models import Server

from .browser_testing import BrowserTestCase as BrowserTestCase


@tag("browser")
class ShellBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    def _grant_all(self) -> None:
        for codename in ("view_siteobservation", "add_server"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))

    def test_each_place_is_one_activation_away_and_announced_current(self) -> None:
        self._grant_all()
        self.sign_in()
        page = self.page
        for path, label in (
            ("/", "Servers"),
            ("/sites/", "Sites"),
            ("/activity/", "Activity"),
            ("/settings/", "Settings"),
        ):
            with self.subTest(path=path):
                page.goto(f"{self.live_server_url}{path}")
                expect(page.get_by_role("heading", name=label, level=1)).to_be_visible()
                current = page.locator("nav[aria-label='Primary'] a[aria-current='page']")
                expect(current).to_have_text(label)

    def test_empty_places_offer_their_primary_action(self) -> None:
        self._grant_all()
        Server.objects.all().delete()
        self.sign_in()
        page = self.page
        for path in ("/", "/sites/"):
            with self.subTest(path=path):
                page.goto(f"{self.live_server_url}{path}")
                expect(page.get_by_role("heading", name="Add your first server")).to_be_visible()
                expect(page.get_by_role("link", name="Add server")).to_be_visible()
                self.assertEqual(
                    page.locator(
                        "main .usa-button:not(.usa-button--outline):not(.usa-button--unstyled)"
                    ).count(),
                    1,
                )
        page.goto(f"{self.live_server_url}/activity/")
        expect(page.get_by_role("heading", name="Activity", level=1)).to_be_visible()
        page.goto(f"{self.live_server_url}/settings/")
        expect(page.get_by_role("heading", name="Your account")).to_be_visible()
        expect(page.locator("#main-content").get_by_text("Signed in as operator")).to_be_visible()

    def test_keyboard_and_narrow_layout(self) -> None:
        self._grant_all()
        self.sign_in()
        page = self.page
        page.goto(f"{self.live_server_url}/")
        page.set_viewport_size({"width": 320, "height": 740})
        self.assertEqual(
            page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            ),
            0,
        )
        # The primary navigation follows the skip link and reaches Settings by keyboard.
        page.set_viewport_size({"width": 1280, "height": 900})
        page.goto(f"{self.live_server_url}/settings/")
        page.keyboard.press("Tab")
        expect(page.get_by_role("link", name="Skip to main content")).to_be_focused()
        page.keyboard.press("Tab")
        expect(page.get_by_role("link", name="Barectl")).to_be_focused()
        for _ in range(4):
            page.keyboard.press("Tab")
        expect(page.get_by_role("link", name="Settings", exact=True)).to_be_focused()
