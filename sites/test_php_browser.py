"""Journey 5: a site's PHP version changes from Settings, adding it first when missing."""

import tempfile
from dataclasses import replace
from typing import override

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from django.utils import timezone
from playwright.sync_api import expect

from dashboard.browser_testing import BrowserTestCase
from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt
from discovery.snapshot import current_snapshot, save_snapshot
from operations.models import ChangePreparation
from servers.models import Server
from sites.ui_testing import record_http_sites, record_step_run


def record_php85_installed(server: Server) -> None:
    record_http_sites(server)
    snapshot = current_snapshot(server)
    if snapshot is None:
        raise AssertionError("No snapshot.")
    runtimes = tuple(
        replace(row, path="/nix/store/observed-php85", master_state="active", problem="")
        if row.entry == "php85"
        else row
        for row in snapshot.collected.runtimes
    )
    save_snapshot(
        record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED),
        replace(snapshot.collected, runtimes=runtimes),
        timezone.now(),
    )


@tag("browser")
class SitePhpSettingsBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    def sign_in_and_open(self, server: Server) -> None:
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/alpha/settings/")

    def test_keyboard_changes_an_installed_php_version_from_settings(self) -> None:
        server = Server.objects.get(name="Production")
        record_php85_installed(server)
        self.sign_in_and_open(server)
        self.assert_no_native_terms()
        expect(self.page.get_by_role("heading", name="PHP version", level=2)).to_be_visible()
        change = self.page.get_by_role("link", name="Change PHP version", exact=True)
        change.focus()
        self.page.keyboard.press("Enter")
        expect(self.page.locator("#change-php")).to_be_visible()
        self.page.locator("label[for='site-php-php85']").click()
        expect(self.page.locator("#site-php-php85")).to_be_checked()
        button = self.page.get_by_role("button", name="Continue", exact=True)
        button.focus()
        self.page.keyboard.press("Enter")
        expect(
            self.page.get_by_role("heading", name="Select site PHP: review", level=1)
        ).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "set_site_php")
        self.assertEqual(
            preparation.inputs, {"version": 1, "identifier": "alpha", "selection": "php85"}
        )
        self.page.set_viewport_size({"width": 375, "height": 812})
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/alpha/settings/")
        expect(self.page.get_by_role("heading", name="PHP version", level=2)).to_be_visible()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )

    def test_a_missing_php_version_is_added_first_and_continues_the_switch(self) -> None:
        server = Server.objects.get(name="Production")
        record_http_sites(server)
        self.sign_in_and_open(server)
        self.page.get_by_role("link", name="Change PHP version", exact=True).click()
        self.page.locator("label[for='site-php-php85']").click()
        expect(self.page.locator("#site-php-php85")).to_be_checked()
        self.page.get_by_role("button", name="Continue", exact=True).click()
        expect(
            self.page.get_by_role("heading", name="Add runtime: review", level=1)
        ).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "add_runtime")
        self.assertEqual(preparation.inputs, {"version": 1, "selection": "php85"})
        run = record_step_run(preparation)
        self.page.goto(f"{self.live_server_url}/runs/{run.pk}/")
        link = self.page.get_by_role(
            "link", name="Continue to switch the site's PHP version", exact=True
        )
        link.click()
        expect(self.page.locator("#change-php")).to_be_visible()
        expect(self.page.locator("#site-php-php85")).to_be_checked()
        record_php85_installed(server)
        self.page.get_by_role("button", name="Continue", exact=True).click()
        expect(
            self.page.get_by_role("heading", name="Select site PHP: review", level=1)
        ).to_be_visible()
        latest = ChangePreparation.objects.filter(server=server).order_by("-pk").first()
        self.assertEqual(latest.kind_slug if latest is not None else "", "set_site_php")
