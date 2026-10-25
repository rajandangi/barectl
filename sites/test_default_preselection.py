"""New-site forms use only a fresh, verified observed server default."""

import re
from dataclasses import replace
from typing import override

from django.utils import timezone

from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt
from discovery.snapshot import current_snapshot, save_snapshot
from runtimes.defaults import DefaultsObservation
from servers.models import Server
from servers.testing import ControllerConfigTestCase

from .ui_testing import record_http_sites


class DefaultPreselectionTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Defaults", ssh_alias="web.example.com")
        record_http_sites(self.server)

    def default_snapshot(self, *, verified: bool) -> None:
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("No setup snapshot.")
        runtimes = tuple(
            replace(row, master_state="active", problem="")
            if row.entry == "php85" and verified
            else row
            for row in snapshot.collected.runtimes
        )
        collected = replace(
            snapshot.collected,
            runtimes=runtimes,
            runtime_defaults=DefaultsObservation("php85", php_choices=("php84", "php85")),
        )
        attempt = record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED)
        save_snapshot(attempt, collected, timezone.now())

    def php_tiles(self, page: str) -> dict[str, bool]:
        """Each offered PHP version and whether its tile is preselected."""
        content = self.client.get(page).content.decode()
        return {
            entry: bool(re.search(rf'id="create-php-{entry}"\s+value="{entry}"\s+checked', content))
            for entry in ("php84", "php85")
        }

    def test_fresh_verified_default_is_selected_in_the_create_page(self) -> None:
        self.default_snapshot(verified=True)
        self.assertEqual(
            self.php_tiles(f"/servers/{self.server.pk}/sites/create/"),
            {"php84": False, "php85": True},
        )

    def test_unverified_default_falls_back_to_the_newest_installed(self) -> None:
        self.default_snapshot(verified=False)
        self.assertEqual(
            self.php_tiles(f"/servers/{self.server.pk}/sites/create/"),
            {"php84": True, "php85": False},
        )

    def test_a_failed_refresh_offers_no_runtime_and_selects_nothing(self) -> None:
        self.default_snapshot(verified=True)
        record_attempt(self.server, DiscoveryAttempt.Status.FAILED)
        page = self.client.get(f"/servers/{self.server.pk}/sites/create/")
        self.assertNotRegex(page.content.decode(), r'value="php8[45]"\s+checked')
        self.assertContains(page, "Check the connection first.")

    def test_with_no_default_and_nothing_installed_the_newest_offered_is_selected(self) -> None:
        record_http_sites(self.server, installed_php=False)
        self.assertEqual(
            self.php_tiles(f"/servers/{self.server.pk}/sites/create/"),
            {"php84": False, "php85": True},
        )
