"""New-site forms use only a fresh, verified observed server default."""

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
        self.server = Server.objects.create(name="Defaults", ssh_alias="defaults.example.com")
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

    def test_fresh_verified_default_is_selected_in_new_site_form(self) -> None:
        self.default_snapshot(verified=True)
        response = self.client.get(f"/servers/{self.server.pk}/sites/")
        self.assertContains(response, '<option value="php85" selected>')

    def test_unverified_default_is_not_selected(self) -> None:
        self.default_snapshot(verified=False)
        response = self.client.get(f"/servers/{self.server.pk}/sites/")
        self.assertNotContains(response, '<option value="php85" selected>')
        self.assertContains(response, "PHP 8.5 (installs first")

    def test_failed_refresh_does_not_preselect_an_older_default(self) -> None:
        self.default_snapshot(verified=True)
        record_attempt(self.server, DiscoveryAttempt.Status.FAILED)
        response = self.client.get(f"/servers/{self.server.pk}/sites/")
        self.assertNotContains(response, '<option value="php85" selected>')
