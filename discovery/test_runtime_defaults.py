"""A discovery snapshot preserves observed native defaults without fallback authority."""

from dataclasses import replace

from django.test import TestCase
from runtimes.defaults import DefaultsObservation

from servers.models import Server

from .fakes import COLLECTED, COLLECTED_AT
from .models import DiscoveryAttempt
from .snapshot import current_snapshot, save_snapshot


class RuntimeDefaultsSnapshotTests(TestCase):
    def test_fresh_defaults_and_individual_administrator_findings_survive_storage(self) -> None:
        server = Server.objects.create(name="Defaults", ssh_alias="defaults.example.com")
        attempt = DiscoveryAttempt.objects.create(
            server=server, ssh_alias=server.ssh_alias, status=DiscoveryAttempt.Status.SUCCEEDED
        )
        defaults = DefaultsObservation(
            "php85", "", "", "Set by the administrator.", ("php84", "php85"), ("nodejs_24",)
        )
        collected = replace(COLLECTED, runtime_defaults=defaults)
        save_snapshot(attempt, collected, COLLECTED_AT)
        restored = current_snapshot(server)
        if restored is None:
            self.fail("No stored snapshot.")
        self.assertEqual(restored.collected.runtime_defaults, defaults)

    def test_unobserved_defaults_do_not_inherit_a_previous_selection(self) -> None:
        server = Server.objects.create(name="Defaults", ssh_alias="defaults.example.com")
        for defaults in (DefaultsObservation("php85"), None):
            attempt = DiscoveryAttempt.objects.create(
                server=server, ssh_alias=server.ssh_alias, status=DiscoveryAttempt.Status.SUCCEEDED
            )
            save_snapshot(attempt, replace(COLLECTED, runtime_defaults=defaults), COLLECTED_AT)
        restored = current_snapshot(server)
        if restored is None:
            self.fail("No stored snapshot.")
        self.assertIsNone(restored.collected.runtime_defaults)
