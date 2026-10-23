from dataclasses import replace
from datetime import UTC, datetime
from typing import override

from django.test import TestCase

from bootstrap.standing import HostJudgment, Standing
from servers.models import Server

from .fakes import COLLECTED, COLLECTED_AT
from .models import (
    DiscoveryAttempt,
    ObservationOutcome,
    WebStackComponent,
)
from .snapshot import (
    Observation,
    ObservedSetting,
    Package,
    Snapshot,
    WebStackComponentObservation,
    current_snapshot,
    save_snapshot,
)

OBSERVED = ObservationOutcome.OBSERVED


class SnapshotStorageTests(TestCase):
    @override
    def setUp(self) -> None:
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def attempt(self) -> DiscoveryAttempt:
        return DiscoveryAttempt.objects.create(
            server=self.server,
            ssh_alias=self.server.ssh_alias,
            status=DiscoveryAttempt.Status.SUCCEEDED,
        )

    def test_a_saved_snapshot_reads_back_unchanged(self) -> None:
        save_snapshot(self.attempt(), COLLECTED, COLLECTED_AT)
        self.assertEqual(
            current_snapshot(self.server),
            Snapshot(COLLECTED, COLLECTED_AT, "web.example.com", self.server.snapshots.get().pk),
        )

    def test_a_components_profile_state_reads_back(self) -> None:
        deviation = "nginx 1.2 is installed but is not one of the profile's packages."
        component = WebStackComponentObservation(
            WebStackComponent.NGINX,
            Observation(OBSERVED, ("dpkg-query",), "", (Package("nginx", "1.2"),)),
            Observation(OBSERVED, ("systemctl",), "", ()),
            managed=False,
            deviations=(deviation,),
        )
        collected = replace(COLLECTED, components=(component,))
        save_snapshot(self.attempt(), collected, COLLECTED_AT)
        stored = current_snapshot(self.server)
        if stored is None:
            self.fail("The snapshot was stored.")
        self.assertEqual(stored.collected.components, (component,))

    def test_host_standing_and_foundation_read_back(self) -> None:
        standing = HostJudgment(
            Standing.NOT_MANAGEABLE,
            ("Ubuntu 24.04 is outside supported settings.",),
            (),
            (("Nix", "partial"), ("Catalog realisation", "absent")),
            (("APT series", "3.2"), ("Privilege", "Available")),
        )
        collected = replace(COLLECTED, standing=standing)
        save_snapshot(self.attempt(), collected, COLLECTED_AT)
        stored = current_snapshot(self.server)
        if stored is None:
            self.fail("The snapshot was stored.")
        self.assertEqual(stored.collected.standing, standing)

    def test_settings_keys_and_values_read_back(self) -> None:
        settings = (
            ObservedSetting("alpha", "laravel", "APP_URL", "a" * 64, "https://alpha.example.com"),
            ObservedSetting("alpha", "laravel", "MAIL_PASSWORD", "b" * 64),
            ObservedSetting("shop", "wordpress", "MAIL_HOST", "c" * 64),
        )
        collected = replace(COLLECTED, settings=Observation(OBSERVED, ("/var/www",), "", settings))
        save_snapshot(self.attempt(), collected, COLLECTED_AT)
        stored = current_snapshot(self.server)
        if stored is None:
            self.fail("The snapshot was stored.")
        self.assertEqual(stored.collected.settings, collected.settings)

    def test_a_server_without_a_snapshot_has_none(self) -> None:
        self.assertIsNone(current_snapshot(self.server))

    def test_saving_replaces_the_previous_snapshot(self) -> None:
        save_snapshot(self.attempt(), COLLECTED, COLLECTED_AT)
        later = datetime(2026, 9, 28, tzinfo=UTC)
        refreshed = replace(
            COLLECTED, architecture=Observation(OBSERVED, ("uname -m",), "", "aarch64")
        )
        save_snapshot(self.attempt(), refreshed, later)
        self.assertEqual(
            current_snapshot(self.server),
            Snapshot(refreshed, later, "web.example.com", self.server.snapshots.get().pk),
        )
        self.assertEqual(self.server.snapshots.count(), 1)
