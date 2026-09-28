from dataclasses import replace
from datetime import UTC, datetime
from typing import override

from django.test import TestCase

from servers.models import Server

from .fakes import COLLECTED, COLLECTED_AT
from .models import DiscoveryAttempt, ObservationOutcome
from .snapshot import (
    Observation,
    Snapshot,
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
            current_snapshot(self.server), Snapshot(COLLECTED, COLLECTED_AT, "web.example.com")
        )

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
            current_snapshot(self.server), Snapshot(refreshed, later, "web.example.com")
        )
        self.assertEqual(self.server.snapshots.count(), 1)
