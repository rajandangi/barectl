from dataclasses import replace
from datetime import UTC, datetime
from typing import override
from unittest import mock

from django.db import connection, transaction
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from backups import integrity
from backups.models import (
    BackupIntegrity,
    BackupObservation,
    BackupRunObservation,
    BackupTimerObservation,
)
from backups.observation import (
    BackupRun,
    BackupTimer,
    CleanupCounts,
    IntegrityFinding,
    ObservedBackup,
)
from bootstrap.standing import HostJudgment, Standing
from jobs.models import JobObservation
from jobs.observation import JobReading, ObservedChange, ProviderCoverage
from logs.journal_retention import MANAGED, RetentionObservation
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

    def test_a_job_contract_version_reads_back_from_typed_rows(self) -> None:
        unit = "barectl-apply-" + "a" * 32 + ".service"
        reading = JobReading(
            changes=(ObservedChange(unit=unit, contract=1),),
            coverage=(ProviderCoverage("barectl_changes", "complete"),),
        )
        collected = replace(
            COLLECTED,
            jobs=Observation(OBSERVED, ("journalctl",), "", reading),
        )
        save_snapshot(self.attempt(), collected, COLLECTED_AT)

        loaded = current_snapshot(self.server)
        if loaded is None:
            self.fail("The saved snapshot did not read back.")
        self.assertEqual(loaded.collected.jobs.value.changes[0].contract, 1)
        self.assertEqual(JobObservation.objects.get().contract, 1)

    def test_backup_runs_and_timers_read_back_from_typed_rows(self) -> None:
        backup = ObservedBackup(
            "alpha",
            "/nix/store/rac858616ds2w2z3db69kp80vr9s8mkp-restic-0.18.1",
            True,
            True,
            (),
            True,
            "",
            None,
            None,
            None,
            (),
            (
                BackupRun(
                    "cleanup",
                    "failed",
                    "backup_prune",
                    "2026-11-03T10:00:00+00:00",
                    "0123456789abcdef",
                    "all",
                    "scheduled",
                    1,
                    4096,
                    "",
                    "onsite",
                    0,
                    "",
                    CleanupCounts(2, 1, 3, 4),
                    CleanupCounts(0, 0, 0, 0),
                ),
            ),
            (BackupTimer("backup", "", True, 1_762_000_000_000_000, 1_761_000_000_000_000),),
            True,
            False,
        )
        collected = replace(
            COLLECTED, backups=Observation(OBSERVED, ("journalctl",), "", (backup,))
        )
        save_snapshot(self.attempt(), collected, COLLECTED_AT)
        stored = current_snapshot(self.server)
        if stored is None:
            self.fail("The snapshot was stored.")
        self.assertEqual(stored.collected.backups.value, (backup,))
        observation = BackupObservation.objects.get()
        self.assertTrue(observation.runs_truncated)
        self.assertFalse(observation.timers_truncated)
        self.assertEqual(BackupRunObservation.objects.get().onsite_failed, 4)
        self.assertTrue(BackupTimerObservation.objects.get().on)

    def test_snapshot_integrity_writes_are_batched_and_preserve_other_evidence(self) -> None:
        previous = IntegrityFinding(
            "onsite", "succeeded", "", "2026-11-01T00:00:00+00:00", "a" * 16, 1, 2, 4096, "1/20"
        )
        updated = IntegrityFinding(
            "onsite",
            "failed",
            "integrity_pack",
            "2026-11-15T00:00:00+00:00",
            "b" * 16,
            3,
            4,
            8192,
            "2/20",
        )
        other = Server.objects.create(name="Other", ssh_alias="other.example.com")
        integrity.record(other, "site0", (previous,))
        integrity.record(self.server, "unobserved", (previous,))
        backups: list[ObservedBackup] = []
        for index in range(8):
            identifier = f"site{index}"
            if index < 7:
                integrity.record(
                    self.server, identifier, (previous, replace(previous, location="offsite"))
                )
            findings = (
                ()
                if index % 3 == 0
                else (updated,)
                if index % 3 == 1
                else (updated, replace(updated, location="offsite"))
            )
            backups.append(ObservedBackup(identifier, integrity=findings))
        existing = {
            (row.identifier, row.location): row.pk
            for row in BackupIntegrity.objects.filter(server=self.server)
        }
        collected = replace(
            COLLECTED, backups=Observation(OBSERVED, ("journalctl",), "", tuple(backups))
        )
        attempt = self.attempt()
        with (
            mock.patch("django.utils.timezone.now", return_value=COLLECTED_AT),
            transaction.atomic(),
            CaptureQueriesContext(connection) as captured,
        ):
            save_snapshot(attempt, collected, COLLECTED_AT)

        for backup in backups:
            self.assertEqual(
                integrity.stored(self.server, backup.identifier),
                tuple(sorted(backup.integrity, key=lambda finding: finding.location)),
            )
        for row in BackupIntegrity.objects.filter(server=self.server).exclude(
            identifier="unobserved"
        ):
            self.assertEqual(row.checked_at, COLLECTED_AT)
            key = (row.identifier, row.location)
            if key in existing:
                self.assertEqual(row.pk, existing[key])
        self.assertEqual(integrity.stored(other, "site0"), (previous,))
        self.assertEqual(integrity.stored(self.server, "unobserved"), (previous,))
        writes = [query for query in captured if "backups_backupintegrity" in query["sql"]]
        self.assertLessEqual(len(writes), 2)

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

    def test_the_retention_observation_reads_back_from_typed_columns(self) -> None:
        retention = RetentionObservation(MANAGED, "", "2G", "3months")
        collected = replace(COLLECTED, journal_retention=retention)
        save_snapshot(self.attempt(), collected, COLLECTED_AT)
        stored = current_snapshot(self.server)
        if stored is None:
            self.fail("The snapshot was stored.")
        self.assertEqual(stored.collected.journal_retention, retention)

    def test_a_snapshot_without_a_retention_read_reads_back_not_checked(self) -> None:
        save_snapshot(self.attempt(), COLLECTED, COLLECTED_AT)
        stored = current_snapshot(self.server)
        if stored is None:
            self.fail("The snapshot was stored.")
        self.assertIsNone(stored.collected.journal_retention)

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
