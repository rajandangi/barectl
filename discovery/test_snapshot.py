from dataclasses import replace
from datetime import UTC, datetime
from typing import override

from django.test import TestCase

from servers.models import Server

from .models import DiscoveryAttempt, ObservationOutcome, WebStackComponent
from .snapshot import (
    CollectedSnapshot,
    FilesystemSize,
    Observation,
    OsRelease,
    Package,
    PoolEntryObservation,
    SiteFileObservation,
    Snapshot,
    WebStackComponentObservation,
    current_snapshot,
    save_snapshot,
)

OBSERVED = ObservationOutcome.OBSERVED
UNSUPPORTED = ObservationOutcome.UNSUPPORTED
COLLECTED_AT = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)

# Every kind of observation, observed and not, with values that span several lines.
COLLECTED = CollectedSnapshot(
    os=Observation(
        OBSERVED, ("/etc/os-release",), "", OsRelease("Ubuntu 24.04.3 LTS", "Ubuntu", "ubuntu", "")
    ),
    architecture=Observation(OBSERVED, ("uname -m",), "", "x86_64"),
    cpu_count=Observation(UNSUPPORTED, ("nproc",), "nproc did not report the CPU count.", None),
    memory_bytes=Observation(OBSERVED, ("/proc/meminfo",), "", 4_121_137_152),
    filesystem=Observation(
        OBSERVED, ("df -B1 --output=size,avail,target /",), "", FilesystemSize(53_689_778_176, 0)
    ),
    components=(
        WebStackComponentObservation(
            WebStackComponent.POSTGRESQL,
            Observation(
                OBSERVED,
                ("dpkg-query",),
                "",
                (Package("postgresql", "16+257build1.1"), Package("postgresql-16", "16.15-0")),
            ),
            Observation(
                OBSERVED,
                ("ls -1b /etc/postgresql", "systemctl show postgresql.service"),
                "",
                ("postgresql.service active (exited), enabled", "postgresql@16-main.service"),
            ),
        ),
        WebStackComponentObservation(
            WebStackComponent.NGINX,
            Observation(ObservationOutcome.ABSENT, ("dpkg-query",), "No Nginx packages.", ()),
            Observation(ObservationOutcome.ABSENT, ("dpkg-query",), "No Nginx packages.", ()),
        ),
    ),
    nginx_site_files=Observation(
        OBSERVED,
        ("/etc/nginx/sites-enabled",),
        "",
        (
            SiteFileObservation(
                "example.com",
                OBSERVED,
                ("example.com", "www.example.com"),
                ("443 ssl", "[::]:443 ssl"),
                "/etc/nginx/sites-enabled/example.com",
                "",
            ),
            SiteFileObservation(
                "private",
                ObservationOutcome.INACCESSIBLE,
                (),
                (),
                "/etc/nginx/sites-enabled/private",
                "The SSH user cannot read it.",
            ),
        ),
    ),
    php_fpm_pools=Observation(
        OBSERVED,
        ("/etc/php",),
        "Pools in skipped files are not shown.",
        (
            PoolEntryObservation(
                "8.3", "www", OBSERVED, "/run/php/php8.3-fpm.sock", "/etc/php/8.3/www.conf", ""
            ),
        ),
    ),
)


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
