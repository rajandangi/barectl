from dataclasses import replace
from datetime import UTC, datetime
from typing import override

from django.test import TestCase

from servers.models import Server

from .fakes import COLLECTED, COLLECTED_AT
from .models import DiscoveryAttempt, ObservationOutcome, SiteStage
from .snapshot import (
    Observation,
    ObservedCertificate,
    ObservedSite,
    ServedCertificate,
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

    @staticmethod
    def activated_site() -> ObservedSite:
        fingerprint = "a1" * 32
        return ObservedSite(
            identifier="alpha",
            server_names=("alpha.test", "www.alpha.test"),
            document_root="/var/www/alpha/public",
            fastcgi_socket="/run/php/salpha.sock",
            php_version="8.3",
            pool_user="salpha",
            pool_group="salpha",
            account=None,
            resources=(),
            stage=SiteStage.HTTPS,
            certificate_reference="/etc/letsencrypt/live/alpha/fullchain.pem",
            certificate_key_reference="/etc/letsencrypt/live/alpha/privkey.pem",
            certificate=ObservedCertificate(
                outcome=OBSERVED,
                conforms=True,
                issuer="C = US, O = Let's Encrypt, CN = R3",
                not_before="Sep  1 00:00:00 2026 GMT",
                not_after="Nov 30 23:59:59 2026 GMT",
                serial="03A1B2C3D4",
                fingerprint=fingerprint,
                names=("alpha.test", "www.alpha.test"),
                served=(
                    ServedCertificate("alpha.test", fingerprint),
                    ServedCertificate("www.alpha.test", ""),
                ),
                renewal="present",
                source=("openssl x509", "openssl s_client"),
            ),
        )

    def test_an_activated_site_reads_back_with_its_certificate(self) -> None:
        site = self.activated_site()
        collected = replace(COLLECTED, sites=Observation(OBSERVED, ("sites",), "", (site,)))
        save_snapshot(self.attempt(), collected, COLLECTED_AT)
        stored = current_snapshot(self.server)
        if stored is None:
            self.fail("The snapshot was stored.")
        self.assertEqual(stored, Snapshot(collected, COLLECTED_AT, "web.example.com"))
        (read,) = stored.collected.sites.value
        self.assertEqual(read.stage, SiteStage.HTTPS)
        self.assertEqual(read.certificate_reference, site.certificate_reference)
        self.assertEqual(read.certificate_key_reference, site.certificate_key_reference)
        self.assertEqual(read.certificate, site.certificate)
