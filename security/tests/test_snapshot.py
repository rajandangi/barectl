from dataclasses import replace

from django.test import TestCase

from discovery.fakes import COLLECTED, COLLECTED_AT
from discovery.models import DiscoveryAttempt, ObservationOutcome
from discovery.snapshot import Observation, current_snapshot, save_snapshot
from security.observation import (
    AutoUpdatesState,
    Check,
    FirewallRule,
    FirewallState,
    Listener,
    PendingUpdate,
    RestartState,
    SecurityState,
    SshState,
    UpdatesState,
)
from servers.models import Server

ALL_INTERFACES = "0.0.0.0"  # noqa: S104 - an observed address, never bound


def _check[T](value: T) -> Check[T]:
    return Check(ObservationOutcome.OBSERVED, ("a fixed read",), "", value)


def _blocked[T]() -> Check[T]:
    return Check(ObservationOutcome.INACCESSIBLE, ("id -u",), "Root is not available.", None)


STATE = SecurityState(
    firewall=_check(
        FirewallState(
            True,
            True,
            "deny",
            "allow",
            "deny",
            True,
            "on (low)",
            (FirewallRule("standard", "ufw allow 22/tcp", "allow", "tcp", "22"),),
            ("Docker is active.",),
            True,
        )
    ),
    listeners=_check((Listener(ALL_INTERFACES, 443, "tcp", "caddy", True),)),
    ssh=_check(SshState("no", "no", "prohibit-password", (22,), (22,), ("deploy",), "yes")),
    auto_updates=_check(
        AutoUpdatesState(
            True,
            "active",
            "enabled",
            False,
            ("Ubuntu:resolute", "Ubuntu:resolute-security"),
            True,
            "No updates were installed.",
            3600,
        )
    ),
    updates=_check(
        UpdatesState(
            7200,
            (PendingUpdate("openssl", "3.0.0", "3.0.1", "resolute-security/main", "security"),),
        )
    ),
    restart=_check(RestartState(True, ("linux-image-generic",))),
)


class SecuritySnapshotStorageTests(TestCase):
    def test_every_stored_check_reads_back_unchanged(self) -> None:
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        attempt = DiscoveryAttempt.objects.create(
            server=server,
            ssh_alias=server.ssh_alias,
            status=DiscoveryAttempt.Status.SUCCEEDED,
        )
        collected = replace(
            COLLECTED,
            security=Observation(ObservationOutcome.OBSERVED, ("a read",), "", STATE),
        )
        save_snapshot(attempt, collected, COLLECTED_AT)
        stored = current_snapshot(server)
        if stored is None:
            self.fail("The snapshot was stored.")
        self.assertEqual(stored.collected.security, collected.security)

    def test_an_unreadable_check_keeps_its_reason(self) -> None:
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        attempt = DiscoveryAttempt.objects.create(
            server=server,
            ssh_alias=server.ssh_alias,
            status=DiscoveryAttempt.Status.SUCCEEDED,
        )
        state = SecurityState(
            firewall=_blocked(),
            listeners=_blocked(),
            ssh=_blocked(),
            auto_updates=_blocked(),
            updates=_blocked(),
            restart=_blocked(),
        )
        collected = replace(
            COLLECTED,
            security=Observation(ObservationOutcome.OBSERVED, ("id -u",), "", state),
        )
        save_snapshot(attempt, collected, COLLECTED_AT)
        stored = current_snapshot(server)
        if stored is None:
            self.fail("The snapshot was stored.")
        self.assertEqual(stored.collected.security, collected.security)
