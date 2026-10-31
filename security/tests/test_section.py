from dataclasses import replace
from datetime import timedelta
from typing import override

from django.utils import timezone

from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome
from discovery.snapshot import Observation, save_snapshot
from security.observation import FirewallState, SecurityState
from security.testing import blocked, check, ok_state
from servers.models import Server
from servers.testing import ControllerConfigTestCase


class SecuritySectionTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def store(self, state: SecurityState | None) -> None:
        attempt = DiscoveryAttempt.objects.create(
            server=self.server,
            ssh_alias=self.server.ssh_alias,
            status=DiscoveryAttempt.Status.SUCCEEDED,
        )
        collected = replace(
            COLLECTED,
            security=Observation(ObservationOutcome.OBSERVED, ("a read",), "", state),
        )
        save_snapshot(attempt, collected, timezone.now() - timedelta(minutes=5))

    def test_empty_state_asks_for_a_connection_check(self) -> None:
        response = self.client.get(f"/servers/{self.server.pk}/security/")
        self.assertContains(response, "No security checks have been read yet")
        self.assertContains(response, "Run a connection check")

    def test_outside_supported_settings_is_reported_without_blocking_other_checks(self) -> None:
        state = replace(
            ok_state(),
            firewall=check(
                FirewallState(
                    True,
                    True,
                    "deny",
                    "allow",
                    "deny",
                    True,
                    "on (low)",
                    (),
                    ("Docker is active and publishes ports ahead of a host firewall.",),
                    True,
                )
            ),
        )
        self.store(state)
        response = self.client.get(f"/servers/{self.server.pk}/security/")
        self.assertContains(response, "Outside supported settings")
        self.assertContains(response, "Not available yet")
        self.assertContains(response, "Only key sign-in is allowed")

    def test_could_not_check_keeps_the_reason(self) -> None:
        self.store(replace(ok_state(), firewall=blocked()))
        response = self.client.get(f"/servers/{self.server.pk}/security/")
        self.assertContains(response, "Could not check")
        self.assertContains(response, "needs root or the authorized passwordless sudo")

    def test_advanced_shows_the_reads_behind_the_checks(self) -> None:
        self.store(ok_state())
        response = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertContains(response, "Security reads")
        self.assertContains(response, "a fixed read")

    def test_a_failed_later_check_marks_the_checks_stale(self) -> None:
        self.store(ok_state())
        record_attempt(
            self.server, DiscoveryAttempt.Status.FAILED, failure="The connection failed."
        )
        response = self.client.get(f"/servers/{self.server.pk}/security/")
        self.assertContains(response, "The latest connection check failed")
        self.assertContains(response, "Only key sign-in is allowed")
