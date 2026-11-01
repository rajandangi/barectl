from dataclasses import replace
from datetime import timedelta
from typing import override

from django.utils import timezone

from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome
from discovery.snapshot import Observation, save_snapshot
from operations.models import ChangePreparation
from security.observation import (
    DEFAULT_ALLOWED_ORIGINS,
    AutoUpdatesState,
    FirewallState,
    PendingUpdate,
    SecurityState,
    UpdatesState,
)
from security.presentation import UPDATES_ALL_LABEL, UPDATES_CHECK_LABEL, UPDATES_SECURITY_LABEL
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

    def _store_disabled_updates(self) -> None:
        self.store(
            replace(
                ok_state(),
                auto_updates=check(
                    AutoUpdatesState(
                        False,
                        "enabled",
                        "enabled",
                        False,
                        DEFAULT_ALLOWED_ORIGINS,
                        True,
                        "",
                        None,
                        True,
                    )
                ),
            )
        )

    def test_viewers_and_site_operators_see_no_control_and_a_forged_post_is_refused(
        self,
    ) -> None:
        self._store_disabled_updates()
        response = self.client.get(f"/servers/{self.server.pk}/security/")
        self.assertNotContains(response, 'name="state"')
        self.assertNotContains(response, ">Turn on<")
        forged = self.client.post(
            f"/servers/{self.server.pk}/security/automatic-updates/prepare/",
            {"state": "on"},
        )
        self.assertEqual(forged.status_code, 403)
        self.grant("view_changes", "change_site")
        site_operator = self.client.get(f"/servers/{self.server.pk}/security/")
        self.assertNotContains(site_operator, 'name="state"')
        refused = self.client.post(
            f"/servers/{self.server.pk}/security/automatic-updates/prepare/",
            {"state": "on"},
        )
        self.assertEqual(refused.status_code, 403)

    def _store_waiting_updates(self) -> None:
        self.store(
            replace(
                ok_state(),
                updates=check(
                    UpdatesState(
                        7200,
                        (
                            PendingUpdate(
                                "openssl",
                                "3.0.0",
                                "3.0.1",
                                "resolute-security/main",
                                "security",
                            ),
                            PendingUpdate("curl", "8.0", "8.1", "resolute-updates/main", "other"),
                        ),
                    )
                ),
            )
        )

    def test_viewers_and_site_operators_get_no_update_control_and_forged_posts_refuse(
        self,
    ) -> None:
        self._store_waiting_updates()
        response = self.client.get(f"/servers/{self.server.pk}/security/")
        self.assertNotContains(response, UPDATES_CHECK_LABEL)
        self.assertNotContains(response, UPDATES_SECURITY_LABEL)
        for url in ("check", "install"):
            forged = self.client.post(f"/servers/{self.server.pk}/security/updates/{url}/prepare/")
            self.assertEqual(forged.status_code, 403)
        self.grant("view_changes", "change_site")
        site_operator = self.client.get(f"/servers/{self.server.pk}/security/")
        self.assertNotContains(site_operator, UPDATES_CHECK_LABEL)
        refused = self.client.post(
            f"/servers/{self.server.pk}/security/updates/install/prepare/",
            {"selection": "security"},
        )
        self.assertEqual(refused.status_code, 403)

    def test_a_shared_operator_checks_for_and_installs_updates(self) -> None:
        self.grant("view_changes", "change_site", "change_shared")
        self._store_waiting_updates()
        response = self.client.get(f"/servers/{self.server.pk}/security/")
        self.assertContains(response, UPDATES_CHECK_LABEL)
        self.assertContains(response, UPDATES_SECURITY_LABEL)
        self.assertContains(response, UPDATES_ALL_LABEL)
        checked = self.client.post(f"/servers/{self.server.pk}/security/updates/check/prepare/")
        self.assertEqual(checked.status_code, 302)
        preparation = ChangePreparation.objects.get(server=self.server)
        self.assertEqual(preparation.kind_slug, "check_for_ubuntu_updates")
        self.assertEqual(preparation.inputs, {"version": 1})
        ChangePreparation.objects.all().delete()
        installed = self.client.post(
            f"/servers/{self.server.pk}/security/updates/install/prepare/",
            {"selection": "security"},
        )
        self.assertEqual(installed.status_code, 302)
        preparation = ChangePreparation.objects.get(server=self.server)
        self.assertEqual(preparation.kind_slug, "install_ubuntu_updates")
        self.assertEqual(preparation.inputs, {"version": 1, "selection": "security"})

    def test_a_shared_operator_prepares_the_reviewed_change(self) -> None:
        self.grant("view_changes", "change_site", "change_shared")
        self._store_disabled_updates()
        response = self.client.get(f"/servers/{self.server.pk}/security/")
        self.assertContains(response, 'name="state" value="on"')
        self.assertContains(response, "Turn on")
        queued = self.client.post(
            f"/servers/{self.server.pk}/security/automatic-updates/prepare/",
            {"state": "on"},
        )
        self.assertEqual(queued.status_code, 302)
        preparation = ChangePreparation.objects.get(server=self.server)
        self.assertEqual(preparation.kind_slug, "set_automatic_security_updates")
        self.assertEqual(preparation.inputs, {"version": 1, "selection": "on"})
