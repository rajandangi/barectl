from datetime import UTC, datetime

from django.test import SimpleTestCase

from discovery.observations import collect
from discovery.recorded import ReplayShell, load
from discovery.snapshot import CollectedSnapshot
from security.presentation import UNKNOWN, present

STATE = "security-checks-26.04"


class RecordedSecurityTests(SimpleTestCase):
    """The checks over the real output of a target-stack Ubuntu 26.04 server."""

    def collect(self) -> CollectedSnapshot:
        return collect(ReplayShell(load(STATE)))

    def test_every_check_is_read_from_ordinary_discovery(self) -> None:
        collected = self.collect()
        if not collected.security.observed or collected.security.value is None:
            self.fail("Discovery did not read the security checks.")
        checks = collected.security.value
        for name, check in (
            ("firewall", checks.firewall),
            ("listeners", checks.listeners),
            ("ssh", checks.ssh),
            ("automatic updates", checks.auto_updates),
            ("updates", checks.updates),
            ("restart", checks.restart),
        ):
            with self.subTest(check=name):
                self.assertTrue(check.observed, check.warning)
        firewall = checks.firewall.value
        if firewall is None:
            self.fail("The firewall check was not read.")
        self.assertTrue(firewall.ufw_installed)
        self.assertIsNotNone(firewall.ufw_enabled)
        listeners = checks.listeners.value or ()
        self.assertTrue(any(row.port == 22 and row.public for row in listeners), listeners)
        if checks.ssh.value is None:
            self.fail("The SSH check was not read.")
        self.assertIn(checks.ssh.value.password_authentication, {"yes", "no"})
        if checks.auto_updates.value is None:
            self.fail("The automatic updates check was not read.")
        self.assertTrue(checks.auto_updates.value.enabled)
        self.assertTrue(checks.auto_updates.value.list_update_timer)

    def test_the_section_projects_the_stored_checks_without_an_unknown(self) -> None:
        collected = self.collect()
        checks = present(collected, datetime(2026, 10, 31, 12, 0, tzinfo=UTC))
        self.assertEqual(len(checks), 7)
        self.assertNotIn(UNKNOWN, [check.state for check in checks])
