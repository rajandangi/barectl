"""Security checks: read, adopt supported changes and report the rest once (Phase E #302).

docs/quality.md#native-layer, docs/security.md. The scenario makes ordinary ``ufw`` changes
on the disposable target server and proves a fresh controller, with no local database,
reconstructs the same checks: an operator-added rule in the supported shape is reported as
an adopted operator rule, and a rule outside it as outside supported settings.
"""

from django.test import tag

from discovery.observations import collect

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

STATE = "security-checks-26.04"
ADDED_PORT = "8080"
SOURCE_NETWORK = "203.0.113.0/24"
SOURCE_PORT = "5432"
REFUSED_PORT = "3306"
LISTENER_PORT = "9000"
APT_OVERRIDE = "/etc/apt/apt.conf.d/99-security-check-test"
SSH_DROPIN = "/etc/ssh/sshd_config.d/00-security-check-test.conf"


@tag(SCENARIO_TAG)
class SecurityChecks(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "ssecurity"
    records: tuple[str, ...] = (STATE,)

    def test_1_a_fresh_controller_reconstructs_the_checks_after_external_changes(self) -> None:
        with self.shell() as shell:
            before = collect(shell)
            if not before.security.observed or before.security.value is None:
                self.fail("Discovery did not read the security checks.")
            checks = before.security.value
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
            self.checkpoint(STATE, shell)

        self.native(f"ufw allow {ADDED_PORT}/tcp")
        self.native(f"ufw allow proto tcp from {SOURCE_NETWORK} to any port {SOURCE_PORT}")
        self.native(f"ufw deny {REFUSED_PORT}/tcp")
        self.native("printf 'yes\n' > /run/reboot-required")
        self.native("printf 'linux-image-generic\n' > /run/reboot-required.pkgs")
        self.native("printf 'APT::Periodic::Unattended-Upgrade \"0\";\n' > " + APT_OVERRIDE)
        self.native("printf 'PasswordAuthentication yes\n' > " + SSH_DROPIN)
        self.native(
            f"nohup python3 -m http.server {LISTENER_PORT} --bind 0.0.0.0 "
            ">/tmp/security-check-http.log 2>&1 & echo $! > /tmp/security-check-http.pid"
        )
        self.native(
            f"for _ in 1 2 3 4 5 6 7 8 9 10; do "
            f"ss -Hltn 'sport = :{LISTENER_PORT}' | grep -q . && break; sleep 0.1; done"
        )
        try:
            # A new connection and an empty controller database: nothing is imported.
            with self.shell() as shell:
                after = collect(shell)
            if not after.security.observed or after.security.value is None:
                self.fail("A fresh controller did not reconstruct the security checks.")
            firewall = after.security.value.firewall
            if not firewall.observed or firewall.value is None:
                self.fail(firewall.warning or "The firewall checks were not read.")
            operator = {rule.ports for rule in firewall.value.rules if rule.kind == "operator"}
            self.assertIn(ADDED_PORT, operator)
            self.assertIn(SOURCE_PORT, operator)
            self.assertIn(
                f"deny {REFUSED_PORT}/tcp",
                [rule.line for rule in firewall.value.rules if rule.kind == "outside"],
            )
            listeners = after.security.value.listeners.value or ()
            exposed = next((row for row in listeners if row.port == int(LISTENER_PORT)), None)
            if exposed is None:
                self.fail(f"A fresh controller did not read port {LISTENER_PORT}.")
            self.assertTrue(exposed.public)
            restart = after.security.value.restart.value
            if restart is None:
                self.fail("A fresh controller did not read the restart requirement.")
            self.assertTrue(restart.required)
            self.assertIn("linux-image-generic", restart.packages)
            auto = after.security.value.auto_updates.value
            if auto is None:
                self.fail("A fresh controller did not read the automatic update setting.")
            self.assertFalse(auto.enabled)
            ssh = after.security.value.ssh.value
            if ssh is None:
                self.fail("A fresh controller did not read the SSH setting.")
            before_ssh = before.security.value.ssh.value
            if before_ssh is None:
                self.fail("The first controller did not read the SSH setting.")
            self.assertEqual(ssh.password_authentication, "yes")
            self.assertEqual(set(ssh.ports), set(before_ssh.ports))
        finally:
            self.native(f"ufw delete allow {ADDED_PORT}/tcp")
            self.native(
                f"ufw delete allow proto tcp from {SOURCE_NETWORK} to any port {SOURCE_PORT}"
            )
            self.native(f"ufw delete deny {REFUSED_PORT}/tcp")
            self.native(
                "rm -f /run/reboot-required /run/reboot-required.pkgs "
                + APT_OVERRIDE
                + " "
                + SSH_DROPIN
            )
            self.native(
                'kill "$(cat /tmp/security-check-http.pid)" 2>/dev/null || true; '
                "rm -f /tmp/security-check-http.pid"
            )
