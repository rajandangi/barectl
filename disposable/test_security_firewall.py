"""The standard firewall and confirm-or-revert on a real target (Phase E #306).

docs/security.md#firewall, docs/adr/0023. The lifecycle turns the standard on, adds and
removes one operator port, and a fresh controller reconstructs the standard. The failure
cases start the revert service directly because one native item is limited to 180 s; the
fast layer proves the timer is armed with 300 s.
"""

import time
from typing import override

from django.test import tag

from discovery.observations import collect
from operations import revert
from operations.inputs import PreparationInputs
from security.firewall import MANAGE_FIREWALL, standard_holds

from .change_testing import (
    Submitted,
    confirm_window,
    submit_change,
    wait_result,
    wait_window,
)
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


def _on() -> PreparationInputs:
    return PreparationInputs("on", firewall=True)


def _add(port: str, protocol: str = "tcp", network: str = "") -> PreparationInputs:
    return PreparationInputs("add", firewall=True, port=port, protocol=protocol, network=network)


def _remove(port: str, protocol: str = "tcp", network: str = "") -> PreparationInputs:
    return PreparationInputs("remove", firewall=True, port=port, protocol=protocol, network=network)


@tag(SCENARIO_TAG)
class FirewallLifecycle(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "sfirewall"

    @override
    def setUp(self) -> None:
        super().setUp()
        self._reset()

    @override
    def tearDown(self) -> None:
        self._reset()
        super().tearDown()

    def _reset(self) -> None:
        self.native(
            "ufw --force disable >/dev/null 2>&1 || true; "
            "ufw --force reset >/dev/null 2>&1 || true; "
            "for u in $(systemctl list-units --all --plain --no-legend 'barectl-revert-*' "
            "| cut -d' ' -f1); do systemctl stop \"$u\" >/dev/null 2>&1 || true; "
            'systemctl reset-failed "$u" >/dev/null 2>&1 || true; done; '
            "rm -rf /run/barectl/revert-*"
        )

    def _status(self) -> str:
        return self.native("ufw status verbose")

    def _rules(self) -> str:
        return self.native("ufw show added")

    def _start_revert(self, unit: str) -> None:
        identifier = revert.names(unit).identifier
        self.native(f"systemctl start barectl-revert-{identifier}.service")

    def _run(
        self, inputs: PreparationInputs, *, expected: str = "succeeded", reason: str = ""
    ) -> Submitted:
        submitted = submit_change(self, MANAGE_FIREWALL, inputs)
        wait_result(self, submitted, timeout=90, expected=expected, reason=reason)
        return submitted

    def test_1_turns_on_adds_and_removes_and_a_fresh_controller_reconstructs(self) -> None:
        opened = self._run(_on())
        self.assertIs(confirm_window(self, opened), revert.Window.KEPT)
        status = self._status()
        self.assertIn("Status: active", status)
        self.assertIn("Default: deny (incoming), allow (outgoing), deny (routed)", status)
        self.assertIn("Logging: on (low)", status)
        self.assertIn("IPV6=yes", self.native("cat /etc/default/ufw"))
        rules = self._rules()
        ssh_port = self.native("sshd -T | sed -n 's/^port //p' | head -n 1").strip()
        for expected in (
            f"ufw allow {ssh_port}/tcp",
            "ufw allow 80/tcp",
            "ufw allow 443/tcp",
            "ufw allow 443/udp",
        ):
            self.assertIn(expected, rules)
        ipv6 = self.native("cat /etc/ufw/user6.rules")
        for rule in (f"--dport {ssh_port} -j ACCEPT", "--dport 80 -j ACCEPT"):
            self.assertIn(rule, ipv6)
        self.assertIn("-p udp --dport 443 -j ACCEPT", ipv6)

        for inputs, line in (
            (_add("8080:8085"), "ufw allow 8080:8085/tcp"),
            (_add("5353", "udp"), "ufw allow 5353/udp"),
            (
                _add("5432", "tcp", "203.0.113.0/24"),
                "ufw allow from 203.0.113.0/24 to any port 5432 proto tcp",
            ),
        ):
            with self.subTest(rule=line):
                added = self._run(inputs)
                self.assertIs(confirm_window(self, added), revert.Window.KEPT)
                self.assertIn(line, self._rules())
        for inputs, line in (
            (_remove("8080:8085"), "ufw allow 8080:8085/tcp"),
            (_remove("5353", "udp"), "ufw allow 5353/udp"),
            (
                _remove("5432", "tcp", "203.0.113.0/24"),
                "ufw allow from 203.0.113.0/24 to any port 5432 proto tcp",
            ),
        ):
            with self.subTest(removed=line):
                removed = self._run(inputs)
                self.assertIs(confirm_window(self, removed), revert.Window.KEPT)
                self.assertNotIn(line, self._rules())

        with self.shell() as shell:
            after = collect(shell)
        if not after.security.observed or after.security.value is None:
            self.fail("A fresh controller did not read the security checks.")
        firewall = after.security.value.firewall.value
        ssh = after.security.value.ssh.value
        if firewall is None or ssh is None:
            self.fail("A fresh controller did not read the firewall and SSH settings.")
        self.assertTrue(standard_holds(firewall, ssh.sshd_ports), firewall)

    def test_2_a_worker_that_never_confirms_lets_the_server_put_it_back(self) -> None:
        opened = self._run(_on())
        self.assertIn("Status: active", self._status())
        self._start_revert(opened.unit)
        self.assertIs(wait_window(self, opened), revert.Window.PUT_BACK)
        self.assertIn("Status: inactive", self._status())
        self.assertEqual(self.native("sh -c 'ls -d /run/barectl/revert-* 2>/dev/null || true'"), "")
        # The server is still reachable through ordinary SSH after the put-back.
        self.assertIn("ufw 0.36.2", self.native("ufw --version"))

    def test_3_confirmation_racing_a_started_revert_leaves_the_server_reverted(self) -> None:
        opened = self._run(_on())
        self._start_revert(opened.unit)
        # The revert service is waiting for the confirmation's lock or already restoring.
        window = confirm_window(self, opened)
        self.assertIn(window, {revert.Window.PUT_BACK, revert.Window.NOT_KNOWN})
        self.assertIs(wait_window(self, opened), revert.Window.PUT_BACK)
        self.assertIn("Status: inactive", self._status())

    def test_4_the_revert_waits_for_a_held_lock(self) -> None:
        opened = self._run(_on())
        self.native(
            "nohup sh -c 'exec 9>>/run/lock/barectl/mutation.lock; "
            "flock -n 9 || exit 1; sleep 4' >/tmp/barectl-hold.log 2>&1 &"
        )
        time.sleep(0.5)
        self._start_revert(opened.unit)
        time.sleep(1)
        # The revert is waiting, so the new firewall and its preimage are still in place.
        self.assertIn("Status: active", self._status())
        self.assertNotEqual(
            self.native("sh -c 'ls -d /run/barectl/revert-* 2>/dev/null || true'"), ""
        )
        self.assertIs(wait_window(self, opened, timeout=30), revert.Window.PUT_BACK)
        self.assertIn("Status: inactive", self._status())

    def test_5_a_second_controller_refuses_while_the_window_is_open(self) -> None:
        opened = self._run(_on())
        second = submit_change(self, MANAGE_FIREWALL, _add("9090"))
        wait_result(self, second, timeout=30, expected="refused", reason="revert_active")
        self.assertNotIn("ufw allow 9090/tcp", self._rules())
        self.assertIs(confirm_window(self, opened), revert.Window.KEPT)
        ssh_port = self.native("sshd -T | sed -n 's/^port //p' | head -n 1").strip()
        self.assertIn(f"ufw allow {ssh_port}/tcp", self._rules())

    def test_6_a_rule_that_blocks_the_new_connection_is_put_back(self) -> None:
        opened = self._run(_on())
        ssh_port = self.native("sshd -T | sed -n 's/^port //p' | head -n 1").strip()
        self.native(f"ufw deny {ssh_port}/tcp")
        from discovery.ssh import ConnectionFailed

        with self.assertRaises(ConnectionFailed), self.shell():
            pass
        # The worker cannot confirm over a new connection and this test starts the revert
        # service directly, as the spec allows inside the 180 s item limit.
        self._start_revert(opened.unit)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                with self.shell():
                    break
            except ConnectionFailed:
                time.sleep(0.2)
        else:
            self.fail("The server did not become reachable again after the put-back.")
        self.assertIn("Status: inactive", self._status())
        self.assertNotIn(f"deny {ssh_port}/tcp", self._rules())
