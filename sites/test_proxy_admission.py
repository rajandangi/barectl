"""Malformed native proxy evidence cannot select a PHP runtime."""

from typing import ClassVar
from unittest import TestCase

from sites.bodies.admission import state_selection

HEADER = (
    "# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state "
    "srv_uweight srv_iweight srv_time_since_last_change srv_check_status "
    "srv_check_result srv_check_health srv_check_state srv_agent_state bk_f_forced_id "
    "srv_f_forced_id srv_fqdn srv_port srvrecord srv_use_ssl srv_check_port "
    "srv_check_addr srv_agent_addr srv_agent_port "
).strip()
STATE = (
    "1\n" + HEADER + "\n"
    "2 php 1 php84 - 2 4 1 1 0 1 0 0 8 0 0 1 - 0 - 0 0 - - 0\n"
    "2 php 2 php85 - 0 5 1 1 0 1 0 0 8 0 0 1 - 0 - 0 0 - - 0\n"
)


class ProxyNativeStateTests(TestCase):
    def test_only_complete_known_native_state_selects_one_runtime(self) -> None:
        self.assertEqual(state_selection(STATE), "php84")
        for invalid in (
            "",
            "1\n" + HEADER + "\n",
            STATE.replace("php85", "foreign"),
            STATE.replace("2 php 2", "2 php 1"),
            STATE.replace(" - 0 5 ", " - 2 4 "),
            STATE.replace(" - 2 4 ", " - 0 5 "),
            STATE.replace("srv_port", "missing_field"),
            STATE.replace(" - 2 4 ", " /foreign.sock 2 4 "),
            STATE.replace("1 0 0 8", "1 0 high 8"),
        ):
            with self.subTest(invalid=invalid[:100]), self.assertRaises(ValueError):
                state_selection(invalid)

    def test_a_restarted_proxy_reports_its_health_counter(self) -> None:
        # A restart loads the state file; HAProxy then reports a non-zero check health.
        restarted = STATE.replace(
            "2 php 1 php84 - 2 4 1 1 0 1 0 0 8",
            "2 php 1 php84 - 2 4 1 1 3 1 0 4 8",
        )
        self.assertEqual(state_selection(restarted), "php84")


class ExecutedCommandTests(TestCase):
    """A daemon reload clears ExecStart's runtime fields; the process still binds the unit."""

    identifier: ClassVar[str] = "alpha"
    argv: ClassVar[list[str]] = [
        "/nix/var/nix/profiles/barectl/haproxy/bin/haproxy",
        "-f",
        "/etc/haproxy/sites/alpha.cfg",
    ]

    def bus(self, entry: list[object]) -> str:
        import json

        values = [
            ("t", 1_792_000_000_000_000),
            ("t", 88_000_000_000),
            ("a(sasbttttuii)", [entry]),
            ("a(sasbttttuii)", []),
            ("as", []),
            ("a(sb)", []),
            ("as", []),
            ("as", []),
        ]
        return "\n".join(json.dumps({"type": kind, "data": data}) for kind, data in values)

    def test_a_running_invocation_binds_its_process(self) -> None:
        from unittest import mock

        from sites.bodies import admission

        start, monotonic = 1_792_000_000_000_000, 88_000_000_000
        now, now_monotonic = start + 5_000_000, monotonic + 5_000_000
        with (
            mock.patch.object(
                admission,
                "hap_run",
                return_value=self.bus(
                    [*self.argv[:1], self.argv, False, start, monotonic, 0, 0, 4321, 0, 0]
                ),
            ),
            mock.patch("sites.bodies.admission.time.time_ns", return_value=now * 1000),
            mock.patch(
                "sites.bodies.admission.time.monotonic_ns",
                return_value=now_monotonic * 1000,
            ),
        ):
            _context, found = admission.hap_execution(self.identifier, self.argv, 4321, monotonic)
        self.assertEqual(found, start)

    def test_a_reloaded_unit_derives_its_start_from_the_preserved_monotonic_clock(self) -> None:
        from unittest import mock

        from sites.bodies import admission

        with mock.patch.object(
            admission,
            "hap_run",
            return_value=self.bus([*self.argv[:1], self.argv, False, 0, 0, 0, 0, 0, 0, 0]),
        ):
            _context, found = admission.hap_execution(
                self.identifier, self.argv, 4321, 88_000_000_000
            )
        self.assertGreater(found, 1_700_000_000_000_000)

    def test_another_command_or_account_is_refused(self) -> None:
        from unittest import mock

        from sites.bodies import admission

        for entry in (
            ["/bin/true", ["/bin/true"], False, 0, 0, 0, 0, 0, 0, 0],
            [*self.argv[:1], [*self.argv, "--foreign"], False, 0, 0, 0, 0, 0, 0, 0],
            [*self.argv[:1], self.argv, True, 0, 0, 0, 0, 0, 0, 0],
        ):
            with (
                self.subTest(entry=entry),
                mock.patch.object(admission, "hap_run", return_value=self.bus(entry)),
                self.assertRaises(ValueError),
            ):
                admission.hap_execution(self.identifier, self.argv, 4321, 88_000_000_000)
