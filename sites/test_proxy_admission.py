"""Malformed native proxy evidence cannot select a PHP runtime."""

from types import SimpleNamespace
from typing import ClassVar
from unittest import TestCase, mock

from sites.bodies import admission
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

INFO = "Name: HAProxy\nNbthread: 1\nNbproc: 1\nPid: 4321\nMaxconn: 64"
STAT = (
    "# pxname,svname,slim,econ,eresp,cli_abrt,srv_abrt\n"
    "php,FRONTEND,64,0,0,0,0\n"
    "php,php84,2,0,0,0,0\n"
    "php,php85,2,0,0,0,0\n"
    "php,BACKEND,64,0,0,0,0"
)


class ProxyBatchTests(TestCase):
    def read(self, batch: str, *, changed: bool = False) -> admission.ProxyState:
        process = {"pid": 4321}
        observations = [process, {"pid": 4322}] if changed else [process, process]
        with (
            mock.patch.object(admission, "hap_process", side_effect=observations),
            mock.patch.object(admission, "haproxy_config", return_value="convention"),
            mock.patch(
                "sites.bodies.admission.pathlib.Path.read_text",
                side_effect=["convention", STATE],
            ),
            mock.patch.object(admission, "hap_safe"),
            mock.patch.object(admission, "hap_api", return_value=batch) as api,
        ):
            result = admission.haproxy_state(SimpleNamespace(identifier="alpha"))
        api.assert_called_once_with("alpha", "show info;show servers state;show stat")
        return result

    def test_batch_preserves_native_state_and_selection(self) -> None:
        result = self.read("\n\n".join((INFO, STATE.rstrip("\n"), STAT)))
        self.assertEqual(result["state"], STATE)
        self.assertEqual(result["selection"], "php84")
        self.assertEqual(result["persistent"], "php84")
        self.assertEqual(result["ready"], ["php84"])
        self.assertEqual(result["errors"]["php85"]["econ"], 0)

    def test_missing_extra_and_malformed_blocks_refuse_at_state_read(self) -> None:
        blocks = (INFO, STATE.rstrip("\n"), STAT)
        for invalid in (
            "\n\n".join(blocks[:2]),
            "\n\n".join((*blocks, "extra")),
            "\n\n".join((INFO, "", STAT)),
            "\n\n".join(("Wrong: HAProxy\n" + INFO, *blocks[1:])),
            "\n\n".join((INFO, "2\n" + blocks[1][2:], STAT)),
            "\n\n".join((INFO, blocks[1], "pxname," + STAT[len("# pxname,") :])),
            "\n\n".join((INFO, blocks[1].replace("php85", "foreign"), STAT)),
            "\n\n".join((INFO, blocks[1], STAT.replace("php85", "foreign"))),
        ):
            with self.subTest(invalid=invalid[:70]), self.assertRaises(ValueError):
                self.read(invalid)

    def test_generation_change_after_complete_batch_refuses_state(self) -> None:
        batch = "\n\n".join((INFO, STATE.rstrip("\n"), STAT))
        with self.assertRaisesRegex(ValueError, "Proxy identity changed during observation"):
            self.read(batch, changed=True)


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
