"""Malformed native proxy evidence cannot select a PHP runtime."""

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
        ):
            with self.subTest(invalid=invalid[:100]), self.assertRaises(ValueError):
                state_selection(invalid)
