"""Key-only SSH sign-in and its native put-back window on Ubuntu 26.04 (#308)."""

import time
from typing import override
from unittest import mock

from django.test import tag

from discovery import ssh
from discovery.observations import collect
from discovery.ssh import ConnectionFailed
from operations import revert
from operations.inputs import PreparationInputs
from security.sign_in import PATH, REQUIRE_KEY_SIGN_IN

from .change_testing import Submitted, confirm_window, submit_change, wait_result, wait_window
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

OVERRIDE = "/etc/ssh/sshd_config.d/00-a-override.conf"
MATCH_OVERRIDE = "/etc/ssh/sshd_config.d/99-match-test.conf"


@tag(SCENARIO_TAG)
class SignInLifecycle(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "ssignin"

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
            "for u in $(systemctl list-units --all --plain --no-legend 'barectl-revert-*' "
            "| cut -d' ' -f1); do systemctl stop \"$u\" >/dev/null 2>&1 || true; "
            'systemctl reset-failed "$u" >/dev/null 2>&1 || true; done; '
            f"rm -rf /run/barectl/revert-*; rm -f {PATH} {OVERRIDE} {MATCH_OVERRIDE}; "
            "sshd -t && systemctl reload ssh.service"
        )

    def _run(self, *, expected: str = "succeeded", reason: str = "") -> Submitted:
        submitted = submit_change(self, REQUIRE_KEY_SIGN_IN, PreparationInputs("on"))
        wait_result(self, submitted, timeout=90, expected=expected, reason=reason)
        return submitted

    def _start_revert(self, submitted: Submitted) -> None:
        identifier = revert.names(submitted.unit).identifier
        self.native(f"systemctl start barectl-revert-{identifier}.service")

    def test_1_confirmed_change_and_fresh_controller_recognition(self) -> None:
        with self.shell() as shell:
            before = collect(shell)
        before_ssh = before.security.value.ssh.value if before.security.value is not None else None
        if before_ssh is None:
            self.fail("The initial SSH sign-in settings were not read.")
        opened = self._run()
        self.assertIs(confirm_window(self, opened), revert.Window.KEPT)
        self.assertEqual(
            self.native(f"cat {PATH}"),
            "PasswordAuthentication no\n"
            "KbdInteractiveAuthentication no\n"
            "PermitRootLogin prohibit-password\n",
        )
        self.assertIn("0 0 644", self.native(f"stat -c '%u %g %a' {PATH}"))
        self.assertIn("passwordauthentication no", self.native("sshd -T"))
        with self.shell() as shell:
            discovered = collect(shell)
        if not discovered.security.observed or discovered.security.value is None:
            self.fail("A fresh controller did not read Security.")
        check = discovered.security.value.ssh
        self.assertTrue(check.observed, check.warning)
        if check.value is None:
            self.fail("A fresh controller did not read SSH sign-in.")
        self.assertTrue(check.value.contexts_checked)
        self.assertEqual(check.value.match_overrides, ())
        self.assertEqual(check.value.per_source_penalties, before_ssh.per_source_penalties)

    def test_2_worker_loss_puts_back_the_previous_drop_in(self) -> None:
        self.native(
            f"printf 'PasswordAuthentication yes\\n' > {PATH}; "
            f"chmod 0640 {PATH}; chown root:root {PATH}"
        )
        opened = self._run()
        self._start_revert(opened)
        self.assertIs(wait_window(self, opened), revert.Window.PUT_BACK)
        self.assertEqual(self.native(f"cat {PATH}"), "PasswordAuthentication yes\n")
        self.assertEqual(self.native(f"stat -c '%u %g %a' {PATH}"), "0 0 640\n")
        with self.shell() as shell:
            self.assertEqual(shell.run("id -u").exit_status, 0)

    def test_3_drop_in_that_blocks_new_key_sign_in_is_put_back(self) -> None:
        opened = self._run()
        self.native(
            f"printf 'Match User root\\nPubkeyAuthentication no\\n' >> {PATH}; "
            "sshd -t && systemctl reload ssh.service"
        )
        with mock.patch.object(ssh, "CONNECT_TIMEOUT", 2):
            with self.assertRaises(ConnectionFailed), self.shell():
                pass
            self._start_revert(opened)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                try:
                    with self.shell():
                        break
                except ConnectionFailed:
                    time.sleep(0.2)
            else:
                self.fail("The prior SSH sign-in did not return after put-back.")
        self.assertIs(wait_window(self, opened), revert.Window.PUT_BACK)

    def test_4_an_earlier_setting_that_wins_is_reported_and_put_back(self) -> None:
        self.native(f"printf 'PasswordAuthentication yes\\n' > {OVERRIDE}")
        opened = self._run(expected="refused", reason="sign_in_verify")
        self.assertIs(wait_window(self, opened), revert.Window.PUT_BACK)
        self.assertEqual(self.native(f"test -e {PATH} && echo present || true"), "")

    def test_5_source_specific_match_is_unknown_and_refuses(self) -> None:
        self.native(
            f"printf 'Match Address 203.0.113.0/24\\nPasswordAuthentication yes\\n' > "
            f"{MATCH_OVERRIDE}; sshd -t"
        )
        with self.shell() as shell:
            observed = collect(shell)
            check = observed.security.value.ssh if observed.security.value is not None else None
            if check is None:
                self.fail("Security was not read.")
            self.assertTrue(check.observed)
            self.assertIn("every connection", check.warning)
            self.assertIn(22, check.value.sshd_ports if check.value is not None else ())
            inputs = PreparationInputs("on")
            draft = REQUIRE_KEY_SIGN_IN.review(REQUIRE_KEY_SIGN_IN.inspect(shell, inputs), inputs)
            self.assertFalse(draft.eligible)
            self.assertIn("every connection", str(draft.refusals))

    def test_6_user_match_that_reenables_passwords_is_reported_and_put_back(self) -> None:
        self.native(
            f"printf 'Match User root\\nPasswordAuthentication yes\\n' > {MATCH_OVERRIDE}; sshd -t"
        )
        opened = self._run(expected="refused", reason="sign_in_verify")
        self.assertIs(wait_window(self, opened), revert.Window.PUT_BACK)
