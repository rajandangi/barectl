"""docs/adr/0023: the fixed confirm-or-revert commands and their native evidence."""

from django.test import SimpleTestCase

from . import revert

UNIT = "barectl-apply-" + "a" * 32 + ".service"
FILES = ("/etc/ufw/user.rules", "/etc/ufw/user6.rules")


class RevertCommandTests(SimpleTestCase):
    def test_names_come_from_the_reviewed_run(self) -> None:
        window = revert.names(UNIT)
        self.assertEqual(window.identifier, "a" * 32)
        self.assertEqual(window.timer_unit, "barectl-revert-" + "a" * 32 + ".timer")
        self.assertEqual(window.service_unit, "barectl-revert-" + "a" * 32 + ".service")
        self.assertEqual(window.preimage, "/run/barectl/revert-" + "a" * 32)

    def test_the_timer_is_armed_for_five_minutes_before_the_change(self) -> None:
        armed = revert.arm_step()
        self.assertIn("--on-active=300", armed)
        self.assertIn("--property=Restart=on-failure", armed)
        self.assertIn(f"--property=StartLimitBurst={revert.RESTART_LIMIT + 1}", armed)
        self.assertIn('--setenv=BARECTL_REVERT_ID="$id"', armed)
        self.assertIn("/run/barectl/revert-$BARECTL_REVERT_ID/restore.sh", armed)

    def test_the_preimage_is_root_only_and_records_the_previous_enabled_state(self) -> None:
        saved = revert.save_steps(FILES, revert.reload_ufw_steps())
        self.assertIn("umask 077", saved)
        self.assertIn('mkdir -m 0700 -- "$revert"', saved)
        self.assertIn("/etc/ufw/user.rules", saved)
        self.assertIn("user6.rules.absent", saved)
        self.assertIn('"$revert/enabled"', saved)
        self.assertIn("BARECTL_REVERT_RESTORE", saved)

    def test_the_restore_waits_for_the_lock_and_uses_ufw_only(self) -> None:
        script = revert.restore_script(FILES, revert.reload_ufw_steps())
        self.assertIn("flock -w 120 9", script)
        self.assertIn("ufw reload", script)
        self.assertIn("ufw --force disable", script)
        self.assertIn(revert.RESTORED_MARKER, script)
        self.assertIn('rm -rf -- "$revert"', script)

    def test_confirmation_removes_the_preimage_only_after_the_service_is_clean(self) -> None:
        script = revert.confirmation(UNIT)[2]
        self.assertIn("# barectl-revert-confirm", script)
        self.assertIn("flock -n 9", script)
        self.assertIn('systemctl stop -- "$timer"', script)
        self.assertIn('"$populated" -eq 1', script)
        self.assertIn('rm -rf -- "$revert"', script)
        self.assertLess(script.index("systemctl stop"), script.index('rm -rf -- "$revert"'))

    def test_every_kind_refuses_while_a_window_or_preimage_remains(self) -> None:
        step = revert.refusal_step('refuse "revert_active"')
        self.assertIn("barectl-revert-*.timer", step)
        self.assertIn("barectl-revert-*.service", step)
        self.assertIn("/run/barectl/revert-*", step)
        self.assertIn("active|activating|deactivating|failed", step)

    def test_window_evidence_is_one_of_three_words(self) -> None:
        self.assertIs(revert.parse_window("kept\n"), revert.Window.KEPT)
        self.assertIs(revert.parse_window("put_back"), revert.Window.PUT_BACK)
        self.assertIs(revert.parse_window("not_known"), revert.Window.NOT_KNOWN)
        self.assertIsNone(revert.parse_window("maybe"))
