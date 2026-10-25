"""WordPress server cron on a real Ubuntu 26.04 host (Phase C #357, native scenario C1 part 2).

docs/quality.md#native-layer. The fast layer proves the review, the projection and the
body's order; only a real systemd can prove that a calendar tick runs the site's due
events, that a page load stops running them once the task owns cron, that ticks continue
with no controller involved, and that turning off gives page-load cron back first.
"""

import os
import shlex
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import override

from django.test import tag

from automation import change
from automation.convention import service_name, timer_name
from discovery import recorded, ssh
from operations.inputs import PreparationInputs
from wordpress import create

from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG
from .test_wordpress_create import CANARY, DOMAIN, IDENTIFIER, WordPressCreateCase

STATE = "automation-wordpress-26.04"
DUE_EVENT = "barectl_probe"
ON_EVENT = "barectl_probe_on"
OFF_EVENT = "barectl_probe_off"
PRIVATE = f"/var/www/{IDENTIFIER}/private/wp-config.php"


@tag(SCENARIO_TAG)
class WordPressServerCron(WordPressCreateCase):
    records: tuple[str, ...] = (STATE,)

    @override
    @contextmanager
    def shell(self) -> Iterator[ssh.RemoteShell]:
        """A plain connection: only the checkpoint shell records a transcript.

        Setup applies reviewed changes that use the confidential channel, which a recording
        shell refuses by design (ADR 0032).
        """
        os.environ["SSH_AUTH_SOCK"] = ""
        with ssh.connect(self.target()) as connection:
            yield connection

    def wp(self, *arguments: str) -> str:
        command = " ".join(shlex.quote(argument) for argument in arguments)
        return self.native(
            f"runuser -u s{IDENTIFIER} -- /var/www/{IDENTIFIER}/bin/wp "
            f"--path=/var/www/{IDENTIFIER}/current/public {command}"
        ).strip()

    def due_events(self, hook: str = DUE_EVENT) -> int:
        return int(self.wp("eval", f"echo (int) (bool) wp_next_scheduled('{hook}');"))

    def schedule_due_event(self, hook: str = DUE_EVENT, *, delay: int = 0) -> None:
        scheduled = self.wp(
            "eval",
            f"var_export(wp_schedule_single_event(time() + {delay}, '{hook}')); "
            f"echo '|', (int) (bool) wp_next_scheduled('{hook}');",
        )
        self.assertEqual(self.due_events(hook), 1, scheduled)

    def wait_manageable(self, *, timeout: float = 60) -> None:
        """Wait for the host to report the target stack before reading or applying."""
        from bootstrap.standing import Standing
        from discovery.observations import collect

        end = time.monotonic() + timeout
        while True:
            with self.shell() as shell:
                standing = collect(shell, sites=False).standing
            if standing is not None and standing.standing == Standing.TARGET_STACK:
                return
            if time.monotonic() >= end:
                self.fail(f"The host is not manageable: {standing}")

    def wait_for_due_events(self, count: int, *, hook: str = DUE_EVENT, timeout: float = 20) -> int:
        end = time.monotonic() + timeout
        value = self.due_events(hook)
        while value != count and time.monotonic() < end:
            time.sleep(0.2)
            value = self.due_events(hook)
        return value

    def visit_home(self) -> None:
        self.native(
            "curl --fail --silent --show-error --max-time 20 --insecure "
            f"--resolve {DOMAIN}:443:127.0.0.1 https://{DOMAIN}/ >/dev/null"
        )

    def constant(self) -> str:
        return self.native(
            f"grep -o \"DISABLE_WP_CRON', '[a-z]*\" {shlex.quote(PRIVATE)} || true"
        ).strip()

    def property(self, unit: str, name: str) -> str:
        return self.native(f"systemctl show --value -p {name} {unit}").strip()

    def unix_property(self, unit: str, name: str) -> str:
        return self.native(f"systemctl show --value --timestamp=unix -p {name} {unit}").strip()

    def test_1_creates_the_pinned_wordpress_site(self) -> None:
        self.install_acme()
        self.install_engine()
        apply_change(
            self,
            create.CREATE_WORDPRESS,
            self.inputs(),
            timeout=120,
            secret=CANARY.encode(),
        )
        home = self.native(
            "curl --silent --show-error --fail --max-time 20 --insecure "
            f"--resolve {DOMAIN}:443:127.0.0.1 https://{DOMAIN}/"
        )
        self.assertIn("WordPress", home)

    def test_2_turns_on_server_cron_and_page_loads_stop_running_it(self) -> None:
        self.wait_manageable()
        apply_change(
            self,
            change.SET_WORDPRESS_SERVER_CRON,
            PreparationInputs("", IDENTIFIER, schedule_state="on"),
            timeout=180,
        )
        timer = timer_name(IDENTIFIER, "wpcron")
        service = service_name(IDENTIFIER, "wpcron")
        self.assertIn("active", self.property(timer, "ActiveState"))
        self.assertIn("enabled", self.property(timer, "UnitFileState"))
        self.assertIn("true", self.constant())
        # One run happened before the hand-over: the timer fired it, not a page load.
        triggered = self.unix_property(timer, "LastTriggerUSec")
        started = self.unix_property(service, "ExecMainStartTimestamp")
        self.assertTrue(triggered.startswith("@") and triggered.strip("@").isdigit(), triggered)
        self.assertTrue(started.startswith("@") and started.strip("@").isdigit(), started)
        self.assertEqual(self.property(service, "Result"), "success")
        # A due event survives a page load once the server task owns cron.
        self.schedule_due_event(ON_EVENT, delay=-1)
        self.wp("eval", "delete_transient('doing_cron');")
        self.visit_home()
        self.assertEqual(self.wait_for_due_events(1, hook=ON_EVENT, timeout=3), 1)
        # The task itself runs it, exactly as the timer will every minute.
        self.native(f"systemctl start {service}")
        self.assertEqual(self.wait_for_due_events(0, hook=ON_EVENT, timeout=15), 0)
        # The timer is armed for the next minute without any controller involved.
        self.assertNotIn(self.property(timer, "NextElapseUSecRealtime"), ("", "0", "n/a"))

    def test_3_the_fresh_controller_reconstructs_it_and_proposes_nothing(self) -> None:
        inputs = PreparationInputs("", IDENTIFIER, schedule_state="on")
        self.wait_manageable()
        state = self.record_state
        if state:
            with ssh.connect(self.target()) as connection:
                shell: ssh.RemoteShell = recorded.RecordingShell(
                    connection, state, secrets=(recorded.SEEDED_SECRET,)
                )
                self._checkpoint(shell, inputs)
        else:
            with self.shell() as shell:
                self._checkpoint(shell, inputs)

    def _checkpoint(self, shell: ssh.RemoteShell, inputs: PreparationInputs) -> None:
        from discovery.observations import collect

        observed = collect(shell, releases=True)
        draft = change.review(change.inspect(shell, inputs), inputs)
        self.checkpoint(STATE, shell)
        schedule = next(row for row in observed.automation.value if row.identifier == IDENTIFIER)
        self.assertEqual(schedule.status.value, "succeeded")
        self.assertTrue(schedule.timer_enabled)
        self.assertEqual(schedule.disable_wp_cron, "true")
        self.assertTrue(draft.no_changes, draft.refusals)
        self.assertEqual(draft.effects, ())

    def test_4_turning_off_gives_page_load_cron_back_before_the_task_stops(self) -> None:
        self.wait_manageable()
        apply_change(
            self,
            change.SET_WORDPRESS_SERVER_CRON,
            PreparationInputs("", IDENTIFIER, schedule_state="off"),
            timeout=120,
        )
        timer = timer_name(IDENTIFIER, "wpcron")
        service = service_name(IDENTIFIER, "wpcron")
        self.assertNotIn("true", self.constant())
        # Page loads run a due event again, with no server task to wait for.
        self.schedule_due_event(OFF_EVENT, delay=5)
        self.wp("eval", "delete_transient('doing_cron');")
        self.visit_home()
        self.assertEqual(self.wait_for_due_events(0, hook=OFF_EVENT, timeout=15), 0)
        self.assertEqual(self.property(timer, "LoadState"), "not-found")
        self.assertEqual(self.property(service, "LoadState"), "not-found")
        self.assertEqual(
            self.native(
                f"test -e /etc/systemd/system/{timer} || "
                f"test -e /etc/systemd/system/{service} || echo gone"
            ).strip(),
            "gone",
        )


__all__ = ["WordPressServerCron"]
