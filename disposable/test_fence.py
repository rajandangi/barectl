"""A PHP switch fences a WordPress site's server cron, keeps serving, and restores it.

docs/quality.md#native-layer, Phase C scenario C3 ([#357](https://github.com/rajandangi/barectl/issues/357))
and [#395](https://github.com/rajandangi/barectl/issues/395). The fast layer proves the plan,
the order and the refusals against a simulated systemd; only a real systemd and a real slice
can prove that masking and stopping a site's automation never interrupts its HAProxy or
PHP-FPM serving, that a switch restores the timer on the target runtime, and that a slice
which cannot drain refuses with nothing changed.
"""

import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import override

from django.test import tag

from automation.convention import service_name, slice_name, timer_name
from discovery import recorded, ssh
from operations.inputs import PreparationInputs
from sites import php_change
from wordpress import create

from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG
from .test_wordpress_create import CANARY, DOMAIN, IDENTIFIER, WordPressCreateCase

STATE = "fence-wordpress-26.04"
BLOCKER = "barectl-fence-blocker"
TARGET = "php85"
SOURCE = "php84"


@tag(SCENARIO_TAG)
class PHPFence(WordPressCreateCase):
    """One WordPress site with server cron on, then a PHP switch that fences it."""

    records: tuple[str, ...] = (STATE,)

    @override
    @contextmanager
    def shell(self) -> Iterator[ssh.RemoteShell]:
        """A plain connection: only the checkpoint shell records a transcript."""
        os.environ["SSH_AUTH_SOCK"] = ""
        with ssh.connect(self.target()) as connection:
            yield connection

    def property(self, unit: str, name: str) -> str:
        return self.native(f"systemctl show --value -p {name} {unit}").strip()

    def home(self) -> str:
        return self.native(
            "curl --silent --show-error --fail --max-time 20 --insecure "
            f"--resolve {DOMAIN}:443:127.0.0.1 https://{DOMAIN}/"
        )

    def wrapper_runtime(self) -> str:
        return self.native(
            "grep -o '/nix/var/nix/profiles/barectl/php[0-9]*/bin/php' "
            f"/var/www/{IDENTIFIER}/bin/php | head -1"
        ).strip()

    def slice_populated(self) -> bool:
        control_group = self.property(slice_name(IDENTIFIER), "ControlGroup")
        if not control_group.startswith("/"):
            return False
        return "populated 1" in self.native(
            f"cat /sys/fs/cgroup{control_group}/cgroup.events 2>/dev/null || true"
        )

    def wait_manageable(self, *, timeout: float = 60) -> None:
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

    def test_1_creates_the_site_and_turns_server_cron_on(self) -> None:
        from automation import change

        self.install_acme()
        self.install_engine()
        apply_change(
            self,
            create.CREATE_WORDPRESS,
            self.inputs(),
            timeout=120,
            secret=CANARY.encode(),
        )
        self.assertIn("WordPress", self.home())
        self.wait_manageable()
        apply_change(
            self,
            change.SET_WORDPRESS_SERVER_CRON,
            PreparationInputs("", IDENTIFIER, schedule_state="on"),
            timeout=180,
        )
        self.assertEqual(self.property(timer_name(IDENTIFIER, "wpcron"), "ActiveState"), "active")

    def test_2_a_switch_fences_and_restores_the_timer_on_the_target_runtime(self) -> None:
        timer = timer_name(IDENTIFIER, "wpcron")
        service = service_name(IDENTIFIER, "wpcron")
        proxy = f"haproxy-site@{IDENTIFIER}.service"
        before_proxy = self.property(proxy, "MainPID")
        self.assertFalse(self.slice_populated())
        with self.shell() as shell:
            evidence = php_change.inspect(shell, PreparationInputs(TARGET, IDENTIFIER))
        if evidence.state is None:
            from sites import observation as site_observation

            raw = self.native(
                site_observation.python_command(php_change.READ_SOURCE, (IDENTIFIER,))
                + " 2>&1; true"
            )
            self.fail("The site's PHP state could not be read:\n" + raw[-4000:])
        apply_change(self, php_change.SET_SITE_PHP, PreparationInputs(TARGET, IDENTIFIER))
        self.assertIn("WordPress", self.home(), "The site must keep serving across the fence.")
        self.assertEqual(
            self.property(proxy, "MainPID"),
            before_proxy,
            "The site's own proxy process must never stop for a fence.",
        )
        self.assertIn(TARGET, self.wrapper_runtime())
        self.assertEqual(self.property(timer, "ActiveState"), "active")
        self.assertTrue(self.property(timer, "UnitFileState").startswith("enabled"))
        self.assertEqual(self.property(service, "Result"), "success")
        self.assertFalse(self.slice_populated())

    def test_3_a_fence_that_cannot_drain_refuses_with_nothing_changed(self) -> None:
        timer = timer_name(IDENTIFIER, "wpcron")
        runtime = self.wrapper_runtime()
        self.addCleanup(self.native, f"systemctl kill -s SIGKILL {BLOCKER} || true")
        # A process that survives SIGTERM keeps the slice populated past the stop budget.
        self.native(
            "systemd-run "
            f"--unit={BLOCKER} --slice={slice_name(IDENTIFIER)} --quiet "
            "--property=TimeoutStopSec=5 --property=SendSIGKILL=no "
            "/bin/sh -c 'trap \"\" TERM; exec sleep 240'"
        )
        deadline = time.monotonic() + 10
        while not self.slice_populated() and time.monotonic() < deadline:
            time.sleep(0.2)
        if not self.slice_populated():
            self.fail(
                "The blocker is not inside the site's slice:\n"
                + self.native(
                    f"systemctl status --no-pager {BLOCKER} | head -20; "
                    f"systemd-cgls --no-pager /sys/fs/cgroup | head -40; "
                    f"systemctl show -p ControlGroup {slice_name(IDENTIFIER)}"
                )
            )
        apply_change(
            self,
            php_change.SET_SITE_PHP,
            PreparationInputs(SOURCE, IDENTIFIER),
            timeout=120,
            expected="refused",
            reason="automation_fence",
        )
        self.assertEqual(
            self.wrapper_runtime(),
            runtime,
            "A refused fence must not change the runtime.\n"
            + self.native("journalctl -u 'barectl-apply-*' -n 40 --no-pager | tail -40"),
        )
        self.assertIn("WordPress", self.home(), "Serving never stops for a fence.")
        states = self.native(f"systemctl show -p LoadState -p UnitFileState -p ActiveState {timer}")
        self.assertEqual(
            self.property(timer, "RefuseManualStart"),
            "yes",
            states
            + "\n"
            + self.native(
                "ls -l /run/systemd/system | head -20; "
                "journalctl -u 'barectl-apply-*' -n 40 --no-pager | tail -40"
            ),
        )
        self.assertEqual(self.property(timer, "ActiveState"), "inactive", states)

    def test_4_the_paused_state_is_read_from_the_runtime_mask(self) -> None:
        from automation import observation
        from automation.status import ScheduleStatus

        with self.shell() as shell:
            value = observation.read(shell)
        self.assertIsNotNone(value)
        if value is None:
            self.fail("The automation read returned nothing.")
        row = observation.schedule_for(value, IDENTIFIER)
        self.assertEqual(row.status, ScheduleStatus.PAUSED)
        self.assertTrue(row.masked)
        self.assertFalse(row.timer_enabled)

    def test_5_records_the_paused_state(self) -> None:
        if self.record_state:
            with ssh.connect(self.target()) as connection:
                shell: ssh.RemoteShell = recorded.RecordingShell(
                    connection, STATE, secrets=(recorded.SEEDED_SECRET,)
                )
                self._checkpoint(shell)
        else:
            with self.shell() as shell:
                self._checkpoint(shell)

    def _checkpoint(self, shell: ssh.RemoteShell) -> None:
        from discovery.observations import collect

        collect(shell)
        self.checkpoint(STATE, shell)


__all__ = ["PHPFence"]
