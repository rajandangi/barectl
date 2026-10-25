"""The Laravel scheduler on the prepared L5 layer (Phase C #357, native scenario C2).

docs/quality.md#native-layer. Creating and deploying the Laravel site costs more than one
item once the scheduler's calendar wait is added, so this scenario starts from the prepared
L5 snapshot (#393) and proves only the scheduler: a tick runs the current release as the
site account with no controller connection open, a hand-made crontab blocks turning it on,
Run now starts one bare tick, and Off removes the units. The Deploy lifecycle that prepares
the state is ``disposable.test_laravel_deploy.LaravelDeployMariaDB``.
"""

import os
import shlex
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import override

from django.test import tag

from discovery import recorded, ssh
from operations.inputs import PreparationInputs

from .scenario_testing import SCENARIO_TAG
from .test_laravel_deploy import LaravelDeployCase

STATE = "automation-laravel-26.04"
SITE = "sqwalpha"
DOMAIN = "site.fixture.test"


@tag(SCENARIO_TAG)
class LaravelScheduler(LaravelDeployCase):
    """Turn the scheduler on, prove one tick with no controller, Run now and Off."""

    layer = "L5"
    exclusive = True
    prefix = "sqw"
    identity = SITE
    domain = DOMAIN
    records: tuple[str, ...] = (STATE,)
    schedule_state = STATE

    @override
    @contextmanager
    def shell(self) -> Iterator[ssh.RemoteShell]:
        """A plain connection: only the scheduler checkpoint records a transcript."""
        os.environ["SSH_AUTH_SOCK"] = ""
        with ssh.connect(self.target()) as connection:
            yield connection

    def unit_property(self, unit: str, name: str) -> str:
        return self.native(f"systemctl show --value -p {name} {unit}").strip()

    def unit_unix(self, unit: str, name: str) -> int:
        value = self.native(f"systemctl show --value --timestamp=unix -p {name} {unit}").strip()
        return int(value.removeprefix("@") or 0)

    def wait_for_a_tick(self, service: str, after: int, *, timeout: float = 75) -> int:
        """Wait for a completed run that started after ``after``, with no controller open."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            started = self.unit_unix(service, "ExecMainStartTimestamp")
            state = self.unit_property(service, "ActiveState")
            if started > after and state in ("inactive", "failed"):
                return started
            time.sleep(1)
        detail = self.native(f"systemctl status {service} --no-pager -n 20")
        raise AssertionError(f"No scheduler run after the reviewed change: {detail}")

    def _scheduler_checkpoint(self, shell: ssh.RemoteShell, inputs: PreparationInputs) -> None:
        from automation import scheduler as scheduler_change
        from automation.status import ScheduleStatus
        from discovery.observations import collect

        observed = collect(shell, releases=True)
        evidence = scheduler_change.inspect(shell, inputs)
        draft = scheduler_change.review(evidence, inputs)
        if not draft.eligible:
            self.fail(f"{draft.refusals} site={evidence.site} laravel={evidence.laravel}")
        self.checkpoint(self.schedule_state, shell)
        row = next(
            item
            for item in observed.automation.value
            if item.identifier == self.identity and item.role == "schedule"
        )
        self.assertEqual(row.status, ScheduleStatus.SUCCEEDED)
        self.assertTrue(row.timer_enabled)
        self.assertTrue(row.timer_active)
        self.assertTrue(draft.no_changes, draft.refusals)
        self.assertEqual(draft.effects, ())

    def test_the_scheduler_ticks_with_the_controller_stopped(self) -> None:
        from automation import scheduler as scheduler_change
        from automation.convention import service_name, timer_name
        from automation.status import ScheduleStatus
        from discovery.observations import collect

        inputs = PreparationInputs("", self.identity, schedule_state="on")
        line, unit, _ = self.apply(scheduler_change.SET_LARAVEL_SCHEDULER, inputs, timeout=90)
        self.assert_succeeded(line, unit)
        timer = timer_name(self.identity, "schedule")
        service = service_name(self.identity, "schedule")
        self.assertEqual(self.unit_property(timer, "ActiveState"), "active")
        self.assertIn("enabled", self.unit_property(timer, "UnitFileState"))
        self.assertEqual(self.unit_property(service, "Type"), "oneshot")
        self.assertIn("1h", self.unit_property(service, "TimeoutStartUSec"))
        self.assertIn(
            f"/var/www/{self.identity}/bin/php "
            f"/var/www/{self.identity}/current/artisan schedule:run",
            self.unit_property(service, "ExecStart"),
        )
        # No Barectl connection stays open: only the harness reads the server container.
        started = self.unit_unix(service, "ExecMainStartTimestamp")
        completed = self.wait_for_a_tick(service, started)
        self.assertGreater(completed, 0)

        state = self.record_state
        if state == self.schedule_state:
            with ssh.connect(self.target()) as connection:
                recording = recorded.RecordingShell(
                    connection, state, secrets=(recorded.SEEDED_SECRET,)
                )
                self._scheduler_checkpoint(recording, inputs)
        else:
            with self.shell() as shell:
                self._scheduler_checkpoint(shell, inputs)

        with self.shell() as shell:
            observed = collect(shell, releases=True)
        row = next(
            item
            for item in observed.automation.value
            if item.identifier == self.identity and item.role == "schedule"
        )
        self.assertEqual(row.status, ScheduleStatus.SUCCEEDED)
        self.assertGreater(row.next_elapse_us, 0)

        # A hand-made crontab entry blocks turning the managed scheduler on.
        cron = "/etc/cron.d/barectl-sqw-scheduler-duplicate"
        self.native(
            "printf '%s\\n' "
            + shlex.quote(
                f"* * * * * root /var/www/{self.identity}/bin/php "
                f"/var/www/{self.identity}/current/artisan schedule:run"
            )
            + f" > {cron} && chmod 644 {cron}"
        )
        self.addCleanup(self.native, f"rm -f {cron}")
        blocked = self.review(scheduler_change.SET_LARAVEL_SCHEDULER, inputs)
        self.assertFalse(blocked.eligible)
        self.assertTrue(any("crontab" in refusal for refusal in blocked.refusals), blocked.refusals)

        # Run now starts the installed service once and waits for its result.
        before = self.unit_unix(service, "ExecMainStartTimestamp")
        line, unit, _ = self.apply(
            scheduler_change.SET_LARAVEL_SCHEDULER,
            PreparationInputs("", self.identity, schedule_state="run"),
            timeout=90,
        )
        self.assert_succeeded(line, unit)
        self.assertGreater(self.unit_unix(service, "ExecMainStartTimestamp"), before)

        line, unit, _ = self.apply(
            scheduler_change.SET_LARAVEL_SCHEDULER,
            PreparationInputs("", self.identity, schedule_state="off"),
            timeout=60,
        )
        self.assert_succeeded(line, unit)
        self.assertEqual(self.unit_property(timer, "LoadState"), "not-found")
        self.assertEqual(self.unit_property(service, "LoadState"), "not-found")


__all__ = ["LaravelScheduler"]
