"""A fresh controller reconstructs server cron and its last result from the server alone."""

from django.test import TestCase
from django.utils import timezone

from discovery import recorded
from discovery.models import DiscoveryAttempt
from discovery.observations import collect
from discovery.recorded import ReplayShell
from discovery.snapshot import current_snapshot, save_snapshot
from operations.inputs import PreparationInputs
from servers.models import Server

from . import change
from .status import ScheduleStatus

STATE = "automation-wordpress-26.04"
IDENTIFIER = "swpalpha"


class RecordedServerCronTests(TestCase):
    def test_the_recorded_state_reconstructs_with_cron_on_and_a_successful_run(self) -> None:
        observed = collect(ReplayShell(recorded.load(STATE)), releases=True)
        self.assertEqual(observed.automation.outcome.value, "observed")
        schedule = next(row for row in observed.automation.value if row.identifier == IDENTIFIER)
        self.assertEqual(schedule.status, ScheduleStatus.SUCCEEDED)
        self.assertTrue(schedule.installed)
        self.assertTrue(schedule.timer_active)
        self.assertTrue(schedule.timer_enabled)
        self.assertEqual(schedule.disable_wp_cron, "true")
        self.assertGreater(schedule.last_exit_us, 0)
        self.assertGreater(schedule.next_elapse_us, 0)
        cron = [
            row
            for row in observed.settings.value
            if row.identifier == IDENTIFIER and row.key == "DISABLE_WP_CRON"
        ]
        self.assertEqual([row.value for row in cron], ["true"])

    def test_a_repeated_review_from_the_recorded_state_proposes_nothing(self) -> None:
        shell = ReplayShell(recorded.load(STATE))
        collect(shell, releases=True)
        inputs = PreparationInputs("", IDENTIFIER, schedule_state="on")
        draft = change.review(change.inspect(shell, inputs), inputs)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
        self.assertEqual(draft.effects, ())

    def test_the_stored_snapshot_keeps_the_setting_and_last_result(self) -> None:
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        collected = collect(ReplayShell(recorded.load(STATE)), releases=True)
        attempt = DiscoveryAttempt.objects.create(
            server=server,
            ssh_alias=server.ssh_alias,
            status=DiscoveryAttempt.Status.SUCCEEDED,
        )
        save_snapshot(attempt, collected, timezone.now())
        stored = current_snapshot(server)
        if stored is None:
            self.fail("The snapshot was stored.")
        self.assertEqual(stored.collected.automation, collected.automation)
        schedule = next(
            row for row in stored.collected.automation.value if row.identifier == IDENTIFIER
        )
        self.assertEqual(schedule.status, ScheduleStatus.SUCCEEDED)
        self.assertEqual(schedule.disable_wp_cron, "true")
