"""One real discovery transcript drives the Jobs classification (#285, #289)."""

from typing import override

from django.test import SimpleTestCase
from django.utils import timezone

from automation.status import ScheduleStatus
from discovery.fakes import READ_ONLY
from discovery.observations import collect
from discovery.recorded import ReplayShell, load
from discovery.snapshot import Snapshot
from servers.models import Server

from .automatic import (
    OBJECT_CACHE,
    QUEUE_WORKER,
    SCHEDULED_TASK,
    AutomaticWork,
    automatic_work,
)

STATE = "jobs-changes-26.04"
SERVER = Server(pk=1, name="Web", ssh_alias="web.example.com")


class RecordedJobsTests(SimpleTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.shell = ReplayShell(load(STATE))
        self.addCleanup(self.assert_read_only)

    def assert_read_only(self) -> None:
        for command in self.shell.commands:
            self.assertRegex(command, READ_ONLY)

    def test_the_second_controller_names_a_finished_change_from_the_journal(self) -> None:
        collected = collect(self.shell, releases=True)
        reading = collected.jobs.value
        self.assertEqual(reading.coverage[0].state, "complete")
        (row,) = [change for change in reading.changes if change.kind_slug == "create_http_site"]
        self.assertEqual(row.sites, ("s5alpha",))
        self.assertEqual(row.result_class, "succeeded")
        self.assertIsNotNone(row.started_at)
        self.assertIsNotNone(row.finished_at)


class RecordedAutomaticTests(SimpleTestCase):
    def work(self, state: str, *, releases: bool = True) -> AutomaticWork:
        collected = collect(ReplayShell(load(state)), releases=releases)
        return automatic_work(Snapshot(collected, timezone.now(), "web.example.com"), SERVER)

    def test_the_recorded_wordpress_cron_appears_with_its_next_elapse(self) -> None:
        work = self.work("automation-wordpress-26.04")
        (row,) = [
            entry
            for entry in work.rows
            if entry.identifier == "l3wordpress" and entry.work_type == SCHEDULED_TASK
        ]
        self.assertEqual(row.state, "On, the last run succeeded")
        self.assertFalse(row.needs_attention)
        self.assertIsNotNone(row.next_run_at)
        self.assertFalse(row.next_run_unknown)

    def test_the_recorded_laravel_scheduler_appears_as_a_scheduled_task(self) -> None:
        work = self.work("automation-laravel-26.04")
        (row,) = [
            entry
            for entry in work.rows
            if entry.identifier == "sqwalpha" and entry.work_type == SCHEDULED_TASK
        ]
        self.assertEqual(row.state, "On, the last run succeeded")
        self.assertEqual(row.role, "schedule")

    def test_the_recorded_queue_workers_appear_as_a_running_worker(self) -> None:
        work = self.work("automation-laravel-workers-26.04")
        (row,) = [
            entry
            for entry in work.rows
            if entry.identifier == "sqwalpha" and entry.work_type == QUEUE_WORKER
        ]
        self.assertEqual(row.state, "On, running")
        self.assertIn("barectl-site-sqwalpha-queue1.service", row.detail_lines[2][1])

    def test_the_recorded_wordpress_cache_appears_as_an_object_cache(self) -> None:
        work = self.work("object-cache-26.04", releases=False)
        (row,) = [
            entry
            for entry in work.rows
            if entry.identifier == "l3wordpress" and entry.work_type == OBJECT_CACHE
        ]
        self.assertEqual(row.state, "On")
        self.assertFalse(row.needs_attention)

    def test_the_recorded_skipped_and_failed_states_keep_phase_c_sentences(self) -> None:
        from dataclasses import replace

        collected = collect(ReplayShell(load("automation-wordpress-26.04")), releases=True)
        found = next(row for row in collected.automation.value if row.identifier == "l3wordpress")
        skipped = replace(found, status=ScheduleStatus.SKIPPED)
        failed = replace(found, status=ScheduleStatus.FAILED)
        work = automatic_work(
            Snapshot(
                replace(
                    collected,
                    automation=replace(collected.automation, value=(skipped, failed)),
                ),
                timezone.now(),
                "web.example.com",
            ),
            SERVER,
        )
        self.assertEqual(
            [row.state for row in work.rows],
            ["On, a run took too long so the next one was skipped", "On, the last run failed"],
        )
        self.assertEqual(
            [row.attention_sentence for row in work.rows],
            [
                (
                    "Scheduled tasks for l3wordpress skipped a run because the previous run "
                    "took longer than a minute."
                ),
                "Scheduled tasks for l3wordpress on, the last run failed.",
            ],
        )
