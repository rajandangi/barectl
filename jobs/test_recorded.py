"""One real discovery transcript drives the Jobs classification (#285)."""

from typing import override

from django.test import SimpleTestCase

from discovery.fakes import READ_ONLY
from discovery.observations import collect
from discovery.recorded import ReplayShell, load

STATE = "jobs-changes-26.04"


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
