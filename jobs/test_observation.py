"""Real systemctl and journalctl output replayed at the remote-shell seam (#285)."""

import json
from datetime import UTC, datetime

from django.test import SimpleTestCase

from discovery.fakes import kept_text
from operations import native

from . import observation
from .testing import (
    BOOT,
    INVOCATION,
    OTHER_INVOCATION,
    OTHER_UNIT,
    SECRET,
    UNIT,
    journal_shell,
    line,
    result_line,
    retained,
)


class RecordedChangeJobsTests(SimpleTestCase):
    def test_a_running_unit_and_a_collected_run_are_told_apart(self) -> None:
        reading = observation.read(
            journal_shell(
                units=retained(UNIT, INVOCATION),
                history="\n".join(
                    (
                        line(
                            "barectl-stage preflight",
                            unit=OTHER_UNIT,
                            invocation=OTHER_INVOCATION,
                            usec=1_762_000_000_000_000,
                        ),
                        line(
                            result_line(kind="create_http_site", sites=("alpha",)),
                            unit=OTHER_UNIT,
                            invocation=OTHER_INVOCATION,
                            usec=1_762_000_000_100_000,
                        ),
                    )
                ),
            )
        )
        running, finished = reading.changes
        self.assertTrue(running.running)
        self.assertEqual(running.unit, UNIT)
        self.assertFalse(finished.running)
        self.assertEqual(finished.result_class, "succeeded")
        self.assertEqual(finished.kind_slug, "create_http_site")
        self.assertEqual(finished.sites, ("alpha",))
        self.assertEqual(reading.coverage[0].state, "complete")

    def test_a_collected_unit_is_kept_without_double_counting(self) -> None:
        reading = observation.read(
            journal_shell(
                units=retained(UNIT, INVOCATION, active="inactive", sub="dead", populated=0),
                history=line(result_line(), usec=1_762_000_000_100_000),
            )
        )
        self.assertEqual(len(reading.changes), 1)
        self.assertEqual(reading.changes[0].result_class, "succeeded")

    def test_lines_without_kind_or_site_are_a_generic_change(self) -> None:
        reading = observation.read(
            journal_shell(
                units=BOOT + "\n",
                history=line(result_line(), usec=1_762_000_000_100_000),
            )
        )
        (row,) = reading.changes
        self.assertEqual(row.kind_slug, "")
        self.assertEqual(row.sites, ())

    def test_a_malformed_result_line_could_not_confirm_and_is_unreadable(self) -> None:
        reading = observation.read(
            journal_shell(
                units=BOOT + "\n",
                history=line("barectl-result {not json", usec=1_762_000_000_100_000),
            )
        )
        (row,) = reading.changes
        self.assertEqual(row.result_class, "")
        self.assertEqual(reading.coverage[0].state, "unreadable")

    def test_a_missing_timestamp_is_unreadable_not_an_invented_time(self) -> None:
        reading = observation.read(
            journal_shell(units=BOOT + "\n", history=line(result_line(), usec=None))
        )
        self.assertEqual(reading.changes, ())
        self.assertEqual(reading.coverage[0].state, "unreadable")

    def test_denied_journal_access_keeps_running_work_and_names_the_denial(self) -> None:
        reading = observation.read(
            journal_shell(
                units=retained(UNIT, INVOCATION),
                history="",
                root="1000",
                authorized=False,
            )
        )
        (row,) = reading.changes
        self.assertTrue(row.running)
        coverage = reading.coverage[0]
        self.assertEqual(coverage.state, "access_denied")
        self.assertIn("did not use sudo", coverage.warning)

    def test_the_line_cap_is_an_explicit_truncation(self) -> None:
        history = "\n".join(
            line(
                result_line(),
                unit=f"barectl-apply-{index:032x}.service",
                invocation=f"{index:032x}",
                usec=1_762_000_000_000_000 + index,
            )
            for index in range(observation.HISTORY_LINES + 1)
        )
        reading = observation.read(journal_shell(units=BOOT + "\n", history=history))
        self.assertEqual(len(reading.changes), observation.HISTORY_LINES)
        self.assertEqual(reading.coverage[0].state, "truncated")
        self.assertIn("older results", reading.coverage[0].warning)

    def test_the_oldest_held_time_is_kept(self) -> None:
        reading = observation.read(
            journal_shell(
                units=BOOT + "\n",
                history=line(result_line(), usec=1_762_000_000_100_000),
                oldest=json.dumps({"__REALTIME_TIMESTAMP": "1700000000000000"}),
            )
        )
        self.assertEqual(
            reading.coverage[0].oldest_at,
            datetime.fromtimestamp(1_700_000_000, tz=UTC),
        )
        self.assertEqual(reading.coverage[0].state, "complete")

    def test_no_available_evidence_is_not_a_claim_that_nothing_ran(self) -> None:
        reading = observation.read(journal_shell(units=BOOT + "\n", history=""))
        self.assertEqual(reading.changes, ())
        self.assertEqual(reading.coverage[0].state, "no_evidence")
        self.assertIn("does not mean no change ran", reading.coverage[0].warning)

    def test_a_journal_message_never_reaches_the_observation(self) -> None:
        reading = observation.read(
            journal_shell(
                units=BOOT + "\n",
                history="\n".join(
                    (
                        line(f"barectl-stage {SECRET}", usec=1_762_000_000_000_000),
                        line(result_line(), usec=1_762_000_000_100_000),
                    )
                ),
            )
        )
        self.assertNotIn(SECRET, kept_text(reading))
        self.assertNotIn(SECRET, repr(reading))

    def test_the_read_issues_only_fixed_reads(self) -> None:
        replay = journal_shell(
            units=BOOT + "\n",
            history=line(result_line(), usec=1_762_000_000_100_000),
        )
        observation.read(replay)
        self.assertEqual(
            replay.commands,
            [
                native.RUNNING_STATES,
                "id -u",
                observation.HISTORY_COMMAND,
                "id -u",
                observation.OLDEST_COMMAND,
            ],
        )


class PrivilegedReadTests(SimpleTestCase):
    def test_the_journal_read_uses_the_engines_exact_sudo_authorization(self) -> None:
        replay = journal_shell(
            units=BOOT + "\n",
            history=line(result_line(), usec=1_762_000_000_100_000),
            root="1000",
            authorized=True,
        )
        reading = observation.read(replay)
        self.assertEqual(reading.coverage[0].state, "complete")
        history = ["/usr/bin/sh", "-c", observation.HISTORY_COMMAND]
        self.assertIn(native.authorization(history), replay.commands)
        self.assertIn(native.privileged(history, root=False), replay.commands)
