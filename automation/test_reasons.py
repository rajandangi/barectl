"""The automation vocabulary reads on the run screens (#495, #504).

Every assertion observes the sentence an operator sees for a reason a scheduler, cron or
queue-worker body prints, not the shape of the declaration.
"""

from django.test import SimpleTestCase

from operations import engine, reasons
from operations.models import Result

from .bodies.reasons import SCHEDULE_REASONS, SCHEDULER_REASONS, WORKER_REASONS

_DECLARATIONS = (SCHEDULE_REASONS, SCHEDULER_REASONS, WORKER_REASONS)


class AutomationReasonTests(SimpleTestCase):
    def test_every_declared_pair_has_its_own_sentence(self) -> None:
        for declared in _DECLARATIONS:
            for reason in declared:
                for outcome in reason.outcomes:
                    with self.subTest(reason=reason.name, outcome=outcome.value):
                        sentence = engine.reason_text(outcome.value, reason.name)
                        self.assertEqual(sentence, reason.sentence(outcome))
                        self.assertNotEqual(sentence, reasons.OUTCOME_SENTENCES[outcome])

    def test_a_scheduler_cron_or_worker_change_that_stops_names_start_units_tick_or_environment(
        self,
    ) -> None:
        cases = (
            ("partial", "automation_start", "did not start"),
            ("partial", "automation_units", "units"),
            ("partial", "automation_tick", "first scheduled run"),
            ("refused", "automation_scheduler", "scheduler"),
            ("partial", "automation_run", "scheduler started one run"),
            ("partial", "automation_running", "still going"),
            ("refused", "queue_workers_site", "account"),
            ("refused", "queue_workers_activation", "current release changed"),
            ("refused", "queue_workers_environment", "environment"),
            ("partial", "queue_workers_environment", "partly applied"),
            ("partial", "queue_workers_start", "worker process is running"),
            ("partial", "queue_workers_stop", "worker stopped"),
        )
        for outcome, reason, words in cases:
            with self.subTest(reason=reason):
                sentence = engine.reason_text(outcome, reason)
                self.assertIn(words, sentence)
                self.assertNotEqual(sentence, reasons.OUTCOME_SENTENCES[Result(outcome)])

    def test_a_scheduled_change_that_fails_without_a_reason_names_the_scheduled_tasks(self) -> None:
        sentence = engine.reason_text("failed", "automation")

        self.assertIn("scheduled tasks", sentence)
        self.assertNotIn("without reporting how far it got", sentence)
        self.assertNotEqual(sentence, reasons.OUTCOME_SENTENCES[Result.FAILED])
        self.assertNotEqual(sentence, engine.reason_text("refused", "automation"))

    def test_no_partial_sentence_claims_nothing_changed(self) -> None:
        for declared in _DECLARATIONS:
            for reason in declared:
                if Result.PARTIAL in reason.outcomes:
                    with self.subTest(reason=reason.name):
                        self.assertNotIn("nothing changed", reason.sentence(Result.PARTIAL).lower())

    def test_a_scheduler_result_line_reads_as_the_units_step(self) -> None:
        line = engine.parse_result_line(
            'barectl-result {"class":"partial","reason":"automation_units",'
            '"change_kind":"set_laravel_scheduler"}'
        )

        self.assertIsNotNone(line)
        assert line is not None  # noqa: S101 - narrows the optional for mypy
        self.assertEqual(line.reason, "automation_units")
        self.assertEqual(
            engine.reason_text(line.result_class, line.reason),
            engine.reason_text("partial", "automation_units"),
        )
