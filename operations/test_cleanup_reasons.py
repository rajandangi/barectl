"""The finished-run cleanup body's result reason reads on the run screens (#495)."""

from django.test import SimpleTestCase

from operations import engine, reasons
from operations.bodies.cleanup_reasons import CLEANUP_REASONS


class CleanupReasonTests(SimpleTestCase):
    def test_every_declared_reason_has_its_own_sentence(self) -> None:
        for reason in CLEANUP_REASONS:
            for outcome in reason.outcomes:
                with self.subTest(reason=reason.name, outcome=outcome.value):
                    sentence = engine.reason_text(outcome.value, reason.name)
                    self.assertEqual(sentence, reason.sentence(outcome))
                    self.assertNotEqual(sentence, reasons.OUTCOME_SENTENCES[outcome])
                    line = engine.parse_result_line(
                        f'barectl-result {{"class":"{outcome.value}","reason":"{reason.name}"}}'
                    )
                    if line is None:
                        self.fail("The result line did not parse.")
                    self.assertEqual(line.reason, reason.name)

    def test_a_cleanup_that_stops_partway_names_its_own_cause(self) -> None:
        sentence = engine.reason_text("partial", "cleanup")

        self.assertIn("cleanup stopped partway", sentence)
        self.assertIn("partly applied", sentence)
        self.assertNotIn("Nothing changed", sentence)
        self.assertNotIn("without reporting how far it got", sentence)
