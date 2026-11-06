"""The log rotation body's result reasons read on the run screens (#495)."""

from django.test import SimpleTestCase

from logs.bodies.reasons import LOG_ROTATION_REASONS
from operations import engine, reasons


class LogRotationReasonTests(SimpleTestCase):
    def test_every_declared_reason_has_its_own_sentence(self) -> None:
        for reason in LOG_ROTATION_REASONS:
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

    def test_log_rotation_names_the_missing_tool_or_the_refused_file(self) -> None:
        missing = engine.reason_text("refused", "logrotate_missing")
        invalid = engine.reason_text("refused", "rotation_invalid")

        self.assertIn("does not run logrotate", missing)
        self.assertIn("logrotate refused the reviewed rotation file", invalid)
        for sentence in (missing, invalid):
            self.assertNotIn("without reporting how far it got", sentence)
