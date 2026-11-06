"""The log rotation body's result reasons read on the run screens (#495)."""

from django.test import SimpleTestCase

from logs.bodies.reasons import LOG_ROTATION_REASONS
from operations import engine
from operations.reason_testing import assert_declared_sentences


class LogRotationReasonTests(SimpleTestCase):
    def test_every_declared_reason_has_its_own_sentence(self) -> None:
        assert_declared_sentences(self, (LOG_ROTATION_REASONS,))

    def test_log_rotation_names_the_missing_tool_or_the_refused_file(self) -> None:
        missing = engine.reason_text("refused", "logrotate_missing")
        invalid = engine.reason_text("refused", "rotation_invalid")

        self.assertIn("does not run logrotate", missing)
        self.assertIn("logrotate refused the reviewed rotation file", invalid)
        for sentence in (missing, invalid):
            self.assertNotIn("without reporting how far it got", sentence)
