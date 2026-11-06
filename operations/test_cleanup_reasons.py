"""The finished-run cleanup body's result reason reads on the run screens (#495)."""

from django.test import SimpleTestCase

from operations import engine
from operations.bodies.cleanup_reasons import CLEANUP_REASONS
from operations.reason_testing import assert_declared_sentences


class CleanupReasonTests(SimpleTestCase):
    def test_every_declared_reason_has_its_own_sentence(self) -> None:
        assert_declared_sentences(self, (CLEANUP_REASONS,))

    def test_a_cleanup_that_stops_partway_names_its_own_cause(self) -> None:
        sentence = engine.reason_text("partial", "cleanup")

        self.assertIn("cleanup stopped partway", sentence)
        self.assertIn("partly applied", sentence)
        self.assertNotIn("Nothing changed", sentence)
        self.assertNotIn("without reporting how far it got", sentence)
