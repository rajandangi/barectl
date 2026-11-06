"""The runtime vocabulary reads on the run screens (#495, #501).

Every assertion observes the sentence an operator sees for a reason the server printed,
not the shape of the declaration.
"""

from django.test import SimpleTestCase

from operations import engine, reasons
from operations.models import Result

from .change import ADD_RUNTIME
from .defaults import SET_DEFAULT_NODE, SET_DEFAULT_PHP
from .remove import REMOVE_RUNTIME
from .revert import REVERT_RUNTIME
from .update import UPDATE_CATALOG

KINDS = (
    ADD_RUNTIME,
    REMOVE_RUNTIME,
    UPDATE_CATALOG,
    REVERT_RUNTIME,
    SET_DEFAULT_PHP,
    SET_DEFAULT_NODE,
)


def _sentence(outcome: Result, reason: str) -> str:
    return engine.reason_text(outcome.value, reason)


class RuntimeRemovalReasonTests(SimpleTestCase):
    def test_a_runtime_the_default_still_uses_reads_as_still_in_use(self) -> None:
        sentence = _sentence(Result.REFUSED, "runtime_in_use")

        self.assertIn("still in use", sentence)
        self.assertIn("default", sentence)
        self.assertNotIn("without reporting how far it got", sentence)

    def test_a_runtime_with_unreadable_default_commands_reads_distinctly(self) -> None:
        unreadable = _sentence(Result.REFUSED, "defaults_unreadable")
        generic = _sentence(Result.REFUSED, "")

        self.assertNotEqual(unreadable, generic)
        self.assertIn("default", unreadable)
        self.assertIn("discovery", unreadable.lower())
        self.assertNotIn("without reporting how far it got", unreadable)

    def test_both_runtime_removal_reasons_are_read_from_the_result_line(self) -> None:
        for reason in ("runtime_in_use", "defaults_unreadable"):
            with self.subTest(reason=reason):
                line = engine.parse_result_line(
                    'barectl-result {"class":"refused","reason":"'
                    + reason
                    + '","change_kind":"remove_runtime"}'
                )
                self.assertIsNotNone(line)
                if line is None:
                    self.fail("The result line was not read.")
                self.assertEqual(line.reason, reason)


class RuntimeStepReasonTests(SimpleTestCase):
    def test_a_runtime_that_stops_at_realisation_configuration_or_start_names_the_step(
        self,
    ) -> None:
        for reason, step in (
            ("runtime_realise", "realisation"),
            ("runtime_config", "configuration"),
            ("runtime_start", "start"),
        ):
            with self.subTest(reason=reason):
                sentence = _sentence(Result.PARTIAL, reason)
                self.assertIn(step, sentence.lower())
                self.assertNotIn("without reporting how far it got", sentence)

    def test_a_catalog_update_that_stops_at_realisation_names_the_step(self) -> None:
        sentence = _sentence(Result.REFUSED, "runtime_realise")

        self.assertIn("realisation", sentence.lower())
        self.assertIn("before any profile moved", sentence)
        self.assertNotIn("native evidence changed", sentence)


class RuntimeVocabularyTests(SimpleTestCase):
    def test_every_declared_runtime_pair_has_its_own_sentence(self) -> None:
        for kind in KINDS:
            for reason in kind.reasons:
                for outcome in reason.outcomes:
                    with self.subTest(kind=kind.slug, reason=reason.name, outcome=outcome.value):
                        self.assertEqual(
                            _sentence(outcome, reason.name),
                            reason.sentence(outcome),
                        )
                        self.assertNotEqual(
                            _sentence(outcome, reason.name), reasons.OUTCOME_SENTENCES[outcome]
                        )

    def test_every_runtime_body_declares_what_it_prints(self) -> None:
        self.assertEqual(reasons.manifest_errors(), [])
