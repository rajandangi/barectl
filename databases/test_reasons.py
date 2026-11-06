"""The database vocabulary reads on the run screens (#495, #501).

Every assertion observes the sentence an operator sees for a reason the server printed,
not the shape of the declaration.
"""

from django.test import SimpleTestCase

from operations import engine, reasons
from operations.models import Result
from operations.reason_testing import assert_declared_sentences

from .engine import INSTALL, REMOVE
from .site import ADD_SITE_DATABASE

KINDS = (INSTALL, REMOVE, ADD_SITE_DATABASE)


def _sentence(outcome: Result, reason: str) -> str:
    return engine.reason_text(outcome.value, reason)


class DatabaseEngineReasonTests(SimpleTestCase):
    def test_the_engine_step_and_the_reload_step_read_distinctly(self) -> None:
        engine_step = _sentence(Result.PARTIAL, "database_engine")
        reload_step = _sentence(Result.PARTIAL, "database_reload")

        self.assertNotEqual(engine_step, reload_step)
        self.assertIn("engine", engine_step.lower())
        self.assertIn("restart every running PHP master and site proxy", reload_step)
        self.assertNotIn("without reporting how far it got", engine_step)

    def test_an_engine_refusal_still_reads_as_the_reviewed_package_set(self) -> None:
        sentence = _sentence(Result.REFUSED, "database_engine")

        self.assertIn("package set differs from the reviewed one", sentence)
        self.assertIn("before changing packages", sentence)


class SiteDatabaseReasonTests(SimpleTestCase):
    def test_each_stopped_step_names_the_step_it_reached(self) -> None:
        for reason, step in (
            ("site_database_principal", "principal"),
            ("site_database_database", "database"),
            ("site_database_privileges", "privileges"),
            ("site_database_schema", "schema"),
            ("site_database_after", "proof"),
            ("site_database_proof", "proof"),
            ("site_database_probe", "probe"),
        ):
            with self.subTest(reason=reason):
                sentence = _sentence(Result.PARTIAL, reason)
                self.assertIn(step, sentence.lower())
                self.assertNotIn("without reporting how far it got", sentence)

    def test_a_binding_refused_before_any_statement_names_the_principal(self) -> None:
        sentence = _sentence(Result.REFUSED, "site_database_driver")

        self.assertIn("PHP master", sentence)
        self.assertIn("before creating the binding", sentence)


class DatabaseVocabularyTests(SimpleTestCase):
    def test_every_declared_database_pair_has_its_own_sentence(self) -> None:
        assert_declared_sentences(self, tuple(kind.reasons for kind in KINDS))

    def test_every_database_body_declares_what_it_prints(self) -> None:
        self.assertEqual(reasons.manifest_errors(), [])
