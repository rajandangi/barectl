"""The Laravel vocabulary reads on the run screens (#495, #504).

Every assertion observes the sentence an operator sees for a reason a Laravel body prints,
not the shape of the declaration.
"""

from django.test import SimpleTestCase

from operations import engine, reasons
from operations.models import Result
from operations.reason_testing import assert_declared_sentences

from .bodies.reasons import (
    CREATE_REASONS,
    DEPLOY_REASONS,
    EDIT_REASONS,
    ROLLBACK_REASONS,
)

_DECLARATIONS = (CREATE_REASONS, DEPLOY_REASONS, ROLLBACK_REASONS, EDIT_REASONS)


class LaravelReasonTests(SimpleTestCase):
    def test_every_declared_pair_has_its_own_sentence(self) -> None:
        assert_declared_sentences(self, _DECLARATIONS)

    def test_a_deploy_that_stops_names_the_step_and_not_the_class_sentence(self) -> None:
        cases = (
            ("refused", "laravel_source", "repository or branch"),
            ("refused", "laravel_disk", "free space"),
            ("partial", "laravel_shared", "shared environment"),
            ("refused", "laravel_fetch", "could not be fetched"),
            ("partial", "laravel_composer", "dependencies could not be installed"),
            ("partial", "laravel_release", "release"),
            ("partial", "laravel_migrations", "migration"),
            ("partial", "laravel_readiness", "readiness check"),
        )
        for outcome, reason, words in cases:
            with self.subTest(reason=reason):
                sentence = engine.reason_text(outcome, reason)
                self.assertIn(words, sentence)
                self.assertNotEqual(sentence, reasons.OUTCOME_SENTENCES[Result(outcome)])

    def test_a_rollback_refused_because_the_release_is_absent_has_its_own_sentence(self) -> None:
        sentence = engine.reason_text("refused", "release_absent")

        self.assertIn("no longer retained", sentence)
        self.assertIn("release list", sentence)
        self.assertNotEqual(sentence, reasons.OUTCOME_SENTENCES[Result.REFUSED])

    def test_editing_an_environment_that_stops_names_the_environment_config_or_worker_step(
        self,
    ) -> None:
        cases = (
            ("partial", "laravel_environment", "partly applied"),
            ("partial", "laravel_config", "cached configuration"),
            ("partial", "laravel_worker", "worker"),
        )
        for outcome, reason, words in cases:
            with self.subTest(reason=reason):
                sentence = engine.reason_text(outcome, reason)
                self.assertIn(words, sentence)
                self.assertNotEqual(sentence, reasons.OUTCOME_SENTENCES[Result(outcome)])

    def test_a_laravel_change_refused_by_its_fence_shows_the_fence_sentence(self) -> None:
        sentence = engine.reason_text("refused", "automation_fence")

        self.assertIn("background work did not stop", sentence)
        self.assertIn("stays paused", sentence)

    def test_no_partial_sentence_claims_nothing_changed(self) -> None:
        for declared in _DECLARATIONS:
            for reason in declared:
                if Result.PARTIAL in reason.outcomes:
                    with self.subTest(reason=reason.name):
                        self.assertNotIn("nothing changed", reason.sentence(Result.PARTIAL).lower())

    def test_a_deploy_result_line_reads_as_the_step_sentence(self) -> None:
        line = engine.parse_result_line(
            'barectl-result {"class":"partial","reason":"laravel_composer",'
            '"change_kind":"deploy_laravel_site"}'
        )

        self.assertIsNotNone(line)
        assert line is not None  # noqa: S101 - narrows the optional for mypy
        self.assertEqual(line.reason, "laravel_composer")
        self.assertEqual(
            engine.reason_text(line.result_class, line.reason),
            engine.reason_text("partial", "laravel_composer"),
        )
