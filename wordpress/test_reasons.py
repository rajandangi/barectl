"""The WordPress vocabulary reads on the run screens (#495, #504).

Every assertion observes the sentence an operator sees for a reason a WordPress body prints,
not the shape of the declaration.
"""

from django.test import SimpleTestCase

from operations import engine, reasons
from operations.models import Result
from operations.reason_testing import assert_declared_sentences

from .bodies.reasons import (
    ACTION_REASONS,
    CREATE_REASONS,
    SETTINGS_REASONS,
)

_DECLARATIONS = (CREATE_REASONS, ACTION_REASONS, SETTINGS_REASONS)


class WordPressReasonTests(SimpleTestCase):
    def test_every_declared_pair_has_its_own_sentence(self) -> None:
        assert_declared_sentences(self, _DECLARATIONS)

    def test_creating_a_wordpress_site_that_stops_names_the_database_gate_publish_or_create(
        self,
    ) -> None:
        cases = (
            ("refused", "site_database", "database"),
            ("refused", "site_database_driver", "driver"),
            ("refused", "wordpress_gate", "maintenance gate"),
            ("partial", "wordpress_gate", "partly created"),
            ("partial", "wordpress_publish", "verified site route"),
            ("partial", "wordpress_create", "WordPress installation"),
            ("refused", "wordpress_secret", "confidential"),
        )
        for outcome, reason, words in cases:
            with self.subTest(reason=reason):
                sentence = engine.reason_text(outcome, reason)
                self.assertIn(words, sentence)
                self.assertNotEqual(sentence, reasons.OUTCOME_SENTENCES[Result(outcome)])

    def test_a_password_reset_or_core_verification_names_its_cause_distinctly(self) -> None:
        cases = (
            ("refused", "wordpress_password", "no user with that login"),
            ("partial", "wordpress_password_unverified", "could not confirm"),
            ("refused", "wordpress_checksums", "do not match"),
            ("refused", "wordpress_checksums_unavailable", "checksum service"),
        )
        sentences = set()
        for outcome, reason, words in cases:
            with self.subTest(reason=reason):
                sentence = engine.reason_text(outcome, reason)
                self.assertIn(words, sentence)
                self.assertNotEqual(sentence, reasons.OUTCOME_SENTENCES[Result(outcome)])
                sentences.add(sentence)
        self.assertEqual(len(sentences), len(cases))

    def test_editing_wordpress_settings_that_stops_names_the_configuration_step(self) -> None:
        sentence = engine.reason_text("partial", "wordpress_settings")

        self.assertIn("partly applied", sentence)
        self.assertNotIn("nothing changed", sentence.lower())
        self.assertNotEqual(sentence, reasons.OUTCOME_SENTENCES[Result.PARTIAL])

    def test_a_wordpress_change_refused_by_its_fence_shows_the_fence_sentence(self) -> None:
        sentence = engine.reason_text("refused", "automation_fence")

        self.assertIn("background work did not stop", sentence)
        self.assertIn("stays paused", sentence)

    def test_no_partial_sentence_claims_nothing_changed(self) -> None:
        for declared in _DECLARATIONS:
            for reason in declared:
                if Result.PARTIAL in reason.outcomes:
                    with self.subTest(reason=reason.name):
                        self.assertNotIn("nothing changed", reason.sentence(Result.PARTIAL).lower())

    def test_a_password_reset_result_line_reads_as_its_cause(self) -> None:
        line = engine.parse_result_line(
            'barectl-result {"class":"partial","reason":"wordpress_password_unverified",'
            '"change_kind":"reset_wordpress_password"}'
        )

        self.assertIsNotNone(line)
        assert line is not None  # noqa: S101 - narrows the optional for mypy
        self.assertEqual(line.reason, "wordpress_password_unverified")
        self.assertEqual(
            engine.reason_text(line.result_class, line.reason),
            engine.reason_text("partial", "wordpress_password_unverified"),
        )
