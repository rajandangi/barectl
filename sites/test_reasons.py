"""The shared site vocabulary reads on the run screens (#495, #499).

Every assertion observes the sentence an operator sees for a reason the server printed,
not the shape of the declaration.
"""

from pathlib import Path

from django.test import SimpleTestCase

from operations import engine, reasons
from operations.models import Result

from .bodies.reasons import REMOVAL_REASONS, SITE_REASONS


class SharedSiteReasonTests(SimpleTestCase):
    def test_every_declared_pair_has_a_sentence(self) -> None:
        for reason in SITE_REASONS:
            for outcome in reason.outcomes:
                with self.subTest(reason=reason.name, outcome=outcome.value):
                    self.assertEqual(
                        engine.reason_text(outcome.value, reason.name),
                        reason.sentence(outcome),
                    )

    def test_a_domains_change_that_stops_partway_names_the_domains_step(self) -> None:
        sentence = engine.reason_text("partial", "site_domains")

        self.assertIn("domains change stopped after publishing", sentence)
        self.assertNotIn("without reporting how far it got", sentence)

    def test_a_domains_change_refused_before_publishing_says_nothing_was_published(self) -> None:
        sentence = engine.reason_text("refused", "site_domains")

        self.assertIn("nothing was published", sentence)

    def test_a_pool_change_that_stops_partway_names_the_pool_step(self) -> None:
        sentence = engine.reason_text("partial", "site_pool")

        self.assertIn("restored the previous pool", sentence)
        self.assertNotIn("without reporting how far it got", sentence)

    def test_a_php_change_refused_for_its_precondition_names_it(self) -> None:
        sentence = engine.reason_text("refused", "precondition")

        self.assertIn("native evidence changed", sentence)
        self.assertNotIn("The run stopped before changing anything.", sentence)

    def test_a_node_change_refused_for_its_precondition_names_it(self) -> None:
        sentence = engine.reason_text("refused", "precondition")

        self.assertIn("native evidence changed", sentence)
        self.assertTrue(reasons.accepted("precondition"))

    def test_readiness_that_publishes_then_fails_reads_differently_from_one_that_cannot(
        self,
    ) -> None:
        published = engine.reason_text("partial", "site_readiness")
        cannot_publish = engine.reason_text("refused", "readiness_publish")

        self.assertNotEqual(published, cannot_publish)
        self.assertIn("did not answer its readiness path", published)
        self.assertIn("previous Caddy file is still serving", cannot_publish)

    def test_a_site_change_refused_by_its_fence_shows_the_fence_sentence(self) -> None:
        sentence = engine.reason_text("refused", "automation_fence")

        self.assertIn("background work did not stop", sentence)
        self.assertIn("stays paused", sentence)

    def test_creating_a_site_that_stops_partway_names_the_create_or_caddy_step(self) -> None:
        for reason, words in (
            ("site_create", "partly created"),
            ("site_caddy", "Caddy route"),
        ):
            with self.subTest(reason=reason):
                sentence = engine.reason_text("partial", reason)
                self.assertIn(words, sentence)
                self.assertNotIn("without reporting how far it got", sentence)

    def test_a_pool_refusal_that_used_to_be_swallowed_is_accepted(self) -> None:
        line = engine.parse_result_line(
            'barectl-result {"class":"refused","reason":"site_pool","change_kind":"set_site_pool"}'
        )

        self.assertIsNotNone(line)
        assert line is not None  # noqa: S101 - assertIsNotNone does not narrow for mypy
        self.assertEqual(line.reason, "site_pool")

    def test_every_shared_site_reason_is_accepted(self) -> None:
        for reason in SITE_REASONS:
            with self.subTest(reason=reason.name):
                self.assertTrue(reasons.accepted(reason.name))

    def test_the_shared_declaration_can_be_paired_with_a_partial_outcome(self) -> None:
        self.assertEqual(
            engine.reason_text("partial", "automation_restore"),
            next(reason for reason in SITE_REASONS if reason.name == "automation_restore").sentence(
                Result.PARTIAL
            ),
        )


class RemovalReasonTests(SimpleTestCase):
    """A site removal names the step that stopped (#500)."""

    def test_every_removal_reason_has_a_sentence_for_every_outcome(self) -> None:
        for reason in REMOVAL_REASONS:
            for outcome in reason.outcomes:
                with self.subTest(reason=reason.name, outcome=outcome.value):
                    self.assertEqual(
                        engine.reason_text(outcome.value, reason.name),
                        reason.sentence(outcome),
                    )

    def test_every_reason_the_removal_body_prints_is_accepted(self) -> None:
        body = Path("sites/bodies/remove.py").read_text()
        printed = set(reasons.printed_pairs(body))
        # The helper steps return their reason to the sequence that prints it, so the
        # literal is not visible to the parser's pair scan.
        printed.update(
            {
                "site_remove_database",
                "site_remove_certificate",
                "site_remove_accounts",
                "site_remove_verify",
            }
        )
        for reason in printed:
            with self.subTest(reason=reason):
                self.assertTrue(reasons.accepted(reason))

    def test_a_removal_that_stops_before_dropping_the_database_names_the_database_step(
        self,
    ) -> None:
        sentence = engine.reason_text("partial", "site_remove_database")

        self.assertIn("database", sentence)
        self.assertNotIn("without reporting how far it got", sentence)

    def test_a_removal_that_stops_while_removing_the_certificate_names_the_certificate_step(
        self,
    ) -> None:
        sentence = engine.reason_text("partial", "site_remove_certificate")

        self.assertIn("certificate", sentence)
        self.assertNotIn("without reporting how far it got", sentence)

    def test_a_removal_that_stops_while_removing_accounts_names_the_accounts_step(self) -> None:
        sentence = engine.reason_text("partial", "site_remove_accounts")

        self.assertIn("accounts", sentence)
        self.assertNotIn("without reporting how far it got", sentence)

    def test_a_removal_that_stops_at_final_verification_names_verification(self) -> None:
        sentence = engine.reason_text("partial", "site_remove_verify")

        self.assertIn("verification", sentence.lower())
        self.assertNotEqual(sentence, reasons.OUTCOME_SENTENCES[Result.PARTIAL])

    def test_a_removal_refused_before_changing_anything_names_the_precondition(self) -> None:
        sentence = engine.reason_text("refused", "precondition")

        self.assertIn("native evidence changed", sentence)
        self.assertNotEqual(sentence, reasons.OUTCOME_SENTENCES[Result.REFUSED])

    def test_a_removal_refused_before_removing_the_caddy_route_names_that_step(self) -> None:
        sentence = engine.reason_text("refused", "site_remove_caddy")

        self.assertIn("Caddy", sentence)
        self.assertNotEqual(sentence, reasons.OUTCOME_SENTENCES[Result.REFUSED])

    def test_no_removal_reason_falls_back_to_the_class_sentence(self) -> None:
        for reason in REMOVAL_REASONS:
            for outcome in reason.outcomes:
                with self.subTest(reason=reason.name, outcome=outcome.value):
                    self.assertNotEqual(
                        engine.reason_text(outcome.value, reason.name),
                        reasons.OUTCOME_SENTENCES[outcome],
                    )

    def test_the_removal_declaration_matches_the_body_it_stages(self) -> None:
        self.assertEqual(reasons.manifest_errors(), [])
