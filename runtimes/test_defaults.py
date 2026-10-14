from django.test import SimpleTestCase

from bootstrap.standing import Standing
from operations.consent import consent_of
from operations.inputs import PreparationInputs
from operations.models import Consent
from runtimes import defaults
from runtimes.catalog import Architecture


class DefaultReviewTests(SimpleTestCase):
    def test_administrator_command_refuses_a_shared_default_change(self) -> None:
        draft = defaults.review_php(
            defaults.DefaultEvidence(
                Architecture.AARCH64,
                Standing.TARGET_STACK,
                {
                    "boot": "12345678-1234-1234-1234-123456789abc",
                    "uptime": 1000,
                    "digest": "a" * 64,
                    "profiles": {"php84": "/unavailable"},
                    "php": "",
                    "node": "",
                    "php_problem": "The PHP commands are set by the administrator.",
                    "node_problem": "",
                    "helpers": [],
                },
            ),
            PreparationInputs("php84"),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("administrator", " ".join(draft.refusals))
        self.assertEqual(consent_of(draft.effects), Consent.READ)


class DefaultObservationBoundaryTests(SimpleTestCase):
    def test_malformed_choices_and_selections_are_not_saved_as_native_observation(self) -> None:
        observed = defaults.DefaultsObservation(
            "php85", "nodejs_24", php_choices=("php84", "php85"), node_choices=("nodejs_24",)
        )
        valid = {
            "php": "php85",
            "node": "nodejs_24",
            "php_problem": "",
            "node_problem": "",
            "php_choices": ["php84", "php85"],
            "node_choices": ["nodejs_24"],
        }
        self.assertEqual(defaults.decode_observation(valid), observed)
        for mutated in (
            {**valid, "php_choices": ["php84", "php84"]},
            {**valid, "php_choices": [["php84"]]},
            {**valid, "node": "nodejs_99"},
            {**valid, "path": "/unreviewed"},
            {**valid, "php_problem": "x" * 1025},
        ):
            with self.subTest(mutated=mutated):
                self.assertIsNone(defaults.decode_observation(mutated))


class ObservedDefaultReviewTests(SimpleTestCase):
    def test_changed_default_is_shared_and_repeated_default_needs_no_mutation(self) -> None:
        from discovery.recorded import ReplayShell, load

        for selection, consent, unchanged in (
            ("php84", Consent.SHARED, False),
            ("php85", Consent.READ, True),
        ):
            with self.subTest(selection=selection):
                inputs = PreparationInputs(selection)
                evidence = defaults.inspect(ReplayShell(load("runtime-defaults-26.04")), inputs)
                draft = defaults.review_php(evidence, inputs)
                self.assertTrue(draft.eligible, draft.refusals)
                self.assertEqual(consent_of(draft.effects), consent)
                self.assertEqual(draft.no_changes, unchanged)
