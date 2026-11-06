"""The one result-reason vocabulary (#495).

These tests observe what an operator observes: a reason a body prints, read through the
parser, and the sentence the screen shows for it. They do not assert the shape of the
vocabulary data structure beyond the registration contract the engine needs.
"""

from django.test import SimpleTestCase

from . import engine, reasons
from .models import Result


def _kind(slug: str, *declared: reasons.ResultReason) -> engine.ChangeKind:
    return engine.ChangeKind(
        slug=slug,
        label=slug,
        inspect=lambda shell, inputs: None,
        review=lambda evidence, inputs: engine.ReviewDraft(slug, ""),
        body=lambda document, context: engine.NativeBody(b"exit 0"),
        verify=lambda shell, review: True,
        reasons=declared,
    )


class ResultReasonRegistrationTests(SimpleTestCase):
    def test_the_sentence_is_retrievable_by_reason_and_outcome_alone(self) -> None:
        engine.register_kind(
            _kind(
                "test_reason_retrieval",
                reasons.ResultReason(
                    "test_reason_retrieval",
                    {
                        Result.REFUSED: "The test refused before changing anything.",
                        Result.PARTIAL: "The test stopped after changing the server.",
                    },
                ),
            )
        )

        self.assertEqual(
            engine.reason_text("refused", "test_reason_retrieval"),
            "The test refused before changing anything.",
        )
        self.assertEqual(
            engine.reason_text("partial", "test_reason_retrieval"),
            "The test stopped after changing the server.",
        )

    def test_one_reason_can_read_differently_in_each_outcome(self) -> None:
        engine.register_kind(
            _kind(
                "test_reason_lock",
                reasons.ResultReason(
                    "test_reason_lock",
                    {
                        Result.REFUSED: "The test lock was unsafe.",
                        Result.LOCK_BUSY: "Another test held the lock.",
                    },
                ),
            )
        )

        self.assertEqual(
            engine.reason_text("refused", "test_reason_lock"), "The test lock was unsafe."
        )
        self.assertEqual(
            engine.reason_text("lock_busy", "test_reason_lock"),
            "Another test held the lock.",
        )

    def test_a_conflicting_sentence_fails_registration_naming_the_reason(self) -> None:
        reason = "test_reason_conflict"
        engine.register_kind(
            _kind(reason, reasons.ResultReason(reason, {Result.REFUSED: "First wording."}))
        )

        with self.assertRaisesMessage(ValueError, reason):
            engine.register_kind(
                _kind(reason, reasons.ResultReason(reason, {Result.REFUSED: "Second wording."}))
            )

    def test_the_same_wording_may_be_declared_twice(self) -> None:
        reason = "test_reason_shared"
        for slug in ("test_reason_shared_a", "test_reason_shared_b"):
            engine.register_kind(
                _kind(slug, reasons.ResultReason(reason, {Result.REFUSED: "Shared wording."}))
            )

        self.assertEqual(engine.reason_text("refused", reason), "Shared wording.")

    def test_every_reason_accepted_before_the_change_is_still_accepted(self) -> None:
        for reason in reasons.LEGACY_REASONS:
            with self.subTest(reason=reason):
                self.assertTrue(reasons.accepted(reason))

    def test_an_invented_reason_is_still_unreadable_evidence(self) -> None:
        self.assertFalse(reasons.accepted("invented_reason"))
        self.assertTrue(reasons.accepted(""))  # an outcome may report no reason at all


class AdmissionVocabularyTests(SimpleTestCase):
    def test_admission_reasons_are_declared_once(self) -> None:
        names = [reason.name for reason in reasons.ADMISSION]
        self.assertEqual(len(names), len(set(names)))

    def test_a_kind_with_no_reasons_of_its_own_inherits_admission(self) -> None:
        engine.register_kind(_kind("test_reason_admission_only"))

        for reason in reasons.ADMISSION:
            self.assertTrue(reasons.accepted(reason.name))
            self.assertTrue(engine.reason_text("refused", reason.name))
