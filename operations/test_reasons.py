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

    def test_every_retired_reason_is_still_recognized(self) -> None:
        for reason in reasons.RETIRED_REASONS:
            with self.subTest(reason=reason.name):
                self.assertTrue(reasons.accepted(reason.name))
                self.assertEqual(
                    engine.reason_text("partial", reason.name),
                    reason.sentence(Result.PARTIAL),
                )

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
            self.assertEqual(
                engine.reason_text("refused", reason.name), reason.sentence(Result.REFUSED)
            )

    def test_a_running_backup_refusal_shows_its_own_sentence(self) -> None:
        sentence = engine.reason_text("refused", "active_backup")

        self.assertIn("scheduled backup still had processes", sentence)
        self.assertNotIn("without reporting how far it got", sentence)


class ComposerManifestTests(SimpleTestCase):
    def test_every_declared_vocabulary_matches_its_composed_text(self) -> None:
        self.assertEqual(reasons.manifest_errors(), [])


class RetiredVocabularyTests(SimpleTestCase):
    def test_a_retired_reason_parses_and_shows_the_outcome_sentence(self) -> None:
        for reason in reasons.RETIRED_REASONS:
            with self.subTest(reason=reason.name):
                line = engine.parse_result_line(
                    'barectl-result {"class":"partial","reason":"' + reason.name + '"}'
                )
                self.assertIsNotNone(line)
                if line is None:
                    self.fail(f"Retired reason {reason.name!r} did not parse.")
                self.assertEqual(line.reason, reason.name)
                self.assertEqual(
                    engine.reason_text("partial", reason.name),
                    reason.sentence(Result.PARTIAL),
                )

    def test_no_registered_kind_declares_a_retired_reason(self) -> None:
        for slug, declared in reasons._KIND_REASONS.items():
            for reason in declared:
                with self.subTest(kind=slug, reason=reason.name):
                    self.assertNotIn(reason.name, reasons.RETIRED)


class ManifestTests(SimpleTestCase):
    def _source(self, text: str, name: str = "body.txt") -> str:
        import tempfile
        from pathlib import Path
        from unittest import mock

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        (Path(directory.name) / name).write_text(text)
        patcher = mock.patch.object(reasons, "REPOSITORY", Path(directory.name))
        patcher.start()
        self.addCleanup(patcher.stop)
        return name

    def test_the_real_manifest_is_empty(self) -> None:
        self.assertEqual(reasons.manifest_errors(), [])

    def test_it_fails_when_a_body_prints_an_undeclared_reason(self) -> None:
        source = self._source('result("refused", "undeclared_reason")\n')

        errors = reasons._vocabulary_errors("test", (), (source,))

        self.assertTrue(any(source in error and "undeclared_reason" in error for error in errors))

    def test_every_known_result_helper_shape_is_scanned(self) -> None:
        cases = (
            ('result("partial", "one")\n', "one", "partial"),
            ('_fail("refused", "two")\n', "two", "refused"),
            ('report("partial", "three")\n', "three", "partial"),
            ('refused("four")\n', "four", "refused"),
            ('failed("five")\n', "five", "failed"),
            ('partial("six")\n', "six", "partial"),
            ('document_result(document, "failed", "seven", point="")\n', "seven", "failed"),
            ('emit_result({"class": "refused", "reason": "eight"})\n', "eight", "refused"),
            ("refused nine\n", "nine", "refused"),
            ("partial ten\n", "ten", "partial"),
            ('ExportRefused("eleven")\n', "eleven", "refused"),
        )
        for text, reason, result_class in cases:
            with self.subTest(text=text):
                self.assertIn(result_class, reasons.printed_pairs(text).get(reason, set()))

    def test_an_undeclared_reason_is_caught_in_every_helper_shape(self) -> None:
        bodies = (
            'result("refused", "undeclared_reason")\n',
            '_fail("refused", "undeclared_reason")\n',
            'report("refused", "undeclared_reason")\n',
            'document_result(document, "refused", "undeclared_reason", point="")\n',
            "refused undeclared_reason\n",
        )
        for body in bodies:
            with self.subTest(body=body):
                source = self._source(body)
                errors = reasons._vocabulary_errors("test", (), (source,))
                self.assertTrue(
                    any(source in error and "undeclared_reason" in error for error in errors)
                )

    def test_it_fails_when_a_declaration_cannot_be_printed(self) -> None:
        source = self._source("print('nothing here')\n")
        declared = (reasons.ResultReason("declared_but_absent", {Result.REFUSED: "Refused."}),)

        errors = reasons._vocabulary_errors("test", declared, (source,))

        self.assertTrue(
            any("declared_but_absent" in error and "cannot print" in error for error in errors)
        )

    def test_it_fails_when_a_reason_is_paired_with_an_undeclared_outcome(self) -> None:
        source = self._source('result("partial", "partial_only")\n')
        declared = (reasons.ResultReason("partial_only", {Result.REFUSED: "Refused."}),)

        errors = reasons._vocabulary_errors("test", declared, (source,))

        self.assertTrue(any("partial_only" in error and "partial" in error for error in errors))

    def test_a_retired_reason_cannot_be_produced_fresh(self) -> None:
        retired = reasons.RETIRED_REASONS[0]
        source = self._source(f'result("refused", "{retired.name}")\n')

        errors = reasons._vocabulary_errors("test", (), (source,))

        self.assertTrue(any("retired" in error and retired.name in error for error in errors))

    def test_a_declared_pair_must_have_a_sentence(self) -> None:
        with self.assertRaises(ValueError):
            reasons.ResultReason("empty_sentence", {Result.REFUSED: " "})
