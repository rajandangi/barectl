"""The bootstrap bodies' result reasons read on the run screens (#495)."""

from typing import override

from django.test import SimpleTestCase

from bootstrap.bodies.reasons import CERTIFICATE_EMAIL_REASONS, FOUNDATION_REASONS
from operations import engine, reasons
from operations.models import Result


class ReasonAssertions(SimpleTestCase):
    def declared(self) -> tuple[reasons.ResultReason, ...]:
        return ()

    def test_every_declared_reason_has_its_own_sentence(self) -> None:
        for reason in self.declared():
            for outcome in reason.outcomes:
                with self.subTest(reason=reason.name, outcome=outcome.value):
                    sentence = engine.reason_text(outcome.value, reason.name)
                    self.assertEqual(sentence, reason.sentence(outcome))
                    self.assertNotEqual(sentence, reasons.OUTCOME_SENTENCES[outcome])
                    line = engine.parse_result_line(
                        f'barectl-result {{"class":"{outcome.value}","reason":"{reason.name}"}}'
                    )
                    if line is None:
                        self.fail("The result line did not parse.")
                    self.assertEqual(line.reason, reason.name)


class FoundationReasonTests(ReasonAssertions):
    @override
    def declared(self) -> tuple[reasons.ResultReason, ...]:
        return FOUNDATION_REASONS

    def test_host_setup_names_its_own_native_cause(self) -> None:
        expected = {
            ("refused", "download"): "could not download",
            ("refused", "installer_digest"): "SHA-256",
            ("refused", "foreign_stack"): "foreign stack",
            ("refused", "nix_incomplete"): "incomplete",
            ("partial", "foundation"): "partly applied",
        }
        for (outcome, reason), words in expected.items():
            with self.subTest(outcome=outcome, reason=reason):
                sentence = engine.reason_text(outcome, reason)
                self.assertIn(words, sentence)
                self.assertNotIn("without reporting how far it got", sentence)

    def test_host_setup_names_platform_privilege_and_headroom(self) -> None:
        self.assertIn("not Ubuntu 26.04", engine.reason_text("refused", "platform"))
        self.assertIn("not root", engine.reason_text("refused", "privilege"))
        self.assertIn("free space", engine.reason_text("refused", "headroom"))
        for reason in ("platform", "privilege", "headroom"):
            with self.subTest(reason=reason):
                self.assertNotEqual(
                    engine.reason_text("refused", reason), reasons.OUTCOME_SENTENCES[Result.REFUSED]
                )

    def test_a_partial_host_setup_never_claims_nothing_changed(self) -> None:
        sentence = engine.reason_text("partial", "foundation")

        self.assertNotIn("Nothing changed", sentence)
        self.assertIn("no rollback happens", sentence)


class CertificateEmailReasonTests(ReasonAssertions):
    @override
    def declared(self) -> tuple[reasons.ResultReason, ...]:
        return CERTIFICATE_EMAIL_REASONS

    def test_setting_the_email_names_its_precondition_or_its_own_step(self) -> None:
        precondition = engine.reason_text("refused", "precondition")
        refused = engine.reason_text("refused", "certificate_email")
        partial = engine.reason_text("partial", "certificate_email")

        self.assertIn("native evidence changed", precondition)
        self.assertIn("certificate contact email", refused)
        self.assertIn("left as it was", refused)
        self.assertIn("restored", partial)
        self.assertNotIn("without reporting how far it got", refused)
        self.assertNotIn("without reporting how far it got", partial)
