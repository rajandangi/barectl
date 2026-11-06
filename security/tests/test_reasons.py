"""The security bodies' result reasons read on the run screens (#495).

Every assertion observes the sentence an operator sees for a reason the server printed,
and that the result line still parses, not the shape of the declaration.
"""

from typing import override

from django.test import SimpleTestCase

from operations import engine, reasons
from operations.models import Result
from security.bodies.reasons import (
    AUTOMATIC_UPDATES_REASONS,
    CHECK_UPDATES_REASONS,
    FIREWALL_REASONS,
    INSTALL_UPDATES_REASONS,
    RESTART_REASONS,
    SIGN_IN_REASONS,
)


class SecurityReasonAssertions(SimpleTestCase):
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


class FirewallReasonTests(SecurityReasonAssertions):
    @override
    def declared(self) -> tuple[reasons.ResultReason, ...]:
        return FIREWALL_REASONS

    def test_a_firewall_change_names_the_step_that_stopped_it(self) -> None:
        expected = {
            ("refused", "firewall_ports"): "SSH ports",
            ("refused", "firewall_outside"): "outside the supported shape",
            ("refused", "firewall_standard"): "standard web and SSH allowances",
            ("refused", "firewall_package"): "package transaction",
            ("partial", "firewall_apply"): "firewall change stopped partway",
            ("partial", "firewall_verify"): "did not read back",
        }
        for (outcome, reason), words in expected.items():
            with self.subTest(outcome=outcome, reason=reason):
                sentence = engine.reason_text(outcome, reason)
                self.assertIn(words, sentence)
                self.assertNotIn("without reporting how far it got", sentence)

    def test_a_firewall_change_that_stops_partway_never_claims_nothing_changed(self) -> None:
        for reason, outcome in (("firewall_apply", "partial"), ("firewall_verify", "partial")):
            with self.subTest(reason=reason):
                self.assertNotIn("Nothing changed", engine.reason_text(outcome, reason))


class SignInReasonTests(SecurityReasonAssertions):
    @override
    def declared(self) -> tuple[reasons.ResultReason, ...]:
        return SIGN_IN_REASONS

    def test_a_key_only_sign_in_change_names_syntax_apply_reload_or_verify(self) -> None:
        expected = {
            ("refused", "sign_in_syntax"): "OpenSSH rejected",
            ("refused", "sign_in_apply"): "sign-in file",
            ("partial", "sign_in_reload"): "SSH could not reload",
            ("partial", "sign_in_verify"): "effective sign-in settings",
        }
        for (outcome, reason), words in expected.items():
            with self.subTest(outcome=outcome, reason=reason):
                sentence = engine.reason_text(outcome, reason)
                self.assertIn(words, sentence)
                self.assertNotIn("without reporting how far it got", sentence)


class AutomaticUpdatesReasonTests(SecurityReasonAssertions):
    @override
    def declared(self) -> tuple[reasons.ResultReason, ...]:
        return AUTOMATIC_UPDATES_REASONS

    def test_automatic_updates_names_its_own_cause(self) -> None:
        expected = {
            ("refused", "automatic_updates_package"): "package transaction",
            ("partial", "automatic_updates_package"): "did not read back",
            ("partial", "automatic_updates_configure"): "settings were not accepted",
            ("partial", "automatic_updates_verify"): "did not read back as reviewed",
            ("partial", "automatic_updates_settings"): "customized automatic-update settings",
            ("partial", "automatic_updates_failed"): "stopped before reporting",
        }
        for (outcome, reason), words in expected.items():
            with self.subTest(outcome=outcome, reason=reason):
                sentence = engine.reason_text(outcome, reason)
                self.assertIn(words, sentence)
                self.assertNotIn("without reporting how far it got", sentence)

    def test_a_package_that_fails_after_the_change_does_not_claim_before_further_changes(
        self,
    ) -> None:
        sentence = engine.reason_text("partial", "automatic_updates_package")

        self.assertNotIn("before further changes", sentence)
        self.assertNotIn("Nothing changed", sentence)


class CheckUpdatesReasonTests(SecurityReasonAssertions):
    @override
    def declared(self) -> tuple[reasons.ResultReason, ...]:
        return CHECK_UPDATES_REASONS

    def test_a_check_for_updates_names_its_refresh_cause(self) -> None:
        refused = engine.reason_text("refused", "updates_refresh")
        stopped = engine.reason_text("partial", "updates_refresh_failed")

        self.assertIn("package lists were not refreshed", refused)
        self.assertIn("package-list refresh stopped", stopped)
        self.assertNotEqual(refused, reasons.OUTCOME_SENTENCES[Result.REFUSED])
        self.assertNotEqual(stopped, reasons.OUTCOME_SENTENCES[Result.PARTIAL])


class InstallUpdatesReasonTests(SecurityReasonAssertions):
    @override
    def declared(self) -> tuple[reasons.ResultReason, ...]:
        return INSTALL_UPDATES_REASONS

    def test_an_install_update_names_hold_conffile_and_pending_causes(self) -> None:
        held = engine.reason_text("refused", "updates_hold")
        conffile = engine.reason_text("refused", "updates_conffile")
        pending = engine.reason_text("refused", "updates_pending")

        self.assertIn("apt-mark hold", held)
        self.assertIn("configuration file", conffile)
        self.assertIn("unfinished package state", pending)
        for sentence in (held, conffile, pending):
            self.assertNotIn("without reporting how far it got", sentence)

    def test_an_install_update_names_its_transaction_and_verify_causes(self) -> None:
        transaction = engine.reason_text("refused", "updates_transaction")
        verify = engine.reason_text("refused", "updates_verify")
        stopped = engine.reason_text("partial", "updates_failed")

        self.assertIn("resolved package transaction", transaction)
        self.assertIn("did not read back as expected", verify)
        self.assertIn("stopped before reporting", stopped)


class RestartReasonTests(SecurityReasonAssertions):
    @override
    def declared(self) -> tuple[reasons.ResultReason, ...]:
        return RESTART_REASONS

    def test_a_restart_failure_names_work_evidence_or_apply(self) -> None:
        work = engine.reason_text("refused", "restart_work")
        evidence = engine.reason_text("refused", "restart_evidence")
        apply = engine.reason_text("partial", "restart_apply")

        self.assertIn("still had processes", work)
        self.assertIn("packages that asked for a restart changed", evidence)
        self.assertIn("stopped before asking the server to start again", apply)
        for sentence in (work, evidence, apply):
            self.assertNotIn("without reporting how far it got", sentence)
