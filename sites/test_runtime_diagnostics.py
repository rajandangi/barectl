"""Native switch failures retain fixed phases without exposing original process contents."""

from django.test import SimpleTestCase

from .runtime_native_testing import CANARY, run_switch


class SwitchDiagnosticsTests(SimpleTestCase):
    def test_a_configuration_failure_keeps_the_original_process_exit(self) -> None:
        result = run_switch("fpm-check-error")
        self.assertEqual(result.status, 41)
        self.assertIn("phase=target-fpm-check exception=ValueError exit=78", result.output)
        self.assertNotIn(CANARY, result.output)

    def test_restoration_metadata_cannot_inherit_the_failed_target_probe(self) -> None:
        result = run_switch("restore-read-error")
        self.assertEqual(result.status, 40)
        restored = next(line for line in result.output.splitlines() if "diagnostic restore" in line)
        self.assertIn("phase=restore-target-pool-removal exception=OSError", restored)
        self.assertNotIn("exit=60", restored)
        self.assertNotIn("probe", restored)
        self.assertNotIn(CANARY, result.output)

    def test_both_original_and_recovery_tls_failures_keep_the_partial_guard(self) -> None:
        result = run_switch("both-tls-errors")
        self.assertEqual(result.status, 40)
        self.assertIn("apply phase=target-serving", result.output)
        self.assertIn("restore phase=restored-serving", result.output)
        self.assertIn("exit=60", result.output)
        self.assertNotIn(CANARY, result.output)
        self.assertTrue(all(len(line.encode()) <= 1024 for line in result.output.splitlines()))

    def test_an_identity_mismatch_restores_and_never_discloses_the_body(self) -> None:
        result = run_switch("identity-error")
        self.assertEqual(result.status, 41)
        self.assertIn("identity=false", result.output)
        self.assertNotIn(CANARY, result.output)

    def test_untrusted_http_output_is_only_an_invalid_status_tag(self) -> None:
        result = run_switch("invalid-http")
        self.assertEqual(result.status, 41)
        self.assertIn("http=invalid", result.output)
        self.assertNotIn(CANARY, result.output)

    def test_a_native_exception_discloses_only_its_class_and_phase(self) -> None:
        result = run_switch("publication-error")
        self.assertEqual(result.status, 41)
        self.assertIn("phase=router-publication exception=OSError", result.output)
        self.assertNotIn(CANARY, result.output)

    def test_success_has_no_failure_diagnostics_or_changed_process_limits(self) -> None:
        result = run_switch("success")
        self.assertEqual(result.status, 0)
        self.assertEqual(result.output, "PHP pool and router switched.\n")
        for argv, options in result.calls:
            self.assertEqual(options["stdin"], -3)
            self.assertTrue(options["capture_output"])
            self.assertEqual(
                options["timeout"],
                2 if "/probe-" in argv[-1] else 12 if argv[0] == "/usr/bin/curl" else 30,
            )
