"""PHP selection is reconstructed at the RemoteShell boundary."""

from django.test import SimpleTestCase

from discovery.fakes import FakeServer
from discovery.ssh import CommandResult

from . import runtime_native, runtime_services


class RuntimeObservationTests(SimpleTestCase):
    def test_unreadable_native_default_has_no_cached_or_implied_selection(self) -> None:
        shell = FakeServer()
        shell.results[runtime_native.READ] = CommandResult(0, '{"default":"8.5"}')
        observed = runtime_services.observe_php_runtime(shell)
        self.assertIsNone(observed.default)
        self.assertIsNone(observed.supply)
        self.assertTrue(observed.failure)

    def test_failed_or_truncated_read_never_probes_a_fallback(self) -> None:
        for result in (CommandResult(1, ""), CommandResult(0, "{}", truncated=True)):
            with self.subTest(result=result):
                shell = FakeServer()
                shell.results[runtime_native.READ] = result
                observed = runtime_services.observe_php_runtime(shell)
                self.assertTrue(observed.failure)
                self.assertIsNone(observed.default)
                self.assertIsNone(observed.supply)
                self.assertEqual(shell.commands, [runtime_native.READ])
