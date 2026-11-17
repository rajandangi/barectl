"""Host-standing judgments replayed from the native transcript set."""

import subprocess
from typing import ClassVar
from unittest import TestCase, mock

from bootstrap.standing import Standing
from logs.journal_retention import NOT_CONFIGURED

from . import recorded
from .models import ObservationOutcome
from .observations import collect, standing
from .recorded import ReplayShell
from .ssh import CommandResult, RemoteShell


class NixBinaryProbeTests(TestCase):
    def test_a_missing_nix_binary_does_not_walk_its_parents_over_ssh(self) -> None:
        from .fakes import FakeServer

        shell = FakeServer()
        self.assertEqual(standing._nix_shape(shell), "absent")
        self.assertEqual(len(shell.commands), 9)

    def test_an_unreadable_or_malformed_reply_never_proves_nix_absent(self) -> None:
        from .fakes import FakeServer

        for result in (
            CommandResult(1, "missing\n"),
            CommandResult(0, "missing\n", truncated=True),
            CommandResult(0, "unreadable\n"),
            CommandResult(0, ""),
            CommandResult(0, "invalid\n"),
            CommandResult(0, "missing\npresent\n"),
        ):
            with self.subTest(result=result):
                shell = FakeServer()
                shell.results[standing._NIX_BINARY_COMMAND] = result
                self.assertIsNone(standing._nix_shape(shell))


class PanelBatchTests(TestCase):
    def test_collection_uses_one_panel_read_and_reports_present_paths(self) -> None:
        from .fakes import FakeServer

        shell = FakeServer()
        shell.files["/usr/local/cpanel"] = ""
        judgment = collect(shell, sites=False).standing
        panel_reads = [command for command in shell.commands if command == standing._PANEL_COMMAND]
        self.assertEqual(len(panel_reads), 1)
        if judgment is None:
            self.fail("Collection did not produce host standing.")
        self.assertEqual(dict(judgment.evidence)["Hosting panel paths"], "/usr/local/cpanel")

    def test_failed_or_invalid_batch_keeps_panel_evidence_unknown(self) -> None:
        from .fakes import FakeServer

        valid = "missing\n" * len(standing._PANEL_PATHS)
        for result in (
            CommandResult(1, valid),
            CommandResult(0, valid, truncated=True),
            CommandResult(0, ""),
            CommandResult(0, valid + "missing\n"),
            CommandResult(0, "missing\n" * (len(standing._PANEL_PATHS) - 1)),
            CommandResult(0, valid.replace("missing", "invalid", 1)),
        ):
            with self.subTest(result=result):
                shell = FakeServer()
                shell.results[standing._PANEL_COMMAND] = result
                judgment = collect(shell, sites=False).standing
                if judgment is None:
                    self.fail("Collection did not produce host standing.")
                self.assertEqual(
                    dict(judgment.evidence)["Hosting panel paths"], "Could not be read"
                )

    def test_valid_mixed_reply_retains_present_missing_and_hidden_meanings(self) -> None:
        from .fakes import FakeServer

        shell = FakeServer()
        shell.files["/usr/local/cpanel"] = ""
        shell.files["/www/server"] = ""
        shell.unsearchable.add("/www")
        judgment = collect(shell, sites=False).standing
        if judgment is None:
            self.fail("Collection did not produce host standing.")
        self.assertEqual(dict(judgment.evidence)["Hosting panel paths"], "/usr/local/cpanel")
        self.assertIn("Hosting panel paths are present: /usr/local/cpanel.", judgment.reasons)
        self.assertEqual(sum(command == standing._PANEL_COMMAND for command in shell.commands), 1)

    def test_hidden_panel_path_does_not_prove_panels_absent(self) -> None:
        from .fakes import FakeServer

        shell = FakeServer()
        shell.files["/www/server"] = ""
        shell.unsearchable.add("/www")
        judgment = collect(shell, sites=False).standing
        if judgment is None:
            self.fail("Collection did not produce host standing.")
        self.assertEqual(dict(judgment.evidence)["Hosting panel paths"], "Could not be read")
        self.assertIn("Hosting panel paths could not be inspected.", judgment.reasons)


class RequiredToolsTests(TestCase):
    def test_the_fixed_shell_read_preserves_lookup_classifications(self) -> None:
        script = (
            """
command() {
    case "$2" in
        apt-get) printf /usr/bin/apt-get; return 0;;
        dpkg-query) printf ' \\t\\n'; return 0;;
        df) return 127;;
        systemctl) return 126;;
        *) return 1;;
    esac
}
"""
            + standing._TOOLS_COMMAND
        )
        completed = subprocess.run(  # noqa: S603 - the fixed read and test-only shell function.
            ["/bin/sh", "-c", script], check=True, capture_output=True, text=True
        )
        shell = mock.Mock(spec=RemoteShell)
        shell.run.return_value = CommandResult(completed.returncode, completed.stdout)
        self.assertEqual(
            standing._required_tools(shell),
            tuple(
                zip(
                    standing._TOOLS,
                    (True, False, False, *(None for _ in standing._TOOLS[3:])),
                    strict=True,
                )
            ),
        )
        shell.run.assert_called_once_with(standing._TOOLS_COMMAND)

    def test_an_incomplete_or_unreadable_batch_never_confirms_tools(self) -> None:
        shell = mock.Mock(spec=RemoteShell)
        valid = "present\n" * len(standing._TOOLS)
        for result in (
            CommandResult(1, valid),
            CommandResult(0, valid, truncated=True),
            CommandResult(0, ""),
            CommandResult(0, "present\n" * (len(standing._TOOLS) - 1)),
            CommandResult(0, valid + "present\n"),
            CommandResult(0, valid.replace("present", "invalid", 1)),
        ):
            with self.subTest(result=result):
                shell.run.return_value = result
                self.assertEqual(
                    standing._required_tools(shell), tuple((tool, None) for tool in standing._TOOLS)
                )


class RecordedHostStandingTests(TestCase):
    cases: ClassVar[dict[str, tuple[Standing, tuple[str, ...]]]] = {
        "pristine-26.04": (Standing.FRESH, ()),
        "foundation-26.04": (Standing.TARGET_STACK, ()),
        "http-site-26.04": (Standing.TARGET_STACK, ()),
        "runtime-defaults-26.04": (Standing.TARGET_STACK, ()),
        "site-node-26.04": (Standing.TARGET_STACK, ()),
        "site-node-interrupted-26.04": (Standing.TARGET_STACK, ()),
        "http-site-unsafe-master-26.04": (Standing.TARGET_STACK, ()),
        "reconstruction-26.04": (Standing.TARGET_STACK, ()),
        "jobs-changes-26.04": (Standing.TARGET_STACK, ()),
        "judge-by-shape-26.04": (Standing.TARGET_STACK, ()),
        "race-lock-busy-26.04": (Standing.TARGET_STACK, ()),
        "unknown-runtime-26.04": (Standing.TARGET_STACK, ()),
        "runtime-protection-fault-26.04": (Standing.TARGET_STACK, ()),
        "site-database-26.04": (Standing.TARGET_STACK, ()),
        "laravel-create-26.04": (Standing.TARGET_STACK, ()),
        "automation-wordpress-26.04": (Standing.TARGET_STACK, ()),
        "automation-laravel-26.04": (Standing.TARGET_STACK, ()),
        "automation-laravel-workers-26.04": (Standing.TARGET_STACK, ()),
        "fence-wordpress-26.04": (Standing.TARGET_STACK, ()),
        "valkey-installed-26.04": (Standing.TARGET_STACK, ()),
        "object-cache-26.04": (Standing.TARGET_STACK, ()),
        "object-cache-laravel-26.04": (Standing.TARGET_STACK, ()),
        "object-cache-edited-26.04": (Standing.TARGET_STACK, ()),
        "nginx-26.04": (Standing.NOT_MANAGEABLE, ("Nginx packages",)),
        "apache-26.04": (Standing.NOT_MANAGEABLE, ("Apache packages",)),
        "apt-php-26.04": (Standing.NOT_MANAGEABLE, ("APT PHP packages",)),
        "earlier-barectl-26.04": (
            Standing.NOT_MANAGEABLE,
            ("Earlier Barectl layouts are not managed.",),
        ),
        "ubuntu-24.04": (
            Standing.NOT_MANAGEABLE,
            ("Ubuntu 24.04 is outside supported settings.",),
        ),
        "nix-build-user-collision-26.04": (
            Standing.NOT_MANAGEABLE,
            ("The Nix build-user ID range is occupied or could not be checked.",),
        ),
        "partial-nix-26.04": (
            Standing.NOT_MANAGEABLE,
            ("Nix installation incomplete.",),
        ),
        "apt-daily-active-26.04": (
            Standing.NOT_MANAGEABLE,
            ("APT background package activity",),
        ),
        "security-checks-26.04": (Standing.TARGET_STACK, ()),
    }

    def test_each_native_host_transcript_has_the_expected_judgment(self) -> None:
        self.assertEqual(set(recorded.stored()), set(self.cases))
        for state, (expected_standing, reason_fragments) in self.cases.items():
            with self.subTest(state=state):
                snapshot = collect(ReplayShell(recorded.load(state)))
                standing = snapshot.standing
                self.assertIsNotNone(standing)
                if standing is None:
                    self.fail(f"The transcript of {state} did not produce host standing.")
                self.assertEqual(standing.standing, expected_standing)
                if expected_standing == Standing.TARGET_STACK:
                    # Every recorded foundation has no certificate contact email line.
                    self.assertEqual(snapshot.certificate_email_state, "absent")
                    self.assertEqual(snapshot.certificate_email, "")
                    # Its one foundation read found no retention drop-in.
                    self.assertIsNotNone(snapshot.journal_retention)
                    if snapshot.journal_retention is not None:
                        self.assertEqual(snapshot.journal_retention.state, NOT_CONFIGURED)
                else:
                    self.assertEqual(snapshot.certificate_email_state, "")
                for fragment in reason_fragments:
                    self.assertTrue(
                        any(fragment in reason for reason in standing.reasons),
                        standing.reasons,
                    )

    def test_a_foreign_web_stack_is_judged_without_reading_its_sites(self) -> None:
        shell = ReplayShell(recorded.load("nginx-26.04"))
        snapshot = collect(shell)
        self.assertEqual(snapshot.sites.outcome, ObservationOutcome.ABSENT)
        self.assertEqual(snapshot.sites.value, ())
        self.assertFalse([command for command in shell.commands if "/etc/nginx" in command])

    def test_a_target_stack_collection_issues_one_foundation_read(self) -> None:
        shell = ReplayShell(recorded.load("foundation-26.04"))
        snapshot = collect(shell)
        reads = [command for command in shell.commands if "journal_retention_file" in command]
        self.assertEqual(len(reads), 1)
        self.assertIsNotNone(snapshot.journal_retention)

    def test_required_tool_checks_use_one_bounded_remote_read(self) -> None:
        shell = ReplayShell(recorded.load("foundation-26.04"))
        snapshot = collect(shell)
        self.assertEqual(
            snapshot.standing.standing if snapshot.standing else None, Standing.TARGET_STACK
        )
        self.assertEqual(sum("command -v" in command for command in shell.commands), 1)

    def test_an_unread_foundation_is_not_checked_rather_than_not_configured(self) -> None:
        snapshot = collect(ReplayShell(recorded.load("pristine-26.04")))
        self.assertIsNone(snapshot.journal_retention)
