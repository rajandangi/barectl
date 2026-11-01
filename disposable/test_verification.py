"""Controller runner evidence and process lifecycle, without a native server."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from .verification import BUILD_GATES, aggregate, follow, input_revision, record


class VerificationRunnerTests(SimpleTestCase):
    def test_foreground_failure_retains_full_trace_and_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "failure.log"
            result = subprocess.run(  # noqa: S603 - fixed test module and controlled argv
                [
                    sys.executable,
                    "-m",
                    "disposable.verification",
                    "run",
                    str(log),
                    "--",
                    sys.executable,
                    "-c",
                    (
                        "print('FAIL: original_test'); print('AssertionError: original'); "
                        "print('tail\\n' * 100); raise SystemExit(7)"
                    ),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 7)
            self.assertIn("FAIL: original_test", result.stdout)
            self.assertIn("AssertionError: original", log.read_text())
            evidence = json.loads(log.with_suffix(".log.json").read_text())
            self.assertEqual(evidence["exit_status"], 7)
            self.assertEqual(evidence["result"], "failed")
            self.assertEqual(evidence["log"], str(log.resolve()))
            self.assertEqual(evidence["command"], [sys.executable])
            self.assertTrue(evidence["command_redacted"])
            self.assertNotIn("original_test", log.with_suffix(".log.json").read_text())
            self.assertEqual(len(evidence["command_sha256"]), 64)

    def test_bounded_wait_does_not_stop_the_foreground_job(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "held.log"
            process = subprocess.Popen(  # noqa: S603 - controlled test command
                [
                    sys.executable,
                    "-m",
                    "disposable.verification",
                    "run",
                    str(log),
                    "--",
                    sys.executable,
                    "-c",
                    "import sys; sys.stdin.read()",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
            )
            try:
                import time

                deadline = time.monotonic() + 5
                while not log.with_suffix(".log.pid").exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(follow(log, 0), 124)
                self.assertIsNone(process.poll())
                process.communicate(timeout=5)
                self.assertEqual(follow(log, None), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()

    def test_missing_job_is_not_reported_as_running(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "dead.log"
            self.assertEqual(follow(log, None), 1)
            log.with_suffix(".log.pid").write_text(str(os.getpid()))
            self.assertEqual(follow(log, 0), 1)

    def test_build_keeps_failed_stage_logs_and_aggregate_ledger(self) -> None:
        import shutil

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "docker" / "disposable-server"
            scripts.mkdir(parents=True)
            repository = Path(__file__).resolve().parent.parent
            for name in ("build.sh", "quiet-run.sh"):
                shutil.copy(repository / "docker" / "disposable-server" / name, scripts / name)
            scenario = scripts / "run-scenarios.sh"
            scenario.write_text("#!/bin/sh\nexit 0\n")
            scenario.chmod(0o700)
            binary = root / "bin"
            binary.mkdir()
            uv = binary / "uv"
            uv.write_text(
                "#!/bin/sh\nshift\n"
                'if [ "$1" = python ]; then shift; exec "$TEST_PYTHON" "$@"; fi\n'
                'case "$*" in *"--tag browser"*) '
                "echo 'FAIL: failing_browser'; echo 'AssertionError: retained'; "
                "i=0; while [ $i -lt 100 ]; do echo dom; i=$((i+1)); done; exit 7;; esac\n"
                "exit 0\n"
            )
            uv.chmod(0o700)
            result = subprocess.run(  # noqa: S603 - isolated fake build commands
                ["/bin/sh", str(scripts / "build.sh")],
                env={
                    **os.environ,
                    "PATH": str(binary) + os.pathsep + os.environ["PATH"],
                    "PYTHONPATH": str(repository),
                    "TEST_PYTHON": sys.executable,
                    "BARECTL_NATIVE_LOCKED": "1",
                    "BARECTL_BUILD_LOGS": str(root / "logs"),
                },
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("FAIL: failing_browser", result.stdout)
            artifacts = next((root / "logs").glob("run-*"))
            self.assertIn("AssertionError: retained", (artifacts / "browser.log").read_text())
            ledger = json.loads((artifacts / "ledger.json").read_text())
            self.assertTrue(ledger["complete"])
            browser = next(entry for entry in ledger["gates"] if entry["name"] == "browser")
            self.assertEqual(browser["result"], "failed")
            self.assertEqual(browser["exit_status"], 7)
            self.assertFalse(browser["command_redacted"])
            self.assertEqual(browser["command"][-2:], ["--tag", "browser"])

    def test_source_identity_survives_commit_and_detects_working_edits(self) -> None:
        from contextlib import chdir

        from .verification import input_revision

        with tempfile.TemporaryDirectory() as directory, chdir(directory):
            for arguments in (
                ["init", "-q"],
                ["config", "user.name", "Verification Test"],
                ["config", "user.email", "verification@example.invalid"],
            ):
                subprocess.run(["/usr/bin/git", *arguments], check=True)  # noqa: S603 - isolated fixture repository
            source = Path("source.txt")
            source.write_text("first\n")
            subprocess.run(["/usr/bin/git", "add", "source.txt"], check=True)
            staged = input_revision()
            subprocess.run(["/usr/bin/git", "commit", "-qm", "fixture"], check=True)
            committed = input_revision()
            self.assertEqual(staged["index_sha256"], committed["index_sha256"])
            self.assertEqual(staged["working_diff_sha256"], committed["working_diff_sha256"])
            source.write_text("changed\n")
            changed = input_revision()
            self.assertNotEqual(changed["working_diff_sha256"], committed["working_diff_sha256"])
            subprocess.run(["/usr/bin/git", "add", "source.txt"], check=True)
            self.assertNotEqual(input_revision()["index_sha256"], committed["index_sha256"])

    def test_each_failed_git_probe_refuses_unchanged_evidence(self) -> None:
        from unittest.mock import patch

        probes = [
            ["diff", "--binary", "HEAD"],
            ["ls-files", "--stage", "-z"],
            ["diff", "--binary"],
            ["ls-files", "--others", "--exclude-standard"],
            ["rev-parse", "HEAD"],
        ]
        for failing in probes:
            with self.subTest(probe=failing), tempfile.TemporaryDirectory() as directory:

                def probe(
                    command: list[str], failing: list[str] = failing, **kwargs: object
                ) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
                    code = 1 if command[1:] == failing else 0
                    if kwargs.get("text"):
                        return subprocess.CompletedProcess(command, code, stdout="revision")
                    return subprocess.CompletedProcess(command, code, stdout=b"")

                with patch("disposable.verification.subprocess.run", side_effect=probe):
                    inputs = input_revision()
                    path = Path(directory) / "evidence.json"
                    record(path, "test", ["test"], Path(directory) / "test.log", 0, 0, inputs)
                    self.assertFalse(json.loads(path.read_text())["source_unchanged"])

    def test_aggregate_requires_matching_valid_completion_markers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in BUILD_GATES:
                log = root / f"{name}.log"
                log.write_text("retained evidence")
                record(log.with_suffix(".log.json"), name, ["test"], log, 0, 0, input_revision())
                log.with_suffix(".log.status").write_text("0\n")
            aggregate(root)
            self.assertTrue(json.loads((root / "ledger.json").read_text())["complete"])
            status = root / "browser.log.status"
            for marker in (None, "7\n", "invalid\n", "00\n"):
                with self.subTest(marker=marker):
                    if marker is None:
                        status.unlink()
                    else:
                        status.write_text(marker)
                    aggregate(root)
                    self.assertFalse(json.loads((root / "ledger.json").read_text())["complete"])

    def test_aggregate_rejects_conflicting_command_and_source_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in BUILD_GATES:
                log = root / f"{name}.log"
                log.write_text("retained evidence")
                record(
                    log.with_suffix(".log.json"),
                    name,
                    ["test"],
                    log,
                    0,
                    0,
                    input_revision(),
                    reveal_command=True,
                )
                log.with_suffix(".log.status").write_text("0\n")
            path = root / "browser.log.json"
            original = json.loads(path.read_text())
            for field, value in (
                ("command", ["different"]),
                ("inputs", {}),
                ("duration_seconds", -1),
                ("result", "passed incorrectly"),
            ):
                with self.subTest(field=field):
                    path.write_text(json.dumps({**original, field: value}))
                    aggregate(root)
                    self.assertFalse(json.loads((root / "ledger.json").read_text())["complete"])
