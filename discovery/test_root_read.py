"""Bounded root reads through the existing privilege adapter (docs/ssh-connections.md)."""

import shlex
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from discovery.root_read import run_root
from discovery.ssh import MAX_OUTPUT, CommandResult


class _Shell:
    host_key = "ssh-ed25519 SHA256:test"

    def __init__(self, audit: Path) -> None:
        self.audit = audit
        self.uid = "1000"
        self.identity_status = 0
        self.authorized = True
        self.commands: list[str] = []

    def run(self, command: str, stdin: bytes | None = None) -> CommandResult:
        self.commands.append(command)
        script = (
            f"id() {{ printf '%s\\n' {shlex.quote(self.uid)}; "
            f"return {self.identity_status}; }}; "
            "sudo() { "
            f"printf '%s\\n' \"$@\" >> {shlex.quote(str(self.audit))}; "
            'shift; if [ "$1" = -l ]; then '
            "printf '%070000d\\n' 0; "
            f"return {0 if self.authorized else 1}; fi; "
            'shift; command sh "$@"; }; ' + command
        )
        result = subprocess.run(  # noqa: S603 - fixed reads and test-only identity/sudo functions
            ["/bin/sh", "-c", script], capture_output=True, check=False
        )
        return CommandResult(
            result.returncode,
            result.stdout[:MAX_OUTPUT].decode(),
            len(result.stdout) > MAX_OUTPUT,
        )


class RootReadTests(SimpleTestCase):
    def test_each_read_checks_identity_and_exact_sudo_in_one_round_trip(self) -> None:
        with TemporaryDirectory() as directory:
            audit = Path(directory) / "sudo"
            shell = _Shell(audit)
            command = "printf '%s\\n' 'read with quotes: '\"'\"' and $HOME'; exit 7"
            for uid in ("0", "1000"):
                with self.subTest(uid=uid):
                    shell.uid = uid
                    result = run_root(shell, command)
                    self.assertEqual(result, CommandResult(7, "read with quotes: ' and $HOME\n"))
            self.assertEqual(len(shell.commands), 2)
            self.assertEqual(
                audit.read_text().splitlines(),
                ["-n", "-l", "/usr/bin/sh", "-c", command, "-n", "/usr/bin/sh", "-c", command],
            )

    def test_identity_and_authorization_are_rechecked_and_fail_closed(self) -> None:
        with TemporaryDirectory() as directory:
            audit = Path(directory) / "sudo"
            shell = _Shell(audit)
            self.assertEqual(run_root(shell, "printf read"), CommandResult(0, "read"))
            shell.authorized = False
            self.assertEqual(run_root(shell, "printf read"), CommandResult(1, ""))
            authorization = ["-n", "-l", "/usr/bin/sh", "-c", "printf read"]
            execution = ["-n", "/usr/bin/sh", "-c", "printf read"]
            self.assertEqual(
                audit.read_text().splitlines(), authorization + execution + authorization
            )
            shell.identity_status = 1
            before = audit.read_text()
            self.assertEqual(run_root(shell, "printf read"), CommandResult(1, ""))
            self.assertEqual(audit.read_text(), before)
            shell.identity_status = 0
            for newlines, expected in (
                (0, CommandResult(0, "read")),
                (MAX_OUTPUT - 2, CommandResult(0, "read")),
                (MAX_OUTPUT - 1, CommandResult(1, "")),
            ):
                with self.subTest(identity_bytes=newlines + 2):
                    shell.uid = "0" + "\n" * newlines
                    self.assertEqual(run_root(shell, "printf read"), expected)
                    self.assertEqual(audit.read_text(), before)
            shell.uid = "0"
            self.assertEqual(run_root(shell, "printf '%070000d' 0").truncated, True)
            self.assertEqual(audit.read_text(), before)
