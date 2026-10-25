"""Bounded root reads through the existing privilege adapter (docs/ssh-connections.md)."""

from django.test import SimpleTestCase

from discovery.root_read import run_root
from discovery.ssh import CommandResult


class _Shell:
    """A non-root connection whose authorization probe may be echoed past the answer bound."""

    host_key = "ssh-ed25519 SHA256:test"

    def __init__(self, *, authorized: bool, truncated: bool = False) -> None:
        self.authorized = authorized
        self.truncated = truncated
        self.commands: list[str] = []

    def run(self, command: str, stdin: bytes | None = None) -> CommandResult:
        self.commands.append(command)
        if command == "id -u":
            return CommandResult(0, "1000\n")
        if command.startswith("sudo -n -l "):
            if not self.authorized:
                return CommandResult(1, "")
            return CommandResult(0, "the echo of a long command\n", self.truncated)
        if command.startswith("sudo -n "):
            return CommandResult(0, "read\n")
        raise AssertionError(f"Unexpected command: {command}")


class RootReadTests(SimpleTestCase):
    def test_a_truncated_authorization_echo_still_authorizes_the_exact_read(self) -> None:
        shell = _Shell(authorized=True, truncated=True)
        result = run_root(shell, "example-read")
        self.assertEqual(result.exit_status, 0)
        self.assertEqual(result.stdout, "read\n")
        self.assertTrue(shell.commands[-1].startswith("sudo -n "))

    def test_a_refused_authorization_runs_nothing(self) -> None:
        shell = _Shell(authorized=False)
        result = run_root(shell, "example-read")
        self.assertEqual(result.exit_status, 1)
        self.assertEqual(result.stdout, "")
        self.assertFalse(
            any(command.startswith("sudo -n /usr/bin/sh") for command in shell.commands)
        )
