"""The SSH transport against an in-process SSH server on the loopback interface.

These tests use real SSH negotiation, host-key checks and public-key authentication, so they
cover trust decisions and error sanitization that the workflow tests substitute.
"""

import base64
import logging
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import traceback
from contextlib import suppress
from pathlib import Path
from typing import override
from unittest import mock, skipUnless

from paramiko import ECDSAKey

from servers.ssh_config import ConnectionTarget

from . import ssh
from .ssh_testing import USER, SshServerTestCase


def _usage() -> tuple[int, int]:
    """The process's running threads and open file descriptors."""
    return threading.active_count(), len(os.listdir("/dev/fd"))


DRIP = "while :; do printf x; sleep 0.2; done"


class TransportTests(SshServerTestCase):
    def test_trusted_server_runs_commands_and_reports_its_key(self) -> None:
        before = self.controller_files()
        with ssh.connect(self.target()) as shell:
            result = shell.run("printf 'ID=ubuntu\\n'")
            missing = shell.run("barectl-no-such-command")
            fingerprint = shell.host_key
        self.assertEqual(
            (result.exit_status, result.stdout, result.truncated), (0, "ID=ubuntu\n", False)
        )
        self.assertEqual(missing.exit_status, 127)
        self.assertEqual(fingerprint, f"{self.host_key.get_name()} {self.host_key.fingerprint}")
        self.assertEqual(len(self.server.commands), 2)
        # No PTY, environment or agent forwarding was requested, and nothing was recorded.
        self.assertEqual(self.server.refused, [])
        self.assertEqual(self.controller_files(), before)

    def test_exit_statuses_are_reported_exactly(self) -> None:
        with ssh.connect(self.target()) as shell:
            statuses = [
                shell.run(command).exit_status
                for command in (
                    "true",
                    "false",
                    "exit 2",
                    "/dev/null",
                    "barectl-no-such-command",
                    "exit 255",
                )
            ]
        self.assertEqual(statuses, [0, 1, 2, 126, 127, 255])

    def test_stdin_reaches_the_command_without_becoming_part_of_its_command(self) -> None:
        payload = b"barectl-stdin-canary-6f20\n"
        command = "IFS= read -r value; printf '%s\\n' \"$value\""
        with ssh.connect(self.target()) as shell:
            result = shell.run(command, stdin=payload)
        self.assertEqual((result.exit_status, result.stdout), (0, payload.decode()))
        self.assertEqual(len(self.server.commands), 1)
        self.assertNotIn(payload.decode().strip(), " ".join(self.server.commands))

    def test_output_whitespace_and_line_boundaries_are_kept(self) -> None:
        with ssh.connect(self.target()) as shell:
            spaced = shell.run("printf '  a \\t\\n\\n\\nb  \\r\\n\\n'")
            unterminated = shell.run("printf 'last line'")
            empty = shell.run("printf ''")
            undecodable = shell.run("printf 'a\\377b\\n'")
        self.assertEqual(spaced.stdout, "  a \t\n\n\nb  \r\n\n")
        self.assertEqual(unterminated.stdout, "last line")
        self.assertEqual((empty.exit_status, empty.stdout, empty.truncated), (0, "", False))
        self.assertEqual(undecodable.stdout, "a\ufffdb\n")

    def test_error_output_is_neither_kept_nor_mistaken_for_output(self) -> None:
        result = self.run_command("head -c 1000000 /dev/zero >&2; printf 'ok\\n'; exit 3")
        self.assertEqual((result.exit_status, result.stdout, result.truncated), (3, "ok\n", False))

    def test_hashed_known_hosts_entries_are_trusted(self) -> None:
        self.known_hosts.write_text("", encoding="utf-8")
        self.trust(self.host_key, hashed=True)
        with ssh.connect(self.target()) as shell:
            self.assertTrue(shell.host_key)

    def test_every_configured_known_hosts_file_is_read(self) -> None:
        self.known_hosts.write_text("", encoding="utf-8")
        second = self.directory / "known_hosts2"
        self.trust(self.host_key, file=second)
        target = self.target(known_hosts_files=(self.known_hosts, second))
        with ssh.connect(target) as shell:
            self.assertTrue(shell.host_key)

    def test_default_ports_are_looked_up_without_a_port(self) -> None:
        # A server on port 22 is recorded by host name alone; one on another port is not.
        self.known_hosts.write_text(
            f"127.0.0.1 {self.host_key.get_name()} {self.host_key.get_base64()}\n",
            encoding="utf-8",
        )
        self.assertIn("does not trust the host key presented for web-1", self.failure())

    def test_unknown_host_keys_are_rejected_before_authentication(self) -> None:
        self.known_hosts.write_text("# no entries\n", encoding="utf-8")
        before = self.controller_files()
        self.assertIn("does not trust the host key presented for web-1", self.failure())
        self.assertEqual(self.server.auth_attempts, 0)
        # Barectl never records a key it was offered.
        self.assertEqual(self.controller_files(), before)

    def test_changed_host_keys_are_rejected_before_authentication(self) -> None:
        self.known_hosts.write_text("", encoding="utf-8")
        self.trust(ECDSAKey.generate())
        before = self.controller_files()
        self.assertIn("presented a different host key", self.failure())
        self.assertEqual(self.server.auth_attempts, 0)
        self.assertEqual(self.controller_files(), before)

    def test_revoked_host_keys_are_rejected_even_when_listed(self) -> None:
        self.trust(self.host_key, marker="@revoked")
        before = self.controller_files()
        self.assertIn("marks as revoked", self.failure())
        self.assertEqual(self.server.auth_attempts, 0)
        self.assertEqual(self.controller_files(), before)

    def test_revoked_host_keys_in_another_file_are_rejected(self) -> None:
        revocations = self.directory / "revoked_hosts"
        self.trust(self.host_key, marker="@revoked", file=revocations)
        target = self.target(known_hosts_files=(self.known_hosts, revocations))
        self.assertIn("marks as revoked", self.failure(target))
        self.assertEqual(self.server.auth_attempts, 0)

    def test_rejected_credentials_are_sanitized(self) -> None:
        other = self.directory / "other"
        ECDSAKey.generate().write_private_key_file(str(other))
        message = self.failure(self.target(identity_files=(other,)))
        self.assertIn("rejected the SSH credentials available for web-1", message)
        self.assertGreater(self.server.auth_attempts, 0)

    def test_slow_authentication_is_reported_as_a_timeout(self) -> None:
        self.server.auth_delay = 1.5
        with mock.patch.object(ssh, "CONNECT_TIMEOUT", 0.5):
            message = self.failure()
        self.assertIn("Authentication for web-1 did not finish", message)

    def test_missing_credentials_are_reported_as_rejected(self) -> None:
        message = self.failure(self.target(identity_files=(self.directory / "absent",)))
        self.assertIn("rejected the SSH credentials", message)

    def test_passphrase_protected_key_files_are_not_prompted_for(self) -> None:
        protected = self.directory / "protected"
        self.client_key.write_private_key_file(str(protected), password="secret-passphrase")  # noqa: S106
        message = self.failure(self.target(identity_files=(protected,)))
        self.assertIn("unless they are loaded in the agent", message)
        self.assertNotIn("secret-passphrase", message)

    def test_unresponsive_servers_time_out(self) -> None:
        silent = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(silent.close)
        target = ConnectionTarget("web-1", "127.0.0.1", silent.getsockname()[1], USER, (), ())
        started = time.monotonic()
        with mock.patch.object(ssh, "CONNECT_TIMEOUT", 0.5):
            self.assertIn("failed or timed out", self.failure(target))
        self.assertLess(time.monotonic() - started, 5)

    def test_unreachable_servers_are_explained(self) -> None:
        closed = socket.create_server(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        target = ConnectionTarget("web-1", "127.0.0.1", port, USER, (), ())
        self.assertIn("could not reach the SSH service configured for web-1", self.failure(target))

    def test_commands_that_keep_writing_are_stopped_at_the_limit(self) -> None:
        with (
            mock.patch.object(ssh, "COMMAND_TIMEOUT", 0.5),
            ssh.connect(self.target()) as shell,
            self.assertRaises(ssh.ConnectionFailed) as raised,
        ):
            started = time.monotonic()
            shell.run(DRIP)
        self.assertLess(time.monotonic() - started, 2)
        self.assertIn("A remote command did not finish within", str(raised.exception))

    def test_a_connection_is_stopped_at_its_overall_limit(self) -> None:
        # Each command stays within its own limit, but the connection's total does not.
        with (
            mock.patch.object(ssh, "SESSION_TIMEOUT", 0.6),
            ssh.connect(self.target()) as shell,
        ):
            started = time.monotonic()
            self.assertEqual(shell.run("printf 'ok\\n'").stdout, "ok\n")
            with self.assertRaises(ssh.ConnectionFailed) as raised:
                shell.run(DRIP)
            self.assertLess(time.monotonic() - started, 2)
            # Once the limit has passed, no further command is sent.
            with self.assertRaises(ssh.ConnectionFailed):
                shell.run("printf 'ok\\n'")
        self.assertIn("The remote commands did not finish within", str(raised.exception))
        self.assertEqual(len(self.server.commands), 2)

    def test_output_at_the_limit_is_complete(self) -> None:
        result = self.run_command(f"head -c {ssh.MAX_OUTPUT} /dev/zero | tr '\\0' x")
        self.assertEqual((result.exit_status, result.truncated), (0, False))
        self.assertEqual(result.stdout, "x" * ssh.MAX_OUTPUT)

    def test_large_output_is_truncated(self) -> None:
        for size in (ssh.MAX_OUTPUT + 1, ssh.MAX_OUTPUT * 20):
            with self.subTest(size=size):
                result = self.run_command(f"head -c {size} /dev/zero | tr '\\0' x")
                self.assertTrue(result.truncated)
                self.assertEqual(result.stdout, "x" * ssh.MAX_OUTPUT)

    def test_oversized_answers_are_refused_as_they_arrive(self) -> None:
        # Valid base64 and a valid last line, from a server that ignores the output limit.
        self.server.raw_output = b"QUFB" * (ssh.MAX_RECEIVED // 2) + b"\nexit 0 0\n"
        with self.assertRaises(ssh.ConnectionFailed) as raised:
            self.run_command("printf x")
        self.assertIn("its result could not be read", str(raised.exception))

    def test_unreadable_results_are_never_taken_as_output(self) -> None:
        # What a server sends when its shell does not run the command as asked.
        for raw in (
            b"",
            b"garbage\n",
            b"!!!!\nexit 0 0\n",
            b"eA==\nexit 0 1\n",
            b"eA==\nexit 999 0\n",
        ):
            with self.subTest(raw=raw):
                self.server.raw_output = raw
                with self.assertRaises(ssh.ConnectionFailed) as raised:
                    self.run_command("printf x")
                self.assertIn("its result could not be read", str(raised.exception))

    def test_stalled_commands_are_stopped_at_the_limit(self) -> None:
        self.server.stalled = True
        with (
            mock.patch.object(ssh, "COMMAND_TIMEOUT", 0.5),
            ssh.connect(self.target()) as shell,
            self.assertRaises(ssh.ConnectionFailed) as raised,
        ):
            started = time.monotonic()
            shell.run("printf ok")
        self.assertLess(time.monotonic() - started, 2)
        self.assertIn("A remote command did not finish within", str(raised.exception))

    def test_dropped_connections_never_give_a_result(self) -> None:
        self.server.disconnecting = True
        with ssh.connect(self.target()) as shell:
            with self.assertRaises(ssh.ConnectionFailed) as raised:
                shell.run("cat /etc/os-release")
            # Nothing more is sent on a connection that ended.
            with self.assertRaises(ssh.ConnectionFailed):
                shell.run("cat /etc/os-release")
        self.assertIn("ended before a remote command finished", str(raised.exception))
        self.assertEqual(len(self.server.commands), 1)

    def test_connections_are_released_whatever_the_outcome(self) -> None:
        def succeed() -> None:
            self.run_command("printf ok")

        def truncate() -> None:
            self.run_command(f"head -c {ssh.MAX_OUTPUT * 2} /dev/zero")

        def time_out() -> None:
            with mock.patch.object(ssh, "COMMAND_TIMEOUT", 0.3):
                self.run_command(DRIP)

        def stall() -> None:
            self.server.stalled = True
            try:
                with mock.patch.object(ssh, "COMMAND_TIMEOUT", 0.3):
                    self.run_command("printf ok")
            finally:
                self.server.stalled = False

        def disconnect() -> None:
            self.server.disconnecting = True
            try:
                self.run_command("printf ok")
            finally:
                self.server.disconnecting = False

        def refuse_credentials() -> None:
            self.run_command_as(self.target(identity_files=(self.directory / "absent",)))

        def refuse_host_key() -> None:
            self.run_command_as(self.target(known_hosts_files=()))

        for outcome in (
            succeed,
            truncate,
            time_out,
            stall,
            disconnect,
            refuse_credentials,
            refuse_host_key,
        ):
            with self.subTest(outcome=outcome.__name__):
                # The first connection sets up state that lasts, such as gevent's loop.
                self.run_command("true")
                self.assert_released(_usage())
                usage = _usage()
                with suppress(ssh.ConnectionFailed):
                    outcome()
                self.assert_released(usage)

    def test_an_interrupted_command_releases_its_connection(self) -> None:
        # The worker exits with SystemExit when an operator forces it to stop.
        def stop(_signum: int, _frame: object) -> None:
            raise SystemExit(1)

        previous = signal.signal(signal.SIGUSR1, stop)
        self.addCleanup(signal.signal, signal.SIGUSR1, previous)
        self.run_command("true")
        self.assert_released(_usage())
        usage = _usage()
        timer = threading.Timer(0.5, os.kill, args=(os.getpid(), signal.SIGUSR1))
        started = time.monotonic()
        timer.start()
        with self.assertRaises(SystemExit):
            self.run_command("sleep 30")
        self.assertLess(time.monotonic() - started, 5)
        self.assert_released(usage)
        self.assertEqual(self.run_command("printf ok").stdout, "ok")

    def run_command_as(self, target: ConnectionTarget) -> ssh.CommandResult:
        with ssh.connect(target) as shell:
            return shell.run("printf ok")

    def assert_released(self, before: tuple[int, int]) -> None:
        """Wait for the connection's threads, sockets and files to be released."""
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            closed = not any(transport.is_active() for transport in self.server.transports)
            threads, descriptors = _usage()
            if closed and threads <= before[0] and descriptors <= before[1]:
                return
            time.sleep(0.05)
        self.fail(f"Resources were not released: {_usage()} after starting from {before}.")

    def test_each_connection_reads_trust_again(self) -> None:
        with ssh.connect(self.target()) as shell:
            self.assertTrue(shell.host_key)
        self.known_hosts.write_text("", encoding="utf-8")
        self.assertIn("does not trust the host key presented for web-1", self.failure())


# Bytes a shell or a text encoding could alter: NUL, invalid UTF-8, CR and no final newline.
SECRET = b"canary-4c1e\x00\xff\r\nsecond line"


class _Captured(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.messages: list[str] = []

    @override
    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(f"{record.getMessage()} {record.args!r}")


class StandardInputTests(SshServerTestCase):
    """docs/ssh-connections.md#pyinfra-connection"""

    def capture_logs(self) -> _Captured:
        """Every record pyinfra, paramiko and the rest log, even below their usual level."""
        captured = _Captured()
        for logger in (
            logging.getLogger(),
            logging.getLogger("pyinfra"),
            logging.getLogger("paramiko"),
        ):
            self.addCleanup(logger.setLevel, logger.level)
            logger.setLevel(logging.DEBUG)
            logger.addHandler(captured)
            self.addCleanup(logger.removeHandler, captured)
        return captured

    def assert_not_revealed(self, *texts: str) -> None:
        for text in texts:
            for form in (SECRET.decode("latin-1"), base64.b64encode(SECRET).decode("ascii")):
                self.assertNotIn(form, text)

    def test_standard_input_reaches_the_command_byte_for_byte(self) -> None:
        with ssh.connect(self.target()) as shell:
            received = shell.run("od -An -v -tx1 | tr -d ' \\n'", stdin=SECRET)
            empty = shell.run("wc -c", stdin=b"")
            none = shell.run("wc -c")
            # A command that never reads its input still finishes with its own status.
            ignored = shell.run("exit 3", stdin=SECRET * 50_000)
        self.assertEqual((received.exit_status, received.stdout), (0, SECRET.hex()))
        self.assertEqual((empty.stdout.strip(), none.stdout.strip()), ("0", "0"))
        self.assertEqual(ignored.exit_status, 3)

    def test_standard_input_is_never_logged_or_sent_in_the_command(self) -> None:
        captured = self.capture_logs()
        with ssh.connect(self.target()) as shell:
            self.assertEqual(shell.run("cat >/dev/null", stdin=SECRET).exit_status, 0)
        self.assertTrue(captured.messages)
        self.assert_not_revealed(*captured.messages, *self.server.commands)

    def test_failures_never_quote_standard_input(self) -> None:
        captured = self.capture_logs()
        for setting in ("disconnecting", "raw_output"):
            with self.subTest(setting=setting):
                self.server.disconnecting = setting == "disconnecting"
                self.server.raw_output = b"garbage\n" if setting == "raw_output" else None
                with (
                    self.assertRaises(ssh.ConnectionFailed) as raised,
                    ssh.connect(self.target()) as shell,
                ):
                    shell.run("cat", stdin=SECRET)
                exception = raised.exception
                self.assertIsNone(exception.__context__ if exception.__suppress_context__ else None)
                self.assert_not_revealed(
                    str(exception), repr(exception), "".join(traceback.format_exception(exception))
                )
        self.assert_not_revealed(*captured.messages)


@skipUnless(shutil.which("ssh-agent") and shutil.which("ssh-add"), "OpenSSH agent tools needed")
class AgentTests(SshServerTestCase):
    """Authentication through a disposable ssh-agent, as the controller host's agent."""

    def start_agent(self) -> None:
        # A short socket path: Unix socket paths are limited to about 100 bytes.
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir="/tmp")))
        sock = directory / "agent"
        agent = subprocess.Popen(  # noqa: S603 - fixed arguments
            ["ssh-agent", "-D", "-a", str(sock)],  # noqa: S607 - found on PATH above
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(agent.wait)
        self.addCleanup(agent.terminate)
        deadline = time.monotonic() + 5
        while not sock.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        environment = {"SSH_AUTH_SOCK": str(sock)}
        self.enterContext(mock.patch.dict(os.environ, environment))
        subprocess.run(  # noqa: S603 - fixed arguments
            ["ssh-add", str(self.key_file)],  # noqa: S607 - found on PATH above
            check=True,
            capture_output=True,
            env={**os.environ, **environment},
        )

    def test_agent_keys_authenticate(self) -> None:
        self.start_agent()
        with ssh.connect(self.target(identity_files=(self.directory / "absent",))) as shell:
            self.assertTrue(shell.host_key)
        # The agent is used for authentication only, never forwarded.
        self.assertEqual(self.server.refused, [])

    def test_agent_supplies_passphrase_protected_identity_files(self) -> None:
        protected = self.directory / "protected"
        self.client_key.write_private_key_file(str(protected), password="secret-passphrase")  # noqa: S106
        self.start_agent()
        with ssh.connect(self.target(identity_files=(protected,))) as shell:
            self.assertTrue(shell.host_key)
