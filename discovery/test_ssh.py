"""The SSH transport against an in-process SSH server on the loopback interface.

These tests use real SSH negotiation, host-key checks and public-key authentication, so they
cover trust decisions and error sanitization that the workflow tests substitute.
"""

import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import ClassVar, override
from unittest import mock, skipUnless

import paramiko
from django.test import SimpleTestCase
from paramiko import Channel, ECDSAKey, HostKeys, PKey, ServerInterface, Transport
from paramiko.common import (
    AUTH_FAILED,
    AUTH_SUCCESSFUL,
    OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED,
    OPEN_SUCCEEDED,
)

from servers.ssh_config import ConnectionTarget

from . import ssh

USER = "deploy"


class _Handler(ServerInterface):
    def __init__(self, server: SshServer) -> None:
        self.server = server

    @override
    def get_allowed_auths(self, username: str) -> str:
        return "publickey"

    @override
    def check_auth_publickey(self, username: str, key: PKey) -> int:
        self.server.auth_attempts += 1
        time.sleep(self.server.auth_delay)
        if username == USER and key == self.server.authorized:
            return AUTH_SUCCESSFUL
        return AUTH_FAILED

    @override
    def check_channel_request(self, kind: str, _chanid: int) -> int:
        if kind == "session":
            return OPEN_SUCCEEDED
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    @override
    def check_channel_exec_request(self, channel: Channel, command: bytes) -> bool:
        self.server.commands.append(command.decode())
        # Respond after paramiko has acknowledged the request, which happens on return.
        threading.Timer(0.05, self.server.respond, args=(channel, command.decode())).start()
        return True


class SshServer:
    """A minimal SSH server that answers exec requests from a table."""

    def __init__(self, host_key: PKey, authorized: PKey) -> None:
        self.host_key = host_key
        self.authorized = authorized
        self.responses: dict[str, tuple[int, bytes]] = {}
        # Commands that write a byte every 0.2 seconds for five seconds.
        self.dripping: set[str] = set()
        self.commands: list[str] = []
        self.auth_attempts = 0
        # Seconds to wait before answering, as an agent waiting for a key touch would.
        self.auth_delay = 0.0
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port: int = self.listener.getsockname()[1]
        self.transports: list[Transport] = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            transport = Transport(connection)
            transport.add_server_key(self.host_key)
            self.transports.append(transport)
            threading.Thread(target=self._negotiate, args=(transport,), daemon=True).start()

    def _negotiate(self, transport: Transport) -> None:
        try:
            transport.start_server(server=_Handler(self))
        except paramiko.SSHException, EOFError, OSError:
            transport.close()

    def respond(self, channel: Channel, command: str) -> None:
        if command in self.dripping:
            self._drip(channel)
            return
        status, output = self.responses.get(command, (127, b""))
        channel.sendall(output)
        channel.send_exit_status(status)
        channel.close()

    def _drip(self, channel: Channel) -> None:
        try:
            for _ in range(25):
                channel.sendall(b"x")
                time.sleep(0.2)
            channel.send_exit_status(0)
        except OSError, EOFError, paramiko.SSHException:
            pass
        channel.close()

    def close(self) -> None:
        self.listener.close()
        for transport in self.transports:
            transport.close()


class SshServerTestCase(SimpleTestCase):
    host_key: ClassVar[PKey]
    client_key: ClassVar[PKey]
    directory: Path
    server: SshServer
    key_file: Path
    known_hosts: Path

    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.host_key = ECDSAKey.generate()
        cls.client_key = ECDSAKey.generate()

    @override
    def setUp(self) -> None:
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        # Never offer the developer's own agent keys to the test server.
        self.enterContext(mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": ""}))
        self.server = SshServer(self.host_key, self.client_key)
        self.addCleanup(self.server.close)
        self.key_file = self.directory / "id_ecdsa"
        self.client_key.write_private_key_file(str(self.key_file))
        self.known_hosts = self.directory / "known_hosts"
        self.trust(self.host_key)

    def host_pattern(self) -> str:
        return f"[127.0.0.1]:{self.server.port}"

    def trust(self, key: PKey, *, marker: str = "", hashed: bool = False) -> None:
        name = HostKeys.hash_host(self.host_pattern()) if hashed else self.host_pattern()
        line = f"{marker} {name} {key.get_name()} {key.get_base64()}".strip()
        with self.known_hosts.open("a", encoding="utf-8") as file:
            file.write(f"{line}\n")

    def target(self, *, identity_files: tuple[Path, ...] | None = None) -> ConnectionTarget:
        return ConnectionTarget(
            alias="web-1",
            hostname="127.0.0.1",
            port=self.server.port,
            user=USER,
            identity_files=(self.key_file,) if identity_files is None else identity_files,
            known_hosts_files=(self.directory / "missing", self.known_hosts),
        )

    def failure(self, target: ConnectionTarget | None = None) -> str:
        with (
            self.assertRaises(ssh.ConnectionFailed) as raised,
            ssh.connect(target or self.target()),
        ):
            pass
        message = str(raised.exception)
        # Operator guidance names the alias only, never connection details or key paths.
        for detail in ("127.0.0.1", str(self.server.port), str(self.directory), USER):
            self.assertNotIn(detail, message)
        return message


class TransportTests(SshServerTestCase):
    def test_trusted_server_runs_commands_and_reports_its_key(self) -> None:
        self.server.responses["cat /etc/os-release"] = (0, b"ID=ubuntu\n")
        with ssh.connect(self.target()) as shell:
            result = shell.run("cat /etc/os-release")
            missing = shell.run("test -e /nowhere")
            fingerprint = shell.host_key
        self.assertEqual(
            (result.exit_status, result.stdout, result.truncated), (0, "ID=ubuntu\n", False)
        )
        self.assertEqual(missing.exit_status, 127)
        self.assertTrue(fingerprint.startswith("ecdsa-sha2-nistp256 SHA256:"))
        self.assertEqual(self.server.commands, ["cat /etc/os-release", "test -e /nowhere"])

    def test_hashed_known_hosts_entries_are_trusted(self) -> None:
        self.known_hosts.write_text("", encoding="utf-8")
        self.trust(self.host_key, hashed=True)
        with ssh.connect(self.target()) as shell:
            self.assertTrue(shell.host_key)

    def test_unknown_host_keys_are_rejected_before_authentication(self) -> None:
        self.known_hosts.write_text("# no entries\n", encoding="utf-8")
        before = (self.known_hosts.read_bytes(), self.known_hosts.stat().st_mtime_ns)
        self.assertIn("does not trust the host key presented for web-1", self.failure())
        self.assertEqual(self.server.auth_attempts, 0)
        # Barectl never records a key it was offered.
        self.assertEqual(
            (self.known_hosts.read_bytes(), self.known_hosts.stat().st_mtime_ns), before
        )

    def test_changed_host_keys_are_rejected_before_authentication(self) -> None:
        self.known_hosts.write_text("", encoding="utf-8")
        self.trust(ECDSAKey.generate())
        self.assertIn("presented a different host key", self.failure())
        self.assertEqual(self.server.auth_attempts, 0)

    def test_revoked_host_keys_are_rejected_even_when_listed(self) -> None:
        self.trust(self.host_key, marker="@revoked")
        self.assertIn("marks as revoked", self.failure())
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
        self.server.dripping.add("cat slow")
        with (
            mock.patch.object(ssh, "COMMAND_TIMEOUT", 0.5),
            ssh.connect(self.target()) as shell,
            self.assertRaises(ssh.ConnectionFailed) as raised,
        ):
            started = time.monotonic()
            shell.run("cat slow")
        self.assertLess(time.monotonic() - started, 2)
        self.assertIn("A discovery command did not finish within", str(raised.exception))

    def test_large_output_is_truncated(self) -> None:
        self.server.responses["cat big"] = (0, b"x" * (ssh.MAX_OUTPUT + 10))
        with ssh.connect(self.target()) as shell:
            result = shell.run("cat big")
        self.assertTrue(result.truncated)
        self.assertEqual(len(result.stdout), ssh.MAX_OUTPUT)


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

    def test_agent_supplies_passphrase_protected_identity_files(self) -> None:
        protected = self.directory / "protected"
        self.client_key.write_private_key_file(str(protected), password="secret-passphrase")  # noqa: S106
        self.start_agent()
        with ssh.connect(self.target(identity_files=(protected,))) as shell:
            self.assertTrue(shell.host_key)
