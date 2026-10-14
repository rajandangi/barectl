"""Shared in-process SSH server for transport and worker journeys."""

import os
import signal
import socket
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import IO, ClassVar, override
from unittest import mock

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
        self.server.offered.append(key)
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

    @override
    def check_channel_pty_request(
        self,
        channel: Channel,
        _term: bytes,
        width: int,
        height: int,
        _pixelwidth: int,
        _pixelheight: int,
        _modes: bytes,
    ) -> bool:
        self.server.refused.append("pty")
        return False

    @override
    def check_channel_env_request(self, channel: Channel, name: bytes, value: bytes) -> bool:
        self.server.refused.append("env")
        return False

    @override
    def check_channel_forward_agent_request(self, channel: Channel) -> bool:
        self.server.refused.append("agent forwarding")
        return False


class SshServer:
    """A minimal SSH server that runs each exec request with the local ``/bin/sh``.

    Commands run as the test's own user, with a fixed environment, so the transports are
    tested against real command semantics: exit statuses, output streams and timing.
    """

    def __init__(self, host_key: PKey, authorized: PKey) -> None:
        self.host_key = host_key
        self.authorized = authorized
        # Exec requests as received, and channel requests the server refused.
        self.commands: list[str] = []
        self.refused: list[str] = []
        # Bytes sent instead of running a command, as a misbehaving server's shell would.
        self.raw_output: bytes | None = None
        # Accept commands but never answer, as a stalled server does.
        self.stalled = False
        # Send part of an answer, then drop the connection, as a crashing server does.
        self.disconnecting = False
        self.auth_attempts = 0
        self.offered: list[PKey] = []
        # Seconds to wait before answering, as an agent waiting for a key touch would.
        self.auth_delay = 0.0
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port: int = self.listener.getsockname()[1]
        self.transports: list[Transport] = []
        self.processes: list[subprocess.Popen[bytes]] = []
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
        if self.stalled:
            return
        if self.disconnecting:
            channel.sendall(b"ID=ubu")
            channel.get_transport().close()
            return
        if self.raw_output is not None:
            # The client may refuse the answer part way and close the connection.
            with suppress(OSError, EOFError, paramiko.SSHException):
                channel.sendall(self.raw_output)
                channel.send_exit_status(0)
                channel.close()
            return
        process = subprocess.Popen(  # noqa: S603 - the tests' own commands
            ["/bin/sh", "-c", command],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            start_new_session=True,
        )
        self.processes.append(process)
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise AssertionError
        threading.Thread(target=self._feed, args=(channel, process.stdin), daemon=True).start()
        errors = threading.Thread(
            target=self._copy, args=(process.stderr, channel.sendall_stderr), daemon=True
        )
        errors.start()
        threading.Thread(target=self._watch, args=(channel, process), daemon=True).start()
        self._copy(process.stdout, channel.sendall)
        errors.join()
        status = process.wait()
        process.stdout.close()
        process.stderr.close()
        with suppress(OSError, EOFError, paramiko.SSHException):
            channel.send_exit_status(status if status >= 0 else 128 - status)
            channel.close()

    @staticmethod
    def _feed(channel: Channel, stdin: IO[bytes]) -> None:
        """Pass the client's standard input to the command until the client ends it."""
        # The command may exit, or the test end, before the input is consumed.
        with suppress(OSError, ValueError, EOFError, paramiko.SSHException), stdin:
            while chunk := channel.recv(4096):
                stdin.write(chunk)
                stdin.flush()

    def _copy(self, stream: IO[bytes], send: Callable[[bytes], None]) -> None:
        try:
            while chunk := os.read(stream.fileno(), 4096):
                send(chunk)
        except OSError, EOFError, paramiko.SSHException:
            # The client closed the channel; stop the command as sshd would.
            self._stop(stream)

    @staticmethod
    def _watch(channel: Channel, process: subprocess.Popen[bytes]) -> None:
        """Stop the command when the client goes away, as sshd does."""
        while process.poll() is None:
            if channel.closed:
                _kill(process)
                return
            time.sleep(0.05)

    def _stop(self, stream: IO[bytes]) -> None:
        for process in self.processes:
            if stream in (process.stdout, process.stderr):
                _kill(process)

    def close(self) -> None:
        self.listener.close()
        for transport in self.transports:
            transport.close()
        for process in self.processes:
            _kill(process)
            process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


def _kill(process: subprocess.Popen[bytes]) -> None:
    """Stop a command and anything it started."""
    # The group can outlive the shell, or already be gone.
    with suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGKILL)


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

    def trust(
        self, key: PKey, *, marker: str = "", hashed: bool = False, file: Path | None = None
    ) -> None:
        name = HostKeys.hash_host(self.host_pattern()) if hashed else self.host_pattern()
        line = f"{marker} {name} {key.get_name()} {key.get_base64()}".strip()
        with (file or self.known_hosts).open("a", encoding="utf-8") as handle:
            handle.write(f"{line}\n")

    def target(
        self,
        *,
        identity_files: tuple[Path, ...] | None = None,
        known_hosts_files: tuple[Path, ...] | None = None,
    ) -> ConnectionTarget:
        return ConnectionTarget(
            alias="web-1",
            hostname="127.0.0.1",
            port=self.server.port,
            user=USER,
            identity_files=(self.key_file,) if identity_files is None else identity_files,
            known_hosts_files=(self.directory / "missing", self.known_hosts)
            if known_hosts_files is None
            else known_hosts_files,
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

    def controller_files(self) -> dict[str, tuple[bytes, int]]:
        """The controller's key and trust files, to show a connection leaves them alone."""
        return {
            path.name: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in sorted(self.directory.iterdir())
        }

    def run_command(self, command: str) -> ssh.CommandResult:
        with ssh.connect(self.target()) as shell:
            return shell.run(command)
