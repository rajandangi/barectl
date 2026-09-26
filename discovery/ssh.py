"""Connect to a managed server over SSH with the controller host's credentials and trust.

This is Barectl's only remote execution boundary (see docs/ssh-connections.md).
Authentication uses the key files an alias names, or the default key files, and the SSH
agent in the worker's environment. Host identity comes only from the controller's
known_hosts files: unknown, changed and revoked keys are refused, whatever the SSH
configuration says, and Barectl never records a key. Failures are reported as sanitized
``ConnectionFailed`` messages; remote output, exception text, host names and key paths are
never included.
"""

import base64
import hashlib
import socket
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, override

from paramiko import (
    BadHostKeyException,
    MissingHostKeyPolicy,
    PKey,
    SSHClient,
    SSHException,
)
from paramiko.hostkeys import HostKeyEntry, InvalidHostKey

from servers.ssh_config import ConnectionTarget

CONNECT_TIMEOUT = 10
COMMAND_TIMEOUT = 15
# Observations are small files. Larger output is reported as truncated, not stored.
MAX_OUTPUT = 64 * 1024
MAX_ERROR_OUTPUT = 4 * 1024


class ConnectionFailed(Exception):
    """A sanitized, operator-facing reason a connection or command failed."""


@dataclass(frozen=True)
class CommandResult:
    exit_status: int
    stdout: str
    stderr: str
    # More than MAX_OUTPUT bytes were written; stdout holds only the start.
    truncated: bool = False


class RemoteShell(Protocol):
    """An authenticated connection to a server whose host key was verified."""

    @property
    def host_key(self) -> str:
        """The verified host key's type and SHA256 fingerprint."""
        ...

    def run(self, command: str) -> CommandResult: ...


class _UntrustedHostKey(Exception):
    def __init__(self, *, revoked: bool) -> None:
        super().__init__()
        self.revoked = revoked


class _RejectUntrusted(MissingHostKeyPolicy):
    """Refuse any server whose key is not in known_hosts, without recording it."""

    def __init__(self, revoked: frozenset[bytes]) -> None:
        self.revoked = revoked

    @override
    def missing_host_key(self, client: SSHClient, hostname: str, key: PKey) -> None:
        raise _UntrustedHostKey(revoked=key.asbytes() in self.revoked)


class _ParamikoShell:
    def __init__(self, client: SSHClient, host_key: str) -> None:
        self._client = client
        self.host_key = host_key

    def run(self, command: str) -> CommandResult:
        # No PTY and no environment: the command runs non-interactively with the SSH
        # user's own permissions.
        stdin, stdout, stderr = self._client.exec_command(command, timeout=COMMAND_TIMEOUT)
        stdin.close()
        try:
            output = stdout.read(MAX_OUTPUT + 1)
            errors = stderr.read(MAX_ERROR_OUTPUT)
        except TimeoutError:
            raise ConnectionFailed(_TIMED_OUT_COMMAND) from None
        channel = stdout.channel
        truncated = len(output) > MAX_OUTPUT
        if truncated:
            channel.close()
        elif not channel.status_event.wait(COMMAND_TIMEOUT):
            raise ConnectionFailed(_TIMED_OUT_COMMAND)
        return CommandResult(
            exit_status=channel.exit_status,
            stdout=output[:MAX_OUTPUT].decode("utf-8", "replace"),
            stderr=errors.decode("utf-8", "replace"),
            truncated=truncated,
        )


_TIMED_OUT_COMMAND = (
    f"A discovery command did not finish within {COMMAND_TIMEOUT} seconds. Barectl closed "
    "the connection."
)


@contextmanager
def connect(target: ConnectionTarget) -> Iterator[RemoteShell]:
    """Open a verified, authenticated connection to ``target``; close it on exit."""
    client = SSHClient()
    revoked = _load_trust(client, target.known_hosts_files)
    client.set_missing_host_key_policy(_RejectUntrusted(revoked))
    try:
        try:
            client.connect(
                hostname=target.hostname,
                port=target.port,
                username=target.user,
                # paramiko accepts a list of files, though its stubs declare one.
                key_filename=[str(path) for path in target.identity_files if path.is_file()]  # type: ignore[arg-type]
                or None,
                # OpenSSH tries the default key files only when an alias names none.
                look_for_keys=not target.identity_files,
                allow_agent=True,
                timeout=CONNECT_TIMEOUT,
                banner_timeout=CONNECT_TIMEOUT,
                auth_timeout=CONNECT_TIMEOUT,
                channel_timeout=CONNECT_TIMEOUT,
            )
        except (_UntrustedHostKey, BadHostKeyException) as error:
            raise ConnectionFailed(_explain(error, target.alias)) from None
        except (SSHException, OSError) as error:
            transport = client.get_transport()
            if transport is not None and transport.initial_kex_done:
                # The host key was verified, so authentication failed. paramiko reports the
                # last error from any key it tried, which need not name the rejection.
                raise ConnectionFailed(_REJECTED_CREDENTIALS.format(alias=target.alias)) from None
            raise ConnectionFailed(_explain(error, target.alias)) from None
        transport = client.get_transport()
        if transport is None:
            raise ConnectionFailed(_explain(SSHException(), target.alias))
        yield _ParamikoShell(client, _fingerprint(transport.get_remote_server_key()))
    finally:
        client.close()


def _load_trust(client: SSHClient, files: tuple[Path, ...]) -> frozenset[bytes]:
    """Add known_hosts entries to ``client``; return the keys marked ``@revoked``.

    paramiko skips marker lines, so a revoked key listed again without the marker would
    be trusted. Barectl drops such entries and treats a revoked key as revoked for every
    host. ``@cert-authority`` lines are not supported and trust nothing.
    """
    revoked: set[bytes] = set()
    entries: list[HostKeyEntry] = []
    for line in _known_hosts_lines(files):
        marker, _, rest = line.partition(" ") if line.startswith("@") else ("", "", line)
        try:
            entry = HostKeyEntry.from_line(rest.strip())
        except InvalidHostKey:
            continue
        if entry is None:
            continue
        if marker == "@revoked":
            revoked.add(entry.key.asbytes())
        elif not marker:
            entries.append(entry)
    host_keys = client.get_host_keys()
    for entry in entries:
        if entry.key.asbytes() not in revoked:
            for name in entry.hostnames:
                host_keys.add(name, entry.key.get_name(), entry.key)
    return frozenset(revoked)


def _known_hosts_lines(files: tuple[Path, ...]) -> Iterator[str]:
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError, UnicodeDecodeError:
            # OpenSSH ignores missing trust files; the server is then unknown and refused.
            continue
        for raw in text.splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                yield line


def _fingerprint(key: PKey) -> str:
    digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    return f"{key.get_name()} SHA256:{digest}"


def _explain(error: BaseException, alias: str) -> str:
    """Describe a connection failure without repeating exception or server text."""
    match error:
        case _UntrustedHostKey(revoked=True):
            return (
                f"The server behind {alias} presented a host key that known_hosts on the "
                "controller host marks as revoked. Barectl did not authenticate."
            )
        case _UntrustedHostKey():
            return (
                f"The controller host does not trust the host key presented for {alias}. "
                "Barectl did not authenticate or record the key. Confirm the server's key "
                "through a trusted channel, add it to known_hosts on the controller host, "
                "then verify the connection again."
            )
        case BadHostKeyException():
            return (
                f"The server behind {alias} presented a different host key from the one "
                "trusted in known_hosts on the controller host. Barectl refused to connect. "
                "The server may have been rebuilt, or the connection may be intercepted. "
                "Confirm the new key through a trusted channel before replacing the old one."
            )
        case TimeoutError():
            return (
                f"The connection to {alias} timed out after {CONNECT_TIMEOUT} seconds. "
                "Check that the server is running and reachable from the controller host."
            )
        case socket.gaierror():
            return f"The controller host could not resolve the host name configured for {alias}."
        case OSError():
            return (
                f"Barectl could not reach the SSH service configured for {alias}. Check its "
                "HostName and Port and that the server accepts connections."
            )
        case _:
            return (
                f"The SSH handshake with {alias} failed or timed out. Check that {alias} "
                "works with ssh from the controller host."
            )


_REJECTED_CREDENTIALS = (
    "The server rejected the SSH credentials available for {alias}. Check that ssh "
    "{alias} works for the account running the Barectl worker, with the same SSH agent "
    "or key files. Barectl cannot use keys that need a passphrase unless they are loaded "
    "in the agent."
)
