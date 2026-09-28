"""Connect to a managed server over SSH with the controller host's credentials and trust.

This is Barectl's only remote execution boundary (see docs/ssh-connections.md).
Authentication uses the key files an alias names, or the default key files, and the SSH
agent in the worker's environment. Host identity comes only from the controller's
known_hosts files: unknown, changed and revoked keys are refused, whatever the SSH
configuration says, and Barectl never records a key. Failures are reported as sanitized
``ConnectionFailed`` messages; remote output, exception text, host names and key paths are
never included.

Remote operations connect with ``connect_alias``, which resolves a registered SSH alias in
the controller's SSH configuration. ``connect`` is the seam behind it: tests substitute
``FakeServer.connect`` there, and the messages here say nothing about what the connection
is used for.
"""

import base64
import binascii
import os
import re
import shlex
import socket
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, override

from django.conf import settings
from paramiko import (
    BadHostKeyException,
    Channel,
    HostKeys,
    MissingHostKeyPolicy,
    PKey,
    SSHClient,
    SSHException,
    Transport,
)
from paramiko.hostkeys import HostKeyEntry, InvalidHostKey
from pyinfra.api.config import Config
from pyinfra.api.exceptions import PyinfraError
from pyinfra.api.host import Host
from pyinfra.api.inventory import Inventory
from pyinfra.api.state import State

from servers.ssh_config import AliasUnusable, ConnectionTarget, resolve_alias

CONNECT_TIMEOUT = 10
COMMAND_TIMEOUT = 15
# The limit for all commands on one connection. A server with many site files and pools
# runs many short commands; together they must finish well before recovery treats the
# remote operation as abandoned (discovery.services.STALE_AFTER).
SESSION_TIMEOUT = 5 * 60
# Observations are small files. Larger output is reported as truncated, not stored.
MAX_OUTPUT = 64 * 1024
MAX_ERROR_OUTPUT = 4 * 1024


class ConnectionFailed(Exception):
    """A sanitized, operator-facing reason a connection or command failed."""


@dataclass(frozen=True)
class CommandResult:
    exit_status: int
    stdout: str
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
        self._session_deadline = time.monotonic() + SESSION_TIMEOUT

    def run(self, command: str) -> CommandResult:
        # The limit covers the whole command, so a server that keeps writing slowly cannot
        # hold the worker; no command runs past the connection's overall limit either.
        now = time.monotonic()
        if now >= self._session_deadline:
            raise ConnectionFailed(_TIMED_OUT_SESSION)
        deadline = min(now + COMMAND_TIMEOUT, self._session_deadline)
        reason = _TIMED_OUT_SESSION if deadline == self._session_deadline else _TIMED_OUT_COMMAND
        # No PTY and no environment: the command runs non-interactively with the SSH
        # user's own permissions.
        stdin, stdout, _ = self._client.exec_command(command, timeout=deadline - now)
        stdin.close()
        channel = stdout.channel
        output = _receive(channel, channel.recv, MAX_OUTPUT + 1, deadline, reason)
        truncated = len(output) > MAX_OUTPUT
        if truncated:
            channel.close()
        else:
            # Drained so the server cannot stall on a full channel; not kept, as error text
            # depends on the server's locale and may quote remote data.
            _receive(channel, channel.recv_stderr, MAX_ERROR_OUTPUT, deadline, reason)
            if not channel.status_event.wait(max(deadline - time.monotonic(), 0)):
                raise ConnectionFailed(reason)
        return CommandResult(
            exit_status=channel.exit_status,
            stdout=output[:MAX_OUTPUT].decode("utf-8", "replace"),
            truncated=truncated,
        )


_TIMED_OUT_COMMAND = (
    f"A remote command did not finish within {COMMAND_TIMEOUT} seconds. Barectl closed "
    "the connection."
)
_TIMED_OUT_SESSION = (
    f"The remote commands did not finish within {SESSION_TIMEOUT // 60} minutes. Barectl "
    "closed the connection."
)


def _receive(
    channel: Channel, receive: Callable[[int], bytes], limit: int, deadline: float, reason: str
) -> bytes:
    """Read up to ``limit`` bytes until end of output, or fail with ``reason`` at ``deadline``."""
    data = bytearray()
    while len(data) < limit:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ConnectionFailed(reason)
        channel.settimeout(remaining)
        try:
            chunk = receive(limit - len(data))
        except TimeoutError:
            raise ConnectionFailed(reason) from None
        if not chunk:
            break
        data += chunk
    return bytes(data)


@contextmanager
def connect_alias(alias: str) -> Iterator[RemoteShell]:
    """Open a verified connection to the server registered as ``alias``; close it on exit.

    The alias is resolved in the controller's SSH configuration each time, and one it no
    longer offers raises ``ConnectionFailed`` before anything connects.
    """
    try:
        target = resolve_alias(settings.SSH_CONFIG_PATH, alias)
    except AliasUnusable as unusable:
        raise ConnectionFailed(str(unusable)) from None
    # Through the module attribute, so a test's substitute for ``connect`` is used.
    with connect(target) as shell:
        yield shell


@contextmanager
def connect(target: ConnectionTarget) -> Iterator[RemoteShell]:
    """Open a verified, authenticated connection to ``target``; close it on exit."""
    client = SSHClient()
    revoked = _load_trust(client, target.known_hosts_files)
    client.set_missing_host_key_policy(_RejectUntrusted(revoked))
    started = time.monotonic()
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
                # paramiko can replace its timeout error with a later key-loading error, so
                # the elapsed time identifies an authentication that waited to the limit.
                waited = time.monotonic() - started >= CONNECT_TIMEOUT
                reason = _AUTH_TIMED_OUT if waited else _REJECTED_CREDENTIALS
                raise ConnectionFailed(reason.format(alias=target.alias)) from None
            raise ConnectionFailed(_explain(error, target.alias)) from None
        transport = client.get_transport()
        if transport is None:
            raise ConnectionFailed(_HANDSHAKE_FAILED.format(alias=target.alias))
        key = transport.get_remote_server_key()
        yield _ParamikoShell(client, f"{key.get_name()} {key.fingerprint}")
    finally:
        client.close()


def _load_trust(client: SSHClient, files: tuple[Path, ...]) -> frozenset[bytes]:
    """Add known_hosts entries to ``client``; return the keys marked ``@revoked``."""
    trusted, revoked = _read_trust(files)
    host_keys = client.get_host_keys()
    for entry in trusted:
        for name in entry.hostnames:
            host_keys.add(name, entry.key.get_name(), entry.key)
    return revoked


def _read_trust(files: tuple[Path, ...]) -> tuple[tuple[HostKeyEntry, ...], frozenset[bytes]]:
    """Read known_hosts entries: those trusted, and the keys marked ``@revoked``.

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
    trusted = tuple(entry for entry in entries if entry.key.asbytes() not in revoked)
    return trusted, frozenset(revoked)


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


@contextmanager
def connect_with_pyinfra(target: ConnectionTarget) -> Iterator[RemoteShell]:
    """Open a verified connection to ``target`` through pyinfra's SSH connector.

    The same contract as ``connect``. pyinfra connects with a fresh inventory and state for
    each call and never reads the controller's SSH configuration: the alias was resolved
    by ``servers.ssh_config``, and only the resolved settings are passed on. Trust comes
    from a private copy of the alias's known_hosts entries without revoked keys, and host
    keys are checked strictly, so pyinfra never records or accepts an unknown key.
    """
    trusted, revoked = _read_trust(target.known_hosts_files)
    try:
        sock = socket.create_connection((target.hostname, target.port), CONNECT_TIMEOUT)
    except OSError as error:
        raise ConnectionFailed(_explain(error, target.alias)) from None
    transports: list[Transport] = []

    def transport_factory(
        sock: socket.socket, disabled_algorithms: dict[str, Iterable[str]] | None = None
    ) -> Transport:
        # Kept so the presented host key can be reported and the connection closed.
        transport = Transport(sock, disabled_algorithms=disabled_algorithms)
        transports.append(transport)
        return transport

    with (
        closing(sock),
        tempfile.TemporaryDirectory(prefix="barectl-trust-") as directory,
    ):
        # A new file each time: pyinfra keeps the host keys it loaded for each file name.
        known_hosts = Path(directory) / "known_hosts"
        known_hosts.write_text(
            "".join(entry.to_line() or "" for entry in trusted), encoding="utf-8"
        )
        host = _pyinfra_host(target, known_hosts, sock, transport_factory)
        started = time.monotonic()
        try:
            try:
                host.connect(show_errors=False, raise_exceptions=True)
            except PyinfraError:
                transport = transports[-1] if transports else None
                raise ConnectionFailed(
                    _refusal(target, transport, trusted, revoked, started)
                ) from None
            transport = transports[-1]
            key = transport.get_remote_server_key()
            yield _PyinfraShell(
                host, transport, f"{key.get_name()} {key.fingerprint}", target.alias
            )
        finally:
            host.disconnect()
            for transport in transports:
                transport.close()


type _TransportFactory = Callable[[socket.socket, dict[str, Iterable[str]] | None], Transport]


def _pyinfra_host(
    target: ConnectionTarget,
    known_hosts: Path,
    sock: socket.socket,
    transport_factory: _TransportFactory,
) -> Host:
    """Build a fresh one-host pyinfra inventory and state for ``target``."""
    data: dict[str, object] = {
        "ssh_hostname": target.hostname,
        "ssh_port": target.port,
        # No SSH configuration is read: every setting comes from the resolved alias.
        "ssh_config_file": os.devnull,
        "ssh_known_hosts_file": str(known_hosts),
        "ssh_strict_host_key_checking": "yes",
        "ssh_forward_agent": False,
        "ssh_connect_retries": 0,
        # Documented as keyword arguments for paramiko's SSHClient.connect.
        "ssh_paramiko_connect_kwargs": {
            "sock": sock,
            "transport_factory": transport_factory,
            "key_filename": [str(path) for path in target.identity_files if path.is_file()] or None,
            # OpenSSH tries the default key files only when an alias names none.
            "look_for_keys": not target.identity_files,
            "allow_agent": True,
            "timeout": CONNECT_TIMEOUT,
            "banner_timeout": CONNECT_TIMEOUT,
            "auth_timeout": CONNECT_TIMEOUT,
            "channel_timeout": CONNECT_TIMEOUT,
        },
    }
    if target.user:
        data["ssh_user"] = target.user
    inventory = Inventory(([(target.alias, data)], {}))  # type: ignore[no-untyped-call]
    state = State(inventory, Config(CONNECT_TIMEOUT=CONNECT_TIMEOUT))  # type: ignore[no-untyped-call]
    return state.inventory.get_host(target.alias)


def _refusal(
    target: ConnectionTarget,
    transport: Transport | None,
    trusted: tuple[HostKeyEntry, ...],
    revoked: frozenset[bytes],
    started: float,
) -> str:
    """Explain why pyinfra could not connect, from what the SSH negotiation reached."""
    if transport is None or not transport.initial_kex_done:
        return _HANDSHAKE_FAILED.format(alias=target.alias)
    key = transport.get_remote_server_key()
    if key.asbytes() in revoked:
        return _explain(_UntrustedHostKey(revoked=True), target.alias)
    host_keys = HostKeys()
    for entry in trusted:
        for name in entry.hostnames:
            host_keys.add(name, entry.key.get_name(), entry.key)
    # paramiko's lookup name: a nondefault port is part of it.
    name = target.hostname if target.port == 22 else f"[{target.hostname}]:{target.port}"
    known = host_keys.lookup(name)
    if known is None:
        return _explain(_UntrustedHostKey(revoked=False), target.alias)
    if known.get(key.get_name()) != key:
        return _explain(BadHostKeyException(name, key, next(iter(known.values()))), target.alias)
    # The host key was verified, so authentication failed or waited to the limit.
    waited = time.monotonic() - started >= CONNECT_TIMEOUT
    reason = _AUTH_TIMED_OUT if waited else _REJECTED_CREDENTIALS
    return reason.format(alias=target.alias)


# pyinfra reports whether a command succeeded, not its exit status, and reads output as
# lines of text without a limit. Each command therefore runs in this POSIX sh wrapper: the
# command runs in its own shell with its error output discarded, at most MAX_OUTPUT + 1
# bytes of its output are kept and encoded as base64, and a last line gives the command's
# exit status and the encoder's. base64 contains no spaces, so remote output cannot imitate
# that line, and the exact bytes survive pyinfra's line handling. The wrapper always exits
# 0, so pyinfra never retries a command. Nothing is written on the server.
_WRAPPER = (
    "exec 3>&1; "
    's=$( { { sh -c {command} 3>&- 4>&-; echo "$?" >&4; } 2>/dev/null'
    " | head -c {limit} | base64 >&3; } 4>&1 ); "
    'printf "\\nexit %s %s\\n" "$s" "$?"'
)
_RESULT = re.compile(r"exit (\d{1,3}) (\d{1,3})")
MAX_EXIT_STATUS = 255


def _wrap(command: str) -> str:
    return _WRAPPER.replace("{command}", shlex.quote(command)).replace(
        "{limit}", str(MAX_OUTPUT + 1)
    )


def _unwrap(lines: list[str], alias: str) -> CommandResult:
    """Decode the wrapper's output; anything else means the command did not finish."""
    lines = [line for line in lines if line]
    status = _RESULT.fullmatch(lines[-1]) if lines else None
    if status is None or status[2] != "0" or int(status[1]) > MAX_EXIT_STATUS:
        raise ConnectionFailed(_UNREADABLE_RESULT.format(alias=alias))
    try:
        output = base64.b64decode("".join(lines[:-1]), validate=True)
    except binascii.Error:
        raise ConnectionFailed(_UNREADABLE_RESULT.format(alias=alias)) from None
    return CommandResult(
        exit_status=int(status[1]),
        stdout=output[:MAX_OUTPUT].decode("utf-8", "replace"),
        truncated=len(output) > MAX_OUTPUT,
    )


class _PyinfraShell:
    def __init__(self, host: Host, transport: Transport, host_key: str, alias: str) -> None:
        self._host = host
        self._transport = transport
        self.host_key = host_key
        self._alias = alias
        self._session_deadline = time.monotonic() + SESSION_TIMEOUT
        # Why the connection was closed at a limit, after which nothing more is sent.
        self._stopped = ""

    def run(self, command: str) -> CommandResult:
        now = time.monotonic()
        if self._stopped or now >= self._session_deadline:
            raise ConnectionFailed(self._stopped or _TIMED_OUT_SESSION)
        deadline = min(now + COMMAND_TIMEOUT, self._session_deadline)
        reason = _TIMED_OUT_SESSION if deadline == self._session_deadline else _TIMED_OUT_COMMAND
        # pyinfra waits for output without a limit of its own, so closing the connection
        # at the deadline is what ends a command that is still running or writing.
        timer = threading.Timer(deadline - now, self._stop, args=(reason,))
        timer.daemon = True
        timer.start()
        try:
            # No PTY, environment, sudo or other privilege change: pyinfra's defaults.
            _, output = self._host.run_shell_command(
                _wrap(command), _timeout=deadline - now, print_output=False, print_input=False
            )
        except TimeoutError:
            self._stop(reason)
        except SSHException, OSError, EOFError:
            self._stop(_UNREADABLE_RESULT.format(alias=self._alias))
        finally:
            timer.cancel()
        if self._stopped:
            raise ConnectionFailed(self._stopped)
        return _unwrap(output.stdout_lines, self._alias)

    def _stop(self, reason: str) -> None:
        # The first reason stands: closing at a deadline makes the command itself fail.
        self._stopped = self._stopped or reason
        self._transport.close()


_UNREADABLE_RESULT = (
    "The connection to {alias} ended before a remote command finished, or its result could "
    "not be read. Barectl closed the connection."
)


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
            return _HANDSHAKE_FAILED.format(alias=alias)


_HANDSHAKE_FAILED = (
    "The SSH handshake with {alias} failed or timed out. Check that {alias} works with ssh "
    "from the controller host."
)
_AUTH_TIMED_OUT = (
    "Authentication for {alias} did not finish within "
    f"{CONNECT_TIMEOUT} seconds. Check that the SSH agent available to the Barectl worker "
    "responds without waiting for a prompt or a hardware key touch."
)
_REJECTED_CREDENTIALS = (
    "The server rejected the SSH credentials available for {alias}. Check that ssh "
    "{alias} works for the account running the Barectl worker, with the same SSH agent "
    "or key files. Barectl cannot use keys that need a passphrase unless they are loaded "
    "in the agent."
)
