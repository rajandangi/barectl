"""Discovery through the default connection, the durable worker and a real SSH server.

The in-process SSH server from ``test_ssh`` runs each command with the local ``/bin/sh``, so
the worker drives the production pyinfra connection without substitution: stalls, dropped
connections, refused trust and a forced worker stop reach the attempt lifecycle and the
pages as they would in production.
Discovery reads this machine through that server; the tests assert outcomes, not what the
machine holds.
"""

import io
import logging
import os
import signal
import tempfile
import threading
import time
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import ClassVar, override
from unittest import mock

from paramiko import ECDSAKey, PKey

from servers.models import Server
from servers.testing import ControllerConfigTestCase

from . import ssh
from .fakes import run_worker
from .models import DiscoveryAttempt, DiscoverySnapshot
from .services import INTERRUPTED_FAILURE
from .test_ssh import USER, SshServer

ALIAS = "web.example.com"


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[str] = []

    @override
    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(self.format(record))


class TransportWorkflowTests(ControllerConfigTestCase):
    host_key: ClassVar[PKey]
    client_key: ClassVar[PKey]
    directory: Path
    server: SshServer

    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.host_key = ECDSAKey.generate()
        cls.client_key = ECDSAKey.generate()

    @override
    def setUp(self) -> None:
        super().setUp()
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": ""}))
        self.server = SshServer(self.host_key, self.client_key)
        self.addCleanup(self.server.close)
        self.known_hosts = self.directory / "known_hosts"
        self.write_config(self.host_entry(ALIAS, self.server, self.client_key, self.known_hosts))
        self.grant("view_server", "add_server", "add_discoveryattempt")
        self.client.force_login(self.user)

    def host_entry(self, alias: str, server: SshServer, key: PKey, known_hosts: Path) -> str:
        """An alias for ``server`` with its own key file and trust file."""
        key_file = self.directory / f"{alias}.key"
        key.write_private_key_file(str(key_file))
        known_hosts.write_text(
            f"[127.0.0.1]:{server.port} {server.host_key.get_name()} "
            f"{server.host_key.get_base64()}\n",
            encoding="utf-8",
        )
        return (
            f"Host {alias}\n"
            "  HostName 127.0.0.1\n"
            f"  Port {server.port}\n"
            f"  User {USER}\n"
            f"  IdentityFile {key_file}\n"
            f"  UserKnownHostsFile {known_hosts}\n"
        )

    def discover(self) -> Server:
        """Register the server and run the worker; the first attempt must succeed."""
        self.client.post("/servers/add/", {"name": "Web", "ssh_alias": ALIAS})
        run_worker()
        server = Server.objects.get()
        self.assertEqual(self.latest(server).status, DiscoveryAttempt.Status.SUCCEEDED)
        return server

    def refresh(self, server: Server) -> DiscoveryAttempt:
        self.client.post(f"/servers/{server.pk}/verify/")
        run_worker()
        return self.latest(server)

    @staticmethod
    def latest(server: Server) -> DiscoveryAttempt:
        return server.discovery_attempts.latest("queued_at", "pk")

    def assert_previous_snapshot_kept(self, server: Server, snapshot: DiscoverySnapshot) -> None:
        """The failed attempt published nothing, and the page labels the old snapshot."""
        self.assertEqual(DiscoverySnapshot.objects.get().pk, snapshot.pk)
        page = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(page, "may be out of date")
        self.assertContains(page, f'datetime="{snapshot.collected_at.isoformat()}"')
        self.assertContains(page, "Retry connection check")

    def assert_disconnected(self, *servers: SshServer) -> None:
        """Wait for the servers, by default the test's own, to see every session closed."""
        transports = [
            transport for server in servers or (self.server,) for transport in server.transports
        ]
        deadline = time.monotonic() + 5
        while any(transport.is_active() for transport in transports):
            if time.monotonic() > deadline:
                self.fail("The worker left its connection open.")
            time.sleep(0.05)

    def test_a_stalled_refresh_fails_keeps_the_snapshot_and_waits_for_retry(self) -> None:
        server = self.discover()
        snapshot = DiscoverySnapshot.objects.get()
        self.server.stalled = True
        started = time.monotonic()
        with mock.patch.object(ssh, "COMMAND_TIMEOUT", 0.5):
            attempt = self.refresh(server)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("A remote command did not finish within", attempt.failure)
        self.assert_previous_snapshot_kept(server, snapshot)
        self.assert_disconnected()
        # No automatic replay: the failure stays until the operator retries.
        run_worker()
        self.assertEqual(server.discovery_attempts.count(), 2)

        self.server.stalled = False
        retried = self.refresh(server)
        self.assertEqual(retried.status, DiscoveryAttempt.Status.SUCCEEDED)
        self.assertNotEqual(DiscoverySnapshot.objects.get().pk, snapshot.pk)

    def test_a_dropped_connection_is_a_failure_not_a_partial_snapshot(self) -> None:
        server = self.discover()
        snapshot = DiscoverySnapshot.objects.get()
        self.server.disconnecting = True
        attempt = self.refresh(server)
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("ended before a remote command finished", attempt.failure)
        self.assert_previous_snapshot_kept(server, snapshot)

    def test_refused_trust_and_credentials_fail_with_fixed_guidance(self) -> None:
        server = self.discover()
        snapshot = DiscoverySnapshot.objects.get()
        trusted = self.known_hosts.read_text(encoding="utf-8")
        self.known_hosts.write_text("", encoding="utf-8")
        attempt = self.refresh(server)
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn(f"does not trust the host key presented for {ALIAS}", attempt.failure)
        self.assertEqual(self.known_hosts.read_text(encoding="utf-8"), "")
        self.assert_previous_snapshot_kept(server, snapshot)

        self.known_hosts.write_text(trusted, encoding="utf-8")
        self.server.authorized = ECDSAKey.generate()
        attempt = self.refresh(server)
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn(f"rejected the SSH credentials available for {ALIAS}", attempt.failure)
        self.assert_previous_snapshot_kept(server, snapshot)

    def test_a_forced_worker_stop_interrupts_the_attempt_and_its_connection(self) -> None:
        server = self.discover()
        snapshot = DiscoverySnapshot.objects.get()
        self.server.stalled = True
        # A second stop signal makes db_worker exit in the middle of the task.
        pid = os.getpid()
        stops = [threading.Timer(delay, os.kill, args=(pid, signal.SIGTERM)) for delay in (1, 1.2)]
        for stop in stops:
            stop.start()
        self.client.post(f"/servers/{server.pk}/verify/")
        started = time.monotonic()
        run_worker()
        self.assertLess(time.monotonic() - started, 5)
        attempt = self.latest(server)
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertEqual(attempt.failure, INTERRUPTED_FAILURE)
        self.assert_previous_snapshot_kept(server, snapshot)
        self.assert_disconnected()

        # The next attempt starts from fresh connection state.
        self.server.stalled = False
        self.assertEqual(self.refresh(server).status, DiscoveryAttempt.Status.SUCCEEDED)

    def test_failures_reveal_no_connection_details_or_remote_output(self) -> None:
        capture = _Capture()
        root = logging.getLogger()
        root.addHandler(capture)
        self.addCleanup(root.removeHandler, capture)
        previous = root.level
        root.setLevel(logging.DEBUG)
        self.addCleanup(root.setLevel, previous)
        output = io.StringIO()
        with redirect_stderr(output), redirect_stdout(output):
            server = self.discover()
            self.server.disconnecting = True
            self.refresh(server)
            self.server.disconnecting = False
            self.server.stalled = True
            with mock.patch.object(ssh, "COMMAND_TIMEOUT", 0.5):
                self.refresh(server)
            self.server.stalled = False
            self.known_hosts.write_text("", encoding="utf-8")
            self.refresh(server)
        page = self.client.get(f"/servers/{server.pk}/").content.decode()
        activity = self.client.get("/activity/").content.decode()
        failures = "\n".join(
            attempt.failure for attempt in server.discovery_attempts.exclude(failure="")
        )
        self.assertEqual(server.discovery_attempts.exclude(failure="").count(), 3)
        revealed = [
            "127.0.0.1",
            str(self.server.port),
            str(self.directory),
            USER,
            # The partial output the dropped connection sent.
            "ID=ubu",
        ]
        for text in (*capture.records, output.getvalue(), failures, page, activity):
            for detail in revealed:
                self.assertNotIn(detail, text)

    def test_one_worker_keeps_servers_and_attempts_apart(self) -> None:
        """Successive attempts and different servers share no connection, key or trust."""
        other_key = ECDSAKey.generate()
        other = SshServer(ECDSAKey.generate(), other_key)
        self.addCleanup(other.close)
        other_trust = self.directory / "other_known_hosts"
        self.write_config(
            self.host_entry(ALIAS, self.server, self.client_key, self.known_hosts)
            + self.host_entry("db.example.com", other, other_key, other_trust)
        )
        for name, alias in (("Web", ALIAS), ("Database", "db.example.com")):
            self.client.post("/servers/add/", {"name": name, "ssh_alias": alias})
        run_worker()
        web = Server.objects.get(name="Web")
        database = Server.objects.get(name="Database")
        for server, remote in ((web, self.server), (database, other)):
            attempt = self.latest(server)
            self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
            key = remote.host_key
            self.assertEqual(attempt.host_key, f"{key.get_name()} {key.fingerprint}")
            # Each server was offered only its own alias's key.
            self.assertEqual(set(remote.offered), {remote.authorized})

        # Withdrawing trust in one server affects only that server's next attempt.
        other_trust.write_text("", encoding="utf-8")
        for server in (web, database):
            self.client.post(f"/servers/{server.pk}/verify/")
        run_worker()
        self.assertEqual(self.latest(web).status, DiscoveryAttempt.Status.SUCCEEDED)
        refused = self.latest(database)
        self.assertEqual(refused.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("does not trust the host key presented for db.example.com", refused.failure)
        # Every attempt opened its own connection, and none is left open.
        self.assertEqual((len(self.server.transports), len(other.transports)), (2, 2))
        self.assert_disconnected(self.server, other)
