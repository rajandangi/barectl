"""The registration-to-result workflow through Django requests and the durable worker.

Real views, services, persistence, alias resolution and the ``db_worker`` command run;
only remote execution is substituted, at ``discovery.ssh.connect``.
"""

import re
import signal
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import ClassVar, override
from unittest import mock

from django.core.management import call_command
from django.db import IntegrityError, transaction
from django.test import Client
from django_tasks_db.models import DBTaskResult

from servers.models import Server
from servers.ssh_config import ConnectionTarget
from servers.tests import HTMX_FRAGMENT, ControllerConfigTestCase

from . import ssh
from .models import DiscoveryAttempt, DiscoverySnapshot
from .services import request_discovery

UBUNTU = """\
PRETTY_NAME="Ubuntu 24.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.3 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
"""
HOST_KEY = "ssh-ed25519 SHA256:bZs0Sdo5mnU6ixaSbHkq9ZvXVsP1pxEmGZ0M8oPq3dE"
READ_ONLY = re.compile(r"\A(cat|test -e|test -r) /(etc|usr/lib)/os-release\Z")


@dataclass
class FakeServer:
    """A managed server as seen through ``RemoteShell``, recording every command."""

    files: dict[str, str] = field(default_factory=lambda: {"/etc/os-release": UBUNTU})
    unreadable: set[str] = field(default_factory=set)
    failure: str = ""
    host_key: str = HOST_KEY
    targets: list[ConnectionTarget] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)

    @contextmanager
    def connect(self, target: ConnectionTarget) -> Iterator[ssh.RemoteShell]:
        self.targets.append(target)
        if self.failure:
            raise ssh.ConnectionFailed(self.failure)
        yield self

    def run(self, command: str) -> ssh.CommandResult:
        self.commands.append(command)
        verb, _, path = command.rpartition(" ")
        exists = path in self.files or path in self.unreadable
        readable = path in self.files
        if verb == "test -e":
            return ssh.CommandResult(0 if exists else 1, "")
        if verb == "test -r":
            return ssh.CommandResult(0 if readable else 1, "")
        if readable:
            return ssh.CommandResult(0, self.files[path])
        return ssh.CommandResult(1, "")


def run_worker() -> None:
    """Run the durable worker until the queue is empty, as `manage.py db_worker` does."""
    # The worker installs its own signal handlers; restore the test runner's afterwards.
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        call_command("db_worker", batch=True, startup_delay=False, interval=0, verbosity=0)
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


class DiscoveryTestCase(ControllerConfigTestCase):
    remote: FakeServer

    @override
    def setUp(self) -> None:
        super().setUp()
        self.remote = FakeServer()
        self.enterContext(mock.patch.object(ssh, "connect", self.remote.connect))

    def sign_in_with(self, *codenames: str) -> None:
        self.grant(*codenames)
        self.client.force_login(self.user)

    def run_worker(self) -> None:
        run_worker()

    def register(self, name: str = "Web", alias: str = "web.example.com") -> Server:
        self.sign_in_with("view_server", "add_server")
        self.client.post("/servers/add/", {"name": name, "ssh_alias": alias})
        return Server.objects.get(name=name)


class RegistrationDiscoveryTests(DiscoveryTestCase):
    def test_registration_queues_work_that_the_worker_completes(self) -> None:
        server = self.register()
        # The request only queued the work; nothing connected during it.
        attempt = DiscoveryAttempt.objects.get()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.QUEUED)
        self.assertEqual(attempt.ssh_alias, "web.example.com")
        self.assertEqual(self.remote.targets, [])
        self.assertTrue(DBTaskResult.objects.filter(status="READY").exists())
        page = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(page, "Connection check queued")
        self.assertContains(page, 'hx-trigger="every 2s"')
        self.assertContains(page, "No observations yet.")

        self.run_worker()

        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED)
        self.assertEqual(attempt.host_key, HOST_KEY)
        self.assertIsNotNone(attempt.started_at)
        self.assertIsNotNone(attempt.finished_at)
        (target,) = self.remote.targets
        self.assertEqual(
            (target.alias, target.hostname, target.user),
            ("web.example.com", "203.0.113.10", "deploy"),
        )
        snapshot = DiscoverySnapshot.objects.get()
        self.assertEqual(snapshot.attempt, attempt)
        self.assertEqual(
            (snapshot.os_pretty_name, snapshot.os_id, snapshot.os_version_id, snapshot.os_source),
            ("Ubuntu 24.04.3 LTS", "ubuntu", "24.04", "/etc/os-release"),
        )
        page = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(page, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertContains(page, "<dd>24.04</dd>", html=True)
        self.assertContains(page, "from <code>/etc/os-release</code>")
        self.assertContains(page, f"<code>{HOST_KEY}</code>")
        self.assertContains(page, "This is a snapshot, not live status.")
        self.assertContains(page, f'datetime="{snapshot.collected_at.isoformat()}"')
        self.assertNotContains(page, "hx-trigger")
        # Remote output that Barectl does not display is not stored.
        self.assertNotContains(page, "Noble Numbat")
        self.assertContains(self.client.get("/"), "<td>Verified</td>", html=True)

    def test_discovery_runs_only_read_only_commands_without_sudo(self) -> None:
        self.remote.files = {"/usr/lib/os-release": UBUNTU}
        self.remote.unreadable = {"/etc/os-release"}
        config_before = self.ssh_config.read_bytes()
        self.register()
        self.run_worker()
        self.assertTrue(self.remote.commands)
        for command in self.remote.commands:
            self.assertRegex(command, READ_ONLY)
        # Nor does Barectl change the controller's SSH configuration.
        self.assertEqual(self.ssh_config.read_bytes(), config_before)

    def test_worker_refuses_aliases_removed_before_it_runs(self) -> None:
        server = self.register()
        self.write_config("Host db-1\n")
        self.run_worker()
        attempt = DiscoveryAttempt.objects.get()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("The SSH alias web.example.com", attempt.failure)
        self.assertEqual(self.remote.targets, [])
        page = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(page, "Connection failed")
        self.assertContains(page, "It is no longer a Host entry.")

    def test_aliases_that_connect_differently_from_ssh_are_refused(self) -> None:
        self.register()
        # The configuration changed after registration; the worker reads it again.
        self.write_config("Host web.example.com\n  ProxyJump bastion\n  IdentityAgent /tmp/a\n")
        self.run_worker()
        attempt = DiscoveryAttempt.objects.get()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("uses IdentityAgent, ProxyJump, which Barectl cannot", attempt.failure)
        self.assertNotIn("bastion", attempt.failure)
        self.assertEqual(self.remote.targets, [])

    def test_connection_failures_are_shown_without_a_snapshot(self) -> None:
        self.remote.failure = "The controller host does not trust the host key presented."
        server = self.register()
        self.run_worker()
        self.assertEqual(DiscoveryAttempt.objects.get().status, DiscoveryAttempt.Status.FAILED)
        self.assertFalse(DiscoverySnapshot.objects.exists())
        page = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(page, "does not trust the host key presented.")
        self.assertContains(page, "No observations yet.")
        self.assertContains(self.client.get("/"), "<td>Connection failed</td>", html=True)

    def test_unexpected_errors_are_recorded_without_their_details(self) -> None:
        def broken(target: ConnectionTarget) -> Iterator[ssh.RemoteShell]:
            raise RuntimeError("password=hunter2 from remote output")

        self.register()
        with (
            mock.patch.object(ssh, "connect", broken),
            self.assertLogs("discovery.services", "ERROR") as logs,
        ):
            self.run_worker()
        attempt = DiscoveryAttempt.objects.get()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertNotIn("hunter2", attempt.failure)
        self.assertIn("unexpected error", attempt.failure)
        message = f"Discovery attempt {attempt.pk} failed unexpectedly: RuntimeError"
        self.assertEqual(logs.output, [f"ERROR:discovery.services:{message}"])
        self.assertNotIn("hunter2", str(DBTaskResult.objects.values_list("traceback", flat=True)))


class PartialObservationTests(DiscoveryTestCase):
    def discover(self) -> DiscoverySnapshot:
        server = self.register()
        self.run_worker()
        self.page = self.client.get(f"/servers/{server.pk}/")
        return DiscoverySnapshot.objects.get()

    def test_unreadable_release_file_is_inaccessible_not_absent(self) -> None:
        self.remote.files = {}
        self.remote.unreadable = {"/etc/os-release"}
        snapshot = self.discover()
        self.assertEqual(snapshot.os_status, "inaccessible")
        self.assertEqual(snapshot.os_pretty_name, "")
        self.assertContains(self.page, "<strong>Inaccessible:</strong>", html=True)
        self.assertContains(self.page, "cannot read /etc/os-release. Barectl does not use sudo.")
        # The connection itself was verified; the warning belongs to the snapshot.
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)

    def test_missing_release_files_are_absent(self) -> None:
        self.remote.files = {}
        snapshot = self.discover()
        self.assertEqual(snapshot.os_status, "absent")
        self.assertContains(self.page, "neither /etc/os-release nor /usr/lib/os-release")

    def test_fallback_release_file_is_used(self) -> None:
        self.remote.files = {"/usr/lib/os-release": 'NAME="Debian GNU/Linux"\nID=debian\n'}
        snapshot = self.discover()
        self.assertEqual(
            (snapshot.os_status, snapshot.os_source), ("observed", "/usr/lib/os-release")
        )
        self.assertContains(self.page, "<dd>Debian GNU/Linux</dd>", html=True)
        self.assertContains(self.page, "<dd>Not reported</dd>", html=True)

    def test_unrecognized_content_is_unsupported(self) -> None:
        self.remote.files = {"/etc/os-release": "<html>not a release file</html>\nX=$(id)\n"}
        snapshot = self.discover()
        self.assertEqual(snapshot.os_status, "unsupported")
        self.assertContains(self.page, "<strong>Unsupported:</strong>", html=True)
        self.assertNotContains(self.page, "not a release file")

    def test_values_are_unquoted_bounded_and_never_executed(self) -> None:
        self.remote.files = {
            "/etc/os-release": (
                "# comment\nNAME='Example $(touch /tmp/x)'\nID=example\n"
                f'PRETTY_NAME="{"x" * 500}"\nVERSION_ID="1\\"2"\nBROKEN="unterminated\n'
            )
        }
        snapshot = self.discover()
        self.assertEqual(snapshot.os_name, "Example $(touch /tmp/x)")
        self.assertEqual(len(snapshot.os_pretty_name), 200)
        self.assertEqual(snapshot.os_version_id, '1"2')


class VerifyConnectionTests(DiscoveryTestCase):
    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def verify_url(self) -> str:
        return f"/servers/{self.server.pk}/verify/"

    def test_verification_requires_permission_and_post(self) -> None:
        self.assertRedirects(
            self.client.post(self.verify_url()), f"/accounts/login/?next={self.verify_url()}"
        )
        self.sign_in_with("view_server")
        self.assertEqual(self.client.post(self.verify_url()).status_code, 403)
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertNotContains(page, "Verify connection")
        self.grant("add_discoveryattempt")
        self.assertEqual(self.client.get(self.verify_url()).status_code, 405)
        self.assertFalse(DiscoveryAttempt.objects.exists())

    def test_verification_requires_csrf(self) -> None:
        self.grant("view_server", "add_discoveryattempt")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        self.assertEqual(client.post(self.verify_url()).status_code, 403)
        self.assertFalse(DiscoveryAttempt.objects.exists())

    def test_explicit_verification_queues_one_attempt(self) -> None:
        self.sign_in_with("view_server", "add_discoveryattempt")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "<strong>Not verified.</strong>", html=True)
        self.assertContains(page, "Verify connection")
        response = self.client.post(self.verify_url())
        self.assertRedirects(response, f"/servers/{self.server.pk}/", fetch_redirect_response=False)
        # Repeated submissions share the active attempt instead of queueing another.
        self.client.post(self.verify_url())
        self.client.post(self.verify_url(), headers=HTMX_FRAGMENT)
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)
        self.assertEqual(DBTaskResult.objects.count(), 1)
        self.run_worker()
        self.assertEqual(self.remote.targets[0].alias, "web.example.com")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "<strong>Verified</strong>", html=True)
        # Refreshing a verified server is not offered, nor accepted from a direct request.
        self.assertNotContains(page, "Verify connection")
        response = self.client.post(self.verify_url(), follow=True)
        self.assertContains(response, "already verified this connection")
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)

    def test_htmx_verification_returns_a_polling_fragment_and_announces_changes(self) -> None:
        self.sign_in_with("view_server", "add_discoveryattempt")
        response = self.client.post(self.verify_url(), headers=HTMX_FRAGMENT)
        content = response.content.decode()
        self.assertNotIn("<html", content)
        self.assertRegex(content, r'<div id="discovery"[^>]*hx-trigger="every 2s"')
        self.assertIn(f"/servers/{self.server.pk}/discovery/?shown=queued", content)
        self.assertIn('<hx-partial hx-target="#discovery-announcement"', content)
        self.assertIn("Connection check queued.", content)
        poll = f"/servers/{self.server.pk}/discovery/?shown=queued"
        self.assertRegex(
            content, r'<hx-partial hx-target="#connection-status"[^>]*>\s*Connection check queued'
        )
        unchanged = self.client.get(poll, headers=HTMX_FRAGMENT).content.decode()
        self.assertNotIn("hx-partial", unchanged)
        self.run_worker()
        finished = self.client.get(poll, headers=HTMX_FRAGMENT)
        self.assertNotContains(finished, "hx-trigger")
        self.assertContains(finished, "Connection verified.")
        # The Status row above the fragment changes with it.
        self.assertRegex(
            finished.content.decode(),
            r'<hx-partial hx-target="#connection-status"[^>]*>\s*Verified\s*</hx-partial>',
        )
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, '<dd id="connection-status">Verified</dd>', html=True)
        self.assertContains(finished, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertIn("HX-Request-Type", finished.headers["Vary"])
        # A plain request for the fragment URL gets the complete page.
        self.assertRedirects(
            self.client.get(f"/servers/{self.server.pk}/discovery/"),
            f"/servers/{self.server.pk}/",
        )

    def test_failed_verification_can_be_retried(self) -> None:
        self.remote.failure = "The server rejected the SSH credentials available for web."
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.client.post(self.verify_url())
        self.run_worker()
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "rejected the SSH credentials")
        self.assertContains(page, "Verify connection")
        self.remote.failure = ""
        self.client.post(self.verify_url())
        self.run_worker()
        self.assertEqual(
            list(DiscoveryAttempt.objects.values_list("status", flat=True)),
            ["succeeded", "failed"],
        )

    def test_servers_without_an_alias_cannot_be_verified(self) -> None:
        legacy = Server.objects.create(name="Legacy", legacy_connection="deploy@web:22")
        self.sign_in_with("view_server", "add_discoveryattempt")
        page = self.client.get(f"/servers/{legacy.pk}/")
        self.assertContains(page, "Barectl cannot connect until you edit this server")
        self.assertNotContains(page, "Verify connection")
        response = self.client.post(f"/servers/{legacy.pk}/verify/", follow=True)
        self.assertContains(response, "Choose an SSH alias before verifying the connection.")
        self.assertFalse(DiscoveryAttempt.objects.exists())

    def test_persistence_allows_one_active_attempt_per_server(self) -> None:
        request_discovery(self.server)
        for status in DiscoveryAttempt.ACTIVE:
            with (
                self.subTest(status=status),
                self.assertRaises(IntegrityError),
                transaction.atomic(),
            ):
                DiscoveryAttempt.objects.create(server=self.server, ssh_alias="x", status=status)
        DiscoveryAttempt.objects.create(server=self.server, ssh_alias="x", status="failed")
        # Other servers are independent.
        other = Server.objects.create(name="Other", ssh_alias="db-1")
        self.assertNotEqual(request_discovery(other), request_discovery(self.server))

    def test_unknown_servers_are_not_found(self) -> None:
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.assertEqual(self.client.get("/servers/999/").status_code, 404)
        self.assertEqual(self.client.post("/servers/999/verify/").status_code, 404)

    def test_detail_requires_view_permission(self) -> None:
        url = f"/servers/{self.server.pk}/"
        self.assertRedirects(self.client.get(url), f"/accounts/login/?next={url}")
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(url).status_code, 403)
        response = self.client.get(f"{url}discovery/", headers=HTMX_FRAGMENT)
        self.assertEqual(response.headers["HX-Refresh"], "true")


class AliasChangeTests(DiscoveryTestCase):
    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def edit(self, name: str, alias: str) -> None:
        self.response = self.client.post(
            f"/servers/{self.server.pk}/edit/", {"name": name, "ssh_alias": alias}
        )

    def test_renaming_does_not_queue_a_check(self) -> None:
        self.sign_in_with("view_server", "change_server")
        self.edit("Renamed", "web.example.com")
        self.assertFalse(DiscoveryAttempt.objects.exists())

    def test_alias_cannot_change_while_a_check_is_active(self) -> None:
        request_discovery(self.server)
        self.sign_in_with("view_server", "change_server")
        self.edit("Web", "db-1")
        self.assertContains(self.response, "Change it after the check finishes.", count=2)
        self.server.refresh_from_db()
        self.assertEqual(self.server.ssh_alias, "web.example.com")
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)

    def test_a_failed_check_keeps_the_earlier_snapshot(self) -> None:
        request_discovery(self.server)
        self.run_worker()
        self.sign_in_with("view_server", "change_server")
        self.edit("Web", "db-1")
        self.remote.failure = "Barectl could not reach the SSH service configured for db-1."
        self.run_worker()
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Connection failed")
        self.assertContains(page, "could not reach the SSH service configured for db-1.")
        # The observations collected through the earlier alias remain, labeled as such.
        self.assertContains(page, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertContains(page, "over SSH alias <code>web.example.com</code>")
        self.assertContains(page, "The latest connection check failed, so these observations")
        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
