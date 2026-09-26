"""The registration-to-result workflow through Django requests and the durable worker.

Real views, services, persistence, alias resolution and the ``db_worker`` command run;
only remote execution is substituted, at ``discovery.ssh.connect``.
"""

import datetime
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
from django.utils import timezone
from django_tasks_db.models import DBTaskResult

from servers.models import Server
from servers.ssh_config import ConnectionTarget
from servers.tests import HTMX_FRAGMENT, ControllerConfigTestCase

from . import services, ssh
from .models import DiscoveryAttempt, DiscoverySnapshot
from .services import (
    INTERRUPTED_FAILURE,
    STALE_AFTER,
    recover_stale_attempts,
    request_discovery,
)

UBUNTU = """\
PRETTY_NAME="Ubuntu 24.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.3 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
"""
MEMINFO = """\
MemTotal:        4024548 kB
MemFree:         1234567 kB
MemAvailable:    2345678 kB
"""
DF_OUTPUT = """\
      Size      Avail Target
 53689778176 48190049280 /
"""
HOST_KEY = "ssh-ed25519 SHA256:bZs0Sdo5mnU6ixaSbHkq9ZvXVsP1pxEmGZ0M8oPq3dE"
READ_ONLY = re.compile(
    r"\A(cat|test -e|test -r) /(etc/os-release|usr/lib/os-release|proc/meminfo)\Z"
    r"|\Auname -m\Z"
    r"|\Anproc\Z"
    r"|\Adf -B1 --output=size,avail,target /\Z"
)


@dataclass
class FakeServer:
    """A managed server as seen through ``RemoteShell``, recording every command."""

    files: dict[str, str] = field(
        default_factory=lambda: {"/etc/os-release": UBUNTU, "/proc/meminfo": MEMINFO}
    )
    unreadable: set[str] = field(default_factory=set)
    # None means the command fails; otherwise its stdout.
    arch: str | None = "x86_64"
    cpu: str | None = "4"
    df_output: str | None = DF_OUTPUT
    failure: str = ""
    # Exit mid-task, as the worker does when an operator forces it to stop.
    interrupt: bool = False
    host_key: str = HOST_KEY
    targets: list[ConnectionTarget] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)

    @contextmanager
    def connect(self, target: ConnectionTarget) -> Iterator[ssh.RemoteShell]:
        self.targets.append(target)
        if self.failure:
            raise ssh.ConnectionFailed(self.failure)
        if self.interrupt:
            raise SystemExit(1)
        yield self

    def run(self, command: str) -> ssh.CommandResult:
        self.commands.append(command)
        if command == "uname -m":
            if self.arch is None:
                return ssh.CommandResult(1, "")
            return ssh.CommandResult(0, f"{self.arch}\n")
        if command == "nproc":
            if self.cpu is None:
                return ssh.CommandResult(1, "")
            return ssh.CommandResult(0, f"{self.cpu}\n")
        if command == "df -B1 --output=size,avail,target /":
            if self.df_output is None:
                return ssh.CommandResult(1, "")
            return ssh.CommandResult(0, self.df_output)
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


class CapacityTests(DiscoveryTestCase):
    def discover(self) -> DiscoverySnapshot:
        server = self.register()
        self.run_worker()
        self.page = self.client.get(f"/servers/{server.pk}/")
        return DiscoverySnapshot.objects.get()

    def test_capacity_is_collected_with_units_provenance_and_time(self) -> None:
        snapshot = self.discover()
        self.assertEqual(
            (snapshot.arch_status, snapshot.arch_value, snapshot.arch_source),
            ("observed", "x86_64", "uname -m"),
        )
        self.assertEqual(
            (snapshot.cpu_status, snapshot.cpu_count, snapshot.cpu_source),
            ("observed", 4, "nproc"),
        )
        self.assertEqual(
            (snapshot.memory_status, snapshot.memory_bytes, snapshot.memory_source),
            ("observed", 4024548 * 1024, "/proc/meminfo"),
        )
        self.assertEqual(
            (
                snapshot.filesystem_status,
                snapshot.filesystem_path,
                snapshot.filesystem_size_bytes,
                snapshot.filesystem_avail_bytes,
            ),
            ("observed", "/", 53689778176, 48190049280),
        )
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)
        # The server overview retains the OS observations alongside capacity.
        self.assertContains(self.page, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertContains(self.page, "<dd>x86_64</dd>", html=True)
        self.assertContains(self.page, "4 CPUs")
        # Memory and filesystem show explicit units, not bare numbers.
        self.assertContains(self.page, "(4121137152 bytes)")
        self.assertContains(self.page, "(53689778176 bytes)", count=1)
        self.assertContains(self.page, "48190049280 bytes")
        self.assertContains(self.page, "total")
        self.assertContains(self.page, "available")
        self.assertContains(self.page, "<code>uname -m</code>", html=True)
        self.assertContains(self.page, "<code>nproc</code>", html=True)
        self.assertContains(self.page, "<code>/proc/meminfo</code>", html=True)
        self.assertContains(self.page, "This is a snapshot, not live status.")
        self.assertContains(self.page, f'datetime="{snapshot.collected_at.isoformat()}"')
        # Only the needed fields are kept; other meminfo lines are discarded.
        self.assertNotContains(self.page, "2345678")
        self.assertContains(self.client.get("/"), "<td>Verified</td>", html=True)

    def test_partial_capacity_shows_warnings_not_zero_values(self) -> None:
        self.remote.files = {"/etc/os-release": UBUNTU}
        self.remote.unreadable = {"/proc/meminfo"}
        self.remote.arch = None
        self.remote.cpu = "four"
        self.remote.df_output = "Size Avail Target\nnot-a-number 123 /\n"
        snapshot = self.discover()
        self.assertEqual(snapshot.arch_status, "unsupported")
        self.assertIsNone(snapshot.cpu_count)
        self.assertEqual(snapshot.cpu_status, "unsupported")
        self.assertEqual(snapshot.memory_status, "inaccessible")
        self.assertIsNone(snapshot.memory_bytes)
        self.assertEqual(snapshot.filesystem_status, "unsupported")
        self.assertIsNone(snapshot.filesystem_size_bytes)
        # A partial inspection still succeeds; the OS observations remain.
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)
        self.assertContains(self.page, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertContains(self.page, "<strong>Inaccessible:</strong>", html=True)
        self.assertContains(self.page, "cannot read /proc/meminfo. Barectl does not use sudo.")
        self.assertContains(self.page, "<strong>Unsupported:</strong>", html=True)
        self.assertNotContains(self.page, "four")
        # Missing observations never look like zero capacity.
        self.assertNotContains(self.page, "<dd>0</dd>", html=True)
        self.assertNotContains(self.page, "(0 bytes)")

    def test_absent_memory_is_distinct_from_inaccessible(self) -> None:
        self.remote.files = {"/etc/os-release": UBUNTU}
        snapshot = self.discover()
        self.assertEqual(snapshot.memory_status, "absent")
        self.assertContains(self.page, "has no /proc/meminfo")

    def test_unsupported_capacity_never_shows_raw_output(self) -> None:
        self.remote.arch = "x86_64\nmalicious $(touch /tmp/x)"
        self.remote.cpu = "0"
        self.remote.files["/proc/meminfo"] = "MemTotal: lots kB\n"
        self.remote.df_output = "Size Avail Target\n100 200 /\n"
        snapshot = self.discover()
        self.assertEqual(
            (
                snapshot.arch_status,
                snapshot.cpu_status,
                snapshot.memory_status,
                snapshot.filesystem_status,
            ),
            ("unsupported", "unsupported", "unsupported", "unsupported"),
        )
        self.assertNotContains(self.page, "malicious")
        self.assertNotContains(self.page, "lots kB")


class CapacityParserTests(DiscoveryTestCase):
    """Edge cases where the workflow cannot clearly express truncated output."""

    def shell_for(self, mapping: dict[str, ssh.CommandResult]) -> ssh.RemoteShell:
        class Stub:
            host_key = HOST_KEY

            def __init__(self, results: dict[str, ssh.CommandResult]) -> None:
                self.results = results

            def run(self, command: str) -> ssh.CommandResult:
                return self.results[command]

        return Stub(mapping)

    def test_truncated_outputs_are_unsupported(self) -> None:
        from .observations import (
            collect_architecture,
            collect_cpu_count,
            collect_filesystem,
            collect_memory,
        )

        shell = self.shell_for(
            {
                "uname -m": ssh.CommandResult(0, "x" * 100, True),
                "nproc": ssh.CommandResult(0, "4", True),
                "cat /proc/meminfo": ssh.CommandResult(0, MEMINFO, True),
                "df -B1 --output=size,avail,target /": ssh.CommandResult(0, DF_OUTPUT, True),
            }
        )
        self.assertEqual(collect_architecture(shell).status, "unsupported")
        self.assertEqual(collect_cpu_count(shell).status, "unsupported")
        self.assertEqual(collect_memory(shell).status, "unsupported")
        self.assertEqual(collect_filesystem(shell).status, "unsupported")


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
        # A verified server offers an explicit refresh that queues new work.
        self.assertContains(page, "Refresh observations")
        response = self.client.post(self.verify_url(), follow=True)
        self.assertContains(response, "Barectl queued a connection check for Web.")
        self.assertEqual(DiscoveryAttempt.objects.count(), 2)

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
        self.assertContains(page, "Retry connection check")
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


class RefreshTests(DiscoveryTestCase):
    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def verify_url(self) -> str:
        return f"/servers/{self.server.pk}/verify/"

    def succeed_once(self) -> DiscoverySnapshot:
        request_discovery(self.server)
        self.run_worker()
        return DiscoverySnapshot.objects.get()

    def test_refresh_queues_work_shows_progress_and_replaces_snapshot(self) -> None:
        first = self.succeed_once()
        self.sign_in_with("view_server", "add_discoveryattempt")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Refresh observations")
        self.assertNotContains(page, "hx-trigger")

        response = self.client.post(self.verify_url(), headers=HTMX_FRAGMENT)
        content = response.content.decode()
        self.assertRegex(content, r'<div id="discovery"[^>]*hx-trigger="every 2s"')
        self.assertIn("Connection check queued.", content)
        self.assertIn('<hx-partial hx-target="#discovery-announcement"', content)

        # Repeated refresh submissions share the active attempt.
        self.client.post(self.verify_url())
        self.client.post(self.verify_url(), headers=HTMX_FRAGMENT)
        self.assertEqual(DiscoveryAttempt.objects.count(), 2)
        self.assertEqual(
            DiscoveryAttempt.objects.filter(status__in=DiscoveryAttempt.ACTIVE).count(), 1
        )

        self.remote.files = {"/etc/os-release": 'PRETTY_NAME="Ubuntu 24.04.4 LTS"\nID=ubuntu\n'}
        self.run_worker()

        attempts = list(DiscoveryAttempt.objects.order_by("queued_at"))
        self.assertEqual(
            [attempt.status for attempt in attempts],
            [
                DiscoveryAttempt.Status.SUCCEEDED,
                DiscoveryAttempt.Status.SUCCEEDED,
            ],
        )
        # A successful refresh replaces the current snapshot coherently.
        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        snapshot = DiscoverySnapshot.objects.get()
        self.assertEqual(snapshot.attempt, attempts[1])
        self.assertEqual(snapshot.os_pretty_name, "Ubuntu 24.04.4 LTS")
        self.assertNotEqual(snapshot.pk, first.pk)
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Ubuntu 24.04.4 LTS")
        self.assertNotContains(page, "may be out of date")

    def test_failed_refresh_preserves_snapshot_and_offers_retry(self) -> None:
        self.succeed_once()
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.remote.failure = "Barectl could not reach the SSH service configured for web."
        self.client.post(self.verify_url())
        self.run_worker()

        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        snapshot = DiscoverySnapshot.objects.get()
        self.assertEqual(snapshot.os_pretty_name, "Ubuntu 24.04.3 LTS")
        latest = DiscoveryAttempt.objects.get(status=DiscoveryAttempt.Status.FAILED)
        self.assertEqual(latest.status, DiscoveryAttempt.Status.FAILED)
        self.assertFalse(DiscoverySnapshot.objects.filter(attempt=latest).exists())

        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Connection failed")
        self.assertContains(page, "could not reach the SSH service")
        self.assertContains(page, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertContains(page, "The latest connection check failed, so these observations")
        self.assertContains(page, "Retry connection check")
        # No automatic retry: one failed attempt stays until the operator retries.
        self.assertEqual(DiscoveryAttempt.objects.count(), 2)

        self.remote.failure = ""
        self.client.post(self.verify_url())
        self.run_worker()
        self.assertEqual(DiscoveryAttempt.objects.count(), 3)
        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "<strong>Verified</strong>", html=True)
        self.assertContains(page, "Refresh observations")

    def test_partial_refresh_keeps_warnings_not_absent_software(self) -> None:
        self.succeed_once()
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.remote.files = {}
        self.remote.unreadable = {"/etc/os-release"}
        self.client.post(self.verify_url())
        self.run_worker()

        snapshot = DiscoverySnapshot.objects.get()
        self.assertEqual(snapshot.os_status, "inaccessible")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "<strong>Inaccessible:</strong>", html=True)
        self.assertNotContains(page, "No observations yet.")
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)

    def test_unsupported_refresh_is_not_absent_software(self) -> None:
        self.succeed_once()
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.remote.files = {"/etc/os-release": "<html>not a release file</html>\n"}
        self.client.post(self.verify_url())
        self.run_worker()

        snapshot = DiscoverySnapshot.objects.get()
        self.assertEqual(snapshot.os_status, "unsupported")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "<strong>Unsupported:</strong>", html=True)
        self.assertNotContains(page, "not a release file")

    def test_snapshot_age_is_labelled(self) -> None:
        snapshot = self.succeed_once()
        DiscoverySnapshot.objects.filter(pk=snapshot.pk).update(
            collected_at=timezone.now() - datetime.timedelta(hours=3, minutes=5)
        )
        self.sign_in_with("view_server")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "(3\xa0hours, 5\xa0minutes ago)")

    def test_bounded_timeout_failure_preserves_snapshot(self) -> None:
        self.succeed_once()
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.remote.failure = (
            "A discovery command did not finish within 15 seconds. Barectl closed the connection."
        )
        self.client.post(self.verify_url())
        self.run_worker()

        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "did not finish within")
        self.assertContains(page, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertContains(page, "may be out of date")


class RecoveryTests(DiscoveryTestCase):
    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def make_stale(
        self, attempt: DiscoveryAttempt, *, queued: bool = False, started: bool = False
    ) -> None:
        past = timezone.now() - STALE_AFTER - datetime.timedelta(minutes=1)
        query = DiscoveryAttempt.objects.filter(pk=attempt.pk)
        if queued:
            query.update(queued_at=past)
        if started:
            query.update(started_at=past)

    def interrupt_running(self) -> DiscoveryAttempt:
        """Leave a refresh running after a success, as a worker killed mid-task would."""
        request_discovery(self.server)
        self.run_worker()
        interrupted = request_discovery(self.server)
        claimed = DiscoveryAttempt.objects.filter(
            pk=interrupted.pk, status=DiscoveryAttempt.Status.QUEUED
        ).update(status=DiscoveryAttempt.Status.RUNNING, started_at=timezone.now())
        self.assertEqual(claimed, 1)
        interrupted.refresh_from_db()
        return interrupted

    def test_running_interruption_is_recovered_and_retryable(self) -> None:
        attempt = self.interrupt_running()
        snapshot = DiscoverySnapshot.objects.get()
        self.make_stale(attempt, started=True)

        recovered = recover_stale_attempts()
        self.assertEqual(recovered, 1)
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("stopped before finishing", attempt.failure)
        self.assertEqual(attempt.failure, INTERRUPTED_FAILURE)
        # The previous snapshot is preserved and labeled stale in the page.
        self.assertEqual(DiscoverySnapshot.objects.get().pk, snapshot.pk)
        self.sign_in_with("view_server", "add_discoveryattempt")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "stopped before finishing")
        self.assertContains(page, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertContains(page, "may be out of date")
        self.assertContains(page, "Retry connection check")

        self.client.post(f"/servers/{self.server.pk}/verify/")
        self.run_worker()
        self.assertEqual(
            DiscoveryAttempt.objects.filter(status=DiscoveryAttempt.Status.SUCCEEDED).count(), 2
        )

    def test_abandoned_queued_attempt_without_waiting_task_is_recovered(self) -> None:
        attempt = request_discovery(self.server)
        self.make_stale(attempt, queued=True)
        # No worker ever claimed it and no READY task remains (simulating a lost task).
        DBTaskResult.objects.all().delete()
        recovered = recover_stale_attempts()
        self.assertEqual(recovered, 1)
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("stopped before finishing", attempt.failure)

    def test_queued_with_ready_task_waits_for_worker(self) -> None:
        attempt = request_discovery(self.server)
        self.make_stale(attempt, queued=True)
        # A READY task still waits: restarting the worker should run it, not fail it.
        self.assertEqual(recover_stale_attempts(), 0)
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.QUEUED)
        self.run_worker()
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED)

    def test_queued_attempt_whose_task_a_worker_claimed_is_left_until_that_goes_stale(
        self,
    ) -> None:
        attempt = request_discovery(self.server)
        self.make_stale(attempt, queued=True)
        # A worker claimed the task and is about to claim the attempt.
        task = DBTaskResult.objects.get()
        task.claim("worker-1")
        self.assertEqual(recover_stale_attempts(), 0)
        # That worker was killed before claiming the attempt.
        past = timezone.now() - STALE_AFTER - datetime.timedelta(minutes=1)
        DBTaskResult.objects.filter(pk=task.pk).update(started_at=past)
        self.assertEqual(recover_stale_attempts(), 1)
        attempt.refresh_from_db()
        self.assertEqual(attempt.failure, INTERRUPTED_FAILURE)

    def test_stale_worker_cannot_overwrite_recovery_or_newer_result(self) -> None:
        stale = self.interrupt_running()
        first_snapshot = DiscoverySnapshot.objects.get()
        self.make_stale(stale, started=True)
        recover_stale_attempts()
        stale.refresh_from_db()
        self.assertEqual(stale.status, DiscoveryAttempt.Status.FAILED)

        # The stale worker finishes late: its conditional update must not win.
        services._finish_failed(stale.pk, "late failure from stale worker")
        stale.refresh_from_db()
        self.assertEqual(stale.status, DiscoveryAttempt.Status.FAILED)
        self.assertEqual(stale.failure, INTERRUPTED_FAILURE)

        # Nor can it publish a snapshot after recovery.
        with mock.patch.object(ssh, "connect", self.remote.connect):
            services._discover(stale)
        self.assertEqual(DiscoverySnapshot.objects.get().pk, first_snapshot.pk)
        self.assertFalse(
            DiscoverySnapshot.objects.filter(attempt=stale).exists(),
        )

        # A newer refresh still succeeds coherently after the interruption.
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.client.post(f"/servers/{self.server.pk}/verify/")
        self.run_worker()
        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        self.assertNotEqual(DiscoverySnapshot.objects.get().pk, first_snapshot.pk)

    def test_worker_restart_recovery_through_real_worker_integration(self) -> None:
        interrupted = self.interrupt_running()
        self.make_stale(interrupted, started=True)
        # The next real worker run recovers abandoned attempts before claiming new work.
        other = Server.objects.create(name="Other", ssh_alias="db-1")
        request_discovery(other)
        self.run_worker()
        interrupted.refresh_from_db()
        self.assertEqual(interrupted.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("stopped before finishing", interrupted.failure)

    def test_polling_recovers_abandoned_attempt_without_new_work(self) -> None:
        interrupted = self.interrupt_running()
        self.sign_in_with("view_server", "add_discoveryattempt")
        # Within the bound the attempt may still finish, so the page keeps polling.
        fragment = self.client.get(
            f"/servers/{self.server.pk}/discovery/?shown=running", headers=HTMX_FRAGMENT
        )
        self.assertContains(fragment, 'hx-trigger="every 2s"')
        self.assertNotContains(fragment, "Retry connection check")

        # Past the bound, with no worker running anything, the next poll recovers it.
        self.make_stale(interrupted, started=True)
        fragment = self.client.get(
            f"/servers/{self.server.pk}/discovery/?shown=running", headers=HTMX_FRAGMENT
        )
        interrupted.refresh_from_db()
        self.assertEqual(interrupted.status, DiscoveryAttempt.Status.FAILED)
        content = fragment.content.decode()
        self.assertNotIn("hx-trigger", content)
        self.assertIn("stopped before finishing", content)
        self.assertIn("Retry connection check", content)
        self.assertContains(fragment, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertRegex(
            content, r'hx-target="#discovery-announcement"[^>]*>\s*The connection failed\.'
        )

    def test_server_list_recovers_abandoned_attempts(self) -> None:
        interrupted = self.interrupt_running()
        self.make_stale(interrupted, started=True)
        self.sign_in_with("view_server")
        page = self.client.get("/")
        self.assertContains(page, "Web")
        self.assertNotContains(page, "Checking connection")
        interrupted.refresh_from_db()
        self.assertEqual(interrupted.status, DiscoveryAttempt.Status.FAILED)

    def test_forced_worker_stop_marks_attempt_interrupted(self) -> None:
        request_discovery(self.server)
        self.run_worker()
        snapshot = DiscoverySnapshot.objects.get()
        # A second Ctrl+C makes the worker exit in the middle of the task.
        self.remote.interrupt = True
        attempt = request_discovery(self.server)
        self.run_worker()
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertEqual(attempt.failure, INTERRUPTED_FAILURE)
        self.assertEqual(DiscoverySnapshot.objects.get().pk, snapshot.pk)
