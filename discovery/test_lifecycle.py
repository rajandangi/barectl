"""The registration-to-result workflow through Django requests and the durable worker.

Real views, services, persistence, alias resolution and the ``db_worker`` command run;
only remote execution is substituted, at ``discovery.ssh.connect``.
"""

import datetime
import inspect
from collections.abc import Iterator
from contextlib import contextmanager
from typing import ClassVar, override
from unittest import mock

from django.db import IntegrityError, connection, transaction
from django.db.models import Q, UniqueConstraint
from django.test import Client, TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from django.utils.formats import date_format

from servers.models import Server
from servers.ssh_config import ConnectionTarget
from servers.testing import HTMX_FRAGMENT

from . import services, ssh
from .fakes import (
    DPKG_OUTPUT,
    HOST_KEY,
    PACKAGE_QUERY,
    STALE,
    UBUNTU,
    UNIT_QUERY,
    DiscoveryTestCase,
    SitePoolFixtures,
    claim_task,
    current,
    observed,
    record_attempt,
    task_records,
    unit_report,
    waiting_tasks,
)
from .models import DiscoveryAttempt, DiscoverySnapshot
from .presentation import present
from .services import (
    INTERRUPTED_FAILURE,
    STALE_AFTER,
    history,
    read_discovery,
    request_discovery,
)


class ActiveAttemptRuleTests(TestCase):
    def test_the_one_active_attempt_constraint_covers_the_active_statuses(self) -> None:
        (constraint,) = (
            constraint
            for constraint in DiscoveryAttempt._meta.constraints
            if isinstance(constraint, UniqueConstraint)
            and constraint.name == "discovery_one_active_attempt_per_server"
        )
        self.assertEqual(constraint.condition, Q(status__in=list(DiscoveryAttempt.ACTIVE)))


class RecoverFirstTests(TestCase):
    def test_every_public_function_recovers_abandoned_attempts_first(self) -> None:
        class Recovered(Exception):
            pass

        entries = [
            (name, function)
            for name, function in inspect.getmembers(services, inspect.isfunction)
            if function.__module__ == services.__name__ and not name.startswith("_")
        ]
        self.assertIn("run_attempt", dict(entries))
        with mock.patch.object(services, "_recover_stale_attempts", side_effect=Recovered):
            for name, function in entries:
                with self.subTest(function=name):
                    # Recovery raises before the function could use its placeholder arguments.
                    arguments = [
                        object()
                        for parameter in inspect.signature(function).parameters.values()
                        if parameter.default is inspect.Parameter.empty
                    ]
                    with self.assertRaises(Recovered):
                        function(*arguments)


class RegistrationDiscoveryTests(DiscoveryTestCase):
    def test_registration_queues_work_that_the_worker_completes(self) -> None:
        server = self.register()
        # The request only queued the work; nothing connected during it.
        attempt = DiscoveryAttempt.objects.get()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.QUEUED)
        self.assertEqual(attempt.ssh_alias, "web.example.com")
        self.assertEqual(self.remote.targets, [])
        self.assertEqual(waiting_tasks(attempt), 1)
        page = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(page, "Connection check queued")
        self.assertContains(page, 'hx-trigger="every 2s"')
        self.assertContains(page, "No observations yet.")
        self.assertContains(
            page,
            "No component observations yet. Barectl reads web-stack components after it "
            "verifies the connection.",
        )
        self.assertContains(
            page,
            "No Nginx site file observations yet. Barectl reads Nginx site files after it "
            "verifies the connection.",
        )
        self.assertContains(
            page,
            "No PHP-FPM pool observations yet. Barectl reads PHP-FPM pools after it verifies "
            "the connection.",
        )

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
        self.assertEqual(DiscoverySnapshot.objects.get().attempt, attempt)
        self.snapshot = current(server)
        release = observed(self.snapshot.collected.os)
        self.assertEqual(
            (
                release.pretty_name,
                release.id,
                release.version_id,
                self.snapshot.collected.os.source,
            ),
            ("Ubuntu 24.04.3 LTS", "ubuntu", "24.04", ("/etc/os-release",)),
        )
        page = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(page, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertContains(page, "<dd>24.04</dd>", html=True)
        self.assertContains(page, "from <code>/etc/os-release</code>")
        self.assertContains(page, f"<code>{HOST_KEY}</code>")
        self.assertContains(page, "This is a snapshot, not live status.")
        self.assertContains(page, f'datetime="{self.snapshot.collected_at.isoformat()}"')
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
        # Every test checks the commands against READ_ONLY (see assert_read_only).
        self.assertTrue(self.remote.commands)
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
        self.assertNotIn("hunter2", str(task_records(attempt).values_list("traceback", flat=True)))


class ObservationWorkflowTests(SitePoolFixtures, DiscoveryTestCase):
    """Observations through the worker, the database and the server page.

    The rules themselves are tested through ``collect``, and the page's rendering from stored
    snapshots. These check that the database refuses what the rules never produce, and that
    a collection is stored, replaced without duplicates and shown.
    """

    def test_the_database_refuses_absent_attributes(self) -> None:
        self.discover()
        # The storage itself is under test here, so this reads the stored columns.
        snapshot = DiscoverySnapshot.objects.get()
        columns = ("os_status", "arch_status", "cpu_status", "memory_status", "filesystem_status")
        for name in columns:
            with self.subTest(field=name):
                previous = getattr(snapshot, name)
                setattr(snapshot, name, "absent")
                with self.assertRaises(IntegrityError), transaction.atomic():
                    snapshot.save(update_fields=[name])
                setattr(snapshot, name, previous)

    def test_repeated_discovery_replaces_state_without_duplicates(self) -> None:
        self.enable_sites({"example.com": self.EXAMPLE_SITE, "default": self.DEFAULT_SITE})
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        collected = self.discover()
        self.assertEqual(len(collected.nginx_site_files.value), 2)
        self.assertEqual(len(collected.php_fpm_pools.value), 1)
        first = DiscoverySnapshot.objects.get()
        self.sign_in_with("view_server", "add_discoveryattempt")

        # example.com is removed, default changes its listen address, and a second
        # PHP version appears.
        self.enable_sites(
            {"default": "server {\n  listen 8080;\n  server_name default.example;\n}\n"}
        )
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        self.enable_pools("8.1", {"admin.conf": "[admin]\nlisten = 127.0.0.1:9100\n"})
        self.install_php_fpm("8.1", "8.3")
        self.client.post(f"/servers/{first.server.pk}/verify/")
        self.run_worker()

        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        self.assertNotEqual(DiscoverySnapshot.objects.get().pk, first.pk)
        refreshed = current(first.server).collected
        self.assertEqual(
            [(s.name, s.server_names, s.listens) for s in refreshed.nginx_site_files.value],
            [("default", ("default.example",), ("8080",))],
        )
        self.assertEqual(
            [(pool.version, pool.name) for pool in refreshed.php_fpm_pools.value],
            [("8.1", "admin"), ("8.3", "www")],
        )
        self.assertEqual(len(refreshed.php_fpm_pools.value), 2)
        page = self.client.get(f"/servers/{first.server.pk}/")
        self.assertNotContains(page, "<code>example.com</code>")
        self.assertNotContains(page, "Server names example.com")
        self.assertContains(page, "Listens on 8080")
        self.assertContains(page, "127.0.0.1:9100")


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
        self.assertEqual(task_records().count(), 1)
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
        self.assertIn(f"/servers/{self.server.pk}/discovery/?shown=QUEUED", content)
        self.assertIn('<hx-partial hx-target="#discovery-announcement"', content)
        self.assertIn("Connection check queued.", content)
        poll = f"/servers/{self.server.pk}/discovery/?shown=QUEUED"
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
        """Run one successful discovery and return its stored snapshot row."""
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
        self.assertEqual(
            observed(current(self.server).collected.os).pretty_name, "Ubuntu 24.04.4 LTS"
        )
        self.assertNotEqual(snapshot.pk, first.pk)
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Ubuntu 24.04.4 LTS")
        self.assertNotContains(page, "may be out of date")

    def test_refresh_replaces_service_observations(self) -> None:
        before = self.succeed_once()
        self.assertEqual(len(current(self.server).collected.components), 4)
        # Nginx was uninstalled and MariaDB stopped between the two discoveries.
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(1, DPKG_OUTPUT.replace("nginx ", ""))
        self.remote.results[UNIT_QUERY.format("mariadb.service")] = ssh.CommandResult(
            0, unit_report("mariadb.service", active="inactive", sub="dead")
        )
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.client.post(self.verify_url())
        self.run_worker()
        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        after = DiscoverySnapshot.objects.get()
        self.assertNotEqual(after.pk, before.pk)
        self.assertEqual(
            [
                (c.component, c.package.outcome, c.service.outcome)
                for c in current(self.server).collected.components
            ],
            [
                ("nginx", "absent", "absent"),
                ("php-fpm", "observed", "observed"),
                ("mariadb", "observed", "observed"),
                ("postgresql", "observed", "observed"),
            ],
        )
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertNotContains(page, "nginx 1.24.0-2ubuntu7.18")
        self.assertContains(page, "mariadb.service inactive (dead), enabled")

    def test_failed_refresh_preserves_snapshot_and_offers_retry(self) -> None:
        self.succeed_once()
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.remote.failure = "Barectl could not reach the SSH service configured for web."
        self.client.post(self.verify_url())
        self.run_worker()

        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        self.assertEqual(
            observed(current(self.server).collected.os).pretty_name, "Ubuntu 24.04.3 LTS"
        )
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

        self.assertEqual(current(self.server).collected.os.outcome, "inaccessible")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "<strong>Inaccessible:</strong>", html=True)
        self.assertNotContains(page, "No observations yet.")
        self.assert_succeeded()

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
            "A remote command did not finish within 15 seconds. Barectl closed the connection."
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

    def latest(self) -> DiscoveryAttempt:
        """The server's latest attempt, as any page reading it would see it."""
        attempt = read_discovery(self.server).attempt
        if attempt is None:
            raise AssertionError("The server has no attempt.")
        return attempt

    def latest_status(self) -> str:
        return self.latest().status

    def interrupt_running(self) -> DiscoveryAttempt:
        """Leave a refresh running after a success, as a worker killed mid-task would."""
        request_discovery(self.server)
        self.run_worker()
        return record_attempt(request_discovery(self.server), DiscoveryAttempt.Status.RUNNING)

    def test_the_server_page_read_recovers_abandoned_attempts_itself(self) -> None:
        attempt = record_attempt(
            self.interrupt_running(), DiscoveryAttempt.Status.RUNNING, age=STALE
        )
        other = Server.objects.create(name="Database", ssh_alias="db-1")
        request_discovery(other)
        # Read first, with no earlier read of the server's state to recover it.
        discovery = read_discovery(self.server)
        recorded = discovery.history
        self.assertEqual(
            [listed.status for listed, _ in recorded],
            [DiscoveryAttempt.Status.FAILED, DiscoveryAttempt.Status.SUCCEEDED],
        )
        self.assertEqual(recorded[0].attempt, attempt)
        self.assertEqual(recorded[0].attempt.failure, INTERRUPTED_FAILURE)
        self.assertIsNone(recorded[0].snapshot)
        self.assertIsNotNone(recorded[1].snapshot)
        # The latest attempt and the current snapshot come from the same read.
        self.assertEqual(discovery.attempt, attempt)
        self.assertEqual(discovery.snapshot, recorded[1].snapshot)
        self.assertEqual(discovery.snapshot, current(self.server))
        self.assertEqual({listed.server for listed, _ in history()}, {self.server, other})

    def test_running_interruption_is_recovered_and_retryable(self) -> None:
        attempt = self.interrupt_running()
        snapshot = DiscoverySnapshot.objects.get()
        record_attempt(attempt, DiscoveryAttempt.Status.RUNNING, age=STALE)

        # Reading the latest attempt recovers it; no caller has to remember to.
        attempt = self.latest()
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
        record_attempt(attempt, age=STALE)
        # No worker ever claimed it and no READY task remains (simulating a lost task).
        task_records(attempt).delete()
        self.assertEqual(self.latest_status(), DiscoveryAttempt.Status.FAILED)
        attempt.refresh_from_db()
        self.assertIn("stopped before finishing", attempt.failure)

    def test_queued_with_ready_task_waits_for_worker(self) -> None:
        attempt = request_discovery(self.server)
        record_attempt(attempt, age=STALE)
        # A READY task still waits: restarting the worker should run it, not fail it.
        self.assertEqual(self.latest_status(), DiscoveryAttempt.Status.QUEUED)
        self.run_worker()
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED)

    def test_queued_attempt_whose_task_a_worker_claimed_is_left_until_that_goes_stale(
        self,
    ) -> None:
        attempt = request_discovery(self.server)
        record_attempt(attempt, age=STALE)
        # A worker claimed the task and is about to claim the attempt.
        claim_task(attempt)
        self.assertEqual(self.latest_status(), DiscoveryAttempt.Status.QUEUED)
        # That worker was killed before claiming the attempt.
        claim_task(attempt, age=STALE)
        self.assertEqual(self.latest_status(), DiscoveryAttempt.Status.FAILED)
        attempt.refresh_from_db()
        self.assertEqual(attempt.failure, INTERRUPTED_FAILURE)

    def run_recovered_mid_run(self, attempt: DiscoveryAttempt) -> None:
        """Run the worker; while it connects, the attempt goes stale and a page recovers it."""
        connect = ssh.connect

        @contextmanager
        def connect_after_recovery(target: ConnectionTarget) -> Iterator[ssh.RemoteShell]:
            record_attempt(attempt, DiscoveryAttempt.Status.RUNNING, age=STALE)
            self.assertEqual(self.latest_status(), DiscoveryAttempt.Status.FAILED)
            with connect(target) as shell:
                yield shell

        with mock.patch.object(ssh, "connect", connect_after_recovery):
            self.run_worker()

    def test_stale_worker_cannot_overwrite_recovery_or_newer_result(self) -> None:
        request_discovery(self.server)
        self.run_worker()
        first_snapshot = DiscoverySnapshot.objects.get()

        # The stale worker fails late: its failure must not replace the recovery's.
        self.remote.failure = "late failure from stale worker"
        failed = request_discovery(self.server)
        self.run_recovered_mid_run(failed)
        failed.refresh_from_db()
        self.assertEqual(failed.status, DiscoveryAttempt.Status.FAILED)
        self.assertEqual(failed.failure, INTERRUPTED_FAILURE)

        # Nor can a stale worker that succeeds late publish a snapshot after recovery.
        self.remote.failure = ""
        stale = request_discovery(self.server)
        self.run_recovered_mid_run(stale)
        stale.refresh_from_db()
        self.assertEqual(stale.status, DiscoveryAttempt.Status.FAILED)
        self.assertEqual(stale.failure, INTERRUPTED_FAILURE)
        self.assertEqual(stale.host_key, "")
        self.assertEqual(DiscoverySnapshot.objects.get().pk, first_snapshot.pk)

        # A newer refresh still succeeds coherently after the interruption.
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.client.post(f"/servers/{self.server.pk}/verify/")
        self.run_worker()
        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        self.assertNotEqual(DiscoverySnapshot.objects.get().pk, first_snapshot.pk)

    def test_worker_restart_recovery_through_real_worker_integration(self) -> None:
        interrupted = self.interrupt_running()
        record_attempt(interrupted, DiscoveryAttempt.Status.RUNNING, age=STALE)
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
            f"/servers/{self.server.pk}/discovery/?shown=RUNNING", headers=HTMX_FRAGMENT
        )
        self.assertContains(fragment, 'hx-trigger="every 2s"')
        self.assertNotContains(fragment, "Retry connection check")

        # Past the bound, with no worker running anything, the next poll recovers it.
        record_attempt(interrupted, DiscoveryAttempt.Status.RUNNING, age=STALE)
        fragment = self.client.get(
            f"/servers/{self.server.pk}/discovery/?shown=RUNNING", headers=HTMX_FRAGMENT
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
        record_attempt(interrupted, DiscoveryAttempt.Status.RUNNING, age=STALE)
        self.sign_in_with("view_server")
        page = self.client.get("/")
        self.assertContains(page, "Web")
        self.assertNotContains(page, "Checking connection")
        interrupted.refresh_from_db()
        self.assertEqual(interrupted.status, DiscoveryAttempt.Status.FAILED)

    def test_a_running_attempt_that_is_not_stale_is_shown_as_running(self) -> None:
        self.interrupt_running()
        self.sign_in_with("view_server")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "<strong>Checking connection</strong> since", html=False)
        self.assertContains(page, "A new connection check is running")
        self.assertContains(page, 'hx-trigger="every 2s"')

    def test_every_page_that_shows_attempts_recovers_abandoned_ones(self) -> None:
        self.sign_in_with("view_server", "delete_server")
        pages = {
            "server": f"/servers/{self.server.pk}/",
            "activity": "/activity/",
            "removal": f"/servers/{self.server.pk}/remove/",
        }
        for name, url in pages.items():
            with self.subTest(page=name):
                DiscoveryAttempt.objects.all().delete()
                interrupted = self.interrupt_running()
                record_attempt(interrupted, DiscoveryAttempt.Status.RUNNING, age=STALE)
                page = self.client.get(url)
                self.assertEqual(page.status_code, 200)
                self.assertNotContains(page, "Checking connection")
                interrupted.refresh_from_db()
                self.assertEqual(interrupted.failure, INTERRUPTED_FAILURE)

    def test_healthy_attempts_finish_before_recovery_would_interrupt_them(self) -> None:
        # Connecting, the handshake, authentication and opening a channel each have a limit.
        longest = datetime.timedelta(seconds=4 * ssh.CONNECT_TIMEOUT + ssh.SESSION_TIMEOUT)
        self.assertGreater(STALE_AFTER, longest * 1.5)

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


class ActivityHistoryTests(DiscoveryTestCase):
    """Reviewing recorded attempts: each server's history and the Activity view.

    Attempt outcomes and the snapshots successes published stay distinguishable: a failed
    or interrupted attempt remains listed beside the snapshot it did not replace.
    """

    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def verify_url(self) -> str:
        return f"/servers/{self.server.pk}/verify/"

    def test_history_shows_the_attempt_and_its_snapshot_collection_time(self) -> None:
        request_discovery(self.server)
        self.run_worker()
        snapshot = DiscoverySnapshot.objects.get()
        self.sign_in_with("view_server")
        history = self.history_of(self.client.get(f"/servers/{self.server.pk}/"))
        self.assertIn("Discovery history", history)
        self.assertIn("Verified", history)
        self.assertIn(date_format(snapshot.collected_at, "M j, Y, H:i:s T"), history)
        self.assertIn("not live status", history)

    def test_a_failed_refresh_stays_listed_with_the_previous_snapshot(self) -> None:
        request_discovery(self.server)
        self.run_worker()
        snapshot = DiscoverySnapshot.objects.get()
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.remote.failure = "Barectl could not reach the SSH service configured for web."
        self.client.post(self.verify_url())
        self.run_worker()

        page = self.client.get(f"/servers/{self.server.pk}/")
        content = page.content.decode()
        # The latest failure is shown although the earlier snapshot is still displayed.
        self.assertIn("The latest connection check failed", content)
        self.assertIn("could not reach the SSH service", content)
        self.assertIn("Ubuntu 24.04.3 LTS", content)
        history = content[content.index('id="discovery-history"') :]
        self.assertLess(history.index("Connection failed"), history.index("Verified"))
        self.assertIn(date_format(snapshot.collected_at, "M j, Y, H:i:s T"), history)

    def test_activity_shows_the_snapshot_warnings_beside_their_attempt(self) -> None:
        del self.remote.files["/proc/meminfo"]
        self.remote.unreadable = {"/proc/meminfo"}
        request_discovery(self.server)
        self.run_worker()
        warning = "cannot read /proc/meminfo. Barectl does not use sudo."
        self.assertIn(warning, current(self.server).collected.memory_bytes.warning)
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.remote.failure = "Barectl could not reach the SSH service configured for web."
        self.client.post(self.verify_url())
        self.run_worker()

        content = self.client.get("/activity/").content.decode()
        table = content[content.index("<table") : content.index("</table>")]
        failed, succeeded = table.split("<tr>")[2:]
        # The failed refresh published nothing, so it carries no snapshot warnings.
        self.assertIn("could not reach the SSH service", failed)
        self.assertNotIn("/proc/meminfo", failed)
        self.assertIn("1 observation warning", succeeded)
        self.assertIn("Memory: <strong>Inaccessible:</strong>", succeeded)
        self.assertIn(warning, succeeded)
        # The server page shows the warning with the snapshot, not again in its history.
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, warning, count=1)
        self.assertNotIn(warning, self.history_of(page))

    def test_history_claims_no_warnings_for_a_complete_snapshot(self) -> None:
        request_discovery(self.server)
        self.run_worker()
        collected = current(self.server).collected
        # Notes on completed observations, such as an empty site directory, are findings.
        self.assertNotEqual(collected.nginx_site_files.warning, "")
        self.assertEqual(present(collected).warnings, [])
        self.sign_in_with("view_server")
        self.assertNotContains(self.client.get("/activity/"), "observation warning")

    def test_activity_queries_do_not_grow_with_snapshots(self) -> None:
        self.sign_in_with("view_server")
        request_discovery(self.server)
        self.run_worker()
        with CaptureQueriesContext(connection) as one:
            self.client.get("/activity/")
        other = Server.objects.create(name="DB", ssh_alias="stage.example.net")
        request_discovery(other)
        self.run_worker()
        with CaptureQueriesContext(connection) as two:
            page = self.client.get("/activity/")
        self.assertEqual(page.content.decode().count("<tr>"), 3)
        self.assertEqual(len(two), len(one))

    def test_activity_lists_attempts_across_servers_newest_first(self) -> None:
        request_discovery(self.server)
        other = Server.objects.create(name="DB", ssh_alias="stage.example.net")
        request_discovery(other)
        self.run_worker()
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.remote.failure = "Barectl could not reach the SSH service configured for web."
        self.client.post(self.verify_url())
        self.run_worker()

        page = self.client.get("/activity/")
        self.assertContains(page, "Discovery attempts across all servers")
        # Newest recorded first: Web's failed refresh, DB's check, then Web's first.
        content = page.content.decode()
        failure = content.index("could not reach the SSH service")
        db_row = content.index("stage.example.net")
        web_retry = content.index("web.example.com", db_row)
        self.assertLess(failure, db_row)
        self.assertLess(db_row, web_retry)

    def test_activity_shows_interrupted_attempts_after_recovery(self) -> None:
        attempt = record_attempt(
            request_discovery(self.server), DiscoveryAttempt.Status.RUNNING, age=STALE
        )
        self.sign_in_with("view_server")
        page = self.client.get("/activity/")
        self.assertContains(page, "stopped before finishing")
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)

    def test_unexpected_failures_reach_activity_without_their_details(self) -> None:
        def broken(target: ConnectionTarget) -> Iterator[ssh.RemoteShell]:
            raise RuntimeError("password=hunter2 from remote output")

        request_discovery(self.server)
        with mock.patch.object(ssh, "connect", broken):
            self.run_worker()
        self.sign_in_with("view_server")
        page = self.client.get("/activity/")
        self.assertContains(page, "unexpected error")
        self.assertNotContains(page, "hunter2")
