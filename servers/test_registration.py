"""Registering, re-aliasing and removing servers through requests and the durable worker.

Real views, services, persistence and the ``db_worker`` command run; only remote execution
is substituted, at ``discovery.ssh.connect``.
"""

import tempfile
from pathlib import Path
from typing import ClassVar, override
from unittest import mock

from django.db import transaction
from django.db.models.deletion import Collector
from django.http.response import HttpResponseBase
from django.tasks import TaskResultStatus
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.utils import timezone
from django_tasks_db.models import DBTaskResult

from discovery import ssh
from discovery.fakes import HOST_KEY, DiscoveryTestCase, FakeServer, run_worker
from discovery.models import ComponentObservation, DiscoveryAttempt, DiscoverySnapshot
from discovery.services import forget_discovery, request_discovery
from discovery.test_attempts import STALE, record_attempt

from .models import Server
from .registration import RemovalBlocked, SaveOutcome, remove_server, save_server


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


class SaveServerTests(TestCase):
    """The alias-changed decision, through ``save_server`` without a request."""

    def test_a_registration_queues_a_check(self) -> None:
        server = Server(name="Web", ssh_alias="web.example.com")
        self.assertIs(save_server(server), SaveOutcome.QUEUED)
        self.assertEqual(DiscoveryAttempt.objects.get().ssh_alias, "web.example.com")

    def test_only_a_changed_alias_queues_a_check(self) -> None:
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        server.name = "Renamed"
        self.assertIs(save_server(server), SaveOutcome.SAVED)
        self.assertFalse(DiscoveryAttempt.objects.exists())
        server.ssh_alias = "db-1"
        self.assertIs(save_server(server), SaveOutcome.QUEUED)
        self.assertEqual(DiscoveryAttempt.objects.get().ssh_alias, "db-1")

    def test_an_active_check_keeps_the_alias(self) -> None:
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        request_discovery(server)
        server.name = "Renamed"
        server.ssh_alias = "db-1"
        self.assertIs(save_server(server), SaveOutcome.BUSY)
        # Nothing was saved, not even the new name.
        server.refresh_from_db()
        self.assertEqual((server.name, server.ssh_alias), ("Web", "web.example.com"))
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)

    def test_a_taken_alias_saves_nothing(self) -> None:
        Server.objects.create(name="Database", ssh_alias="db-1")
        self.assertIs(save_server(Server(name="Web", ssh_alias="db-1")), SaveOutcome.TAKEN)
        self.assertEqual(Server.objects.count(), 1)
        self.assertFalse(DiscoveryAttempt.objects.exists())

    def test_an_edit_never_registers_a_removed_server_again(self) -> None:
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        Server.objects.filter(pk=server.pk).delete()
        for alias in ("web.example.com", "db-1"):
            server.ssh_alias = alias
            with self.subTest(alias=alias), self.assertRaises(Server.DoesNotExist):
                save_server(server)
        self.assertFalse(Server.objects.exists())


class RemovalTests(DiscoveryTestCase):
    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def remove_url(self, server: Server | None = None) -> str:
        return f"/servers/{(server or self.server).pk}/remove/"

    def confirm(self, client: Client | None = None) -> HttpResponseBase:
        return (client or self.client).post(self.remove_url(), {"confirm": "remove"})

    def test_removal_requires_sign_in_and_permissions(self) -> None:
        url = self.remove_url()
        self.assertRedirects(self.client.get(url), f"/accounts/login/?next={url}")
        self.assertRedirects(self.confirm(), f"/accounts/login/?next={url}")
        for codenames in (("view_server",), ("delete_server",), ("view_server", "change_server")):
            with self.subTest(codenames=codenames):
                self.user.user_permissions.clear()
                self.sign_in_with(*codenames)
                self.assertEqual(self.client.get(url).status_code, 403)
                self.assertContains(self.confirm(), "Access denied", status_code=403)
        self.assertTrue(Server.objects.filter(pk=self.server.pk).exists())
        self.user.user_permissions.clear()
        self.sign_in_with("view_server", "change_server")
        self.assertNotContains(self.client.get(f"/servers/{self.server.pk}/"), url)

    def test_removal_requires_csrf(self) -> None:
        self.grant("view_server", "delete_server")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        self.assertEqual(self.confirm(client).status_code, 403)
        self.assertTrue(Server.objects.filter(pk=self.server.pk).exists())

    def test_removal_requires_confirmation(self) -> None:
        request_discovery(self.server)
        self.run_worker()
        self.sign_in_with("view_server", "delete_server")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(
            page, f'href="{self.remove_url()}">Remove<span class="usa-sr-only"> Web</span></a>'
        )
        # Opening the confirmation, or posting without confirming, deletes nothing.
        page = self.client.get(self.remove_url())
        self.assertContains(page, "<h1>Remove Web</h1>", html=True)
        self.assertContains(
            page,
            '<button type="submit" class="usa-button barectl-button--destructive" '
            'name="confirm" value="remove">Remove server</button>',
            html=True,
        )
        self.assertContains(page, "1 discovery attempt and the latest snapshot")
        self.assertContains(page, "<code>web.example.com</code>")
        self.assertContains(page, "Barectl does not connect to the server")
        self.assertContains(page, "known_hosts")
        response = self.client.post(self.remove_url())
        self.assertContains(response, "<h1>Remove Web</h1>", html=True)
        self.assertEqual(Server.objects.count(), 1)
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)
        self.assertEqual(DiscoverySnapshot.objects.count(), 1)

    def test_removal_deletes_the_registration_and_its_history_only(self) -> None:
        known_hosts = self.ssh_config.with_name("known_hosts")
        known_hosts.write_text(f"web.example.com {HOST_KEY}\n", encoding="utf-8")
        other = Server.objects.create(name="Database", ssh_alias="db-1")
        request_discovery(self.server)
        request_discovery(other)
        self.run_worker()
        # A failed refresh adds history alongside the successful snapshot.
        self.remote.failure = "Barectl could not reach the SSH service configured for web."
        request_discovery(self.server)
        self.run_worker()
        self.assertEqual(DiscoveryAttempt.objects.filter(server=self.server).count(), 2)
        controller_files = {path: path.read_bytes() for path in (self.ssh_config, known_hosts)}
        connections = len(self.remote.targets)
        removed_attempts = list(
            DiscoveryAttempt.objects.filter(server=self.server).values_list("pk", flat=True)
        )

        self.sign_in_with("view_server", "delete_server", "add_server")
        response = self.confirm()

        self.assertRedirects(response, "/", fetch_redirect_response=False)
        self.assertFalse(Server.objects.filter(pk=self.server.pk).exists())
        self.assertFalse(DiscoveryAttempt.objects.filter(server_id=self.server.pk).exists())
        self.assertFalse(DiscoverySnapshot.objects.filter(server_id=self.server.pk).exists())
        self.assertFalse(
            ComponentObservation.objects.filter(snapshot__server_id=self.server.pk).exists()
        )
        # The worker's records of the removed attempts go too.
        tasks = DBTaskResult.objects.values_list("args_kwargs__args__0", flat=True)
        self.assertFalse(set(tasks) & set(removed_attempts))
        # Other servers keep their history.
        self.assertEqual(DiscoveryAttempt.objects.get().server, other)
        self.assertEqual(DiscoverySnapshot.objects.get().server, other)
        self.assertEqual(list(tasks), [DiscoveryAttempt.objects.get().pk])
        # Nothing connected to the server, and the controller's files are unchanged.
        self.assertEqual(len(self.remote.targets), connections)
        for path, content in controller_files.items():
            self.assertEqual(path.read_bytes(), content)
        page = self.client.get("/")
        self.assertContains(page, "Removed Web and its discovery history from Barectl.")
        self.assertNotContains(page, "web.example.com")
        # The alias stays configured on the controller, so it can be registered again.
        form = self.client.get("/servers/add/")
        self.assertContains(form, '<option value="web.example.com">')

    def test_removal_is_refused_while_discovery_is_active(self) -> None:
        attempt = request_discovery(self.server)
        self.sign_in_with("view_server", "delete_server")
        for state in (DiscoveryAttempt.Status.QUEUED, DiscoveryAttempt.Status.RUNNING):
            with self.subTest(state=state):
                record_attempt(attempt, state)
                page = self.client.get(self.remove_url())
                self.assertContains(page, "Discovery in progress")
                self.assertNotContains(page, 'name="confirm"')
                # Only a confirmed removal is refused as a conflict.
                self.assertEqual(self.client.post(self.remove_url()).status_code, 200)
                response = self.confirm()
                self.assertContains(response, "Discovery in progress", status_code=409)
                self.assertTrue(Server.objects.filter(pk=self.server.pk).exists())
                self.assertTrue(DiscoveryAttempt.objects.filter(pk=attempt.pk).exists())

        # The active job was not lost: once it finishes, removal proceeds.
        record_attempt(attempt)
        self.run_worker()
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED)
        self.assertRedirects(self.confirm(), "/", fetch_redirect_response=False)
        self.assertFalse(Server.objects.exists())

    def test_a_refusal_is_reported_after_the_blocking_check_finishes(self) -> None:
        self.sign_in_with("view_server", "delete_server")
        # A concurrent check blocked the removal and finished before the page rendered.
        with mock.patch("servers.views.remove_server", side_effect=RemovalBlocked):
            response = self.confirm()
        self.assertContains(response, "so the server was not removed", status_code=409)
        self.assertContains(response, 'name="confirm"', status_code=409)
        self.assertTrue(Server.objects.filter(pk=self.server.pk).exists())

    def test_an_abandoned_attempt_does_not_block_removal(self) -> None:
        record_attempt(request_discovery(self.server), DiscoveryAttempt.Status.RUNNING, age=STALE)
        self.sign_in_with("view_server", "delete_server")
        self.assertRedirects(self.confirm(), "/", fetch_redirect_response=False)
        self.assertFalse(Server.objects.exists())
        self.assertFalse(DiscoveryAttempt.objects.exists())
        # Its task never ran, and its record goes with the attempt.
        self.assertFalse(DBTaskResult.objects.exists())

    def test_removal_keeps_only_task_records_a_live_worker_still_holds(self) -> None:
        request_discovery(self.server)
        self.run_worker()
        task = DBTaskResult.objects.get()
        # A worker that finished the attempt but has not saved its task yet, and one that
        # was stopped mid-task long ago.
        for started, kept in ((timezone.now(), True), (timezone.now() - STALE, False)):
            with self.subTest(kept=kept):
                DBTaskResult.objects.filter(pk=task.pk).update(
                    status=TaskResultStatus.RUNNING, started_at=started
                )
                with transaction.atomic():
                    forget_discovery(self.server)
                    self.assertFalse(DiscoveryAttempt.objects.exists())
                    self.assertEqual(DBTaskResult.objects.exists(), kept)
                    transaction.set_rollback(True)

    def test_removed_and_unknown_servers_are_not_found(self) -> None:
        self.sign_in_with("view_server", "delete_server", "add_discoveryattempt")
        self.assertEqual(self.client.get("/servers/999/remove/").status_code, 404)
        self.confirm()
        self.assertEqual(self.confirm().status_code, 404)
        self.assertEqual(self.client.post(f"/servers/{self.server.pk}/verify/").status_code, 404)
        self.assertFalse(DiscoveryAttempt.objects.exists())


class RemovalRaceTests(TransactionTestCase):
    """Removal against discovery started by a concurrent request, with real commits.

    An attempt created inside removal's transaction, after its check, stands in for any
    interleaving a database allows: the foreign key check at commit refuses it. Foreign
    keys are checked when a transaction commits, so these tests cannot run inside
    TestCase's wrapping transaction. ``discovery.test_race`` runs the two requests in
    separate processes on a database file.
    """

    server: Server

    @override
    def setUp(self) -> None:
        remote = FakeServer()
        self.enterContext(mock.patch.object(ssh, "connect", remote.connect))
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (directory / "config").write_text("Host web.example.com\n", encoding="utf-8")
        self.enterContext(override_settings(SSH_CONFIG_PATH=str(directory / "config")))
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        request_discovery(self.server)
        run_worker()

    def test_discovery_queued_after_the_active_check_blocks_removal(self) -> None:
        delete = Collector.delete
        previous = DiscoveryAttempt.objects.get()

        def queue_then_delete(collector: Collector) -> tuple[int, dict[str, int]]:
            if Server in collector.data:
                # Another request queues discovery after removal checked for active
                # attempts, before the server row is deleted.
                request_discovery(self.server)
            return delete(collector)

        with (
            mock.patch.object(Collector, "delete", queue_then_delete),
            self.assertRaises(RemovalBlocked),
        ):
            remove_server(self.server)
        # The whole removal was rolled back: the registration and its history remain.
        self.assertTrue(Server.objects.filter(pk=self.server.pk).exists())
        self.assertEqual(DiscoveryAttempt.objects.get(), previous)
        self.assertEqual(DiscoverySnapshot.objects.get().attempt, previous)

    def test_discovery_requested_after_removal_is_refused(self) -> None:
        # A request that loaded the server before another request removed it.
        loaded = Server.objects.get(pk=self.server.pk)
        remove_server(self.server)
        with self.assertRaises(Server.DoesNotExist):
            request_discovery(loaded)
        self.assertFalse(DiscoveryAttempt.objects.exists())
        self.assertFalse(DBTaskResult.objects.filter(status="READY").exists())
