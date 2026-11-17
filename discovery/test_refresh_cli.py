"""Operator refresh through its shared interface and Django command."""

import io
import json
from typing import cast, override
from unittest import mock

from django.contrib.auth.models import Permission
from django.core.exceptions import PermissionDenied
from django.core.management import call_command
from django.core.management.base import CommandError

from operations.models import RemoteOperation
from servers.models import Server

from .fakes import DiscoveryTestCase
from .models import DiscoveryAttempt
from .services import RefreshNotFound, read_refresh, request_refresh


class RefreshCommandTests(DiscoveryTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        self.user.set_password("local secret")
        self.user.save(update_fields=["password"])
        self.grant("view_server", "add_discoveryattempt")

    def command(self, *words: str) -> dict[str, object]:
        output = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO("local secret\n")):
            call_command(
                "barectl",
                "server",
                *words,
                "--username",
                "operator",
                "--password-stdin",
                "--json",
                stdout=output,
            )
        return cast(dict[str, object], json.loads(output.getvalue()))

    def test_request_shares_attempt_and_worker_publishes_only_its_snapshot(self) -> None:
        first = self.command("refresh", str(self.server.pk))
        self.assertEqual(first["code"], "accepted")
        self.assertEqual(first["snapshot"], None)
        self.assertEqual(self.command("refresh", str(self.server.pk))["code"], "shared_active")
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)
        self.assertEqual(self.remote.targets, [])

        self.run_worker()
        first_operation = cast(dict[str, object], first["operation"])
        result = self.command("refresh-status", str(first_operation["id"]))
        self.assertEqual(result["code"], "succeeded")
        snapshot = cast(dict[str, object], result["snapshot"])
        os_value = cast(dict[str, object], snapshot["os"])
        self.assertEqual(os_value["outcome"], "observed")
        self.assertTrue(snapshot["connection_current"])
        serialized = json.dumps(result)
        self.assertNotIn("/etc/", serialized)
        self.assertNotIn("settings", serialized)

    def test_status_does_not_queue_and_missing_id_is_private(self) -> None:
        with self.assertRaises(RefreshNotFound):
            read_refresh(404, user=self.user)
        self.assertEqual(DiscoveryAttempt.objects.count(), 0)

        self.user.user_permissions.remove(Permission.objects.get(codename="add_discoveryattempt"))
        with self.assertRaises(PermissionDenied):
            read_refresh(404, user=self.user)
        with self.assertRaises(PermissionDenied):
            request_refresh(self.server.pk, user=self.user)

    def test_non_terminal_requires_stdin_flag(self) -> None:
        with (
            mock.patch("sys.stdin", io.StringIO("local secret\n")),
            self.assertRaises(CommandError),
        ):
            call_command(
                "barectl", "server", "refresh", str(self.server.pk), "--username", "operator"
            )
        self.assertEqual(DiscoveryAttempt.objects.count(), 0)

    def test_bad_password_and_missing_server(self) -> None:
        output = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO("bad\n")), self.assertRaises(CommandError):
            call_command(
                "barectl",
                "server",
                "refresh",
                str(self.server.pk),
                "--username",
                "operator",
                "--password-stdin",
                "--json",
                stdout=output,
            )
        self.assertEqual(json.loads(output.getvalue())["code"], "authentication_failed")
        self.assertEqual(DiscoveryAttempt.objects.count(), 0)

        with self.assertRaises(CommandError):
            self.command("refresh", "404")

    def test_wait_timeout_keeps_the_queued_operation(self) -> None:
        output = io.StringIO()
        with (
            mock.patch("sys.stdin", io.StringIO("local secret\n")),
            mock.patch("dashboard.management.commands.barectl.time.sleep"),
            mock.patch("dashboard.management.commands.barectl.time.monotonic", side_effect=[0, 1]),
            self.assertRaises(CommandError),
        ):
            call_command(
                "barectl",
                "server",
                "refresh",
                str(self.server.pk),
                "--username",
                "operator",
                "--password-stdin",
                "--wait",
                "--timeout",
                "1",
                "--json",
                stdout=output,
            )
        result = json.loads(output.getvalue())
        self.assertEqual(result["code"], "client_timeout")
        self.assertEqual(result["operation"]["id"], DiscoveryAttempt.objects.get().pk)
        self.assertEqual(DiscoveryAttempt.objects.get().status, DiscoveryAttempt.Status.QUEUED)

    def test_other_operation_blocks_without_a_discovery_attempt(self) -> None:
        blocker = RemoteOperation.objects.create(
            server=self.server,
            kind=RemoteOperation.Kind.CHANGE_PREPARATION,
            status=RemoteOperation.Status.QUEUED,
            ssh_alias=self.server.ssh_alias,
        )
        output = io.StringIO()
        with (
            mock.patch("sys.stdin", io.StringIO("local secret\n")),
            self.assertRaises(CommandError),
        ):
            call_command(
                "barectl",
                "server",
                "refresh",
                str(self.server.pk),
                "--username",
                "operator",
                "--password-stdin",
                "--json",
                stdout=output,
            )
        result = json.loads(output.getvalue())
        self.assertEqual(result["code"], "busy")
        self.assertEqual(result["operation"]["id"], blocker.pk)
        self.assertEqual(DiscoveryAttempt.objects.count(), 0)

    def test_worker_refuses_revoked_alias_actor_and_status_has_no_old_snapshot(self) -> None:
        first = self.command("refresh", str(self.server.pk))
        self.run_worker()
        self.assertEqual(DiscoveryAttempt.objects.get().status, DiscoveryAttempt.Status.SUCCEEDED)
        second = self.command("refresh", str(self.server.pk))
        self.user.user_permissions.remove(Permission.objects.get(codename="add_discoveryattempt"))
        self.run_worker()
        self.grant("add_discoveryattempt")
        second_operation = cast(dict[str, object], second["operation"])
        output = io.StringIO()
        with (
            mock.patch("sys.stdin", io.StringIO("local secret\n")),
            self.assertRaises(CommandError),
        ):
            call_command(
                "barectl",
                "server",
                "refresh-status",
                str(second_operation["id"]),
                "--username",
                "operator",
                "--password-stdin",
                "--json",
                stdout=output,
            )
        result = json.loads(output.getvalue())
        self.assertEqual(result["code"], "failed")
        self.assertIsNone(result["snapshot"])
        self.assertEqual(result["snapshot_availability"], "not_applicable")
        self.assertNotEqual(first["operation"], second["operation"])

    def test_wait_observes_worker_completion_and_resume_never_queues(self) -> None:
        output = io.StringIO()
        with (
            mock.patch("sys.stdin", io.StringIO("local secret\n")),
            mock.patch(
                "dashboard.management.commands.barectl.time.sleep",
                side_effect=lambda _: self.run_worker(),
            ),
        ):
            call_command(
                "barectl",
                "server",
                "refresh",
                str(self.server.pk),
                "--username",
                "operator",
                "--password-stdin",
                "--wait",
                "--json",
                stdout=output,
            )
        result = json.loads(output.getvalue())
        self.assertEqual(result["code"], "succeeded")
        self.assertEqual(result["snapshot_availability"], "retained")
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)
        resumed = self.command("refresh-status", str(result["operation"]["id"]))
        self.assertEqual(resumed["code"], "succeeded")
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)

    def test_wait_rechecks_permissions_and_rejects_ignored_timeout(self) -> None:
        output = io.StringIO()
        with (
            mock.patch("sys.stdin", io.StringIO("local secret\n")),
            mock.patch(
                "dashboard.management.commands.barectl.time.sleep",
                side_effect=lambda _: self.user.user_permissions.remove(
                    Permission.objects.get(codename="add_discoveryattempt")
                ),
            ),
            self.assertRaises(CommandError),
        ):
            call_command(
                "barectl",
                "server",
                "refresh",
                str(self.server.pk),
                "--username",
                "operator",
                "--password-stdin",
                "--wait",
                "--json",
                stdout=output,
            )
        self.assertEqual(json.loads(output.getvalue())["code"], "permission_denied")
        self.assertEqual(DiscoveryAttempt.objects.get().status, DiscoveryAttempt.Status.QUEUED)

        output = io.StringIO()
        with self.assertRaises(CommandError):
            call_command(
                "barectl",
                "server",
                "refresh-status",
                "1",
                "--username",
                "operator",
                "--password-stdin",
                "--timeout",
                "1",
                "--json",
                stdout=output,
            )
        self.assertEqual(json.loads(output.getvalue())["code"], "invalid_input")
