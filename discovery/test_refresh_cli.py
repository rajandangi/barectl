"""Operator refresh through its shared interface and Django command."""

import io
import json
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from datetime import timedelta
from pathlib import Path
from typing import cast, override
from unittest import mock

from django.contrib.auth.models import Permission
from django.core.exceptions import PermissionDenied
from django.core.management import call_command
from django.core.management.base import CommandError, OutputWrapper
from django.utils import timezone

from dashboard.management.commands.barectl import Command
from operations import lifecycle
from operations.models import RemoteOperation
from servers.models import Server

from .fakes import DiscoveryTestCase
from .models import DiscoveryAttempt, DiscoverySnapshot
from .services import RefreshNotFound, queue_discovery, read_refresh, request_refresh


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

    def run_command(self, *words: str) -> tuple[int, str]:
        output = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO("local secret\n")):
            try:
                call_command("barectl", "server", *words, stdout=output)
            except CommandError as error:
                return error.returncode, output.getvalue()
        return 0, output.getvalue()

    def test_parser_errors_have_a_json_envelope(self) -> None:
        for words in (
            ("refresh", "nope", "--username", "operator"),
            ("refresh", "1", "--username", "operator", "--wait", "--timeout", "bad"),
            ("refresh", "1"),
        ):
            with self.subTest(words=words):
                command = Command()
                self.assertFalse(command.requires_system_checks)
                output = io.StringIO()
                command.stdout = OutputWrapper(output)
                parser = command.create_parser("manage.py", "barectl")
                with self.assertRaises(CommandError) as caught:
                    parser.parse_args(["server", *words, "--json"])
                self.assertEqual(caught.exception.returncode, 2)
                self.assertEqual(json.loads(output.getvalue())["code"], "invalid_input")
                self.assertEqual(output.getvalue().count("\n"), 1)

        output = io.StringIO()
        command = Command()
        command.stdout = OutputWrapper(output)
        parser = command.create_parser("manage.py", "barectl")
        with self.assertRaises(CommandError):
            parser.parse_args(["server", "refresh", "nope", "--username", "operator"])
        self.assertEqual(output.getvalue(), "")
        help_output = io.StringIO()
        with redirect_stdout(help_output), self.assertRaises(SystemExit) as help_caught:
            parser.parse_args(["server", "refresh", "--help", "--json"])
        self.assertEqual(help_caught.exception.code, 0)
        self.assertIn("usage:", help_output.getvalue())
        self.assertEqual(output.getvalue(), "")
        options = parser.parse_args(
            ["--verbosity", "0", "server", "refresh", "1", "--username", "operator"]
        )
        self.assertEqual(options.verbosity, 0)
        version_output = io.StringIO()
        with redirect_stdout(version_output), self.assertRaises(SystemExit) as version_caught:
            parser.parse_args(["--version"])
        self.assertEqual(version_caught.exception.code, 0)
        self.assertTrue(version_output.getvalue())

    def test_rejected_argument_values_are_not_reported(self) -> None:
        sentinel = "DUMMY_CREDENTIAL_SENTINEL"
        cases = (
            ("refresh", "1", "--password=" + sentinel),
            ("refresh-status", "1", "--password", sentinel),
            ("refresh", "1", "--password-not-supported", sentinel),
            ("refresh-status", sentinel),
            ("refresh", "1", "--timeout", sentinel),
        )
        for action in cases:
            for machine in (False, True):
                with self.subTest(action=action, machine=machine):
                    output, errors = io.StringIO(), io.StringIO()
                    command = Command()
                    command.stdout = OutputWrapper(output)
                    parser = command.create_parser("manage.py", "barectl")
                    words = ["server", *action, "--username", "operator"]
                    if machine:
                        words.append("--json")
                    with (
                        mock.patch("dashboard.management.commands.barectl.authenticate") as auth,
                        mock.patch(
                            "dashboard.management.commands.barectl.request_refresh"
                        ) as request,
                        mock.patch("dashboard.management.commands.barectl.read_refresh") as read,
                        redirect_stderr(errors),
                        self.assertRaises(CommandError) as caught,
                    ):
                        parser.parse_args(words)
                    self.assertEqual(caught.exception.returncode, 2)
                    self.assertNotIn(sentinel, output.getvalue() + errors.getvalue())
                    self.assertNotIn(sentinel, str(caught.exception))
                    auth.assert_not_called()
                    request.assert_not_called()
                    read.assert_not_called()
                    if machine:
                        self.assertEqual(json.loads(output.getvalue())["code"], "invalid_input")
                        self.assertEqual(output.getvalue().count("\n"), 1)
                    else:
                        self.assertEqual(output.getvalue(), "")
        self.assertFalse(DiscoveryAttempt.objects.exists())

    def test_subprocess_parser_diagnostics_hide_rejected_values(self) -> None:
        sentinel = "DUMMY_CREDENTIAL_SENTINEL"
        root = Path(__file__).resolve().parents[1]
        for extra in (
            ("--json", "--password=" + sentinel),
            ("--json", "--password", sentinel),
            ("--password-not-supported", sentinel),
            ("--json", "--traceback", "--timeout", sentinel),
        ):
            with self.subTest(extra=extra):
                result = subprocess.run(  # noqa: S603 - fixed local command with dummy test input
                    [
                        sys.executable,
                        "manage.py",
                        "barectl",
                        "server",
                        "refresh",
                        "1",
                        "--username",
                        "operator",
                        *extra,
                    ],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertNotIn(sentinel, result.stdout + result.stderr)
                if "--json" in extra:
                    self.assertEqual(json.loads(result.stdout)["code"], "invalid_input")
                    self.assertEqual(result.stdout.count("\n"), 1)
                else:
                    self.assertEqual(result.stdout, "")

    def test_id_validation_and_timeout_bounds(self) -> None:
        common = ("--username", "operator", "--password-stdin", "--json")
        for action in ("refresh", "refresh-status"):
            for value in ("0", "-1"):
                with self.subTest(action=action, value=value):
                    status, output = self.run_command(action, value, *common)
                    self.assertEqual(status, 2)
                    self.assertEqual(json.loads(output)["code"], "invalid_input")
        for value in ("0", "601"):
            status, output = self.run_command(
                "refresh", str(self.server.pk), *common, "--wait", "--timeout", value
            )
            self.assertEqual(status, 2)
            self.assertEqual(json.loads(output)["code"], "invalid_input")
        for value in ("1", "600"):
            with mock.patch(
                "dashboard.management.commands.barectl.time.monotonic", side_effect=[0, int(value)]
            ):
                status, output = self.run_command(
                    "refresh", str(self.server.pk), *common, "--wait", "--timeout", value
                )
            self.assertEqual(status, 7)
            self.assertEqual(json.loads(output)["code"], "client_timeout")

    def test_terminal_prompt_text_status_and_interrupt_keep_id(self) -> None:
        with (
            mock.patch("sys.stdin") as stdin,
            mock.patch(
                "dashboard.management.commands.barectl.getpass.getpass", return_value="local secret"
            ) as prompt,
        ):
            stdin.isatty.return_value = True
            output = io.StringIO()
            call_command(
                "barectl",
                "server",
                "refresh",
                str(self.server.pk),
                "--username",
                "operator",
                stdout=output,
            )
        prompt.assert_called_once()
        operation_id = DiscoveryAttempt.objects.get().pk
        self.assertIn(f"Operation {operation_id}: accepted", output.getvalue())

        output = io.StringIO()
        with (
            mock.patch("sys.stdin", io.StringIO("local secret\n")),
            mock.patch(
                "dashboard.management.commands.barectl.time.sleep", side_effect=KeyboardInterrupt
            ),
            self.assertRaises(CommandError) as caught,
        ):
            call_command(
                "barectl",
                "server",
                "refresh-status",
                str(operation_id),
                "--username",
                "operator",
                "--password-stdin",
                "--wait",
                stdout=output,
            )
        self.assertEqual(caught.exception.returncode, 130)
        self.assertEqual(output.getvalue(), f"Operation {operation_id}: checking\n")
        self.assertEqual(DiscoveryAttempt.objects.get().status, DiscoveryAttempt.Status.QUEUED)

        status_output = io.StringIO()
        with (
            mock.patch("sys.stdin", io.StringIO("local secret\n")),
            mock.patch(
                "dashboard.management.commands.barectl.time.sleep", side_effect=KeyboardInterrupt
            ),
            self.assertRaises(CommandError) as caught,
        ):
            call_command(
                "barectl",
                "server",
                "refresh-status",
                str(operation_id),
                "--username",
                "operator",
                "--password-stdin",
                "--wait",
                "--json",
                stdout=status_output,
            )
        self.assertEqual(caught.exception.returncode, 130)
        self.assertEqual(json.loads(status_output.getvalue())["operation_id"], operation_id)

    def test_text_status_without_wait_and_missing_operation(self) -> None:
        operation_id = cast(
            dict[str, object], self.command("refresh", str(self.server.pk))["operation"]
        )["id"]
        status, output = self.run_command(
            "refresh-status", str(operation_id), "--username", "operator", "--password-stdin"
        )
        self.assertEqual(status, 0)
        self.assertEqual(
            output,
            f"Operation {operation_id}: checking\nOperation {operation_id}: in_progress (queued)\n",
        )
        status, output = self.run_command(
            "refresh-status", "404", "--username", "operator", "--password-stdin", "--json"
        )
        self.assertEqual(status, 4)
        self.assertEqual(json.loads(output)["code"], "not_found")

    def test_failed_wait_and_stale_connection_have_exit_six(self) -> None:
        common = ("--username", "operator", "--password-stdin", "--json")
        for failure, code in (
            ("A remote read failed.", "failed"),
            ("The saved connection changed; request a new check.", "stale_connection"),
        ):
            with self.subTest(code=code):
                operation = cast(
                    dict[str, object], self.command("refresh", str(self.server.pk))["operation"]
                )
                operation_id = cast(int, operation["id"])

                def fail_during_wait(
                    _: float, *, target: int = operation_id, reason: str = failure
                ) -> None:
                    RemoteOperation.objects.filter(pk=target).update(
                        status=RemoteOperation.Status.FAILED, failure=reason
                    )

                with mock.patch(
                    "dashboard.management.commands.barectl.time.sleep", side_effect=fail_during_wait
                ):
                    status, output = self.run_command(
                        "refresh-status", str(operation_id), *common, "--wait"
                    )
                self.assertEqual(status, 6)
                result = json.loads(output)
                self.assertEqual(result["code"], code)
                self.assertIsNone(result["snapshot"])

    def test_revoked_permission_blocks_recovery(self) -> None:
        self.user.user_permissions.remove(Permission.objects.get(codename="add_discoveryattempt"))
        with mock.patch.object(lifecycle, "_recover_stale_operations") as recover:
            with self.assertRaises(PermissionDenied):
                request_refresh(self.server.pk, user=self.user)
            with self.assertRaises(PermissionDenied):
                read_refresh(1, user=self.user)
        recover.assert_not_called()

    def test_removed_or_inactive_actor_cannot_trigger_recovery(self) -> None:
        for inactive in (True, False):
            with self.subTest(inactive=inactive):
                actor = self.user
                if inactive:
                    actor.is_active = False
                    actor.save(update_fields=["is_active"])
                else:
                    actor.delete()
                with mock.patch.object(lifecycle, "_recover_stale_operations") as recover:
                    with self.assertRaises(PermissionDenied):
                        request_refresh(self.server.pk, user=actor)
                    with self.assertRaises(PermissionDenied):
                        read_refresh(1, user=actor)
                recover.assert_not_called()
                if inactive:
                    actor.is_active = True
                    actor.save(update_fields=["is_active"])
                else:
                    break

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

    def test_status_keeps_retained_snapshot_historical_after_connection_change(self) -> None:
        requested = self.command("refresh", str(self.server.pk))
        self.run_worker()
        operation = cast(dict[str, object], requested["operation"])
        operation_id = cast(int, operation["id"])
        current = self.command("refresh-status", str(operation_id))
        current_snapshot = cast(dict[str, object], current["snapshot"])
        self.assertTrue(current_snapshot["connection_current"])

        self.server.connection_revision += 1
        self.server.save(update_fields=["connection_revision"])
        count = DiscoveryAttempt.objects.count()
        remote_reads = len(self.remote.targets)
        historical = self.command("refresh-status", str(operation_id))

        self.assertEqual(historical["code"], "succeeded")
        self.assertEqual(historical["snapshot_availability"], "retained")
        self.assertEqual(historical["operation"], current["operation"])
        self.assertEqual(historical["snapshot"], {**current_snapshot, "connection_current": False})
        self.assertEqual(DiscoveryAttempt.objects.count(), count)
        self.assertEqual(len(self.remote.targets), remote_reads)

    def test_status_elapsed_seconds_stops_at_completion(self) -> None:
        queued_at = timezone.now() - timedelta(hours=1)
        for status, started_at, finished_at, expected in (
            (
                RemoteOperation.Status.SUCCEEDED,
                queued_at + timedelta(seconds=10),
                queued_at + timedelta(seconds=40),
                30,
            ),
            (
                RemoteOperation.Status.FAILED,
                queued_at + timedelta(seconds=10),
                queued_at + timedelta(seconds=40),
                30,
            ),
            (RemoteOperation.Status.FAILED, None, queued_at + timedelta(seconds=20), 20),
            (RemoteOperation.Status.FAILED, None, queued_at - timedelta(seconds=5), 0),
        ):
            with self.subTest(status=status, started_at=started_at, finished_at=finished_at):
                attempt = request_refresh(self.server.pk, user=self.user).operation
                RemoteOperation.objects.filter(pk=attempt.pk).update(
                    status=status,
                    queued_at=queued_at,
                    started_at=started_at,
                    finished_at=finished_at,
                )
                result = read_refresh(attempt.pk, user=self.user)
                self.assertEqual(result["progress"]["elapsed_seconds"], expected)
                with mock.patch(
                    "discovery.services.timezone.now", return_value=queued_at + timedelta(hours=2)
                ):
                    later = read_refresh(attempt.pk, user=self.user)
                self.assertEqual(later["progress"]["elapsed_seconds"], expected)

    def test_status_elapsed_seconds_advances_for_queued_and_running(self) -> None:
        attempt = request_refresh(self.server.pk, user=self.user).operation
        queued_at = timezone.now()
        RemoteOperation.objects.filter(pk=attempt.pk).update(queued_at=queued_at)
        with mock.patch(
            "discovery.services.timezone.now", return_value=queued_at + timedelta(seconds=10)
        ):
            queued_first = read_refresh(attempt.pk, user=self.user)
        with mock.patch(
            "discovery.services.timezone.now", return_value=queued_at + timedelta(seconds=20)
        ):
            queued_later = read_refresh(attempt.pk, user=self.user)
        self.assertEqual(queued_first["progress"]["elapsed_seconds"], 10)
        self.assertEqual(queued_later["progress"]["elapsed_seconds"], 20)

        started_at = queued_at + timedelta(seconds=5)
        RemoteOperation.objects.filter(pk=attempt.pk).update(
            status=RemoteOperation.Status.RUNNING,
            started_at=started_at,
        )
        with mock.patch(
            "discovery.services.timezone.now", return_value=queued_at + timedelta(seconds=20)
        ):
            running_first = read_refresh(attempt.pk, user=self.user)
        with mock.patch(
            "discovery.services.timezone.now", return_value=queued_at + timedelta(seconds=30)
        ):
            running_later = read_refresh(attempt.pk, user=self.user)
        self.assertEqual(running_first["progress"]["elapsed_seconds"], 15)
        self.assertEqual(running_later["progress"]["elapsed_seconds"], 25)

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

    def test_worker_refuses_deleted_refresh_actor_before_alias_ssh(self) -> None:
        requested = request_refresh(self.server.pk, user=self.user)
        attempt = cast(DiscoveryAttempt, requested.operation)
        self.assertIsNone(attempt.connection)
        self.assertEqual(attempt.authority, "discovery.add_discoveryattempt")

        self.user.delete()
        attempt.refresh_from_db()
        self.assertIsNone(attempt.requested_by_id)
        self.run_worker()

        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("account that requested", attempt.failure)
        self.assertEqual(self.remote.targets, [])
        self.assertFalse(DiscoverySnapshot.objects.filter(attempt=attempt).exists())

    def test_worker_allows_anonymous_legacy_alias_check(self) -> None:
        attempt = queue_discovery(self.server)
        self.assertIsNone(attempt.connection)
        self.assertIsNone(attempt.requested_by_id)
        self.assertEqual(attempt.authority, "")

        self.run_worker()

        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED)
        self.assertTrue(DiscoverySnapshot.objects.filter(attempt=attempt).exists())

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
