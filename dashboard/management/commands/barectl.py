"""Local operator commands for the shared Refresh server operation."""

import getpass
import json
import sys
import time
from typing import NoReturn, override

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.core.management.base import BaseCommand, CommandError, CommandParser

from discovery.services import RefreshNotFound, RefreshStatus, read_refresh, request_refresh


class Command(BaseCommand):
    help = "Refresh a server or read a refresh operation on this controller."

    @override
    def add_arguments(self, parser: CommandParser) -> None:
        server = parser.add_subparsers(dest="area", required=True)
        server_parser = server.add_parser("server")
        actions = server_parser.add_subparsers(dest="action", required=True)
        for action, label in (("refresh", "server_id"), ("refresh-status", "operation_id")):
            command = actions.add_parser(action)
            command.add_argument(label, type=int)
            command.add_argument("--username", required=True)
            command.add_argument("--password-stdin", action="store_true")
            command.add_argument("--json", action="store_true")
            command.add_argument("--wait", action="store_true")
            command.add_argument("--timeout", type=int)

    def _fail(
        self,
        machine: bool,
        code: str,
        message: str,
        status: int,
        operation_id: int | None = None,
    ) -> NoReturn:
        if machine:
            self.stdout.write(
                json.dumps(
                    {"version": 1, "code": code, "message": message, "operation_id": operation_id}
                )
            )
        raise CommandError(message, returncode=status)

    def _actor(self, options: dict[str, object], machine: bool) -> User:
        if options["password_stdin"]:
            password = sys.stdin.readline().rstrip("\r\n")
        elif sys.stdin.isatty():
            password = getpass.getpass("Password: ")
        else:
            self._fail(
                machine,
                "credentials_required",
                "Use --password-stdin when input is not a terminal.",
                2,
            )
        user = authenticate(username=options["username"], password=password)
        if not isinstance(user, User) or not user.is_active:
            self._fail(machine, "authentication_failed", "Authentication failed.", 3)
        return user

    def _operation_id(
        self, options: dict[str, object], user: User, machine: bool
    ) -> tuple[int, str]:
        if options["action"] == "refresh":
            server_id = options["server_id"]
            if not isinstance(server_id, int) or server_id <= 0:
                self._fail(machine, "invalid_input", "Server ID must be positive.", 2)
            requested = request_refresh(server_id, user=user)
            operation, decision = requested.operation, requested.disposition
            if not machine:
                self.stdout.write(f"Operation {operation.pk}: {decision}")
            if decision == "busy":
                if machine:
                    self.stdout.write(
                        json.dumps(
                            {
                                "version": 1,
                                "code": "busy",
                                "operation": {
                                    "id": operation.pk,
                                    "kind": operation.kind,
                                    "status": operation.status,
                                },
                            }
                        )
                    )
                raise CommandError("Another server operation is active.", returncode=5)
            return operation.pk, decision
        operation_id = options["operation_id"]
        if not isinstance(operation_id, int) or operation_id <= 0:
            self._fail(machine, "invalid_input", "Operation ID must be positive.", 2)
        return operation_id, "in_progress"

    def _poll(self, operation_id: int, user: User, wait: bool, timeout: int) -> RefreshStatus:
        payload = read_refresh(operation_id, user=user)
        deadline = time.monotonic() + timeout
        while wait and payload["code"] == "in_progress":
            if time.monotonic() >= deadline:
                return {
                    **payload,
                    "code": "client_timeout",
                    "message": "Still running; use refresh-status to resume.",
                }
            time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
            payload = read_refresh(operation_id, user=user)
        return payload

    @override
    def handle(self, *args: object, **options: object) -> None:
        machine = options["json"] is True
        timeout_option = options["timeout"]
        if timeout_option is not None and options["wait"] is not True:
            self._fail(machine, "invalid_input", "--timeout requires --wait.", 2)
        timeout = 120 if timeout_option is None else timeout_option
        if not isinstance(timeout, int) or timeout <= 0 or timeout > 600:
            self._fail(machine, "invalid_input", "Timeout must be between 1 and 600 seconds.", 2)
        user = self._actor(options, machine)

        operation_id: int | None = None
        try:
            operation_id, decision = self._operation_id(options, user, machine)
            payload = self._poll(operation_id, user, options["wait"] is True, timeout)
        except RefreshNotFound:
            self._fail(machine, "not_found", "Server or refresh operation was not found.", 4)
        except PermissionDenied:
            self._fail(
                machine,
                "permission_denied",
                "Permission to refresh this server is unavailable.",
                3,
                operation_id,
            )
        except KeyboardInterrupt:
            self._fail(
                machine,
                "interrupted",
                "Stopped waiting; the operation continues.",
                130,
                operation_id,
            )

        if machine:
            if options["action"] == "refresh" and not options["wait"]:
                payload = {**payload, "code": decision}
            self.stdout.write(json.dumps(payload))
        else:
            status = payload["operation"]["status"]
            self.stdout.write(f"Operation {operation_id}: {payload['code']} ({status})")
        if payload["code"] == "failed":
            raise CommandError("Refresh failed.", returncode=6)
        if payload["code"] == "client_timeout":
            raise CommandError("Wait timed out; the operation continues.", returncode=7)
