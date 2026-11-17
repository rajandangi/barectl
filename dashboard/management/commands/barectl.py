"""Local operator commands for the shared Refresh server operation."""

import getpass
import json
import sys
import time
from argparse import Namespace
from collections.abc import Iterable
from typing import Literal, NoReturn, TypeVar, overload, override

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.core.management.base import (
    BaseCommand,
    CommandError,
    CommandParser,
    OutputWrapper,
)

from discovery.services import RefreshNotFound, RefreshStatus, read_refresh, request_refresh
from operations.lifecycle import OperationRefused

_Namespace = TypeVar("_Namespace")


class RefreshCommandParser(CommandParser):
    output: OutputWrapper | None = None

    @override
    def error(self, message: str) -> NoReturn:
        # argparse messages can contain rejected argv values, including credentials.
        super().error("Invalid command arguments.")
        raise AssertionError("Parser error unexpectedly returned.")

    @overload
    def parse_args(
        self, args: Iterable[str] | None = None, namespace: None = None
    ) -> Namespace: ...

    @overload
    def parse_args(self, args: Iterable[str] | None, namespace: _Namespace) -> _Namespace: ...

    @overload
    def parse_args(self, *, namespace: _Namespace) -> _Namespace: ...

    @override
    def parse_args(
        self, args: Iterable[str] | None = None, namespace: _Namespace | None = None
    ) -> _Namespace | Namespace:
        words = list(args) if args is not None else None
        try:
            return super().parse_args(words, namespace)
        except (CommandError, SystemExit) as error:
            if (
                self.output is not None
                and words is not None
                and "--json" in words
                and not (isinstance(error, SystemExit) and error.code == 0)
            ):
                self.output.write(
                    json.dumps(
                        {
                            "version": 1,
                            "code": "invalid_input",
                            "message": "Invalid command arguments.",
                            "operation_id": None,
                        }
                    )
                )
            if isinstance(error, CommandError):
                raise CommandError("Invalid command arguments.", returncode=2) from None
            raise


class Command(BaseCommand):
    help = "Refresh a server or read a refresh operation on this controller."
    # Django's own startup diagnostics run outside the versioned command envelope.
    requires_system_checks: list[str] | tuple[str, ...] | Literal["__all__"] = ()
    _called_from_command_line = False

    @override
    def create_parser(self, prog_name: str, subcommand: str, **kwargs: object) -> CommandParser:
        # Django constructs CommandParser directly; argparse parents preserve its options.
        base_parser = super().create_parser(prog_name, subcommand, **kwargs)
        parser = RefreshCommandParser(
            parents=[base_parser],
            add_help=False,
            prog=base_parser.prog,
            description=base_parser.description,
            formatter_class=base_parser.formatter_class,
            called_from_command_line=self._called_from_command_line,
            allow_abbrev=False,
        )
        parser.output = self.stdout
        return parser

    @override
    def add_arguments(self, parser: CommandParser) -> None:
        server = parser.add_subparsers(
            dest="area", required=True, parser_class=RefreshCommandParser
        )
        server_parser = server.add_parser(
            "server", allow_abbrev=False, called_from_command_line=self._called_from_command_line
        )
        actions = server_parser.add_subparsers(
            dest="action", required=True, parser_class=RefreshCommandParser
        )
        for action, label in (("refresh", "server_id"), ("refresh-status", "operation_id")):
            command = actions.add_parser(
                action, allow_abbrev=False, called_from_command_line=self._called_from_command_line
            )
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
                self.stdout.flush()
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
        if not machine:
            self.stdout.write(f"Operation {operation_id}: checking")
            self.stdout.flush()
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

    def _timeout(self, options: dict[str, object], machine: bool) -> int:
        timeout_option = options["timeout"]
        if timeout_option is not None and options["wait"] is not True:
            self._fail(machine, "invalid_input", "--timeout requires --wait.", 2)
        timeout = 120 if timeout_option is None else timeout_option
        if not isinstance(timeout, int) or timeout <= 0 or timeout > 600:
            self._fail(machine, "invalid_input", "Timeout must be between 1 and 600 seconds.", 2)
        return timeout

    @override
    def handle(self, *args: object, **options: object) -> None:
        machine = options["json"] is True
        timeout = self._timeout(options, machine)
        user = self._actor(options, machine)

        operation_id: int | None = None
        try:
            operation_id, decision = self._operation_id(options, user, machine)
            payload = self._poll(operation_id, user, options["wait"] is True, timeout)
        except RefreshNotFound:
            self._fail(machine, "not_found", "Server or refresh operation was not found.", 4)
        except OperationRefused:
            self._fail(machine, "stale_connection", "The connection changed; reload and retry.", 6)
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
        if payload["code"] in ("failed", "stale_connection"):
            raise CommandError("Refresh failed.", returncode=6)
        if payload["code"] == "client_timeout":
            raise CommandError("Wait timed out; the operation continues.", returncode=7)
