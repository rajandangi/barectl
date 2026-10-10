"""The base case of the native acceptance tests that apply a reviewed plan on a real,
disposable Ubuntu server, and the faults they inject
(docs/quality.md#native-suites; ``bootstrap/test_apply_remote.py`` describes the contract).

Tagged ``ssh`` and skipped unless the disposable server is configured. Ground truth is read
through ``docker exec``, independently of Barectl's connection.
"""

import os
import re
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import ClassVar, override
from unittest import mock, skipUnless

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, User
from django.test import TestCase, override_settings, tag

from dashboard.testing import TEST_MANIFEST
from discovery import ssh
from discovery.fakes import run_worker
from discovery.native_testing import setting
from discovery.ssh import CommandResult, ConnectionFailed, RemoteShell
from operations.models import RemoteOperation
from servers.models import Server
from servers.ssh_config import ConnectionTarget

from . import native
from .models import ApplyRun, ConfigurationPlan, Execution, PlanPreparation, Verification
from .native_testing import FIXTURES

Status = RemoteOperation.Status
PERMISSIONS = (
    "view_server",
    "view_configurationplan",
    "prepare_configurationplan",
    "apply_configurationplan",
)
UNIT_PROPERTIES = (
    "ActiveState",
    "SubState",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
    "InvocationID",
    "Type",
    "ExitType",
    "Restart",
    "RuntimeMaxUSec",
    "TimeoutStopUSec",
    "KillMode",
    "RemainAfterExit",
    "StandardInput",
    "StandardOutput",
    "ExecStartEx",
)
# APT's line for each repository it contacts; their absence from a unit's journal shows
# that the payload stopped before APT fetched anything.
UPDATE_OUTPUT = re.compile(r"^(Hit|Get|Ign|Err):", re.MULTILINE)


class LosingShell:
    """A real Barectl connection whose answer to one command is lost.

    ``after`` decides for each command whether to run it on the server before the
    connection is lost, as when a network fails after the request left, or to lose the
    connection without sending it.
    """

    def __init__(self, shell: RemoteShell, lose: Callable[[str], bool], *, after: bool) -> None:
        self.shell = shell
        self.lose = lose
        self.after = after
        self.lost = False

    @property
    def host_key(self) -> str:
        return self.shell.host_key

    def run(self, command: str, stdin: bytes | None = None) -> CommandResult:
        if self.lost:
            raise ConnectionFailed("The connection ended.")
        if self.lose(command):
            self.lost = True
            if self.after:
                self.shell.run(command, stdin)
            raise ConnectionFailed("The connection ended.")
        return self.shell.run(command, stdin)


def is_submission(command: str) -> bool:
    return command.startswith(f"sudo -n {native.SYSTEMD_RUN} ")


def is_inspection(command: str) -> bool:
    return command.startswith("cat /proc/sys/kernel/random/boot_id; systemctl show")


@tag("ssh")
@skipUnless(FIXTURES, "Set BARECTL_SSH_TEST_* to run against a disposable server")
class ApplyAcceptanceTestCase(TestCase):
    user: ClassVar[User]
    config: Path
    directory: Path

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.user = get_user_model().objects.create_user("operator")
        for codename in PERMISSIONS:
            cls.user.user_permissions.add(Permission.objects.get(codename=codename))

    @override
    def setUp(self) -> None:
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir="/tmp")))
        self.config = self.directory / "config"
        self.write_config(setting("USER"))
        self.enterContext(
            override_settings(SSH_CONFIG_PATH=str(self.config), VITE_MANIFEST_PATH=TEST_MANIFEST)
        )
        self.enterContext(mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": ""}))
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Disposable", ssh_alias="disposable")
        # Retained units from earlier tests would count against the limit and hold state.
        self.clear_units()
        self.addCleanup(self.clear_units)

    def write_config(self, user: str, path: Path | None = None, key: str = "KEY") -> None:
        """Write the controller's SSH configuration: ``disposable`` as ``user`` with ``key``,
        and ``disposable-second``, another alias of the same server with the second key."""
        (path or self.config).write_text(
            "".join(
                f"Host {alias}\n"
                f"  HostName {setting('HOST')}\n  Port {setting('PORT')}\n  User {login}\n"
                f"  UserKnownHostsFile {setting('KNOWN_HOSTS')}\n  IdentityFile {setting(file)}\n"
                for alias, login, file in (
                    ("disposable", user, key),
                    ("disposable-second", setting("USER"), "SECOND_KEY"),
                )
            ),
            encoding="utf-8",
        )

    def administer(self, script: str, *, detach: bool = False) -> str:
        """Run ``script`` as the server's administrator, outside Barectl; return its output."""
        options = ["-d"] if detach else []
        result = subprocess.run(  # noqa: S603 - the tests' own fixture scripts
            ["docker", "exec", *options, setting("CONTAINER"), "sh", "-c", script],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return result.stdout

    def clear_units(self) -> None:
        self.administer(
            "systemctl kill --signal=SIGKILL 'barectl-apply-*' 2>/dev/null; "
            "systemctl stop 'barectl-apply-*' 2>/dev/null; "
            "systemctl reset-failed 'barectl-apply-*' 2>/dev/null; true"
        )

    def units(self) -> list[str]:
        listed = self.administer(
            "systemctl list-units --all --plain --no-legend --type=service 'barectl-apply-*'"
        )
        return [line.split()[0] for line in listed.splitlines() if line.strip()]

    def unit(self, name: str) -> dict[str, str]:
        properties = " ".join(f"-p {prop}" for prop in UNIT_PROPERTIES)
        shown = self.administer(f"systemctl show {properties} {name}")
        return dict(line.split("=", 1) for line in shown.splitlines() if "=" in line)

    def journal(self, name: str) -> str:
        return self.administer(f"journalctl -u {name} -o cat --no-pager")

    def wait_terminal(self, name: str, timeout: float = 120) -> dict[str, str]:
        """Wait until the unit's main process and every other process of it ended."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            shown = self.unit(name)
            done = (shown["ActiveState"], shown["SubState"]) in {
                ("active", "exited"),
                ("failed", "failed"),
                ("inactive", "dead"),
            }
            if done:
                return shown
            time.sleep(1)
        raise AssertionError(f"{name} did not finish.")

    def plan(self, action: str = "metadata_refresh") -> ConfigurationPlan:
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": action})
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        return ConfigurationPlan.objects.get(preparation=preparation)

    def request(self, plan: ConfigurationPlan) -> ApplyRun:
        self.client.post(f"/plans/{plan.pk}/apply/")
        return ApplyRun.objects.get(plan_number=plan.pk)

    def apply(self, plan: ConfigurationPlan | None = None) -> ApplyRun:
        refresh = plan or self.plan()
        self.assertTrue(refresh.eligible, list(refresh.refusals.values_list("text", flat=True)))
        run = self.request(refresh)
        run_worker()
        run.refresh_from_db()
        return run

    def check(self, run: ApplyRun) -> ApplyRun:
        self.client.post(f"/applies/{run.pk}/check/")
        run_worker()
        run.refresh_from_db()
        return run

    @contextmanager
    def losing(self, lose: Callable[[str], bool], *, after: bool) -> Iterator[None]:
        """Lose the answer to the first command ``lose`` matches on Barectl's connections."""
        real = ssh.connect

        @contextmanager
        def connect(target: ConnectionTarget) -> Iterator[RemoteShell]:
            with real(target) as shell:
                yield LosingShell(shell, lose, after=after)

        with mock.patch.object(ssh, "connect", connect):
            yield

    def update_stamp(self) -> str:
        return self.administer("stat -c %Y /var/lib/apt/periodic/update-success-stamp").strip()

    def submit(self, script: Callable[[str, str, int], str], alias: str = "disposable") -> str:
        """Submit a unit through Barectl's adapter and connection; return its name.

        ``script`` receives the unit name, boot ID and a deadline and returns the payload.
        """
        boot = self.administer("cat /proc/sys/kernel/random/boot_id").strip()
        uptime = int(self.administer("cut -d' ' -f1 /proc/uptime | tr -d .").strip())
        name = native.new_unit_name()
        argv = native.submission(name, script(name, boot, uptime + 90000))
        with ssh.connect_alias(alias) as shell:
            self.assertEqual(shell.run(native.privileged(argv, root=False)).exit_status, 0)
        return name

    def inspect(self, name: str) -> native.UnitEvidence:
        with ssh.connect_alias("disposable") as shell:
            return native.inspect(shell, name)

    def lock_is_free(self) -> bool:
        free = self.administer(f"flock -n {native.LOCK_FILE} true && echo free || echo held")
        return free.strip() == "free"

    def renewal(self, *, survivor: bool = False) -> None:
        """Stand in for Certbot's packaged renewal service with processes that keep running.

        A ``survivor`` outlives the service's main process; systemd then reports the service
        inactive while the kernel keeps its control group populated.
        """
        self.addCleanup(
            self.administer,
            "pkill -f '^sleep 6001$'; systemctl stop certbot.service 2>/dev/null; "
            "systemctl reset-failed certbot.service 2>/dev/null; true",
        )
        if survivor:
            self.administer(
                "systemd-run --quiet --unit=certbot.service -p KillMode=none "
                "sh -c 'sleep 6001 </dev/null >/dev/null 2>&1 & exit 0'"
            )
        else:
            self.administer("systemd-run --quiet --unit=certbot.service sleep 6001")
        time.sleep(1)

    def refused(self, plan: ConfigurationPlan | None = None) -> ApplyRun:
        """Apply and assert the payload refused before the update, changing nothing."""
        before = self.update_stamp()
        run = self.apply(plan)
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.verification, Verification.NOT_APPLICABLE)
        self.assertIn(run.execution, Execution.refused_before_changes())
        self.assertNotRegex(self.journal(run.unit_name), UPDATE_OUTPUT)
        self.assertEqual(self.update_stamp(), before)
        return run
