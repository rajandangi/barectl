"""Applying a reviewed metadata refresh on a real, disposable Ubuntu server.

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``discovery/test_remote.py`` and ``bootstrap/test_remote.py`` describe; the SSH user must
have noninteractive sudo, and ``BARECTL_SSH_TEST_CONTAINER`` and
``BARECTL_SSH_TEST_UNPRIVILEGED_USER`` must be set.

Every run goes through actual systemd, flock and APT on the server. Ground truth is read
through ``docker exec``, independently of Barectl's connection. Faults are injected only
at the transport, by losing a real connection's answers, or by stopping the controller
process; the native execution itself is never simulated. The runtime limit is shortened
only for the timeout test, whose submission is otherwise the production one; the
production limits are asserted on the units the other tests create.
"""

import json
import os
import re
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from pathlib import Path
from typing import ClassVar, override
from unittest import mock, skipUnless

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, User
from django.db.models import F
from django.test import TestCase, override_settings, tag

from dashboard.testing import TEST_MANIFEST
from discovery import ssh
from discovery.fakes import run_worker
from discovery.ssh import CommandResult, ConnectionFailed, RemoteShell
from discovery.test_remote import setting
from operations.models import RemoteOperation
from servers.models import Server
from servers.ssh_config import ConnectionTarget

from . import native
from .models import ApplyRun, ConfigurationPlan, Execution, PlanPreparation, Verification
from .test_remote import FIXTURES

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

# A controller in its own process with its own database file. "submit" registers the
# server, prepares a metadata refresh plan, requests its run and runs the worker, which
# kills its own process right after the server acknowledged the submission. "check" is a
# new process on the same database: it treats the run as abandoned (its worker is gone),
# asks for its outcome, runs the worker and prints what it recorded.
CONTROLLER = """
import json
import os
import re
import signal
import sys
from datetime import timedelta
from pathlib import Path

os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
from config import settings as configured

database, ssh_config, manifest, phase = sys.argv[1:]
configured.DATABASES["default"]["NAME"] = database
configured.SSH_CONFIG_PATH = ssh_config
configured.VITE_MANIFEST_PATH = Path(manifest)
configured.VITE_DEV_SERVER_URL = ""
configured.ALLOWED_HOSTS = ["testserver"]

import django

django.setup()

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import Client
from django.utils import timezone

from bootstrap import apply, native
from bootstrap.models import ApplyRun, ConfigurationPlan
from discovery.fakes import run_worker
from operations.models import RemoteOperation
from servers.models import Server

client = Client()
if phase == "submit":
    call_command("migrate", verbosity=0)
    user = get_user_model().objects.create_user("controller-operator")
    for codename in (
        "view_server",
        "view_configurationplan",
        "prepare_configurationplan",
        "apply_configurationplan",
    ):
        user.user_permissions.add(Permission.objects.get(codename=codename))
    server = Server.objects.create(name="Disposable", ssh_alias="disposable")
    client.force_login(user)
    client.post(f"/servers/{server.pk}/plans/prepare/", {"action": "metadata_refresh"}, secure=True)
    run_worker()
    plan = ConfigurationPlan.objects.get()
    client.post(f"/plans/{plan.pk}/apply/", secure=True)
    watch = apply._watch

    def destroyed(*args, **kwargs):
        # The server acknowledged the submission; the controller dies before it watches.
        print(json.dumps({"unit": ApplyRun.objects.get().unit_name}), flush=True)
        os.kill(os.getpid(), signal.SIGKILL)

    apply._watch = destroyed
    run_worker()
    raise SystemExit("The controller was not destroyed.")
else:
    client.force_login(get_user_model().objects.get())
    run = ApplyRun.objects.get()
    before = {"status": run.status, "dispatched": run.dispatched_at is not None,
              "acknowledged": run.acknowledged_at is not None}
    # Its worker is gone: after the stale limit, recovery reconciles the dispatched run.
    RemoteOperation.objects.filter(pk=run.pk).update(
        started_at=timezone.now() - apply.STALE_AFTER - timedelta(minutes=1)
    )
    page = client.get(f"/applies/{run.pk}/", secure=True)
    reconciling = ApplyRun.objects.get().status
    client.post(f"/applies/{run.pk}/check/", secure=True)
    run_worker()
    run = ApplyRun.objects.get()
    print(json.dumps({
        "before": before,
        "reconciling": reconciling,
        "status": run.status,
        "execution": run.execution,
        "verification": run.verification,
        "failure": run.failure,
        "unit": run.unit_name,
        "invocation": run.invocation_id,
        "page": page.status_code,
    }))
"""


class _LosingShell:
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

    def run(self, command: str) -> CommandResult:
        if self.lost:
            raise ConnectionFailed("The connection ended.")
        if self.lose(command):
            self.lost = True
            if self.after:
                self.shell.run(command)
            raise ConnectionFailed("The connection ended.")
        return self.shell.run(command)


def _is_submission(command: str) -> bool:
    return command.startswith(f"sudo -n {native.SYSTEMD_RUN} ")


def _is_inspection(command: str) -> bool:
    return command.startswith("cat /proc/sys/kernel/random/boot_id; systemctl show")


@tag("ssh")
@skipUnless(FIXTURES, "Set BARECTL_SSH_TEST_* to run against a disposable server")
class ApplyAcceptanceTestCase(TestCase):
    """A signed-in operator, a registered disposable server and helpers to read it natively."""

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
                yield _LosingShell(shell, lose, after=after)

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


class ApplyAcceptanceTests(ApplyAcceptanceTestCase):
    def test_a_reviewed_refresh_runs_natively_through_the_dashboard(self) -> None:
        package_plan = self.plan("php")
        self.assertTrue(package_plan.eligible)
        plan = self.plan()
        before = self.update_stamp()
        time.sleep(1.1)
        # Two submissions of one revision converge on one run.
        first = self.request(plan)
        second = self.request(plan)
        self.assertEqual(first.pk, second.pk)
        run_worker()
        run = ApplyRun.objects.get(pk=first.pk)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual(run.execution, Execution.SUCCEEDED)
        self.assertEqual(run.verification, Verification.PASSED)
        self.assertEqual(self.units(), [run.unit_name])
        # Native truth, read outside Barectl.
        shown = self.unit(run.unit_name)
        self.assertEqual(
            {key: shown[key] for key in UNIT_PROPERTIES if key != "ExecStartEx"},
            {
                "ActiveState": "active",
                "SubState": "exited",
                "Result": "success",
                "ExecMainCode": "1",
                "ExecMainStatus": "0",
                "InvocationID": run.invocation_id,
                "Type": "exec",
                "ExitType": "cgroup",
                "Restart": "no",
                "RuntimeMaxUSec": "30min",
                "TimeoutStopUSec": "1min",
                "KillMode": "control-group",
                "RemainAfterExit": "yes",
                "StandardInput": "null",
                "StandardOutput": "journal",
            },
        )
        self.assertIn("flags=no-env-expand", shown["ExecStartEx"])
        self.assertRegex(self.journal(run.unit_name), UPDATE_OUTPUT)
        self.assertNotEqual(self.update_stamp(), before)
        self.assertEqual(
            self.administer(
                f"stat -c '%F %U %a' {native.LOCK_DIRECTORY}; stat -c '%F %U %s' {native.LOCK_FILE}"
            ),
            "directory root 700\nregular empty file root 0\n",
        )
        # The dashboard shows the outcomes separately, and the audit keeps no remote output.
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Applied and verified")
        self.assertContains(page, "Completed successfully")
        self.assertContains(page, "Postconditions hold")
        self.assertNotContains(page, "Hit:")
        self.assertContains(
            self.client.get(f"/plans/{package_plan.pk}/"), "A later package metadata refresh"
        )
        self.assertContains(self.client.get("/activity/"), "Apply: Package metadata refresh")
        self.assertContains(
            self.client.get(f"/servers/{self.server.pk}/"), "Latest apply run: Applied"
        )

    def test_lost_answers_reconcile_from_a_new_connection_without_resubmitting(self) -> None:
        # The submission reaches the server, but its acknowledgement is lost.
        with self.losing(_is_submission, after=True):
            run = self.apply()
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIsNone(run.acknowledged_at)
        (name,) = self.units()
        self.assertEqual(name, run.unit_name)
        self.wait_terminal(name)
        self.assertContains(self.client.get(f"/applies/{run.pk}/"), "Check outcome")
        run = self.check(run)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual(run.invocation_id, self.unit(name)["InvocationID"])
        self.assertEqual(self.units(), [name])

        # The connection is lost after acknowledgement, while the worker watches.
        with self.losing(_is_inspection, after=False):
            run = self.apply()
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIsNotNone(run.acknowledged_at)
        self.wait_terminal(run.unit_name)
        run = self.check(run)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual(len(self.units()), 2)

        # The submission never left: the run reconciles, and no unit exists to find.
        with self.losing(_is_submission, after=False):
            run = self.apply()
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertNotIn(run.unit_name, self.units())
        run = self.check(run)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIn("no unit with this run's name", run.failure)

    def test_destroying_the_controller_leaves_native_execution_to_finish(self) -> None:
        controller = self.directory / "controller"
        controller.mkdir()
        config = controller / "config"
        self.write_config(setting("USER"), config, key="SECOND_KEY")
        database = controller / "db.sqlite3"

        def start(phase: str) -> subprocess.CompletedProcess[str]:
            arguments = [str(database), str(config), str(TEST_MANIFEST), phase]
            return subprocess.run(  # noqa: S603 - the test's own script
                [sys.executable, "-c", CONTROLLER, *arguments],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

        submitted = start("submit")
        self.assertEqual(submitted.returncode, -signal.SIGKILL, submitted.stderr[-3000:])
        unit = json.loads(submitted.stdout.strip().splitlines()[-1])["unit"]
        # systemd owns the run: it finishes after its controller was destroyed.
        self.assertEqual(self.units(), [unit])
        shown = self.wait_terminal(unit)
        self.assertEqual((shown["Result"], shown["ExecMainStatus"]), ("success", "0"))
        with closing(sqlite3.connect(database)) as records:
            (status,) = records.execute(
                "SELECT status FROM operations_remoteoperation WHERE kind = 'apply'"
            ).fetchone()
        self.assertEqual(status, Status.RUNNING)

        checked = start("check")
        self.assertEqual(checked.returncode, 0, checked.stderr[-3000:])
        result = json.loads(checked.stdout.strip().splitlines()[-1])
        self.assertEqual(
            result["before"], {"status": "running", "dispatched": True, "acknowledged": True}
        )
        self.assertEqual(result["reconciling"], Status.RECONCILING)
        self.assertEqual(result["status"], Status.SUCCEEDED, result["failure"])
        self.assertEqual(result["execution"], Execution.SUCCEEDED)
        self.assertEqual(result["verification"], Verification.PASSED)
        self.assertEqual(result["invocation"], shown["InvocationID"])
        self.assertEqual(self.units(), [unit])

    def test_the_runtime_limit_stops_the_whole_run(self) -> None:
        with mock.patch.object(native, "RUNTIME_MAX", "3s"):
            name = self.submit(
                lambda unit, boot, deadline: "; ".join(
                    [*native.admission(unit, boot, deadline), "sleep 120"]
                )
            )
        self.assertEqual(self.inspect(name).execution, Execution.RUNNING)
        self.assertFalse(self.lock_is_free())
        shown = self.wait_terminal(name, timeout=30)
        self.assertEqual(shown["Result"], "timeout")
        evidence = self.inspect(name)
        self.assertEqual(evidence.execution, Execution.TIMED_OUT)
        self.assertFalse(evidence.populated)
        self.assertTrue(self.lock_is_free())

    def test_a_child_outliving_its_wrapper_blocks_admission_until_it_ends(self) -> None:
        # The child closes the inherited lock descriptor and continues after its wrapper
        # is killed; the wrapper itself only waits, holding the lock until it dies.
        child = "setsid sh -c 'exec 9>&- </dev/null >/dev/null 2>&1; exec sleep 300' & wait"
        name = self.submit(
            lambda unit, boot, deadline: "; ".join([*native.admission(unit, boot, deadline), child])
        )
        time.sleep(1)
        self.assertFalse(self.lock_is_free())
        self.administer(f"systemctl kill --kill-whom=main --signal=SIGKILL {name}")
        time.sleep(1)
        evidence = self.inspect(name)
        # Its main process was killed, the lock is free, and a process remains.
        self.assertEqual(evidence.exec_main_code, 2)
        self.assertTrue(evidence.populated)
        self.assertEqual(evidence.execution, Execution.RUNNING)
        self.assertTrue(self.lock_is_free())
        run = self.apply()
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Execution.OTHER_RUN_ACTIVE)
        self.assertNotRegex(self.journal(run.unit_name), UPDATE_OUTPUT)
        self.administer(f"systemctl kill --signal=SIGKILL {name}")
        self.wait_terminal(name, timeout=30)
        evidence = self.inspect(name)
        self.assertEqual(evidence.execution, Execution.KILLED)
        self.assertFalse(evidence.populated)

    def test_refusals_under_the_lock_change_nothing(self) -> None:
        self.administer(f"install -d -m 700 {native.LOCK_DIRECTORY}; touch {native.LOCK_FILE}")
        # The bracket keeps pkill from matching its own shell's command line.
        stop_holders = "pkill -f '[f]lock -o /run/lock/barectl'; pkill -f '[f]cntl.lockf'; true"
        self.addCleanup(self.administer, stop_holders)
        self.administer(f"flock -o {native.LOCK_FILE} sleep 120", detach=True)
        time.sleep(1)
        self.assertEqual(self.refused().execution, Execution.LOCK_CONFLICT)
        self.administer(stop_holders)

        apt_lock = (
            "import fcntl, os, time; "
            "f = os.open('/var/lib/apt/lists/lock', os.O_RDWR | os.O_CREAT, 0o640); "
            "fcntl.lockf(f, fcntl.LOCK_EX); time.sleep(120)"
        )
        self.administer(f'python3 -c "{apt_lock}"', detach=True)
        time.sleep(1)
        self.assertEqual(self.refused().execution, Execution.PACKAGE_MANAGER_BUSY)
        self.administer(stop_holders)

        # An unknown hook added after review is drift, refused before APT runs.
        plan = self.plan()
        self.addCleanup(self.administer, "rm -f /etc/apt/apt.conf.d/99barectl-test")
        self.administer(
            "printf 'DPkg::Post-Invoke {\"true\";};\\n' >/etc/apt/apt.conf.d/99barectl-test"
        )
        self.assertEqual(self.refused(plan).execution, Execution.DRIFT)
        self.administer("rm -f /etc/apt/apt.conf.d/99barectl-test")

        # Delayed delivery: the server's monotonic clock is past the admission deadline.
        plan = self.plan()
        ConfigurationPlan.objects.filter(pk=plan.pk).update(
            uptime_centiseconds=F("uptime_centiseconds") - 100000,
            admission_deadline_centiseconds=F("admission_deadline_centiseconds") - 100000,
        )
        self.assertEqual(self.refused(plan).execution, Execution.EXPIRED)

        # A plan reviewed in another boot, as after a restart.
        plan = self.plan()
        ConfigurationPlan.objects.filter(pk=plan.pk).update(
            boot_id="00000000-0000-4000-8000-000000000000"
        )
        self.assertEqual(self.refused(plan).execution, Execution.BOOT_CHANGED)

        # A lock directory an unprivileged user could have created is not trusted.
        self.addCleanup(self.administer, f"chown root:root {native.LOCK_DIRECTORY}")
        self.administer(f"chown nobody {native.LOCK_DIRECTORY}")
        self.assertEqual(self.refused().execution, Execution.UNSAFE_LOCK)

    def test_privilege_is_rechecked_for_the_exact_submission(self) -> None:
        plan = self.plan()
        # The alias now logs in as an account without sudo; nothing may be submitted.
        self.write_config(setting("UNPRIVILEGED_USER"))
        run = self.apply(plan)
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Execution.NOT_SUBMITTED)
        self.assertIsNone(run.dispatched_at)
        self.assertIn("sudo -n -l does not authorize", run.failure)
        self.assertEqual(self.units(), [])
