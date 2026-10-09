"""Coordination, uncertainty and cleanup of native execution on a disposable Ubuntu server.

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. Every run goes through actual systemd, flock
and APT; ground truth is read through ``docker exec``. Faults are injected natively: by
racing independent controller processes with their own databases and aliases, by killing
or stopping processes, by holding the lock, by vacuuming the journal, and by restarting
the container's systemd. The container shares the Docker host's kernel, so a restart
keeps the kernel's boot ID and monotonic clock; a new boot ID is then bind-mounted over
``/proc/sys/kernel/random/boot_id``, which every process on the server reads, to stand for
the new boot a real reboot would bring.
"""

import json
import subprocess
import sys
import threading
import time
from unittest import mock

from django.contrib.auth.models import Permission

from dashboard.testing import TEST_MANIFEST
from discovery import ssh
from discovery.fakes import run_worker
from discovery.native_testing import setting
from operations.models import RemoteOperation
from servers.models import Server

from . import apply, native
from .apply_remote_testing import UPDATE_OUTPUT, ApplyAcceptanceTestCase, is_submission
from .models import (
    ADMISSION_CENTISECONDS,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEvidence,
    PlanNativeUnit,
    Verification,
)

Status = RemoteOperation.Status
# A boot ID no real boot of the disposable server has.
NEW_BOOT = "0badb007-0000-4000-8000-000000000109"

# An independent controller in its own process, with its own database file and SSH alias.
# "prepare" creates its database, account and registration and reviews a plan for the
# given action, a metadata refresh unless a test names another, through the dashboard.
# "apply" requests that plan's run and runs the worker; the worker's submission waits
# until every controller named in the barrier directory is about to submit, so the
# submissions reach the server together. "fresh" reviews a new
# refresh plan and applies it, then reviews a cleanup plan without applying it.
CONTROLLER = """
import json
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path

os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
from config import settings as configured

database, ssh_config, manifest, alias, name, barrier, phase, action = sys.argv[1:]
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

from bootstrap.models import ApplyRun, ConfigurationPlan
from discovery import ssh
from discovery.fakes import run_worker
from servers.models import Server

client = Client()


def prepare(action):
    server = Server.objects.get()
    client.post(f"/servers/{server.pk}/plans/prepare/", {"action": action}, secure=True)
    run_worker()
    return ConfigurationPlan.objects.latest("pk")


def apply(plan):
    client.post(f"/plans/{plan.pk}/apply/", secure=True)
    run_worker()
    run = ApplyRun.objects.get(plan_number=plan.pk)
    return {
        "plan": plan.pk,
        "run": run.pk,
        "status": run.status,
        "execution": run.execution,
        "verification": run.verification,
        "failure": run.failure,
        "unit": run.unit_name,
    }


if phase == "prepare":
    call_command("migrate", verbosity=0)
    user = get_user_model().objects.create_user(f"{name}-operator")
    for codename in (
        "view_server",
        "view_configurationplan",
        "prepare_configurationplan",
        "apply_configurationplan",
    ):
        user.user_permissions.add(Permission.objects.get(codename=codename))
    Server.objects.create(name=f"Disposable {name}", ssh_alias=alias)
    client.force_login(user)
    plan = prepare(action)
    print(json.dumps({"plan": plan.pk, "eligible": plan.eligible}), flush=True)
elif phase == "apply":
    client.force_login(get_user_model().objects.get())
    real = ssh.connect

    class Synchronized:
        def __init__(self, shell):
            self.shell = shell

        @property
        def host_key(self):
            return self.shell.host_key

        def run(self, command):
            if command.startswith("sudo -n /usr/bin/systemd-run "):
                Path(barrier, name).touch()
                deadline = time.monotonic() + 120
                while {"a", "b"} - set(os.listdir(barrier)) and time.monotonic() < deadline:
                    time.sleep(0.005)
            return self.shell.run(command)

    @contextmanager
    def connect(target):
        with real(target) as shell:
            yield Synchronized(shell)

    ssh.connect = connect
    started = time.monotonic()
    result = apply(ConfigurationPlan.objects.get())
    result["seconds"] = time.monotonic() - started
    print(json.dumps(result), flush=True)
else:
    client.force_login(get_user_model().objects.get())
    fresh = apply(prepare("metadata_refresh"))
    cleanup = prepare("clear_results")
    fresh["cleanup_units"] = list(cleanup.native_units.values_list("unit_name", flat=True))
    fresh["recorded_runs"] = list(ApplyRun.objects.values_list("unit_name", flat=True))
    print(json.dumps(fresh), flush=True)
"""


def _names(value: object) -> list[str]:
    """The unit names a controller printed as a JSON list."""
    if not isinstance(value, list):
        raise AssertionError("The controller did not print a list of unit names.")
    return [str(item) for item in value]


class ControllerTestCase(ApplyAcceptanceTestCase):
    """Independent controllers, each a separate process with its own database and alias."""

    def controller(
        self, name: str, alias: str, phase: str, action: str = "metadata_refresh"
    ) -> subprocess.Popen[str]:
        directory = self.directory / name
        directory.mkdir(exist_ok=True)
        barrier = self.directory / "barrier"
        barrier.mkdir(exist_ok=True)
        arguments = [
            str(directory / "db.sqlite3"),
            str(self.config),
            str(TEST_MANIFEST),
            alias,
            name,
            str(barrier),
            phase,
            action,
        ]
        return subprocess.Popen(  # noqa: S603 - the test's own script
            [sys.executable, "-c", CONTROLLER, *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def finish(self, process: subprocess.Popen[str]) -> dict[str, object]:
        stdout, stderr = process.communicate(timeout=300)
        self.assertEqual(process.returncode, 0, stderr[-3000:])
        result: dict[str, object] = json.loads(stdout.strip().splitlines()[-1])
        return result


class CoordinationAcceptanceTests(ControllerTestCase):
    def test_independent_controllers_racing_through_two_aliases_admit_one_mutation(self) -> None:
        controllers = {"a": "disposable", "b": "disposable-second"}
        for name, alias in controllers.items():
            prepared = self.finish(self.controller(name, alias, "prepare"))
            self.assertTrue(prepared["eligible"])
        before = self.update_stamp()
        time.sleep(1.1)
        racing = [self.controller(name, alias, "apply") for name, alias in controllers.items()]
        results = [self.finish(process) for process in racing]
        executions = [str(result["execution"]) for result in results]
        succeeded = [r for r in results if r["execution"] == Execution.SUCCEEDED]
        refused = [r for r in results if r["execution"] != Execution.SUCCEEDED]
        # At most one mutation ran. Every other run stopped under the lock before changing
        # anything, without waiting: it found the lock taken, or found the other run's unit
        # still with processes, so simultaneous submissions may both refuse.
        self.assertLessEqual(len(succeeded), 1, executions)
        self.assertTrue(refused, executions)
        for run in refused:
            self.assertIn(
                run["execution"], {Execution.LOCK_CONFLICT, Execution.OTHER_RUN_ACTIVE}, executions
            )
            self.assertEqual(run["status"], Status.FAILED)
            self.assertIn("Prepare a new plan", str(run["failure"]))
            self.assertNotRegex(self.journal(str(run["unit"])), UPDATE_OUTPUT)
            self.assertLess(float(str(run["seconds"])), 60)
        for run in succeeded:
            self.assertEqual(run["status"], Status.SUCCEEDED, run["failure"])
            self.assertRegex(self.journal(str(run["unit"])), UPDATE_OUTPUT)
        self.assertEqual(self.update_stamp() != before, bool(succeeded))
        self.assertEqual(sorted(self.units()), sorted(str(r["unit"]) for r in results))
        # A refused controller needs fresh evidence and review: its revision is spent, and a
        # new plan, prepared after the race, applies. The other controller's unit is visible
        # to it as native work, but none of that controller's records are.
        name = "a" if refused[0] is results[0] else "b"
        other = results[1] if name == "a" else results[0]
        fresh = self.finish(self.controller(name, controllers[name], "fresh"))
        self.assertEqual(fresh["status"], Status.SUCCEEDED, fresh["failure"])
        self.assertIn(other["unit"], _names(fresh["cleanup_units"]))
        self.assertNotIn(other["unit"], _names(fresh["recorded_runs"]))
        self.assertEqual(len(self.units()), 3)

    def test_a_lock_held_under_another_alias_refuses_at_once(self) -> None:
        # Another controller's run, submitted through the second alias, holds the lock.
        holder = self.submit(
            lambda unit, boot, deadline: "; ".join(
                [*native.admission(unit, boot, deadline), "sleep 120"]
            ),
            alias="disposable-second",
        )
        started = time.monotonic()
        run = self.refused()
        self.assertLess(time.monotonic() - started, 60)
        self.assertEqual(run.execution, Execution.LOCK_CONFLICT)
        self.assertEqual(self.inspect(holder).execution, Execution.RUNNING)
        # The spent revision cannot be applied again; its page offers no apply control.
        plan_page = self.client.get(f"/plans/{run.plan_number}/")
        self.assertNotContains(plan_page, "Apply plan")
        self.assertContains(plan_page, "Open the apply run for this plan")

    def test_descendants_keep_the_lock_and_the_unit_until_the_last_one_exits(self) -> None:
        # The wrapper exits at once; its child keeps descriptor 9 and the lock.
        name = self.submit(
            lambda unit, boot, deadline: "; ".join(
                [*native.admission(unit, boot, deadline), "sleep 300 </dev/null >/dev/null &"]
            )
        )
        time.sleep(1)
        shown = self.unit(name)
        # systemd reports the main process's normal exit, but the unit is still active.
        self.assertEqual((shown["ExecMainCode"], shown["ExecMainStatus"]), ("1", "0"))
        self.assertEqual(shown["ActiveState"], "active")
        evidence = self.inspect(name)
        self.assertTrue(evidence.populated)
        self.assertEqual(evidence.execution, Execution.RUNNING)
        self.assertFalse(self.lock_is_free())
        self.assertEqual(self.refused().execution, Execution.LOCK_CONFLICT)
        self.administer(f"systemctl kill --kill-whom=all --signal=SIGKILL {name}")
        shown = self.wait_terminal(name, timeout=30)
        self.assertEqual((shown["ActiveState"], shown["SubState"]), ("active", "exited"))
        evidence = self.inspect(name)
        self.assertEqual(evidence.execution, Execution.SUCCEEDED)
        self.assertFalse(evidence.populated)
        self.assertTrue(self.lock_is_free())
        # A finished unit kept after exit, with nothing left running, is evidence, not a
        # conflict: the next reviewed refresh runs.
        run = self.apply()
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)

    def test_stopping_a_run_ends_its_whole_control_group_within_the_stop_limit(self) -> None:
        stubborn = "sh -c 'trap \"\" TERM; while :; do sleep 1; done' </dev/null >/dev/null & wait"
        # Only the stop limit is shortened, as the runtime limit is in the timeout test.
        with mock.patch.object(native, "TIMEOUT_STOP", "3"):
            name = self.submit(
                lambda unit, boot, deadline: "; ".join(
                    [*native.admission(unit, boot, deadline), stubborn]
                )
            )
        time.sleep(1)
        self.assertTrue(self.inspect(name).populated)
        started = time.monotonic()
        self.administer(f"systemctl stop {name}")
        shown = self.wait_terminal(name, timeout=30)
        self.assertLess(time.monotonic() - started, 20)
        evidence = self.inspect(name)
        self.assertFalse(evidence.populated)
        self.assertIn(evidence.execution, {Execution.KILLED, Execution.TIMED_OUT})
        self.assertNotEqual(shown["Result"], "success")
        self.assertTrue(self.lock_is_free())

    def test_a_scheduled_renewal_with_processes_refuses_every_change(self) -> None:
        self.user.user_permissions.add(Permission.objects.get(codename="clear_native_results"))
        self.renewal()
        refresh = self.refused()
        self.assertEqual(refresh.execution, Execution.RENEWAL_ACTIVE, refresh.failure)
        self.assertIn("renewal service still had processes", refresh.failure)
        self.assertEqual(self.unit(refresh.unit_name)["ExecMainStatus"], "25")
        # A reviewed cleanup of that finished unit refuses the same way and clears nothing.
        cleanup = self.plan("clear_results")
        run = self.apply(cleanup)
        self.assertEqual(run.execution, Execution.RENEWAL_ACTIVE, run.failure)
        self.assertIn(refresh.unit_name, self.units())
        self.assertEqual(self.unit("certbot.service")["ActiveState"], "active")
        self.administer("systemctl stop certbot.service")
        self.assertEqual(self.apply().status, Status.SUCCEEDED)

    def test_a_renewal_process_outliving_its_service_refuses_until_it_ends(self) -> None:
        self.renewal(survivor=True)
        shown = self.administer(
            "systemctl show -p ActiveState certbot.service; "
            "cat /sys/fs/cgroup/system.slice/certbot.service/cgroup.events"
        )
        self.assertIn("ActiveState=inactive", shown)
        self.assertIn("populated 1", shown)
        run = self.refused()
        self.assertEqual(run.execution, Execution.RENEWAL_ACTIVE, run.failure)
        self.administer("pkill -f '^sleep 6001$'; sleep 1")
        self.assertEqual(self.apply().status, Status.SUCCEEDED)

    def closure(self, run: ApplyRun) -> ApplyRun:
        self.client.post(f"/applies/{run.pk}/acknowledge/", {"understood": "on"})
        run_worker()
        run.refresh_from_db()
        return run

    def delayed(self, run: ApplyRun, alias: str = "disposable") -> str:
        """Deliver ``run``'s reviewed payload now, as a delivery delayed in transit would."""
        plan = ConfigurationPlan.objects.get(pk=run.plan_number)
        digest = plan.evidence.get(kind=PlanEvidence.Kind.APT_REVALIDATION).fingerprint
        script = native.metadata_refresh(
            run.unit_name, run.boot_id, run.admission_deadline_centiseconds, digest
        )
        with ssh.connect_alias(alias) as shell:
            result = shell.run(
                native.privileged(native.submission(run.unit_name, script), root=False)
            )
        self.assertEqual(result.exit_status, 0)
        self.wait_terminal(run.unit_name, timeout=60)
        return run.unit_name

    def uptime(self) -> int:
        return int(self.administer("cut -d' ' -f1 /proc/uptime | tr -d .").strip())

    def test_same_boot_closure_needs_an_expired_deadline_the_lock_and_no_active_run(self) -> None:
        plan = self.plan()
        # The plan's deadline, on the server's clock, is 30 seconds away.
        uptime = self.uptime()
        ConfigurationPlan.objects.filter(pk=plan.pk).update(
            uptime_centiseconds=uptime + 3000 - ADMISSION_CENTISECONDS,
            admission_deadline_centiseconds=uptime + 3000,
        )
        before = self.update_stamp()
        # The submission is held in transit: it never reaches the server now.
        with self.losing(is_submission, after=False):
            run = self.apply(plan)
        self.assertEqual(run.status, Status.RECONCILING)
        run = self.check(run)
        self.assertEqual(run.execution, Execution.NOT_FOUND)
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Outcome unknown so far.")
        # Before the deadline, a delayed delivery could still start: no closure.
        run = self.closure(run)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIn("admission deadline has not passed", run.closure_blocked)
        while self.uptime() < run.admission_deadline_centiseconds:
            time.sleep(1)
        # Another change holds the lock: no closure.
        self.administer(f"flock -o {native.LOCK_FILE} sleep 60", detach=True)
        time.sleep(1)
        run = self.closure(run)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIn("held Barectl's mutation lock", run.closure_blocked)
        self.administer("pkill -f '[f]lock -o /run/lock/barectl'; true")
        # A bootstrap unit still has processes: no closure.
        active = self.submit(lambda unit, boot, deadline: "exec 9>&-; sleep 120")
        time.sleep(1)
        run = self.closure(run)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIn("still has processes", run.closure_blocked)
        self.administer(f"systemctl kill --signal=SIGKILL {active}; sleep 1")
        # Certbot's scheduled renewal still has processes: no closure.
        self.renewal()
        run = self.closure(run)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertEqual(run.closure_blocked, apply.CLOSURE_RENEWAL_ACTIVE)
        self.administer("systemctl stop certbot.service")
        # Every proof holds: the run closes as outcome unknown, never as unchanged.
        run = self.closure(run)
        self.assertEqual(run.status, Status.FAILED, run.closure_blocked)
        self.assertEqual(run.execution, Execution.OUTCOME_UNKNOWN)
        self.assertEqual(run.verification, Verification.UNAVAILABLE)
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Outcome unknown: this run may have changed the server")
        self.assertTrue(self.lock_is_free())
        # The delayed payload finally arrives: it refuses its expired deadline under the
        # lock, before APT runs.
        unit = self.delayed(run)
        shown = self.unit(unit)
        self.assertEqual(shown["ExecMainStatus"], str(native.Exit.EXPIRED))
        self.assertNotRegex(self.journal(unit), UPDATE_OUTPUT)
        self.assertEqual(self.update_stamp(), before)

    def test_missing_journals_leave_the_unit_as_evidence(self) -> None:
        with self.losing(is_submission, after=True):
            run = self.apply()
        self.assertEqual(run.status, Status.RECONCILING)
        self.wait_terminal(run.unit_name)
        self.administer(
            "journalctl --rotate >/dev/null 2>&1; sleep 2; "
            "journalctl --vacuum-time=1s >/dev/null 2>&1"
        )
        self.assertNotRegex(self.journal(run.unit_name), UPDATE_OUTPUT)
        run = self.check(run)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual(run.execution, Execution.SUCCEEDED)

    def restart(self) -> None:
        """Restart the container's systemd, then give it a new boot ID, as a reboot would."""
        container = setting("CONTAINER")
        subprocess.run(  # noqa: S603 - the tests' own container
            ["docker", "restart", container],  # noqa: S607
            check=True,
            capture_output=True,
            timeout=120,
        )
        self.addCleanup(self.administer, "umount /proc/sys/kernel/random/boot_id 2>/dev/null; true")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            state = subprocess.run(  # noqa: S603 - the tests' own container
                ["docker", "exec", container, "systemctl", "is-system-running"],  # noqa: S607
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
            if state in {"running", "degraded"}:
                break
            time.sleep(1)
        self.administer(
            f"printf '%s\\n' {NEW_BOOT} >/run/barectl-test-boot-id; "
            "mount --bind /run/barectl-test-boot-id /proc/sys/kernel/random/boot_id"
        )
        self.assertEqual(self.administer("cat /proc/sys/kernel/random/boot_id").strip(), NEW_BOOT)

    def test_a_restart_loses_native_evidence_and_old_payloads_refuse_their_boot(self) -> None:
        # A run whose acknowledgement was lost; its unit ran before the restart.
        with self.losing(is_submission, after=True):
            lost = self.apply()
        self.wait_terminal(lost.unit_name)
        # A run through the second alias whose submission is still in transit.
        second = Server.objects.create(name="Disposable again", ssh_alias="disposable-second")
        first, self.server = self.server, second
        with self.losing(is_submission, after=False):
            held = self.apply()
        self.server = first
        self.assertEqual((lost.status, held.status), (Status.RECONCILING, Status.RECONCILING))
        before = self.update_stamp()
        self.restart()
        # The restarted server has no transient units and no lock directory.
        self.assertEqual(self.units(), [])
        lost = self.check(lost)
        self.assertEqual(lost.status, Status.RECONCILING)
        self.assertIn("The server restarted", lost.failure)
        # Nothing is resumed or replayed; an acknowledgement closes it with the lock taken.
        lost = self.closure(lost)
        self.assertEqual(lost.status, Status.FAILED, lost.closure_blocked)
        self.assertEqual(lost.execution, Execution.OUTCOME_UNKNOWN)
        self.assertEqual(
            self.administer(f"stat -c '%F %U %a' {native.LOCK_DIRECTORY}"), "directory root 700\n"
        )
        # The payload held in transit arrives after the restart and refuses its boot.
        unit = self.delayed(held, alias="disposable-second")
        self.assertEqual(self.unit(unit)["ExecMainStatus"], str(native.Exit.BOOT_CHANGED))
        self.assertNotRegex(self.journal(unit), UPDATE_OUTPUT)
        self.assertEqual(self.update_stamp(), before)
        # Checking the held run finds that unit and closes it from its evidence.
        held = self.check(held)
        self.assertEqual(held.status, Status.FAILED)
        self.assertEqual(held.execution, Execution.BOOT_CHANGED)
        self.assertEqual(len(self.units()), 1)

    def create_units(self, successful: int, failed: int) -> None:
        """Leave finished bootstrap units on the server, as earlier runs would."""
        self.administer(
            f"for i in $(seq 1 {successful + failed}); do "
            f"c=/bin/true; [ $i -gt {successful} ] && c=/bin/false; "
            "systemd-run --quiet --remain-after-exit --service-type=exec "
            "--unit=barectl-apply-$(printf '%032x' $((i + 4096))).service $c; done; true"
        )

    def test_the_retained_limit_holds_under_simultaneous_submission_and_cleanup(self) -> None:
        self.user.user_permissions.add(Permission.objects.get(codename="clear_native_results"))
        self.create_units(native.RETAINED_LIMIT - 9, 8)
        # A submission whose unit systemd created but could not start.
        self.administer(
            "systemd-run --quiet --remain-after-exit --service-type=exec "
            f"--unit=barectl-apply-{'f' * 32}.service "
            "--property=User=barectl-missing-user /bin/true; true"
        )
        self.assertEqual(len(self.units()), native.RETAINED_LIMIT)
        before = self.update_stamp()
        # Two controllers passed their own checks before the limit was reached, and their
        # submissions arrive together.
        plans = [self.plan(), self.plan()]
        boot = self.administer("cat /proc/sys/kernel/random/boot_id").strip()
        names = [native.new_unit_name() for _ in plans]
        argvs = [
            native.submission(
                name,
                native.metadata_refresh(
                    name,
                    boot,
                    plan.admission_deadline_centiseconds or 0,
                    plan.evidence.get(kind=PlanEvidence.Kind.APT_REVALIDATION).fingerprint,
                ),
            )
            for name, plan in zip(names, plans, strict=True)
        ]
        results: list[ssh.CommandResult] = []
        start = threading.Barrier(2)

        def submit(argv: list[str], alias: str) -> None:
            with ssh.connect_alias(alias) as shell:
                start.wait(timeout=60)
                results.append(shell.run(native.privileged(argv, root=False) + " 2>&1"))

        threads = [
            threading.Thread(target=submit, args=(argv, alias))
            for argv, alias in zip(argvs, ("disposable", "disposable-second"), strict=True)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)
        self.assertEqual([result.exit_status for result in results], [0, 0], results)
        for name in names:
            shown = self.wait_terminal(name)
            self.assertIn(
                int(shown["ExecMainStatus"]),
                {native.Exit.CAPACITY, native.Exit.LOCK_CONFLICT, native.Exit.OTHER_RUN_ACTIVE},
            )
            self.assertNotRegex(self.journal(name), UPDATE_OUTPUT)
        self.assertEqual(self.update_stamp(), before)
        self.assertEqual(len(self.units()), native.RETAINED_LIMIT + 2)
        # A controller refuses before submitting anything at the limit.
        refused = self.apply()
        self.assertEqual(refused.status, Status.FAILED, refused.failure)
        self.assertEqual(
            refused.execution, Execution.NOT_SUBMITTED, f"{refused.status}: {refused.failure}"
        )
        self.assertEqual(len(self.units()), native.RETAINED_LIMIT + 2)
        # A reviewed cleanup stays available at capacity. A unit whose evidence changed
        # after review refuses the whole cleanup before anything is cleared.
        cleanup = self.plan("clear_results")
        self.assertEqual(cleanup.native_units.count(), native.RETAINED_LIMIT + 2)
        first = PlanNativeUnit.objects.filter(plan=cleanup, position=0)
        self.assertEqual(first.update(invocation_id="0" * 32), 1)
        run = self.apply(cleanup)
        self.assertEqual(run.execution, Execution.DRIFT, f"{run.status}: {run.failure}")
        self.assertEqual(len(self.units()), native.RETAINED_LIMIT + 3)
        # A fresh review clears every finished unit, including the refused and the partly
        # created ones, and the failed cleanup, and keeps Barectl's audit.
        cleanup = self.plan("clear_results")
        cleared = set(cleanup.native_units.values_list("unit_name", flat=True))
        self.assertIn(f"barectl-apply-{'f' * 32}.service", cleared)
        self.assertTrue(set(names) <= cleared)
        self.assertIn(run.unit_name, cleared)
        journal_before = self.journal(names[0])
        run = self.apply(cleanup)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual(run.verification, Verification.PASSED)
        self.assertEqual(self.units(), [run.unit_name])
        # systemd forgot the units; their journal entries stay.
        self.assertEqual(self.unit(names[0])["ActiveState"], "inactive")
        self.assertTrue(journal_before)
        self.assertTrue(self.journal(names[0]).startswith(journal_before))
        self.assertEqual(ApplyRun.objects.filter(execution=Execution.DRIFT).count(), 1)
        # With room again, a reviewed refresh runs.
        self.assertEqual(self.apply().status, Status.SUCCEEDED)

    def test_cleanup_never_touches_a_running_unit(self) -> None:
        self.user.user_permissions.add(Permission.objects.get(codename="clear_native_results"))
        self.create_units(2, 1)
        running = self.submit(lambda unit, boot, deadline: "exec 9>&-; sleep 120")
        cleanup = self.plan("clear_results")
        self.assertNotIn(running, set(cleanup.native_units.values_list("unit_name", flat=True)))
        # While it runs, the cleanup refuses under the lock, like any other change.
        run = self.apply(cleanup)
        self.assertEqual(run.execution, Execution.OTHER_RUN_ACTIVE)
        self.assertEqual(self.inspect(running).execution, Execution.RUNNING)
        self.assertEqual(len(self.units()), 5)
        self.administer(f"systemctl kill --signal=SIGKILL {running}; sleep 1")
        run = self.apply(self.plan("clear_results"))
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual(self.units(), [run.unit_name])
