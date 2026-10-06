"""Certbot renewal setup on a real, disposable server (docs/tls.md#certbot-renewal-setup).

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. Every run goes through the dashboard request,
the worker, Barectl's SSH connection and actual systemd, APT, dpkg and Certbot's maintainer
scripts, with at most one administrator command inserted between two named fragments of
the production payload. Ground truth is read as root through ``docker exec``.
"""

import shlex
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission

from bootstrap import apply as bootstrap_apply
from bootstrap.models import (
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEffect,
    PlanPreparation,
    Verification,
)
from bootstrap.test_apply_remote import ApplyAcceptanceTestCase, _is_inspection
from discovery.fakes import run_worker
from discovery.test_remote import setting
from operations.models import RemoteOperation
from sites import native as site_native

from . import renewal, setup_native
from .models import SetupRunResult

Status = RemoteOperation.Status
Effect = PlanEffect.Kind
Exit = setup_native.Exit
NEW_BOOT = "0badb007-0000-4000-8000-000000000152"
TLS = ("view_tlsplan", "prepare_tlsplan", "apply_tlsplan")
# The administrator's own undoing of a setup, so that each test starts without Certbot.
PURGE = "; ".join(
    (
        "systemctl unmask --runtime certbot.timer certbot.service >/dev/null 2>&1",
        "rm -rf /run/systemd/system/certbot.timer.d /run/systemd/system/certbot.service.d",
        "systemctl disable --now certbot.timer >/dev/null 2>&1",
        "systemctl stop certbot.service >/dev/null 2>&1",
        "systemctl reset-failed certbot.service certbot.timer >/dev/null 2>&1",
        (
            "DEBIAN_FRONTEND=noninteractive apt-get -q -y purge --autoremove certbot "
            "python3-certbot python3-acme >/dev/null 2>&1"
        ),
        f"rm -rf {renewal.DROP_IN_DIRECTORY} {renewal.WRAPPER} {renewal.DEPLOY_HOOK}",
        "rm -rf /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt",
        "rm -f /etc/systemd/system/timers.target.wants/certbot.timer",
        "systemctl daemon-reload",
        "true",
    )
)


class SetupTestCase(ApplyAcceptanceTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        for codename in TLS:
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.administer(PURGE)
        self.addCleanup(self.administer, PURGE)

    def setup_plan(self) -> ConfigurationPlan:
        self.client.post(f"/servers/{self.server.pk}/tls/certbot/prepare/")
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        return ConfigurationPlan.objects.get(preparation=preparation)

    def eligible(self) -> ConfigurationPlan:
        plan = self.setup_plan()
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan

    def apply_setup(self, plan: ConfigurationPlan) -> ApplyRun:
        run = self.request(plan)
        run_worker()
        run.refresh_from_db()
        return run

    @contextmanager
    def injected(self, after: str, step: str) -> Iterator[None]:
        real = setup_native.setup_steps

        def payload(unit: str, boot: str, deadline: int, **reviewed: object) -> str:
            steps = real(unit, boot, deadline, **reviewed)  # type: ignore[arg-type]
            names = [item.name for item in steps]
            steps.insert(names.index(after) + 1, site_native.Step("injected", step))
            return "; ".join(item.text for item in steps)

        with mock.patch.object(setup_native, "setup_payload", payload):
            yield

    def fault(self, after: str, step: str, undo: str = "true") -> ApplyRun:
        plan = self.eligible()
        self.addCleanup(self.administer, undo)
        with self.injected(after, step):
            return self.apply_setup(plan)

    def show(self, unit: str, *properties: str) -> dict[str, str]:
        options = " ".join(f"-p {name}" for name in properties)
        shown = self.administer(f"systemctl show {options} {unit}")
        return dict(line.split("=", 1) for line in shown.splitlines() if "=" in line)

    def timer(self) -> tuple[str, str]:
        shown = self.show("certbot.timer", "UnitFileState", "ActiveState")
        return shown["UnitFileState"], shown["ActiveState"]

    def never_renewed(self) -> None:
        """Certbot's service never ran, and Certbot holds no state beyond its package."""
        shown = self.show("certbot.service", "ExecMainStartTimestampMonotonic")
        self.assertEqual(shown["ExecMainStartTimestampMonotonic"], "0")
        self.assertEqual(self.administer("ls -A /var/log/letsencrypt 2>/dev/null; true"), "")
        found = self.administer("find /etc/letsencrypt -mindepth 1 2>/dev/null | sort; true")
        self.assertEqual(found.split(), [] if not found else ["/etc/letsencrypt/cli.ini"])

    def installed(self) -> str:
        return self.administer("dpkg-query -W -f='${Version} ${db:Status-Abbrev}' certbot; true")

    def wait_for_process(self, command: str) -> None:
        deadline = time.monotonic() + 240
        while not self.administer(f"pgrep -fx {shlex.quote(command)}; true").strip():
            self.assertLess(time.monotonic(), deadline, f"{command} never started")
            time.sleep(0.5)

    def restart(self) -> None:
        """Restart the container, then give it a new boot ID, as a reboot would."""
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


class SetupAcceptanceTests(SetupTestCase):
    def test_a_reviewed_setup_installs_certbot_and_guards_its_renewal(self) -> None:
        plan = self.eligible()
        kinds = list(plan.effects.values_list("kind", flat=True))
        for kind in (Effect.PACKAGES, Effect.SERVICE_INHIBITION, Effect.RENEWAL_INTEGRATION):
            self.assertIn(kind, kinds)
        self.assertNotIn(Effect.MAINTAINER_START, kinds)
        self.assertTrue(plan.transitions.filter(package="certbot").exists())
        # Preparing changed nothing.
        self.assertEqual(self.installed(), "")
        run = self.apply_setup(plan)
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        self.assertEqual(SetupRunResult.objects.get(run=run).problems, "")
        self.assertTrue(self.installed().endswith(" ii "))
        for file in renewal.files():
            self.assertEqual(self.administer(f"cat {file.path}"), file.content)
            self.assertEqual(
                self.administer(f"stat -c '%U %G %a' {file.path}").strip(),
                f"root root {file.mode.lstrip('0')}",
            )
        self.assertEqual(self.timer(), ("enabled", "active"))
        shown = self.show(
            "certbot.service", "DropInPaths", "ExecStart", "SuccessExitStatus", "KillMode"
        )
        self.assertEqual(shown["DropInPaths"], renewal.DROP_IN)
        self.assertIn(f"argv[]=/usr/bin/sh {renewal.WRAPPER} ;", shown["ExecStart"])
        self.assertEqual(shown["SuccessExitStatus"], "75 76")
        self.assertEqual(self.administer("ls /run/systemd/system | grep certbot; true"), "")
        self.never_renewed()
        # A repeated review has no changes.
        again = self.setup_plan()
        self.assertTrue(again.no_changes, list(again.refusals.values_list("text", flat=True)))
        # After a restart empties /run, the service recreates the lock inode, takes it and
        # finds nothing to renew.
        self.administer("rm -rf /run/lock/barectl")
        self.administer("systemctl start certbot.service")
        shown = self.show("certbot.service", "Result", "ExecMainStatus")
        self.assertEqual((shown["Result"], shown["ExecMainStatus"]), ("success", "0"))
        self.assertEqual(
            self.administer(
                "stat -c '%F %U %a' /run/lock/barectl; "
                "stat -c '%F %U %h' /run/lock/barectl/mutation.lock"
            ),
            "directory root 700\nregular empty file root 1\n",
        )
        self.assertTrue(self.lock_is_free())
        # A new preparation, a protected read-only inspection, shows that renewal ran.
        inspected = self.setup_plan()
        page = self.client.get(f"/plans/{inspected.pk}/")
        self.assertContains(page, "certbot.timer is enabled and active")
        self.assertContains(page, "completed: nothing was due")

    def test_a_lost_acknowledgement_is_checked_without_resubmitting(self) -> None:
        plan = self.eligible()
        with self.losing(_is_inspection, after=False):
            run = self.apply_setup(plan)
        self.assertEqual(run.status, Status.RECONCILING)
        self.wait_terminal(run.unit_name, timeout=600)
        run = self.check(run)
        self.assertEqual((run.status, run.verification), (Status.SUCCEEDED, Verification.PASSED))
        self.assertEqual(self.units(), [run.unit_name])


class InhibitionTests(SetupTestCase):
    def test_timer_and_service_cannot_start_while_inhibited(self) -> None:
        run = self.fault(
            "inhibition",
            "systemctl start certbot.timer >/dev/null 2>&1; "
            "systemctl start certbot.service >/dev/null 2>&1; true",
        )
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        # Nothing renewed during the run; the timer runs only once the guard exists.
        self.never_renewed()

    def test_a_timer_forced_to_fire_runs_only_the_guarded_wrapper(self) -> None:
        directory = "/run/systemd/system/certbot.timer.d"
        run = self.fault(
            "inhibition",
            f"mkdir -p {directory} && printf '[Timer]\\nOnActiveSec=1s\\nRandomizedDelaySec=0\\n' "
            f">{directory}/barectl-test.conf && systemctl daemon-reload",
            f"rm -rf {directory}; systemctl daemon-reload",
        )
        self.assertEqual(run.execution, Execution.SUCCEEDED, run.failure)
        # Verification sees the foreign timer drop-in.
        self.assertEqual(run.verification, Verification.FAILED)
        self.assertIn("certbot.timer is not enabled", SetupRunResult.objects.get(run=run).problems)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            shown = self.show(
                "certbot.service", "ExecMainStartTimestampMonotonic", "Result", "ExecMainStatus"
            )
            if shown["ExecMainStartTimestampMonotonic"] != "0" and shown["Result"]:
                break
            time.sleep(1)
        self.assertNotEqual(shown["ExecMainStartTimestampMonotonic"], "0")
        self.assertEqual((shown["Result"], shown["ExecMainStatus"]), ("success", "0"))
        self.assertIn(
            f"/usr/bin/sh {renewal.WRAPPER}", self.show("certbot.service", "ExecStart")["ExecStart"]
        )

    def test_a_refusal_during_installation_removes_the_masks(self) -> None:
        # APT's lock held by another package operation: nothing changed.
        holder = (
            "import fcntl, os, time; "
            "f = os.open('/var/lib/dpkg/lock-frontend', os.O_RDWR | os.O_CREAT, 0o640); "
            "fcntl.lockf(f, fcntl.LOCK_EX); time.sleep(120)"
        )
        self.addCleanup(self.administer, "pkill -f '[l]ock-frontend'; true")
        self.administer(f'python3 -c "{holder}"', detach=True)
        time.sleep(1)
        run = self.apply_setup(self.eligible())
        self.assertEqual(run.execution, Execution.PACKAGE_MANAGER_BUSY, run.failure)
        self.assertEqual(self.installed(), "")
        self.assertEqual(self.administer("ls /run/systemd/system | grep certbot; true"), "")

    def test_a_partial_publication_stops_with_the_timer_inhibited(self) -> None:
        # The drop-in's directory is read-only: both scripts are published, the drop-in not.
        directory = renewal.DROP_IN_DIRECTORY
        run = self.fault(
            "installation",
            f"mkdir -m 0755 {directory} && mount --bind {directory} {directory} && "
            f"mount -o remount,bind,ro {directory}",
            f"umount {directory} 2>/dev/null; true",
        )
        self.assertEqual((run.execution, run.exit_status), (Execution.PARTIAL, Exit.FILES))
        self.assertIn("publishing the renewal files stopped", run.failure)
        present = self.administer(
            f"for f in {renewal.DEPLOY_HOOK} {renewal.WRAPPER} {renewal.DROP_IN}; do "
            '[ -f "$f" ] && echo "$f"; done; true'
        )
        self.assertEqual(present.split(), [renewal.DEPLOY_HOOK, renewal.WRAPPER])
        self.assertEqual(self.show("certbot.timer", "LoadState")["LoadState"], "masked")
        self.assertEqual(
            self.administer("ls -A /usr/local/sbin | grep '^\\.' ; true"), "", "a stage remains"
        )
        self.never_renewed()

    def test_a_corrupted_override_stops_with_the_timer_inhibited(self) -> None:
        run = self.fault(
            "files",
            f"printf 'TimeoutStartSec=1min\\n' >>{renewal.DROP_IN}",
        )
        self.assertEqual((run.execution, run.exit_status), (Execution.PARTIAL, Exit.OVERRIDE))
        self.assertIn("systemctl cat certbot.service", run.failure)
        self.assertEqual(self.timer(), ("masked-runtime", "inactive"))
        self.never_renewed()

    def test_a_timer_that_cannot_be_enabled_is_reported(self) -> None:
        wants = "/etc/systemd/system/timers.target.wants"
        run = self.fault(
            "override",
            f"mkdir -p {wants} && mount --bind -o ro {wants} {wants} && "
            f"mount -o remount,bind,ro {wants}",
            f"umount {wants} 2>/dev/null; true",
        )
        self.assertEqual((run.execution, run.exit_status), (Execution.PARTIAL, Exit.TIMER))
        self.assertEqual(self.timer()[0], "disabled")
        self.never_renewed()

    def test_killed_runs_leave_renewal_inhibited_until_a_restart(self) -> None:
        for after, installed in (("inhibition", False), ("installation", True), ("files", True)):
            with self.subTest(after=after):
                run = self.fault(after, "kill -9 $$")
                self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.KILLED))
                self.assertEqual(self.installed().endswith(" ii "), installed)
                shown = self.show("certbot.timer", "LoadState")
                self.assertEqual(shown["LoadState"], "masked")
                self.never_renewed()
                self.clear_units()
                ApplyRun.objects.all().delete()
                self.administer(PURGE)

    def test_a_restart_at_the_inhibition_boundary_leaves_the_timer_disabled(self) -> None:
        with mock.patch.object(bootstrap_apply, "WATCH_LIMIT", timedelta(seconds=6)):
            run = self.fault("installation", "sleep 600")
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertEqual(self.show("certbot.timer", "LoadState")["LoadState"], "masked")
        # The watch gives up after 6 s; the boundary is reached once the injected step runs.
        self.wait_for_process("sleep 600")
        self.restart()
        self.assertEqual(self.units(), [])
        # The runtime masks are gone, the timer the maintainer scripts could not enable is
        # disabled, and nothing renewed.
        self.assertEqual(self.timer(), ("disabled", "inactive"))
        self.assertEqual(self.administer("ls /run/systemd/system | grep certbot; true"), "")
        self.never_renewed()
        run = self.check(run)
        self.assertIn("The server restarted", run.failure)
        self.client.post(f"/applies/{run.pk}/acknowledge/", {"understood": "on"})
        run_worker()
        run.refresh_from_db()
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.OUTCOME_UNKNOWN))
        # A fresh review offers what remains: the renewal files and the timer, not packages.
        plan = self.eligible()
        self.assertFalse(plan.transitions.exists())
        run = self.apply_setup(plan)
        self.assertEqual(
            (run.status, run.verification), (Status.SUCCEEDED, Verification.PASSED), run.failure
        )
        self.assertEqual(self.timer(), ("enabled", "active"))
