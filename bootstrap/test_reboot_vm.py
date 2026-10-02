"""Bootstrap across a real kernel reboot, on an Ubuntu official server cloud image.

Tagged ``vm``, and ``ssh`` through its base class, and skipped unless ``BARECTL_VM_TEST``
and the ``BARECTL_SSH_TEST_*`` connection variables are set, as
``docker/vm-server/run-tests.sh`` does. The disposable container of
``bootstrap/test_coordination_remote.py`` shares its host's kernel, so its restart keeps
the kernel's boot ID and monotonic clock; this virtual machine reboots its own kernel, so
both really change. It starts as the cloud image boots, without Nginx or PHP, with the
image's own packages, APT hooks and sources.

Ground truth is read as the server's administrator through the controller's OpenSSH
client, with the first key and its own trust file, independently of Barectl's connection.
No payload differs from what the worker submits: one reviewed payload, held in transit
before the reboot, is delivered afterwards through Barectl's adapter and connection.
"""

import os
import re
import shlex
import subprocess
import time
from typing import override
from unittest import skipUnless

from django.contrib.auth.models import Permission
from django.test import tag

from discovery import ssh
from discovery.fakes import run_worker
from discovery.models import ComponentObservation, DiscoveryAttempt
from discovery.services import request_discovery
from discovery.test_remote import setting
from operations.models import RemoteOperation
from servers.models import Server

from . import native
from .models import (
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEvidence,
    PlanPreparation,
    PlanRefusal,
    Verification,
)
from .test_apply_remote import (
    UPDATE_OUTPUT,
    ApplyAcceptanceTestCase,
    _is_inspection,
    _is_submission,
)
from .test_remote import PHP, PHP_FPM

Status = RemoteOperation.Status
VM = bool(os.environ.get("BARECTL_VM_TEST"))


@tag("vm")
@skipUnless(VM, "Run docker/vm-server/run-tests.sh to test against a virtual machine")
class RebootTests(ApplyAcceptanceTestCase):
    """The virtual machine, administered through OpenSSH as the sudo-capable SSH user."""

    @override
    def setUp(self) -> None:
        super().setUp()
        self.user.user_permissions.add(Permission.objects.get(codename="add_discoveryattempt"))

    @override
    def administer(self, script: str, *, detach: bool = False, timeout: float = 900) -> str:
        """Run ``script`` as root through OpenSSH, outside Barectl; return its output.

        A detached script runs as a transient unit of its own, which a reboot ends.
        """
        if detach:
            script = f"systemd-run --quiet --collect sh -c {shlex.quote(script)}"
        result = subprocess.run(  # noqa: S603 - the tests' own fixture scripts
            [  # noqa: S607
                "ssh",
                "-q",
                "-i",
                setting("KEY"),
                "-p",
                setting("PORT"),
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                f"UserKnownHostsFile={setting('KNOWN_HOSTS')}",
                "-o",
                "StrictHostKeyChecking=yes",
                f"{setting('USER')}@{setting('HOST')}",
                f"sudo sh -c {shlex.quote(script)}",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout

    def boot(self, timeout: float = 60) -> tuple[str, int]:
        """The kernel's boot ID and its monotonic uptime in hundredths of a second."""
        boot, uptime = self.administer(
            "cat /proc/sys/kernel/random/boot_id; cut -d' ' -f1 /proc/uptime | tr -d .",
            timeout=timeout,
        ).split()
        return boot, int(uptime)

    def reboot_when(self, condition: str) -> tuple[str, int]:
        """Have the server reboot its kernel as soon as ``condition`` holds there.

        The server itself waits for the condition, so the reboot follows it at once.
        Returns the boot ID and uptime read before, for ``rebooted``.
        """
        before = self.boot()
        self.administer(f"until {condition}; do sleep 0.05; done; systemctl reboot", detach=True)
        return before

    def rebooted(self, before: tuple[str, int], unit: str = "") -> None:
        """Wait until the server is back in a boot other than ``before``'s.

        When it never went away, the failure shows what ``unit`` logged, such as a run
        that stopped before dpkg unpacked anything.
        """
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            time.sleep(5)
            try:
                if self.boot(timeout=30)[0] != before[0]:
                    self.administer("systemctl is-system-running --wait >/dev/null; true")
                    return
            except subprocess.CalledProcessError, subprocess.TimeoutExpired:
                continue
        logged = self.journal(unit)[-3000:] if unit else ""
        raise AssertionError(f"The server did not come back after rebooting.\n{logged}")

    def eligible(self, action: str) -> ConfigurationPlan:
        plan = self.plan(action)
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan

    def closure(self, run: ApplyRun) -> ApplyRun:
        self.client.post(f"/applies/{run.pk}/acknowledge/", {"understood": "on"})
        run_worker()
        run.refresh_from_db()
        return run

    def delayed(self, run: ApplyRun) -> str:
        """Deliver ``run``'s reviewed refresh payload now, through the second alias."""
        plan = ConfigurationPlan.objects.get(pk=run.plan_number)
        digest = plan.evidence.get(kind=PlanEvidence.Kind.APT_REVALIDATION).fingerprint
        script = native.metadata_refresh(
            run.unit_name, run.boot_id, run.admission_deadline_centiseconds, digest
        )
        with ssh.connect_alias("disposable-second") as shell:
            result = shell.run(
                native.privileged(native.submission(run.unit_name, script), root=False)
            )
        self.assertEqual(result.exit_status, 0)
        self.wait_terminal(run.unit_name, timeout=300)
        return run.unit_name

    def php_serving(self) -> None:
        self.assertEqual(
            self.administer(
                f"systemctl is-enabled {PHP_FPM}; systemctl is-active {PHP_FPM}"
            ).split(),
            ["enabled", "active"],
        )
        self.assertIn(PHP.socket or "", self.administer(f"ss -Hlx src {PHP.socket}"))

    def test_a_reboot_ends_accepted_work_which_is_reconciled_never_resumed(self) -> None:
        # The cloud image's indexes are refreshed through a reviewed plan, which also runs
        # the image's update hooks.
        refresh = self.apply(self.eligible("metadata_refresh"))
        self.assertEqual((refresh.status, refresh.verification), (Status.SUCCEEDED, "passed"))
        self.assertRegex(self.journal(refresh.unit_name), UPDATE_OUTPUT)

        # Nginx, applied and verified, and then a plan without changes.
        nginx = self.apply(self.eligible("nginx"))
        self.assertEqual(nginx.status, Status.SUCCEEDED, nginx.failure)
        self.assertEqual(nginx.verification, Verification.PASSED)
        self.assertEqual(self.journal(nginx.unit_name).count(native.GUARD_ADMITTED + "\n"), 1)
        self.assertTrue(self.plan("nginx").no_changes)

        # A refresh through the second alias, reviewed before the reboot, whose submission
        # is held in transit.
        first = self.server
        self.server = Server.objects.create(name="Second alias", ssh_alias="disposable-second")
        with self.losing(_is_submission, after=False):
            held = self.apply(self.eligible("metadata_refresh"))
        self.server = first
        self.assertEqual(held.status, Status.RECONCILING)

        # The PHP installation is accepted; the worker loses its connection while it
        # watches, and the server reboots as soon as dpkg has unpacked a first package,
        # which dpkg's own log records at once.
        php = self.eligible("php")
        stamp = self.update_stamp()
        logged = int(self.administer("wc -l </var/log/dpkg.log"))
        old_boot, old_uptime = self.reboot_when(
            f"tail -n +{logged + 1} /var/log/dpkg.log | grep -q ' status unpacked '"
        )
        with self.losing(_is_inspection, after=False):
            run = self.apply(php)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIsNotNone(run.acknowledged_at)
        self.rebooted((old_boot, old_uptime), run.unit_name)

        # A new kernel: a new boot ID, a monotonic clock started again, and no transient
        # unit, lock directory or package process left. Nothing resumed the run or
        # refreshed the indexes.
        boot, uptime = self.boot()
        self.assertNotEqual(boot, old_boot)
        self.assertLess(uptime, old_uptime)
        self.assertEqual(self.units(), [])
        self.assertEqual(
            self.administer(
                f"test -e {native.LOCK_DIRECTORY} && echo present; "
                "pgrep -x 'apt-get|dpkg|apt' || true"
            ),
            "",
        )
        self.assertEqual(self.update_stamp(), stamp)

        # Check outcome finds no native evidence and explains the restart; the run stays
        # reconciling until an acknowledgement closes it, with the lock taken, as outcome
        # unknown, never as unchanged.
        run = self.check(run)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIn("The server restarted", run.failure)
        run = self.closure(run)
        self.assertEqual(run.status, Status.FAILED, run.closure_blocked)
        self.assertEqual(run.execution, Execution.OUTCOME_UNKNOWN)
        self.assertContains(
            self.client.get(f"/applies/{run.pk}/"),
            "Outcome unknown: this run may have changed the server",
        )
        self.assertEqual(
            self.administer(f"stat -c '%F %U %a' {native.LOCK_DIRECTORY}"), "directory root 700\n"
        )

        # The held payload arrives now. Its admission deadline is still ahead on the new
        # boot's clock, so only its boot identity refuses it, before APT runs.
        self.assertGreater(held.admission_deadline_centiseconds, self.boot()[1])
        unit = self.delayed(held)
        self.assertEqual(self.unit(unit)["ExecMainStatus"], str(native.Exit.BOOT_CHANGED))
        self.assertNotRegex(self.journal(unit), UPDATE_OUTPUT)
        self.assertEqual(self.update_stamp(), stamp)
        held = self.check(held)
        self.assertEqual((held.status, held.execution), (Status.FAILED, Execution.BOOT_CHANGED))

        # dpkg was stopped part way, leaving records only root can complete, so dpkg
        # refuses the review's unprivileged reads and the review is refused with the fix.
        # The administrator completes the packages with ordinary tools, and a fresh review
        # decides what remains.
        self.assertTrue(self.administer("dpkg --audit"))
        review = self.plan("php")
        self.assertFalse(review.eligible)
        self.assertTrue(
            review.refusals.filter(
                reason=PlanRefusal.Reason.INCOMPLETE, text__contains="sudo dpkg --configure -a"
            ).exists(),
            list(review.refusals.values_list("text", flat=True)),
        )
        self.administer(
            "DEBIAN_FRONTEND=noninteractive dpkg --configure -a >/dev/null; "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -f >/dev/null"
        )
        self.assertEqual(self.administer("dpkg --audit"), "")
        review = self.plan("php")
        self.assertTrue(review.eligible, list(review.refusals.values_list("text", flat=True)))
        if not review.no_changes:
            recovered = self.apply(review)
            self.assertEqual(recovered.status, Status.SUCCEEDED, recovered.failure)
            self.assertEqual(recovered.verification, Verification.PASSED)
        self.php_serving()
        self.assertTrue(self.plan("php").no_changes)
        self.assertTrue(self.plan("nginx").no_changes)

        # Discovery after the reboot observes both services from the server alone.
        attempt = DiscoveryAttempt.objects.filter(server=self.server).latest("pk")
        self.assertEqual(attempt.status, Status.SUCCEEDED, attempt.failure)
        request_discovery(self.server)
        run_worker()
        attempt = DiscoveryAttempt.objects.filter(server=self.server).latest("pk")
        units = {
            f"{unit.name} {unit.active_state}"
            for component in ComponentObservation.objects.filter(snapshot__attempt=attempt)
            for unit in component.service_units.all()
        }
        self.assertLessEqual({"nginx.service active", f"{PHP_FPM}.service active"}, units)
        # A reviewed refresh runs again in the new boot.
        self.assertEqual(self.apply(self.eligible("metadata_refresh")).status, Status.SUCCEEDED)
        versions = self.administer(f"uname -m; dpkg-query -W apt dpkg systemd nginx {PHP_FPM}")
        version = re.escape(PHP_FPM.removeprefix("php").removesuffix("-fpm"))
        self.assertTrue(
            re.search(rf"^{re.escape(PHP_FPM)}\t{version}\.", versions, re.MULTILINE), versions
        )

    def test_the_renewal_timer_lock_and_sentinel_survive_a_reboot(self) -> None:
        """The guarded renewal and the shared lock across a real kernel reboot.

        The image's indexes were refreshed by the journey above; this test runs after it in
        the module and proves the timer's own service, the empty lock's recovery and the
        operator's data across a second real reboot, without a certificate authority: the
        guarded wrapper has nothing due and exits cleanly.
        """
        for codename in ("view_tlsplan", "prepare_tlsplan", "apply_tlsplan"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        sentinel = "barectl-reboot-sentinel"
        self.administer(
            f"install -d -o root -g root -m 0755 /var/www/sentinel && "
            f"printf %s {sentinel} >/var/www/sentinel/kept && sync /var/www/sentinel/kept"
        )
        self.client.post(f"/servers/{self.server.pk}/tls/certbot/prepare/")
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        setup = self.apply(plan)
        self.assertEqual(
            (setup.status, setup.verification),
            (Status.SUCCEEDED, Verification.PASSED),
            setup.failure,
        )
        self.assertEqual(
            self.administer(
                "systemctl is-enabled certbot.timer; systemctl is-active certbot.timer"
            ).split(),
            ["enabled", "active"],
        )
        old_boot, old_uptime = self.reboot_when("test -f /root/barectl-reboot")
        self.administer("touch /root/barectl-reboot", detach=False)
        self.rebooted((old_boot, old_uptime))
        self.administer("rm -f /root/barectl-reboot; true")
        boot, uptime = self.boot()
        self.assertNotEqual(boot, old_boot)
        self.assertLess(uptime, old_uptime)
        # The runtime lock is gone with /run, the timer recovered, and the sentinel data
        # is unchanged. The guarded wrapper has nothing to renew and exits cleanly.
        self.assertEqual(
            self.administer("test ! -e /run/lock/barectl/mutation.lock && echo fresh").strip(),
            "fresh",
        )
        self.assertEqual(
            self.administer(
                "systemctl is-enabled certbot.timer; systemctl is-active certbot.timer"
            ).split(),
            ["enabled", "active"],
        )
        self.administer("systemctl start certbot.service")
        self.assertEqual(
            self.administer("systemctl show -p ExecMainStatus --value certbot.service").strip(),
            "0",
        )
        self.assertEqual(
            self.administer("systemctl show -p Result --value certbot.service").strip(), "success"
        )
        self.assertEqual(self.administer("cat /var/www/sentinel/kept").strip(), sentinel)
        # The shared lock is recreated safely after the reboot and can be taken at once:
        # the payloads' own contract is an empty regular file, root-owned, one link.
        locked = self.administer(
            "install -d -m 0700 /run/lock/barectl && f=/run/lock/barectl/mutation.lock && "
            'exec 9>>"$f" && { flock -n 9 || { sleep 2; flock -n 9; }; } && '
            "stat -c '%F %u %h' \"$f\""
        )
        self.assertEqual(locked.split(), ["regular", "empty", "file", "0", "1"])
