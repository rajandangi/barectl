"""Guarded renewal and Barectl's runs excluding each other on a real server (docs/tls.md).

Tagged ``ssh``. After a reviewed setup, certbot.service runs the guarded wrapper through
actual systemd. Certbot itself is replaced, where a test needs it, by a stand-in bound over
/usr/bin/certbot, so that its processes can outlive the wrapper; no certificate is issued.
"""

import json
import shlex
import subprocess
import sys
import time
from typing import override

from django.contrib.auth.models import Permission

from bootstrap import native as bootstrap_native
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, Verification
from dashboard.testing import TEST_MANIFEST
from operations.models import RemoteOperation
from sites.test_coordination_remote import CONTROLLER as SITE_CONTROLLER

from . import renewal
from .test_setup_remote import SetupTestCase

Status = RemoteOperation.Status
Outcome = renewal.Outcome
LOCK = bootstrap_native.LOCK_FILE
STAND_IN = "/run/barectl-test-certbot"
SETUP_RELEASE = "/run/barectl-test-renewal-setup-release"
SETUP_ADMITTED = "barectl-test: renewal setup admitted"
CONTROLLER = SITE_CONTROLLER.replace(
    "client = Client()",
    f"""
from sites import native as site_native
from tls import setup_native

if name == "a":
    real_steps = setup_native.setup_steps

    def setup_payload(unit: str, boot: str, deadline: int, **reviewed: object) -> str:
        steps = real_steps(unit, boot, deadline, **reviewed)
        names = [item.name for item in steps]
        gate = (
            "printf '%s\\\\n' '{SETUP_ADMITTED}'; "
            "for i in $(seq 1 2400); do "
            "[ -e {SETUP_RELEASE} ] && break; sleep 0.05; done; "
            "[ -e {SETUP_RELEASE} ] || exit 99"
        )
        steps.insert(names.index("admission") + 1, site_native.Step("injected", gate))
        return "; ".join(item.text for item in steps)

    setup_native.setup_payload = setup_payload

client = Client()
""",
).replace(
    'if command.startswith("sudo -n /usr/bin/systemd-run "):',
    'if action != "certbot" and command.startswith("sudo -n /usr/bin/systemd-run "):',
)


class RenewalTestCase(SetupTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.user.user_permissions.add(Permission.objects.get(codename="clear_native_results"))
        run = self.apply_setup(self.eligible())
        self.assertEqual(
            (run.status, run.verification), (Status.SUCCEEDED, Verification.PASSED), run.failure
        )
        ApplyRun.objects.all().delete()
        ConfigurationPlan.objects.all().delete()
        self.clear_units()
        self.addCleanup(
            self.administer,
            f"umount /usr/bin/certbot 2>/dev/null; rm -f {STAND_IN}; "
            "systemctl kill --signal=SIGKILL certbot.service 2>/dev/null; "
            "rm -rf /run/systemd/system/certbot.service.d; systemctl daemon-reload; "
            "pkill -f '[b]arectl-test-holder'; pkill -x -f 'sleep 31'; true",
        )

    def stand_in(self, script: str) -> None:
        """Replace Certbot with ``script`` for the next renewals."""
        self.administer(
            f"printf '%s\\n' '#!/bin/sh' {shlex.quote(script)} >{STAND_IN} && "
            f"chmod 755 {STAND_IN} && mount --bind {STAND_IN} /usr/bin/certbot"
        )

    def renew(self, *, wait: bool = True) -> dict[str, str]:
        """Start certbot.service as the timer does; with ``wait``, return its outcome."""
        self.administer(f"systemctl start {'' if wait else '--no-block '}certbot.service; true")
        return self.show("certbot.service", "Result", "ExecMainStatus", "ActiveState", "MainPID")

    def renewal_journal(self) -> str:
        return self.administer("journalctl -u certbot.service -o cat --no-pager")

    def hold(self, script: str) -> None:
        """An administrator's command holding the mutation lock, as a compatible tool would."""
        marked = shlex.quote(f": barectl-test-holder; {script}")
        self.administer(f"flock -n {LOCK} sh -c {marked}", detach=True)
        deadline = time.monotonic() + 10
        while self.lock_is_free() and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertFalse(self.lock_is_free())


class RenewalExclusionTests(RenewalTestCase):
    def test_renewal_skips_while_another_change_holds_the_lock(self) -> None:
        # An interactive Certbot command under the lock, such as a later issuance.
        self.hold("certbot certificates >/dev/null 2>&1; sleep 31")
        shown = self.renew()
        self.assertEqual(
            (shown["Result"], shown["ExecMainStatus"]), ("success", str(Outcome.LOCK_HELD))
        )
        self.assertIn("skipped: another change holds the mutation lock", self.renewal_journal())
        # And a Barectl run refuses at once.
        refused = self.refused()
        self.assertEqual(refused.execution, Execution.LOCK_CONFLICT)

    def test_renewal_skips_while_an_apply_run_has_processes(self) -> None:
        running = self.submit(lambda unit, boot, deadline: "exec 9>&-; sleep 120")
        time.sleep(1)
        shown = self.renew()
        self.assertEqual(
            (shown["Result"], shown["ExecMainStatus"]), ("success", str(Outcome.APPLY_ACTIVE))
        )
        self.assertIn(f"{running} has processes", self.renewal_journal())
        self.administer(f"systemctl kill --signal=SIGKILL {running}; sleep 1")
        shown = self.renew()
        self.assertEqual((shown["Result"], shown["ExecMainStatus"]), ("success", "0"))

    def test_a_running_renewal_holds_the_lock_against_every_run(self) -> None:
        self.stand_in("sleep 60")
        self.renew(wait=False)
        time.sleep(2)
        self.assertFalse(self.lock_is_free())
        self.assertEqual(self.refused().execution, Execution.LOCK_CONFLICT)
        self.administer("systemctl stop certbot.service")
        self.assertTrue(self.lock_is_free())

    def test_a_child_outliving_the_wrapper_blocks_every_change_and_closure(self) -> None:
        # Certbot's children close the lock descriptor and ignore SIGTERM; killing the
        # wrapper leaves them in the service's control group until the stop limit.
        self.stand_in("exec 9>&-; trap '' TERM; sleep 600")
        self.renew(wait=False)
        time.sleep(2)
        main = self.show("certbot.service", "MainPID")["MainPID"]
        self.administer(f"kill -9 {main}")
        time.sleep(1)
        self.assertTrue(self.lock_is_free())
        self.assertIn(
            "populated 1",
            self.administer("cat /sys/fs/cgroup/system.slice/certbot.service/cgroup.events"),
        )
        refresh = self.refused()
        self.assertEqual(refresh.execution, Execution.RENEWAL_ACTIVE)
        cleanup = self.apply(self.plan("clear_results"))
        self.assertEqual(cleanup.execution, Execution.RENEWAL_ACTIVE)
        self.administer("systemctl kill --signal=SIGKILL certbot.service; sleep 1")
        self.assertEqual(self.apply().status, Status.SUCCEEDED)

    def test_an_unsafe_lock_fails_the_renewal(self) -> None:
        self.administer("mkdir -p -m 0700 /run/lock/barectl && chmod 0755 /run/lock/barectl")
        self.addCleanup(self.administer, "chmod 0700 /run/lock/barectl")
        shown = self.renew()
        self.assertEqual(
            (shown["Result"], shown["ExecMainStatus"]), ("exit-code", str(Outcome.UNSAFE_LOCK))
        )

    def test_the_start_limit_stops_a_renewal_and_frees_the_lock(self) -> None:
        directory = "/run/systemd/system/certbot.service.d"
        self.administer(
            f"mkdir -p {directory} && printf '[Service]\\nTimeoutStartSec=3s\\n' "
            f">{directory}/zz-barectl-test.conf && systemctl daemon-reload"
        )
        self.stand_in("sleep 60")
        shown = self.renew()
        self.assertEqual(shown["Result"], "timeout")
        self.assertTrue(self.lock_is_free())


class SetupCoordinationTests(SetupTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        (self.directory / "barrier").mkdir()
        self.administer(f"rm -f {SETUP_RELEASE}")
        self.addCleanup(self.administer, f"rm -f {SETUP_RELEASE}")

    def controller(self, name: str, alias: str, phase: str) -> subprocess.Popen[str]:
        directory = self.directory / name
        directory.mkdir(exist_ok=True)
        arguments = [
            str(directory / "db.sqlite3"),
            str(self.config),
            str(TEST_MANIFEST),
            alias,
            name,
            str(self.directory / "barrier"),
            phase,
            "certbot",
        ]
        process = subprocess.Popen(  # noqa: S603 - the test's own script
            [sys.executable, "-c", CONTROLLER, *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(self.stop_controller, process)
        return process

    def stop_controller(self, process: subprocess.Popen[str]) -> None:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)

    def held_admission(self, unit: str) -> None:
        self.assertIn(SETUP_ADMITTED, self.journal(unit))
        group = self.show(unit, "ControlGroup")["ControlGroup"]
        self.assertEqual(group, f"/system.slice/{unit}")
        self.assertIn("populated 1", self.administer(f"cat /sys/fs/cgroup{group}/cgroup.events"))
        self.assertFalse(self.lock_is_free())

    def wait_admitted(self) -> str:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            for unit in self.units():
                if SETUP_ADMITTED in self.journal(unit):
                    self.held_admission(unit)
                    return unit
            time.sleep(0.1)
        raise AssertionError("The first controller never reached its held native admission")

    def finish(self, process: subprocess.Popen[str]) -> dict[str, object]:
        stdout, stderr = process.communicate(timeout=900)
        self.assertEqual(process.returncode, 0, stderr[-3000:])
        result: dict[str, object] = json.loads(stdout.strip().splitlines()[-1])
        return result

    def test_two_controllers_setting_up_renewal_admit_one_run(self) -> None:
        controllers = {"a": "disposable", "b": "disposable-second"}
        for name, alias in controllers.items():
            self.assertTrue(self.finish(self.controller(name, alias, "prepare"))["eligible"])
        time.sleep(1.1)
        first = self.controller("a", controllers["a"], "apply")
        try:
            admitted = self.wait_admitted()
            second = self.finish(self.controller("b", controllers["b"], "apply"))
            self.assertEqual(second["execution"], Execution.LOCK_CONFLICT, second)
            self.held_admission(admitted)
        finally:
            self.administer(f"touch {SETUP_RELEASE}")
        results = [self.finish(first), second]
        executions = [str(result["execution"]) for result in results]
        succeeded = [r for r in results if r["execution"] == Execution.SUCCEEDED]
        self.assertEqual(len(succeeded), 1, executions)
        refused = next(r for r in results if r["execution"] != Execution.SUCCEEDED)
        self.assertIn(
            refused["execution"],
            {Execution.LOCK_CONFLICT, Execution.OTHER_RUN_ACTIVE, Execution.DRIFT},
            executions,
        )
        self.assertEqual(self.timer(), ("enabled", "active"))
        name = "a" if refused is results[0] else "b"
        review = self.finish(self.controller(name, controllers[name], "review"))
        self.assertEqual((review["eligible"], review["no_changes"]), (True, True), review)
