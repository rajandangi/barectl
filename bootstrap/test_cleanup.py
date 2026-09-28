"""Clearing finished bootstrap runs: a reviewed plan applied through the same apply lifecycle.

Real views, services, the lifecycle, the worker, persistence and rendering run against the
simulated systemd of ``bootstrap.fakes``. These tests establish the local workflow and its
permissions; ``bootstrap/test_apply_remote.py`` establishes what real systemd does with
the payload.
"""

from django.test import SimpleTestCase

from operations.models import RemoteOperation
from servers.models import Server

from . import apply, native
from .fakes import BOOT_ID, NativeUnit, finished_unit
from .models import ApplyRun, ConfigurationPlan, Execution, PlanEffect, Verification
from .native import Exit
from .test_apply import APPLY_PERMISSIONS, ApplyTestCase

Status = RemoteOperation.Status
CLEAR_PERMISSIONS = (
    "view_server",
    "view_configurationplan",
    "prepare_configurationplan",
    "clear_native_results",
)
EXITED = "barectl-apply-" + "a" * 32 + ".service"
FAILED = "barectl-apply-" + "b" * 32 + ".service"
RUNNING = "barectl-apply-" + "c" * 32 + ".service"


class CleanupTestCase(ApplyTestCase):
    def cleanup_plan(self) -> ConfigurationPlan:
        plan = self.plan("clear_results")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan

    def clear(self, plan: ConfigurationPlan) -> ApplyRun:
        self.sign_in_with(*CLEAR_PERMISSIONS)
        self.client.post(f"/plans/{plan.pk}/apply/")
        self.run_worker()
        return ApplyRun.objects.get(plan_number=plan.pk)


class CleanupWorkflowTests(CleanupTestCase):
    def test_a_reviewed_cleanup_clears_only_finished_units(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        self.systemd.units[FAILED] = finished_unit(2, failed=True)
        self.systemd.units[RUNNING] = NativeUnit(1000, 0, "success", invocation_id="c" * 32)
        plan = self.cleanup_plan()
        self.assertFalse(plan.no_changes)
        self.assertEqual(
            list(plan.native_units.values_list("unit_name", "invocation_id", "active_state")),
            [(EXITED, f"{1:032x}", "active"), (FAILED, f"{2:032x}", "failed")],
        )
        effects = dict(plan.effects.values_list("kind", "text"))
        self.assertIn("systemctl stop for 1 successful", effects[PlanEffect.Kind.CLEAR_UNITS])
        self.assertIn(
            "only close that run as outcome unknown", effects[PlanEffect.Kind.NATIVE_EVIDENCE]
        )
        self.assertIn("1 still running", effects[PlanEffect.Kind.KEPT_UNITS])
        self.sign_in_with(*CLEAR_PERMISSIONS)
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, "Finished bootstrap runs to clear")
        self.assertContains(page, EXITED)
        self.assertContains(page, f"Apply plan {plan.pk}")
        run = self.clear(plan)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual(run.execution, Execution.SUCCEEDED)
        self.assertEqual(run.verification, Verification.PASSED)
        # The reviewed units and their invocations are bound into the one submission.
        (submission,) = self.systemd.submissions
        self.assertIn(f"{EXITED}:{1:032x} {FAILED}:{2:032x}", submission)
        self.assertNotIn(RUNNING, submission)
        self.assertEqual(set(self.systemd.units), {RUNNING, run.unit_name})
        # Barectl's own audit stays.
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Clear finished bootstrap runs: apply run")
        self.assertContains(page, "Applied and verified")
        # The audit names every unit the reviewed cleanup cleared, apart from the plan.
        self.assertEqual(
            run.reviewed_changes.splitlines(),
            [f"Clear {EXITED}, invocation {1:032x}", f"Clear {FAILED}, invocation {2:032x}"],
        )
        self.assertContains(page, f"Clear {EXITED}, invocation {1:032x}")

    def test_units_of_runs_this_installation_is_establishing_are_kept(self) -> None:
        other = Server.objects.create(name="Alias", ssh_alias="stage.example.net")
        self.systemd.lose_acknowledgement = True
        reconciling = self.apply()
        self.systemd.lose_acknowledgement = False
        self.assertEqual(reconciling.status, Status.RECONCILING)
        # The same server registered under another alias prepares a cleanup meanwhile.
        server, self.server = self.server, other
        plan = self.cleanup_plan()
        self.server = server
        self.assertTrue(plan.no_changes)
        effects = dict(plan.effects.values_list("kind", "text"))
        self.assertIn(
            "this installation is still establishing", effects[PlanEffect.Kind.KEPT_UNITS]
        )

    def test_nothing_finished_is_a_plan_without_changes(self) -> None:
        plan = self.cleanup_plan()
        self.assertTrue(plan.no_changes)
        self.sign_in_with(*CLEAR_PERMISSIONS)
        self.assertNotContains(self.client.get(f"/plans/{plan.pk}/"), "Apply plan")

    def test_changed_units_refuse_the_whole_cleanup_before_clearing(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        plan = self.cleanup_plan()
        self.systemd.exit_status = Exit.DRIFT
        self.systemd.result = "exit-code"
        run = self.clear(plan)
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Execution.DRIFT)
        self.assertIn("stopped before clearing anything", run.failure)
        self.assertIn(EXITED, self.systemd.units)

    def test_a_partial_cleanup_is_reported_as_failed(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        plan = self.cleanup_plan()
        self.systemd.exit_status = Exit.CLEANUP_FAILED
        self.systemd.result = "exit-code"
        run = self.clear(plan)
        self.assertEqual(run.execution, Execution.FAILED)
        self.assertIn("some units may be cleared", run.failure)


class CleanupCapacityTests(CleanupTestCase):
    def test_cleanup_stays_available_at_capacity_up_to_its_ceiling(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        self.systemd.retained = native.RETAINED_LIMIT
        refresh = self.apply()
        self.assertEqual(refresh.failure, apply.RETAINED_FAILURE)
        self.assertEqual(refresh.execution, Execution.NOT_SUBMITTED)
        plan = self.cleanup_plan()
        run = self.clear(plan)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.systemd.retained = native.CLEANUP_CEILING
        self.systemd.units[FAILED] = finished_unit(2, failed=True)
        run = self.clear(self.cleanup_plan())
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.failure, apply.CLEANUP_CEILING_FAILURE)
        self.assertEqual(run.execution, Execution.NOT_SUBMITTED)

    def test_capacity_refused_under_the_lock_changes_nothing(self) -> None:
        self.systemd.exit_status = Exit.CAPACITY
        self.systemd.result = "exit-code"
        run = self.apply()
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Execution.CAPACITY)
        self.assertIn("stopped before changing anything", run.failure)
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "The run stopped before making any requested change.")


class CleanupAccessTests(CleanupTestCase):
    def test_clearing_needs_its_own_permission(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        plan = self.cleanup_plan()
        # Applying other plans does not allow clearing native results, nor the reverse.
        self.user.user_permissions.clear()
        self.sign_in_with(*APPLY_PERMISSIONS)
        self.assertNotContains(self.client.get(f"/plans/{plan.pk}/"), "Apply plan")
        self.assertEqual(self.client.post(f"/plans/{plan.pk}/apply/").status_code, 403)
        self.assertFalse(ApplyRun.objects.exists())
        csrf = self.client_class(enforce_csrf_checks=True)
        self.user.user_permissions.clear()
        self.grant(*CLEAR_PERMISSIONS)
        csrf.force_login(self.user)
        self.assertEqual(csrf.post(f"/plans/{plan.pk}/apply/").status_code, 403)
        refresh = self.plan("metadata_refresh")
        self.assertEqual(self.client.post(f"/plans/{refresh.pk}/apply/").status_code, 403)
        self.assertEqual(self.clear(plan).status, Status.SUCCEEDED)

    def test_the_worker_rechecks_the_clearing_permission(self) -> None:
        self.systemd.units[EXITED] = finished_unit(1)
        plan = self.cleanup_plan()
        self.sign_in_with(*CLEAR_PERMISSIONS)
        self.client.post(f"/plans/{plan.pk}/apply/")
        self.user.user_permissions.clear()
        self.run_worker()
        run = ApplyRun.objects.get()
        self.assertEqual(run.failure, apply.REVOKED_FAILURE)
        self.assertFalse(self.systemd.submissions)


class CleanupPayloadTests(SimpleTestCase):
    def test_the_payload_verifies_every_unit_before_clearing_any(self) -> None:
        unit = native.new_unit_name()
        targets = [native.ClearTarget(EXITED, "a" * 32), native.ClearTarget(FAILED, "b" * 32)]
        payload = native.clear_results(unit, BOOT_ID, 590025, targets)
        lock = payload.index("flock -n 9 || exit 10")
        capacity = payload.index(f"-lt {native.CLEANUP_CEILING} ] || exit 18")
        verify = payload.index("exit 15")
        stop = payload.index('systemctl stop "$n"')
        reset = payload.index('systemctl reset-failed "$n"')
        self.assertLess(lock, capacity)
        self.assertLess(capacity, verify)
        self.assertLess(verify, stop)
        self.assertLess(stop, reset)
        self.assertIn(f"t='{EXITED}:{'a' * 32} {FAILED}:{'b' * 32}'", payload)

    def test_targets_are_validated(self) -> None:
        unit = native.new_unit_name()
        for targets in (
            [],
            [native.ClearTarget("nginx.service", "a" * 32)],
            [native.ClearTarget(EXITED, "'; reboot; '")],
            [native.ClearTarget(unit, "a" * 32)],
            [native.ClearTarget(EXITED, "a" * 32)] * (native.CLEANUP_BATCH + 1),
        ):
            with self.subTest(targets=len(targets)), self.assertRaises(ValueError):
                native.clear_results(unit, BOOT_ID, 1, targets)

    def test_a_full_batch_fits_one_submission(self) -> None:
        targets = [
            native.ClearTarget(f"barectl-apply-{index:032x}.service", f"{index:032x}")
            for index in range(1, native.CLEANUP_BATCH + 1)
        ]
        unit = native.new_unit_name()
        payload = native.clear_results(unit, BOOT_ID, 590025, targets)
        self.assertEqual(native.submission(unit, payload)[-1], payload)

    def test_the_closure_probe_reads_only_under_the_lock(self) -> None:
        unit = native.new_unit_name()
        _, _, script = native.closure_probe(unit)
        lock = script.index("flock -n 9 || exit 10")
        for read in ("random/boot_id", "/proc/uptime", "populated", f"LoadState {unit}"):
            self.assertLess(lock, script.index(read))
        self.assertNotIn("systemctl stop", script)
        self.assertNotIn("reset-failed", script)
        good = f"{BOOT_ID}\n590025\npopulated 0\nnot-found\n"
        probe = native.parse_probe(good)
        self.assertEqual(
            (probe.uptime_centiseconds, probe.populated, probe.unit_loaded), (590025, 0, False)
        )
        for bad in (good + "x\n", good.replace("590025", "59.0"), good.replace(BOOT_ID, "x")):
            with self.subTest(bad=bad), self.assertRaises(native.Unreadable):
                native.parse_probe(bad)

    def test_retained_states_are_read_strictly(self) -> None:
        unit = finished_unit(1).report(EXITED)
        boot, units = native.parse_retained_states(f"{BOOT_ID}\n{unit}")
        self.assertEqual(boot, BOOT_ID)
        self.assertEqual([(u.unit, u.terminal) for u in units], [(EXITED, True)])
        for bad in (
            f"{BOOT_ID}\n{unit}extra\n",
            f"{BOOT_ID}\n{unit.replace(EXITED, 'nginx.service')}",
        ):
            with self.subTest(bad=bad), self.assertRaises(native.Unreadable):
                native.parse_retained_states(bad)
        self.assertEqual(native.parse_retained_states(f"{BOOT_ID}\n"), (BOOT_ID, []))
