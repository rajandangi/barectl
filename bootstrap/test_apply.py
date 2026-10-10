"""The request-to-worker-to-native-unit-to-rendered-audit workflow for apply runs.

Real views, services, the lifecycle, the ``db_worker`` command, persistence and rendering
run against a simulated server whose systemd answers ``bootstrap.native``'s submission and
inspection. These tests establish the local lifecycle: one submission per revision,
reconciliation instead of replay, conditional recording, sanitized audit and gating. They
establish nothing about real systemd, flock or APT; ``bootstrap/test_apply_remote.py``
does, against a disposable Ubuntu server.
"""

import os
import re
import shutil
import subprocess
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission
from django.db.models import F
from django.test import SimpleTestCase
from django.utils import timezone

from discovery.fakes import HOST_KEY, record_attempt
from discovery.models import DiscoveryAttempt
from discovery.ssh import CommandResult, ConnectionFailed
from operations import lifecycle
from operations.models import RemoteOperation
from servers.models import Server
from servers.registration import RemovalBlocked, remove_server
from servers.testing import HTMX_FRAGMENT

from . import apply, native
from .fakes import BOOT_ID, UPTIME_CENTISECONDS, NativeSystemd, PreparationTestCase
from .models import (
    ADMISSION_CENTISECONDS,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEvidence,
    Verification,
)
from .native import Exit

Status = RemoteOperation.Status
APPLY_PERMISSIONS = (
    "view_server",
    "view_configurationplan",
    "prepare_configurationplan",
    "apply_configurationplan",
)
SUBMISSION = re.compile(r"\A(sudo -n )?/usr/bin/systemd-run --unit=barectl-apply-[0-9a-f]{32}")
# The closure probe, and sudo's listing of it, which runs nothing.
PROBE = re.compile(r"\A(sudo -n (-l )?)?/usr/bin/sh -c '")
# A package run's verification reads the marks of the packages it installed, and the PHP
# command-line runtime's or the MariaDB server's version.
VERIFICATION_READS = re.compile(
    r"\Aapt-mark (showmanual [a-z0-9+. -]+"
    r"|showauto \| grep -vxF (-e [a-z0-9+.-]+ )+\| LC_ALL=C sort \| sha256sum)\Z"
    r"|\Aphp8\.5 -v\Z"
    r"|\A/usr/sbin/mariadbd --version\Z"
)


class ApplyTestCase(PreparationTestCase):
    systemd: NativeSystemd

    @override
    def setUp(self) -> None:
        super().setUp()
        self.systemd = NativeSystemd()
        self.systemd.answer(self.remote)
        self.enterContext(mock.patch.object(apply, "POLL_INTERVAL", 0))

    @override
    def assert_read_only(self) -> None:
        # Besides reads, each run submits exactly one transient unit, never a second.
        units = [
            match[1]
            for command in self.remote.commands
            if (match := re.search(r"--unit=(\S+)", command)) and SUBMISSION.match(command)
        ]
        self.assertEqual(len(units), len(set(units)), "A run was submitted twice")
        reads = [
            command
            for command in self.remote.commands
            if not SUBMISSION.match(command)
            and not command.startswith(f"sudo -n -l {native.SYSTEMD_RUN} ")
            and command
            not in {
                native.USER_ID,
                native.RETAINED_UNITS,
                native.RETAINED_STATES,
                native.DPKG_STATUS_DIGEST,
                apply.AUTO_MARKS_DIGEST,
            }
            and not VERIFICATION_READS.match(command)
            and not command.startswith("cat /proc/sys/kernel/random/boot_id; systemctl show")
            and not PROBE.match(command)
        ]
        self.remote.commands[:] = reads
        super().assert_read_only()

    def refresh_plan(self) -> ConfigurationPlan:
        plan = self.plan("metadata_refresh")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan

    def request(self, plan: ConfigurationPlan) -> ApplyRun:
        self.sign_in_with(*APPLY_PERMISSIONS)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.filter(plan_number=plan.pk).first()
        if run is None:
            raise AssertionError("No run was queued.")
        return run

    def apply(self, plan: ConfigurationPlan | None = None) -> ApplyRun:
        run = self.request(plan or self.refresh_plan())
        self.run_worker()
        return ApplyRun.objects.get(pk=run.pk)

    def check(self, run: ApplyRun) -> ApplyRun:
        self.client.post(f"/applies/{run.pk}/check/")
        self.run_worker()
        return ApplyRun.objects.get(pk=run.pk)


class ApplyWorkflowTests(ApplyTestCase):
    def test_a_reviewed_refresh_runs_once_natively_and_is_audited(self) -> None:
        self.systemd.running = 2
        plan = self.refresh_plan()
        queued = self.request(plan)
        # The native identity is saved before the worker sends anything.
        self.assertEqual(queued.status, Status.QUEUED)
        self.assertRegex(queued.unit_name, r"\Abarectl-apply-[0-9a-f]{32}\.service\Z")
        self.assertFalse(self.systemd.submissions)
        self.run_worker()
        run = ApplyRun.objects.get(pk=queued.pk)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual(run.execution, Execution.SUCCEEDED)
        self.assertEqual(run.verification, Verification.PASSED)
        self.assertEqual(run.invocation_id, "0f" * 16)
        self.assertIsNotNone(run.dispatched_at)
        self.assertIsNotNone(run.acknowledged_at)
        self.assertEqual(run.host_key, HOST_KEY)
        (submission,) = self.systemd.submissions
        self.assertIn(f"--unit={queued.unit_name}", submission)
        self.assertTrue(submission.startswith("sudo -n /usr/bin/systemd-run "))
        # sudo authorization was listed for exactly the submitted command line.
        listed = [
            c for c in self.remote.commands if c.startswith("sudo -n -l /usr/bin/systemd-run ")
        ]
        self.assertEqual(listed, [submission.replace("sudo -n ", "sudo -n -l ", 1)])
        # The payload is bound to the reviewed boot, deadline and APT digest.
        digest = plan.evidence.get(kind=PlanEvidence.Kind.APT_REVALIDATION).fingerprint
        for bound in (BOOT_ID, str(UPTIME_CENTISECONDS + ADMISSION_CENTISECONDS), digest):
            self.assertIn(bound, submission)
        # The audit keeps copies that outlive the plan.
        self.assertEqual(
            (run.plan_number, run.server_name, run.reviewed_host_key, run.boot_id),
            (plan.pk, "Web", HOST_KEY, BOOT_ID),
        )
        self.assertEqual(run.requested_by_name, "operator")
        self.assertIn("Package index update. apt-get update downloads", run.effects)
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Applied and verified")
        self.assertContains(page, "Completed successfully")
        self.assertContains(page, "Postconditions hold")
        self.assertContains(page, run.unit_name)
        self.assertContains(page, "The server has no discovery snapshot.")
        self.assertNotContains(page, "Check outcome")
        plan_page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(plan_page, f'href="/applies/{run.pk}/"')
        self.assertNotContains(plan_page, "Apply plan")
        server_page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertContains(server_page, "Latest apply run: Applied and verified")
        activity = self.client.get("/activity/")
        self.assertContains(activity, "Apply: Package metadata refresh")

    def test_the_polled_status_also_updates_the_audit(self) -> None:
        run = self.request(self.refresh_plan())
        page = self.client.get(f"/applies/{run.pk}/").content.decode()
        shown = page.split("?shown=")[1].split('"')[0]
        self.assertIn("Not submitted", page)
        self.run_worker()
        url = f"/applies/{run.pk}/status/?shown={shown}"
        changed = self.client.get(url, headers=HTMX_FRAGMENT).content.decode()
        audit = changed.split('hx-target="#apply-audit"')[1]
        self.assertIn("acknowledged by the server", audit)
        self.assertNotIn("Not submitted", audit)
        # A poll that already shows the current state leaves the audit alone.
        presented = apply.read_apply(run.pk)
        if presented is None:
            self.fail("The run is not readable.")
        url = f"/applies/{run.pk}/status/?shown={presented.token}"
        unchanged = self.client.get(url, headers=HTMX_FRAGMENT).content.decode()
        self.assertNotIn('hx-target="#apply-audit"', unchanged)

    def test_duplicate_requests_converge_on_one_run(self) -> None:
        plan = self.refresh_plan()
        self.sign_in_with(*APPLY_PERMISSIONS)
        first = self.client.post(f"/plans/{plan.pk}/apply/")
        second = self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get()
        self.assertRedirects(first, f"/applies/{run.pk}/", fetch_redirect_response=False)
        self.assertRedirects(second, f"/applies/{run.pk}/", fetch_redirect_response=False)
        self.run_worker()
        self.client.post(f"/plans/{plan.pk}/apply/")
        self.run_worker()
        self.assertEqual(ApplyRun.objects.count(), 1)
        self.assertEqual(len(self.systemd.submissions), 1)

    def test_the_account_and_privilege_are_rechecked_before_submission(self) -> None:
        cases = {
            "revoked": apply.REVOKED_FAILURE,
            "sudo": apply.PRIVILEGE_FAILURE,
            "host key": apply.HOST_KEY_FAILURE,
            "retained": apply.RETAINED_FAILURE,
        }
        for case, failure in cases.items():
            with self.subTest(case=case):
                self.remote.host_key = HOST_KEY
                run = self.request(self.refresh_plan())
                # Each changes after review, before the worker runs.
                self.systemd.sudo_allowed = case != "sudo"
                self.systemd.retained = native.RETAINED_LIMIT if case == "retained" else 0
                if case == "host key":
                    self.remote.host_key = "ssh-ed25519 SHA256:other"
                if case == "revoked":
                    self.user.user_permissions.clear()
                self.run_worker()
                run.refresh_from_db()
                self.assertEqual(run.status, Status.FAILED)
                self.assertEqual(run.failure, failure)
                self.assertEqual(run.execution, Execution.NOT_SUBMITTED)
                self.assertIsNone(run.dispatched_at)
                self.assertFalse(self.systemd.submissions)
        self.remote.host_key = HOST_KEY

    def test_root_submits_without_sudo(self) -> None:
        self.systemd.root = True
        run = self.apply()
        self.assertEqual(run.status, Status.SUCCEEDED)
        self.assertTrue(self.systemd.submissions[0].startswith("/usr/bin/systemd-run "))
        self.assertFalse(any(c.startswith("sudo -n -l") for c in self.remote.commands))

    def test_refusals_on_the_server_stop_before_changes_and_need_a_new_plan(self) -> None:
        refusals = {
            Exit.LOCK_CONFLICT: Execution.LOCK_CONFLICT,
            Exit.UNSAFE_LOCK: Execution.UNSAFE_LOCK,
            Exit.BOOT_CHANGED: Execution.BOOT_CHANGED,
            Exit.EXPIRED: Execution.EXPIRED,
            Exit.OTHER_RUN_ACTIVE: Execution.OTHER_RUN_ACTIVE,
            Exit.DRIFT: Execution.DRIFT,
            Exit.PACKAGE_MANAGER_BUSY: Execution.PACKAGE_MANAGER_BUSY,
            Exit.RENEWAL_ACTIVE: Execution.RENEWAL_ACTIVE,
        }
        for status, execution in refusals.items():
            with self.subTest(execution=execution):
                self.systemd.exit_status = status
                self.systemd.result = "exit-code"
                run = self.apply()
                self.assertEqual(run.status, Status.FAILED)
                self.assertEqual(run.execution, execution)
                self.assertEqual(run.verification, Verification.NOT_APPLICABLE)
                self.assertIn("stopped before changing anything", run.failure)
                page = self.client.get(f"/applies/{run.pk}/")
                self.assertContains(page, "The run stopped before making any requested change.")

    def test_a_refusal_that_exits_during_inspection_is_inspected_again(self) -> None:
        self.systemd.running = 1
        self.systemd.exiting = True
        self.systemd.exit_status = Exit.DRIFT
        self.systemd.result = "exit-code"
        run = self.apply()
        self.assertEqual(run.status, Status.FAILED, run.failure)
        self.assertEqual(run.execution, Execution.DRIFT)
        self.assertEqual(self.systemd.inspections, 2)

    def test_failed_timed_out_and_killed_runs_are_distinguished(self) -> None:
        cases = (
            (Exit.UPDATE_FAILED, "exit-code", 1, Execution.FAILED),
            (15, "timeout", 2, Execution.TIMED_OUT),
            (9, "signal", 2, Execution.KILLED),
            (0, "exit-code", 1, Execution.FAILED),
            (42, "exit-code", 1, Execution.FAILED),
        )
        for status, result, code, execution in cases:
            with self.subTest(result=result, status=status):
                self.systemd.exit_status = status
                self.systemd.result = result
                self.systemd.exec_main_code = code
                run = self.apply()
                self.assertEqual(run.status, Status.FAILED)
                self.assertEqual(run.execution, execution)
                self.assertEqual(run.verification, Verification.NOT_APPLICABLE)

    def test_a_failed_refresh_names_the_expired_publisher_recovery(self) -> None:
        self.systemd.exit_status = Exit.UPDATE_FAILED
        run = self.apply()
        self.assertEqual(run.execution, Execution.FAILED)
        self.assertIn("Release file as expired", run.failure)
        self.assertIn("wait until it does, then prepare another refresh", run.failure)

    def test_a_successful_exit_needs_verified_postconditions(self) -> None:
        self.systemd.dpkg_status_after = "d" * 64
        run = self.apply()
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Execution.SUCCEEDED)
        self.assertEqual(run.verification, Verification.FAILED)
        self.assertEqual(run.failure, apply.VERIFICATION_FAILED)
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Completed successfully")
        self.assertContains(page, "Postconditions do not hold")

    def test_a_rejected_submission_created_nothing(self) -> None:
        self.systemd.reject = True
        run = self.apply()
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Execution.NOT_SUBMITTED)
        self.assertEqual(run.failure, apply.REJECTED_FAILURE)

    def test_an_oversized_payload_is_refused_before_connecting(self) -> None:
        with self.assertRaises(native.PayloadTooLarge):
            native.submission(native.new_unit_name(), "x" * (native.MAX_PAYLOAD + 1))
        with mock.patch.object(native, "MAX_PAYLOAD", 100):
            run = self.apply()
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.failure, apply.TOO_LARGE_FAILURE)
        self.assertFalse(self.systemd.submissions)

    def test_a_successful_refresh_invalidates_earlier_package_plans(self) -> None:
        package_plan = self.plan("nginx")
        self.assertTrue(package_plan.eligible)
        self.systemd.exit_status = Exit.DRIFT
        self.systemd.result = "exit-code"
        self.apply()
        page = self.client.get(f"/plans/{package_plan.pk}/")
        self.assertNotContains(page, "A later package metadata refresh")
        self.systemd.exit_status = 0
        self.systemd.result = "success"
        self.apply()
        page = self.client.get(f"/plans/{package_plan.pk}/")
        self.assertContains(page, "A later package metadata refresh")
        later = self.plan("nginx")
        self.assertNotContains(self.client.get(f"/plans/{later.pk}/"), "A later package metadata")
        # An uncertain refresh may have changed the indexes too.
        self.systemd.lose_acknowledgement = True
        self.assertEqual(self.apply().status, Status.RECONCILING)
        self.assertContains(self.client.get(f"/plans/{later.pk}/"), "A later package metadata")


class ReconciliationTests(ApplyTestCase):
    def test_a_lost_acknowledgement_reconciles_without_submitting_again(self) -> None:
        self.systemd.lose_acknowledgement = True
        run = self.apply()
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertEqual(run.execution, Execution.NOT_SUBMITTED)
        self.assertIsNotNone(run.dispatched_at)
        self.assertIn(apply.LOST_ACKNOWLEDGEMENT, run.failure)
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Outcome being reconciled")
        self.assertContains(page, "Check outcome")
        # The reconciling run keeps the server's active slot, and nothing is replayed.
        self.run_worker()
        self.assertEqual(len(self.systemd.submissions), 1)
        active = lifecycle.active_operation(self.server)
        self.assertEqual(active.pk if active else None, run.pk)
        checked = self.check(run)
        self.assertEqual(checked.status, Status.SUCCEEDED, checked.failure)
        self.assertEqual(checked.execution, Execution.SUCCEEDED)
        self.assertEqual(checked.invocation_id, "0f" * 16)
        self.assertEqual(len(self.systemd.submissions), 1)

    def test_losing_the_connection_after_acknowledgement_reconciles(self) -> None:
        self.systemd.lose_at_inspection = 1
        run = self.apply()
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIsNotNone(run.acknowledged_at)
        self.assertEqual(run.execution, Execution.SUBMITTED)
        checked = self.check(run)
        self.assertEqual(checked.status, Status.SUCCEEDED)
        self.assertEqual(len(self.systemd.submissions), 1)

    def test_a_stopped_worker_leaves_a_dispatched_run_reconciling(self) -> None:
        self.systemd.stop_worker_at_inspection = 1
        run = self.request(self.refresh_plan())
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertEqual(run.failure, apply.UNCERTAIN)
        self.assertEqual(self.check(run).status, Status.SUCCEEDED)

    def test_abandoned_runs_reconcile_if_dispatched_and_fail_otherwise(self) -> None:
        dispatched = self.request(self.refresh_plan())
        record_attempt(dispatched, Status.RUNNING, age=apply.STALE_AFTER * 2)
        RemoteOperation.objects.filter(pk=dispatched.pk).update(dispatched_at=timezone.now())
        self.client.get(f"/servers/{self.server.pk}/advanced/")
        dispatched.refresh_from_db()
        self.assertEqual(dispatched.status, Status.RECONCILING)
        self.assertEqual(dispatched.failure, apply.UNCERTAIN)
        # Reconciling runs are never failed by the stale limit.
        RemoteOperation.objects.filter(pk=dispatched.pk).update(
            started_at=timezone.now() - timedelta(days=30)
        )
        self.client.get(f"/servers/{self.server.pk}/advanced/")
        dispatched.refresh_from_db()
        self.assertEqual(dispatched.status, Status.RECONCILING)
        other = Server.objects.create(name="Other", ssh_alias="stage.example.net")
        undispatched = ApplyRun.objects.create(
            server=other,
            ssh_alias=other.ssh_alias,
            plan_number=999999,
            requested_by_name="operator",
            server_name=other.name,
            action="metadata_refresh",
            intent="",
            profile_revision=1,
            reviewed_host_key=HOST_KEY,
            boot_id=BOOT_ID,
            admission_deadline_centiseconds=1,
            admission_expires_at=timezone.now(),
            effects="",
            unit_name=native.new_unit_name(),
        )
        record_attempt(undispatched, Status.RUNNING, age=apply.STALE_AFTER * 2)
        self.client.get(f"/servers/{self.server.pk}/advanced/")
        undispatched.refresh_from_db()
        self.assertEqual(undispatched.status, Status.FAILED)
        self.assertEqual(undispatched.failure, apply.INTERRUPTED_FAILURE)

    def test_a_run_still_running_after_the_watch_limit_is_checked_later(self) -> None:
        self.systemd.running = 3
        with mock.patch.object(apply, "WATCH_LIMIT", timedelta()):
            run = self.apply()
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertEqual(run.execution, Execution.RUNNING)
        self.assertIn(apply.STILL_RUNNING, run.failure)
        # The page never presents the last inspection as the current state.
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Running when last inspected")
        self.assertNotContains(page, Execution.RUNNING.label)
        run = self.check(run)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIn(apply.STILL_RUNNING, run.failure)
        run = self.check(self.check(run))
        self.assertEqual(run.status, Status.SUCCEEDED)
        self.assertEqual(len(self.systemd.submissions), 1)

    def test_missing_native_evidence_stays_reconciling(self) -> None:
        self.systemd.lose_acknowledgement = True
        run = self.apply()
        self.systemd.units.clear()
        run = self.check(run)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIn(apply.NOT_FOUND, run.failure)
        self.systemd.boot_id = "11111111-2222-3333-4444-555555555555"
        run = self.check(run)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIn(apply.RESTARTED, run.failure)

    def test_a_different_invocation_is_not_attributed_to_the_run(self) -> None:
        self.systemd.lose_at_inspection = 2
        self.systemd.running = 1
        run = self.apply()
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertEqual(run.invocation_id, "0f" * 16)
        for unit in self.systemd.units.values():
            unit.invocation_id = "ab" * 16
        run = self.check(run)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIn(apply.MISMATCH, run.failure)

    def test_a_failed_check_leaves_the_run_reconciling(self) -> None:
        self.systemd.lose_acknowledgement = True
        run = self.apply()
        self.remote.failure = "The connection to web.example.com timed out."
        run = self.check(run)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIn("timed out", run.failure)
        self.remote.failure = ""

    def test_only_reconciling_runs_can_be_checked(self) -> None:
        run = self.apply()
        response = self.client.post(f"/applies/{run.pk}/check/", follow=True)
        self.assertContains(response, "Only a run whose outcome is being reconciled")
        self.assertEqual(self.client.post("/applies/999/check/").status_code, 404)


class ApplyAccessTests(ApplyTestCase):
    def test_applying_needs_its_own_permission_and_csrf(self) -> None:
        plan = self.refresh_plan()
        self.assertNotContains(self.client.get(f"/plans/{plan.pk}/"), "Apply plan")
        self.assertEqual(self.client.post(f"/plans/{plan.pk}/apply/").status_code, 403)
        self.assertEqual(self.client.get(f"/plans/{plan.pk}/apply/").status_code, 405)
        self.sign_in_with(*APPLY_PERMISSIONS)
        csrf = self.client_class(enforce_csrf_checks=True)
        csrf.force_login(self.user)
        self.assertEqual(csrf.post(f"/plans/{plan.pk}/apply/").status_code, 403)
        self.assertFalse(ApplyRun.objects.exists())

    def test_expired_and_refused_plans_are_not_applied(self) -> None:
        plan = self.refresh_plan()
        ConfigurationPlan.objects.filter(pk=plan.pk).update(
            admission_expires_at=timezone.now() - timedelta(seconds=1)
        )
        self.sign_in_with(*APPLY_PERMISSIONS)
        self.assertNotContains(self.client.get(f"/plans/{plan.pk}/"), "Apply plan")
        response = self.client.post(f"/plans/{plan.pk}/apply/", follow=True)
        self.assertContains(response, "admission deadline has passed")
        self.ubuntu.hooks.append(("DPkg::Post-Invoke::", "true"))
        refused = self.plan("metadata_refresh")
        response = self.client.post(f"/plans/{refused.pk}/apply/", follow=True)
        self.assertContains(response, "Only an eligible plan with changes can be applied.")
        self.assertFalse(ApplyRun.objects.exists())

    def test_inventory_access_alone_never_shows_apply_runs(self) -> None:
        run = self.apply()
        self.client.logout()
        self.user.user_permissions.clear()
        self.sign_in_with("view_server")
        self.assertEqual(self.client.get(f"/applies/{run.pk}/").status_code, 403)
        self.assertNotContains(self.client.get("/activity/"), "Apply:")
        self.assertEqual(self.client.post(f"/applies/{run.pk}/check/").status_code, 403)

    def test_removal_keeps_finished_audit_and_waits_for_active_runs(self) -> None:
        self.systemd.lose_acknowledgement = True
        run = self.apply()
        with self.assertRaises(RemovalBlocked):
            remove_server(self.server)
        self.assertEqual(self.check(run).status, Status.SUCCEEDED)
        DiscoveryAttempt.objects.all().delete()
        remove_server(self.server)
        self.assertFalse(Server.objects.exists())
        kept = ApplyRun.objects.get(pk=run.pk)
        self.assertIsNone(kept.server_id)
        self.assertIsNone(kept.plan_id)
        self.assertEqual((kept.server_name, kept.plan_number), ("Web", run.plan_number))
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Web (registration removed)")
        self.assertContains(page, f"Plan {run.plan_number} (no longer recorded)")
        activity = self.client.get("/activity/")
        self.assertContains(activity, "Web (removed)")


class PreparationDigestTests(PreparationTestCase):
    def test_a_configuration_changing_while_read_is_refused(self) -> None:
        digests = iter(("a" * 64, "b" * 64))

        def changing(command: str) -> CommandResult | None:
            if command == native.APT_DIGEST:
                return CommandResult(0, f"{next(digests)}  -\n")
            return None

        self.remote.answers.insert(0, changing)
        plan = self.plan("metadata_refresh")
        self.assertFalse(plan.eligible)
        self.assertIn(
            "The APT configuration changed while Barectl read it.",
            " ".join(plan.refusals.values_list("text", flat=True)),
        )
        self.assertFalse(plan.evidence.filter(kind=PlanEvidence.Kind.APT_REVALIDATION).exists())


class NativeCommandTests(SimpleTestCase):
    """The fixed submission and payload text, stated independently of the adapter."""

    def test_the_submission_uses_the_production_limits_and_no_scope_pty_or_wait(self) -> None:
        unit = native.new_unit_name()
        argv = native.submission(unit, "exit 0")
        self.assertEqual(argv[0], "/usr/bin/systemd-run")
        self.assertEqual(argv[-3:], ["/usr/bin/sh", "-c", "exit 0"])
        for option in (
            f"--unit={unit}",
            "--expand-environment=no",
            "--service-type=exec",
            "--remain-after-exit",
            "--property=ExitType=cgroup",
            "--property=Restart=no",
            "--property=RuntimeMaxSec=30min",
            "--property=TimeoutStopSec=60",
            "--property=KillMode=control-group",
            "--property=StandardInput=null",
            "--property=StandardOutput=journal",
        ):
            self.assertIn(option, argv)
        for forbidden in ("--scope", "--pty", "--pipe", "--wait", "--collect", "-t", "-P", "-G"):
            self.assertNotIn(forbidden, argv)

    def test_parameters_are_validated_before_they_reach_shell_text(self) -> None:
        unit = native.new_unit_name()
        with self.assertRaises(ValueError):
            native.metadata_refresh("x; reboot", BOOT_ID, 1, "a" * 64)
        with self.assertRaises(ValueError):
            native.metadata_refresh(unit, "$(reboot)", 1, "a" * 64)
        with self.assertRaises(ValueError):
            native.metadata_refresh(unit, BOOT_ID, 1, "'; reboot; '")
        with self.assertRaises(ValueError):
            native.inspection("nginx.service")
        payload = native.metadata_refresh(unit, BOOT_ID, 590025, "a" * 64)
        # Every refusal happens under the lock and before apt-get runs.
        lock = payload.index("flock -n 9 || exit 10")
        update = payload.index("apt-get -q --error-on=any update")
        for check in ("exit 12", "exit 13", "exit 14", "exit 25", "exit 15"):
            self.assertLess(lock, payload.index(check))
            self.assertLess(payload.index(check), update)
        self.assertNotIn("&", payload.replace("&&", "").replace(">&", ""))
        self.assertLess(len(payload.encode()), native.MAX_PAYLOAD)

    def test_inspection_output_is_read_strictly(self) -> None:
        unit = native.new_unit_name()
        good = (
            f"{BOOT_ID}\nId={unit}\nLoadState=loaded\nActiveState=active\nSubState=exited\n"
            f"Result=success\nExecMainCode=1\nExecMainStatus=0\nInvocationID={'a' * 32}\n"
            "populated 0\n"
        )
        evidence = native.parse_inspection(good, unit)
        self.assertEqual(evidence.execution, Execution.SUCCEEDED)
        # Result=success with processes left in the control group is not success.
        running = native.parse_inspection(good.replace("populated 0", "populated 1"), unit)
        self.assertEqual(running.execution, Execution.RUNNING)
        for bad in (
            good.replace(f"Id={unit}", "Id=other.service"),
            good.replace("populated 0\n", ""),
            good.replace("ExecMainStatus=0", "ExecMainStatus=zero"),
            good.replace(BOOT_ID, "not-a-boot"),
            good + "Extra=1\n",
        ):
            with self.subTest(bad=bad), self.assertRaises(native.Unreadable):
                native.parse_inspection(bad, unit)


class _LocalShell:
    """Runs inspection's shell text with /bin/sh; ``paths`` maps the server paths it reads."""

    host_key = HOST_KEY

    def __init__(self, paths: dict[str, str], bin_directory: Path) -> None:
        self.paths = paths
        self.environment = {"PATH": f"{bin_directory}:{os.environ['PATH']}"}

    def run(self, command: str) -> CommandResult:
        for server, local in self.paths.items():
            command = command.replace(server, local)
        completed = subprocess.run(  # noqa: S603 - the test's own script
            ["/bin/sh", "-c", command],
            capture_output=True,
            text=True,
            env=self.environment,
            check=False,
        )
        return CommandResult(completed.returncode, completed.stdout)


class InspectionShellTests(SimpleTestCase):
    """Inspection's shell text under /bin/sh, with systemctl and the unit's control group
    simulated; bootstrap/test_package_remote.py runs it against real systemd."""

    @override
    def setUp(self) -> None:
        self.unit = native.new_unit_name()
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.root / "boot_id").write_text(f"{BOOT_ID}\n")
        group = self.root / "cgroup" / "system.slice" / self.unit
        group.mkdir(parents=True)
        self.events = group / "cgroup.events"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.command("systemctl", self.systemctl())

    def systemctl(self) -> str:
        return (
            'case "$*" in *ControlGroup*) '
            f"echo /system.slice/{self.unit};; *) printf '%s\\n' "
            f"Id={self.unit} LoadState=loaded ActiveState=active SubState=running "
            "Result=success ExecMainCode=0 ExecMainStatus=0 "
            f"InvocationID={'a' * 32};; esac"
        )

    def command(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)

    def inspect(self) -> native.UnitEvidence:
        shell = _LocalShell(
            {
                "/proc/sys/kernel/random/boot_id": str(self.root / "boot_id"),
                "/sys/fs/cgroup": str(self.root / "cgroup"),
            },
            self.bin,
        )
        return native.inspect(shell, self.unit)

    def test_a_populated_control_group_is_read(self) -> None:
        self.events.write_text("populated 1\nfrozen 0\n")
        evidence = self.inspect()
        self.assertTrue(evidence.populated)
        self.assertEqual(evidence.execution, Execution.RUNNING)

    def test_a_control_group_removed_while_it_is_read_has_no_processes(self) -> None:
        self.events.write_text("populated 1\nfrozen 0\n")
        grep = shutil.which("grep")
        if grep is None:
            self.fail("grep is not installed.")
        # The unit exits after its properties were read: systemd removes its control group
        # between the readability test and the read.
        self.command("grep", f'rm -f "{self.events}"; exec {grep} "$@"')
        evidence = self.inspect()
        self.assertFalse(evidence.populated)
        # Its properties still read running, so the watch inspects it again.
        self.assertEqual(evidence.execution, Execution.RUNNING)

    def test_a_control_group_without_its_populated_line_is_unreadable(self) -> None:
        self.events.write_text("frozen 0\n")
        with self.assertRaises(native.Unreadable):
            self.inspect()


class CheckRevisionTests(ApplyTestCase):
    def test_check_outcome_inspects_within_the_run_and_queues_nothing_else(self) -> None:
        self.systemd.lose_acknowledgement = True
        run = self.apply()
        self.assertEqual(run.status, Status.RECONCILING)
        self.client.post(f"/applies/{run.pk}/check/")
        pending = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(pending, "Check queued.")
        self.assertContains(pending, f'hx-get="/applies/{run.pk}/status/')
        active = lifecycle.active_operation(self.server)
        self.assertEqual(active.pk if active else None, run.pk)
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual(run.status, Status.SUCCEEDED)
        self.assertIsNone(run.check_requested_at)
        self.assertEqual(run.revision, 1)
        self.assertFalse(DiscoveryAttempt.objects.exists())
        self.assertEqual(RemoteOperation.objects.count(), 2)

    def test_an_older_check_never_overwrites_a_newer_one(self) -> None:
        self.systemd.lose_acknowledgement = True
        self.systemd.running = 5
        run = self.apply()
        # An older check started first, at the next revision, and is still inspecting.
        RemoteOperation.objects.filter(pk=run.pk).update(revision=F("revision") + 1)
        older = ApplyRun.objects.get(pk=run.pk)
        # A newer check starts and finishes meanwhile: the unit is still running.
        run = self.check(run)
        self.assertEqual(run.revision, older.revision + 1)
        self.assertIn(apply.STILL_RUNNING, run.failure)
        self.assertEqual(run.execution, Execution.RUNNING)
        # The older check now sees the finished unit; nothing it found is recorded.
        for unit in self.systemd.units.values():
            unit.running = 0
        apply._check(older)
        run.refresh_from_db()
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIn(apply.STILL_RUNNING, run.failure)
        self.assertEqual(run.execution, Execution.RUNNING)
        # A new check establishes the outcome.
        self.assertEqual(self.check(run).status, Status.SUCCEEDED)

    def test_a_stale_worker_cannot_record_after_recovery(self) -> None:
        self.systemd.running = 50
        with mock.patch.object(apply, "WATCH_LIMIT", timedelta()):
            run = self.apply()
        self.assertEqual(run.status, Status.RECONCILING)
        # The original worker's view of the run, still running, records nothing now.
        self.assertFalse(apply._record(run.pk, Status.RUNNING, execution=Execution.SUCCEEDED))
        run.refresh_from_db()
        self.assertEqual(run.execution, Execution.RUNNING)

    def test_verification_unavailable_keeps_the_native_outcome(self) -> None:
        # The run finished on the server; the controller then loses the connection while
        # verifying. The execution outcome stays; the run fails as verification unavailable.
        def lose_verification(command: str) -> CommandResult | None:
            if command == native.DPKG_STATUS_DIGEST and self.systemd.submissions:
                raise ConnectionFailed("The connection to web.example.com ended.")
            return None

        # The server has a snapshot from before the run, which stays as it was.
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.client.post(f"/servers/{self.server.pk}/verify/")
        self.run_worker()
        self.remote.answers.insert(0, lose_verification)
        run = self.apply()
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Execution.SUCCEEDED)
        self.assertEqual(run.verification, Verification.UNAVAILABLE)
        self.assertEqual(run.failure, apply.VERIFICATION_UNAVAILABLE)
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Completed successfully")
        self.assertContains(page, "Could not be checked")
        self.assertContains(page, "does not show its effects")
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)

    def test_a_controller_error_while_checking_is_not_a_remote_failure(self) -> None:
        self.systemd.lose_acknowledgement = True
        run = self.apply()
        with mock.patch.object(native, "inspect", side_effect=RuntimeError("remote text")):
            run = self.check(run)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIn(apply.UNEXPECTED_FAILURE, run.failure)
        self.assertNotIn("remote text", run.failure)
        self.assertEqual(self.check(run).status, Status.SUCCEEDED)


class OutcomeUnknownTests(ApplyTestCase):
    def lost(self) -> ApplyRun:
        """A run whose submission's answer was lost and whose unit is gone."""
        self.systemd.lose_acknowledgement = True
        run = self.apply()
        self.systemd.lose_acknowledgement = False
        self.systemd.units.clear()
        run = self.check(run)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertEqual(run.execution, Execution.NOT_FOUND)
        return run

    def acknowledge(self, run: ApplyRun, *, understood: bool = True) -> ApplyRun:
        data = {"understood": "on"} if understood else {}
        self.client.post(f"/applies/{run.pk}/acknowledge/", data)
        self.run_worker()
        return ApplyRun.objects.get(pk=run.pk)

    def past_deadline(self, run: ApplyRun) -> None:
        self.systemd.uptime_centiseconds = run.admission_deadline_centiseconds

    def test_missing_evidence_is_shown_as_outcome_unknown_and_stays_reconciling(self) -> None:
        run = self.lost()
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Outcome unknown so far.")
        self.assertContains(page, "Close as outcome unknown")
        self.assertContains(page, "never as unchanged")
        # Checking again, however often, never closes it without an acknowledgement.
        self.past_deadline(run)
        for _ in range(2):
            run = self.check(run)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertEqual(self.systemd.probes, 0)
        self.assertEqual(len(self.systemd.submissions), 1)

    def test_closing_needs_the_apply_permission_and_an_explicit_acknowledgement(self) -> None:
        run = self.lost()
        self.past_deadline(run)
        self.client.logout()
        self.user.user_permissions.clear()
        self.sign_in_with("view_server", "view_configurationplan")
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Check outcome")
        self.assertNotContains(page, "Close as outcome unknown")
        self.assertEqual(self.client.post(f"/applies/{run.pk}/acknowledge/").status_code, 403)
        self.sign_in_with(*APPLY_PERMISSIONS)
        csrf = self.client_class(enforce_csrf_checks=True)
        csrf.force_login(self.user)
        self.assertEqual(
            csrf.post(f"/applies/{run.pk}/acknowledge/", {"understood": "on"}).status_code, 403
        )
        response = self.client.post(f"/applies/{run.pk}/acknowledge/", follow=True)
        self.assertContains(response, "Confirm that you understand the outcome is unknown.")
        run.refresh_from_db()
        self.assertIsNone(run.unknown_acknowledged_at)
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertEqual(self.systemd.probes, 0)

    def test_every_missing_proof_keeps_the_run_reconciling(self) -> None:
        run = self.lost()
        # Same boot, deadline not passed on the server's clock.
        self.systemd.uptime_centiseconds = run.admission_deadline_centiseconds - 1
        run = self.acknowledge(run)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIn("admission deadline has not passed", run.closure_blocked)
        self.assertIsNone(run.closure_requested_at)
        self.assertEqual(run.unknown_acknowledged_by_name, "operator")
        self.assertContains(self.client.get(f"/applies/{run.pk}/"), "Not closed.")
        self.past_deadline(run)
        # The acknowledgement was used; a later check does not close the run by itself.
        run = self.check(run)
        self.assertEqual(run.status, Status.RECONCILING)
        cases = {
            "lock held": apply.CLOSURE_LOCK_HELD,
            "unsafe lock": apply.CLOSURE_UNSAFE_LOCK,
            "active": apply.CLOSURE_ACTIVE,
            "renewal": apply.CLOSURE_RENEWAL_ACTIVE,
            "no sudo": apply.CLOSURE_PRIVILEGE,
            "revoked": apply.CLOSURE_ACCOUNT,
        }
        for case, reason in cases.items():
            with self.subTest(case=case):
                self.systemd.probe_exit = {"lock held": 10, "unsafe lock": 11}.get(case, 0)
                self.systemd.probe_populated = 1 if case == "active" else 0
                self.systemd.probe_renewal = case == "renewal"
                self.systemd.sudo_allowed = case != "no sudo"
                self.client.post(f"/applies/{run.pk}/acknowledge/", {"understood": "on"})
                if case == "revoked":
                    self.user.user_permissions.remove(
                        Permission.objects.get(codename="apply_configurationplan")
                    )
                self.run_worker()
                run.refresh_from_db()
                self.assertEqual(run.status, Status.RECONCILING)
                self.assertEqual(run.closure_blocked, reason)
                self.assertEqual(run.execution, Execution.NOT_FOUND)
        self.assertEqual(len(self.systemd.submissions), 1)

    def test_an_expired_deadline_with_the_lock_taken_closes_as_outcome_unknown(self) -> None:
        package_plan = self.plan("nginx")
        run = self.lost()
        self.past_deadline(run)
        run = self.acknowledge(run)
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Execution.OUTCOME_UNKNOWN)
        self.assertEqual(run.verification, Verification.UNAVAILABLE)
        self.assertEqual(run.failure, apply.OUTCOME_UNKNOWN)
        self.assertEqual(self.systemd.probes, 1)
        # The probe ran with sudo, after sudo -n -l authorized exactly it.
        probe = next(c for c in self.remote.commands if c.startswith("sudo -n /usr/bin/sh -c"))
        self.assertIn(probe.replace("sudo -n ", "sudo -n -l ", 1), self.remote.commands)
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Outcome unknown: this run may have changed the server")
        self.assertContains(page, "Acknowledged by operator")
        self.assertNotContains(page, "nothing changed")
        self.assertContains(self.client.get("/activity/"), "Outcome unknown")
        # It may have changed the indexes, so earlier package plans are invalidated.
        self.assertContains(
            self.client.get(f"/plans/{package_plan.pk}/"), "A later package metadata refresh"
        )
        # The server's slot is free again, and nothing was ever submitted twice.
        self.assertIsNone(lifecycle.active_operation(self.server))
        self.assertEqual(len(self.systemd.submissions), 1)

    def test_a_changed_boot_with_the_lock_taken_closes_as_outcome_unknown(self) -> None:
        run = self.lost()
        self.systemd.boot_id = "11111111-2222-4333-8444-555555555555"
        self.systemd.uptime_centiseconds = 100
        run = self.check(run)
        self.assertIn(apply.RESTARTED, run.failure)
        run = self.acknowledge(run)
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Execution.OUTCOME_UNKNOWN)

    def test_only_a_run_without_native_evidence_can_be_acknowledged(self) -> None:
        self.systemd.lose_acknowledgement = True
        run = self.apply()
        response = self.client.post(
            f"/applies/{run.pk}/acknowledge/", {"understood": "on"}, follow=True
        )
        self.assertContains(response, "whose latest check found no native record")
        run.refresh_from_db()
        self.assertIsNone(run.unknown_acknowledged_at)
        self.assertEqual(self.client.post("/applies/999/acknowledge/").status_code, 404)


class RegistrationBoundaryTests(ApplyTestCase):
    def test_a_reconciling_run_keeps_its_registration_and_alias(self) -> None:
        self.systemd.lose_acknowledgement = True
        run = self.apply()
        self.assertEqual(run.status, Status.RECONCILING)
        self.sign_in_with("change_server")
        self.client.post(
            f"/servers/{self.server.pk}/edit/", {"name": "Web", "ssh_alias": "stage.example.net"}
        )
        self.server.refresh_from_db()
        self.assertEqual(self.server.ssh_alias, "web.example.com")
        with self.assertRaises(RemovalBlocked):
            remove_server(self.server)
        # Checking still connects with the alias the run was submitted with.
        self.remote.targets.clear()
        self.assertEqual(self.check(run).status, Status.SUCCEEDED)
        self.assertEqual({target.alias for target in self.remote.targets}, {"web.example.com"})
