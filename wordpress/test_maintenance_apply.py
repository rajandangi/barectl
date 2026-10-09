"""Applying a reviewed WordPress maintenance action through requests and the worker
(docs/wordpress.md#maintaining-wordpress), against a simulated server.

Real views, services, the lifecycle, the ``db_worker`` command, persistence and rendering run;
only remote execution is substituted. The native effects are qualified by
``test_maintenance_remote``.
"""

import shlex
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission

from bootstrap import apply as bootstrap_apply
from bootstrap import native as bootstrap_native
from bootstrap.fakes import NativeSystemd
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, Verification
from bootstrap.plan_testing import kept_text
from discovery import ssh
from operations.models import RemoteOperation
from servers.models import Server
from servers.registration import RemovalBlocked, remove_server
from servers.testing import HTMX_FRAGMENT

from . import execution, inspection, maintenance_apply, maintenance_fakes, maintenance_native
from .install_apply_testing import staged_body
from .maintenance_models import (
    MaintenanceResult,
    Operation,
    PlanWordpressMaintenance,
    RunWordpressMaintenance,
)
from .maintenance_testing import MAINTAIN_VIEW, RUN, MaintenanceTestCase

Status = RemoteOperation.Status
Exit = execution.Exit
MARKER = f"{execution.RECORD_MARKER} "


class ApplyTestCase(MaintenanceTestCase):
    systemd: NativeSystemd

    @override
    def setUp(self) -> None:
        super().setUp()
        self.systemd = NativeSystemd()
        self.enterContext(mock.patch.object(bootstrap_apply, "POLL_INTERVAL", 0))

    @override
    def assert_read_only(self) -> None:
        """Apply runs execute application code; each is submitted once."""

    def apply(
        self,
        operation: str = Operation.REWRITE,
        *,
        plan: ConfigurationPlan | None = None,
        perms: tuple[str, ...] = RUN,
    ) -> ApplyRun:
        plan = plan or self.maintained(operation)
        self.sign_in_as(*perms)
        self.systemd.answer(self.remote)
        self.application.answer(self.remote)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.run_worker()
        run.refresh_from_db()
        return run

    def again(self) -> None:
        ApplyRun.objects.all().delete()
        self.systemd.units.clear()
        self.systemd.submissions.clear()
        self.record_php_snapshot()


class RequestTests(ApplyTestCase):
    def test_only_a_maintainer_is_offered_the_apply(self) -> None:
        plan = self.maintained()
        self.sign_in_as(*MAINTAIN_VIEW)
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertNotContains(page, f"/plans/{plan.pk}/apply/")
        self.assertNotContains(page, "Barectl does not apply this kind of plan yet")
        self.sign_in_as(*RUN)
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, f"/plans/{plan.pk}/apply/")
        self.assertContains(page, "never submitted twice")

    def test_other_authority_grants_no_maintenance(self) -> None:
        plan = self.maintained()
        for perms in (
            (*MAINTAIN_VIEW, "prepare_wordpressplan", "inspect_wordpress"),
            (*MAINTAIN_VIEW, "prepare_wordpressplan", "install_wordpress"),
            (*MAINTAIN_VIEW, "apply_configurationplan", "apply_siteplan", "apply_databaseplan"),
            ("view_server", "view_configurationplan", "apply_configurationplan"),
        ):
            with self.subTest(perms):
                self.sign_in_as(*perms)
                self.assertEqual(self.client.post(f"/plans/{plan.pk}/apply/").status_code, 403)
                self.assertFalse(ApplyRun.objects.exists())

    def test_the_maintenance_permission_grants_no_inspection_or_other_apply(self) -> None:
        inspection_plan = self.inspected()
        self.sign_in_as(*RUN)
        self.assertEqual(self.client.post(f"/plans/{inspection_plan.pk}/apply/").status_code, 403)
        self.assertFalse(ApplyRun.objects.exists())

    def test_the_account_is_rechecked_when_the_worker_dispatches(self) -> None:
        plan = self.maintained()
        self.sign_in_as(*RUN)
        self.systemd.answer(self.remote)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.user.user_permissions.remove(Permission.objects.get(codename="maintain_wordpress"))
        self.remote.targets.clear()
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.failure, bootstrap_apply.REVOKED_FAILURE)
        self.assertEqual(self.systemd.submissions, [])
        self.assertEqual(self.remote.targets, [])

    def test_a_deactivated_account_is_not_dispatched(self) -> None:
        plan = self.maintained()
        self.sign_in_as(*RUN)
        self.client.post(f"/plans/{plan.pk}/apply/")
        self.user.is_active = False
        self.user.save()
        self.remote.targets.clear()
        self.run_worker()
        self.assertEqual(self.systemd.submissions, [])

    def test_polling_checking_and_acknowledging_need_the_maintenance_view_authority(self) -> None:
        run = self.apply()
        self.sign_in_as("view_server", "view_configurationplan", "apply_configurationplan")
        self.assertEqual(self.client.get(f"/applies/{run.pk}/").status_code, 403)
        self.assertEqual(
            self.client.get(f"/applies/{run.pk}/status/", headers=HTMX_FRAGMENT).status_code, 403
        )
        self.assertEqual(self.client.post(f"/applies/{run.pk}/check/").status_code, 403)
        self.assertEqual(
            self.client.post(f"/applies/{run.pk}/acknowledge/", {"understood": "on"}).status_code,
            403,
        )
        self.sign_in_as(*MAINTAIN_VIEW)
        self.assertEqual(self.client.get(f"/applies/{run.pk}/").status_code, 200)
        self.assertEqual(
            self.client.get(f"/applies/{run.pk}/status/", headers=HTMX_FRAGMENT).status_code, 200
        )

    def test_the_result_needs_the_view_authority_on_every_surface(self) -> None:
        run = self.apply()
        self.sign_in_as("view_server", "view_siteobservation")
        poll = f"/servers/{self.server.pk}/sites/shop/wordpress/maintenance/"
        self.assertEqual(self.client.get(poll, headers=HTMX_FRAGMENT).status_code, 403)
        self.assertEqual(self.client.get(f"/applies/{run.pk}/").status_code, 403)


class PayloadTests(ApplyTestCase):
    def test_the_submission_carries_the_reviewed_body_under_native_limits(self) -> None:
        plan = self.maintained(Operation.CACHE)
        run = self.apply(plan=plan)
        self.assertEqual(len(self.systemd.submissions), 1, run.failure)
        submission = self.systemd.submissions[0]
        review = PlanWordpressMaintenance.objects.get(plan=plan)
        body = staged_body(submission)
        self.assertEqual(inspection.digest(body), review.body_sha256)
        for limit in (
            f"--property=LimitFSIZE={maintenance_native.MAX_FILE_BYTES}",
            f"--property=MemoryMax={maintenance_native.MEMORY_MAX_BYTES}",
            "--property=MemorySwapMax=0",
        ):
            self.assertIn(limit, submission)
        self.assertIn("W flush cache flush", body)
        self.assertEqual(review.payload_bytes, len(shlex.split(submission)[-1].encode()))
        self.assertLess(review.payload_bytes or 0, bootstrap_native.MAX_PAYLOAD)

    def test_each_action_runs_only_its_fixed_command(self) -> None:
        for operation in Operation:
            with self.subTest(operation):
                self.again()
                run = self.apply(operation)
                body = staged_body(self.systemd.submissions[0])
                self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
                command = maintenance_native.COMMANDS[operation]
                self.assertIn(f"W flush {command};", body)
                other = maintenance_native.COMMANDS[
                    Operation.CACHE if operation == Operation.REWRITE else Operation.REWRITE
                ]
                self.assertNotIn(f"W flush {other}", body)
                for forbidden in ("--hard", "--allow-root", "wp eval", "db query", "--ssh"):
                    self.assertNotIn(forbidden, body)
                self.assertEqual(
                    "--skip-plugins" in body, not maintenance_native.LOADS_EXTENSIONS[operation]
                )

    def test_a_changed_pin_refuses_before_anything_is_sent(self) -> None:
        plan = self.maintained()
        with mock.patch.object(maintenance_native, "COMMAND_SECONDS", 90):
            run = self.apply(plan=plan)
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.failure, maintenance_apply.EVIDENCE_FAILURE)
        self.assertEqual(self.systemd.submissions, [])

    def test_an_unqualified_core_is_never_sent(self) -> None:
        plan = self.maintained()
        PlanWordpressMaintenance.objects.filter(plan=plan).update(core_qualified=False)
        run = self.apply(plan=plan)
        self.assertEqual(run.failure, maintenance_apply.EVIDENCE_FAILURE)
        self.assertEqual(self.systemd.submissions, [])

    def test_a_payload_that_differs_from_its_review_is_never_sent(self) -> None:
        plan = self.maintained()
        PlanWordpressMaintenance.objects.filter(plan=plan).update(body_sha256="1" * 64)
        run = self.apply(plan=plan)
        self.assertEqual(run.failure, maintenance_apply.EVIDENCE_FAILURE)
        self.assertEqual(self.systemd.submissions, [])

    def test_missing_evidence_refuses_before_anything_is_sent(self) -> None:
        plan = self.maintained()
        plan.evidence.filter(kind="wordpress_state").delete()
        run = self.apply(plan=plan)
        self.assertEqual(run.failure, maintenance_apply.EVIDENCE_FAILURE)
        self.assertEqual(self.systemd.submissions, [])

    def test_a_non_root_user_needs_sudo_to_authorize_the_result_read(self) -> None:
        self.systemd.sudo_allowed = False
        run = self.apply()
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(self.systemd.submissions, [])


class ResultTests(ApplyTestCase):
    def test_a_rewrite_flush_is_retrieved_stored_and_rendered_with_its_time(self) -> None:
        run = self.apply(Operation.REWRITE)
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        result = MaintenanceResult.objects.get(run=run)
        self.assertEqual((result.state, result.rules), ("available", "stored"))
        self.assertIsNotNone(result.reported_at)
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Result: Flush rewrite rules")
        self.assertContains(page, "The rewrite rules were flushed and stored again.")
        self.assertContains(page, "(server clock)")
        self.assertContains(page, "Nginx and <code>.htaccess</code> were not touched")
        self.record_php_snapshot()
        site = self.client.get(f"/servers/{self.server.pk}/sites/shop/wordpress/")
        self.assertContains(site, "Latest maintenance result")

    def test_the_result_needs_the_application_permission_at_every_place_it_is_shown(self) -> None:
        run = self.apply(Operation.REWRITE)
        self.record_php_snapshot()
        site = f"/servers/{self.server.pk}/sites/shop/wordpress/"
        poll = f"{site}maintenance/"
        targets: tuple[tuple[str, dict[str, str]], ...] = (
            (f"/applies/{run.pk}/", {}),
            (f"/applies/{run.pk}/status/", HTMX_FRAGMENT),
            (site, {}),
            (poll, HTMX_FRAGMENT),
        )
        self.sign_in_as(*RUN)
        for url, headers in targets:
            self.assertContains(self.client.get(url, headers=headers), "were flushed and stored")
        self.sign_in_as(*(code for code in RUN if code != "view_siteapplicationobservation"))
        for url, headers in targets:
            page = self.client.get(url, headers=headers)
            self.assertEqual(page.status_code, 200, url)
            self.assertNotContains(page, "were flushed and stored")
            self.assertNotContains(page, "Result: Flush rewrite rules")

    def test_plain_permalinks_store_no_rules_and_the_result_says_so(self) -> None:
        self.application.records[Operation.REWRITE] = maintenance_fakes.project(
            Operation.REWRITE, maintenance_fakes.REWRITE_EMPTY
        )
        run = self.apply(Operation.REWRITE)
        self.assertEqual(MaintenanceResult.objects.get(run=run).rules, "empty")
        self.assertContains(
            self.client.get(f"/applies/{run.pk}/"), "WordPress stores no rewrite rules"
        )

    def test_a_cache_flush_never_claims_to_clear_the_live_site(self) -> None:
        run = self.apply(Operation.CACHE)
        self.assertEqual((run.status, run.verification), (Status.SUCCEEDED, Verification.PASSED))
        result = MaintenanceResult.objects.get(run=run)
        self.assertEqual((result.state, result.rules), ("available", ""))
        page = self.client.get(f"/applies/{run.pk}/").content.decode()
        self.assertIn("cleared only its own command-line process", page)
        self.assertIn("is not a live-site cache repair", page)
        for claim in ("cache was cleared", "site cache is cleared", "pages are fresh"):
            self.assertNotIn(claim, page)

    def test_hostile_output_never_reaches_the_record_the_database_or_a_page(self) -> None:
        noise = "debug: secret=hunter2"
        self.application.records[Operation.CACHE] = maintenance_fakes.project(
            Operation.CACHE,
            (0, noise + "\n" + maintenance_fakes.CACHE_OK[1], noise),
        )
        plan = self.maintained(Operation.CACHE)
        run = self.apply(plan=plan)
        result = MaintenanceResult.objects.get(run=run)
        self.assertEqual((result.state, result.why), ("unavailable", "output"))
        self.assertEqual(run.status, Status.SUCCEEDED)
        surfaces = [
            kept_text(plan),
            self.client.get(f"/applies/{run.pk}/").content.decode(),
            self.client.get(f"/servers/{self.server.pk}/sites/shop/wordpress/").content.decode(),
        ]
        self.assertFalse(any("hunter2" in text for text in surfaces))
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Result unavailable")
        self.assertContains(page, "does not run it again")

    def test_a_record_outside_the_grammar_is_stored_as_invalid_not_trusted(self) -> None:
        good = maintenance_fakes.default_record(Operation.REWRITE)
        for record in (
            good.replace('"rules":"stored"', '"rules":"yes"'),
            good + " ",
            MARKER + '{"v":1,"op":"rewrite","state":"ok","at":1791513935}',
            MARKER + "x" * 20000,
        ):
            with self.subTest(record[:60]):
                self.again()
                self.application.records[Operation.REWRITE] = record
                run = self.apply(Operation.REWRITE)
                result = MaintenanceResult.objects.get(run=run)
                self.assertEqual((result.state, result.why), ("unavailable", "invalid"))
                self.assertEqual(run.status, Status.SUCCEEDED)

    def test_a_missing_or_rotated_journal_is_result_unavailable_not_a_failed_run(self) -> None:
        for journal, why in (
            ("empty", "journal_missing"),
            ("error", "journal_unreadable"),
            ("duplicate", "extra"),
        ):
            with self.subTest(journal):
                self.again()
                self.application.journal = journal
                run = self.apply(Operation.REWRITE)
                result = MaintenanceResult.objects.get(run=run)
                self.assertEqual((result.state, result.why), ("unavailable", why))
                self.assertEqual(
                    (run.status, run.execution, run.verification),
                    (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
                    run.failure,
                )
                page = self.client.get(f"/applies/{run.pk}/")
                self.assertContains(page, "Result unavailable")
                self.assertContains(page, "execution outcome above comes from systemd")

    def test_a_staging_directory_left_behind_fails_verification_but_keeps_the_result(self) -> None:
        self.application.residue = True
        run = self.apply()
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.FAILED, Execution.SUCCEEDED, Verification.FAILED),
        )
        self.assertIn("safe to remove", run.failure)
        self.assertEqual(MaintenanceResult.objects.get(run=run).state, "available")

    def test_an_unreadable_retrieval_keeps_the_execution_outcome(self) -> None:
        for failing, garbled in (({"journal"}, False), (set(), True)):
            with self.subTest(failing=failing, garbled=garbled):
                self.again()
                self.application.failing = failing
                self.application.garbled = garbled
                run = self.apply()
                self.assertEqual(
                    (run.status, run.execution, run.verification),
                    (Status.FAILED, Execution.SUCCEEDED, Verification.UNAVAILABLE),
                )
                self.assertFalse(MaintenanceResult.objects.filter(run=run).exists())
                self.assertContains(self.client.get(f"/applies/{run.pk}/"), "was not retrieved")

    def test_the_result_is_written_once(self) -> None:
        run = self.apply()
        first = MaintenanceResult.objects.get(run=run)
        self.application.records[Operation.REWRITE] = maintenance_fakes.project(
            Operation.REWRITE, maintenance_fakes.REWRITE_EMPTY
        )
        with ssh.connect_alias(run.ssh_alias) as shell:
            self.assertEqual(maintenance_apply.verify(shell, run), Verification.PASSED)
        self.assertEqual(MaintenanceResult.objects.get(run=run).pk, first.pk)
        self.assertEqual(MaintenanceResult.objects.filter(run=run).count(), 1)


class OutcomeTests(ApplyTestCase):
    def test_each_exit_status_names_its_boundary(self) -> None:
        cases = {
            Exit.TOOLS: (Execution.MAINTENANCE_REFUSED, "lacks a native tool"),
            Exit.STAGING: (Execution.MAINTENANCE_REFUSED, "staging area"),
            Exit.PROJECTION: (Execution.FAILED, "Whether the command took effect is unknown"),
            maintenance_native.Exit.COMMAND: (Execution.FAILED, "did not complete"),
            Exit.DRIFT: (Execution.DRIFT, "changed after review"),
            bootstrap_native.Exit.LOCK_CONFLICT: (Execution.LOCK_CONFLICT, "mutation lock"),
            bootstrap_native.Exit.UNSAFE_LOCK: (Execution.UNSAFE_LOCK, "lock directory"),
            bootstrap_native.Exit.BOOT_CHANGED: (Execution.BOOT_CHANGED, "server restarted"),
            bootstrap_native.Exit.EXPIRED: (Execution.EXPIRED, "admission deadline"),
            bootstrap_native.Exit.OTHER_RUN_ACTIVE: (Execution.OTHER_RUN_ACTIVE, "still had"),
            bootstrap_native.Exit.RENEWAL_ACTIVE: (Execution.RENEWAL_ACTIVE, "renewal"),
            bootstrap_native.Exit.CAPACITY: (Execution.CAPACITY, "too many finished runs"),
            143: (Execution.FAILED, "did not complete"),
        }
        for status, (outcome, text) in cases.items():
            with self.subTest(status=status):
                self.again()
                self.systemd.exit_status = status
                self.systemd.result = "exit-code"
                run = self.apply()
                self.assertEqual(
                    (run.status, run.execution, run.exit_status, run.verification),
                    (Status.FAILED, outcome, status, Verification.NOT_APPLICABLE),
                    run.failure,
                )
                self.assertIn(text, run.failure)
                self.assertFalse(MaintenanceResult.objects.filter(run=run).exists())
                self.assertNotContains(self.client.get(f"/applies/{run.pk}/"), "Result unavailable")

    def test_a_refusal_ran_no_application_code(self) -> None:
        self.systemd.exit_status = Exit.DRIFT
        self.systemd.result = "exit-code"
        run = self.apply()
        self.assertContains(
            self.client.get(f"/applies/{run.pk}/"), "stopped before making any requested change"
        )
        self.assertIn("before running any application code", run.failure)

    def test_an_uncertain_outcome_is_never_run_again_on_its_own(self) -> None:
        self.systemd.exit_status = Exit.PROJECTION
        self.systemd.result = "exit-code"
        run = self.apply()
        self.assertEqual(len(self.systemd.submissions), 1)
        self.run_worker()
        self.assertEqual(len(self.systemd.submissions), 1)
        self.assertIn("Barectl does not run it again", run.failure)

    def test_a_timeout_and_a_kill_say_application_code_ran(self) -> None:
        self.systemd.result = "timeout"
        self.systemd.exit_status = 0
        run = self.apply()
        self.assertEqual(run.execution, Execution.TIMED_OUT)
        self.assertIn("ran application code and published no result", run.failure)
        self.assertIn("unknown", run.failure)

    def test_the_finished_audit_survives_the_servers_removal(self) -> None:
        run = self.apply()
        remove_server(self.server)
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Run WP-CLI 2.12.0 as sshop")
        self.assertContains(page, "rewrite flush")
        self.assertTrue(RunWordpressMaintenance.objects.filter(run=run).exists())
        self.assertTrue(MaintenanceResult.objects.filter(run=run).exists())

    def test_an_active_maintenance_protects_the_server_from_removal(self) -> None:
        plan = self.maintained()
        self.sign_in_as(*RUN)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.assertEqual(run.status, Status.QUEUED)
        with self.assertRaises(RemovalBlocked):
            remove_server(self.server)
        self.assertTrue(Server.objects.filter(pk=self.server.pk).exists())

    def test_the_activity_lists_the_run_under_its_site(self) -> None:
        run = self.apply()
        self.sign_in_as(*MAINTAIN_VIEW)
        page = self.client.get(f"/servers/{self.server.pk}/sites/shop/activity/")
        self.assertContains(page, f"/applies/{run.pk}/")


class ReconciliationTests(ApplyTestCase):
    def test_a_lost_acknowledgement_is_checked_without_running_again(self) -> None:
        self.systemd.lose_acknowledgement = True
        run = self.apply()
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertEqual(len(self.systemd.submissions), 1)
        self.systemd.lose_acknowledgement = False
        self.sign_in_as(*RUN)
        self.assertEqual(self.client.post(f"/applies/{run.pk}/check/").status_code, 302)
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        self.assertEqual(len(self.systemd.submissions), 1)
        self.assertEqual(MaintenanceResult.objects.get(run=run).state, "available")

    def test_the_check_retrieves_by_the_recorded_invocation(self) -> None:
        self.systemd.lose_acknowledgement = True
        run = self.apply()
        self.systemd.lose_acknowledgement = False
        self.sign_in_as(*RUN)
        self.client.post(f"/applies/{run.pk}/check/")
        self.run_worker()
        retrievals = [c for c in self.remote.commands if c.startswith("printf '%s\\n' ")]
        self.assertTrue(retrievals)
        run.refresh_from_db()
        self.assertTrue(
            all(c.startswith(f"printf '%s\\n' {run.invocation_id} | ") for c in retrievals)
        )

    def test_checking_needs_the_maintenance_authority(self) -> None:
        self.systemd.lose_acknowledgement = True
        run = self.apply()
        self.sign_in_as(
            "view_server", "view_configurationplan", "inspect_wordpress", "apply_configurationplan"
        )
        self.assertEqual(self.client.post(f"/applies/{run.pk}/check/").status_code, 403)

    def test_another_active_operation_conflicts_with_the_apply(self) -> None:
        first = self.maintained()
        second = self.maintained()
        self.sign_in_as(*RUN)
        self.client.post(f"/plans/{first.pk}/apply/")
        self.client.post(f"/plans/{second.pk}/apply/")
        self.assertEqual(ApplyRun.objects.count(), 1)

    def test_a_site_whose_removal_races_the_apply_is_a_404(self) -> None:
        plan = self.maintained()
        self.sign_in_as(*RUN)
        with mock.patch("bootstrap.views.request_apply", side_effect=Server.DoesNotExist):
            self.assertEqual(self.client.post(f"/plans/{plan.pk}/apply/").status_code, 404)
