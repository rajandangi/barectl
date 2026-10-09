"""Applying a reviewed WordPress inspection through requests and the worker
(docs/wordpress.md#inspecting-wordpress), against a simulated server.

Real views, services, the lifecycle, the ``db_worker`` command, persistence and rendering
run; only remote execution is substituted. The native effects are qualified by
``test_inspection_remote``.
"""

import shlex
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission

from bootstrap import apply as bootstrap_apply
from bootstrap import native as bootstrap_native
from bootstrap.fakes import NativeSystemd
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, Verification
from bootstrap.test_workflow import kept_text
from discovery import ssh
from operations.models import RemoteOperation
from servers.models import Server
from servers.registration import RemovalBlocked, remove_server
from servers.testing import HTMX_FRAGMENT

from . import execution, inspection, inspection_apply, inspection_fakes, inspection_native
from .inspection_models import (
    InspectionItem,
    InspectionResult,
    Operation,
    PlanWordpressInspection,
    RunWordpressInspection,
)
from .inspection_testing import INSPECT_VIEW, RUN, InspectionTestCase
from .test_install_apply import staged_body

Status = RemoteOperation.Status
Exit = execution.Exit
MARKER = f"{execution.RECORD_MARKER} "


class ApplyTestCase(InspectionTestCase):
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
        operation: str = Operation.INSPECT,
        *,
        plan: ConfigurationPlan | None = None,
        perms: tuple[str, ...] = RUN,
    ) -> ApplyRun:
        plan = plan or self.inspected(operation)
        self.sign_in_as(*perms)
        self.systemd.answer(self.remote)
        self.application.answer(self.remote)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.run_worker()
        run.refresh_from_db()
        return run


class RequestTests(ApplyTestCase):
    def test_only_an_inspector_is_offered_the_apply(self) -> None:
        plan = self.inspected()
        self.sign_in_as(*INSPECT_VIEW)
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertNotContains(page, f"/plans/{plan.pk}/apply/")
        self.assertNotContains(page, "Barectl does not apply this kind of plan yet")
        self.sign_in_as(*RUN)
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, f"/plans/{plan.pk}/apply/")
        self.assertContains(page, "never submitted twice")

    def test_the_apply_needs_its_own_permission(self) -> None:
        plan = self.inspected()
        for perms in (
            (*INSPECT_VIEW, "prepare_wordpressplan", "install_wordpress"),
            (*INSPECT_VIEW, "apply_configurationplan", "apply_siteplan"),
            ("view_server", "view_configurationplan", "apply_configurationplan"),
        ):
            with self.subTest(perms):
                self.sign_in_as(*perms)
                self.assertEqual(self.client.post(f"/plans/{plan.pk}/apply/").status_code, 403)
                self.assertFalse(ApplyRun.objects.exists())

    def test_the_account_is_rechecked_when_the_worker_dispatches(self) -> None:
        plan = self.inspected()
        self.sign_in_as(*RUN)
        self.systemd.answer(self.remote)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.user.user_permissions.remove(Permission.objects.get(codename="inspect_wordpress"))
        self.remote.targets.clear()
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.failure, bootstrap_apply.REVOKED_FAILURE)
        self.assertEqual(self.systemd.submissions, [])
        self.assertEqual(self.remote.targets, [])

    def test_a_deactivated_account_is_not_dispatched(self) -> None:
        plan = self.inspected()
        self.sign_in_as(*RUN)
        self.client.post(f"/plans/{plan.pk}/apply/")
        self.user.is_active = False
        self.user.save()
        self.remote.targets.clear()
        self.run_worker()
        self.assertEqual(self.systemd.submissions, [])

    def test_polling_checking_and_acknowledging_need_the_inspection_view_authority(self) -> None:
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
        self.sign_in_as(*INSPECT_VIEW)
        self.assertEqual(self.client.get(f"/applies/{run.pk}/").status_code, 200)
        self.assertEqual(
            self.client.get(f"/applies/{run.pk}/status/", headers=HTMX_FRAGMENT).status_code, 200
        )

    def test_the_result_needs_the_view_authority_on_every_surface(self) -> None:
        run = self.apply()
        self.sign_in_as("view_server", "view_siteobservation")
        poll = f"/servers/{self.server.pk}/sites/shop/wordpress/inspection/"
        self.assertEqual(self.client.get(poll, headers=HTMX_FRAGMENT).status_code, 403)
        self.assertEqual(self.client.get(f"/applies/{run.pk}/").status_code, 403)


class PayloadTests(ApplyTestCase):
    def test_the_submission_carries_the_reviewed_body_under_native_limits(self) -> None:
        plan = self.inspected(Operation.CORE)
        run = self.apply(plan=plan)
        self.assertEqual(len(self.systemd.submissions), 1, run.failure)
        submission = self.systemd.submissions[0]
        review = PlanWordpressInspection.objects.get(plan=plan)
        body = staged_body(submission)
        self.assertEqual(inspection.digest(body), review.body_sha256)
        for limit in (
            f"--property=LimitFSIZE={inspection_native.MAX_FILE_BYTES}",
            f"--property=MemoryMax={inspection_native.MEMORY_MAX_BYTES}",
            "--property=MemorySwapMax=0",
        ):
            self.assertIn(limit, submission)
        self.assertIn("core verify-checksums --version=7.1.3 --locale=en_US", body)
        self.assertEqual(review.payload_bytes, len(shlex.split(submission)[-1].encode()))
        self.assertLess(review.payload_bytes or 0, bootstrap_native.MAX_PAYLOAD)

    def test_each_operation_runs_only_its_fixed_commands(self) -> None:
        for operation in Operation:
            with self.subTest(operation):
                ApplyRun.objects.all().delete()
                self.systemd.units.clear()
                self.systemd.submissions.clear()
                self.record_php_snapshot()
                run = self.apply(operation)
                body = staged_body(self.systemd.submissions[0])
                self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
                for command in inspection_native.COMMANDS[operation]:
                    if "<" not in command:
                        self.assertIn(command, body)
                other = {
                    Operation.INSPECT: "verify-checksums",
                    Operation.CORE: "plugin list",
                    Operation.PLUGINS: "core is-installed",
                }[operation]
                self.assertNotIn(other, body)
                for forbidden in ('eval "$@', "--allow-root", "--ssh", "wp eval", "db query"):
                    self.assertNotIn(forbidden, body)

    def test_a_changed_pin_refuses_before_anything_is_sent(self) -> None:
        plan = self.inspected()
        with mock.patch.object(inspection_native, "COMMAND_SECONDS", 90):
            run = self.apply(plan=plan)
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.failure, inspection_apply.EVIDENCE_FAILURE)
        self.assertEqual(self.systemd.submissions, [])

    def test_a_payload_that_differs_from_its_review_is_never_sent(self) -> None:
        plan = self.inspected()
        PlanWordpressInspection.objects.filter(plan=plan).update(body_sha256="1" * 64)
        run = self.apply(plan=plan)
        self.assertEqual(run.failure, inspection_apply.EVIDENCE_FAILURE)
        self.assertEqual(self.systemd.submissions, [])

    def test_missing_evidence_refuses_before_anything_is_sent(self) -> None:
        plan = self.inspected()
        plan.evidence.filter(kind="wordpress_state").delete()
        run = self.apply(plan=plan)
        self.assertEqual(run.failure, inspection_apply.EVIDENCE_FAILURE)
        self.assertEqual(self.systemd.submissions, [])

    def test_a_non_root_user_needs_sudo_to_authorize_the_result_read(self) -> None:
        self.systemd.sudo_allowed = False
        run = self.apply()
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(self.systemd.submissions, [])


class ResultTests(ApplyTestCase):
    def test_an_inspection_is_retrieved_stored_typed_and_rendered_with_its_time(self) -> None:
        run = self.apply(Operation.INSPECT)
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        result = InspectionResult.objects.get(run=run)
        self.assertEqual(
            (result.state, result.core_installed, result.core_version),
            ("available", True, "7.1.3"),
        )
        self.assertIsNotNone(result.reported_at)
        self.assertEqual(
            list(InspectionItem.objects.filter(result=result).values_list("kind", "name")),
            [("plugin", "akismet"), ("theme", "twentytwentysix")],
        )
        page = self.client.get(f"/applies/{run.pk}/")
        for text in (
            "Result: Inspect WordPress",
            "akismet",
            "5.7.2",
            "twentytwentysix",
            "Network"[:0],
        ):
            self.assertContains(page, text)
        self.assertContains(page, "not a live-security assessment")
        self.assertContains(page, "(server clock)")
        self.record_php_snapshot()
        site = self.client.get(f"/servers/{self.server.pk}/sites/shop/wordpress/")
        self.assertContains(site, "Latest explicit inspection result")
        self.assertContains(site, "akismet")

    def test_the_result_needs_the_application_permission_at_every_place_it_is_shown(self) -> None:
        run = self.apply(Operation.INSPECT)
        self.record_php_snapshot()
        site = f"/servers/{self.server.pk}/sites/shop/wordpress/"
        poll = f"{site}inspection/"
        self.sign_in_as(*RUN)
        for url, headers in (
            (f"/applies/{run.pk}/", {}),
            (f"/applies/{run.pk}/status/", HTMX_FRAGMENT),
            (site, {}),
            (poll, HTMX_FRAGMENT),
        ):
            self.assertContains(self.client.get(url, headers=headers), "5.7.2")
        self.sign_in_as(*(code for code in RUN if code != "view_siteapplicationobservation"))
        for url, headers in (
            (f"/applies/{run.pk}/", {}),
            (f"/applies/{run.pk}/status/", HTMX_FRAGMENT),
            (site, {}),
            (poll, HTMX_FRAGMENT),
        ):
            page = self.client.get(url, headers=headers)
            self.assertEqual(page.status_code, 200, url)
            for text in ("5.7.2", "Result: Inspect WordPress", "Latest explicit inspection result"):
                self.assertNotContains(page, text, msg_prefix=url)

    def test_mu_plugins_and_drop_ins_are_listed_apart_from_ordinary_plugins(self) -> None:
        plugins = (
            '[{"name":"akismet","status":"inactive","version":"5.7.2"},'
            '{"name":"loader","status":"must-use","version":""},'
            '{"name":"object-cache.php","status":"dropin","version":""}]'
        )
        self.application.records[Operation.INSPECT] = inspection_fakes.project(
            Operation.INSPECT, inspection_fakes.inventory_outputs(plugins=plugins)
        )
        run = self.apply(Operation.INSPECT)
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Must-use plugin")
        self.assertContains(page, "Drop-in")
        self.assertContains(page, "Must-use (loaded automatically)")

    def test_core_checksums_report_each_classification(self) -> None:
        mismatch = (
            "Warning: File doesn't verify against checksum: wp-includes/load.php\n"
            "Warning: File should not exist: wp-admin/evil.php\n"
            "Error: WordPress installation doesn't verify against checksums.\n"
        )
        cases = {
            "match": (0, *inspection_fakes.CORE_OK),
            "mismatch": (1, "", mismatch),
            "unavailable": (1, "", "Error: RuntimeException: Failed to get url\n"),
        }
        for verdict, (status, out, err) in cases.items():
            with self.subTest(verdict):
                ApplyRun.objects.all().delete()
                self.systemd.units.clear()
                self.record_php_snapshot()
                self.application.records[Operation.CORE] = inspection_fakes.project(
                    Operation.CORE, inspection_fakes.core_outputs(status, out, err), "7.1.3"
                )
                run = self.apply(Operation.CORE)
                result = InspectionResult.objects.get(run=run)
                self.assertEqual(
                    (run.status, run.verification, result.integrity),
                    (Status.SUCCEEDED, Verification.PASSED, verdict),
                    run.failure,
                )
                page = self.client.get(f"/applies/{run.pk}/").content.decode()
                self.assertIn("inspection-core-verdict", page)
                if verdict == "mismatch":
                    self.assertIn("wp-includes/load.php", page)
                    self.assertIn("evidence to investigate, not proof of compromise", page)
                if verdict == "unavailable":
                    self.assertIn("neither a pass nor a mismatch", page)
                    self.assertNotIn("Matches the official checksums", page)

    def test_plugin_checksums_keep_unavailable_apart_from_match_and_mismatch(self) -> None:
        self.application.plugins = {"akismet": "d", "jetpack": "d", "custom": "d"}
        self.application.records[Operation.PLUGINS] = inspection_fakes.project(
            Operation.PLUGINS,
            inspection_fakes.plugin_outputs(
                akismet=(0, inspection_fakes.PLUGIN_OK, ""),
                custom=(
                    0,
                    inspection_fakes.PLUGIN_SKIPPED,
                    (
                        "Warning: Could not retrieve the checksums for version 1 of plugin "
                        "custom, skipping.\n"
                    ),
                ),
                jetpack=(
                    1,
                    (
                        '[{"plugin_name":"jetpack","file":"a.php",'
                        '"message":"Checksum does not match"}]'
                    ),
                    "Error: No plugins verified (1 failed).\n",
                ),
            ),
            "akismet",
            "custom",
            "jetpack",
        )
        run = self.apply(Operation.PLUGINS)
        items = {item.name: item.verdict for item in InspectionItem.objects.filter(result__run=run)}
        self.assertEqual(
            items, {"akismet": "match", "custom": "unavailable", "jetpack": "mismatch"}
        )
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "1</strong> match")
        self.assertContains(
            page,
            "neither trusted nor reported corrupt",
        )
        self.assertContains(page, "official checksum catalog was not available")

    def test_hostile_output_never_reaches_the_record_the_database_or_a_page(self) -> None:
        noise = "debug: secret=hunter2"
        outputs = inspection_fakes.inventory_outputs()
        outputs["plugins"] = (0, noise + outputs["plugins"][1], noise)
        self.application.records[Operation.INSPECT] = inspection_fakes.project(
            Operation.INSPECT, outputs
        )
        plan = self.inspected(Operation.INSPECT)
        run = self.apply(plan=plan)
        result = InspectionResult.objects.get(run=run)
        self.assertEqual((result.state, result.why), ("unavailable", "output"))
        self.assertEqual(run.status, Status.SUCCEEDED)
        surfaces = [
            kept_text(plan),
            self.client.get(f"/applies/{run.pk}/").content.decode(),
            self.client.get(f"/servers/{self.server.pk}/sites/shop/wordpress/").content.decode(),
        ]
        self.assertFalse(any("hunter2" in text for text in surfaces))
        self.assertContains(self.client.get(f"/applies/{run.pk}/"), "Result unavailable")

    def test_every_result_limit_makes_the_result_unavailable(self) -> None:
        many = ",".join(
            f'{{"name":"p{index}","status":"inactive","version":"1"}}' for index in range(129)
        )
        outputs = inspection_fakes.inventory_outputs(plugins=f"[{many}]")
        self.application.records[Operation.INSPECT] = inspection_fakes.project(
            Operation.INSPECT, outputs
        )
        run = self.apply(Operation.INSPECT)
        result = InspectionResult.objects.get(run=run)
        self.assertEqual((result.state, result.why), ("unavailable", "overflow"))
        self.assertFalse(InspectionItem.objects.filter(result=result).exists())

    def test_a_record_outside_the_grammar_is_stored_as_invalid_not_trusted(self) -> None:
        good = inspection_fakes.default_record(Operation.INSPECT)
        for record in (
            good.replace('"installed":true', '"installed":"yes"'),
            good + " ",
            MARKER + '{"v":1,"op":"inspect","state":"ok","at":1791513935,"items":[]}',
            MARKER + "x" * 20000,
        ):
            with self.subTest(record[:60]):
                ApplyRun.objects.all().delete()
                self.systemd.units.clear()
                self.record_php_snapshot()
                self.application.records[Operation.INSPECT] = record
                run = self.apply(Operation.INSPECT)
                result = InspectionResult.objects.get(run=run)
                self.assertEqual((result.state, result.why), ("unavailable", "invalid"))
                self.assertEqual(run.status, Status.SUCCEEDED)

    def test_a_missing_or_rotated_journal_is_result_unavailable_not_a_failed_run(self) -> None:
        for journal, why in (
            ("empty", "journal_missing"),
            ("error", "journal_unreadable"),
            ("duplicate", "extra"),
        ):
            with self.subTest(journal):
                ApplyRun.objects.all().delete()
                self.systemd.units.clear()
                self.record_php_snapshot()
                self.application.journal = journal
                run = self.apply(Operation.INSPECT)
                result = InspectionResult.objects.get(run=run)
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
        run = self.apply(Operation.INSPECT)
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.FAILED, Execution.SUCCEEDED, Verification.FAILED),
        )
        self.assertIn("safe to remove", run.failure)
        self.assertEqual(InspectionResult.objects.get(run=run).state, "available")

    def test_an_unreadable_retrieval_keeps_the_execution_outcome(self) -> None:
        for failing, garbled in (({"journal"}, False), (set(), True)):
            with self.subTest(failing=failing, garbled=garbled):
                ApplyRun.objects.all().delete()
                self.systemd.units.clear()
                self.record_php_snapshot()
                self.application.failing = failing
                self.application.garbled = garbled
                run = self.apply(Operation.INSPECT)
                self.assertEqual(
                    (run.status, run.execution, run.verification),
                    (Status.FAILED, Execution.SUCCEEDED, Verification.UNAVAILABLE),
                )
                self.assertFalse(InspectionResult.objects.filter(run=run).exists())
                page = self.client.get(f"/applies/{run.pk}/")
                self.assertContains(page, "Result unavailable")
                self.assertContains(page, "was not retrieved")

    def test_the_result_is_written_once(self) -> None:
        run = self.apply()
        first = InspectionResult.objects.get(run=run)
        self.application.records[Operation.INSPECT] = inspection_fakes.project(
            Operation.INSPECT, inspection_fakes.inventory_outputs(plugins="[]")
        )
        with ssh.connect_alias(run.ssh_alias) as shell:
            self.assertEqual(inspection_apply.verify(shell, run), Verification.PASSED)
        self.assertEqual(InspectionResult.objects.get(run=run).pk, first.pk)
        self.assertEqual(InspectionResult.objects.filter(run=run).count(), 1)


class OutcomeTests(ApplyTestCase):
    def test_each_exit_status_names_its_boundary(self) -> None:
        cases = {
            Exit.TOOLS: (Execution.INSPECTION_REFUSED, "lacks a native tool"),
            Exit.STAGING: (Execution.INSPECTION_REFUSED, "staging area"),
            Exit.PROJECTION: (Execution.FAILED, "produced no valid result record"),
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
                ApplyRun.objects.all().delete()
                self.systemd.units.clear()
                self.systemd.submissions.clear()
                self.systemd.exit_status = status
                self.systemd.result = "exit-code"
                self.record_php_snapshot()
                run = self.apply()
                self.assertEqual(
                    (run.status, run.execution, run.exit_status, run.verification),
                    (Status.FAILED, outcome, status, Verification.NOT_APPLICABLE),
                    run.failure,
                )
                self.assertIn(text, run.failure)
                self.assertFalse(InspectionResult.objects.filter(run=run).exists())
                self.assertNotContains(self.client.get(f"/applies/{run.pk}/"), "Result unavailable")

    def test_a_refusal_ran_no_application_code(self) -> None:
        self.systemd.exit_status = Exit.DRIFT
        self.systemd.result = "exit-code"
        run = self.apply()
        self.assertContains(
            self.client.get(f"/applies/{run.pk}/"), "stopped before making any requested change"
        )
        self.assertIn("before running any application code", run.failure)

    def test_a_timeout_and_a_kill_say_application_code_ran(self) -> None:
        self.systemd.result = "timeout"
        self.systemd.exit_status = 0
        run = self.apply()
        self.assertEqual(run.execution, Execution.TIMED_OUT)
        self.assertIn("ran application code and published no result", run.failure)

    def test_the_finished_audit_survives_the_servers_removal(self) -> None:
        run = self.apply()
        remove_server(self.server)
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Run WP-CLI 2.12.0 as sshop")
        self.assertContains(page, "akismet")
        self.assertTrue(RunWordpressInspection.objects.filter(run=run).exists())
        self.assertTrue(InspectionResult.objects.filter(run=run).exists())

    def test_an_active_inspection_protects_the_server_from_removal(self) -> None:
        plan = self.inspected()
        self.sign_in_as(*RUN)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.assertEqual(run.status, Status.QUEUED)
        with self.assertRaises(RemovalBlocked):
            remove_server(self.server)
        self.assertTrue(Server.objects.filter(pk=self.server.pk).exists())

    def test_the_activity_lists_the_run_under_its_site(self) -> None:
        run = self.apply()
        self.sign_in_as(*INSPECT_VIEW)
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
        self.assertEqual(InspectionResult.objects.get(run=run).state, "available")
        self.assertContains(self.client.get(f"/applies/{run.pk}/"), "akismet")

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

    def test_a_check_cannot_be_requested_without_the_view_authority(self) -> None:
        self.systemd.lose_acknowledgement = True
        run = self.apply()
        self.sign_in_as("view_server")
        self.assertEqual(self.client.post(f"/applies/{run.pk}/check/").status_code, 403)

    def test_another_active_operation_conflicts_with_the_apply(self) -> None:
        first = self.inspected()
        second = self.inspected()
        self.sign_in_as(*RUN)
        self.client.post(f"/plans/{first.pk}/apply/")
        self.client.post(f"/plans/{second.pk}/apply/")
        self.assertEqual(ApplyRun.objects.count(), 1)

    def test_a_site_whose_removal_races_the_apply_is_a_404(self) -> None:
        plan = self.inspected()
        self.sign_in_as(*RUN)
        with mock.patch("bootstrap.views.request_apply", side_effect=Server.DoesNotExist):
            self.assertEqual(self.client.post(f"/plans/{plan.pk}/apply/").status_code, 404)
