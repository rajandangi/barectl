"""Applying a reviewed WordPress Finish through requests and the worker
(docs/wordpress.md#finishing-a-partial-installation), against a simulated server.

Real views, services, the lifecycle, the ``db_worker`` command, persistence and rendering run;
only remote execution is substituted. The native effects are qualified by
``test_finish_remote``.
"""

import re
import shlex

from django.contrib.auth.models import Permission

from bootstrap import apply as bootstrap_apply
from bootstrap import native as bootstrap_native
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, Verification
from bootstrap.test_workflow import kept_text
from operations.models import RemoteOperation
from servers.models import Server
from servers.registration import RemovalBlocked, remove_server
from servers.testing import HTMX_FRAGMENT

from . import core_native, finish_apply, finish_native, install_apply, install_native
from . import test_install_apply as base
from .fakes import SALT_VALUES
from .finish_testing import FinishTestCase
from .install_testing import PREPARE, VIEW
from .models import InstallRunResult, PlanWordpressFinish, RunWordpressFinish

Status = RemoteOperation.Status
Exit = finish_native.Exit
INSTALL = (*PREPARE, "install_wordpress")


class FinishApplyCase(FinishTestCase, base.ApplyTestCase):
    """The stranded site with an executing server: the unit's exit becomes the app's
    outcome, and a successful run leaves the application the verification reads."""


class ApplyRequestTests(FinishApplyCase):
    def test_only_an_installer_is_offered_the_apply(self) -> None:
        plan = self.reviewed()
        self.sign_in_as(*VIEW)
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertNotContains(page, f"/plans/{plan.pk}/apply/")
        self.assertNotContains(page, "Barectl does not apply this kind of plan yet")
        self.sign_in_as(*INSTALL)
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, f"/plans/{plan.pk}/apply/")
        self.assertContains(page, f"Apply plan {plan.pk}")
        self.assertContains(page, "never submitted twice")

    def test_the_apply_needs_its_own_permission(self) -> None:
        plan = self.reviewed()
        self.sign_in_as(*PREPARE, "apply_configurationplan", "apply_siteplan")
        self.assertEqual(self.client.post(f"/plans/{plan.pk}/apply/").status_code, 403)
        self.assertFalse(ApplyRun.objects.exists())

    def test_the_account_is_rechecked_when_the_worker_dispatches(self) -> None:
        plan = self.reviewed()
        self.sign_in_as(*INSTALL)
        self.systemd.answer(self.remote)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.user.user_permissions.remove(Permission.objects.get(codename="install_wordpress"))
        self.remote.targets.clear()
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.failure, bootstrap_apply.REVOKED_FAILURE)
        self.assertEqual(self.systemd.submissions, [])
        self.assertEqual(self.remote.targets, [])

    def test_polling_checking_and_acknowledging_need_the_installation_authority(self) -> None:
        run = self.apply()
        self.sign_in_as("view_server", "view_configurationplan", "apply_configurationplan")
        self.assertEqual(self.client.get(f"/applies/{run.pk}/").status_code, 403)
        self.assertEqual(
            self.client.get(f"/applies/{run.pk}/status/", headers=HTMX_FRAGMENT).status_code, 403
        )
        self.assertEqual(self.client.post(f"/applies/{run.pk}/check/").status_code, 403)
        self.assertEqual(self.client.post(f"/applies/{run.pk}/acknowledge/").status_code, 403)
        self.sign_in_as(*VIEW)
        self.assertEqual(self.client.get(f"/applies/{run.pk}/").status_code, 200)

    def test_an_installation_reviews_permissions_work_the_same_for_a_finish(self) -> None:
        plan = self.reviewed()
        self.sign_in_as("view_server", "view_configurationplan", "install_wordpress")
        self.assertEqual(self.client.post(f"/plans/{plan.pk}/apply/").status_code, 403)
        self.assertFalse(ApplyRun.objects.exists())


class ApplyPayloadTests(FinishApplyCase):
    def body(self) -> str:
        return base.staged_body(self.systemd.submissions[0])

    def test_the_submission_carries_the_reviewed_body_under_native_limits(self) -> None:
        plan = self.reviewed()
        run = self.apply(plan)
        self.assertEqual(len(self.systemd.submissions), 1, run.failure)
        submission = self.systemd.submissions[0]
        review = PlanWordpressFinish.objects.get(plan=plan)
        body = self.body()
        self.assertEqual(install_native.digest(body), review.body_sha256)
        for limit in (
            f"--property=LimitFSIZE={core_native.MAX_FILE_BYTES}",
            f"--property=MemoryMax={core_native.MEMORY_MAX_BYTES}",
            "--property=MemorySwapMax=0",
        ):
            self.assertIn(limit, submission)
        for pinned in (
            core_native.ARCHIVE_URL,
            core_native.ARCHIVE_SHA256,
            str(core_native.ARCHIVE_BYTES),
            review.gate_sha256,
            review.ready_sha256,
            review.certificate_sha256,
        ):
            self.assertIn(pinned, body)
        self.assertEqual(review.payload_bytes, len(shlex.split(submission)[-1].encode()))
        self.assertLess(review.payload_bytes or 0, bootstrap_native.MAX_PAYLOAD)

    def test_the_largest_review_still_fits_one_run_with_room(self) -> None:
        # Everything published, nothing else created: comparison, loader, configuration and
        # installation all run.
        self.stranded.leave("publish")
        review = PlanWordpressFinish.objects.get(plan=self.reviewed())
        self.assertTrue(
            review.compares
            and review.creates_loader
            and review.creates_configuration
            and review.runs_install
        )
        self.assertLess(review.payload_bytes or 0, bootstrap_native.MAX_PAYLOAD - 1000)

    def test_the_body_contains_only_the_steps_the_review_found_missing(self) -> None:
        cases = {
            "gate": (True, True, True, False),
            "publish": (True, True, True, True),
            "loader": (False, True, True, True),
            "configuration": (False, False, True, True),
            "install": (False, False, False, True),
        }
        for boundary, (loader, configuration, install, _compares) in cases.items():
            with self.subTest(boundary=boundary):
                ApplyRun.objects.all().delete()
                self.systemd.submissions.clear()
                self.systemd.units.clear()
                self.stranded.leave(boundary)
                self.record_php_snapshot()
                self.apply(self.reviewed())
                body = self.body()
                review = PlanWordpressFinish.objects.order_by("-plan_id")[0]
                names = [
                    step.name
                    for step in finish_native.body_steps(
                        review, install_apply._evidence(review.plan), "24.04"
                    )
                ]
                self.assertEqual("loader" in names, loader)
                self.assertEqual("configuration" in names, configuration)
                self.assertEqual("install" in names, install)
                self.assertIn("compare", names)
                self.assertEqual("--prompt=admin_password" in body, install)
                self.assertEqual("core install" in body, install)
                self.assertIn('find "./$2"', body)

    def test_an_installed_database_never_runs_core_installation_or_creates_an_account(
        self,
    ) -> None:
        self.stranded.leave("install")
        self.apply(self.reviewed())
        body = self.body()
        self.assertNotIn("core install", body)
        self.assertNotIn("--prompt=admin_password", body)
        self.assertNotIn("user get", body)
        self.assertNotIn("user list", body)
        self.assertNotIn("user update", body)
        self.assertNotIn("/dev/urandom", body)

    def test_the_body_never_removes_rotates_resets_or_replaces(self) -> None:
        self.stranded.leave("publish")
        self.apply(self.reviewed())
        body = self.body()
        self.assertNotIn("--allow-root", body)
        self.assertNotIn("--force", body)
        self.assertNotIn("DROP ", body.upper().replace("DROPPED", ""))
        self.assertNotIn("--prompt=user_pass", body)
        # The only recursive removal is the cleanup of the run's own staging directory.
        self.assertEqual(len(re.findall(r"rm -rf", body)), 1)
        self.assertIn('rm -rf -- "$stg/dl" "$stg/tmp" "$stg/home" "$stg/tree"', body)
        # Release entries move only to absent destinations, without overwriting.
        self.assertIn("mv --no-copy --no-clobber -T", body)
        self.assertNotRegex(body, r"\bcp\b.*\$pub|\brsync\b|\bmv -f\b")

    def test_the_body_checks_the_gate_before_it_publishes_anything(self) -> None:
        self.apply(self.reviewed())
        body = self.body()
        steps = finish_native.body_steps(
            PlanWordpressFinish.objects.get(),
            install_apply._evidence(self.reviewed_plan()),
            "24.04",
        )
        names = [step.name for step in steps]
        self.assertLess(names.index("compare") if "compare" in names else 0, names.index("gated"))
        self.assertLess(names.index("gated"), names.index("publish"))
        self.assertLess(names.index("publish"), names.index("ready"))
        self.assertLess(body.index("barectl-wordpress: gate verified"), body.index("mv --no-copy"))

    def reviewed_plan(self) -> ConfigurationPlan:
        return PlanWordpressFinish.objects.get().plan

    def test_the_body_never_names_a_password_or_a_salt(self) -> None:
        self.apply(self.reviewed())
        body = self.body()
        self.assertNotIn("--admin_password", body)
        self.assertNotIn("set -x", body)
        self.assertNotRegex(body, r"\bsalt\w*=")
        self.assertEqual(body.count("--prompt=admin_password"), 1)
        self.assertNotRegex(body, r"[A-Za-z0-9]{40,}\b(?<![0-9a-f]{64})")

    def test_the_body_runs_wordpress_only_as_the_site_user(self) -> None:
        self.apply(self.reviewed())
        body = self.body()
        self.assertRegex(body, r's\(\)\{ runuser -u "\$u" -- /usr/bin/env -i ')
        for found in re.finditer(r"/usr/bin/php[\d.$a-z]*", body):
            context = body[max(0, found.start() - 40) : found.end() + 12]
            self.assertTrue(
                'W(){ wpath=$1; shift; s "' in context
                or "f(){ /usr/bin/php8.3 -n -r" in context
                or "f(){ /usr/bin/php8.5 -n -r" in context
                or 'sh sh "/usr/bin/php$php"' in context.replace("' ", " ")
                or "for b in" in body[max(0, found.start() - 400) : found.start()]
                or 'sh "/usr/bin/php$php"' in context,
                context,
            )

    def test_the_comparison_runs_as_the_site_user_without_following_links(self) -> None:
        self.stranded.leave("publish")
        self.apply(self.reviewed())
        body = self.body()
        self.assertIn("d(){ s /usr/bin/sh -c", body)
        self.assertIn('find "./$2" -printf', body)
        self.assertIn('find "./$2" -type f -exec sha256sum', body)

    def test_a_changed_pin_refuses_before_anything_is_sent(self) -> None:
        from unittest import mock

        plan = self.reviewed()
        with mock.patch.object(core_native, "ARCHIVE_SHA256", "0" * 64):
            run = self.apply(plan)
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.failure, finish_apply.EVIDENCE_FAILURE)
        self.assertEqual(self.systemd.submissions, [])

    def test_a_payload_that_differs_from_its_review_is_never_sent(self) -> None:
        plan = self.reviewed()
        PlanWordpressFinish.objects.filter(plan=plan).update(body_sha256="1" * 64)
        run = self.apply(plan)
        self.assertEqual(run.failure, finish_apply.EVIDENCE_FAILURE)
        self.assertEqual(self.systemd.submissions, [])

    def test_decisions_that_disagree_with_one_another_are_never_sent(self) -> None:
        for change in (
            {"runs_install": False},
            {"creates_configuration": False},
            {"strict_content": False},
        ):
            with self.subTest(change=change):
                ApplyRun.objects.all().delete()
                self.systemd.units.clear()
                self.record_php_snapshot()
                plan = self.reviewed()
                PlanWordpressFinish.objects.filter(plan=plan).update(**change)
                run = self.apply(plan)
                self.assertEqual(run.failure, finish_apply.EVIDENCE_FAILURE)
                self.assertEqual(self.systemd.submissions, [])

    def test_missing_evidence_refuses_before_anything_is_sent(self) -> None:
        plan = self.reviewed()
        plan.evidence.filter(kind="wordpress_database").delete()
        run = self.apply(plan)
        self.assertEqual(run.failure, finish_apply.EVIDENCE_FAILURE)
        self.assertEqual(self.systemd.submissions, [])


class ApplyOutcomeTests(FinishApplyCase):
    def test_a_verified_finish_that_installed_requires_the_password_step(self) -> None:
        run = self.apply()
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        self.assertEqual(InstallRunResult.objects.get(run=run).problems, "")
        review = RunWordpressFinish.objects.get(run=run)
        self.assertEqual(review.canonical_name, "www.shop.example.com")
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Administrator password setup required")
        self.assertContains(
            page,
            f"sudo -u sshop /usr/bin/php{self.site.php} /usr/local/lib/wp-cli/wp-cli-2.12.0.phar "
            "--path=/var/www/shop/public --url=https://www.shop.example.com "
            "user update owner --prompt=user_pass --skip-email",
        )
        self.assertContains(page, 'href="https://www.shop.example.com/"')
        self.assertContains(page, 'href="https://www.shop.example.com/wp-admin/"')
        content = page.content.decode()
        for claim in ("password was delivered", "email was sent", "ready to log in"):
            self.assertNotIn(claim, content)
        self.assertContains(page, "not a live health check")
        self.assertContains(page, "Verify that the provisioning gate")

    def test_a_verified_finish_of_an_installed_database_asks_for_no_password_step(self) -> None:
        self.stranded.leave("install")
        run = self.apply(self.reviewed({}))
        self.assertEqual(
            (run.status, run.execution, run.verification), (Status.SUCCEEDED, "succeeded", "passed")
        )
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertNotContains(page, "Administrator password setup required")
        self.assertNotContains(page, "user update")
        self.assertContains(page, 'href="https://www.shop.example.com/wp-admin/"')
        self.assertContains(page, "run no installation")

    def test_plugin_tables_beside_the_core_schema_verify(self) -> None:
        self.stranded.leave("install")
        self.stranded.plugin_tables = 3
        self.stranded.table_total = 15
        run = self.apply(self.reviewed({}))
        self.assertEqual(run.verification, Verification.PASSED, run.failure)

    def test_a_first_installation_still_requires_exactly_the_core_tables(self) -> None:
        self.stranded.table_total = 13
        run = self.apply()
        self.assertEqual(run.verification, Verification.FAILED)
        self.assertIn("exactly 12 tables", InstallRunResult.objects.get(run=run).problems)

    def test_the_completion_needs_the_view_authority(self) -> None:
        run = self.apply()
        self.sign_in_as("view_server")
        self.assertEqual(self.client.get(f"/applies/{run.pk}/").status_code, 403)
        self.sign_in_as(*VIEW)
        self.assertContains(self.client.get(f"/applies/{run.pk}/"), "Administrator password setup")

    def test_a_failed_run_offers_no_next_step(self) -> None:
        self.systemd.exit_status = Exit.INSTALL
        self.systemd.result = "exit-code"
        run = self.apply()
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertNotContains(page, 'id="run-completion"')
        self.assertNotContains(page, 'href="https://www.shop.example.com/wp-admin/"')

    def test_each_exit_status_names_its_boundary(self) -> None:
        cases = {
            Exit.TOOLS: (Execution.ARTIFACT_REFUSED, "lacks a native tool"),
            Exit.STAGING: (Execution.ARTIFACT_REFUSED, "staging area"),
            Exit.DOWNLOAD: (Execution.ARTIFACT_REFUSED, "could not download"),
            Exit.ARCHIVE: (Execution.ARTIFACT_REFUSED, "not the reviewed bytes"),
            Exit.ENTRIES: (Execution.ARTIFACT_REFUSED, "refuses"),
            Exit.EXTRACT: (Execution.ARTIFACT_REFUSED, "did not extract"),
            Exit.CHECKSUMS: (Execution.ARTIFACT_REFUSED, "checksum verification"),
            Exit.NOT_GATED: (Execution.NOT_GATED, "not the reviewed provisioning gate"),
            Exit.PUBLISH: (Execution.PARTIAL, "Publishing the missing release entries stopped"),
            Exit.PLACEHOLDER: (Execution.PARTIAL, "placeholder"),
            Exit.LOADER: (Execution.PARTIAL, "public loader"),
            Exit.CONFIGURATION: (Execution.PARTIAL, "private configuration"),
            Exit.INSTALL: (Execution.PARTIAL, "never replayed"),
            Exit.SCHEMA: (Execution.PARTIAL, "complete WordPress core schema"),
            Exit.INTEGRITY: (Execution.PARTIAL, "published tree failed"),
            Exit.ACCESS: (Execution.PARTIAL, "site user"),
            Exit.READY: (Execution.PARTIAL, "not served"),
            Exit.NOT_SERVING: (Execution.NOT_SERVING, "verified that application paths answer"),
            Exit.EXPOSED: (Execution.EXPOSURE_UNCERTAIN, "may be reachable"),
            Exit.DRIFT: (Execution.DRIFT, "existing files"),
            bootstrap_native.Exit.LOCK_CONFLICT: (Execution.LOCK_CONFLICT, "mutation lock"),
            bootstrap_native.Exit.BOOT_CHANGED: (Execution.BOOT_CHANGED, "server restarted"),
            bootstrap_native.Exit.EXPIRED: (Execution.EXPIRED, "admission deadline"),
            bootstrap_native.Exit.OTHER_RUN_ACTIVE: (Execution.OTHER_RUN_ACTIVE, "still had"),
            bootstrap_native.Exit.RENEWAL_ACTIVE: (Execution.RENEWAL_ACTIVE, "renewal"),
            bootstrap_native.Exit.CAPACITY: (Execution.CAPACITY, "too many finished runs"),
            143: (Execution.FAILED, "did not complete"),
        }
        for status, (execution, text) in cases.items():
            with self.subTest(status=status):
                ApplyRun.objects.all().delete()
                self.systemd.units.clear()
                self.systemd.submissions.clear()
                self.systemd.exit_status = status
                self.systemd.result = "exit-code"
                self.record_php_snapshot()
                run = self.apply(self.reviewed())
                self.assertEqual(
                    (run.status, run.execution, run.exit_status, run.verification),
                    (Status.FAILED, execution, status, Verification.NOT_APPLICABLE),
                    run.failure,
                )
                self.assertIn(text, run.failure)
                if execution in {Execution.PARTIAL, Execution.NOT_SERVING}:
                    self.assertIn("removes nothing automatically", run.failure)
                    self.assertIn("never replays core installation", run.failure)

    def test_a_refusal_before_changes_is_not_a_partial_run(self) -> None:
        self.assertIn(Execution.NOT_GATED, Execution.refused_before_changes())
        self.systemd.exit_status = Exit.NOT_GATED
        self.systemd.result = "exit-code"
        run = self.apply()
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "stopped before making any requested change")

    def test_the_serving_outcomes_separate_restored_from_uncertain_exposure(self) -> None:
        self.systemd.exit_status = Exit.NOT_SERVING
        self.systemd.result = "exit-code"
        restored = self.apply(self.reviewed())
        self.assertEqual(restored.execution, Execution.NOT_SERVING)
        self.assertIn("restored the provisioning gate", restored.failure)
        self.assertNotIn("reachable", restored.failure)
        ApplyRun.objects.all().delete()
        self.systemd.units.clear()
        self.systemd.exit_status = Exit.EXPOSED
        self.record_php_snapshot()
        uncertain = self.apply(self.reviewed())
        self.assertEqual(uncertain.execution, Execution.EXPOSURE_UNCERTAIN)
        self.assertIn("could not prove", uncertain.failure)
        self.assertIn("/etc/nginx/sites-available/shop.conf", uncertain.failure)
        self.assertIn("ordinary administration", uncertain.failure)

    def test_each_difference_the_verification_finds_is_reported(self) -> None:
        for difference, text in {
            "ready": "not the reviewed ready form",
            "preimage": "recovery preimage",
            "placeholder": "placeholder's preimage",
            "loader": "fixed loader",
            "configuration": "private configuration",
            "version": "installed core release",
            "entries": "holds more than public and private",
            "schema": "complete WordPress core schema",
            "tables": "exactly 12 tables",
            "options": "siteurl and home options",
            "nginx": "does not accept its configuration",
        }.items():
            with self.subTest(difference=difference):
                ApplyRun.objects.all().delete()
                self.systemd.units.clear()
                self.state.differences = {difference}
                self.record_php_snapshot()
                run = self.apply(self.reviewed())
                self.assertEqual(
                    (run.status, run.execution, run.verification),
                    (Status.FAILED, Execution.SUCCEEDED, Verification.FAILED),
                )
                self.assertIn(text, InstallRunResult.objects.get(run=run).problems)
                self.assertIn("does not repair or roll back", run.failure)
                self.assertIn("finishing-a-partial-installation", run.failure)
                self.assertNotContains(
                    self.client.get(f"/applies/{run.pk}/"), 'id="run-completion"'
                )

    def test_an_unreadable_verification_keeps_the_execution_outcome(self) -> None:
        self.state.applied = False
        self.systemd.on_submit = None
        run = self.apply()
        self.assertEqual(run.execution, Execution.SUCCEEDED)
        self.assertEqual(run.verification, Verification.UNAVAILABLE)
        self.assertEqual(run.status, Status.FAILED)

    def test_the_finished_audit_survives_the_servers_removal(self) -> None:
        run = self.apply()
        remove_server(self.server)
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Verify that the provisioning gate")
        self.assertContains(page, "Administrator password setup required")
        self.assertTrue(RunWordpressFinish.objects.filter(run=run).exists())
        self.assertTrue(InstallRunResult.objects.filter(run=run).exists())

    def test_an_active_finish_protects_the_server_from_removal(self) -> None:
        plan = self.reviewed()
        self.sign_in_as(*INSTALL)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.assertEqual(run.status, Status.QUEUED)
        with self.assertRaises(RemovalBlocked):
            remove_server(self.server)
        self.assertTrue(Server.objects.filter(pk=self.server.pk).exists())

    def test_the_activity_lists_the_run_under_its_site(self) -> None:
        run = self.apply()
        self.sign_in_as("view_server", "view_siteobservation", "view_wordpressplan")
        page = self.client.get(f"/servers/{self.server.pk}/sites/shop/activity/")
        self.assertContains(page, f"/applies/{run.pk}/")
        self.assertContains(page, "WordPress installation Finish")

    def test_the_audit_lists_what_was_found_and_what_was_created(self) -> None:
        self.stranded.leave("configuration")
        run = self.apply(self.reviewed())
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Compare the existing release files with the staged copy")
        self.assertContains(page, "Keep the existing loader")
        self.assertContains(page, "Keep /var/www/shop/private/wp-config.php")
        self.assertContains(page, "Install the core schema in sshop")
        self.stranded.leave("install")
        ApplyRun.objects.all().delete()
        self.systemd.units.clear()
        self.record_php_snapshot()
        run = self.apply(self.reviewed({}))
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "run no installation")


class SecretSurfaceTests(FinishApplyCase):
    def test_no_record_or_page_holds_a_password_or_a_salt(self) -> None:
        plan = self.reviewed()
        run = self.apply(plan)
        submitted = self.systemd.submissions[0]
        encoded = re.search(r"([A-Za-z0-9+/=]{200,})", submitted)
        if encoded is None:
            raise AssertionError("The submission carries no staged body.")
        surfaces = [
            kept_text(plan),
            submitted.replace(encoded[1], ""),
            base.staged_body(submitted),
        ]
        surfaces += [
            f"{field.attname}={getattr(row, field.attname)}"
            for row in (run, RunWordpressFinish.objects.get(run=run))
            for field in row._meta.concrete_fields
        ]
        surfaces.append(InstallRunResult.objects.get(run=run).problems)
        surfaces += [
            self.client.get(url).content.decode()
            for url in (f"/plans/{plan.pk}/", f"/applies/{run.pk}/")
        ]
        surfaces += [command for command in self.remote.commands if "sudo" not in command]
        text = "\n".join(surfaces)
        for token in set(re.findall(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9]{32}(?![A-Za-z0-9+/=])", text)):
            self.assertRegex(
                token, r"^[0-9a-f]{32}$", "a generated-looking token on the controller"
            )
        for word in ("AUTH_KEY'", "NONCE_SALT'", "--admin_password", "admin_password="):
            self.assertNotIn(word, text.replace("define(", ""))

    def test_the_configuration_digest_is_not_a_salt_and_the_file_never_leaves(self) -> None:
        self.stranded.leave("configuration")
        plan = self.reviewed()
        run = self.apply(plan)
        row = RunWordpressFinish.objects.get(run=run)
        self.assertEqual(len(row.configuration_sha256), 64)
        for command in self.remote.commands:
            for salt in SALT_VALUES:
                self.assertNotIn(salt, command)
