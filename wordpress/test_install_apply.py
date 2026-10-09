"""Applying a reviewed WordPress installation through requests and the worker
(docs/wordpress.md#applying-an-installation), against a simulated server.

Real views, services, the lifecycle, the ``db_worker`` command, persistence and rendering
run; only remote execution is substituted. The native effects are qualified by
``test_install_apply_remote``.
"""

import base64
import gzip
import re
import shlex
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission

from bootstrap import apply as bootstrap_apply
from bootstrap import native as bootstrap_native
from bootstrap.fakes import NativeSystemd
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, Verification
from bootstrap.test_workflow import kept_text
from operations.models import RemoteOperation
from servers.testing import HTMX_FRAGMENT
from servers.models import Server
from servers.registration import RemovalBlocked, remove_server

from . import core_native, install_apply, install_native
from .install_testing import PREPARE, VIEW, InstallTestCase
from .models import InstallRunResult, PlanWordpressInstall, RunWordpressInstall

Status = RemoteOperation.Status
Exit = install_native.Exit
INSTALL = (*PREPARE, "install_wordpress")


def staged_body(submission: str) -> str:
    """The reviewed body a submission carries, decoded the way the server decodes it."""
    found = re.search(r"b=\$\(printf %s '\"'\"'([A-Za-z0-9+/=]+)'\"'\"'", submission)
    assert found is not None, "The submission carries no staged body."
    return gzip.decompress(base64.b64decode(found[1])).decode()


class ApplyTestCase(InstallTestCase):
    systemd: NativeSystemd

    @override
    def setUp(self) -> None:
        super().setUp()
        self.systemd = NativeSystemd()
        self.systemd.on_submit = self.applied
        self.enterContext(mock.patch.object(bootstrap_apply, "POLL_INTERVAL", 0))

    def applied(self) -> None:
        """A successful run leaves the application, as the payload does."""
        self.state.applied = self.systemd.exit_status == 0

    @override
    def assert_read_only(self) -> None:
        """Apply runs change the server; each is submitted once."""

    def apply(
        self, plan: ConfigurationPlan | None = None, *, perms: tuple[str, ...] = INSTALL
    ) -> ApplyRun:
        plan = plan or self.reviewed()
        self.sign_in_as(*perms)
        self.systemd.answer(self.remote)
        self.state.answer(self.remote)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.run_worker()
        run.refresh_from_db()
        return run


class ApplyRequestTests(ApplyTestCase):
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

    def test_polling_and_acknowledging_need_the_installation_authority(self) -> None:
        run = self.apply()
        self.sign_in_as("view_server", "view_configurationplan", "apply_configurationplan")
        self.assertEqual(self.client.get(f"/applies/{run.pk}/").status_code, 403)
        self.assertEqual(
            self.client.get(f"/applies/{run.pk}/status/", headers=HTMX_FRAGMENT).status_code, 403
        )
        self.assertEqual(self.client.post(f"/applies/{run.pk}/check/").status_code, 403)
        self.sign_in_as(*VIEW)
        self.assertEqual(self.client.get(f"/applies/{run.pk}/").status_code, 200)


class ApplyPayloadTests(ApplyTestCase):
    def test_the_submission_carries_the_reviewed_body_under_native_limits(self) -> None:
        plan = self.reviewed()
        run = self.apply(plan)
        self.assertEqual(len(self.systemd.submissions), 1, run.failure)
        submission = self.systemd.submissions[0]
        review = PlanWordpressInstall.objects.get(plan=plan)
        body = staged_body(submission)
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
            review.preimage_sha256,
            review.certificate_sha256,
        ):
            self.assertIn(pinned, body)
        self.assertLessEqual(len(submission), bootstrap_native.MAX_PAYLOAD + 2000)
        self.assertEqual(review.payload_bytes, len(shlex.split(submission)[-1].encode()))

    def test_the_payload_fits_one_run_with_room(self) -> None:
        review = PlanWordpressInstall.objects.get(plan=self.reviewed())
        self.assertLess(review.payload_bytes or 0, bootstrap_native.MAX_PAYLOAD)
        run = self.apply()
        body = staged_body(self.systemd.submissions[0])
        self.assertLess(len(body.encode()), bootstrap_native.MAX_BODY)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)

    def test_the_body_never_names_a_password_or_a_salt(self) -> None:
        self.apply()
        body = staged_body(self.systemd.submissions[0])
        self.assertNotIn("--admin_password", body)
        self.assertNotIn("--allow-root", body)
        self.assertNotIn("set -x", body)
        self.assertNotRegex(body, r"\bsalt\w*=")
        # The salts and the password are generated by the unit and only ever flow through
        # shell builtins and a pipe: the one place the prompt is named.
        self.assertEqual(body.count("--prompt=admin_password"), 1)
        self.assertNotRegex(body, r"[A-Za-z0-9]{40,}\b(?<![0-9a-f]{64})")

    def test_the_body_runs_wordpress_only_as_the_site_user(self) -> None:
        self.apply()
        body = staged_body(self.systemd.submissions[0])
        # Application code, WP-CLI and the archive's tools run through ``s``, which is
        # ``runuser -u`` with a cleared environment; the only PHP run as root is the fixed
        # FastCGI client, which loads no application file, and the tool check.
        self.assertRegex(body, r's\(\)\{ runuser -u "\$u" -- /usr/bin/env -i ')
        self.assertNotIn("--allow-root", body)
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

    def test_a_changed_pin_refuses_before_anything_is_sent(self) -> None:
        plan = self.reviewed()
        with mock.patch.object(core_native, "ARCHIVE_SHA256", "0" * 64):
            run = self.apply(plan)
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.failure, install_apply.EVIDENCE_FAILURE)
        self.assertEqual(self.systemd.submissions, [])

    def test_a_payload_that_differs_from_its_review_is_never_sent(self) -> None:
        plan = self.reviewed()
        PlanWordpressInstall.objects.filter(plan=plan).update(body_sha256="1" * 64)
        run = self.apply(plan)
        self.assertEqual(run.failure, install_apply.EVIDENCE_FAILURE)
        self.assertEqual(self.systemd.submissions, [])

    def test_missing_evidence_refuses_before_anything_is_sent(self) -> None:
        plan = self.reviewed()
        plan.evidence.filter(kind="wordpress_database").delete()
        run = self.apply(plan)
        self.assertEqual(run.failure, install_apply.EVIDENCE_FAILURE)
        self.assertEqual(self.systemd.submissions, [])


class ApplyOutcomeTests(ApplyTestCase):
    def test_a_verified_installation_requires_the_password_step_and_offers_the_site(self) -> None:
        run = self.apply()
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        self.assertEqual(InstallRunResult.objects.get(run=run).problems, "")
        review = RunWordpressInstall.objects.get(run=run)
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
        self.assertContains(page, f"Publish the provisioning gate (SHA-256 {review.gate_sha256})")

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
            Exit.GATE: (Execution.GATE_REFUSED, "could not be published"),
            Exit.GATE_NOT_SERVING: (Execution.GATE_REFUSED, "did not serve it"),
            Exit.GATE_NOT_RESTORED: (Execution.PARTIAL, "could not be proven restored"),
            Exit.PUBLISH: (Execution.PARTIAL, "Publishing the release files stopped"),
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
            Exit.DRIFT: (Execution.DRIFT, "changed after review"),
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

    def test_refusals_before_changes_say_nothing_changed(self) -> None:
        self.systemd.exit_status = Exit.ARCHIVE
        self.systemd.result = "exit-code"
        run = self.apply()
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "stopped before making any requested change")

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
        self.assertContains(page, "Publish the provisioning gate")
        self.assertContains(page, "Administrator password setup required")
        self.assertTrue(RunWordpressInstall.objects.filter(run=run).exists())
        self.assertTrue(InstallRunResult.objects.filter(run=run).exists())

    def test_an_active_installation_protects_the_server_from_removal(self) -> None:
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


class SecretSurfaceTests(ApplyTestCase):
    def test_no_record_or_page_holds_a_password_or_a_salt(self) -> None:
        plan = self.reviewed()
        run = self.apply(plan)
        submitted = self.systemd.submissions[0]
        encoded = re.search(r"([A-Za-z0-9+/=]{200,})", submitted)
        assert encoded is not None
        surfaces = [kept_text(plan), submitted.replace(encoded[1], ""), staged_body(submitted)]
        surfaces += [
            f"{field.attname}={getattr(row, field.attname)}"
            for row in (run, RunWordpressInstall.objects.get(run=run))
            for field in row._meta.concrete_fields
        ]
        surfaces.append(InstallRunResult.objects.get(run=run).problems)
        surfaces += [
            self.client.get(url).content.decode()
            for url in (f"/plans/{plan.pk}/", f"/applies/{run.pk}/")
        ]
        surfaces += [command for command in self.remote.commands if "sudo" not in command]
        text = "\n".join(surfaces)
        # Passwords and salts are generated on the server and exist nowhere on the controller:
        # no 32 to 64 character random token other than the digests and unit names it records.
        for token in set(re.findall(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9]{32}(?![A-Za-z0-9+/=])", text)):
            self.assertRegex(
                token, r"^[0-9a-f]{32}$", "a generated-looking token on the controller"
            )
        for word in ("AUTH_KEY'", "NONCE_SALT'", "--admin_password", "admin_password="):
            self.assertNotIn(word, text.replace("define(", ""))
