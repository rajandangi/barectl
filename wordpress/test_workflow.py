"""The request-to-worker-to-plan-to-apply workflow for the WP-CLI tool setup.

Real views, services, the lifecycle, the ``db_worker`` command, persistence and rendering
run; only remote execution is substituted, with a simulated Ubuntu server answering at
``discovery.ssh.connect`` (docs/wordpress.md#wp-cli-setup).
"""

from typing import override
from unittest import mock

from bootstrap import apply as bootstrap_apply
from bootstrap.fakes import PLAN_PERMISSIONS, NativeSystemd, PreparationTestCase
from bootstrap.models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEffect,
    PlanPreparation,
    Verification,
)
from bootstrap.plan_testing import kept_text
from discovery.fakes import READ_ONLY
from operations.models import RemoteOperation
from servers.registration import remove_server

from . import setup_native
from .fakes import WpcliServer, wpcli_read_only
from .models import PlanWpcliTool, RunWpcliTool, WpcliRunResult
from .setup import PROFILE_REVISION

Status = RemoteOperation.Status
Effect = PlanEffect.Kind
PERMISSIONS = (*PLAN_PERMISSIONS, "apply_configurationplan")


class WpcliTestCase(PreparationTestCase):
    """WP-CLI setup through requests and the worker, against a simulated server."""

    wpcli: WpcliServer

    @override
    def setUp(self) -> None:
        super().setUp()
        self.wpcli = WpcliServer()
        self.wpcli.answer(self.remote)

    @override
    def assert_read_only(self) -> None:
        from bootstrap.fakes import PREPARATION_READ_ONLY

        for command in self.remote.commands:
            self.assertTrue(
                READ_ONLY.fullmatch(command)
                or PREPARATION_READ_ONLY.fullmatch(command)
                or wpcli_read_only(command),
                f"Not a read-only command: {command}",
            )

    def prepare_setup(self, *, perms: tuple[str, ...] = PERMISSIONS) -> PlanPreparation:
        """Request a WP-CLI setup preparation as an operator with ``perms``."""
        self.sign_in_with(*perms)
        self.ubuntu.answer(self.remote)
        self.wpcli.answer(self.remote)
        self.client.post(f"/servers/{self.server.pk}/wordpress/wp-cli/prepare/")
        self.run_worker()
        return PlanPreparation.objects.latest("queued_at", "pk")


class PreparationTests(WpcliTestCase):
    def test_a_request_queues_work_that_the_worker_turns_into_a_reviewed_plan(self) -> None:
        self.sign_in_with(*PLAN_PERMISSIONS)
        self.ubuntu.answer(self.remote)
        response = self.client.post(f"/servers/{self.server.pk}/wordpress/wp-cli/prepare/")
        self.assertRedirects(response, f"/servers/{self.server.pk}/advanced/#wordpress-plans")
        preparation = PlanPreparation.objects.get()
        self.assertEqual((preparation.status, preparation.action), (Status.QUEUED, Action.WPCLI))
        self.assertEqual(self.remote.targets, [])
        self.run_worker()
        preparation.refresh_from_db()
        self.assertEqual(preparation.status, Status.SUCCEEDED)
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        kinds = [kind for kind, _ in plan.effects.values_list("kind", "text")]
        self.assertEqual(kinds[0], Effect.TOOL_DOWNLOAD)
        tool = PlanWpcliTool.objects.get(plan=plan)
        self.assertEqual(
            (
                tool.version,
                tool.phar_url,
                tool.signature_url,
                tool.key_url,
                tool.fingerprint,
                tool.sha256,
                tool.path,
            ),
            (
                setup_native.VERSION,
                setup_native.PHAR_URL,
                setup_native.SIGNATURE_URL,
                setup_native.KEY_URL,
                setup_native.FINGERPRINT,
                setup_native.SHA256,
                setup_native.PHAR,
            ),
        )
        self.assertTrue(tool.creates_directory)
        self.assertFalse(tool.exists)
        # Preparing read the server only, and the plan page shows the reviewed pins.
        self.assert_read_only()
        page = self.client.get(f"/plans/{preparation.pk}/")
        self.assertContains(page, setup_native.FINGERPRINT)
        self.assertContains(page, setup_native.PHAR_URL)
        self.assertContains(page, "bootstrap permissions")
        advanced = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertContains(advanced, "Prepare WP-CLI setup plan")
        self.assertContains(advanced, "WordPress")

    def test_the_section_shows_a_satisfied_setup_without_changes(self) -> None:
        self.wpcli.install()
        preparation = self.prepare_setup()
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertTrue(plan.no_changes, list(plan.refusals.values_list("text", flat=True)))
        self.assertTrue(PlanWpcliTool.objects.get(plan=plan).exists)
        page = self.client.get(f"/plans/{preparation.pk}/")
        self.assertContains(page, "already satisfies")
        self.assertContains(page, "Installed with these bytes; left as it is")

    def test_a_foreign_artifact_is_refused_without_changes(self) -> None:
        self.wpcli.phar = "foreign"
        preparation = self.prepare_setup()
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertFalse(plan.eligible)
        self.assertIn(
            "does not overwrite foreign tools",
            " ".join(plan.refusals.values_list("text", flat=True)),
        )
        self.assertFalse(PlanWpcliTool.objects.exists())

    def test_missing_native_tools_are_refused(self) -> None:
        self.wpcli.tools = ("gpg",)
        preparation = self.prepare_setup()
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertFalse(plan.eligible)
        self.assertIn("/usr/bin/curl", " ".join(plan.refusals.values_list("text", flat=True)))

    def test_the_request_needs_its_own_permission(self) -> None:
        self.sign_in_with("view_server", "view_configurationplan")
        self.ubuntu.answer(self.remote)
        response = self.client.post(f"/servers/{self.server.pk}/wordpress/wp-cli/prepare/")
        self.assertEqual(response.status_code, 403)
        self.run_worker()
        self.assertFalse(PlanPreparation.objects.exists())

    def test_plans_record_only_public_pins(self) -> None:
        preparation = self.prepare_setup()
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertIn(setup_native.SHA256, kept_text(plan))
        self.assertNotIn("password", kept_text(plan))
        self.assertIn("wpcli_revalidation", kept_text(plan))
        self.assertEqual(plan.profile_revision, PROFILE_REVISION)


class ApplyTests(WpcliTestCase):
    systemd: NativeSystemd

    @override
    def setUp(self) -> None:
        super().setUp()
        self.systemd = NativeSystemd()
        self.systemd.on_submit = self.applied
        self.enterContext(mock.patch.object(bootstrap_apply, "POLL_INTERVAL", 0))

    def applied(self) -> None:
        """A successful run installs the authenticated artifact, as the payload does."""
        if self.systemd.exit_status == 0:
            self.wpcli.install()

    @override
    def assert_read_only(self) -> None:
        """Apply runs change the server; each is submitted once."""

    def apply(self, *, perms: tuple[str, ...] = PERMISSIONS) -> ApplyRun:
        preparation = self.prepare_setup(perms=perms)
        self.systemd.answer(self.remote)
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.run_worker()
        run.refresh_from_db()
        return run

    def test_a_reviewed_setup_downloads_authenticates_and_installs(self) -> None:
        run = self.apply()
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        self.assertEqual(len(self.systemd.submissions), 1)
        submission = self.systemd.submissions[0]
        for pinned in (
            setup_native.PHAR_URL,
            setup_native.SIGNATURE_URL,
            setup_native.KEY_URL,
            setup_native.FINGERPRINT,
            setup_native.SHA256,
        ):
            self.assertIn(pinned, submission)
        # The artifact is never executed anywhere in the submission.
        self.assertNotIn("php", submission.replace("wordpress", ""))
        self.assertTrue(self.wpcli.phar == "installed")
        tool = RunWpcliTool.objects.get(run=run)
        self.assertEqual((tool.version, tool.path), (setup_native.VERSION, setup_native.PHAR))
        self.assertEqual(WpcliRunResult.objects.get(run=run).problems, "")
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, f"Authenticate WP-CLI {setup_native.VERSION}")
        self.assertContains(page, f"Publish {setup_native.PHAR}")
        # The finished audit survives the server's removal.
        remove_server(self.server)
        self.assertContains(self.client.get(f"/applies/{run.pk}/"), "Authenticate WP-CLI")

    def test_each_refusal_names_its_boundary(self) -> None:
        cases = {
            setup_native.Exit.TOOLS: (
                Execution.TOOL_REFUSED,
                "/usr/bin/gpg and /usr/bin/curl",
            ),
            setup_native.Exit.KEY: (Execution.TOOL_REFUSED, "did not authenticate"),
            setup_native.Exit.SIGNATURE: (
                Execution.TOOL_REFUSED,
                "signature is invalid",
            ),
            setup_native.Exit.DOWNLOAD: (Execution.TOOL_REFUSED, "could not be downloaded"),
            setup_native.Exit.FILE: (Execution.PARTIAL, "Stopped at exit status"),
            setup_native.Exit.DRIFT: (Execution.DRIFT, "changed after review"),
        }
        for status, (execution, text) in cases.items():
            with self.subTest(status=status):
                ApplyRun.objects.all().delete()
                PlanPreparation.objects.all().delete()
                self.systemd.exit_status = status
                self.systemd.result = "exit-code"
                self.wpcli.answer(self.remote)
                run = self.apply()
                self.assertEqual(
                    (run.status, run.execution, run.exit_status, run.verification),
                    (Status.FAILED, execution, status, Verification.NOT_APPLICABLE),
                )
                self.assertIn(text, run.failure)
                if execution in Execution.refused_before_changes():
                    self.assertEqual(self.wpcli.phar, "absent")

    def test_the_apply_needs_its_own_permission(self) -> None:
        preparation = self.prepare_setup(perms=PLAN_PERMISSIONS)
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.sign_in_with(*PLAN_PERMISSIONS)
        response = self.client.post(f"/plans/{plan.pk}/apply/")
        self.assertEqual(response.status_code, 403)
        self.run_worker()
        self.assertFalse(ApplyRun.objects.exists())

    def test_verification_reports_a_foreign_result(self) -> None:
        def foreign() -> None:
            self.wpcli.install()
            self.wpcli.phar = "foreign"

        self.systemd.on_submit = lambda: foreign() if self.systemd.exit_status == 0 else None
        run = self.apply()
        self.assertEqual(run.execution, Execution.SUCCEEDED)
        self.assertEqual(run.verification, Verification.FAILED)
        self.assertIn(
            "does not have its reviewed bytes", WpcliRunResult.objects.get(run=run).problems
        )
        self.assertIn("does not have its reviewed bytes", run.failure)
