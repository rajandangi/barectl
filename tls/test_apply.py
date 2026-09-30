"""Applying challenge route plans through requests, the worker and a simulated server.

The server is ``SiteServer`` with ``bootstrap.fakes.NativeSystemd`` answering submission and
inspection; ``tls/test_challenge_remote.py`` establishes the native behaviour.
"""

from typing import override
from unittest import mock

from bootstrap import apply as bootstrap_apply
from bootstrap.fakes import NativeSystemd
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, Verification
from operations.models import RemoteOperation
from servers.registration import remove_server

from . import native
from .fakes import NAMES, TLS_PERMISSIONS, TlsTestCase
from .models import ChallengeRunResult, RunChallenge

Status = RemoteOperation.Status
Exit = native.Exit
APPLY = (*TLS_PERMISSIONS, "apply_tlsplan")


class ChallengeApplyTests(TlsTestCase):
    systemd: NativeSystemd

    @override
    def setUp(self) -> None:
        super().setUp()
        self.site.add_site("shop", NAMES)
        self.systemd = NativeSystemd()
        self.systemd.on_submit = self.applied
        self.enterContext(mock.patch.object(bootstrap_apply, "POLL_INTERVAL", 0))

    def applied(self) -> None:
        """A successful run leaves the route, as the payload does on a real server."""
        if self.systemd.exit_status == 0:
            challenge = RunChallenge.objects.latest("pk")
            self.site.add_challenge("shop", backup=challenge.backup_path)

    @override
    def assert_read_only(self) -> None:
        """Apply runs change the server; each is submitted once."""

    def route_plan(self) -> ConfigurationPlan:
        self.prepare_challenge(perms=APPLY)
        self.systemd.answer(self.remote)
        plan = ConfigurationPlan.objects.latest("pk")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan

    def apply(self) -> ApplyRun:
        plan = self.route_plan()
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.run_worker()
        run.refresh_from_db()
        return run

    def test_a_confirmed_route_is_submitted_verified_and_audited(self) -> None:
        run = self.apply()
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        self.assertEqual(len(self.systemd.submissions), 1)
        challenge = RunChallenge.objects.get(run=run)
        suffix = run.unit_name.removeprefix("barectl-apply-").removesuffix(".service")
        self.assertEqual(challenge.backup_path, f"/var/backups/nginx/shop.conf.{suffix}")
        self.assertEqual(ChallengeRunResult.objects.get(run=run).problems, "")
        audit = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(audit, "Replace /etc/nginx/sites-available/shop.conf")
        self.assertContains(audit, f"The preimage is kept at {challenge.backup_path}.")
        remove_server(self.server)
        self.assertContains(self.client.get(f"/applies/{run.pk}/"), "registration removed")

    def test_each_exit_status_names_its_boundary(self) -> None:
        cases = {
            Exit.DRIFT: (Execution.DRIFT, "changed after review"),
            Exit.DIRECTORIES: (Execution.PARTIAL, "was not changed"),
            Exit.REPLACEMENT: (Execution.PARTIAL, "could not be replaced"),
            Exit.RESTORED: (Execution.PARTIAL, "was restored from"),
            Exit.NOT_RESTORED: (Execution.PARTIAL, "Restore the preimage with cp"),
            Exit.NGINX_RELOAD: (Execution.PARTIAL, "systemctl status nginx.service"),
            Exit.NOT_SERVING: (Execution.PARTIAL, "The probe was removed"),
            Exit.PROBE_LEFT: (Execution.PARTIAL, "verification is incomplete"),
            25: (Execution.RENEWAL_ACTIVE, "renewal service still had processes"),
        }
        for status, (execution, text) in cases.items():
            with self.subTest(status=status):
                ApplyRun.objects.all().delete()
                self.systemd.exit_status = status
                self.systemd.result = "exit-code"
                run = self.apply()
                self.assertEqual(
                    (run.status, run.execution, run.exit_status, run.verification),
                    (Status.FAILED, execution, status, Verification.NOT_APPLICABLE),
                )
                self.assertIn(text, run.failure)

    def test_a_route_unlike_the_review_fails_verification(self) -> None:
        self.systemd.on_submit = None
        run = self.apply()
        self.assertEqual((run.status, run.verification), (Status.FAILED, Verification.FAILED))
        problems = ChallengeRunResult.objects.get(run=run).problems
        self.assertIn("/etc/nginx/sites-available/shop.conf does not have", problems)
        self.assertIn("/var/lib/letsencrypt/shop is not a directory", problems)
        self.assertIn("does not hold the preimage", problems)

    def test_applying_needs_its_own_permission(self) -> None:
        self.prepare_challenge()
        plan = ConfigurationPlan.objects.latest("pk")
        response = self.client.post(f"/plans/{plan.pk}/apply/")
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ApplyRun.objects.exists())
