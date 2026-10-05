"""Applying site plans through requests, the worker and a simulated server.

Real views, services, the lifecycle, the worker, persistence and rendering run; the server
is ``SiteServer`` with ``bootstrap.fakes.NativeSystemd`` answering submission and
inspection. These tests establish the local workflow, permissions, audit and the meaning of
each exit status; ``sites/test_faults_remote.py`` establishes the native behaviour.
"""

from typing import override
from unittest import mock

from django.contrib.auth.models import Permission
from django.test import Client

from bootstrap import apply as bootstrap_apply
from bootstrap.fakes import PLAN_PERMISSIONS, NativeSystemd
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, Verification
from discovery.fakes import add_site as discovery_site
from discovery.fakes import current, record_attempt
from discovery.models import DiscoveryAttempt
from discovery.services import request_discovery
from operations.models import RemoteOperation
from servers.discovery_state import SitePage, SnapshotNotice
from servers.registration import remove_server

from . import native
from .convention import SitePaths
from .fakes import SITE_PERMISSIONS, Node, SiteTestCase
from .handler import VERIFIED_SCOPE
from .models import RunAccountChange, RunDirectoryChange, RunFileChange, RunSite, SiteRunResult

Status = RemoteOperation.Status
Exit = native.Exit
APPLY = (*SITE_PERMISSIONS, "apply_siteplan")
NAMES = ("shop.example.com", "www.shop.example.com")


class SiteApplyTests(SiteTestCase):
    systemd: NativeSystemd

    @override
    def setUp(self) -> None:
        super().setUp()
        self.systemd = NativeSystemd()
        self.systemd.on_submit = self.created
        self.enterContext(mock.patch.object(bootstrap_apply, "POLL_INTERVAL", 0))

    def created(self) -> None:
        """A successful run creates the site, as the payload does on a real server."""
        if self.systemd.exit_status == 0:
            self.site.add_site("shop", NAMES)
            # The following discovery reads the site the run created.
            discovery_site(self.remote, "shop", NAMES)
            self.site.answer(self.remote)

    @override
    def assert_read_only(self) -> None:
        submissions = [
            c.split("--unit=", 1)[1].split()[0]
            for c in self.remote.commands
            if c.startswith(
                ("/usr/bin/systemd-run --unit=", "sudo -n /usr/bin/systemd-run --unit=")
            )
        ]
        self.assertEqual(len(submissions), len(set(submissions)), "A run was submitted twice")

    def site_plan(self) -> ConfigurationPlan:
        self.prepare_site(perms=APPLY)
        self.systemd.answer(self.remote)
        plan = ConfigurationPlan.objects.latest("pk")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan

    def apply(self, plan: ConfigurationPlan | None = None) -> ApplyRun:
        plan = plan or self.site_plan()
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get(plan_number=plan.pk)
        self.run_worker()
        run.refresh_from_db()
        return run

    def test_a_confirmed_run_is_submitted_verified_and_audited(self) -> None:
        plan = self.site_plan()
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(
            page, f"Apply plan {plan.pk}, HTTP PHP site, revision 3, to <strong>Web</strong>"
        )
        self.assertContains(page, "admission deadline")
        run = self.apply(plan)
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        (submission,) = self.systemd.submissions
        digest = native.site_digest(SitePaths("shop", "8.3"))
        self.assertIn(digest.replace("'", "'\"'\"'"), submission)
        result = SiteRunResult.objects.get(run=run)
        self.assertEqual(
            (result.uid, result.gid, result.probe_absent, result.problems), (1003, 1003, True, "")
        )
        # The audit keeps the reviewed changes, typed and as text.
        self.assertEqual(RunSite.objects.get(run=run).names, "\n".join(NAMES))
        self.assertEqual(RunFileChange.objects.filter(run=run).count(), 5)
        self.assertEqual(RunDirectoryChange.objects.filter(run=run).count(), 3)
        self.assertEqual(RunAccountChange.objects.get(run=run).user, "sshop")
        audit = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(audit, "Publish /etc/nginx/sites-available/shop.conf")
        self.assertContains(audit, "Create directory /var/www/shop/private, sshop:sshop 0700")
        self.assertContains(audit, "sshop was bound to UID 1003 and GID 1003.")
        self.assertContains(audit, "The temporary probe was removed.")
        # Discovery follows the run.
        self.assertTrue(DiscoveryAttempt.objects.filter(server=self.server).exists())
        # Removing the registration keeps the audit.
        remove_server(self.server)
        self.assertEqual(RunFileChange.objects.filter(run=run).count(), 5)
        self.assertContains(self.client.get(f"/applies/{run.pk}/"), "registration removed")

    def test_a_verified_run_links_to_the_current_site_page(self) -> None:
        self.grant("view_siteobservation")
        run = self.apply()
        # The post-apply discovery is queued by the run; the worker completes it.
        self.run_worker()
        sites = current(self.server).collected.sites
        self.assertEqual(sites.outcome.name, "OBSERVED", sites.warning)
        self.assertEqual([site.identifier for site in sites.value], ["shop"])
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Observed as a current site")
        self.assertContains(page, f'href="/servers/{self.server.pk}/sites/shop/overview/"')
        self.assertContains(page, "Open site shop.example.com, www.shop.example.com")
        # The placeholder check was local; public DNS and deployment are not claimed.
        self.assertContains(page, VERIFIED_SCOPE)

    def test_a_verified_run_without_a_current_observation_links_to_the_server(self) -> None:
        self.grant("view_siteobservation")
        run = self.apply()
        # The site is not in a current complete observation (a pending or failed refresh).
        unknown = SitePage(
            "shop", None, "unknown", SnapshotNotice("The latest check failed.", emphasized=True)
        )
        with mock.patch("sites.handler.site_page", return_value=unknown):
            page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "no current complete observation of this site")
        self.assertContains(page, VERIFIED_SCOPE)
        self.assertContains(page, f'href="/servers/{self.server.pk}/"')
        self.assertNotContains(page, "Observed as a current site")

    def test_a_later_check_leaves_the_post_run_observation_stale(self) -> None:
        self.grant("view_siteobservation")
        run = self.apply()
        self.run_worker()
        for status, text in (
            (RemoteOperation.Status.QUEUED, "a newer connection check is refreshing"),
            (RemoteOperation.Status.RUNNING, "a newer connection check is refreshing"),
            (RemoteOperation.Status.FAILED, "the latest connection check failed"),
        ):
            record_attempt(request_discovery(self.server), status)
            with self.subTest(status=status):
                page = self.client.get(f"/applies/{run.pk}/")
                self.assertContains(page, "The run is verified and the site was observed at")
                self.assertContains(page, text)
                self.assertContains(page, f'href="/servers/{self.server.pk}/sites/shop/overview/"')
                self.assertNotContains(page, "Observed as a current site")

    def test_the_completion_needs_the_site_observation_permission(self) -> None:
        # A plan viewer without the observation permission never sees the site's evidence.
        run = self.apply()
        self.run_worker()
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertNotContains(page, "Observed as a current site")
        self.assertNotContains(page, "Open site")
        self.assertNotContains(page, "#run-completion")
        self.assertNotContains(page, VERIFIED_SCOPE)

    def test_each_exit_status_names_its_boundary(self) -> None:
        cases = {
            Exit.DRIFT: (Execution.DRIFT, "changed after review"),
            Exit.ACCOUNT_BUSY: (Execution.ACCOUNT_BUSY, "useradd could not change"),
            Exit.ACCOUNT: (Execution.PARTIAL, "may or may not exist"),
            Exit.ACCOUNT_MISMATCH: (Execution.PARTIAL, "userdel sshop only if nothing"),
            Exit.DIRECTORIES: (Execution.PARTIAL, "ls -ld /var/www/shop"),
            Exit.CONTENT: (Execution.PARTIAL, "Remove the probe"),
            Exit.POOL: (Execution.PARTIAL, "PHP-FPM was not reloaded"),
            Exit.POOL_WITHDRAWN: (Execution.PARTIAL, "configuration is valid"),
            Exit.POOL_INVALID: (Execution.PARTIAL, "php-fpm8.3 -t"),
            Exit.FPM_RELOAD: (Execution.PARTIAL, "systemctl status php8.3-fpm.service"),
            Exit.SOCKET: (Execution.PARTIAL, "ls -l /run/php/sshop.sock"),
            Exit.SITE_FILE: (Execution.PARTIAL, "the site is not enabled"),
            Exit.SITE_LINK: (Execution.PARTIAL, "ls -l /etc/nginx/sites-enabled/shop.conf"),
            Exit.LINK_WITHDRAWN: (Execution.PARTIAL, "is not loaded"),
            Exit.NGINX_INVALID: (Execution.PARTIAL, "rm /etc/nginx/sites-enabled/shop.conf"),
            Exit.NGINX_RELOAD: (Execution.PARTIAL, "systemctl status nginx.service"),
            Exit.NOT_SERVING: (Execution.PARTIAL, "The probe was removed"),
            Exit.PROBE_LEFT: (Execution.PARTIAL, "verification is incomplete"),
        }
        for status, (execution, text) in cases.items():
            with self.subTest(status=status):
                ApplyRun.objects.all().delete()
                DiscoveryAttempt.objects.all().delete()
                self.systemd.exit_status = status
                self.systemd.result = "exit-code"
                run = self.apply()
                self.assertEqual(
                    (run.status, run.execution, run.exit_status, run.verification),
                    (Status.FAILED, execution, status, Verification.NOT_APPLICABLE),
                )
                self.assertIn(text, run.failure)
                self.assertNotIn("userdel sshop;", run.failure)
                refused = execution in Execution.refused_before_changes()
                self.assertEqual(DiscoveryAttempt.objects.exists(), not refused)
                if not refused:
                    self.assertIn("never resumes or adopts a partial site", run.failure)

    def test_a_site_that_differs_from_the_review_fails_verification(self) -> None:
        self.systemd.on_submit = self.created_wrong
        run = self.apply()
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.FAILED, Execution.SUCCEEDED, Verification.FAILED),
        )
        self.assertIn("/var/www/shop/private does not have its reviewed owner", run.failure)
        self.assertIn("www.shop.example.com did not return the placeholder", run.failure)

    def created_wrong(self) -> None:
        self.site.add_site("shop", NAMES)
        self.site.paths["/var/www/shop/private"] = Node("d", 0o755, 1003, 1003, "sshop", "sshop")
        self.site.serving = False

    def test_a_verification_read_that_is_not_authorized_refuses_submission(self) -> None:
        plan = self.site_plan()
        self.site.privilege = "narrow"
        self.systemd.on_submit = self.created
        run = self.apply(plan)
        # The state read is not authorized any more, so nothing was submitted.
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Execution.NOT_SUBMITTED)
        self.assertEqual(self.systemd.submissions, [])

    def test_verification_that_cannot_read_is_unavailable(self) -> None:
        def narrowed() -> None:
            self.site.add_site("shop", NAMES)
            self.site.privilege = "narrow"

        self.systemd.on_submit = narrowed
        run = self.apply()
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.FAILED, Execution.SUCCEEDED, Verification.UNAVAILABLE),
        )
        self.assertFalse(SiteRunResult.objects.exists())

    def test_applying_needs_the_site_apply_permission_at_request_and_dispatch(self) -> None:
        plan = self.site_plan()
        self.user.user_permissions.clear()
        for cache in ("_perm_cache", "_user_perm_cache", "_group_perm_cache"):
            self.user.__dict__.pop(cache, None)
        self.sign_in_with(*SITE_PERMISSIONS, *PLAN_PERMISSIONS, "apply_configurationplan")
        self.assertEqual(self.client.post(f"/plans/{plan.pk}/apply/").status_code, 403)
        self.assertNotContains(self.client.get(f"/plans/{plan.pk}/"), "Apply plan")
        self.grant("apply_siteplan")
        for cache in ("_perm_cache", "_user_perm_cache", "_group_perm_cache"):
            self.user.__dict__.pop(cache, None)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run = ApplyRun.objects.get()
        # The account loses the permission before the worker dispatches.
        self.user.user_permissions.remove(
            *self.user.user_permissions.filter(codename="apply_siteplan")
        )
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.NOT_SUBMITTED))
        self.assertIn("no longer allowed", run.failure)
        self.assertEqual(self.systemd.submissions, [])

    def test_confirmation_is_csrf_protected_and_repeats_converge(self) -> None:
        plan = self.site_plan()
        checked = Client(enforce_csrf_checks=True)
        checked.force_login(self.user)
        self.assertEqual(checked.post(f"/plans/{plan.pk}/apply/").status_code, 403)
        self.assertFalse(ApplyRun.objects.exists())
        first = self.client.post(f"/plans/{plan.pk}/apply/")
        second = self.client.post(f"/plans/{plan.pk}/apply/")
        self.assertEqual(first["Location"], second["Location"])
        self.assertEqual(ApplyRun.objects.count(), 1)

    def test_a_lost_answer_is_checked_and_an_unknown_outcome_needs_the_apply_permission(
        self,
    ) -> None:
        plan = self.site_plan()
        self.systemd.lose_acknowledgement = True
        run = self.apply(plan)
        self.assertEqual(run.status, Status.RECONCILING)
        # The unit is gone when checked, as after a restart.
        self.systemd.units.clear()
        self.systemd.lose_acknowledgement = False
        self.client.post(f"/applies/{run.pk}/check/")
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual((run.status, run.execution), (Status.RECONCILING, Execution.NOT_FOUND))
        # An account that may view but not apply site plans cannot close it.
        viewer = type(self.user).objects.create_user("viewer")
        self.client.force_login(viewer)
        for codename in ("view_server", "view_siteplan", "apply_configurationplan"):
            viewer.user_permissions.add(Permission.objects.get(codename=codename))
        response = self.client.post(f"/applies/{run.pk}/acknowledge/", {"understood": "on"})
        self.assertEqual(response.status_code, 403)
        self.client.force_login(self.user)
        self.systemd.uptime_centiseconds = 10**12
        self.client.post(f"/applies/{run.pk}/acknowledge/", {"understood": "on"})
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.OUTCOME_UNKNOWN))
        self.assertEqual(len(self.systemd.submissions), 1)
