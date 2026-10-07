"""PHP driver plans (docs/databases.md#php-database-drivers): request, worker, review.

Real views, services, the lifecycle, the worker, persistence and rendering run; only remote
execution is substituted, with ``SiteServer`` answering at ``discovery.ssh.connect``.
"""

import re
import shlex
from typing import ClassVar, override
from unittest import mock

from django.http.response import HttpResponseBase

from bootstrap import apply as bootstrap_apply
from bootstrap import native
from bootstrap.fakes import RESOLUTE_PACKAGING, NativeSystemd, Packaging
from bootstrap.models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEffect,
    PlanEvidence,
    PlanPreparation,
    PlanRefusal,
    Verification,
)
from bootstrap.profiles import PROFILES
from operations.models import RemoteOperation
from servers.testing import HTMX_FRAGMENT
from sites.fakes import SiteTestCase

from .models import DatabaseRequest, PlanDriverPool

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
DATABASE_PERMISSIONS = ("view_server", "view_databaseplan", "prepare_databaseplan")


class DriverTestCase(SiteTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.site.sites["blog"] = (("blog.example.com",), True, True)
        self.site.pools.add("blog")
        self.site.sockets.add("/run/php/sblog.sock")

    def prepare_driver(
        self, action: str = Action.PHP_MYSQL, *, perms: tuple[str, ...] = DATABASE_PERMISSIONS
    ) -> HttpResponseBase:
        self.sign_in_with(*perms)
        self.site.answer(self.remote)
        response = self.client.post(
            f"/servers/{self.server.pk}/databases/prepare/", {"action": action}
        )
        self.run_worker()
        return response

    def driver_plan(self, action: str = Action.PHP_MYSQL) -> ConfigurationPlan:
        self.prepare_driver(action)
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        plan = ConfigurationPlan.objects.filter(preparation=preparation).first()
        if plan is None:
            raise AssertionError(f"No plan: {preparation.status} {preparation.failure}")
        return plan

    def texts(self, plan: ConfigurationPlan) -> str:
        return " ".join(plan.refusals.values_list("text", flat=True))


class DriverReviewTests(DriverTestCase):
    def test_explicit_branch_and_supply_are_kept_with_the_request(self) -> None:
        self.sign_in_with(*DATABASE_PERMISSIONS)
        self.site.answer(self.remote)
        self.client.post(
            f"/servers/{self.server.pk}/databases/prepare/",
            {"action": Action.PHP_MYSQL, "php_version": "8.4", "php_supply": "sury"},
        )
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        request = DatabaseRequest.objects.get(preparation=preparation)
        self.assertEqual((request.php_version, request.php_supply), ("8.4", "sury"))
        self.run_worker()
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertFalse(plan.eligible)
        self.assertEqual((plan.php_version, plan.php_supply), ("8.4", "sury"))

    def test_site_context_uses_the_fresh_native_site_selection(self) -> None:
        self.site.add_site("blog", ("blog.example.com",))
        self.sign_in_with(*DATABASE_PERMISSIONS)
        self.site.answer(self.remote)
        self.client.post(
            f"/servers/{self.server.pk}/databases/prepare/",
            {"action": Action.PHP_MYSQL, "from": "blog", "origin": "database"},
        )
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        request = DatabaseRequest.objects.get(preparation=preparation)
        self.assertEqual(request.identifier, "blog")
        self.run_worker()
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertTrue(plan.eligible, self.texts(plan))
        self.assertEqual(plan.php_version, self.packaging.release.php)
        self.assertTrue(plan.evidence.filter(kind=PlanEvidence.Kind.SITE_REVALIDATION).exists())

    def test_a_server_with_php_and_a_site_admits_the_mariadb_driver(self) -> None:
        plan = self.driver_plan()
        self.assertTrue(plan.eligible, self.texts(plan))
        php = self.packaging.release.php
        self.assertEqual(
            list(plan.transitions.values_list("step", "package")),
            [("install", f"php{php}-mysql"), ("configure", f"php{php}-mysql")],
        )
        self.assertEqual(
            list(plan.roots.values_list("name", "version", "installed")),
            [(f"php{php}-mysql", self.packaging.php_version, False)],
        )
        kinds = list(plan.effects.values_list("kind", flat=True))
        for kind in (
            Effect.PACKAGES,
            Effect.PACKAGE_GUARD,
            Effect.MAINTAINER_START,
            Effect.SERVICE_RELOAD,
            Effect.DRIVER_MODULES,
            Effect.INVALIDATES_PLANS,
            Effect.NO_ROLLBACK,
        ):
            self.assertIn(kind, kinds)
        reload = plan.effects.get(kind=Effect.SERVICE_RELOAD).text
        self.assertIn("blog as sblog on /run/php/sblog.sock", reload)
        self.assertIn(f"www as www-data on /run/php/php{php}-fpm.sock", reload)
        self.assertEqual(
            list(PlanDriverPool.objects.filter(plan=plan).values_list("name", "default")),
            [("www", True), ("blog", False)],
        )
        closure = plan.evidence.get(kind=PlanEvidence.Kind.FPM_CLOSURE).summary
        self.assertIn("recognized pools: www, blog (sblog)", closure)

    def test_the_postgresql_driver_brings_libpq(self) -> None:
        plan = self.driver_plan(Action.PHP_PGSQL)
        self.assertTrue(plan.eligible, self.texts(plan))
        packages = plan.transitions.filter(step="install").values_list("package", flat=True)
        self.assertEqual(list(packages), ["libpq5", f"php{self.packaging.release.php}-pgsql"])

    def test_the_review_is_rendered_with_the_pools(self) -> None:
        self.driver_plan()
        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertContains(page, "PHP-FPM pools the reload restarts")
        self.assertContains(page, "<code>sblog</code>")
        self.assertContains(page, "Prepare PHP PostgreSQL driver plan")

    def test_an_installed_driver_with_its_modules_is_a_no_op(self) -> None:
        self.site.drivers = ("mysql",)
        plan = self.driver_plan()
        self.assertTrue(plan.eligible and plan.no_changes, self.texts(plan))

    def test_a_disabled_module_is_customized(self) -> None:
        php = f"/etc/php/{self.packaging.release.php}"
        self.site.drivers = ("mysql",)
        self.site.ubuntu.unloaded_modules = ("mysqli",)
        self.site.removed.add(f"{php}/fpm/conf.d/20-mysqli.ini")
        plan = self.driver_plan()
        self.assertIn(Reason.CUSTOMIZED, self.reasons(plan))
        self.assertIn("sudo phpenmod mysqlnd mysqli pdo_mysql", self.texts(plan))
        self.assertIn("mysqli (not loaded)", self.texts(plan))

    def test_php_must_be_installed_first(self) -> None:
        self.site.ubuntu.php = "absent"
        plan = self.driver_plan()
        self.assertIn(Reason.PREREQUISITE, self.reasons(plan))
        self.assertIn("Prepare and apply the PHP profile first", self.texts(plan))

    def test_an_installed_php_the_archive_no_longer_offers_is_refused(self) -> None:
        php = self.packaging.release.php
        older = "8.3.6-0ubuntu0.24.04.5" if php == "8.3" else "8.5.4-0ubuntu1.1"
        self.site.ubuntu.installed_versions = {f"php{php}-common": older}
        plan = self.driver_plan()
        self.assertEqual(self.reasons(plan), [Reason.INSTALLED_PACKAGE_CHANGE])
        self.assertIn(
            f"php{php}-common {older} is installed, and php{php}-mysql depends on exactly "
            "that version",
            self.texts(plan),
        )
        self.assertIn(f"sudo apt-get install --only-upgrade php{php}-common", self.texts(plan))
        self.assertEqual(plan.transitions.count(), 0)

    def test_a_custom_file_in_the_pool_directory_is_customized(self) -> None:
        pool = f"/etc/php/{self.packaging.release.php}/fpm/pool.d/custom.conf"
        self.site.files[pool] = "[custom]\nuser = nobody\n"
        plan = self.driver_plan()
        self.assertIn(Reason.CUSTOMIZED, self.reasons(plan))
        self.assertIn(
            f"{pool} (not a distribution file or an exact site template)", self.texts(plan)
        )

    def test_the_stock_php_profile_still_refuses_site_pools(self) -> None:
        self.sign_in_with("view_server", "view_configurationplan", "prepare_configurationplan")
        self.site.answer(self.remote)
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": "php"})
        self.run_worker()
        plan = ConfigurationPlan.objects.latest("pk")
        self.assertIn(Reason.CUSTOMIZED, self.reasons(plan))

    def test_reading_the_pools_needs_privilege(self) -> None:
        self.site.privilege = "narrow"
        plan = self.driver_plan()
        self.assertIn(Reason.PRIVILEGE, self.reasons(plan))
        self.assertFalse(PlanDriverPool.objects.filter(plan=plan).exists())
        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertNotContains(page, "PHP-FPM pools the reload restarts")


class ResoluteDriverReviewTests(DriverReviewTests):
    packaging: ClassVar[Packaging] = RESOLUTE_PACKAGING


class DriverPermissionTests(DriverTestCase):
    def test_bootstrap_and_site_permissions_grant_nothing(self) -> None:
        response = self.prepare_driver(
            perms=("view_server", "view_configurationplan", "prepare_configurationplan")
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(PlanPreparation.objects.exists())
        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertNotContains(page, "Database plans")

    def test_viewers_see_the_section_without_the_buttons(self) -> None:
        self.sign_in_with("view_server", "view_databaseplan")
        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertContains(page, "Database plans")
        self.assertNotContains(page, "Prepare PHP MariaDB driver plan")

    def test_an_unknown_action_is_refused(self) -> None:
        response = self.prepare_driver("nginx")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(PlanPreparation.objects.exists())

    def test_the_section_is_a_fragment_for_htmx(self) -> None:
        self.prepare_driver()
        response = self.client.get(f"/servers/{self.server.pk}/databases/", headers=HTMX_FRAGMENT)
        self.assertContains(response, 'id="database-plans"')


class DriverPayloadTests(DriverTestCase):
    def test_the_payload_reloads_and_waits_for_every_pool(self) -> None:
        php = self.packaging.release.php
        profile = PROFILES[self.packaging.release.version][Action.PHP_MYSQL]
        steps = native.reload_steps(profile.reload, (f"/run/php/php{php}-fpm.sock",))
        self.assertIn(f"systemctl reload php{php}-fpm.service || exit 26", steps[0])
        with self.assertRaises(ValueError):
            native.reload_steps(profile.reload, ("/tmp/x.sock",))  # noqa: S108 - refused path
        with self.assertRaises(ValueError):
            native.reload_steps(profile.reload, ())


DRIVER_APPLY = (*DATABASE_PERMISSIONS, "apply_databaseplan")
# What applying adds to preparation's reads: the submission, its inspection and the
# verification's reads.
APPLY_READS = re.compile(
    r"\A(sudo -n (-l )?)?/usr/bin/systemd-run --unit=barectl-apply-[0-9a-f]{32}"
    r"|\A(id -u|cat /proc/sys/kernel/random/boot_id; systemctl show .*)\Z"
    r"|\Asystemctl list-units .*|\Asha256sum /var/lib/dpkg/status.*"
    r"|\Aapt-mark (showauto|showmanual).*"
    r"|\Areadlink -f -- /etc/php/8\.[35]/(fpm|cli)/conf\.d/\S+\Z",
    re.DOTALL,
)


class DriverApplyTests(DriverTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.systemd = NativeSystemd()
        self.systemd.answer(self.remote)
        self.systemd.on_submit = self.installed
        self.enterContext(mock.patch.object(bootstrap_apply, "POLL_INTERVAL", 0))

    @override
    def assert_read_only(self) -> None:
        self.remote.commands[:] = [c for c in self.remote.commands if not APPLY_READS.match(c)]
        super().assert_read_only()

    def installed(self) -> None:
        if self.systemd.exit_status == 0:
            self.site.drivers = ("mysql",)
            self.site.answer(self.remote)

    def apply(self) -> ApplyRun:
        plan = self.driver_plan()
        self.assertTrue(plan.eligible, self.texts(plan))
        self.sign_in_with(*DRIVER_APPLY)
        self.client.post(f"/plans/{plan.pk}/apply/")
        self.run_worker()
        return ApplyRun.objects.get(plan_number=plan.pk)

    def payload(self) -> str:
        (submission,) = self.systemd.submissions
        return shlex.split(submission)[-1]

    def test_a_driver_plan_installs_checks_reloads_and_verifies(self) -> None:
        run = self.apply()
        php = self.packaging.release.php
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (RemoteOperation.Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        payload = self.payload()
        self.assertIn(f"install php{php}-mysql={self.packaging.php_version}", payload)
        check = payload.index(f"/usr/sbin/php-fpm{php} -t")
        reload = payload.index(f"systemctl reload php{php}-fpm.service || exit 26")
        self.assertLess(check, reload)
        self.assertIn(f"/run/php/php{php}-fpm.sock /run/php/sblog.sock", payload)
        self.assertIn(f"Install php{php}-mysql", run.reviewed_changes)
        self.assertIn("blog as sblog on /run/php/sblog.sock", run.effects)

    def test_a_failed_reload_is_named(self) -> None:
        self.systemd.exit_status = native.Exit.RELOAD_FAILED
        self.systemd.result = "exit-code"
        run = self.apply()
        self.assertEqual(run.execution, Execution.RELOAD_FAILED)
        self.assertIn("could not reload the service", run.failure)

    def test_a_failed_check_is_named_without_a_reload(self) -> None:
        self.systemd.exit_status = native.Exit.VALIDATION_FAILED
        self.systemd.result = "exit-code"
        run = self.apply()
        self.assertEqual(run.execution, Execution.VALIDATION_FAILED)
        self.assertIn("so Barectl did not reload PHP-FPM", run.failure)

    def test_a_site_pool_that_does_not_listen_again_fails_verification(self) -> None:
        def installed_without_the_site_socket() -> None:
            self.installed()
            self.site.sockets.discard("/run/php/sblog.sock")

        self.systemd.on_submit = installed_without_the_site_socket
        run = self.apply()
        self.assertEqual(run.verification, Verification.FAILED)
        self.assertIn("a reviewed pool's socket is not listening", run.failure)
