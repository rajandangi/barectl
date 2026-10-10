"""Actual native alternatives remain independent of controller inventory."""

import shlex
from unittest import skipUnless
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import tag

from databases.native_testing import mariadb, mariadb_binding
from databases.services import request_driver_preparation
from discovery import ssh
from discovery.fakes import run_worker
from sites import runtime_native as site_runtime_native
from sites.services import request_site_preparation

from . import native
from .apply import request_apply
from .models import Action, ApplyRun, ConfigurationPlan, Execution, Verification
from .native_testing import INSTALL_MARIADB, REMOVE_MARIADB
from .php_source_testing import CONFIGURED, PhpSourceCase, trust_fixture
from .runtime_changes import request_php_default, request_site_php_switch
from .runtime_models import RuntimeChange
from .runtime_services import (
    observe_php_runtime,
    request_php_installation,
    request_runtime_preparation,
)
from .services import request_preparation


@tag("ssh")
@skipUnless(CONFIGURED, "The disposable SSH server is not configured.")
class PhpRuntimeAcceptanceTests(PhpSourceCase):
    def test_native_defaults_and_site_switches_keep_independent_selections(self) -> None:
        trust_fixture(self, self.administer)
        self.administer(
            "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq libsodium23 >/dev/null"
        )
        self.assertEqual(self.administer("ldconfig -p | grep -c 'libsodium.so.23 ' || true"), "0\n")
        user = User.objects.get(username="operator")
        with ssh.connect_alias(self.server.ssh_alias) as shell:
            fresh = observe_php_runtime(shell)
        self.assertEqual(fresh.failure, "")
        self.assertTrue(fresh.fresh)
        self.assertIsNone(fresh.default)
        configured = self.apply(self.plan())
        self.assertEqual(configured.verification, Verification.PASSED, configured.failure)
        refreshed = request_preparation(self.server, user, Action.METADATA_REFRESH)
        self.assertIsNotNone(refreshed)
        run_worker()
        refresh = self.apply(ConfigurationPlan.objects.get(preparation=refreshed))
        self.assertEqual(refresh.verification, Verification.PASSED, refresh.failure)
        first = request_php_default(self.server, user, "8.3")
        self.assertIsNotNone(first)
        run_worker()
        if first is not None:
            first.refresh_from_db()
            self.assertEqual(first.status, RuntimeChange.Status.SUCCEEDED, first.failure)
            self.assertTrue(
                first.steps.filter(
                    preparation__plan__runtime__package_action=Action.PHP_LIBRARIES
                ).exists()
            )
        preparation = request_php_installation(self.server, user, "8.4", "sury")
        self.assertIsNotNone(preparation)
        run_worker()
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        applied = request_apply(plan, user)
        self.assertIsNotNone(applied.run, applied.problem)
        run_worker()
        run = ApplyRun.objects.get(pk=applied.run.pk if applied.run else 0)
        self.assertEqual(run.verification, Verification.PASSED, run.failure)
        with ssh.connect_alias(self.server.ssh_alias) as shell:
            observed = observe_php_runtime(shell)
        self.assertEqual(observed.failure, "")
        self.assertEqual(observed.installed, ("8.3", "8.4"))
        self.assertIsNotNone(observed.default)
        if observed.default is not None:
            self.assertEqual(observed.default.branch, "8.3")
        prepared = request_runtime_preparation(self.server, user, "8.4")
        self.assertIsNotNone(prepared)
        run_worker()
        plan = ConfigurationPlan.objects.get(preparation=prepared)
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        applied = request_apply(plan, user)
        self.assertIsNotNone(applied.run, applied.problem)
        run_worker()
        run = ApplyRun.objects.get(pk=applied.run.pk if applied.run else 0)
        self.assertEqual(run.verification, Verification.PASSED, run.failure)
        self.assertEqual(self.administer("readlink -f /usr/bin/php").strip(), "/usr/bin/php8.4")

        change = request_php_default(self.server, user, "8.5")
        self.assertIsNotNone(change)
        run_worker()
        if change is not None:
            change.refresh_from_db()
            self.assertEqual(change.status, RuntimeChange.Status.SUCCEEDED, change.failure)
        self.assertEqual(self.administer("readlink -f /usr/bin/php").strip(), "/usr/bin/php8.5")
        for identifier in ("alpha", "bravo"):
            prepared_site = request_site_preparation(
                self.server,
                user,
                identifier,
                (identifier + ".example.test",),
                php_version="8.3",
                convention_revision=4,
            )
            self.assertIsNotNone(prepared_site)
            run_worker()
            site_plan = ConfigurationPlan.objects.get(preparation=prepared_site)
            self.assertTrue(
                site_plan.eligible, list(site_plan.refusals.values_list("text", flat=True))
            )
            applied_site = request_apply(site_plan, user)
            self.assertIsNotNone(applied_site.run, applied_site.problem)
            run_worker()
            site_run = ApplyRun.objects.get(pk=applied_site.run.pk if applied_site.run else 0)
            self.assertEqual(site_run.verification, Verification.PASSED, site_run.failure)
        self.administer(INSTALL_MARIADB)
        self.addCleanup(self.administer, REMOVE_MARIADB)
        for statement in mariadb_binding("salpha"):
            self.administer(statement)
        self.administer(
            mariadb(
                "CREATE TABLE salpha.kept (value VARCHAR(20)); "
                "INSERT INTO salpha.kept VALUES ('unchanged')"
            )
        )
        driver = request_driver_preparation(
            self.server, user, Action.PHP_MYSQL, php_version="8.3", php_supply="sury"
        )
        run_worker()
        driver_run = self.apply(ConfigurationPlan.objects.get(preparation=driver))
        self.assertEqual(driver_run.verification, Verification.PASSED, driver_run.failure)
        other_before = self.administer(
            "sha256sum /etc/nginx/sites-available/bravo.conf /etc/php/8.3/fpm/pool.d/bravo.conf"
        )
        change = request_site_php_switch(self.server, user, "alpha", "8.4")
        self.assertIsNotNone(change)
        run_worker()
        if change is not None:
            change.refresh_from_db()
            self.assertEqual(change.status, RuntimeChange.Status.SUCCEEDED, change.failure)
        self.assertEqual(self.administer("readlink -f /usr/bin/php").strip(), "/usr/bin/php8.5")
        self.assertEqual(
            self.administer(
                "sha256sum /etc/nginx/sites-available/bravo.conf /etc/php/8.3/fpm/pool.d/bravo.conf"
            ),
            other_before,
        )
        self.assertIn(
            "unix:/run/php/salpha-php8.4.sock",
            self.administer("cat /etc/nginx/sites-available/alpha.conf"),
        )
        self.assertEqual(
            self.administer("test ! -e /etc/php/8.3/fpm/pool.d/alpha.conf; echo $?"), "0\n"
        )

        self.assertEqual(self.administer(mariadb("SELECT value FROM salpha.kept")), "unchanged\n")
        before = self.administer(
            "sha256sum /etc/nginx/sites-available/alpha.conf /etc/php/8.4/fpm/pool.d/alpha.conf"
        )
        injected = site_runtime_native._PROGRAM.replace(
            "    site_changed = True",
            "    site_changed = True\n    raise ValueError('controlled publication failure')",
            1,
        )
        with patch.object(site_runtime_native, "_PROGRAM", injected):
            preparation = request_runtime_preparation(self.server, user, "8.3", identifier="alpha")
            run_worker()
            rolled_back = self.apply(ConfigurationPlan.objects.get(preparation=preparation))
        self.assertEqual(rolled_back.execution, Execution.PARTIAL, rolled_back.failure)
        self.assertEqual(rolled_back.exit_status, 41, rolled_back.failure)
        self.assertEqual(
            self.administer(
                "sha256sum /etc/nginx/sites-available/alpha.conf /etc/php/8.4/fpm/pool.d/alpha.conf"
            ),
            before,
        )
        self.assertEqual(self.administer("readlink -f /usr/bin/php").strip(), "/usr/bin/php8.5")
        self.assertEqual(
            self.administer("find /var/www/alpha -maxdepth 2 -name '*probe-*' -print"), ""
        )
        self.assertEqual(self.administer(mariadb("SELECT value FROM salpha.kept")), "unchanged\n")

    def test_known_package_failure_restores_default_and_drift_changes_nothing(self) -> None:
        trust_fixture(self, self.administer)
        user = User.objects.get(username="operator")
        self.assertEqual(self.apply(self.plan()).verification, Verification.PASSED)
        refreshed = request_preparation(self.server, user, Action.METADATA_REFRESH)
        run_worker()
        self.assertEqual(
            self.apply(ConfigurationPlan.objects.get(preparation=refreshed)).verification,
            Verification.PASSED,
        )
        preparation = request_php_installation(self.server, user, "8.3", "sury")
        run_worker()
        self.assertEqual(
            self.apply(ConfigurationPlan.objects.get(preparation=preparation)).verification,
            Verification.PASSED,
        )
        preparation = request_php_installation(self.server, user, "8.4", "sury")
        run_worker()
        reviewed = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertTrue(reviewed.eligible, list(reviewed.refusals.values_list("text", flat=True)))
        self.administer("update-alternatives --set php /usr/bin/php8.3 >/dev/null")
        before = self.administer("sha256sum /var/lib/dpkg/status; update-alternatives --query php")
        drift = self.apply(reviewed)
        self.assertEqual(drift.execution, Execution.DRIFT, drift.failure)
        self.assertEqual(
            self.administer("sha256sum /var/lib/dpkg/status; update-alternatives --query php"),
            before,
        )
        preparation = request_php_installation(self.server, user, "8.4", "sury")
        run_worker()
        reviewed = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertTrue(reviewed.eligible, list(reviewed.refusals.values_list("text", flat=True)))
        original = native.Check.step

        def failed_check(check: native.Check) -> str:
            return original(check) + "; exit 24"

        with patch.object(native.Check, "step", failed_check):
            failed = self.apply(reviewed)
        self.assertEqual(failed.execution, Execution.VALIDATION_FAILED, failed.failure)
        self.assertEqual(failed.exit_status, 24)
        self.assertEqual(self.administer("readlink -f /usr/bin/php").strip(), "/usr/bin/php8.3")
        self.assertIn(
            "php8.4-cli|ii",
            self.administer("dpkg-query -W -f='${Package}|${db:Status-Abbrev}' php8.4-cli"),
        )
        self.assertEqual(
            self.administer(
                "test ! -e "
                + native.archive_cache(failed.unit_name).removesuffix("archives/")
                + "; echo $?"
            ),
            "0\n",
        )

        backup = shlex.quote(self.administer("mktemp").strip())
        self.administer("cp -p /usr/bin/php8.4 " + backup + "; printf x >>/usr/bin/php8.4")
        try:
            with ssh.connect_alias(self.server.ssh_alias) as shell:
                changed = observe_php_runtime(shell)
            self.assertTrue(changed.failure)
            self.assertIsNone(changed.default)
            self.assertIsNone(changed.supply)
        finally:
            self.administer("cp -p " + backup + " /usr/bin/php8.4; rm -f " + backup)
