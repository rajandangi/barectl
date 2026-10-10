"""Actual WordPress PHP switches preserve native application and TLS state."""

import math
import time
from typing import ClassVar, override
from unittest import mock

from django.contrib.auth.models import Permission, User
from django.test import tag

from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, Verification
from bootstrap.runtime_changes import request_site_php_switch
from bootstrap.runtime_models import RuntimeChange
from bootstrap.runtime_services import request_runtime_preparation
from discovery.fakes import run_worker
from wordpress import qualification, qualification_testing, setup_native
from wordpress.install_apply_remote_testing import USER
from wordpress.install_remote_testing import (
    IDENTIFIER,
    NAME,
    NAMES,
    PUBLIC,
    InstallationServerCase,
    cleanups,
)
from wordpress.source_remote_testing import prepare_source_site
from wordpress.tls_remote_testing import InstalledWordpressTlsCase

from . import runtime_native


@tag("ssh")
class WordpressRuntimeSwitchTests(InstalledWordpressTlsCase):
    php: ClassVar[str] = "8.3"

    @override
    def setUp(self) -> None:
        self.enterContext(mock.patch.object(InstallationServerCase, "setUp", prepare_source_site))
        super().setUp()
        self.addCleanup(setattr, type(self), "php", "8.3")
        release = self.administer(". /etc/os-release; echo $VERSION_ID").strip()
        architecture = self.administer("dpkg --print-architecture").strip()
        for branch in ("8.4", "8.5"):
            self.enterContext(
                qualification_testing.source_candidate_qualified(release, architecture, branch)
            )
            for command in cleanups(branch):
                self.addCleanup(self.administer, command)
        for codename in (
            "view_siteplan",
            "prepare_siteplan",
            "apply_siteplan",
            "view_databaseplan",
            "prepare_databaseplan",
            "apply_databaseplan",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        type(self).user = User.objects.get(pk=self.user.pk)

    def preserved_application(self) -> dict[str, str]:
        result = self.application_state()
        del result["pool"]
        return result

    def wait_for_initial_cron_lock(self) -> None:
        deadline = time.monotonic() + 120
        query = (
            "mariadb --no-defaults --protocol=socket --batch --skip-column-names "
            '-e "SELECT option_value, UNIX_TIMESTAMP() FROM sshop.wp_options '
            "WHERE option_name='_transient_doing_cron'\""
        )
        while True:
            observed = self.administer(query).strip()
            if not observed:
                print("WordPress initial cron lock: absent")  # noqa: T201 - native qualification receipt
                return
            fields = observed.split("\t")
            self.assertEqual(len(fields), 2, "Cron lock timestamp/native clock unavailable")
            started, now = map(float, fields)
            self.assertTrue(math.isfinite(started) and started > 0)
            self.assertTrue(math.isfinite(now) and now > 0)
            if started + 60 <= now:
                print(  # noqa: T201 - native qualification receipt
                    f"WordPress initial cron lock: expired, age={now - started:.3f}s"
                )
                return
            if time.monotonic() >= deadline:
                self.fail("Initial WordPress cron lock stayed active beyond the bounded wait")
            time.sleep(0.2)

    def complete_initial_maintenance(self) -> None:
        self.wait_for_initial_cron_lock()
        command = (
            f"sudo -u {USER} timeout 90 /usr/bin/php{self.php} {setup_native.PHAR} "
            f"--path={PUBLIC} --url=https://{NAME} --skip-packages --no-color "
        )
        self.assertIn(
            "Success: Executed a total of", self.administer(command + "cron event run --due-now")
        )
        self.wait_for_initial_cron_lock()
        scheduled = self.administer(command + "cron event list --field=next_run_relative")
        self.assertTrue(scheduled.strip())
        self.assertNotIn("now", scheduled.splitlines())

    def test_every_qualified_branch_switch_preserves_wordpress_and_known_failure_restores_it(
        self,
    ) -> None:
        self.assert_public_application()
        self.complete_initial_maintenance()
        before = self.preserved_application()
        default = self.administer("readlink -f /usr/bin/php")
        certificate = self.fingerprint()
        for branch in ("8.4", "8.3", "8.5", "8.4", "8.5", "8.3"):
            old = self.php
            change = request_site_php_switch(self.server, self.user, IDENTIFIER, branch)
            self.assertIsNotNone(change)
            run_worker()
            if change is not None:
                change.refresh_from_db()
                self.assertEqual(change.status, RuntimeChange.Status.SUCCEEDED, change.failure)
                switched = change.steps.exclude(run=None).latest("position").run
                self.assertIsNotNone(switched)
                if switched is not None:
                    switched.refresh_from_db()
                    self.successful(switched)
            type(self).php = branch
            self.assertIn(
                f"unix:/run/php/sshop-php{branch}.sock",
                self.administer("cat /etc/nginx/sites-available/shop.conf"),
            )
            self.assertEqual(
                self.administer(f"test ! -e /etc/php/{old}/fpm/pool.d/shop.conf; echo $?"), "0\n"
            )
            self.assertEqual(self.preserved_application(), before)
            self.assertEqual(self.administer("readlink -f /usr/bin/php"), default)
            self.assertEqual(self.fingerprint(), certificate)
            for name in NAMES:
                self.assertEqual(self.fingerprint(served_name=name), certificate)
            self.assert_public_application()

        runs_before = ApplyRun.objects.count()
        self.assertIn("exif", self.administer("/usr/sbin/php-fpm8.3 -m").splitlines())
        self.assertIn("exif", self.administer("/usr/sbin/php-fpm8.4 -m").splitlines())
        self.administer(
            "test -L /etc/php/8.4/fpm/conf.d/20-exif.ini && phpdismod -v 8.4 -s fpm exif"
        )
        try:
            self.assertNotIn("exif", self.administer("/usr/sbin/php-fpm8.4 -m").splitlines())
            prepared = request_runtime_preparation(
                self.server, self.user, "8.4", identifier=IDENTIFIER
            )
            self.assertIsNotNone(prepared)
            run_worker()
            refused = ConfigurationPlan.objects.get(preparation=prepared)
            self.assertFalse(refused.eligible)
            self.assertIn(
                "The selected runtime cannot preserve the current FPM modules.", self.texts(refused)
            )
            self.assertEqual(ApplyRun.objects.count(), runs_before)
            self.assertEqual(self.preserved_application(), before)
            self.assertEqual(self.administer("readlink -f /usr/bin/php"), default)
        finally:
            self.administer("phpenmod -v 8.4 -s fpm exif")

        native_before = self.administer(
            "sha256sum /etc/nginx/sites-available/shop.conf /etc/php/8.3/fpm/pool.d/shop.conf"
        )
        injected = runtime_native._PROGRAM.replace(
            "    site_changed = True",
            "    site_changed = True\n    raise ValueError('controlled publication failure')",
            1,
        )
        with mock.patch.object(runtime_native, "_PROGRAM", injected):
            prepared = request_runtime_preparation(
                self.server, self.user, "8.4", identifier=IDENTIFIER
            )
            self.assertIsNotNone(prepared)
            run_worker()
            plan = ConfigurationPlan.objects.get(preparation=prepared)
            self.assertTrue(plan.eligible, self.texts(plan))
            restored = self.apply(plan)
        self.assertEqual(
            (restored.execution, restored.exit_status), (Execution.PARTIAL, 41), restored.failure
        )
        self.assertEqual(restored.verification, Verification.NOT_APPLICABLE)
        self.assertEqual(
            self.administer(
                "sha256sum /etc/nginx/sites-available/shop.conf /etc/php/8.3/fpm/pool.d/shop.conf"
            ),
            native_before,
        )
        self.assertEqual(self.preserved_application(), before)
        self.assertEqual(self.administer("readlink -f /usr/bin/php"), default)
        self.assertEqual(
            self.administer("find /var/www/shop -maxdepth 2 -name '*probe-*' -print"), ""
        )
        self.assert_public_application()

        original = qualification.qualified

        def unqualified(
            release: str, architecture: str, branch: str, supply: str = "ubuntu"
        ) -> bool:
            return branch != "8.4" and original(release, architecture, branch, supply)

        runs_before = ApplyRun.objects.count()
        with mock.patch.object(qualification, "qualified", unqualified):
            prepared = request_runtime_preparation(
                self.server, self.user, "8.4", identifier=IDENTIFIER
            )
            run_worker()
        refused = ConfigurationPlan.objects.get(preparation=prepared)
        self.assertFalse(refused.eligible)
        self.assertEqual(ApplyRun.objects.count(), runs_before)
        self.assertEqual(self.preserved_application(), before)
        self.assertEqual(self.administer("readlink -f /usr/bin/php"), default)
