"""PHP database driver plans on a real, disposable Ubuntu server
(docs/databases.md#php-database-drivers).

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. Every plan goes through the dashboard
request, the worker, Barectl's SSH connection and actual APT, dpkg, ucf and systemd on the
server. Ground truth is read as root through ``docker exec``, independently of Barectl. A
site the administrator created by hand shows that the driver's reload keeps every pool.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import ClassVar, override
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission

from bootstrap import native as bootstrap_native
from bootstrap.models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEffect,
    PlanPreparation,
    Verification,
)
from bootstrap.profiles import PROFILES
from bootstrap.test_apply_remote import ApplyAcceptanceTestCase
from discovery.fakes import run_worker
from discovery.releases import SUPPORTED
from operations.models import RemoteOperation
from sites.test_review_remote import create_site, remove_site

from .models import PlanDriverPool

Status = RemoteOperation.Status
PERMISSIONS = ("view_server", "view_databaseplan", "prepare_databaseplan", "apply_databaseplan")
# The release pocket's PHP, which the -updates suite superseded but the archive still offers.
RELEASE_POCKET = {"8.3": "8.3.6-0maysync1", "8.5": "8.5.4-0ubuntu1"}
MODULES = {
    Action.PHP_MYSQL: ("mysqlnd", "mysqli", "pdo_mysql"),
    Action.PHP_PGSQL: ("pgsql", "pdo_pgsql"),
}


class DriverAcceptanceTestCase(ApplyAcceptanceTestCase):
    php: ClassVar[str]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.user = get_user_model().objects.create_user("operator")
        for codename in PERMISSIONS:
            cls.user.user_permissions.add(Permission.objects.get(codename=codename))

    @override
    def setUp(self) -> None:
        super().setUp()
        release = self.administer(". /etc/os-release; echo $VERSION_ID").strip()
        type(self).php = SUPPORTED[release].php
        self.version = release
        self.addCleanup(self.administer, remove_site("blog", self.php))
        self.addCleanup(self.administer, self.remove_drivers())
        self.administer(create_site("blog", ("blog.test",), self.php))

    def remove_drivers(self) -> str:
        php = self.php
        return (
            "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "
            f"php{php}-mysql php{php}-pgsql >/dev/null 2>&1; "
            f"rm -f /etc/php/{php}/fpm/conf.d/99-broken.ini /etc/php/{php}/fpm/pool.d/broken.conf; "
            f"systemctl start php{php}-fpm; systemctl reload php{php}-fpm; true"
        )

    def driver_plan(self, action: Action = Action.PHP_MYSQL) -> ConfigurationPlan:
        self.client.post(f"/servers/{self.server.pk}/databases/prepare/", {"action": action})
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        return ConfigurationPlan.objects.get(preparation=preparation)

    def main_pid(self) -> str:
        return self.administer(f"systemctl show -p MainPID --value php{self.php}-fpm").strip()

    def modules(self) -> set[str]:
        return set(self.administer(f"php-fpm{self.php} -m").split())

    def installed(self, package: str) -> str:
        return self.administer(
            f"dpkg-query -W -f='${{db:Status-Abbrev}}${{Version}}' {package} 2>/dev/null; true"
        )

    @contextmanager
    def injected(self, before: str, step: str) -> Iterator[None]:
        """The production payload with ``step`` run just before its fragment ``before``."""
        real = bootstrap_native.package_change

        def payload(*args: object, **kwargs: object) -> str:
            text = real(*args, **kwargs)  # type: ignore[arg-type]
            self.assertIn(before, text)
            return text.replace(before, f"{step}; {before}", 1)

        with mock.patch.object(bootstrap_native, "package_change", payload):
            yield


class DriverAcceptanceTests(DriverAcceptanceTestCase):
    def test_both_drivers_install_reload_every_pool_and_are_then_established(self) -> None:
        php = self.php
        common = self.installed(f"php{php}-common").removeprefix("ii ")
        for action, engine in ((Action.PHP_MYSQL, "mysql"), (Action.PHP_PGSQL, "pgsql")):
            with self.subTest(action=action):
                before = self.main_pid()
                plan = self.driver_plan(action)
                self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
                pools = list(PlanDriverPool.objects.filter(plan=plan).values_list("name", "user"))
                self.assertEqual(pools, [("www", "www-data"), ("blog", "sblog")])
                reload = plan.effects.get(kind=PlanEffect.Kind.SERVICE_RELOAD).text
                self.assertIn("blog as sblog on /run/php/sblog.sock", reload)
                self.assertEqual(
                    list(plan.roots.values_list("name", "version")),
                    [(f"php{php}-{engine}", common)],
                )
                run = self.apply(plan)
                self.assertEqual(
                    (run.status, run.execution, run.verification, run.exit_status),
                    (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
                    run.failure,
                )
                self.assertEqual(self.installed(f"php{php}-{engine}"), f"ii {common}")
                for sapi in ("fpm", "cli"):
                    for link, module in PROFILES[self.version][action].modules:
                        self.assertEqual(
                            self.administer(f"readlink /etc/php/{php}/{sapi}/conf.d/{link}.ini"),
                            f"/etc/php/{php}/mods-available/{module}.ini\n",
                        )
                self.assertLessEqual(set(MODULES[action]), self.modules())
                self.assertNotEqual(self.main_pid(), before)
                self.administer("test -S /run/php/sblog.sock && ss -Hlx src /run/php/sblog.sock")
                journal = self.journal(run.unit_name)
                self.assertIn(f"Processing triggers for php{php}-fpm", journal)
                self.assertEqual(self.units(), [run.unit_name])
                self.clear_units()
                # Established: another review changes nothing.
                again = self.driver_plan(action)
                self.assertTrue(
                    again.eligible and again.no_changes,
                    list(again.refusals.values_list("text", flat=True)),
                )

    def test_an_older_installed_php_gets_the_driver_at_its_own_version(self) -> None:
        php = self.php
        older = RELEASE_POCKET[php]
        installed = self.administer(
            f"dpkg-query -W -f='${{Package}} ${{db:Status-Abbrev}}\\n' 'php{php}-*' "
            "| awk '$2 == \"ii\" {print $1}'"
        ).split()
        self.addCleanup(
            self.administer,
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --only-upgrade "
            f"{' '.join(installed)} >/dev/null",
        )
        self.administer(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --allow-downgrades "
            f"{' '.join(f'{name}={older}' for name in installed)} >/dev/null"
        )
        plan = self.driver_plan()
        self.assertEqual(
            list(plan.roots.values_list("name", "version")), [(f"php{php}-mysql", older)]
        )
        run = self.apply(plan)
        self.assertEqual(run.verification, Verification.PASSED, run.failure)
        self.assertEqual(self.installed(f"php{php}-mysql"), f"ii {older}")
        self.assertEqual(self.installed(f"php{php}-common"), f"ii {older}")


class DriverFaultTests(DriverAcceptanceTestCase):
    def test_a_rejected_configuration_is_not_reloaded(self) -> None:
        php = self.php
        # A pool without a listen address, which php-fpm -t rejects.
        broken = f"/etc/php/{php}/fpm/pool.d/broken.conf"
        plan = self.driver_plan()
        with self.injected(f"/usr/sbin/php-fpm{php} -t", f"echo '[broken]' > {broken}"):
            run = self.apply(plan)
        self.assertEqual(
            (run.execution, run.exit_status), (Execution.VALIDATION_FAILED, 24), run.failure
        )
        self.assertIn("so Barectl did not reload PHP-FPM", run.failure)
        self.assertNotIn("systemctl reload", self.journal(run.unit_name))
        self.assertEqual(self.installed(f"php{php}-mysql")[:2], "ii")
        self.administer(f"systemctl is-active php{php}-fpm")

    def test_a_failed_reload_is_named(self) -> None:
        php = self.php
        plan = self.driver_plan()
        with self.injected(
            f"systemctl reload php{php}-fpm.service", f"systemctl stop php{php}-fpm"
        ):
            run = self.apply(plan)
        self.assertEqual(
            (run.execution, run.exit_status), (Execution.RELOAD_FAILED, 26), run.failure
        )
        self.assertIn("could not reload the service", run.failure)

    def test_a_change_after_review_refuses_before_apt(self) -> None:
        php = self.php
        plan = self.driver_plan()
        self.administer(
            f"printf '%s\\n' '; operator setting' > /etc/php/{php}/fpm/conf.d/99-broken.ini"
        )
        run = self.apply(plan)
        self.assertEqual((run.execution, run.exit_status), (Execution.DRIFT, 15), run.failure)
        self.assertEqual(self.installed(f"php{php}-mysql"), "")
        # The operator's file is not the distribution's, so a new review refuses it.
        refused = self.driver_plan()
        self.assertIn(
            f"/etc/php/{php}/fpm/conf.d/99-broken.ini",
            " ".join(refused.refusals.values_list("text", flat=True)),
        )
        self.assertFalse(ApplyRun.objects.filter(plan_number=refused.pk).exists())
