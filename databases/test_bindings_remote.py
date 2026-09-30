"""MariaDB site databases on a real, disposable Ubuntu server (docs/databases.md).

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. Every plan goes through the dashboard
request, the worker, Barectl's SSH connection and actual systemd, MariaDB and PHP-FPM.
Ground truth is read as root through ``docker exec``, independently of Barectl. Another
site's database, which its administrator made by hand, keeps sentinel data that no run,
fault or review may change.
"""

import shlex
from collections.abc import Iterator
from contextlib import contextmanager
from typing import ClassVar, override
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission

from bootstrap import native as bootstrap_native
from bootstrap.models import (
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanPreparation,
    PlanRefusal,
    Verification,
)
from bootstrap.test_apply_remote import ApplyAcceptanceTestCase, _is_submission
from bootstrap.test_mariadb_remote import INSTALL_MARIADB, REMOVE_MARIADB
from discovery.fakes import current, run_worker
from discovery.releases import SUPPORTED
from discovery.services import request_discovery
from discovery.test_remote import setting
from operations.models import RemoteOperation
from sites.test_review_remote import PUT_BACK, SET_ASIDE, create_site, remove_site

from . import native
from .models import DatabaseRunResult, PlanCatalogObservation

Status = RemoteOperation.Status
Reason = PlanRefusal.Reason
PERMISSIONS = ("view_server", "view_databaseplan", "prepare_databaseplan", "apply_databaseplan")
MARIADB = "mariadb --no-defaults -N -B -e"
SENTINEL = "kept by the legacy administrator"
PRIVILEGES = (
    "SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES, "
    "CREATE TEMPORARY TABLES, LOCK TABLES"
)


def mariadb(statement: str) -> str:
    return f"{MARIADB} {shlex.quote(statement)}"


def as_site(user: str, statement: str) -> str:
    """``statement`` through the socket as the Linux user ``user``, printing any error."""
    return f"runuser -u {user} -- {MARIADB} {shlex.quote(statement)} 2>&1; true"


LEGACY = (
    mariadb("CREATE USER `slegacy`@`localhost` IDENTIFIED VIA unix_socket"),
    mariadb("CREATE DATABASE `slegacy` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"),
    mariadb(f"GRANT {PRIVILEGES} ON `slegacy`.* TO `slegacy`@`localhost`"),
    mariadb(
        "CREATE TABLE slegacy.kept (value VARCHAR(60)); "  # noqa: S608 - fixed fixture
        f"INSERT INTO slegacy.kept VALUES ('{SENTINEL}')"
    ),
)
DROP_SHOP = mariadb("DROP DATABASE IF EXISTS `sshop`; DROP USER IF EXISTS `sshop`@`localhost`")


class BindingAcceptanceTestCase(ApplyAcceptanceTestCase):
    php: ClassVar[str]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        release = cls.docker(". /etc/os-release; echo $VERSION_ID").strip()
        cls.php = SUPPORTED[release].php
        cls.addClassCleanup(cls.docker, REMOVE_MARIADB)
        cls.addClassCleanup(
            cls.docker,
            f"DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq php{cls.php}-mysql "
            f">/dev/null 2>&1; systemctl reload php{cls.php}-fpm; true",
        )
        cls.docker(
            f"{INSTALL_MARIADB} && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
            f"-o APT::Install-Recommends=0 php{cls.php}-mysql >/dev/null"
        )

    @classmethod
    def docker(cls, script: str) -> str:
        return ApplyAcceptanceTestCase.administer(cls, script)  # type: ignore[arg-type]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.user = get_user_model().objects.create_user("operator")
        for codename in PERMISSIONS:
            cls.user.user_permissions.add(Permission.objects.get(codename=codename))

    @override
    def setUp(self) -> None:
        super().setUp()
        for identifier in ("shop", "legacy"):
            self.addCleanup(self.administer, remove_site(identifier, self.php))
        self.addCleanup(
            self.administer,
            f"systemctl start mariadb; {DROP_SHOP}; "
            + mariadb(
                "DROP DATABASE IF EXISTS `slegacy`; DROP USER IF EXISTS `slegacy`@`localhost`"
            )
            + f"; rm -f /var/www/shop/dbprobe-*.php; {PUT_BACK}",
        )
        self.administer(SET_ASIDE)
        self.administer(create_site("shop", ("shop.test",), self.php))
        self.administer(create_site("legacy", ("legacy.test",), self.php))
        self.administer(" && ".join(LEGACY))

    def database_plan(self, action: str = "database_mariadb") -> ConfigurationPlan:
        self.client.post(
            f"/servers/{self.server.pk}/databases/prepare/",
            {"action": action, "identifier": "shop"},
        )
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        return ConfigurationPlan.objects.get(preparation=preparation)

    def eligible(self) -> ConfigurationPlan:
        plan = self.database_plan()
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan

    def assert_sentinel(self) -> None:
        self.assertEqual(
            self.administer(mariadb("SELECT value FROM slegacy.kept")).strip(), SENTINEL
        )

    def catalog(self) -> str:
        return self.administer(
            mariadb(
                "SELECT User, Host FROM mysql.global_priv WHERE User='sshop'; "
                "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='sshop'"
            )
        )

    @contextmanager
    def injected(self, after: str, step: str) -> Iterator[None]:
        """The production payload with ``step`` run after its fragment ``after``."""
        real = native.binding_steps

        def payload(unit: str, boot: str, deadline: int, change: native.BindingChange) -> str:
            steps = real(unit, boot, deadline, change)
            names = [item.name for item in steps]
            steps.insert(names.index(after) + 1, native.Step("injected", step))
            return "; ".join(item.text for item in steps)

        with mock.patch.object(native, "binding_payload", payload):
            yield


class BindingJourneyTests(BindingAcceptanceTestCase):
    def test_a_site_gets_its_database_uses_it_and_is_refused_everything_else(self) -> None:
        plan = self.eligible()
        run = self.apply(plan)
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        journal = self.journal(run.unit_name)
        self.assertIn("barectl-database: verified", journal)
        result = DatabaseRunResult.objects.get(run=run)
        self.assertEqual(
            (result.principal, result.authentication), ("sshop@localhost", "unix_socket")
        )
        self.assertTrue(result.probe_absent)
        self.assertEqual(self.administer("ls /var/www/shop"), "private\npublic\n")
        self.assertEqual(
            self.administer(mariadb("SHOW CREATE USER `sshop`@`localhost`")).strip(),
            "CREATE USER `sshop`@`localhost` IDENTIFIED VIA unix_socket",
        )

        # As the site's Linux user, through real SQL: its own database works...
        self.assertEqual(
            self.administer(
                as_site(
                    "sshop",
                    "SELECT CURRENT_USER(); CREATE TABLE sshop.t (i INT); "
                    "INSERT INTO sshop.t VALUES (1); SELECT i FROM sshop.t; DROP TABLE sshop.t",
                )
            ),
            "sshop@localhost\n1\n",
        )
        # ...another site's data, administration and TCP without a password are refused.
        for statement, error in (
            ("SELECT value FROM slegacy.kept", "ERROR 1142"),
            ("CREATE DATABASE other", "ERROR 1044"),
            ("CREATE USER other", "ERROR 1227"),
        ):
            self.assertIn(error, self.administer(as_site("sshop", statement)))
        tcp = self.administer(
            "runuser -u sshop -- mariadb --no-defaults -h 127.0.0.1 -P 3306 -u sshop "
            "-e 'SELECT 1' 2>&1; true"
        )
        self.assertIn("ERROR 1698", tcp)
        self.assert_sentinel()

        # The fully satisfied binding is a plan without changes.
        again = self.database_plan()
        self.assertTrue(
            again.eligible and again.no_changes, list(again.refusals.values_list("text", flat=True))
        )

        # Discovery as root reconstructs it; the SSH user with sudo sees it as inaccessible,
        # and an inspection it prepares reads it with privilege.
        self.write_config("root")
        request_discovery(self.server)
        run_worker()
        sites = {site.identifier: site for site in current(self.server).collected.sites.value}
        shop = sites["shop"].database
        self.assertTrue(shop and shop.conforms, shop and shop.warning)
        self.write_config(setting("USER"))
        inspection = self.database_plan("database_inspection")
        observed = PlanCatalogObservation.objects.get(plan=inspection, identifier="shop")
        self.assertTrue(observed.conforms, observed.warning)
        self.write_config(setting("UNPRIVILEGED_USER"))
        refused = self.database_plan("database_inspection")
        self.assertEqual({r.reason for r in refused.refusals.all()}, {Reason.PRIVILEGE})
        self.assertFalse(PlanCatalogObservation.objects.filter(plan=refused).exists())

    def test_lost_acknowledgement_reconciles_without_resubmitting(self) -> None:
        plan = self.eligible()
        with self.losing(_is_submission, after=True):
            run = self.apply(plan)
        self.assertEqual(run.status, Status.RECONCILING)
        (name,) = self.units()
        self.wait_terminal(name)
        run = self.check(run)
        self.assertEqual(
            (run.status, run.verification), (Status.SUCCEEDED, Verification.PASSED), run.failure
        )
        self.assertEqual(self.units(), [name])
        self.assert_sentinel()

    def test_a_second_controller_s_plan_is_refused_once_the_first_applied(self) -> None:
        first = self.eligible()
        self.write_config(setting("USER"))
        second = self.eligible()
        self.assertEqual(self.apply(first).status, Status.SUCCEEDED)
        run = self.apply(second)
        self.assertEqual((run.execution, run.exit_status), (Execution.DRIFT, 15), run.failure)
        self.assertEqual(ApplyRun.objects.count(), 2)
        self.assert_sentinel()


class BindingFaultTests(BindingAcceptanceTestCase):
    def fault(self, after: str, step: str) -> ApplyRun:
        plan = self.eligible()
        with self.injected(after, step):
            run = self.apply(plan)
        self.assertEqual(ApplyRun.objects.count(), 1)
        return run

    def assert_boundary(self, run: ApplyRun, execution: Execution, status: int) -> None:
        self.assertEqual(
            (run.status, run.execution, run.exit_status),
            (Status.FAILED, execution, status),
            run.failure,
        )
        self.administer("systemctl start mariadb")
        self.assert_sentinel()
        self.assertEqual(self.administer("ls /var/www/shop"), "private\npublic\n")

    def test_a_principal_created_after_review_refuses_before_anything(self) -> None:
        plan = self.eligible()
        self.administer(mariadb("CREATE USER `sshop`@`localhost` IDENTIFIED VIA unix_socket"))
        run = self.apply(plan)
        self.assert_boundary(run, Execution.DRIFT, 15)

    def test_a_principal_created_after_the_recheck_is_a_conflict(self) -> None:
        run = self.fault(
            "recheck", mariadb("CREATE USER `sshop`@`localhost` IDENTIFIED VIA unix_socket")
        )
        self.assert_boundary(run, Execution.PRINCIPAL_CONFLICT, 33)
        self.assertIn("ERROR 1396", self.journal(run.unit_name))

    def test_a_database_created_before_its_statement_is_not_adopted(self) -> None:
        run = self.fault("principal", mariadb("CREATE DATABASE `sshop`"))
        self.assert_boundary(run, Execution.PARTIAL, 57)
        # The principal exists; a new review names the partial binding.
        refused = self.database_plan()
        self.assertEqual([r.reason for r in refused.refusals.all()], [Reason.COLLISION])

    def test_a_stopped_engine_before_the_grant_is_partial(self) -> None:
        run = self.fault("database", "systemctl stop mariadb")
        self.assert_boundary(run, Execution.PARTIAL, 59)
        self.administer("systemctl start mariadb")
        refused = self.database_plan()
        self.assertEqual([r.reason for r in refused.refusals.all()], [Reason.PARTIAL_BINDING])
        self.assertIn("GRANT SELECT", " ".join(refused.refusals.values_list("text", flat=True)))

    def test_an_extra_grant_before_the_after_check_is_partial(self) -> None:
        run = self.fault("privileges", mariadb("GRANT SELECT ON mysql.user TO `sshop`@`localhost`"))
        self.assert_boundary(run, Execution.PARTIAL, 61)

    def test_a_pool_without_the_driver_refuses_before_any_statement(self) -> None:
        php = self.php
        disable = (
            f"phpdismod -v {php} -s fpm mysqli pdo_mysql mysqlnd && systemctl reload php{php}-fpm"
        )
        self.addCleanup(
            self.administer,
            f"phpenmod -v {php} -s fpm mysqlnd mysqli pdo_mysql; systemctl reload php{php}-fpm",
        )
        run = self.fault("probe", f"{disable}; sleep 1")
        self.assert_boundary(run, Execution.DRIVER_UNAVAILABLE, 32)
        self.assertEqual(self.catalog(), "")

    def test_an_edited_probe_is_left_and_named(self) -> None:
        run = self.fault(
            "pre-check",
            "for f in /var/www/shop/dbprobe-*.php; do echo '<?php echo 1;' >>\"$f\"; done",
        )
        self.assertEqual((run.execution, run.exit_status), (Execution.PARTIAL, 63), run.failure)
        self.assertIn("could not be removed or had changed", run.failure)
        # The changed probe is kept for inspection.
        self.assertIn("dbprobe-", self.administer("ls /var/www/shop"))
        self.assert_sentinel()

    def test_the_runtime_limit_leaves_what_was_created(self) -> None:
        plan = self.eligible()
        with (
            mock.patch.object(bootstrap_native, "RUNTIME_MAX", "20s"),
            self.injected("principal", "sleep 120"),
        ):
            run = self.apply(plan)
            if run.status == Status.RECONCILING:
                self.wait_terminal(run.unit_name, timeout=60)
                run = self.check(run)
        self.assertEqual(run.execution, Execution.TIMED_OUT, run.failure)
        self.assertIn("sshop\tlocalhost", self.catalog())
        self.assert_sentinel()
