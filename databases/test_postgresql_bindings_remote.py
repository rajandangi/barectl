"""PostgreSQL site databases, and both engines on one server, on a real, disposable Ubuntu
server (docs/databases.md).

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. The server runs the release default's
PostgreSQL ``main`` cluster alone, installed by its administrator, beside MariaDB. Another
site's PostgreSQL database, made by hand by the convention, keeps sentinel data that no run,
fault or review may change.
"""

import shlex
from typing import override

from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, PlanRefusal, Verification
from bootstrap.test_mariadb_remote import INSTALL_MARIADB, REMOVE_MARIADB
from bootstrap.test_postgresql_remote import REMOVE_POSTGRESQL, RESTORE_POSTGRESQL
from discovery.fakes import current, run_worker
from discovery.models import DatabaseEngine
from discovery.releases import SUPPORTED
from discovery.services import request_discovery
from operations.models import RemoteOperation
from sites.convention import render_pool, render_site
from sites.test_review_remote import create_site, remove_site

from .models import DatabaseRunResult, PlanDatabaseBinding, RunDatabaseBinding
from .test_bindings_remote import BindingAcceptanceTestCase, mariadb

Status = RemoteOperation.Status
Reason = PlanRefusal.Reason
PSQL = "runuser -u postgres -- psql -X -A -t -q -v ON_ERROR_STOP=1 -v VERBOSITY=sqlstate"
SENTINEL = "kept by the wiki administrator"


def psql(statement: str, database: str = "postgres") -> str:
    return f"{PSQL} -d {database} -c {shlex.quote(statement)}"


def as_site(user: str, statement: str, database: str) -> str:
    """``statement`` through the socket as the Linux user ``user``, printing any error."""
    return (
        f"runuser -u {user} -- psql -X -A -t -q -v VERBOSITY=sqlstate -h /var/run/postgresql "
        f"-d {database} -c {shlex.quote(statement)} 2>&1; true"
    )


WIKI = (
    psql('CREATE ROLE "swiki" LOGIN'),
    psql(
        'CREATE DATABASE "swiki" WITH OWNER "swiki" TEMPLATE template0 ENCODING \'UTF8\' '
        "LOCALE_PROVIDER libc LC_COLLATE 'C.UTF-8' LC_CTYPE 'C.UTF-8'"
    ),
    psql('REVOKE CONNECT, TEMPORARY ON DATABASE "swiki" FROM PUBLIC'),
    psql("REVOKE ALL ON SCHEMA public FROM PUBLIC", "swiki"),
    as_site("swiki", "CREATE TABLE kept (value text)", "swiki"),
    as_site("swiki", f"INSERT INTO kept VALUES ('{SENTINEL}')", "swiki"),  # noqa: S608 - fixed fixture
)
DROP = "; ".join(
    psql(statement)
    for statement in (
        'DROP DATABASE IF EXISTS "sshop"',
        'DROP DATABASE IF EXISTS "swiki"',
        'DROP DATABASE IF EXISTS "sblog"',
        'DROP ROLE IF EXISTS "sshop"',
        'DROP ROLE IF EXISTS "swiki"',
        'DROP ROLE IF EXISTS "sblog"',
    )
)


class PostgreSQLBindingTestCase(BindingAcceptanceTestCase):
    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        release = cls.docker(". /etc/os-release; echo $VERSION_ID").strip()
        cls.major = SUPPORTED[release].postgresql
        cls.addClassCleanup(cls.docker, RESTORE_POSTGRESQL)
        cls.addClassCleanup(
            cls.docker,
            f"DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq php{cls.php}-pgsql "
            f">/dev/null 2>&1; systemctl reload php{cls.php}-fpm; true",
        )
        # The release default's main cluster alone, as the PostgreSQL profile installs it.
        cls.docker(
            f"{REMOVE_POSTGRESQL}; export DEBIAN_FRONTEND=noninteractive; "
            "apt-get install -y -qq -o APT::Install-Recommends=0 postgresql "
            f"php{cls.php}-pgsql >/dev/null"
        )

    major: str

    @override
    def setUp(self) -> None:
        super().setUp()
        self.addCleanup(self.administer, remove_site("wiki", self.php))
        self.addCleanup(
            self.administer,
            f"systemctl start postgresql@{self.major}-main; {DROP}; rm -f /var/www/*/dbprobe-*.php",
        )
        self.administer(create_site("wiki", ("wiki.test",), self.php))
        self.administer(" && ".join(WIKI))

    def eligible_postgresql(self) -> ConfigurationPlan:
        plan = self.database_plan("database_postgresql")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan

    def assert_wiki(self) -> None:
        self.assertEqual(self.administer(psql("SELECT value FROM kept", "swiki")).strip(), SENTINEL)

    def roles(self) -> str:
        return self.administer(
            psql(
                "SELECT rolname FROM pg_authid WHERE rolname='sshop' UNION ALL "
                "SELECT datname FROM pg_database WHERE datname='sshop'"
            )
        )


class PostgreSQLJourneyTests(PostgreSQLBindingTestCase):
    def test_selected_socket_drives_the_native_postgresql_binding_probe(self) -> None:
        source = "/etc/nginx/sites-available/shop.conf"
        site = render_site("shop", ("shop.test",), ipv6=True, php_version=self.php)
        pool = render_pool("shop", php_version=self.php)
        self.administer(
            f"printf %s {shlex.quote(site)} >{source}; "
            f"printf %s {shlex.quote(pool)} >/etc/php/{self.php}/fpm/pool.d/shop.conf; "
            f"php-fpm{self.php} -t && systemctl reload php{self.php}-fpm; "
            "nginx -t && systemctl reload nginx"
        )
        run = self.apply(self.eligible_postgresql())
        self.assertEqual(
            (run.execution, run.verification),
            (Execution.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        audit = RunDatabaseBinding.objects.get(run=run)
        self.assertEqual((audit.php_version, audit.site_revision), (self.php, 4))
        self.assertEqual(self.administer(f"cat {source}"), site)
        self.assert_wiki()
        self.assert_sentinel()

    def test_a_fresh_binding_prepares_while_mariadb_is_absent(self) -> None:
        # Without the other engine the catalog read has no second section, so its
        # last command is the public schema read, which exits 2 while no database
        # `sshop` exists (docs/databases.md#preparing-a-database-plan).
        self.administer(REMOVE_MARIADB)
        self.addCleanup(self.administer, INSTALL_MARIADB)
        plan = self.eligible_postgresql()
        self.assertFalse(PlanDatabaseBinding.objects.get(plan=plan).other_engine)

    def test_a_site_gets_its_database_uses_it_and_is_refused_everything_else(self) -> None:
        run = self.apply(self.eligible_postgresql())
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        self.assertIn("barectl-database: verified", self.journal(run.unit_name))
        result = DatabaseRunResult.objects.get(run=run)
        self.assertEqual((result.principal, result.probe_absent), ("sshop", True))
        self.assertEqual(self.administer("ls /var/www/shop"), "private\npublic\n")

        # As the site's Linux user, through real SQL: its own database works...
        self.assertEqual(
            self.administer(
                as_site(
                    "sshop",
                    "SELECT current_user; CREATE TABLE t (i int); INSERT INTO t VALUES (1); "
                    "SELECT i FROM t; DROP TABLE t",
                    "sshop",
                )
            ),
            "sshop\n1\n",
        )
        # ...another site's database, administration and TCP without a password are refused.
        self.assertIn(
            "permission denied for database", self.administer(as_site("sshop", "SELECT 1", "swiki"))
        )
        for statement in ("CREATE DATABASE other", "CREATE ROLE other"):
            self.assertIn("42501", self.administer(as_site("sshop", statement, "sshop")))
        tcp = self.administer(
            "runuser -u sshop -- psql -X -h 127.0.0.1 -d sshop -w -c 'SELECT 1' 2>&1; true"
        )
        self.assertIn("password", tcp)
        # PUBLIC keeps nothing on the new database: the wiki's role cannot connect to it.
        self.assertIn(
            "permission denied for database", self.administer(as_site("swiki", "SELECT 1", "sshop"))
        )
        self.assert_wiki()

        again = self.database_plan("database_postgresql")
        self.assertTrue(
            again.eligible and again.no_changes, list(again.refusals.values_list("text", flat=True))
        )
        self.write_config("root")
        request_discovery(self.server)
        run_worker()
        sites = {site.identifier: site for site in current(self.server).collected.sites.value}
        shop, wiki = sites["shop"].database, sites["wiki"].database
        self.assertTrue(shop and shop.conforms, shop and shop.warning)
        self.assertTrue(wiki and wiki.conforms, wiki and wiki.warning)

    def test_both_engines_on_one_server_keep_one_binding_per_site(self) -> None:
        self.administer(create_site("blog", ("blog.test",), self.php))
        self.addCleanup(self.administer, remove_site("blog", self.php))
        self.addCleanup(
            self.administer,
            mariadb("DROP DATABASE IF EXISTS `sblog`; DROP USER IF EXISTS `sblog`@`localhost`"),
        )
        # blog in MariaDB and shop in PostgreSQL, each through the dashboard and worker.
        self.client.post(
            f"/servers/{self.server.pk}/databases/prepare/",
            {"action": "database_mariadb", "identifier": "blog"},
        )
        run_worker()
        mariadb_plan = ConfigurationPlan.objects.latest("pk")
        self.assertTrue(
            mariadb_plan.eligible, list(mariadb_plan.refusals.values_list("text", flat=True))
        )
        self.assertEqual(self.apply(mariadb_plan).verification, Verification.PASSED)
        run = self.apply(self.eligible_postgresql())
        self.assertEqual(run.verification, Verification.PASSED, run.failure)

        # Neither site switches engines: each read covers the other engine.
        self.client.post(
            f"/servers/{self.server.pk}/databases/prepare/",
            {"action": "database_postgresql", "identifier": "blog"},
        )
        run_worker()
        switched = ConfigurationPlan.objects.latest("pk")
        self.assertEqual([r.reason for r in switched.refusals.all()], [Reason.EXISTING_BINDING])
        refused = self.database_plan("database_mariadb")
        self.assertEqual([r.reason for r in refused.refusals.all()], [Reason.EXISTING_BINDING])

        self.write_config("root")
        request_discovery(self.server)
        run_worker()
        sites = {site.identifier: site for site in current(self.server).collected.sites.value}
        found = {
            identifier: sites[identifier].database
            for identifier in ("shop", "blog", "wiki", "legacy")
        }
        engines = {
            identifier: (database.engine, database.conforms) if database else None
            for identifier, database in found.items()
        }
        self.assertEqual(
            engines,
            {
                "shop": (DatabaseEngine.POSTGRESQL, True),
                "blog": (DatabaseEngine.MARIADB, True),
                "wiki": (DatabaseEngine.POSTGRESQL, True),
                "legacy": (DatabaseEngine.MARIADB, True),
            },
            {identifier: d.warning for identifier, d in found.items() if d},
        )
        self.assert_wiki()
        self.assert_sentinel()


class PostgreSQLFaultTests(PostgreSQLBindingTestCase):
    def fault(self, after: str, step: str) -> ApplyRun:
        plan = self.eligible_postgresql()
        with self.injected(after, step):
            return self.apply(plan)

    def assert_boundary(self, run: ApplyRun, execution: Execution, status: int) -> None:
        self.assertEqual(
            (run.status, run.execution, run.exit_status),
            (Status.FAILED, execution, status),
            run.failure,
        )
        self.administer(f"systemctl start postgresql@{self.major}-main")
        self.assert_wiki()
        self.assertEqual(self.administer("ls /var/www/shop"), "private\npublic\n")

    def test_a_role_created_after_review_refuses_before_anything(self) -> None:
        plan = self.eligible_postgresql()
        self.administer(psql('CREATE ROLE "sshop" LOGIN'))
        self.assert_boundary(self.apply(plan), Execution.DRIFT, 15)

    def test_a_role_created_after_the_recheck_is_a_conflict(self) -> None:
        run = self.fault("recheck", psql('CREATE ROLE "sshop" LOGIN'))
        self.assert_boundary(run, Execution.PRINCIPAL_CONFLICT, 33)
        self.assertIn("42710", self.journal(run.unit_name))

    def test_a_database_created_before_its_statement_is_not_adopted(self) -> None:
        run = self.fault("principal", psql('CREATE DATABASE "sshop"'))
        self.assert_boundary(run, Execution.PARTIAL, 57)
        self.assertIn("42P04", self.journal(run.unit_name))

    def test_a_stopped_cluster_before_the_revoke_is_partial_then_finished(self) -> None:
        run = self.fault("database", f"systemctl stop postgresql@{self.major}-main")
        self.assert_boundary(run, Execution.PARTIAL, 59)
        finish = self.eligible_postgresql()
        self.assertIn("Finish", finish.intent)
        self.assertEqual(
            list(finish.binding_statements.values_list("step", flat=True)),
            ["privileges", "schema"],
        )
        finished = self.apply(finish)
        self.assertEqual(
            (finished.status, finished.verification),
            (Status.SUCCEEDED, Verification.PASSED),
            finished.failure,
        )
        again = self.database_plan("database_postgresql")
        self.assertTrue(
            again.eligible and again.no_changes, list(again.refusals.values_list("text", flat=True))
        )
        self.assert_wiki()

    def test_a_database_refusing_connections_before_the_schema_revoke_is_partial(self) -> None:
        run = self.fault("privileges", psql('ALTER DATABASE "sshop" ALLOW_CONNECTIONS false'))
        self.assert_boundary(run, Execution.PARTIAL, 60)
        self.assertEqual(self.roles(), "sshop\nsshop\n")

    def test_a_changed_role_before_the_after_check_is_partial(self) -> None:
        run = self.fault("schema", psql('ALTER ROLE "sshop" CONNECTION LIMIT 5'))
        self.assert_boundary(run, Execution.PARTIAL, 61)

    def test_a_pool_without_the_driver_refuses_before_any_statement(self) -> None:
        php = self.php
        self.addCleanup(
            self.administer,
            f"phpenmod -v {php} -s fpm pgsql pdo_pgsql; systemctl reload php{php}-fpm",
        )
        run = self.fault(
            "probe",
            f"phpdismod -v {php} -s fpm pgsql pdo_pgsql && systemctl reload php{php}-fpm; sleep 1",
        )
        self.assert_boundary(run, Execution.DRIVER_UNAVAILABLE, 32)
        self.assertEqual(self.roles(), "")
