"""A site's database binding created by the product's own reviewed change (#379).

docs/quality.md#native-layer. Each method builds its own site through the real Create site
change, then proves one acceptance criterion of issue #379 on a real Ubuntu 26.04 host.
"""

import base64
import shlex
from typing import cast

from django.test import tag

from discovery.ssh import RemoteShell
from operations.engine import ReviewDraft
from operations.inputs import PreparationInputs
from operations.models import ChangeReview

from . import mirror
from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

IDENTIFIER = "sdbalpha"
DOMAIN = "sdbalpha.example.com"
OTHER = "ssdbother"
MARIADB_SOCKET = "/run/mysqld/mysqld.sock"
MYSQL = "mariadb --no-defaults --protocol=socket --socket=" + MARIADB_SOCKET + " --user=root -N -B"


def write(test: ScenarioTestCase, shell: RemoteShell, path: str, content: str) -> None:
    result = shell.run(f"install -D -m 0644 /dev/stdin {shlex.quote(path)}", stdin=content.encode())
    test.assertEqual(result.exit_status, 0, result.stdout)


class SiteDatabaseCase(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "sdb"

    def router(self, shell: RemoteShell) -> None:
        write(self, shell, "/etc/apt/sources.list.d/barectl-fixture.sources", mirror.apt_sources())
        write(
            self,
            shell,
            "/etc/apt/apt.conf.d/99barectl-fixture",
            'Acquire::By-Hash "no";\nAcquire::Languages "none";\n',
        )
        self.assertEqual(shell.run("rm -f /etc/apt/sources.list.d/ubuntu.sources").exit_status, 0)
        update = shell.run("apt-get update 2>&1")
        self.assertEqual(update.exit_status, 0, update.stdout)

    def create_site(self) -> ChangeReview:
        from sites import change as sites_change

        inputs = PreparationInputs("php84", IDENTIFIER, (DOMAIN,))
        return apply_change(self, sites_change.CREATE_SITE, inputs, timeout=120)

    def bind(self, *, timeout: float = 120) -> ChangeReview:
        from databases import site

        return apply_change(
            self, site.ADD_SITE_DATABASE, PreparationInputs("", IDENTIFIER), timeout=timeout
        )

    def prepare(self, shell: RemoteShell) -> ReviewDraft:
        from databases import site

        inputs = PreparationInputs("", IDENTIFIER)
        return site.review(site.inspect(shell, inputs), inputs)

    def restore_file(self, path: str, content: str) -> None:
        """Write ``content`` to ``path`` on the server through the harness's fixed channel."""
        self.native(
            "printf %s "
            + shlex.quote(base64.b64encode(content.encode()).decode())
            + " | base64 -d >"
            + path
        )


@tag(SCENARIO_TAG)
class SiteDatabaseMariaDB(SiteDatabaseCase):
    records: tuple[str, ...] = ("site-database-26.04",)

    def isolation_database(self) -> None:
        statements = (
            f"CREATE USER `{OTHER}`@`localhost` IDENTIFIED VIA unix_socket; "
            f"CREATE DATABASE `{OTHER}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; "
            f"GRANT ALL PRIVILEGES ON `{OTHER}`.* TO `{OTHER}`@`localhost`"
        )
        self.native(f"{MYSQL} -e {shlex.quote(statements)}")

    def site_query(self, statement: str, database: str = "") -> str:
        return self.native(
            "runuser -u s"
            + IDENTIFIER
            + " -- mariadb --no-defaults --protocol=socket --socket="
            + MARIADB_SOCKET
            + " "
            + database
            + " -N -B -e "
            + shlex.quote(statement)
        )

    def objects(self) -> list[str]:
        return self.site_query(
            "SELECT TABLE_TYPE, TABLE_NAME FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME; "
            "SELECT ROUTINE_NAME FROM information_schema.ROUTINES "
            "WHERE ROUTINE_SCHEMA=DATABASE() ORDER BY ROUTINE_NAME; "
            "SELECT TRIGGER_NAME FROM information_schema.TRIGGERS "
            "WHERE TRIGGER_SCHEMA=DATABASE() ORDER BY TRIGGER_NAME",
            "s" + IDENTIFIER,
        ).split()

    def test_1_creates_the_binding_and_proves_dump_import_and_isolation(self) -> None:
        from databases import engine as kinds
        from databases import site

        with self.shell() as shell:
            self.router(shell)
            apply_change(self, kinds.INSTALL, PreparationInputs("mariadb"), timeout=150)
        self.assertIn("active", self.native("systemctl is-active mariadb.service"))
        # A package transaction reloads systemd and clears the running foundation masters'
        # loaded-execution metadata; restart them, as ordinary administration, so the site
        # review's live protections are current again.
        self.native("systemctl restart php-fpm@php84.service php-fpm@php85.service")
        self.create_site()
        self.isolation_database()
        review = self.bind()
        self.assertEqual(review.document["principal"], "s" + IDENTIFIER)
        with self.shell() as shell:
            self.assertTrue(site.verify(shell, review))
        self.site_query(
            "CREATE TABLE t (i INT PRIMARY KEY); "
            "INSERT INTO t VALUES (7); "
            "CREATE VIEW v AS SELECT i FROM t; "
            "CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW SET NEW.i=NEW.i; "
            "CREATE PROCEDURE p() SELECT COUNT(*) FROM t; ",
            "s" + IDENTIFIER,
        )
        self.assertEqual(self.objects(), ["BASE", "TABLE", "t", "VIEW", "v", "p", "tr"])
        dump = self.native(
            "runuser -u s" + IDENTIFIER + " -- mariadb-dump --no-defaults "
            "--protocol=socket --socket=" + MARIADB_SOCKET + " --single-transaction --quick "
            "--no-tablespaces --routines --events --triggers s" + IDENTIFIER
        )
        self.assertIn("VIEW `v`", dump)
        self.assertIn("PROCEDURE `p`", dump)
        self.assertIn("TRIGGER tr", dump)
        self.site_query("DROP VIEW v; DROP TABLE t; DROP PROCEDURE p;", "s" + IDENTIFIER)
        self.restore_file("/run/sdbdump.sql", dump)
        imported = self.native(
            "runuser -u s" + IDENTIFIER + " -- mariadb --no-defaults "
            "--protocol=socket --socket="
            + MARIADB_SOCKET
            + " s"
            + IDENTIFIER
            + " </run/sdbdump.sql 2>&1"
        )
        self.assertNotIn("ERROR", imported)
        self.assertEqual(self.objects(), ["BASE", "TABLE", "t", "VIEW", "v", "p", "tr"])
        self.assertEqual(
            self.site_query(
                f"SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='{OTHER}'"  # noqa: S608
            ).strip(),
            "0",
        )
        denied = self.native(
            "runuser -u s" + IDENTIFIER + " -- mariadb --no-defaults "
            "--protocol=socket --socket="
            + MARIADB_SOCKET
            + " "
            + OTHER
            + " -e 'SELECT 1' 2>&1 || true"
        )
        self.assertIn("denied", denied.lower())

    def test_2_a_partial_binding_is_finished_without_overwriting(self) -> None:
        from databases import site

        site_user = "s" + IDENTIFIER
        self.native(
            f"{MYSQL} -e "  # noqa: S608
            + shlex.quote(
                f"DELETE FROM mysql.db WHERE User='{site_user}' AND Db='{site_user}'"  # noqa: S608
            )
        )
        with self.shell() as shell:
            draft = self.prepare(shell)
            self.assertTrue(draft.eligible, draft.refusals)
            self.assertFalse(draft.no_changes)
            statements = cast(list[list[str]], draft.document["statements"])
            self.assertEqual([row[0] for row in statements], ["privileges"])
        review = self.bind()
        with self.shell() as shell:
            self.assertTrue(site.verify(shell, review))
        self.assertEqual(self.site_query("SELECT i FROM t", "s" + IDENTIFIER).strip(), "7")

    def test_3_a_fresh_controller_reconstructs_the_binding(self) -> None:
        from discovery.observations import collect
        from operations import engine as operations_engine

        with self.shell() as fresh:
            collect(fresh)
            draft = self.prepare(fresh)
            self.assertTrue(draft.eligible, draft.refusals)
            self.assertTrue(draft.no_changes)
            self.assertIn("already exists", str(draft.document["note"]))
            operations_engine._sites_digest(fresh, draft)
            self.checkpoint("site-database-26.04", fresh)


@tag(SCENARIO_TAG)
class SiteDatabasePostgreSQL(SiteDatabaseCase):
    def site_query(self, statement: str, database: str = "") -> str:
        return self.native(
            "runuser -u s"
            + IDENTIFIER
            + " -- psql -X -A -t -q -d "
            + (database or "postgres")
            + " -c "
            + shlex.quote(statement)
        )

    def test_1_creates_the_binding_and_proves_dump_import_and_isolation(self) -> None:
        from databases import engine as kinds
        from databases import site

        with self.shell() as shell:
            self.router(shell)
            apply_change(self, kinds.INSTALL, PreparationInputs("postgresql"), timeout=180)
        self.assertIn("active", self.native("systemctl is-active postgresql.service"))
        # A package transaction reloads systemd and clears the running foundation masters'
        # loaded-execution metadata; restart them, as ordinary administration, so the site
        # review's live protections are current again.
        self.native("systemctl restart php-fpm@php84.service php-fpm@php85.service")
        self.create_site()
        role = f"CREATE ROLE {OTHER} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE"
        database = (
            f"CREATE DATABASE {OTHER} OWNER {OTHER} TEMPLATE template0 ENCODING 'UTF8' "
            "LOCALE_PROVIDER libc LC_COLLATE 'C.UTF-8' LC_CTYPE 'C.UTF-8'"
        )
        self.native(
            "su - postgres -c "
            + shlex.quote("psql -X -q -c " + shlex.quote(role) + " -c " + shlex.quote(database))
        )
        self.native(
            "su - postgres -c "
            + shlex.quote(
                "psql -X -q -d "
                + OTHER
                + " -c "
                + shlex.quote(f"REVOKE CONNECT, TEMPORARY ON DATABASE {OTHER} FROM PUBLIC")
            )
        )
        review = self.bind(timeout=150)
        self.assertEqual(review.document["principal"], "s" + IDENTIFIER)
        with self.shell() as shell:
            self.assertTrue(site.verify(shell, review))
        self.site_query(
            "CREATE TABLE t (i INT PRIMARY KEY); INSERT INTO t VALUES (7); "
            "CREATE VIEW v AS SELECT i FROM t; "
            "CREATE FUNCTION f() RETURNS int LANGUAGE sql AS 'SELECT 1';",
            "s" + IDENTIFIER,
        )
        objects = self.site_query(
            "SELECT relname FROM pg_class WHERE relnamespace='public'::regnamespace "
            "AND relkind IN ('r','v') ORDER BY relname; "
            "SELECT proname FROM pg_proc WHERE pronamespace='public'::regnamespace",
            "s" + IDENTIFIER,
        ).split()
        self.assertIn("v", objects)
        self.assertIn("f", objects)
        dump = self.native(
            "runuser -u s" + IDENTIFIER + " -- pg_dump --no-owner --no-privileges -d s" + IDENTIFIER
        )
        self.assertIn("VIEW", dump)
        self.assertIn("FUNCTION", dump)
        self.site_query("DROP VIEW v; DROP FUNCTION f(); DROP TABLE t;", "s" + IDENTIFIER)
        self.restore_file("/run/sdbdump.sql", dump)
        imported = self.native(
            "runuser -u s"
            + IDENTIFIER
            + " -- psql -X -q -d s"
            + IDENTIFIER
            + " -f /run/sdbdump.sql 2>&1"
        )
        self.assertNotIn("ERROR", imported)
        self.assertEqual(
            self.site_query(
                "SELECT COUNT(*) FROM pg_database d WHERE d.datname = '"  # noqa: S608
                + OTHER
                + "' AND has_database_privilege(d.oid,'CONNECT')",
                "s" + IDENTIFIER,
            ).strip(),
            "0",
        )
        denied = self.native(
            "runuser -u s"
            + IDENTIFIER
            + " -- psql -X -q -d "
            + OTHER
            + " -c 'SELECT 1' 2>&1 || true"
        )
        self.assertIn("permission denied", denied.lower())

    def test_2_a_partial_binding_is_finished_without_overwriting(self) -> None:
        from databases import site

        self.native(
            "su - postgres -c "
            + shlex.quote(
                "psql -X -q -c "
                + shlex.quote(f"GRANT CONNECT, TEMPORARY ON DATABASE s{IDENTIFIER} TO PUBLIC")
            )
        )
        self.native(
            "su - postgres -c "
            + shlex.quote(
                "psql -X -q -d s"
                + IDENTIFIER
                + " -c "
                + shlex.quote("GRANT ALL ON SCHEMA public TO PUBLIC")
            )
        )
        with self.shell() as shell:
            draft = self.prepare(shell)
            self.assertTrue(draft.eligible, draft.refusals)
            statements = cast(list[list[str]], draft.document["statements"])
            self.assertEqual([row[0] for row in statements], ["privileges", "schema"])
        review = self.bind(timeout=150)
        with self.shell() as shell:
            self.assertTrue(site.verify(shell, review))
        self.assertEqual(self.site_query("SELECT i FROM t", "s" + IDENTIFIER).strip(), "7")

    def test_3_a_fresh_controller_reconstructs_the_binding(self) -> None:
        with self.shell() as fresh:
            draft = self.prepare(fresh)
            self.assertTrue(draft.eligible, draft.refusals)
            self.assertTrue(draft.no_changes)
