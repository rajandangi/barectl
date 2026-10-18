"""A database engine installed and removed by the product's own reviewed change (#378).

docs/quality.md#native-layer. The lane server reaches only its lane: the pinned snapshot
archive that resolves the exact packages, over the fixture CA. Each method proves one
acceptance criterion of issue #378 on a real Ubuntu 26.04 host.
"""

import shlex
from typing import cast

from django.test import tag

from discovery.ssh import RemoteShell
from operations.engine import ChangeKind, ReviewDraft
from operations.inputs import PreparationInputs

from . import mirror
from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


def write(test: ScenarioTestCase, shell: RemoteShell, path: str, content: str) -> None:
    result = shell.run(f"install -D -m 0644 /dev/stdin {shlex.quote(path)}", stdin=content.encode())
    test.assertEqual(result.exit_status, 0, result.stdout)


class DatabaseEngineCase(ScenarioTestCase):
    """The shared setup: point the server's APT at the lane's pinned snapshot."""

    layer = "L1"
    exclusive = True

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

    def review(self, shell: RemoteShell, kind: ChangeKind, engine_name: str) -> ReviewDraft:
        inputs = PreparationInputs(engine_name)
        return kind.review(kind.inspect(shell, inputs), inputs)


@tag(SCENARIO_TAG)
class DatabaseEngineMariaDB(DatabaseEngineCase):
    prefix = "dbm"

    def test_1_installs_mariadb_and_hardens_it(self) -> None:
        from databases import engine as kinds
        from operations.inputs import PreparationInputs

        with self.shell() as shell:
            self.router(shell)
            draft = self.review(shell, kinds.INSTALL, "mariadb")
            self.assertTrue(draft.eligible, draft.refusals)
            self.assertEqual([effect.scope.value for effect in draft.effects], ["server"])
            roots = " ".join(
                f"{name} {version}"
                for name, version in cast(list[list[str]], draft.document["roots"])
            )
            self.assertIn("mariadb-server 1:", roots)
            apply_change(self, kinds.INSTALL, PreparationInputs("mariadb"), timeout=120)
        self.assertIn("active", self.native("systemctl is-active mariadb.service"))
        self.assertIn("mysqld.sock", self.native("ss -Hlx src /run/mysqld/mysqld.sock"))
        self.assertEqual(self.native("ss -Hltn 'sport = :3306'").strip(), "")
        query = (
            "mariadb --no-defaults --protocol=socket --socket=/run/mysqld/mysqld.sock "
            "--user=root -N -B -e"
        )
        self.assertEqual(
            self.native(
                f"{query} \"SELECT COUNT(*) FROM mysql.global_priv WHERE User = ''\""  # noqa: S608
            ).strip(),
            "0",
        )
        self.assertEqual(
            self.native(
                f'{query} "SELECT COUNT(*) FROM information_schema.SCHEMATA '  # noqa: S608
                "WHERE SCHEMA_NAME = 'test'\""
            ).strip(),
            "0",
        )

    def test_2_a_second_review_proposes_no_changes(self) -> None:
        from databases import engine as kinds

        with self.shell() as shell:
            draft = self.review(shell, kinds.INSTALL, "mariadb")
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.effects)
        self.assertIn("already installed", str(draft.document["note"]))

    def test_3_a_fresh_controller_reconstructs_the_engine_and_its_version(self) -> None:
        from databases import observation
        from discovery.observations import collect

        with self.shell() as shell:
            observed = collect(shell, sites=False)
        engines = observation.installed_engines(observed)
        mariadb = next(engine for engine in engines if engine.engine == "mariadb")
        self.assertIn("11.8.6", mariadb.version)
        self.assertTrue(mariadb.managed)
        self.assertTrue(any(unit.active_state == "active" for unit in mariadb.units))

    def test_4_a_second_engine_is_outside_supported_settings(self) -> None:
        from databases import engine as kinds

        with self.shell() as shell:
            draft = self.review(shell, kinds.INSTALL, "postgresql")
        self.assertFalse(draft.eligible)
        self.assertTrue(any("one database engine" in reason for reason in draft.refusals))

    def test_5_removal_is_refused_while_a_site_database_exists(self) -> None:
        from databases import engine as kinds

        created = self.native(
            "mariadb --no-defaults --protocol=socket --socket=/run/mysqld/mysqld.sock "
            "--user=root -e 'CREATE DATABASE s1alpha'"
        )
        self.assertEqual(created, "")
        with self.shell() as shell:
            draft = self.review(shell, kinds.REMOVE, "mariadb")
        self.assertFalse(draft.eligible)
        self.assertTrue(any("refuses to remove" in reason for reason in draft.refusals))

    def test_6_removal_frees_the_engine_once_the_database_is_gone(self) -> None:
        from databases import engine as kinds
        from operations.inputs import PreparationInputs

        self.native(
            "mariadb --no-defaults --protocol=socket --socket=/run/mysqld/mysqld.sock "
            "--user=root -e 'DROP DATABASE s1alpha'"
        )
        with self.shell() as shell:
            draft = self.review(shell, kinds.REMOVE, "mariadb")
            self.assertTrue(draft.eligible, draft.refusals)
        apply_change(self, kinds.REMOVE, PreparationInputs("mariadb"), timeout=120)
        self.assertNotEqual(
            self.native("dpkg-query -W -f='${db:Status-Status}' mariadb-server").strip(),
            "installed",
        )
        listing = self.native("ls -ld /var/lib/mysql 2>&1 || true")
        self.assertIn("/var/lib/mysql", listing)


@tag(SCENARIO_TAG)
class DatabaseEnginePostgreSQL(DatabaseEngineCase):
    prefix = "dbp"

    def test_1_installs_postgresql_with_loopback_only(self) -> None:
        from databases import engine as kinds
        from operations.inputs import PreparationInputs

        with self.shell() as shell:
            self.router(shell)
            draft = self.review(shell, kinds.INSTALL, "postgresql")
            self.assertTrue(draft.eligible, draft.refusals)
            roots = " ".join(
                f"{name} {version}"
                for name, version in cast(list[list[str]], draft.document["roots"])
            )
            self.assertIn("postgresql ", roots)
            apply_change(self, kinds.INSTALL, PreparationInputs("postgresql"), timeout=150)
        self.assertIn("active", self.native("systemctl is-active postgresql.service"))
        self.assertIn(
            "active",
            self.native("systemctl is-active postgresql@18-main.service"),
        )
        listeners = self.native("ss -Hltn 'sport = :5432'").strip()
        for line in listeners.splitlines():
            self.assertRegex(line, r"(127\.0\.0\.1|\[::1\]):5432")

    def test_2_a_fresh_controller_reconstructs_the_engine_and_its_version(self) -> None:
        from databases import observation
        from discovery.observations import collect

        with self.shell() as shell:
            observed = collect(shell, sites=False)
        engines = observation.installed_engines(observed)
        postgres = next(engine for engine in engines if engine.engine == "postgresql")
        self.assertIn("18.6", postgres.version)
        self.assertTrue(postgres.managed)

    def test_3_a_database_refuses_removal(self) -> None:
        from databases import engine as kinds

        created = self.native("su - postgres -c \"psql -X -q -c 'CREATE DATABASE s1alpha'\"")
        self.assertEqual(created, "")
        with self.shell() as shell:
            draft = self.review(shell, kinds.REMOVE, "postgresql")
        self.assertFalse(draft.eligible)
        self.assertTrue(any("refuses to remove" in reason for reason in draft.refusals))
