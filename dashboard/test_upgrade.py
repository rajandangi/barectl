import shutil
import sqlite3
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import ClassVar, override
from unittest import mock

from django.contrib.auth.hashers import check_password
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase

from operations.models import RemoteOperation
from servers.models import Server

from . import upgrade
from .upgrade import (
    PRE_BASELINE_REFUSAL,
    V040_MIGRATIONS,
    V040_SENTINELS,
    SchemaState,
    UpgradeEnvironment,
    UpgradeRefused,
    perform_upgrade,
)

FIXTURE = Path(__file__).resolve().parent / "upgrade_fixtures" / "v0.4.0.sqlite"
PENDING = frozenset({("dashboard", "9999_pending_for_the_upgrade_test")})


def pending_schema() -> SchemaState:
    """A 0.4.0 database with one migration this release still has to apply."""
    return SchemaState(applied=V040_MIGRATIONS, known=V040_MIGRATIONS | PENDING)


class UpgradeTestCase(TestCase):
    server: ClassVar[Server]
    restored: list[Path]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def environment(
        self,
        state: SchemaState,
        *,
        backup: Path | None = None,
        migrate: Callable[[], None] | None = None,
        restore: Callable[[Path], None] | None = None,
        commands: list[str] | None = None,
        operations: list[RemoteOperation] | None = None,
        tasks: int = 0,
        servers: list[Server] | None = None,
        request: Callable[[Server], object] | None = None,
    ) -> UpgradeEnvironment:
        restored: list[Path] = []
        self.restored = restored

        def create_backup() -> Path:
            if backup is None:
                self.fail("The upgrade created a backup when it should not have.")
            return backup

        def run_migrations() -> None:
            if migrate is not None:
                migrate()

        return UpgradeEnvironment(
            installed_version=lambda: "1.0.0",
            schema_state=lambda: state,
            active_operations=lambda: operations or [],
            active_tasks=lambda: tasks,
            process_commands=lambda: commands or [],
            create_backup=create_backup,
            run_migrations=run_migrations,
            restore_backup=restored.append,
            servers=lambda: servers or [],
            request_discovery=request or (lambda server: object()),
        )

    def failing_migration(self) -> Callable[[], None]:
        def migrate() -> None:
            raise RuntimeError("a migration failed")

        return migrate


class UpgradeTests(UpgradeTestCase):
    def test_successful_upgrade_backs_up_migrates_and_queues_every_server(self) -> None:
        backup = Path("/controller/upgrade-backups/20261109T120000Z")
        migrated: list[bool] = []
        other = Server.objects.create(name="Database", ssh_alias="db-1")
        queued: list[Server] = []

        def migrate() -> None:
            migrated.append(True)

        outcome = perform_upgrade(
            environment=self.environment(
                pending_schema(),
                backup=backup,
                migrate=migrate,
                servers=[self.server, other],
                request=queued.append,
            )
        )

        self.assertEqual(migrated, [True])
        self.assertEqual(outcome.backup, backup)
        self.assertEqual(outcome.queued, (self.server, other))
        self.assertEqual(outcome.unreadable, ())
        self.assertEqual(queued, [self.server, other])

    def test_refuses_while_a_remote_operation_is_active(self) -> None:
        operation = RemoteOperation.objects.create(
            server=self.server,
            ssh_alias=self.server.ssh_alias,
            kind=RemoteOperation.Kind.CHANGE_PREPARATION,
            status=RemoteOperation.Status.RUNNING,
        )
        migrated: list[bool] = []

        def migrate() -> None:
            migrated.append(True)

        with self.assertRaisesMessage(UpgradeRefused, upgrade.ACTIVE_OPERATION_REFUSAL):
            perform_upgrade(
                environment=self.environment(
                    pending_schema(), operations=[operation], migrate=migrate
                )
            )
        self.assertEqual(migrated, [])

    def test_refuses_while_a_queued_task_remains(self) -> None:
        with self.assertRaisesMessage(UpgradeRefused, upgrade.ACTIVE_TASK_REFUSAL):
            perform_upgrade(environment=self.environment(pending_schema(), tasks=1))

    def test_refuses_while_the_worker_is_running(self) -> None:
        with self.assertRaisesMessage(UpgradeRefused, upgrade.WORKER_REFUSAL):
            perform_upgrade(
                environment=self.environment(
                    pending_schema(), commands=["python manage.py db_worker"]
                )
            )

    def test_refuses_a_pre_0_4_0_database_with_one_sentence(self) -> None:
        missing = next(iter(V040_SENTINELS))
        with self.assertRaisesMessage(UpgradeRefused, PRE_BASELINE_REFUSAL):
            perform_upgrade(
                environment=self.environment(
                    SchemaState(V040_MIGRATIONS - {missing}, V040_MIGRATIONS)
                )
            )
        self.assertTrue(PRE_BASELINE_REFUSAL.endswith("."))
        self.assertNotIn("\n", PRE_BASELINE_REFUSAL)

    def test_failed_migration_restores_the_original_database(self) -> None:
        backup = Path("/controller/upgrade-backups/20261109T120000Z")
        environment = self.environment(
            pending_schema(), backup=backup, migrate=self.failing_migration()
        )

        with self.assertRaisesMessage(UpgradeRefused, f"Backup: {backup}"):
            perform_upgrade(environment=environment)

        self.assertEqual(self.restored, [backup])

    def test_reports_a_server_whose_discovery_could_not_be_queued(self) -> None:
        other = Server.objects.create(name="Broken", ssh_alias="broken.example.com")

        def request(server: Server) -> object:
            if server == other:
                raise RuntimeError("the row vanished")
            return object()

        outcome = perform_upgrade(
            environment=self.environment(
                pending_schema(),
                backup=Path("/controller/upgrade-backups/20261109T120000Z"),
                servers=[self.server, other],
                request=request,
            )
        )

        self.assertEqual(outcome.queued, (self.server,))
        self.assertEqual(outcome.unreadable, ((other, "RuntimeError"),))


class BackupTests(TestCase):
    @override
    def setUp(self) -> None:
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.directory = directory
        self.database = directory / "db.sqlite3"
        self.env_file = directory / ".env"
        with sqlite3.connect(self.database) as database:
            database.execute("CREATE TABLE record (value TEXT NOT NULL)")
            database.execute("INSERT INTO record VALUES ('original')")
        self.env_file.write_text("BARECTL_SECRET_KEY=fixture\n", encoding="utf-8")

    def test_backup_is_timestamped_and_contains_database_and_environment(self) -> None:
        backup = upgrade.create_database_backup(
            database=self.database,
            env_file=self.env_file,
            root=self.directory / "upgrades",
            now=datetime(2026, 11, 9, 12, 0, tzinfo=UTC),
        )

        self.assertEqual(backup.name, "20261109T120000Z")
        self.assertEqual(backup.parent, self.directory / "upgrades")
        with sqlite3.connect(backup / "db.sqlite3") as database:
            self.assertEqual(database.execute("SELECT value FROM record").fetchone(), ("original",))
        self.assertEqual(
            (backup / ".env").read_text(encoding="utf-8"), "BARECTL_SECRET_KEY=fixture\n"
        )

    def test_restore_puts_the_original_database_back(self) -> None:
        backup = upgrade.create_database_backup(
            database=self.database,
            env_file=self.env_file,
            root=self.directory / "upgrades",
            now=datetime(2026, 11, 9, 12, 0, tzinfo=UTC),
        )
        with sqlite3.connect(self.database) as database:
            database.execute("DELETE FROM record")
            database.execute("INSERT INTO record VALUES ('changed')")
        (self.database.with_name("db.sqlite3-wal")).write_bytes(b"stale")

        upgrade.restore_database_backup(backup, database=self.database)

        with sqlite3.connect(self.database) as database:
            self.assertEqual(database.execute("SELECT value FROM record").fetchone(), ("original",))
        self.assertFalse(self.database.with_name("db.sqlite3-wal").exists())


class SchemaStateTests(TestCase):
    def test_current_schema_contains_the_0_4_0_baseline(self) -> None:
        state = upgrade.schema_state()

        self.assertTrue(state.baseline_applied)
        self.assertTrue(state.applied >= V040_MIGRATIONS)
        self.assertTrue(V040_SENTINELS <= V040_MIGRATIONS)
        self.assertEqual(state.unknown, frozenset())
        self.assertEqual(state.describe(), "up to date")

    def test_a_partly_migrated_database_names_the_pending_count(self) -> None:
        state = pending_schema()

        self.assertEqual(state.pending, PENDING)
        self.assertEqual(state.describe(), "0.4.0 with 1 migration pending")


class CommandTests(UpgradeTestCase):
    def test_command_reports_version_and_next_commands(self) -> None:
        backup = Path("/controller/upgrade-backups/20261109T120000Z")
        environment = self.environment(pending_schema(), backup=backup, servers=[self.server])

        with mock.patch.object(upgrade, "default_environment", return_value=environment):
            out = StringIO()
            call_command("barectl_upgrade", stdout=out)

        content = out.getvalue()
        self.assertIn("Installed version: 1.0.0", content)
        self.assertIn("Database schema: 0.4.0 with 1 migration pending", content)
        self.assertIn(f"Backup written to {backup}", content)
        self.assertIn("Queued a fresh discovery for Web", content)
        self.assertIn("python manage.py db_worker", content)

    def test_command_prints_version_and_schema_before_refusing(self) -> None:
        environment = self.environment(SchemaState(frozenset(), V040_MIGRATIONS))

        with (
            mock.patch.object(upgrade, "default_environment", return_value=environment),
            self.assertRaisesMessage(CommandError, PRE_BASELINE_REFUSAL),
        ):
            out = StringIO()
            call_command("barectl_upgrade", stdout=out)

        content = out.getvalue()
        self.assertIn("Installed version: 1.0.0", content)
        self.assertIn("Database schema: no recorded migrations", content)


class FixtureMigrationTests(TransactionTestCase):
    database: ClassVar[Path]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.database = directory / "fixture.sqlite3"
        shutil.copyfile(FIXTURE, cls.database)

    def one(
        self, database: sqlite3.Connection, sql: str, parameters: tuple[object, ...] = ()
    ) -> tuple[object, ...]:
        row = database.execute(sql, parameters).fetchone()
        if row is None:
            self.fail(f"No row for {sql} {parameters}")
        return tuple(row)

    def test_every_represented_record_survives_migration(self) -> None:
        original = connection.settings_dict["NAME"]
        connection.close()
        connection.settings_dict["NAME"] = str(self.database)
        try:
            executor = MigrationExecutor(connection)
            executor.migrate(executor.loader.graph.leaf_nodes())
        finally:
            connection.close()
            connection.settings_dict["NAME"] = original

        with sqlite3.connect(self.database) as database:
            applied = frozenset(
                (str(app), str(name))
                for app, name in database.execute("SELECT app, name FROM django_migrations")
            )
            self.assertEqual(applied, V040_MIGRATIONS)
            for table in (
                "auth_user",
                "servers_server",
                "servers_connectiondefinition",
                "discovery_discoveryattempt",
                "discovery_discoverysnapshot",
                "discovery_settingobservation",
                "operations_changepreparation",
                "operations_changereview",
                "operations_changerun",
            ):
                with self.subTest(table=table):
                    count = self.one(database, f"SELECT COUNT(*) FROM {table}")[0]  # noqa: S608
                    self.assertEqual(count, 1)
            self.assertEqual(self.one(database, "SELECT COUNT(*) FROM auth_group")[0], 3)

            user_id, email, encoded = self.one(
                database,
                "SELECT id, email, password FROM auth_user WHERE username = ?",
                ("operator",),
            )
            self.assertEqual(email, "operator@example.com")
            self.assertTrue(check_password("fixture-password", str(encoded)))
            administrator_id = self.one(
                database, "SELECT id FROM auth_group WHERE name = ?", ("Administrator",)
            )[0]
            self.assertEqual(
                self.one(
                    database,
                    "SELECT group_id FROM auth_user_groups WHERE user_id = ?",
                    (user_id,),
                )[0],
                administrator_id,
            )
            codenames = {
                str(codename)
                for (codename,) in database.execute(
                    "SELECT permission.codename FROM auth_group_permissions AS membership "
                    "JOIN auth_permission AS permission "
                    "ON permission.id = membership.permission_id "
                    "WHERE membership.group_id = ?",
                    (administrator_id,),
                )
            }
            self.assertEqual(
                codenames,
                {
                    "view_changes",
                    "change_site",
                    "change_shared",
                    "change_destructive",
                    "manage_secrets",
                    "view_evidence",
                    "view_server",
                },
            )

            server_id, alias, revision = self.one(
                database,
                "SELECT id, ssh_alias, connection_revision FROM servers_server WHERE name = ?",
                ("Web",),
            )
            self.assertEqual(alias, "web.example.com")
            self.assertEqual(revision, 1)
            saved_revision, address, username = self.one(
                database,
                "SELECT revision, address, username FROM servers_connectiondefinition "
                "WHERE server_id = ?",
                (server_id,),
            )
            self.assertEqual(saved_revision, revision)
            self.assertEqual(address, "203.0.113.10")
            self.assertEqual(username, "deploy")

            attempt_id, status, requester = self.one(
                database,
                "SELECT attempt.remoteoperation_ptr_id, operation.status, attempt.requested_by_id "
                "FROM discovery_discoveryattempt AS attempt "
                "JOIN operations_remoteoperation AS operation "
                "ON operation.id = attempt.remoteoperation_ptr_id "
                "WHERE operation.server_id = ?",
                (server_id,),
            )
            self.assertEqual(status, "succeeded")
            self.assertEqual(requester, user_id)
            snapshot_id, collected_at, pretty_name, standing = self.one(
                database,
                "SELECT id, collected_at, os_pretty_name, host_standing "
                "FROM discovery_discoverysnapshot WHERE attempt_id = ?",
                (attempt_id,),
            )
            self.assertEqual(collected_at, "2026-10-20 09:30:00")
            self.assertEqual(pretty_name, "Ubuntu 26.04.1 LTS")
            self.assertEqual(standing, "target_stack")
            identifier, application, name, value = self.one(
                database,
                "SELECT identifier, application, name, value "
                "FROM discovery_settingobservation WHERE snapshot_id = ?",
                (snapshot_id,),
            )
            self.assertEqual(identifier, "shop")
            self.assertEqual(application, "laravel")
            self.assertEqual(name, "APP_NAME")
            self.assertEqual(value, "Fixture Shop")

            preparation_id, kind, preparer = self.one(
                database,
                "SELECT remoteoperation_ptr_id, kind_slug, requested_by_id "
                "FROM operations_changepreparation",
            )
            self.assertEqual(kind, "install_database_engine")
            self.assertEqual(preparer, user_id)
            review_id, preparation, intent = self.one(
                database,
                "SELECT id, preparation_id, intent FROM operations_changereview",
            )
            self.assertEqual(preparation, preparation_id)
            self.assertEqual(intent, "Install MariaDB")
            review_of_run, server_of_run, runner, status, execution, verification = self.one(
                database,
                "SELECT run.review_id, operation.server_id, run.requested_by_id, "
                "operation.status, run.execution, run.verification "
                "FROM operations_changerun AS run "
                "JOIN operations_remoteoperation AS operation "
                "ON operation.id = run.remoteoperation_ptr_id",
            )
            self.assertEqual(review_of_run, review_id)
            self.assertEqual(server_of_run, server_id)
            self.assertEqual(runner, user_id)
            self.assertEqual(status, "succeeded")
            self.assertEqual(execution, "succeeded")
            self.assertEqual(verification, "passed")
