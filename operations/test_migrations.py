"""Upgrade existing operation audit rows through the additive change-engine migration."""

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

from operations.models import RemoteOperation


class ChangeEngineUpgradeTests(TransactionTestCase):
    def test_existing_remote_operation_survives_the_engine_schema_migration(self) -> None:
        latest = MigrationExecutor(connection).loader.graph.leaf_nodes()

        def restore_schema() -> None:
            MigrationExecutor(connection).migrate(latest)

        self.addCleanup(restore_schema)
        start = [
            ("operations", "0001_initial"),
            ("servers", "0001_initial"),
            ("discovery", "0005_discoverysnapshot_host_evidence"),
        ]
        MigrationExecutor(connection).migrate(start)
        historical = MigrationExecutor(connection).loader.project_state(start).apps
        historical_server = historical.get_model("servers", "Server")
        historical_operation = historical.get_model("operations", "RemoteOperation")
        server = historical_server.objects.create(name="Upgrade test", ssh_alias="upgrade.example")
        previous = historical_operation.objects.create(
            server=server,
            kind="apply",
            ssh_alias=server.ssh_alias,
            status="succeeded",
        )

        target = [("operations", "0002_change_engine")]
        MigrationExecutor(connection).migrate(target)

        restore_schema()
        upgraded = RemoteOperation.objects.get(pk=previous.pk)
        self.assertEqual(
            (upgraded.server_id, upgraded.kind, upgraded.status),
            (server.pk, "apply", "succeeded"),
        )
