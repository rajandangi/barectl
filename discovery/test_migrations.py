"""The observation vocabulary migration renames models and fields without losing rows."""

from typing import override

from django.db import connection, models
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.utils import timezone

BEFORE = [("discovery", "0004_discoverysnapshot_pools_source_and_more")]
AFTER = [("discovery", "0005_rename_observation_vocabulary")]
STATUSES = {
    f"{prefix}_status": "observed" for prefix in ("os", "arch", "cpu", "memory", "filesystem")
}


class ObservationVocabularyMigrationTests(TransactionTestCase):
    @override
    def tearDown(self) -> None:
        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes())
        super().tearDown()

    @staticmethod
    def migrate(target: list[tuple[str, str]]) -> dict[str, models.Manager[models.Model]]:
        """Migrate to ``target`` and return its historical discovery models' managers."""
        executor = MigrationExecutor(connection)
        executor.migrate(target)
        apps = executor.loader.project_state(target).apps
        managers = {
            model._meta.object_name or "": model._default_manager
            for model in apps.get_app_config("discovery").get_models()
        }
        managers["Server"] = apps.get_model("servers", "Server")._default_manager
        return managers

    def seed(self) -> None:
        old = self.migrate(BEFORE)
        server = old["Server"].create(name="Web", ssh_alias="web")
        attempt = old["DiscoveryAttempt"].create(server=server, ssh_alias="web", status="succeeded")
        snapshot = old["DiscoverySnapshot"].create(
            server=server,
            attempt=attempt,
            collected_at=timezone.now(),
            sites_status="inaccessible",
            sites_source="/etc/nginx/sites-enabled",
            sites_warning="The SSH user cannot read the site configuration files.",
            pools_status="observed",
            pools_source="/etc/php",
            **STATUSES,
        )
        old["ServiceObservation"].create(
            snapshot=snapshot,
            component="nginx",
            package_status="observed",
            packages="nginx 1.24.0",
            service_status="observed",
            units="nginx.service active (running), enabled",
        )
        old["SiteObservation"].create(
            snapshot=snapshot, name="default", status="observed", listens="80", source="default"
        )
        old["PoolObservation"].create(
            snapshot=snapshot, version="8.3", name="www", status="observed", listen="9000"
        )

    def test_rows_and_values_survive_the_renames(self) -> None:
        self.seed()
        new = self.migrate(AFTER)
        self.assertEqual(
            list(
                new["DiscoverySnapshot"].values_list(
                    "nginx_site_files_status",
                    "nginx_site_files_source",
                    "nginx_site_files_warning",
                    "php_fpm_pools_status",
                    "php_fpm_pools_source",
                    "components__units",
                    "nginx_site_files__listens",
                    "php_fpm_pools__listen",
                )
            ),
            [
                (
                    "inaccessible",
                    "/etc/nginx/sites-enabled",
                    "The SSH user cannot read the site configuration files.",
                    "observed",
                    "/etc/php",
                    "nginx.service active (running), enabled",
                    "80",
                    "9000",
                )
            ],
        )
        self.assertEqual(
            list(new["ComponentObservation"].values_list("component", "packages")),
            [("nginx", "nginx 1.24.0")],
        )
        self.assertEqual(list(new["NginxSiteObservation"].values_list("name")), [("default",)])
        self.assertEqual(
            list(new["PhpFpmPoolObservation"].values_list("version", "name")), [("8.3", "www")]
        )

    def test_reversing_restores_the_previous_names(self) -> None:
        self.seed()
        self.migrate(AFTER)
        old = self.migrate(BEFORE)
        self.assertEqual(
            list(
                old["DiscoverySnapshot"].values_list(
                    "sites_status", "pools_source", "services__units", "sites__name", "pools__name"
                )
            ),
            [
                (
                    "inaccessible",
                    "/etc/php",
                    "nginx.service active (running), enabled",
                    "default",
                    "www",
                )
            ],
        )
