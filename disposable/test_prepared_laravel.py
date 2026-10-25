"""The prepared-Laravel cache layer: L1 plus a deployed site, workers, Valkey and phpredis.

docs/quality.md#native-layer. Creating, deploying and starting the queue workers costs more
than one item; the L5 snapshot commits them once so the cache lifecycle stays a small item.
"""

import os

from django.test import tag

from operations.inputs import PreparationInputs

from . import images
from .change_testing import apply_change
from .docker import docker
from .scenario_testing import SCENARIO_TAG
from .test_automation import _PROBE_JOB, _QUEUE_MIGRATION
from .test_laravel_deploy import LaravelDeployCase

_LARAVEL_CACHE_ROUTE = """<?php

use Illuminate\\Support\\Facades\\Cache;
use Illuminate\\Support\\Facades\\Route;

Route::get('/', function () {
    Cache::put('barectl-cache-check', 'through-the-private-cache', 60);

    return Cache::get('barectl-cache-check', 'miss');
});
"""

_MIGRATION_SESSIONS_ONLY = """<?php

use Illuminate\\Database\\Migrations\\Migration;
use Illuminate\\Database\\Schema\\Blueprint;
use Illuminate\\Support\\Facades\\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('sessions', function (Blueprint $table) {
            $table->string('id')->primary();
            $table->foreignId('user_id')->nullable()->index();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->longText('payload');
            $table->integer('last_activity')->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sessions');
    }
};
"""


@tag(SCENARIO_TAG)
class PrepareLaravel(LaravelDeployCase):
    """L1 plus the deployed worker fixture with its cache route and prerequisites."""

    layer = "L1"
    preparation = True
    identity = "sqwalpha"
    domain = "site.fixture.test"
    prefix = "sqw"

    def test_commits_the_laravel_cache_fixture_into_the_prepared_layer(self) -> None:
        from automation import worker_change
        from cache import engine as cache_engine
        from laravel import change
        from sites.client_change import SET_SITE_PHP_CLIENT

        self.install_acme()
        self.install_engine()
        self.create()
        self.push(
            {
                "database/migrations/2026_10_20_000000_create_queue_tables.php": _QUEUE_MIGRATION,
                "app/Jobs/BarectlProbe.php": _PROBE_JOB,
                "resources/views/welcome.blade.php": (
                    "<html><body>Queue worker fixture</body></html>\n"
                ),
                "routes/web.php": _LARAVEL_CACHE_ROUTE,
                "database/migrations/2026_10_19_000000_create_sessions_table.php": (
                    _MIGRATION_SESSIONS_ONLY
                ),
            },
            "cache worker fixture",
        )
        line, unit, _ = self.apply(change.DEPLOY_SITE, self.deploy_inputs(), timeout=180)
        self.assert_succeeded(line, unit)
        apply_change(
            self,
            worker_change.SET_LARAVEL_QUEUE_WORKERS,
            PreparationInputs(
                "",
                self.identity,
                worker_action="start",
                worker_queues=("default",),
                worker_processes=2,
                worker_timeout=60,
            ),
            timeout=120,
        )
        apply_change(self, cache_engine.INSTALL, PreparationInputs(), timeout=180)
        apply_change(
            self,
            SET_SITE_PHP_CLIENT,
            PreparationInputs(identifier=self.identity, php_client=True),
            timeout=180,
        )
        self.assertIn("CACHE_STORE=database", self.native(f"cat {self.base()}/private/laravel.env"))
        self.assertEqual(self.https_status("/"), 200)
        self.assertEqual(self.https_body("/"), "through-the-private-cache")
        image = images.tag("L5")
        if not images.exists(image):
            docker("commit", os.environ["BARECTL_SSH_TEST_CONTAINER"], image, timeout=60)
        self.assertEqual(images.ensure("L5"), image)


__all__ = ["PrepareLaravel"]
