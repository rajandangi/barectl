"""WordPress server cron on a real Ubuntu 26.04 host (Phase C #357, native scenario C1 part 2).

docs/quality.md#native-layer. The fast layer proves the review, the projection and the
body's order; only a real systemd can prove that a calendar tick runs the site's due
events, that a page load stops running them once the task owns cron, that ticks continue
with no controller involved, and that turning off gives page-load cron back first.
"""

import os
import shlex
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import override

from django.test import tag

from automation import change
from automation.convention import service_name, timer_name
from automation.worker_observation import ObservedWorker
from automation.workers import WorkerDefinition
from discovery import recorded, ssh
from operations.inputs import PreparationInputs
from wordpress import create

from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG
from .test_laravel_deploy import LaravelDeployCase
from .test_wordpress_create import CANARY, DOMAIN, IDENTIFIER, WordPressCreateCase

STATE = "automation-wordpress-26.04"
QUEUE_STATE = "automation-laravel-26.04"
DUE_EVENT = "barectl_probe"
ON_EVENT = "barectl_probe_on"
OFF_EVENT = "barectl_probe_off"
PRIVATE = f"/var/www/{IDENTIFIER}/private/wp-config.php"


@tag(SCENARIO_TAG)
class WordPressServerCron(WordPressCreateCase):
    records: tuple[str, ...] = (STATE,)

    @override
    @contextmanager
    def shell(self) -> Iterator[ssh.RemoteShell]:
        """A plain connection: only the checkpoint shell records a transcript.

        Setup applies reviewed changes that use the confidential channel, which a recording
        shell refuses by design (ADR 0032).
        """
        os.environ["SSH_AUTH_SOCK"] = ""
        with ssh.connect(self.target()) as connection:
            yield connection

    def wp(self, *arguments: str) -> str:
        command = " ".join(shlex.quote(argument) for argument in arguments)
        return self.native(
            f"runuser -u s{IDENTIFIER} -- /var/www/{IDENTIFIER}/bin/wp "
            f"--path=/var/www/{IDENTIFIER}/current/public {command}"
        ).strip()

    def due_events(self, hook: str = DUE_EVENT) -> int:
        return int(self.wp("eval", f"echo (int) (bool) wp_next_scheduled('{hook}');"))

    def schedule_due_event(self, hook: str = DUE_EVENT, *, delay: int = 0) -> None:
        scheduled = self.wp(
            "eval",
            f"var_export(wp_schedule_single_event(time() + {delay}, '{hook}')); "
            f"echo '|', (int) (bool) wp_next_scheduled('{hook}');",
        )
        self.assertEqual(self.due_events(hook), 1, scheduled)

    def wait_manageable(self, *, timeout: float = 60) -> None:
        """Wait for the host to report the target stack before reading or applying."""
        from bootstrap.standing import Standing
        from discovery.observations import collect

        end = time.monotonic() + timeout
        while True:
            with self.shell() as shell:
                standing = collect(shell, sites=False).standing
            if standing is not None and standing.standing == Standing.TARGET_STACK:
                return
            if time.monotonic() >= end:
                self.fail(f"The host is not manageable: {standing}")

    def wait_for_due_events(self, count: int, *, hook: str = DUE_EVENT, timeout: float = 20) -> int:
        end = time.monotonic() + timeout
        value = self.due_events(hook)
        while value != count and time.monotonic() < end:
            time.sleep(0.2)
            value = self.due_events(hook)
        return value

    def visit_home(self) -> None:
        self.native(
            "curl --fail --silent --show-error --max-time 20 --insecure "
            f"--resolve {DOMAIN}:443:127.0.0.1 https://{DOMAIN}/ >/dev/null"
        )

    def constant(self) -> str:
        return self.native(
            f"grep -o \"DISABLE_WP_CRON', '[a-z]*\" {shlex.quote(PRIVATE)} || true"
        ).strip()

    def property(self, unit: str, name: str) -> str:
        return self.native(f"systemctl show --value -p {name} {unit}").strip()

    def unix_property(self, unit: str, name: str) -> str:
        return self.native(f"systemctl show --value --timestamp=unix -p {name} {unit}").strip()

    def test_1_creates_the_pinned_wordpress_site(self) -> None:
        self.install_acme()
        self.install_engine()
        apply_change(
            self,
            create.CREATE_WORDPRESS,
            self.inputs(),
            timeout=120,
            secret=CANARY.encode(),
        )
        home = self.native(
            "curl --silent --show-error --fail --max-time 20 --insecure "
            f"--resolve {DOMAIN}:443:127.0.0.1 https://{DOMAIN}/"
        )
        self.assertIn("WordPress", home)

    def test_2_turns_on_server_cron_and_page_loads_stop_running_it(self) -> None:
        self.wait_manageable()
        apply_change(
            self,
            change.SET_WORDPRESS_SERVER_CRON,
            PreparationInputs("", IDENTIFIER, schedule_state="on"),
            timeout=180,
        )
        timer = timer_name(IDENTIFIER, "wpcron")
        service = service_name(IDENTIFIER, "wpcron")
        self.assertIn("active", self.property(timer, "ActiveState"))
        self.assertIn("enabled", self.property(timer, "UnitFileState"))
        self.assertIn("true", self.constant())
        # One run happened before the hand-over: the timer fired it, not a page load.
        triggered = self.unix_property(timer, "LastTriggerUSec")
        started = self.unix_property(service, "ExecMainStartTimestamp")
        self.assertTrue(triggered.startswith("@") and triggered.strip("@").isdigit(), triggered)
        self.assertTrue(started.startswith("@") and started.strip("@").isdigit(), started)
        self.assertEqual(self.property(service, "Result"), "success")
        # A due event survives a page load once the server task owns cron.
        self.schedule_due_event(ON_EVENT, delay=-1)
        self.wp("eval", "delete_transient('doing_cron');")
        self.visit_home()
        self.assertEqual(self.wait_for_due_events(1, hook=ON_EVENT, timeout=3), 1)
        # The task itself runs it, exactly as the timer will every minute.
        self.native(f"systemctl start {service}")
        self.assertEqual(self.wait_for_due_events(0, hook=ON_EVENT, timeout=15), 0)
        # The timer is armed for the next minute without any controller involved.
        self.assertNotIn(self.property(timer, "NextElapseUSecRealtime"), ("", "0", "n/a"))

    def test_3_the_fresh_controller_reconstructs_it_and_proposes_nothing(self) -> None:
        inputs = PreparationInputs("", IDENTIFIER, schedule_state="on")
        self.wait_manageable()
        state = self.record_state
        if state:
            with ssh.connect(self.target()) as connection:
                shell: ssh.RemoteShell = recorded.RecordingShell(
                    connection, state, secrets=(recorded.SEEDED_SECRET,)
                )
                self._checkpoint(shell, inputs)
        else:
            with self.shell() as shell:
                self._checkpoint(shell, inputs)

    def _checkpoint(self, shell: ssh.RemoteShell, inputs: PreparationInputs) -> None:
        from discovery.observations import collect

        observed = collect(shell, releases=True)
        draft = change.review(change.inspect(shell, inputs), inputs)
        self.checkpoint(STATE, shell)
        schedule = next(row for row in observed.automation.value if row.identifier == IDENTIFIER)
        self.assertEqual(schedule.status.value, "succeeded")
        self.assertTrue(schedule.timer_enabled)
        self.assertEqual(schedule.disable_wp_cron, "true")
        self.assertTrue(draft.no_changes, draft.refusals)
        self.assertEqual(draft.effects, ())

    def test_4_turning_off_gives_page_load_cron_back_before_the_task_stops(self) -> None:
        self.wait_manageable()
        apply_change(
            self,
            change.SET_WORDPRESS_SERVER_CRON,
            PreparationInputs("", IDENTIFIER, schedule_state="off"),
            timeout=120,
        )
        timer = timer_name(IDENTIFIER, "wpcron")
        service = service_name(IDENTIFIER, "wpcron")
        self.assertNotIn("true", self.constant())
        # Page loads run a due event again, with no server task to wait for.
        self.schedule_due_event(OFF_EVENT, delay=5)
        self.wp("eval", "delete_transient('doing_cron');")
        self.visit_home()
        self.assertEqual(self.wait_for_due_events(0, hook=OFF_EVENT, timeout=15), 0)
        self.assertEqual(self.property(timer, "LoadState"), "not-found")
        self.assertEqual(self.property(service, "LoadState"), "not-found")
        self.assertEqual(
            self.native(
                f"test -e /etc/systemd/system/{timer} || "
                f"test -e /etc/systemd/system/{service} || echo gone"
            ).strip(),
            "gone",
        )


__all__ = ["LaravelQueueWorkers", "WordPressServerCron"]


_QUEUE_MIGRATION = r"""<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('jobs', function (Blueprint $table) {
            $table->id();
            $table->string('queue')->index();
            $table->longText('payload');
            $table->unsignedTinyInteger('attempts');
            $table->unsignedInteger('reserved_at')->nullable();
            $table->unsignedInteger('available_at');
            $table->unsignedInteger('created_at');
        });
        Schema::create('job_batches', function (Blueprint $table) {
            $table->string('id')->primary();
            $table->string('name');
            $table->integer('total_jobs');
            $table->integer('pending_jobs');
            $table->integer('failed_jobs');
            $table->longText('failed_job_ids');
            $table->mediumText('options')->nullable();
            $table->integer('cancelled_at')->nullable();
            $table->integer('created_at');
            $table->integer('finished_at')->nullable();
        });
        Schema::create('failed_jobs', function (Blueprint $table) {
            $table->id();
            $table->string('uuid')->unique();
            $table->text('connection');
            $table->text('queue');
            $table->longText('payload');
            $table->longText('exception');
            $table->timestamp('failed_at')->useCurrent();
        });
        Schema::create('cache', function (Blueprint $table) {
            $table->string('key')->primary();
            $table->mediumText('value');
            $table->integer('expiration');
        });
        Schema::create('cache_locks', function (Blueprint $table) {
            $table->string('key')->primary();
            $table->string('owner');
            $table->integer('expiration');
        });
        Schema::create('barectl_probe', function (Blueprint $table) {
            $table->id();
            $table->string('marker');
            $table->string('phase');
            $table->timestamp('created_at')->useCurrent();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('barectl_probe');
        Schema::dropIfExists('cache_locks');
        Schema::dropIfExists('cache');
        Schema::dropIfExists('failed_jobs');
        Schema::dropIfExists('job_batches');
        Schema::dropIfExists('jobs');
    }
};
"""

_PROBE_JOB = r"""<?php

namespace App\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\DB;

class BarectlProbe implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(
        public string $marker,
        public int $seconds = 0,
    ) {}

    public function handle(): void
    {
        DB::table('barectl_probe')->insert([
            'marker' => $this->marker,
            'phase' => 'start',
        ]);
        if ($this->seconds > 0) {
            sleep($this->seconds);
        }
        DB::table('barectl_probe')->insert([
            'marker' => $this->marker,
            'phase' => 'end',
        ]);
    }
}
"""


@tag(SCENARIO_TAG)
class LaravelQueueWorkers(LaravelDeployCase):
    """Database queue workers on a real host (Phase C #357, native scenario C2 part 2)."""

    prefix = "sqw"
    identity = "sqwalpha"
    records: tuple[str, ...] = (QUEUE_STATE,)

    @override
    @contextmanager
    def shell(self) -> Iterator[ssh.RemoteShell]:
        """A plain connection: only the checkpoint shell records a transcript."""
        os.environ["SSH_AUTH_SOCK"] = ""
        with ssh.connect(self.target()) as connection:
            yield connection

    def start_inputs(self) -> PreparationInputs:
        return PreparationInputs(
            "",
            self.identity,
            worker_action="start",
            worker_queues=("default",),
            worker_processes=2,
            worker_timeout=60,
        )

    def action_inputs(self, action: str) -> PreparationInputs:
        return PreparationInputs("", self.identity, worker_action=action)

    def queue_unit(self, process: int) -> str:
        return service_name(self.identity, f"queue{process}")

    def property(self, unit: str, name: str) -> str:
        return self.native(f"systemctl show --value -p {name} {unit}").strip()

    def unix_property(self, unit: str, name: str) -> str:
        return self.native(f"systemctl show --value --timestamp=unix -p {name} {unit}").strip()

    def worker_row(self) -> ObservedWorker:
        from automation import worker_observation

        with self.shell() as shell:
            value = worker_observation.read(shell)
        return worker_observation.worker_for(value, self.identity)

    def assert_queue_active(self, name: str, *, timeout: float = 20) -> None:
        self.wait_active(name, timeout=timeout)
        journal = self.native(f"journalctl -u {name} --no-pager -o cat -n 30 || true")
        self.assertIn("active", self.property(name, "ActiveState"), journal)

    def wait_active(self, name: str, *, timeout: float = 20) -> None:
        end = time.monotonic() + timeout
        state = self.property(name, "ActiveState")
        while state != "active" and time.monotonic() < end:
            time.sleep(0.2)
            state = self.property(name, "ActiveState")
        self.assertEqual(state, "active")

    def probe(self, statement: str) -> str:
        return self.native(self._migrations_client(statement)).strip()

    def probe_count(self, marker: str, phase: str) -> int:
        return int(
            self.probe(
                "SELECT COUNT(*) FROM barectl_probe WHERE marker = "  # noqa: S608
                f"'{marker}' AND phase = '{phase}'"
            )
        )

    def wait_probe(self, marker: str, phase: str, *, timeout: float = 30) -> None:
        end = time.monotonic() + timeout
        while self.probe_count(marker, phase) == 0 and time.monotonic() < end:
            time.sleep(0.2)
        self.assertEqual(self.probe_count(marker, phase), 1, f"{marker} {phase}")

    def write_dispatch(self, current: str) -> None:
        import base64

        payload = base64.b64encode(_DISPATCH_SCRIPT.encode()).decode()
        self.native(
            f"printf %s {shlex.quote(payload)} | base64 -d > {current}/dispatch.php && "
            f"chmod 644 {current}/dispatch.php"
        )

    def dispatch(self, marker: str, seconds: int = 0) -> None:
        self.native(
            f"runuser -u s{self.identity} -- /bin/sh -c "
            f"'cd {self.base()}/current && {self.base()}/bin/php dispatch.php {marker} {seconds}'"
        )

    def test_1_creates_the_site_with_its_queue_tables(self) -> None:
        from laravel import change

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
            },
            "queue worker fixture",
        )
        line, unit, _ = self.apply(change.DEPLOY_SITE, self.deploy_inputs(), timeout=180)
        self.assert_succeeded(line, unit)
        current = f"{self.base()}/current"
        self.write_dispatch(current)
        self.assertIn("create_queue_tables", self.native(f"ls {current}/database/migrations"))
        self.native(
            f"runuser -u s{self.identity} -- {self.base()}/bin/php "
            f"{current}/artisan migrate --force --no-interaction"
        )
        self.assertEqual(self.probe("SELECT COUNT(*) FROM jobs"), "0")
        self.assertEqual(self.probe("SELECT COUNT(*) FROM barectl_probe"), "0")

    def test_2_starts_the_workers_and_proves_recovery_without_a_controller(self) -> None:
        from automation import worker_change
        from automation.worker_status import WorkerStatus

        draft = self.review(worker_change.SET_LARAVEL_QUEUE_WORKERS, self.start_inputs())
        if not draft.eligible:
            self.fail(" ".join(draft.refusals))
        line, unit, draft = self.apply(
            worker_change.SET_LARAVEL_QUEUE_WORKERS, self.start_inputs(), timeout=60
        )
        self.assert_succeeded(line, unit)
        definition = draft.document["definition"]
        if not isinstance(definition, dict):
            self.fail("The review carried no definition.")
        self.assertEqual(definition["processes"], 2)
        environment = self.native(f"cat {self.base()}/private/laravel.env")
        self.assertIn("DB_QUEUE_RETRY_AFTER=90", environment)
        for process in (1, 2):
            name = self.queue_unit(process)
            self.assert_queue_active(name)
            self.assertIn("enabled", self.property(name, "UnitFileState"))
            self.assertEqual(self.property(name, "Restart"), "always")
            self.assertEqual(self.property(name, "StartLimitBurst"), "5")
            self.assertEqual(self.property(name, "TimeoutStopUSec"), "1min 15s")
            self.assertEqual(self.property(name, "User"), f"s{self.identity}")
        # Jobs dispatched with no Barectl controller are processed by both processes.
        self.dispatch("offline-one")
        self.dispatch("offline-two")
        self.wait_probe("offline-one", "end")
        self.wait_probe("offline-two", "end")
        row = self.worker_row()
        self.assertEqual(row.status, WorkerStatus.RUNNING)
        # A crash restarts without the controller.
        before = int(self.unix_property(self.queue_unit(1), "NRestarts"))
        self.native(f"systemctl kill --signal=KILL {self.queue_unit(1)} || true")
        end = time.monotonic() + 30
        while (
            int(self.unix_property(self.queue_unit(1), "NRestarts")) <= before
            and time.monotonic() < end
        ):
            time.sleep(0.2)
        self.assertGreater(int(self.unix_property(self.queue_unit(1), "NRestarts")), before)
        self.assertIn("active", self.property(self.queue_unit(1), "ActiveState"))
        # Repeated starts stop at the start limit and read as such.
        for _ in range(6):
            self.native(f"systemctl restart {self.queue_unit(1)} >/dev/null 2>&1 || true")
        self.assertEqual(self.property(self.queue_unit(1), "Result"), "start-limit-hit")
        row = self.worker_row()
        self.assertEqual(row.status, WorkerStatus.STOPPED_AFTER_CRASHES)
        # Start clears the failed state and runs both processes again.
        line, unit, _ = self.apply(
            worker_change.SET_LARAVEL_QUEUE_WORKERS, self.start_inputs(), timeout=120
        )
        self.assert_succeeded(line, unit)
        self.wait_active(self.queue_unit(1))
        # A graceful restart lets the in-flight job finish.
        self.dispatch("inflight", 8)
        self.wait_probe("inflight", "start")
        line, unit, _ = self.apply(
            worker_change.SET_LARAVEL_QUEUE_WORKERS, self.action_inputs("restart"), timeout=120
        )
        self.assert_succeeded(line, unit)
        self.wait_probe("inflight", "end", timeout=30)

    def test_3_the_fresh_controller_reconstructs_it_and_proposes_nothing(self) -> None:

        state = self.record_state
        if state:
            with ssh.connect(self.target()) as connection:
                shell: ssh.RemoteShell = recorded.RecordingShell(
                    connection, state, secrets=(recorded.SEEDED_SECRET,)
                )
                self._checkpoint(shell)
        else:
            with self.shell() as shell:
                self._checkpoint(shell)

    def _checkpoint(self, shell: ssh.RemoteShell) -> None:
        from automation import worker_change
        from discovery.observations import collect

        observed = collect(shell, releases=True)
        inputs = self.start_inputs()
        draft = worker_change.review(worker_change.inspect(shell, inputs), inputs)
        self.checkpoint(QUEUE_STATE, shell)
        row = next(item for item in observed.workers.value if item.identifier == self.identity)
        self.assertEqual(row.status.value, "running")
        self.assertEqual(row.definition, WorkerDefinition(("default",), 2, 60))
        self.assertTrue(draft.no_changes, draft.refusals)
        self.assertEqual(draft.effects, ())

    def test_4_an_explicit_stop_survives_a_restart(self) -> None:
        from automation import worker_change

        line, unit, _ = self.apply(
            worker_change.SET_LARAVEL_QUEUE_WORKERS, self.action_inputs("stop"), timeout=120
        )
        self.assert_succeeded(line, unit)
        for process in (1, 2):
            name = self.queue_unit(process)
            self.assertEqual(self.property(name, "ActiveState"), "inactive")
            self.assertEqual(self.property(name, "UnitFileState"), "disabled")
        # A systemd re-exec is the controller-independent part of a restart; the disabled
        # unit has no boot link, so the explicit stop survives it.
        self.native("systemctl daemon-reexec")
        time.sleep(1)
        for process in (1, 2):
            name = self.queue_unit(process)
            self.assertEqual(self.property(name, "ActiveState"), "inactive")
            self.assertEqual(self.property(name, "UnitFileState"), "disabled")


_DISPATCH_SCRIPT = """<?php

require __DIR__.'/vendor/autoload.php';

$app = require_once __DIR__.'/bootstrap/app.php';
$kernel = $app->make(Illuminate\\Contracts\\Console\\Kernel::class);
$kernel->bootstrap();

App\\Jobs\\BarectlProbe::dispatch($argv[1] ?? 'probe', (int) ($argv[2] ?? 0));
echo "dispatched\n";
"""
