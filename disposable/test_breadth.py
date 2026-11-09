"""The scheduled breadth scenarios (Phase C #357, docs/quality.md#the-scheduled-breadth-job).

These run only in the weekly/dispatched breadth job, never in the merge build:

- a reboot with the controller closed: the workers return, a missed minute is not made up
  in a burst, and a maintenance gate keeps boot activation off across the boot;
- a scheduler tick longer than a minute: ``DeferReactivation`` delays the next start to the
  next calendar elapse instead of starting immediately;
- memory per cache instance and per queue worker inside 1, 2 and 4 GiB memory cgroups,
  with the site's disk use and the foundation's provisional headroom in the same sample.

Every class starts from the prepared L5 snapshot (#393) so the measurement or the reboot is
the item, not the site's setup. The containers share the Docker VM's kernel, so the reboot is
a userspace reboot and the memory figures are cgroup limits, not whole-host measurements;
the qualification record states both gaps.
"""

import json
import os
import shlex
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from typing import TYPE_CHECKING, NamedTuple, override

from django.test import SimpleTestCase, tag

from discovery import ssh
from operations.inputs import PreparationInputs

from .change_testing import apply_change, submit_change, wait_result
from .scenario_testing import SCENARIO_TAG
from .test_laravel_deploy import (
    _GOOD_BOOTSTRAP,
    _GOOD_CSS,
    _GOOD_VIEW,
    _HEALTH_RENAMED,
    LaravelDeployCase,
)

if TYPE_CHECKING:
    from jobs.automatic import AutomaticRow
    from jobs.backups import BackupRunRow, BackupTimerRow
    from jobs.presentation import JobRow, JobsView

SITE = "sqwalpha"
DOMAIN = "site.fixture.test"
CACHE_UNIT = f"valkey-server@{SITE}.service"
SITE_ROOT = f"/var/www/{SITE}"
BACKUP_ROOT = f"/var/lib/barectl-backups/{SITE}"
# bootstrap/standing.py's provisional, unqualified headroom thresholds.
DISK_TARGET_BYTES = 4 * 1024**3
MEMORY_TARGET_BYTES = 900 * 1024**2
DISK_ROOTS = ("/", "/var", SITE_ROOT, BACKUP_ROOT)


_FilesystemReading = tuple[str | None, bool, int | None]


class _DiskCapacity(NamedTuple):
    measured_path: str | None
    present: bool
    avail_bytes: int | None
    target_bytes: int
    met: bool


class _Capacity(NamedTuple):
    available_memory_bytes: int | None
    available_memory_target_bytes: int
    available_memory_met: bool
    disk: dict[str, _DiskCapacity]
    site_bytes: int | None
    backup_bytes: int | None


def _int(value: str) -> int:
    try:
        return int(value.strip().removeprefix("@"))
    except ValueError:
        return 0


def _byte_count(value: str) -> int | None:
    try:
        number = int(value.strip())
    except ValueError:
        return None
    return number if number >= 0 else None


def _target_met(observed: int | None, target: int) -> bool:
    """An unreadable value is not a pass."""
    return observed is not None and observed >= target


def _filesystem_readings(output: str) -> dict[str, _FilesystemReading]:
    """Parse ``requested<TAB>measured<TAB>avail`` lines from the disk probe."""
    readings: dict[str, _FilesystemReading] = {}
    for line in output.splitlines():
        requested, tab, rest = line.partition("\t")
        measured, separator, avail = rest.partition("\t")
        if not tab or not separator or not requested.strip():
            continue
        readings[requested.strip()] = (
            measured.strip(),
            requested.strip() == measured.strip(),
            _byte_count(avail),
        )
    return readings


def _du_bytes(output: str) -> int | None:
    first = output.split(maxsplit=1)[0] if output.split() else ""
    return _byte_count(first)


def measure_capacity(native: Callable[[str], str]) -> _Capacity:
    """Read the foundation's disk and memory headroom beside the cgroup figures.

    An absent root is measured on its nearest existing ancestor, so the figure is the
    filesystem that would receive the site or its backups rather than a zero.
    """
    roots = " ".join(shlex.quote(path) for path in DISK_ROOTS)
    output = native(
        f'for p in {roots}; do q=$p; while [ ! -e "$q" ]; do q=$(dirname "$q"); done; '
        'printf \'%s\\t%s\\t%s\\n\' "$p" "$q" '
        '"$(df -B1 --output=avail "$q" | tail -n 1 | tr -d \' \')"; done'
    )
    readings = _filesystem_readings(output)
    available = _byte_count(
        native("awk '/^MemAvailable:/ {printf \"%d\\n\", $2 * 1024}' /proc/meminfo")
    )
    disk: dict[str, _DiskCapacity] = {}
    for path in DISK_ROOTS:
        measured_path, present, avail = readings.get(path, (None, False, None))
        disk[path] = _DiskCapacity(
            measured_path,
            present,
            avail,
            DISK_TARGET_BYTES,
            _target_met(avail, DISK_TARGET_BYTES),
        )
    return _Capacity(
        available,
        MEMORY_TARGET_BYTES,
        _target_met(available, MEMORY_TARGET_BYTES),
        disk,
        _du_bytes(native(f"du -sb {shlex.quote(SITE_ROOT)} 2>/dev/null || true")),
        _du_bytes(native(f"du -sb {shlex.quote(BACKUP_ROOT)} 2>/dev/null || true")),
    )


def _capacity_json(capacity: _Capacity) -> dict[str, object]:
    """The one machine-readable sample piece carried by ``BREADTH_MEMORY``."""
    return {
        "available_memory_bytes": capacity.available_memory_bytes,
        "available_memory_target_bytes": capacity.available_memory_target_bytes,
        "available_memory_met": capacity.available_memory_met,
        "disk": {
            path: {
                "measured_path": reading.measured_path,
                "present": reading.present,
                "avail_bytes": reading.avail_bytes,
                "target_bytes": reading.target_bytes,
                "met": reading.met,
            }
            for path, reading in capacity.disk.items()
        },
        "site_bytes": capacity.site_bytes,
        "backup_bytes": capacity.backup_bytes,
    }


class BreadthCase(LaravelDeployCase):
    """Shared probes for the scheduled breadth scenarios."""

    layer = "L5"
    exclusive = True
    breadth = True
    prefix = "sqw"
    identity = SITE
    domain = DOMAIN

    @override
    @contextmanager
    def shell(self) -> Iterator[ssh.RemoteShell]:
        """A plain connection: these scenarios apply fenced changes."""
        os.environ["SSH_AUTH_SOCK"] = ""
        with ssh.connect(self.target()) as connection:
            yield connection

    def unit_property(self, unit: str, name: str) -> str:
        return self.native(f"systemctl show --value -p {name} {unit}").strip()

    def unit_unix(self, unit: str, name: str) -> int:
        return _int(self.native(f"systemctl show --value --timestamp=unix -p {name} {unit}"))

    def served(self, *, timeout: float = 30) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.https_status("/") == 200:
                return True
            time.sleep(1)
        return False

    def unit_unix_manager(self, name: str) -> int:
        return _int(self.native(f"systemctl show --value --timestamp=unix -p {name}"))

    def starts_since(self, unit: str, epoch: int) -> int:
        """How many times the unit was started since an epoch second.

        journald's ``-b`` follows the kernel boot ID, which a container restart does not
        change, so the breadth scenarios count from systemd's userspace boot timestamp.
        """
        return int(
            self.native(
                f"journalctl -u {shlex.quote(unit)} --since @{epoch} --no-pager -o cat "
                "2>/dev/null | grep -c 'Starting' || true"
            ).strip()
            or 0
        )

    def start_scheduler(self) -> None:
        from automation import scheduler

        line, unit, _ = self.apply(
            scheduler.SET_LARAVEL_SCHEDULER,
            PreparationInputs("", self.identity, schedule_state="on"),
            timeout=60,
        )
        self.assert_succeeded(line, unit)

    def _wait_for_gate(self, *, timeout: float = 90) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.https_status("/") == 503:
                return True
            time.sleep(0.3)
        return False

    def _assert_gate_held(self, timer: str, service: str) -> None:
        """The boot fence after a restart: boot activation is off and nothing started.

        The runtime mask and the ``/run`` drop-in do not survive a boot, so this reads the
        durable half the gate leaves: disabled units and no running work.
        """
        for name in (timer, *self.worker_units()):
            self.assertNotIn(
                self.unit_property(name, "UnitFileState"), ("enabled", "enabled-runtime"), name
            )
            self.assertNotIn(
                self.unit_property(name, "ActiveState"), ("active", "activating"), name
            )
        self.assertNotIn(self.unit_property(service, "ActiveState"), ("active", "activating"))

    def _assert_fenced(self, timer: str, service: str) -> None:
        self.assertEqual(self.unit_property(timer, "RefuseManualStart"), "yes")
        self.assertIn(self.unit_property(timer, "ActiveState"), ("inactive", "failed"))
        self.assertNotIn(self.unit_property(timer, "UnitFileState"), ("enabled", "enabled-runtime"))
        for name in (service, *self.worker_units()):
            self.assertEqual(self.unit_property(name, "RefuseManualStart"), "yes", name)
            self.assertNotIn(
                self.unit_property(name, "ActiveState"), ("active", "activating"), name
            )
        for name in self.worker_units():
            self.assertNotIn(
                self.unit_property(name, "UnitFileState"), ("enabled", "enabled-runtime")
            )

    def _assert_resumed(self, timer: str, service: str) -> None:
        self.assertEqual(self.unit_property(timer, "ActiveState"), "active")
        self.assertIn("enabled", self.unit_property(timer, "UnitFileState"))
        self.assertEqual(self.unit_property(service, "RefuseManualStart"), "no")
        for unit in self.worker_units():
            self.wait_active(unit)
            self.assertIn("enabled", self.unit_property(unit, "UnitFileState"))
            self.assertEqual(self.unit_property(unit, "RefuseManualStart"), "no")

    def ensure_scheduler(self) -> None:
        from automation.convention import timer_name

        timer = timer_name(self.identity, "schedule")
        if self.unit_property(timer, "ActiveState") == "active" and "enabled" in self.unit_property(
            timer, "UnitFileState"
        ):
            return
        self.start_scheduler()

    def wait_active(self, unit: str, *, timeout: float = 40) -> None:
        end = time.monotonic() + timeout
        state = self.unit_property(unit, "ActiveState")
        while state != "active" and time.monotonic() < end:
            time.sleep(0.3)
            state = self.unit_property(unit, "ActiveState")
        self.assertEqual(state, "active", unit)

    def worker_units(self) -> tuple[str, ...]:
        return (
            f"barectl-site-{self.identity}-queue1.service",
            f"barectl-site-{self.identity}-queue2.service",
        )


@tag(SCENARIO_TAG)
class RebootAutomation(BreadthCase):
    """A boot with the controller closed: workers return and no missed tick runs in a burst."""

    def test_workers_return_without_a_tick_burst(self) -> None:
        from automation.convention import service_name, timer_name

        self.start_scheduler()
        timer = timer_name(self.identity, "schedule")
        service = service_name(self.identity, "schedule")
        self.assertEqual(self.unit_property(timer, "Persistent"), "no")
        self.assertEqual(self.unit_property(timer, "DeferReactivation"), "yes")
        before_userspace = self.unit_unix_manager("UserspaceTimestamp")
        before_workers = {
            unit: self.unit_property(unit, "InvocationID") for unit in self.worker_units()
        }
        before_started = self.unit_unix(service, "ExecMainStartTimestamp")
        # Leave the server down for more than a minute: a persistent timer would run every
        # missed minute at once when it returns.
        self.stop_for(65)
        after_userspace = self.unit_unix_manager("UserspaceTimestamp")
        self.assertGreater(after_userspace, before_userspace, "the container did not reboot")
        for unit in self.worker_units():
            self.wait_active(unit)
            self.assertIn("enabled", self.unit_property(unit, "UnitFileState"))
            self.assertNotEqual(
                self.unit_property(unit, "InvocationID"), before_workers[unit], unit
            )
        self.assertEqual(self.unit_property(timer, "ActiveState"), "active")
        self.assertIn("enabled", self.unit_property(timer, "UnitFileState"))
        # The missed minute is skipped, not replayed: the timer's next elapse is the next
        # future calendar minute, and at most one tick has run since the boot (the normal
        # tick on a boundary, never one per missed minute).
        now = int(self.native("date +%s").strip())
        next_elapse = self.unit_unix(timer, "NextElapseUSecRealtime")
        self.assertGreater(next_elapse, now)
        self.assertLess(next_elapse - now, 61)
        self.assertLessEqual(self.starts_since(service, after_userspace), 1)
        after_started = self.unit_unix(service, "ExecMainStartTimestamp")
        if after_started != before_started:
            self.assertEqual(after_started % 60, 0, "a tick started off the boundary")
        self.assertTrue(self.served(), "the site did not serve after the boot")


@tag(SCENARIO_TAG)
class JobsSurvivingEvidence(BreadthCase):
    """A journal rotation and a boot keep the newer run and name the retained start."""

    def jobs_view(self) -> JobsView:
        from datetime import UTC, datetime

        from discovery.observations import collect
        from discovery.snapshot import Snapshot
        from jobs.presentation import present
        from servers.models import Server

        with self.shell() as shell:
            collected = collect(shell, releases=True)
        return present(
            Snapshot(collected, datetime.now(UTC), self.target().alias),
            Server(pk=1),
            may_view_changes=True,
        )

    def results_in_journal(self) -> int:
        return int(
            self.native(
                "journalctl -u 'barectl-apply-*' --grep '^barectl-result ' "
                "--no-pager -o cat | wc -l"
            ).strip()
            or 0
        )

    def test_a_rotation_and_boot_keep_the_newer_run_and_name_the_retained_start(self) -> None:
        from datetime import UTC, datetime

        from automation import scheduler
        from automation.worker_change import SET_LARAVEL_QUEUE_WORKERS

        older = submit_change(
            self,
            scheduler.SET_LARAVEL_SCHEDULER,
            PreparationInputs("", self.identity, schedule_state="on"),
        )
        self.assertFalse(older.no_changes)
        wait_result(self, older)
        before = self.jobs_view()
        self.assertTrue(
            any(row.title == scheduler.SET_LARAVEL_SCHEDULER.label for row in self.rows(before)),
            "The finished change was not visible before the rotation.",
        )
        # Seal the journal that holds the finished change, age it past a one-second cutoff
        # and vacuum it: the old change evidence is now gone from the server.
        self.native("journalctl --rotate")
        time.sleep(2)
        self.native("journalctl --vacuum-time=1s")
        self.assertEqual(self.results_in_journal(), 0, "The older change evidence survived.")
        changed_at = int(self.native("date +%s").strip())
        submitted = submit_change(
            self,
            SET_LARAVEL_QUEUE_WORKERS,
            PreparationInputs("", self.identity, worker_action="stop"),
        )
        self.assertFalse(submitted.no_changes)
        wait_result(self, submitted)
        # A container stop and start is the userspace reboot the breadth classes use.
        self.stop_for(20)
        after = self.jobs_view()
        rows = self.rows(after)
        self.assertIn(
            "Change queue workers",
            [row.title for row in rows],
            "The surviving change was not shown after the boot.",
        )
        self.assertNotIn(
            scheduler.SET_LARAVEL_SCHEDULER.label,
            [row.title for row in rows],
            "The removed change was still shown after the boot.",
        )
        notices = [notice for notice in after.notices if notice.oldest_at is not None]
        self.assertTrue(notices, "The retained history start was not named.")
        self.assertEqual(notices[0].text, "The server's retained change history starts")
        oldest = notices[0].oldest_at
        if oldest is None:
            self.fail("The retained history start had no time.")
        self.assertGreaterEqual(oldest.astimezone(UTC), datetime.fromtimestamp(changed_at, UTC))
        # A rotation or a missing line never becomes "nothing ran": the surviving row is
        # shown, the page is not empty and no notice claims there is no evidence.
        self.assertTrue(rows, "Jobs claimed no work after the rotation.")
        self.assertFalse(after.empty)
        self.assertNotIn(
            "does not mean no change ran",
            "\n".join(notice.text for notice in after.notices),
        )

    def rows(
        self, view: JobsView
    ) -> tuple[JobRow | AutomaticRow | BackupRunRow | BackupTimerRow, ...]:
        return tuple(row for group in view.groups if group.key == "recent" for row in group.rows)


@tag(SCENARIO_TAG)
class GateFence(BreadthCase):
    """A Deploy and a Roll back pause the site's work while their gate is up."""

    def test_a_deploy_fences_the_work_and_restores_it_after_up(self) -> None:
        from automation import scheduler
        from automation.convention import service_name, timer_name
        from laravel import change, rollback

        self.start_scheduler()
        timer = timer_name(self.identity, "schedule")
        service = service_name(self.identity, "schedule")
        previous = self.current_release()
        self.push(
            {
                "resources/views/welcome.blade.php": _GOOD_VIEW,
                "bootstrap/app.php": _GOOD_BOOTSTRAP,
                "public/app.css": _GOOD_CSS,
                "database/migrations/2026_10_26_000000_create_gate_table.php": _GATE_MIGRATION,
            },
            "gate deploy",
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            running = pool.submit(self.apply, change.DEPLOY_SITE, self.deploy_inputs(), timeout=150)
            # The migration sleeps, so the gate is up long enough to read the fence while
            # the change is still between its gate and its switch.
            self.assertTrue(self._wait_for_gate(), "the maintenance gate never answered 503")
            self._assert_fenced(timer, service)
            self.assertEqual(
                self.current_release(), previous, "the code switched while the gate was up"
            )
            line, unit, _ = running.result()
        self.assert_succeeded(line, unit)
        self.assertNotEqual(self.current_release(), previous)
        self.assertTrue(self.served(), "the site did not serve on the new release")
        self._assert_resumed(timer, service)
        # The restored scheduler runs the new release: Run now starts its installed service.
        line, unit, _ = self.apply(
            scheduler.SET_LARAVEL_SCHEDULER,
            PreparationInputs("", self.identity, schedule_state="run"),
            timeout=60,
        )
        self.assert_succeeded(line, unit)
        # A Roll back gates and restores the same work on the release it reactivates.
        line, unit, _ = self.apply(
            rollback.ROLLBACK_SITE,
            PreparationInputs("", self.identity, (), previous),
            timeout=120,
        )
        self.assert_succeeded(line, unit)
        self.assertEqual(self.current_release(), previous)
        self.assertTrue(self.served())
        self._assert_resumed(timer, service)


@tag(SCENARIO_TAG)
class RebootGateFence(BreadthCase):
    """A persistent gate keeps boot activation off across a container boot."""

    def test_the_gate_fence_holds_across_a_boot(self) -> None:
        from automation.convention import service_name, timer_name
        from laravel import change

        self.ensure_scheduler()
        timer = timer_name(self.identity, "schedule")
        service = service_name(self.identity, "schedule")
        self.push(
            {
                "resources/views/welcome.blade.php": _GOOD_VIEW,
                "public/app.css": _GOOD_CSS,
                "bootstrap/app.php": _HEALTH_RENAMED,
                "database/migrations/2026_10_26_000001_create_boot_gate_table.php": (
                    _BOOT_GATE_MIGRATION
                ),
            },
            "boot gate",
        )
        line, unit, _ = self.apply(change.DEPLOY_SITE, self.deploy_inputs())
        self.assert_failed(line, "partial", "laravel_readiness", unit)
        self.assertEqual(self.https_status("/"), 503)
        self._assert_fenced(timer, service)
        # Boot activation is off for the timer and the worker services, so a boot cannot
        # start work against the half-migrated release.
        self.stop_for(20)
        boot_epoch = self.unit_unix_manager("UserspaceTimestamp")
        self._assert_gate_held(timer, service)
        self.assertEqual(self.starts_since(service, boot_epoch), 0)
        self.assertEqual(self.https_status("/"), 503)


_BOOT_GATE_MIGRATION = """<?php

use Illuminate\\Database\\Migrations\\Migration;
use Illuminate\\Database\\Schema\\Blueprint;
use Illuminate\\Support\\Facades\\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('boot_gate', function (Blueprint $table) {
            $table->id();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('boot_gate');
    }
};
"""


_GATE_MIGRATION = """<?php

use Illuminate\\Database\\Migrations\\Migration;
use Illuminate\\Database\\Schema\\Blueprint;
use Illuminate\\Support\\Facades\\Schema;

return new class extends Migration
{
    public function up(): void
    {
        sleep(4);
        Schema::create('breadth_gate', function (Blueprint $table) {
            $table->id();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('breadth_gate');
    }
};
"""


_LONG_TICK = """<?php

use Illuminate\\Support\\Facades\\Schedule;

Schedule::call(function (): void {
    sleep(62);
})->everyMinute();
"""


@tag(SCENARIO_TAG)
class LongSchedulerTick(BreadthCase):
    """A tick longer than a calendar minute defers the next start instead of overlapping."""

    def test_a_long_tick_is_followed_by_the_next_calendar_elapse(self) -> None:
        from automation.convention import service_name, timer_name
        from laravel import change

        self.push({"routes/console.php": _LONG_TICK}, "long scheduler tick")
        line, unit, _ = self.apply(change.DEPLOY_SITE, self.deploy_inputs(migrations=False))
        self.assert_succeeded(line, unit)
        self.start_scheduler()
        turned_on = int(self.native("date +%s").strip())
        timer = timer_name(self.identity, "schedule")
        service = service_name(self.identity, "schedule")
        self.assertEqual(self.unit_property(timer, "DeferReactivation"), "yes")
        # The next calendar elapse starts one run; no controller connection is open.
        end = time.monotonic() + 65
        started = 0
        while time.monotonic() < end and started == 0:
            started = self.unit_unix(service, "ExecMainStartTimestamp")
            time.sleep(1)
        self.assertGreater(started, 0, "the scheduler did not tick")
        began = time.monotonic()
        while (
            self.unit_property(service, "ActiveState") in ("active", "activating")
            and time.monotonic() - began < 90
        ):
            time.sleep(1)
        finished = self.unit_unix(service, "ExecMainExitTimestamp")
        self.assertGreaterEqual(finished - started, 60, "the tick was shorter than a minute")
        next_elapse = self.unit_unix(timer, "NextElapseUSecRealtime")
        # The elapse that fell inside the run was deferred; the next start is the next
        # future calendar minute, not an immediate second start.
        self.assertGreater(next_elapse, finished)
        self.assertEqual(next_elapse % 60, 0)
        time.sleep(5)
        self.assertEqual(self.unit_unix(service, "ExecMainStartTimestamp"), started)
        self.assertEqual(self.starts_since(service, turned_on), 1)


class MemoryCase(BreadthCase):
    """One memory class: the site's cache instance and both workers in a sized cgroup."""

    def cgroup(self, unit: str) -> int:
        control = self.unit_property(unit, "ControlGroup")
        if control.startswith("/"):
            value = self.native(f"cat /sys/fs/cgroup{control}/memory.current || true").strip()
            if value.isdigit():
                return int(value)
        return _int(self.unit_property(unit, "MemoryCurrent"))

    def check_memory(self) -> None:
        from cache import instance

        apply_change(
            self,
            instance.SET_SITE_OBJECT_CACHE,
            PreparationInputs(identifier=self.identity, object_cache=True, cache_mib=64),
            timeout=180,
        )
        self.assertEqual(self.https_status("/"), 200)
        time.sleep(2)
        limit = int(self.native("cat /sys/fs/cgroup/memory.max").strip())
        self.assertEqual(limit, self.memory_gib * 2**30)
        cache = self.cgroup(CACHE_UNIT)
        workers = {unit: self.cgroup(unit) for unit in self.worker_units()}
        current = _int(self.native("cat /sys/fs/cgroup/memory.current"))
        peak = _int(self.native("cat /sys/fs/cgroup/memory.peak"))
        maxmemory = int(
            self.native(
                f"awk '/^maxmemory / {{print $2}}' /etc/valkey/{self.identity}.conf"
            ).strip()
        )
        sample = {
            "gib": self.memory_gib,
            "limit_bytes": limit,
            "cgroup_current": current,
            "cgroup_peak": peak,
            "cache_bytes": cache,
            "cache_maxmemory_bytes": maxmemory,
            "workers": workers,
            "capacity": _capacity_json(measure_capacity(self.native)),
        }
        print("BREADTH_MEMORY " + json.dumps(sample, sort_keys=True))  # noqa: T201
        self.assertGreater(cache, 0)
        self.assertLess(cache, maxmemory)
        for unit, value in workers.items():
            self.assertGreater(value, 0, unit)
        self.assertLess(peak, limit)
        self.assertTrue(self.served(timeout=10))


@tag(SCENARIO_TAG)
class MemoryOneGiB(MemoryCase):
    """Memory of the cache instance and both workers in a 1 GiB memory cgroup."""

    memory_gib = 1

    def test_measures_the_cache_instance_and_each_worker(self) -> None:
        self.check_memory()


@tag(SCENARIO_TAG)
class MemoryTwoGiB(MemoryCase):
    """Memory of the cache instance and both workers in a 2 GiB memory cgroup."""

    memory_gib = 2

    def test_measures_the_cache_instance_and_each_worker(self) -> None:
        self.check_memory()


@tag(SCENARIO_TAG)
class MemoryFourGiB(MemoryCase):
    """Memory of the cache instance and both workers in a 4 GiB memory cgroup."""

    memory_gib = 4

    def test_measures_the_cache_instance_and_each_worker(self) -> None:
        self.check_memory()


class CapacityMeasurementTests(SimpleTestCase):
    """The foundation's provisional thresholds are recorded, never smoothed."""

    def test_a_below_target_value_is_a_miss_and_an_unreadable_value_is_not_a_pass(
        self,
    ) -> None:
        self.assertFalse(_target_met(DISK_TARGET_BYTES - 1, DISK_TARGET_BYTES))
        self.assertTrue(_target_met(DISK_TARGET_BYTES, DISK_TARGET_BYTES))
        self.assertTrue(_target_met(MEMORY_TARGET_BYTES, MEMORY_TARGET_BYTES))
        self.assertFalse(_target_met(None, MEMORY_TARGET_BYTES))

    def test_a_missing_root_is_measured_on_its_nearest_existing_ancestor(self) -> None:
        readings = _filesystem_readings(f"/\t/\t8589934592\n{BACKUP_ROOT}\t/var/lib\t4294967296\n")
        self.assertEqual(readings["/"], ("/", True, 8589934592))
        self.assertEqual(readings[BACKUP_ROOT], ("/var/lib", False, 4294967296))
        self.assertEqual(_du_bytes(f"{12 * 1024**2}\t{SITE_ROOT}\n"), 12 * 1024**2)
        self.assertIsNone(_du_bytes(""))

    def test_the_capacity_sample_records_memory_disk_and_each_verdict(self) -> None:
        def native(command: str) -> str:
            if command.startswith("for p in"):
                return (
                    "/\t/\t8589934592\n"
                    "/var\t/var\t8589934592\n"
                    f"{SITE_ROOT}\t{SITE_ROOT}\t4294967296\n"
                    f"{BACKUP_ROOT}\t/var/lib\t10737418234\n"
                )
            if "MemAvailable" in command:
                return str(1024**3)
            if command.startswith("du -sb") and SITE_ROOT in command:
                return f"{12 * 1024**2}\t{SITE_ROOT}\n"
            if command.startswith("du -sb"):
                return ""
            raise AssertionError(command)

        sample = measure_capacity(native)
        self.assertEqual(sample.available_memory_bytes, 1024**3)
        self.assertTrue(sample.available_memory_met)
        self.assertEqual(sample.site_bytes, 12 * 1024**2)
        self.assertIsNone(sample.backup_bytes)
        self.assertEqual(sample.disk["/"].avail_bytes, 8589934592)
        self.assertTrue(sample.disk["/"].met)
        self.assertFalse(sample.disk[BACKUP_ROOT].present)
        self.assertEqual(sample.disk[BACKUP_ROOT].measured_path, "/var/lib")
        self.assertTrue(sample.disk[BACKUP_ROOT].met)
        rendered = json.loads(json.dumps(_capacity_json(sample)))
        self.assertEqual(rendered["disk"][BACKUP_ROOT]["target_bytes"], DISK_TARGET_BYTES)


__all__ = [
    "GateFence",
    "JobsSurvivingEvidence",
    "LongSchedulerTick",
    "MemoryFourGiB",
    "MemoryOneGiB",
    "MemoryTwoGiB",
    "RebootAutomation",
    "RebootGateFence",
]
