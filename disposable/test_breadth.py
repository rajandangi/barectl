"""The scheduled breadth scenarios (Phase C #357, docs/quality.md#the-scheduled-breadth-job).

These run only in the weekly/dispatched breadth job, never in the merge build:

- a reboot with the controller closed: the workers return, a missed minute is not made up
  in a burst, and a maintenance gate keeps boot activation off across the boot;
- a scheduler tick longer than a minute: ``DeferReactivation`` delays the next start to the
  next calendar elapse instead of starting immediately;
- memory per cache instance and per queue worker inside 1, 2 and 4 GiB memory cgroups.

Every class starts from the prepared L5 snapshot (#393) so the measurement or the reboot is
the item, not the site's setup. The containers share the Docker VM's kernel, so the reboot is
a userspace reboot and the memory figures are cgroup limits, not whole-host measurements;
the qualification record states both gaps.
"""

import json
import os
import shlex
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from typing import override

from django.test import tag

from discovery import ssh
from operations.inputs import PreparationInputs

from .change_testing import apply_change
from .scenario_testing import SCENARIO_TAG
from .test_laravel_deploy import _HEALTH_RENAMED, LaravelDeployCase

SITE = "sqwalpha"
DOMAIN = "site.fixture.test"
CACHE_UNIT = f"valkey-server@{SITE}.service"


def _int(value: str) -> int:
    try:
        return int(value.strip().removeprefix("@"))
    except ValueError:
        return 0


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
class GateFence(BreadthCase):
    """A Deploy and a Roll back pause the site's work while their gate is up."""

    def _wait_for_gate(self, *, timeout: float = 90) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.https_status("/") == 503:
                return True
            time.sleep(0.3)
        return False

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

    def test_a_deploy_fences_the_work_and_restores_it_after_up(self) -> None:
        from automation import scheduler
        from automation.convention import service_name, timer_name
        from laravel import change, rollback

        self.start_scheduler()
        timer = timer_name(self.identity, "schedule")
        service = service_name(self.identity, "schedule")
        previous = self.current_release()
        self.push(
            {"database/migrations/2026_10_26_000000_create_gate_table.php": _GATE_MIGRATION},
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
        self.assertTrue(self.served())
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
        self._assert_fenced(timer, service)
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


__all__ = [
    "GateFence",
    "LongSchedulerTick",
    "MemoryFourGiB",
    "MemoryOneGiB",
    "MemoryTwoGiB",
    "RebootAutomation",
    "RebootGateFence",
]
