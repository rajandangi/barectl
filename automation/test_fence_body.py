"""The body-side fence and restore, against a simulated systemd (#395).

The native suite proves the real stop/start; this layer proves the order, the refusals,
that restore starts exactly the reviewed set and proves it active, and that one body
restarts the runtime masters at most once (#586).
"""

import json
import pathlib
import signal
import subprocess
import sys
import tempfile
from typing import override
from unittest import mock

from django.test import SimpleTestCase

from automation.bodies import units
from automation.bodies.source import AUTOMATION_SOURCE

SHOP = "shop"
TIMER = "barectl-site-shop-wpcron.timer"
SERVICE = "barectl-site-shop-wpcron.service"
WORKER = "barectl-site-shop-queue1.service"
SLICE = "barectl-site-shop.slice"


def document(**values: object) -> dict[str, object]:
    site = {
        "identifier": SHOP,
        "slice": SLICE,
        "timers": [TIMER],
        "services": [SERVICE],
        "resume": [TIMER],
        "budget_seconds": 30,
        **values,
    }
    return {"automation_fence": {"version": 1, "sites": [site]}}


class FakeSystemd:
    """Records the systemctl argv and keeps enough state for the helpers' questions."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.state = {TIMER: "loaded", SERVICE: "loaded", WORKER: "loaded", SLICE: "loaded"}
        self.active = {TIMER: "inactive", SERVICE: "inactive", WORKER: "active"}
        # A timer-driven oneshot has no install section; a queue worker carries its own.
        self.file_state = {TIMER: "enabled", SERVICE: "", WORKER: "enabled"}
        # Units this simulated systemd refuses to start.
        self.broken: set[str] = set()
        # Units whose runtime fence drop-in is present.
        self.fenced: set[str] = set()
        # The site's installed unit files, independent of the loaded unit state.
        self.installed = {TIMER, SERVICE}
        self.slice_empty = True
        self.reloads_noted = 0

    def systemctl(self, *arguments: str) -> str:
        self.calls.append(list(arguments))
        verb, name = arguments[0], arguments[-1]
        if verb == "mask":
            self.state[name] = "masked"
        elif verb == "stop":
            self.state[name] = "loaded"
            self.active[name] = "inactive"
        elif verb == "unmask":
            self.state[name] = "loaded"
        elif verb == "enable":
            self.file_state[name] = "enabled"
        elif verb == "start":
            self.active[name] = "failed" if name in self.broken else "active"
            self.file_state[name] = "enabled"
        return ""

    def run(self, args: list[str], text: str | None = None, *, check: bool = True) -> str:
        self.calls.append(list(args[1:]))
        if args[1] == "disable":
            self.file_state[args[2]] = "disabled"
        elif args[1] == "enable":
            self.file_state[args[2]] = "enabled"
        return ""

    def load_state(self, name: str) -> str:
        return self.state.get(name, "not-found")

    def active_state(self, name: str) -> str:
        return self.active.get(name, "inactive")

    def write_dropin(self, name: str) -> None:
        self.calls.append(["write-dropin", name])
        self.fenced.add(name)

    def clear_dropin(self, name: str) -> None:
        self.calls.append(["clear-dropin", name])
        self.fenced.discard(name)

    def unit_file_state(self, name: str) -> str:
        return self.file_state.get(name, "")

    def refuse_manual_start(self, name: str) -> str:
        return "yes" if name in self.fenced else "no"

    def installed_units(self, identifier: str) -> tuple[list[str], list[str]]:
        return (
            sorted(name for name in self.installed if name.endswith(".timer")),
            sorted(name for name in self.installed if name.endswith(".service")),
        )

    def timer_ready(self, name: str) -> bool:
        return self.active.get(name) == "active" and self.file_state.get(name) == "enabled"

    def wait_slice_empty(self, name: str, budget: int) -> bool:
        return self.slice_empty

    def note_reload(self) -> None:
        self.reloads_noted += 1


class InstalledUnitsTests(SimpleTestCase):
    def test_backup_integrity_units_are_not_automation_units(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for name in (
                "barectl-site-shop-check.timer",
                "barectl-site-shop-checkoffsite.service",
                "barectl-site-shop-queue1.service",
            ):
                pathlib.Path(directory, name).touch()
            with mock.patch.object(units, "SYSTEMD_DIRECTORY", directory):
                self.assertEqual(
                    units.installed_units(SHOP),
                    ([], ["barectl-site-shop-queue1.service"]),
                )


class FenceBodyTests(SimpleTestCase):
    @override
    def setUp(self) -> None:
        self.fake = FakeSystemd()
        for name in (
            "systemctl",
            "run",
            "load_state",
            "active_state",
            "timer_ready",
            "unit_file_state",
            "refuse_manual_start",
            "installed_units",
            "write_dropin",
            "note_reload",
            "clear_dropin",
        ):
            self.enterContext(mock.patch.object(units, name, getattr(self.fake, name)))
        self.enterContext(mock.patch.object(units, "wait_slice_empty", self.fake.wait_slice_empty))

    def verbs(self) -> list[list[str]]:
        return self.fake.calls

    def test_the_fence_masks_before_it_stops_and_stops_the_slice_last(self) -> None:
        self.assertTrue(units.fence(document(), SHOP))
        self.assertEqual(
            self.verbs(),
            [
                ["mask", "--runtime", TIMER],
                ["write-dropin", TIMER],
                ["mask", "--runtime", SERVICE],
                ["write-dropin", SERVICE],
                ["daemon-reload"],
                ["stop", TIMER],
                ["stop", SERVICE],
                ["stop", SLICE],
            ],
        )

    def test_a_maintenance_gate_also_removes_boot_activation(self) -> None:
        self.assertTrue(units.fence(document(), SHOP, gate=True))
        self.assertIn(["disable", TIMER], self.verbs())
        self.assertLess(self.verbs().index(["disable", TIMER]), self.verbs().index(["stop", TIMER]))
        # The masks, the reload and ``disable`` reload systemd, so the body restarts the
        # runtime masters when it exits (#586).
        self.assertGreater(self.fake.reloads_noted, 0)

    def test_a_gate_disables_boot_activation_for_every_reviewed_unit(self) -> None:
        self.fake.installed.add(WORKER)
        plan = document(services=[SERVICE, WORKER], resume=[TIMER, WORKER])
        self.assertTrue(units.fence(plan, SHOP, gate=True))
        self.assertEqual(
            [call for call in self.verbs() if call[0] == "disable"],
            [["disable", TIMER], ["disable", SERVICE], ["disable", WORKER]],
        )
        self.assertEqual(self.fake.file_state[WORKER], "disabled")
        self.assertLess(
            self.verbs().index(["disable", WORKER]), self.verbs().index(["stop", WORKER])
        )

    def test_a_gated_fence_restores_the_workers_boot_activation(self) -> None:
        self.fake.installed.add(WORKER)
        plan = document(services=[SERVICE, WORKER], resume=[WORKER, TIMER])
        self.assertTrue(units.fence(plan, SHOP, gate=True))
        self.assertTrue(units.restore(plan, SHOP))
        self.assertEqual(self.fake.file_state[WORKER], "enabled")
        self.assertEqual(self.fake.file_state[TIMER], "enabled")
        self.assertIn(["enable", WORKER], self.verbs())
        self.assertIn(["enable", TIMER], self.verbs())

    def test_restore_re_enables_only_the_reviewed_resume_set(self) -> None:
        self.fake.file_state[WORKER] = "disabled"
        plan = document(services=[SERVICE, WORKER], resume=[TIMER])
        self.assertTrue(units.restore(plan, SHOP))
        self.assertEqual(self.fake.file_state[WORKER], "disabled")
        self.assertNotIn(["enable", WORKER], self.verbs())

    def test_a_fence_without_a_gate_leaves_boot_activation_alone(self) -> None:
        self.assertTrue(units.fence(document(), SHOP))
        self.assertEqual([call for call in self.verbs() if call[0] == "disable"], [])
        self.assertEqual(self.fake.file_state[TIMER], "enabled")
        self.assertEqual(self.fake.file_state[WORKER], "enabled")

    def test_a_fence_that_cannot_drain_reports_failure(self) -> None:
        self.fake.slice_empty = False
        self.assertFalse(units.fence(document(), SHOP))

    def test_a_worker_enabled_after_the_review_refuses_with_nothing_changed(self) -> None:
        self.fake.installed.add(WORKER)
        self.fake.file_state[WORKER] = "enabled"
        plan = document(services=[SERVICE, WORKER], resume=[TIMER])
        self.assertFalse(units.fence(plan, SHOP))
        self.assertEqual(self.verbs(), [], "A stale resume set must not mask or stop anything.")
        self.assertEqual(self.fake.reloads_noted, 0)

    def test_a_unit_removed_after_the_review_refuses_with_nothing_changed(self) -> None:
        self.fake.installed.remove(SERVICE)
        self.assertFalse(units.fence(document(), SHOP))
        self.assertEqual(self.verbs(), [])

    def test_a_site_without_a_plan_needs_no_fence(self) -> None:
        self.assertTrue(units.fence({}, SHOP))
        self.assertTrue(units.restore({"automation_fence": {"version": 1, "sites": []}}, SHOP))
        self.assertEqual(self.verbs(), [])

    def test_restore_unmasks_and_starts_exactly_the_resume_set(self) -> None:
        self.fake.state[TIMER] = "masked"
        self.fake.state[SERVICE] = "masked"
        self.assertTrue(units.restore(document(), SHOP))
        self.assertEqual(
            self.verbs(),
            [
                ["unmask", "--runtime", TIMER],
                ["clear-dropin", TIMER],
                ["unmask", "--runtime", SERVICE],
                ["clear-dropin", SERVICE],
                ["daemon-reload"],
                ["enable", TIMER],
                ["start", TIMER],
            ],
        )
        self.assertGreater(self.fake.reloads_noted, 0)

    def test_a_fenced_unit_refuses_a_manual_start(self) -> None:
        self.assertTrue(units.fence(document(), SHOP))
        self.assertEqual(self.fake.fenced, {TIMER, SERVICE})

    def test_a_partial_restore_reports_failure_and_starts_nothing_else(self) -> None:
        self.fake.broken.add(SERVICE)
        # The reviewed order starts workers before the timers that drive them.
        plan = document(resume=[SERVICE, TIMER])
        self.assertFalse(units.restore(plan, SHOP))
        self.assertEqual(
            [call for call in self.verbs() if call[0] == "start"],
            [["start", SERVICE], ["start", TIMER]],
        )

    def test_a_plan_that_names_another_site_is_refused(self) -> None:
        for plan in (
            document(slice="barectl-site-other.slice"),
            document(timers=["barectl-site-other-wpcron.timer"]),
            document(resume=["barectl-site-shop-wpcron-extra.timer"]),
            document(budget_seconds=0),
            document(budget_seconds=916),
            {"automation_fence": {"version": 1, "sites": [{"identifier": SHOP}]}},
        ):
            with self.subTest(plan=plan), self.assertRaises(ValueError):
                units.fence(plan, SHOP)

    def test_a_worker_reviewed_stop_budget_is_accepted(self) -> None:
        self.assertTrue(units.fence(document(budget_seconds=915), SHOP))

    def test_a_forgotten_site_clears_its_masks_and_failed_state(self) -> None:
        units.forget(document(), SHOP)
        self.assertEqual(
            self.verbs(),
            [
                ["clear-dropin", TIMER],
                ["unmask", "--runtime", TIMER],
                ["reset-failed", TIMER],
                ["clear-dropin", SERVICE],
                ["unmask", "--runtime", SERVICE],
                ["reset-failed", SERVICE],
                ["daemon-reload"],
            ],
        )
        self.assertGreater(self.fake.reloads_noted, 0)


# The assembled helpers with systemd replaced: every argv is recorded, every unit is loaded
# and the restart prints its journal line, so the program's output is the body's journal.
_PRELUDE = """
class ReviewedPreimageChanged(Exception):
    pass


def run(args, text=None, *, check=True):
    return ""


def safe(path, *, directory):
    return True


def replace_site_file(path, text, expected):
    pass
"""
_STUBS = """
def load_state(name):
    return "loaded"


def resume_matches(plan, identifier):
    return True


def write_dropin(name):
    pass


def clear_dropin(name):
    pass


def wait_slice_empty(name, budget_seconds):
    return True


def _active(name):
    return True


def restart_runtime_masters():
    sys.stdout.write("barectl-restarted php-fpm@php84.service\\n")
    sys.stdout.flush()
"""


def body_argv(steps: str) -> list[str]:
    """The assembled unit helpers and ``steps`` as one body's argv."""
    program = "\n".join(
        (_PRELUDE, AUTOMATION_SOURCE, _STUBS, "document = json.loads(sys.argv[1])", steps)
    )
    return [sys.executable, "-c", "import json\n" + program, json.dumps(document())]


def body_output(steps: str) -> list[str]:
    """Run the body built from ``steps``; its printed lines."""
    completed = subprocess.run(  # noqa: S603 - the test's own interpreter
        body_argv(steps), capture_output=True, text=True, timeout=30, check=False
    )
    return completed.stdout.splitlines()


RESULT = 'sys.stdout.write("barectl-result {}\\n")'


class OneRestartPerBodyTests(SimpleTestCase):
    """The body restarts the runtime masters once, however often it reloaded (#586)."""

    def test_a_body_that_fences_restores_and_enables_restarts_the_masters_once(self) -> None:
        lines = body_output(
            "\n".join(
                (
                    f"fence(document, {SHOP!r}, gate=True)",
                    f"restore(document, {SHOP!r})",
                    f"enable_timer({TIMER!r})",
                    f"enable_service({WORKER!r})",
                    RESULT,
                )
            )
        )
        self.assertEqual(lines, ["barectl-result {}", "barectl-restarted php-fpm@php84.service"])

    def test_a_body_that_fails_after_a_reload_still_restarts_the_masters_once(self) -> None:
        lines = body_output(f"daemon_reload()\nenable_timer({TIMER!r})\nraise ValueError")
        self.assertEqual(lines, ["barectl-restarted php-fpm@php84.service"])

    def test_a_stopped_body_restarts_the_masters_once_and_still_dies_by_sigterm(self) -> None:
        steps = (
            f"daemon_reload()\nenable_timer({TIMER!r})\n"
            'sys.stdout.write("ready\\n")\nsys.stdout.flush()\n'
            f"import time\ntime.sleep(30)\n{RESULT}"
        )
        with subprocess.Popen(  # noqa: S603 - the test's own interpreter
            body_argv(steps), stdout=subprocess.PIPE, text=True
        ) as body:
            if body.stdout is None:
                self.fail("The body has no output pipe.")
            self.assertEqual(body.stdout.readline(), "ready\n")
            body.send_signal(signal.SIGTERM)
            rest = body.stdout.read().splitlines()
            returncode = body.wait(timeout=30)
        self.assertEqual(returncode, -signal.SIGTERM)
        self.assertEqual(rest, ["barectl-restarted php-fpm@php84.service"])

    def test_a_body_that_never_reloads_restarts_nothing(self) -> None:
        lines = body_output(f"load_state({TIMER!r})\n{RESULT}")
        self.assertEqual(lines, ["barectl-result {}"])
