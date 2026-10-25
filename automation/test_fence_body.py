"""The body-side fence and restore, against a simulated systemd (#395).

The native suite proves the real stop/start; this layer proves the order, the refusals and
that restore starts exactly the reviewed set and proves it active.
"""

from typing import override
from unittest import mock

from django.test import SimpleTestCase

from automation.bodies import units

SHOP = "shop"
TIMER = "barectl-site-shop-wpcron.timer"
SERVICE = "barectl-site-shop-wpcron.service"
SLICE = "barectl-site-shop.slice"


def document(**values: object) -> dict[str, object]:
    site = {
        "identifier": SHOP,
        "slice": SLICE,
        "timers": [TIMER],
        "services": [SERVICE],
        "resume": [TIMER],
        "budget_seconds": 5,
        **values,
    }
    return {"automation_fence": {"version": 1, "sites": [site]}}


class FakeSystemd:
    """Records the systemctl argv and keeps enough state for the helpers' questions."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.state = {TIMER: "loaded", SERVICE: "loaded", SLICE: "loaded"}
        self.active = {TIMER: "inactive", SERVICE: "inactive"}
        self.file_state = {TIMER: "enabled", SERVICE: ""}
        # Units this simulated systemd refuses to start.
        self.broken: set[str] = set()
        # Units whose runtime fence drop-in is present.
        self.fenced: set[str] = set()
        self.slice_empty = True

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

    def timer_ready(self, name: str) -> bool:
        return self.active.get(name) == "active" and self.file_state.get(name) == "enabled"

    def wait_slice_empty(self, name: str, budget: int) -> bool:
        return self.slice_empty


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
            "write_dropin",
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

    def test_a_fence_that_cannot_drain_reports_failure(self) -> None:
        self.fake.slice_empty = False
        self.assertFalse(units.fence(document(), SHOP))

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
            {"automation_fence": {"version": 1, "sites": [{"identifier": SHOP}]}},
        ):
            with self.subTest(plan=plan), self.assertRaises(ValueError):
                units.fence(plan, SHOP)

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
