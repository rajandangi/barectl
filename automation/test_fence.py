"""The fence a site change declares: what it pauses and what it starts again (Phase C #395).

docs/automation.md#fencing. The plan is read once at review time from the same automation
evidence discovery keeps, so a fresh controller declares exactly what the server shows and
never guesses what was on before.
"""

from typing import cast

from django.test import SimpleTestCase

from automation import fence, workers
from automation.testing import automation, show

SHOP = "shop"
WPCRON_TIMER = "barectl-site-shop-wpcron.timer"
WPCRON_SERVICE = "barectl-site-shop-wpcron.service"
SCHEDULE_TIMER = "barectl-site-shop-schedule.timer"
SCHEDULE_SERVICE = "barectl-site-shop-schedule.service"
QUEUE_SERVICE = "barectl-site-shop-queue1.service"
SLICE = "barectl-site-shop.slice"


def site_plan(**values: object) -> dict[str, object]:
    return {
        "identifier": SHOP,
        "slice": SLICE,
        "timers": [WPCRON_TIMER],
        "services": [WPCRON_SERVICE],
        "resume": [WPCRON_TIMER],
        "budget_seconds": fence.FENCE_BUDGET_SECONDS,
        **values,
    }


def unit(name: str, kind: str, text: str = "") -> dict[str, str]:
    return {"name": name, "kind": kind, "text": text or f"[Unit]\nDescription={name}\n"}


def with_roles(
    units: list[dict[str, str]],
    roles: dict[str, tuple[dict[str, str] | None, dict[str, str] | None]],
) -> dict[str, object]:
    """One site whose read answers each installed role's timer and service properties."""
    value = automation(units=units)
    row = cast("list[dict[str, object]]", value["sites"])[0]
    row["roles"] = {
        role: {"timer": timer, "service": service} for role, (timer, service) in roles.items()
    }
    return value


class FencePlanTests(SimpleTestCase):
    def test_an_enabled_timer_is_paused_and_started_again(self) -> None:
        document = fence.plan_from(automation(timer=show(active="active")), (SHOP,))
        self.assertEqual(document, {"version": 1, "sites": [site_plan()]})

    def test_a_disabled_timer_is_paused_and_not_started_again(self) -> None:
        document = fence.plan_from(automation(timer=show(enabled="disabled")), (SHOP,))
        self.assertEqual(
            document, {"version": 1, "sites": [site_plan(resume=[])]}, "A stopped run stays off."
        )

    def test_a_paused_site_is_fenced_and_not_started_again(self) -> None:
        masked = show(load="masked", enabled="masked")
        document = fence.plan_from(automation(timer=masked, service=masked), (SHOP,))
        self.assertEqual(document, {"version": 1, "sites": [site_plan(resume=[])]})

    def test_a_site_with_no_automation_pauses_nothing(self) -> None:
        self.assertEqual(
            fence.plan_from(automation(units=[]), (SHOP,)), {"version": 1, "sites": []}
        )

    def test_a_site_the_server_does_not_list_pauses_nothing(self) -> None:
        self.assertEqual(fence.plan_from(automation(), ("other",)), {"version": 1, "sites": []})

    def test_unreadable_evidence_is_not_a_plan(self) -> None:
        self.assertIsNone(fence.plan_from(automation(unreadable=True), (SHOP,)))

    def test_a_role_without_its_properties_is_not_a_plan(self) -> None:
        # A role is installed, but the read carried no properties for it: starting it again
        # would be a guess, and leaving it stopped silently would be worse.
        units = [
            unit(SLICE, "slice"),
            unit("barectl-site-shop-queue1.service", "service", "[Service]\nType=exec\n"),
        ]
        value = automation(units=units)
        row = cast("dict[str, object]", cast("list[object]", value["sites"])[0])
        cast("dict[str, object]", row["roles"])["queue1"] = {"service": None, "timer": None}
        self.assertIsNone(fence.plan_from(value, (SHOP,)))

    def test_every_installed_role_is_carried_in_its_own_order(self) -> None:
        """The scheduler and queue roles #265/#266 add need no fence change."""
        value = with_roles(
            [
                unit(SLICE, "slice"),
                unit(WPCRON_SERVICE, "service"),
                unit(WPCRON_TIMER, "timer"),
                unit(SCHEDULE_SERVICE, "service"),
                unit(SCHEDULE_TIMER, "timer"),
            ],
            {
                "wpcron": (show(active="active"), show()),
                "schedule": (show(active="active"), show()),
            },
        )
        self.assertEqual(
            fence.plan_from(value, (SHOP,)),
            {
                "version": 1,
                "sites": [
                    site_plan(
                        timers=[SCHEDULE_TIMER, WPCRON_TIMER],
                        services=[SCHEDULE_SERVICE, WPCRON_SERVICE],
                        resume=[SCHEDULE_TIMER, WPCRON_TIMER],
                    )
                ],
            },
        )

    def test_the_stop_budget_is_the_longest_declared_stop_of_a_reviewed_worker(self) -> None:
        definition = workers.WorkerDefinition(("default",), 1, 900)
        value = with_roles(
            [
                unit(SLICE, "slice"),
                {
                    "name": QUEUE_SERVICE,
                    "kind": "service",
                    "text": workers.render_worker_service(SHOP, 1, definition),
                },
            ],
            {"queue1": (None, show())},
        )
        document = fence.plan_from(value, (SHOP,))
        if document is None:
            self.fail("The worker fence plan was not built.")
        sites = cast("list[dict[str, object]]", document["sites"])
        self.assertEqual(sites[0]["budget_seconds"], 915)

    def test_a_site_without_declared_stops_keeps_the_thirty_second_minimum(self) -> None:
        value = with_roles(
            [
                unit(SLICE, "slice"),
                {
                    "name": QUEUE_SERVICE,
                    "kind": "service",
                    "text": workers.render_worker_service(
                        SHOP, 1, workers.WorkerDefinition(("default",), 1, 30)
                    ),
                },
            ],
            {"queue1": (None, show())},
        )
        document = fence.plan_from(value, (SHOP,))
        if document is None:
            self.fail("The worker fence plan was not built.")
        sites = cast("list[dict[str, object]]", document["sites"])
        self.assertEqual(sites[0]["budget_seconds"], 45)

    def test_a_worker_role_whose_timer_is_absent_is_planned(self) -> None:
        value = with_roles(
            [unit(SLICE, "slice"), unit(QUEUE_SERVICE, "service")],
            {"queue1": (None, show())},
        )
        document = fence.plan_from(value, (SHOP,))
        self.assertEqual(
            document,
            {
                "version": 1,
                "sites": [site_plan(timers=[], services=[QUEUE_SERVICE], resume=[QUEUE_SERVICE])],
            },
        )

    def test_a_worker_without_a_timer_resumes_its_service(self) -> None:
        value = with_roles(
            [unit(SLICE, "slice"), unit(QUEUE_SERVICE, "service")],
            {"queue1": (show(load="not-found", enabled="", active="inactive"), show())},
        )
        document = fence.plan_from(value, (SHOP,))
        self.assertEqual(
            document,
            {
                "version": 1,
                "sites": [site_plan(timers=[], services=[QUEUE_SERVICE], resume=[QUEUE_SERVICE])],
            },
        )

    def test_a_worker_left_fenced_by_an_unfinished_change_is_not_resumed(self) -> None:
        # A gated or interrupted change leaves the worker enabled on disk but refusing a
        # start; a fresh review must not infer that it was on (docs/adr/0036).
        service = show(enabled="enabled")
        service["RefuseManualStart"] = "yes"
        value = with_roles(
            [unit(SLICE, "slice"), unit(QUEUE_SERVICE, "service")],
            {"queue1": (show(load="not-found", enabled="", active="inactive"), service)},
        )
        document = fence.plan_from(value, (SHOP,))
        if document is None:
            self.fail("The fenced worker's site was not planned.")
        sites = cast("list[dict[str, object]]", document["sites"])
        self.assertEqual([entry["resume"] for entry in sites], [[]])

    def test_several_named_sites_carry_their_own_plans(self) -> None:
        first = automation(timer=show(active="active"))
        second = automation("alpha", timer=show(active="active"))
        rows = [*_rows(first), *_rows(second)]
        document = fence.plan_from({"version": 1, "sites": rows}, ("shop", "alpha"))
        if document is None:
            self.fail("Two named sites with automation were not planned.")
        sites = cast("list[dict[str, object]]", document["sites"])
        self.assertEqual([entry["identifier"] for entry in sites], ["alpha", "shop"])

    def test_a_site_with_a_second_scheduler_is_still_planned(self) -> None:
        document = fence.plan_from(
            automation(timer=show(active="active"), duplicate="A crontab runs this site too."),
            (SHOP,),
        )
        self.assertEqual(document, {"version": 1, "sites": [site_plan()]})


def _rows(value: dict[str, object]) -> list[object]:
    return cast("list[object]", value["sites"])
