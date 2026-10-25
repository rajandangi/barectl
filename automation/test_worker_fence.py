"""Queue workers are in the fence plan a site change declares (Phase C #266/#395)."""

from typing import cast

from django.test import SimpleTestCase

from automation import convention, fence
from automation.testing import automation, show

IDENTIFIER = "shop"
SLICE = "barectl-site-shop.slice"
QUEUE1 = "barectl-site-shop-queue1.service"
QUEUE2 = "barectl-site-shop-queue2.service"


def unit(name: str, kind: str) -> dict[str, str]:
    return {"name": name, "kind": kind, "text": f"[Unit]\nDescription={name}\n"}


def worker_plan(
    *,
    queue1: dict[str, str] | None = None,
    queue2: dict[str, str] | None = None,
) -> dict[str, object] | None:
    value = automation(identifier=IDENTIFIER)
    row = cast("dict[str, object]", cast("list[object]", value["sites"])[0])
    row["units"] = [
        unit(SLICE, "slice"),
        unit(QUEUE1, "service"),
        unit(QUEUE2, "service"),
    ]
    roles = cast("dict[str, dict[str, object]]", row["roles"])
    absent = show(load="not-found", enabled="", active="inactive")
    roles["queue1"] = {
        "service": absent if queue1 is None else queue1,
        "timer": absent,
    }
    roles["queue2"] = {
        "service": absent if queue2 is None else queue2,
        "timer": absent,
    }
    return fence.plan_from(value, (IDENTIFIER,))


class WorkerFencePlanTests(SimpleTestCase):
    def test_enabled_worker_services_are_fenced_and_resumed(self) -> None:
        document = worker_plan(queue1=show(enabled="enabled"), queue2=show(enabled="enabled"))
        if document is None:
            self.fail("The worker fence plan was not built.")
        sites = cast("list[dict[str, object]]", document["sites"])
        self.assertEqual(
            sites[0]["services"],
            [QUEUE1, QUEUE2],
        )
        self.assertEqual(sites[0]["resume"], [QUEUE1, QUEUE2])
        self.assertEqual(sites[0]["timers"], [])

    def test_a_stopped_worker_is_fenced_but_not_resumed(self) -> None:
        document = worker_plan(queue1=show(enabled="disabled"), queue2=None)
        if document is None:
            self.fail("The worker fence plan was not built.")
        sites = cast("list[dict[str, object]]", document["sites"])
        services = cast("list[str]", sites[0]["services"])
        resume = cast("list[str]", sites[0]["resume"])
        self.assertIn(QUEUE1, services)
        self.assertNotIn(QUEUE1, resume)

    def test_a_worker_left_fenced_by_a_change_is_not_resumed(self) -> None:
        worker = show(enabled="enabled")
        worker["RefuseManualStart"] = "yes"
        document = worker_plan(queue1=worker)
        if document is None:
            self.fail("The worker fence plan was not built.")
        sites = cast("list[dict[str, object]]", document["sites"])
        self.assertNotIn(QUEUE1, cast("list[str]", sites[0]["resume"]))

    def test_a_deploy_and_rollback_fence_the_worker_services(self) -> None:
        for slug in ("deploy_laravel_site", "rollback_laravel_site"):
            with self.subTest(slug=slug):
                self.assertEqual(fence.fenced_sites(slug, (IDENTIFIER,)), (IDENTIFIER,))
                document = worker_plan(queue1=show(enabled="enabled"))
                if document is None:
                    self.fail("The deploy fence plan was not built.")
                sites = cast("list[dict[str, object]]", document["sites"])
                self.assertIn(QUEUE1, cast("list[str]", sites[0]["services"]))

    def test_the_worker_change_owns_its_own_units_and_is_not_fenced(self) -> None:
        self.assertIn("set_laravel_queue_workers", fence.NO_FENCE)
        self.assertEqual(fence.fenced_sites("set_laravel_queue_workers", (IDENTIFIER,)), ())

    def test_the_scheduler_and_workers_share_the_plan(self) -> None:
        value = automation(identifier=IDENTIFIER)
        row = cast("dict[str, object]", cast("list[object]", value["sites"])[0])
        row["units"] = [
            unit(SLICE, "slice"),
            unit(convention.service_name(IDENTIFIER, convention.ROLE_SCHEDULE), "service"),
            unit(convention.timer_name(IDENTIFIER, convention.ROLE_SCHEDULE), "timer"),
            unit(QUEUE1, "service"),
        ]
        roles = cast("dict[str, dict[str, object]]", row["roles"])
        roles[convention.ROLE_SCHEDULE] = {
            "service": show(),
            "timer": show(enabled="enabled"),
        }
        roles["queue1"] = {"service": show(enabled="enabled"), "timer": show(load="not-found")}
        document = fence.plan_from(value, (IDENTIFIER,))
        if document is None:
            self.fail("The shared fence plan was not built.")
        sites = cast("list[dict[str, object]]", document["sites"])
        self.assertEqual(
            sites[0]["timers"], [convention.timer_name(IDENTIFIER, convention.ROLE_SCHEDULE)]
        )
        self.assertEqual(
            sites[0]["services"],
            [QUEUE1, convention.service_name(IDENTIFIER, convention.ROLE_SCHEDULE)],
        )
        self.assertIn(QUEUE1, cast("list[str]", sites[0]["resume"]))
