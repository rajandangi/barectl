"""A site change fences the queue workers too, and resumes exactly what was on."""

from dataclasses import replace

from django.test import SimpleTestCase

from automation import fence
from automation.observation import ObservedSchedule
from automation.testing import observed_worker
from automation.worker_observation import ObservedWorker
from automation.worker_status import WorkerStatus
from automation.workers import WorkerDefinition
from discovery.fakes import COLLECTED
from discovery.models import ObservationOutcome
from discovery.snapshot import CollectedSnapshot, Observation


def collected(
    *, worker: ObservedWorker | None = None, schedule: ObservedSchedule | None = None
) -> CollectedSnapshot:
    return replace(
        COLLECTED,
        automation=Observation(
            ObservationOutcome.OBSERVED,
            ("/etc/systemd/system",),
            "",
            (schedule,) if schedule is not None else (),
        ),
        workers=Observation(
            ObservationOutcome.OBSERVED,
            ("/etc/systemd/system",),
            "",
            (worker,) if worker is not None else (),
        ),
    )


class FencePlanTests(SimpleTestCase):
    def test_an_enabled_worker_is_fenced_and_resumed_on_the_same_services(self) -> None:
        plan = fence.review_fence_plan(
            collected(
                worker=observed_worker(
                    definition=WorkerDefinition(("default",), 2, 60), active_processes=2
                )
            ),
            "shop",
        )
        if plan is None:
            self.fail("The fence plan was not built.")
        self.assertEqual(plan.fence.slice, "barectl-site-shop.slice")
        self.assertEqual(plan.fence.timers, ())
        self.assertEqual(
            plan.fence.services,
            (
                "barectl-site-shop-queue1.service",
                "barectl-site-shop-queue2.service",
            ),
        )
        self.assertEqual(plan.resume, plan.fence.services)

    def test_a_stopped_worker_is_fenced_without_being_resumed(self) -> None:
        plan = fence.review_fence_plan(
            collected(
                worker=observed_worker(status=WorkerStatus.OFF, enabled=False, active_processes=0)
            ),
            "shop",
        )
        if plan is None:
            self.fail("The fence plan was not built.")
        self.assertEqual(len(plan.fence.services), 1)
        self.assertEqual(plan.resume, ())

    def test_crashed_work_is_not_restarted_after_a_change(self) -> None:
        plan = fence.review_fence_plan(
            collected(
                worker=observed_worker(
                    status=WorkerStatus.STOPPED_AFTER_CRASHES,
                    active_processes=0,
                    result="start-limit-hit",
                )
            ),
            "shop",
        )
        if plan is None:
            self.fail("The fence plan was not built.")
        self.assertEqual(plan.resume, ())

    def test_no_automation_evidence_never_yields_a_blind_fence(self) -> None:
        self.assertIsNone(fence.review_fence_plan(collected(), "shop"))
