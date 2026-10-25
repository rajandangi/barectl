"""Reading and projecting queue workers from one native answer."""

from django.test import SimpleTestCase

from automation import worker_observation, workers
from automation.testing import laravel_site, observed_worker, worker_payload, worker_show
from automation.worker_status import STATUS_SENTENCE, WorkerStatus


class ReadValidationTests(SimpleTestCase):
    def test_the_native_read_is_valid_python_and_takes_the_shared_lock(self) -> None:
        compile(worker_observation.READ_SOURCE, "<worker-read>", "exec")
        self.assertIn("flock", worker_observation.read_command())

    def test_a_valid_answer_is_strictly_the_documented_shape(self) -> None:
        self.assertTrue(worker_observation.valid(worker_payload()))
        for forged in (
            {**worker_payload(), "version": 2},
            {**worker_payload(), "extra": True},
            {**worker_payload(), "sites": [{"identifier": "shop"}]},
            {
                **worker_payload(),
                "sites": [
                    {
                        **worker_payload()["sites"][0],  # type: ignore[index]
                        "show": {},
                    }
                ],
            },
        ):
            with self.subTest(forged=forged):
                self.assertFalse(worker_observation.valid(forged))


class ProjectionTests(SimpleTestCase):
    def test_a_running_worker_carries_its_definition_and_every_process(self) -> None:
        value = worker_payload(definition=workers.WorkerDefinition(("default", "mail"), 2, 60))
        row = worker_observation.worker_for(value, "shop")
        self.assertEqual(row.status, WorkerStatus.RUNNING)
        self.assertEqual(row.definition, workers.WorkerDefinition(("default", "mail"), 2, 60))
        self.assertEqual(row.processes, 2)
        self.assertEqual(row.active_processes, 2)
        self.assertTrue(row.enabled)
        self.assertEqual(STATUS_SENTENCE[row.status], "On, running")

    def test_a_supported_hand_edit_is_adopted_as_the_definition(self) -> None:
        edited = workers.WorkerDefinition(("critical", "mail"), 1, 240)
        row = worker_observation.worker_for(worker_payload(definition=edited), "shop")
        self.assertEqual(row.definition, edited)
        self.assertEqual(row.problem, "")

    def test_a_crash_loop_carries_the_start_limit_state(self) -> None:
        value = worker_payload(
            show={
                "queue1": worker_show(
                    active="failed", result="start-limit-hit", restarts="5", exit_time="0"
                ),
                "queue2": worker_show(load="not-found", enabled="", active="inactive"),
                "queue3": worker_show(load="not-found", enabled="", active="inactive"),
                "queue4": worker_show(load="not-found", enabled="", active="inactive"),
            }
        )
        row = worker_observation.worker_for(value, "shop")
        self.assertEqual(row.status, WorkerStatus.STOPPED_AFTER_CRASHES)
        self.assertTrue(row.start_limited)
        self.assertEqual(row.nrestarts, 5)

    def test_a_deliberate_stop_is_off(self) -> None:
        value = worker_payload(
            show={
                "queue1": worker_show(active="inactive", enabled="disabled", result="success"),
            }
        )
        row = worker_observation.worker_for(value, "shop")
        self.assertEqual(row.status, WorkerStatus.OFF)
        self.assertFalse(row.enabled)

    def test_an_unreadable_answer_and_a_missing_row_are_never_running(self) -> None:
        unreadable = worker_observation.worker_for(worker_payload(unreadable=True), "shop")
        missing = worker_observation.worker_for(worker_payload(), "alpha")
        self.assertEqual(unreadable.status, WorkerStatus.UNCONFIRMED)
        self.assertEqual(missing.status, WorkerStatus.OFF)
        self.assertEqual(
            worker_observation.worker_for(None, "shop").status, WorkerStatus.UNCONFIRMED
        )

    def test_a_masked_unit_is_paused_by_a_change(self) -> None:
        value = worker_payload(
            show={"queue1": worker_show(load="masked", active="inactive")},
        )
        self.assertEqual(worker_observation.worker_for(value, "shop").status, WorkerStatus.PAUSED)

    def test_only_laravel_sites_get_a_worker_projection(self) -> None:
        value = worker_payload()
        projected = worker_observation.observations(
            value, sites=(laravel_site(),), laravel=frozenset({"shop"})
        )
        self.assertEqual([row.identifier for row in projected or ()], ["shop"])
        projected = worker_observation.observations(
            value, sites=(laravel_site(),), laravel=frozenset()
        )
        self.assertEqual(projected, ())


class StoredStateTests(SimpleTestCase):
    def test_a_projected_row_keeps_its_definition_for_the_snapshot(self) -> None:
        row = observed_worker(
            status=WorkerStatus.STOPPED_AFTER_CRASHES,
            result="start-limit-hit",
            active_processes=0,
            nrestarts=5,
        )
        self.assertEqual(row.queues, ("default",))
        self.assertEqual(row.timeout, 60)
        self.assertEqual(row.evidence.identifier, "shop")
        self.assertEqual(row.evidence.problem, "")
