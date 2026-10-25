"""The status projection for every state a site's queue workers can be in."""

from django.test import SimpleTestCase

from automation.worker_status import (
    ATTENTION_STATUSES,
    START_LIMIT_RESULT,
    STATUS_SENTENCE,
    WorkerEvidence,
    WorkerStatus,
    attention_problem,
    project,
)


def evidence(**overrides: object) -> WorkerEvidence:
    values: dict[str, object] = {
        "identifier": "shop",
        "installed": True,
        "enabled": True,
        "processes": 2,
        "active_processes": 2,
    }
    values.update(overrides)
    return WorkerEvidence(**values)  # type: ignore[arg-type]


class ProjectionTests(SimpleTestCase):
    def test_running_workers_are_on(self) -> None:
        status = project(evidence())
        self.assertEqual(status, WorkerStatus.RUNNING)
        self.assertEqual(STATUS_SENTENCE[status], "On, running")
        self.assertNotIn(status, ATTENTION_STATUSES)

    def test_a_deliberate_stop_is_off_and_not_an_alarm(self) -> None:
        status = project(evidence(enabled=False, active_processes=0, result="success"))
        self.assertEqual(status, WorkerStatus.OFF)
        self.assertEqual(STATUS_SENTENCE[status], "Off")
        self.assertNotIn(status, ATTENTION_STATUSES)
        self.assertEqual(attention_problem(evidence(enabled=False), status), "")

    def test_a_worker_systemd_gave_up_on_is_stopped_after_repeated_crashes(self) -> None:
        status = project(
            evidence(
                active_processes=0,
                result=START_LIMIT_RESULT,
                start_limited=True,
                nrestarts=5,
            )
        )
        self.assertEqual(status, WorkerStatus.STOPPED_AFTER_CRASHES)
        self.assertEqual(STATUS_SENTENCE[status], "Stopped after repeated crashes")
        self.assertIn(status, ATTENTION_STATUSES)
        self.assertIn("stopped after repeated crashes", attention_problem(evidence(), status))

    def test_a_crash_that_is_restarting_is_shown_and_joins_attention(self) -> None:
        status = project(evidence(active_processes=0, result="signal", nrestarts=1))
        self.assertEqual(status, WorkerStatus.RESTARTING)
        self.assertIn(status, ATTENTION_STATUSES)
        self.assertIn("restarted after a crash", attention_problem(evidence(), status))

    def test_a_masked_unit_reads_paused_and_a_maintenance_gate_reads_off(self) -> None:
        self.assertEqual(project(evidence(masked=True)), WorkerStatus.PAUSED)
        self.assertEqual(
            project(evidence(gate=True, enabled=False, active_processes=0)),
            WorkerStatus.OFF_MAINTENANCE,
        )
        self.assertEqual(attention_problem(evidence(), WorkerStatus.OFF_MAINTENANCE), "")

    def test_an_unreadable_answer_is_never_running(self) -> None:
        status = project(evidence(readable=False, active_processes=2))
        self.assertEqual(status, WorkerStatus.UNCONFIRMED)
        self.assertIn(status, ATTENTION_STATUSES)
        self.assertIn("could not confirm", attention_problem(evidence(), status))

    def test_a_duplicate_worker_is_reported_while_no_worker_is_installed(self) -> None:
        duplicate = "A hand-made crontab entry already runs queue:work for this site."
        status = project(
            evidence(installed=False, enabled=False, active_processes=0, duplicate=duplicate)
        )
        self.assertEqual(status, WorkerStatus.OFF)
        self.assertEqual(
            attention_problem(evidence(installed=False, duplicate=duplicate), status), duplicate
        )

    def test_every_status_has_a_plain_sentence(self) -> None:
        self.assertEqual(set(STATUS_SENTENCE), set(WorkerStatus))
