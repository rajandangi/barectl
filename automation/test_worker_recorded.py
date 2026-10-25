"""A fresh controller reconstructs the worker definition and state from the server alone."""

from django.test import TestCase
from django.utils import timezone

from discovery import recorded
from discovery.models import DiscoveryAttempt
from discovery.observations import collect
from discovery.recorded import ReplayShell
from discovery.snapshot import current_snapshot, save_snapshot
from operations.inputs import PreparationInputs
from servers.models import Server

from . import worker_change
from .worker_status import WorkerStatus
from .workers import WorkerDefinition

STATE = "automation-laravel-workers-26.04"
IDENTIFIER = "sqwalpha"


def inputs() -> PreparationInputs:
    return PreparationInputs(
        "",
        IDENTIFIER,
        worker_action="start",
        worker_queues=("default",),
        worker_processes=2,
        worker_timeout=60,
    )


class RecordedQueueWorkerTests(TestCase):
    def test_the_recorded_state_reconstructs_the_definition_and_running_processes(self) -> None:
        observed = collect(ReplayShell(recorded.load(STATE)), releases=True)
        self.assertEqual(observed.workers.outcome.value, "observed")
        worker = next(row for row in observed.workers.value if row.identifier == IDENTIFIER)
        self.assertEqual(worker.definition, WorkerDefinition(("default",), 2, 60))
        self.assertEqual(worker.status, WorkerStatus.RUNNING)
        self.assertTrue(worker.enabled)
        self.assertEqual(worker.processes, 2)
        self.assertEqual(worker.active_processes, 2)

    def test_a_repeated_review_from_the_recorded_state_proposes_nothing(self) -> None:
        shell = ReplayShell(recorded.load(STATE))
        collect(shell, releases=True)
        draft = worker_change.review(worker_change.inspect(shell, inputs()), inputs())
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
        self.assertEqual(draft.effects, ())

    def test_the_stored_snapshot_keeps_the_definition_and_state(self) -> None:
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        collected = collect(ReplayShell(recorded.load(STATE)), releases=True)
        attempt = DiscoveryAttempt.objects.create(
            server=server,
            ssh_alias=server.ssh_alias,
            status=DiscoveryAttempt.Status.SUCCEEDED,
        )
        save_snapshot(attempt, collected, timezone.now())
        stored = current_snapshot(server)
        if stored is None:
            self.fail("The snapshot was stored.")
        self.assertEqual(stored.collected.workers, collected.workers)
        worker = next(row for row in stored.collected.workers.value if row.identifier == IDENTIFIER)
        self.assertEqual(worker.definition, WorkerDefinition(("default",), 2, 60))
        self.assertEqual(worker.status, WorkerStatus.RUNNING)
