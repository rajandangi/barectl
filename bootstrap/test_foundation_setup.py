"""The setup journey uses recorded evidence without separate wizard state."""

from dataclasses import replace

from django.test import TestCase
from django.utils import timezone

from discovery.fakes import COLLECTED
from discovery.snapshot import Snapshot
from servers.discovery_state import AttemptView, DiscoveryState, Status
from servers.models import Server

from .foundation_setup import project
from .standing import judge
from .standing_testing import fresh_evidence


class FoundationSetupProjectionTests(TestCase):
    def test_steps_follow_connection_readiness_and_verified_native_stack(self) -> None:
        server = Server.objects.create(name="Foundation", ssh_alias="foundation")
        state = DiscoveryState(server, None, None, [], True)
        self.assertEqual(project(state).current, 1)
        attempt = AttemptView(
            1,
            server,
            Status.VERIFIED,
            server.ssh_alias,
            timezone.now(),
            None,
            timezone.now(),
            "",
            "verified fixture",
            None,
        )
        state = replace(state, attempt=attempt)
        self.assertEqual(project(state).current, 2)
        fresh = replace(COLLECTED, standing=judge(fresh_evidence()))
        state = replace(state, snapshot=Snapshot(fresh, timezone.now(), server.ssh_alias))
        self.assertEqual(project(state).current, 3)
        target = replace(
            fresh, standing=judge(replace(fresh_evidence(), foundation=("present",) * 5))
        )
        state = replace(state, snapshot=Snapshot(target, timezone.now(), server.ssh_alias))
        completed = project(state)
        self.assertEqual(completed.current, 4)
        self.assertTrue(completed.complete)
        self.assertTrue(all(step.status == "complete" for step in completed.steps))
        checking = replace(state, attempt=replace(attempt, status=Status.RUNNING))
        self.assertFalse(project(checking).complete)
