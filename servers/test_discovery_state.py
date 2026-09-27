"""The dashboard's view of a server's discovery, for every attempt, snapshot and alias state.

States are built from unsaved attempts, so these tests need no database, worker or page.
"""

from django.test import SimpleTestCase

from discovery.models import DiscoveryAttempt
from discovery.snapshot import Snapshot
from discovery.test_snapshot import COLLECTED, COLLECTED_AT

from .discovery_state import DiscoveryState, Status, connection_status

AttemptStatus = DiscoveryAttempt.Status
SNAPSHOT = Snapshot(collected=COLLECTED, collected_at=COLLECTED_AT, ssh_alias="web")
STATES: tuple[AttemptStatus | None, ...] = (None, *AttemptStatus)


def state(
    attempt_status: AttemptStatus | None,
    *,
    snapshot: Snapshot | None = SNAPSHOT,
    alias_usable: bool = True,
) -> DiscoveryState:
    attempt = None if attempt_status is None else DiscoveryAttempt(status=attempt_status)
    return DiscoveryState(attempt=attempt, snapshot=snapshot, alias_usable=alias_usable)


class ConnectionStatusTests(SimpleTestCase):
    def test_every_attempt_and_alias_state(self) -> None:
        expected = {
            (None, True): Status.NOT_VERIFIED,
            (None, False): Status.UNAVAILABLE,
            (AttemptStatus.QUEUED, True): Status.QUEUED,
            # An active check runs with the alias it was queued with.
            (AttemptStatus.QUEUED, False): Status.QUEUED,
            (AttemptStatus.RUNNING, True): Status.RUNNING,
            (AttemptStatus.RUNNING, False): Status.RUNNING,
            (AttemptStatus.FAILED, True): Status.FAILED,
            (AttemptStatus.FAILED, False): Status.UNAVAILABLE,
            (AttemptStatus.SUCCEEDED, True): Status.VERIFIED,
            # A verified connection no longer holds once its alias is unusable.
            (AttemptStatus.SUCCEEDED, False): Status.UNAVAILABLE,
        }
        for (attempt_status, alias_usable), status in expected.items():
            with self.subTest(attempt=attempt_status, alias_usable=alias_usable):
                self.assertEqual(
                    connection_status(attempt_status, alias_usable=alias_usable), status
                )
                self.assertEqual(state(attempt_status, alias_usable=alias_usable).status, status)

    def test_the_attempt_status_ignores_the_alias(self) -> None:
        for attempt_status in STATES:
            with self.subTest(attempt=attempt_status):
                usable = state(attempt_status).attempt_status
                self.assertEqual(state(attempt_status, alias_usable=False).attempt_status, usable)
        self.assertEqual(state(None).attempt_status, Status.NOT_VERIFIED)


class DiscoveryStateTests(SimpleTestCase):
    def test_polling_and_requests_follow_active_attempts(self) -> None:
        for attempt_status in STATES:
            with self.subTest(attempt=attempt_status):
                active = attempt_status in DiscoveryAttempt.ACTIVE
                self.assertIs(state(attempt_status).polling, active)
                self.assertIs(state(attempt_status).can_request, not active)

    def test_action_label(self) -> None:
        expected = {
            None: "Verify connection",
            AttemptStatus.QUEUED: "Verify connection",
            AttemptStatus.RUNNING: "Verify connection",
            AttemptStatus.FAILED: "Retry connection check",
            AttemptStatus.SUCCEEDED: "Refresh observations",
        }
        for attempt_status, label in expected.items():
            with self.subTest(attempt=attempt_status):
                self.assertEqual(state(attempt_status).action_label, label)

    def test_snapshot_notice(self) -> None:
        failed = "The latest connection check failed, so these observations may be out of date."
        checking = "A new connection check is running; these observations may be out of date."
        expected = {
            None: None,
            AttemptStatus.QUEUED: (checking, False),
            AttemptStatus.RUNNING: (checking, False),
            # A failed check deserves more attention than one in progress.
            AttemptStatus.FAILED: (failed, True),
            AttemptStatus.SUCCEEDED: None,
        }
        for attempt_status, notice in expected.items():
            with self.subTest(attempt=attempt_status):
                shown = state(attempt_status).snapshot_notice
                self.assertEqual(shown and (shown.text, shown.emphasized), notice)

    def test_changes_are_announced_once(self) -> None:
        self.assertFalse(state(None).changed_since(None))
        self.assertEqual(state(None).announcement, "")
        for attempt_status in AttemptStatus:
            with self.subTest(attempt=attempt_status):
                current = state(attempt_status)
                self.assertTrue(current.changed_since(None))
                self.assertFalse(current.changed_since(attempt_status))
                self.assertTrue(current.announcement.endswith("."))
        self.assertEqual(state(AttemptStatus.FAILED).announcement, "The connection failed.")
