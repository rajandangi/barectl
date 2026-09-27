"""The dashboard's view of a server's discovery, for every attempt, snapshot and alias state.

Most states are built from unsaved attempts, so those tests need no database, worker or
page. ``ReadTests`` read states through ``server_state`` and ``inventory``, with recorded
attempts and a controller SSH configuration.
"""

from typing import ClassVar, override

from django.test import SimpleTestCase

from discovery.models import DiscoveryAttempt
from discovery.services import INTERRUPTED_FAILURE
from discovery.snapshot import Snapshot
from discovery.test_attempts import STALE, record_attempt
from discovery.test_snapshot import COLLECTED, COLLECTED_AT

from .discovery_state import DiscoveryState, Status, inventory, server_state
from .models import Server
from .tests import SSH_CONFIG, ControllerConfigTestCase

AttemptStatus = DiscoveryAttempt.Status
SNAPSHOT = Snapshot(collected=COLLECTED, collected_at=COLLECTED_AT, ssh_alias="web")
STATES: tuple[AttemptStatus | None, ...] = (None, *AttemptStatus)
# The connection status for each latest attempt state and whether the alias is usable.
CONNECTION_STATUS = {
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


def state(
    attempt_status: AttemptStatus | None,
    *,
    snapshot: Snapshot | None = SNAPSHOT,
    alias_usable: bool = True,
) -> DiscoveryState:
    attempt = None if attempt_status is None else DiscoveryAttempt(status=attempt_status)
    return DiscoveryState(
        server=Server(name="Web", ssh_alias="web"),
        attempt=attempt,
        snapshot=snapshot,
        alias_usable=alias_usable,
    )


class ConnectionStatusTests(SimpleTestCase):
    def test_every_attempt_and_alias_state(self) -> None:
        for (attempt_status, alias_usable), status in CONNECTION_STATUS.items():
            with self.subTest(attempt=attempt_status, alias_usable=alias_usable):
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


class ReadTests(ControllerConfigTestCase):
    """States read from recorded attempts and the controller's SSH configuration."""

    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def statuses(self) -> tuple[Status, Status]:
        """The server's connection status on its page and in the inventory."""
        (row,) = inventory(Server.objects.all())
        self.assertEqual(row.server, self.server)
        return server_state(self.server).status, row.status

    def test_the_connection_status_follows_the_attempt_and_the_alias(self) -> None:
        unusable = {
            "removed": "Host db-1\n",
            "refused": "Host web.example.com\n  ProxyJump bastion\n",
            "unreadable": "Host web.example.com\nMatch all\n  User x\n",
        }
        for (attempt_status, alias_usable), status in CONNECTION_STATUS.items():
            configs = {"usable": SSH_CONFIG} if alias_usable else unusable
            for config, text in configs.items():
                with self.subTest(attempt=attempt_status, config=config):
                    DiscoveryAttempt.objects.all().delete()
                    if attempt_status is not None:
                        record_attempt(self.server, attempt_status)
                    self.write_config(text)
                    self.assertEqual(self.statuses(), (status, status))
                    self.assertIs(server_state(self.server).alias_usable, alias_usable)

    def test_abandoned_attempts_are_recovered_before_the_status_is_decided(self) -> None:
        for read in ("page", "inventory"):
            with self.subTest(read=read):
                DiscoveryAttempt.objects.all().delete()
                attempt = record_attempt(self.server, AttemptStatus.RUNNING, age=STALE)
                if read == "page":
                    self.assertEqual(server_state(self.server).status, Status.FAILED)
                else:
                    (row,) = inventory(Server.objects.all())
                    self.assertEqual(row.status, Status.FAILED)
                attempt.refresh_from_db()
                self.assertEqual(attempt.failure, INTERRUPTED_FAILURE)

    def test_the_page_state_carries_the_latest_attempt_and_the_history(self) -> None:
        current = server_state(self.server)
        self.assertEqual((current.attempt, current.snapshot, current.history()), (None, None, []))
        earlier = record_attempt(self.server, AttemptStatus.SUCCEEDED)
        latest = record_attempt(self.server, AttemptStatus.FAILED)
        current = server_state(self.server)
        self.assertEqual(current.server, self.server)
        self.assertEqual(current.attempt, latest)
        # Recorded by hand, the succeeded attempt published no snapshot.
        self.assertIsNone(current.snapshot)
        self.assertEqual([attempt for attempt, _ in current.history()], [latest, earlier])
