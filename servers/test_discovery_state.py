"""The dashboard's view of a server's discovery, for every attempt, snapshot and alias state.

Most states are built from attempts as the pages show them, so those tests need no database,
worker or page. ``ReadTests`` read states through ``server_state``, ``inventory`` and
``activity_rows``, with recorded attempts and a controller SSH configuration.
"""

from typing import ClassVar, override

from django.test import SimpleTestCase
from django.utils import timezone

from discovery.fakes import COLLECTED, COLLECTED_AT, STALE, record_attempt
from discovery.models import DiscoveryAttempt
from discovery.services import INTERRUPTED_FAILURE
from discovery.snapshot import Snapshot
from operations.models import RemoteOperation

from .discovery_state import (
    AttemptView,
    DiscoveryState,
    Status,
    activity_rows,
    inventory,
    server_state,
)
from .models import Server
from .testing import SSH_CONFIG, ControllerConfigTestCase

AttemptStatus = RemoteOperation.Status
SNAPSHOT = Snapshot(collected=COLLECTED, collected_at=COLLECTED_AT, ssh_alias="web")
# Discovery is read-only: an attempt never waits for reconciliation.
ATTEMPT_STATES = tuple(status for status in AttemptStatus if status != AttemptStatus.RECONCILING)
STATES: tuple[AttemptStatus | None, ...] = (None, *ATTEMPT_STATES)
WORDING = {
    AttemptStatus.QUEUED: Status.QUEUED,
    AttemptStatus.RUNNING: Status.RUNNING,
    AttemptStatus.FAILED: Status.FAILED,
    AttemptStatus.SUCCEEDED: Status.VERIFIED,
}
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
    server = Server(name="Web", ssh_alias="web")
    attempt = None
    if attempt_status is not None:
        attempt = AttemptView(
            operation_id=1,
            server=server,
            status=WORDING[attempt_status],
            ssh_alias="web",
            queued_at=timezone.now(),
            started_at=None,
            finished_at=None,
            failure="",
            host_key="",
            snapshot=None,
        )
    return DiscoveryState(
        server=server,
        attempt=attempt,
        snapshot=snapshot,
        history=[] if attempt is None else [attempt],
        alias_usable=alias_usable,
    )


class ConnectionStatusTests(SimpleTestCase):
    def test_every_attempt_and_alias_state(self) -> None:
        for (attempt_status, alias_usable), status in CONNECTION_STATUS.items():
            with self.subTest(attempt=attempt_status, alias_usable=alias_usable):
                self.assertEqual(state(attempt_status, alias_usable=alias_usable).status, status)


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
        for attempt_status in ATTEMPT_STATES:
            with self.subTest(attempt=attempt_status):
                current = state(attempt_status)
                self.assertTrue(current.changed_since(None))
                self.assertFalse(current.changed_since(current.shown))
                # The page sends back the module's token, never the stored state.
                self.assertNotEqual(current.shown, attempt_status)
                self.assertTrue(current.announcement.endswith("."))
        self.assertTrue(
            state(AttemptStatus.QUEUED).changed_since(state(AttemptStatus.RUNNING).shown)
        )
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
        self.assertEqual((current.attempt, current.snapshot, current.history), (None, None, []))
        earlier = record_attempt(self.server, AttemptStatus.SUCCEEDED)
        latest = record_attempt(self.server, AttemptStatus.FAILED, failure="Refused.")
        current = server_state(self.server)
        self.assertEqual(current.server, self.server)
        self.assertEqual(current.history[0], current.attempt)
        self.assertEqual(
            current.attempt,
            AttemptView(
                operation_id=latest.pk,
                server=self.server,
                status=Status.FAILED,
                ssh_alias=latest.ssh_alias,
                queued_at=latest.queued_at,
                started_at=latest.started_at,
                finished_at=latest.finished_at,
                failure="Refused.",
                host_key="",
                snapshot=None,
            ),
        )
        # Recorded by hand, the succeeded attempt published no snapshot.
        self.assertIsNone(current.snapshot)
        self.assertEqual(
            [(listed.status, listed.queued_at) for listed in current.history],
            [(Status.FAILED, latest.queued_at), (Status.VERIFIED, earlier.queued_at)],
        )

    def test_attempts_are_listed_in_the_pages_wording(self) -> None:
        other = Server.objects.create(name="Database", ssh_alias="db-1")
        for attempt_status in ATTEMPT_STATES:
            with self.subTest(attempt=attempt_status):
                DiscoveryAttempt.objects.all().delete()
                record_attempt(self.server, attempt_status)
                record_attempt(other, AttemptStatus.SUCCEEDED)
                wording = WORDING[attempt_status]
                listed = server_state(self.server).history
                self.assertEqual([row.status for row in listed], [wording])
                self.assertEqual(
                    [(row.server, row.status) for row in activity_rows()],
                    [(other, Status.VERIFIED), (self.server, wording)],
                )
