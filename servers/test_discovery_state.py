"""The dashboard's view of a server's discovery, for every attempt, snapshot and alias state.

Most states are built from attempts as the pages show them, so those tests need no database,
worker or page. ``ReadTests`` read states through ``server_state``, ``inventory`` and
``activity_rows``, with recorded attempts and a controller SSH configuration.
"""

from dataclasses import replace
from typing import ClassVar, override
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from discovery import snapshot as snapshot_module
from discovery.fakes import COLLECTED, COLLECTED_AT, STALE, record_attempt
from discovery.models import DiscoveryAttempt, DiscoverySnapshot, ObservationOutcome
from discovery.services import INTERRUPTED_FAILURE, history, read_discovery
from discovery.snapshot import Observation, Snapshot, SnapshotFacts, save_snapshot
from operations.models import RemoteOperation
from operations.services import ServerChanges

from .discovery_state import (
    AttemptView,
    DiscoveryState,
    Status,
    activity_rows,
    inventory,
    server_state,
    site_page,
)
from .models import ConnectionDefinition, Server
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
        changes=ServerChanges([], None),
    )


class SiteResolutionTests(SimpleTestCase):
    def test_unknown_without_a_successful_snapshot(self) -> None:
        for attempt_status in STATES:
            with self.subTest(status=attempt_status):
                page = site_page(state(attempt_status, snapshot=None), "alpha")
                self.assertEqual(page.absence, "unknown")
                self.assertFalse(page.found)
                self.assertFalse(page.current)

    def test_a_later_check_leaves_the_last_snapshot_shown_but_stale(self) -> None:
        for attempt_status in (AttemptStatus.QUEUED, AttemptStatus.RUNNING, AttemptStatus.FAILED):
            with self.subTest(status=attempt_status):
                current = state(attempt_status)
                page = site_page(current, "alpha")
                self.assertTrue(page.found)
                self.assertEqual(page.absence, "")
                self.assertEqual(page.stale, current.snapshot_notice)
                self.assertIsNotNone(page.stale)
                self.assertFalse(page.current)
                missing = site_page(current, "absent1")
                self.assertEqual(missing.absence, "missing")
                self.assertFalse(missing.current)

    def test_missing_when_the_complete_collection_omits_the_site(self) -> None:
        page = site_page(state(AttemptStatus.SUCCEEDED), "absent1")
        self.assertEqual(page.absence, "missing")
        self.assertFalse(page.found)

    def test_found_from_the_current_observation(self) -> None:
        page = site_page(state(AttemptStatus.SUCCEEDED), "alpha")
        self.assertTrue(page.found)
        self.assertEqual(page.absence, "")
        self.assertIsNone(page.stale)
        self.assertTrue(page.current)
        self.assertEqual(page.site.identifier if page.site else None, "alpha")

    def test_the_read_indexes_sites_by_identifier(self) -> None:
        current = state(AttemptStatus.SUCCEEDED)
        self.assertEqual(set(current.site_index), {"alpha", "beta"})
        alpha = current.site("alpha")
        assert alpha is not None  # noqa: S101 - narrows the optional for mypy
        self.assertEqual(alpha.identifier, "alpha")
        self.assertIsNone(current.site("absent1"))

    def test_an_inaccessible_or_unsupported_collection_is_unknown_not_removal(self) -> None:
        for outcome in (ObservationOutcome.INACCESSIBLE, ObservationOutcome.UNSUPPORTED):
            with self.subTest(outcome=outcome):
                collected = replace(COLLECTED, sites=Observation(outcome, (), "warn", ()))
                snapshot = replace(SNAPSHOT, collected=collected)
                page = site_page(state(AttemptStatus.SUCCEEDED, snapshot=snapshot), "alpha")
                self.assertEqual(page.absence, "unknown")


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


class AttemptSummaryTests(ControllerConfigTestCase):
    """A history row carries its attempt's facts, and holds a full snapshot only once."""

    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def record_older_snapshot(self, revision: int) -> DiscoveryAttempt:
        """A succeeded attempt for a past connection revision, holding a real snapshot."""
        definition = ConnectionDefinition.objects.create(
            server=self.server,
            revision=revision,
            mode="agent",
            alias="web.example.com",
            address="web.example.com",
            username="root",
            port=22,
        )
        attempt = record_attempt(self.server, AttemptStatus.SUCCEEDED)
        DiscoveryAttempt.objects.filter(pk=attempt.pk).update(connection=definition)
        attempt.refresh_from_db()
        save_snapshot(attempt, COLLECTED, COLLECTED_AT)
        return attempt

    def test_a_summary_carries_the_facts_of_the_snapshot_it_holds(self) -> None:
        attempt = record_attempt(self.server, AttemptStatus.SUCCEEDED)
        save_snapshot(attempt, COLLECTED, COLLECTED_AT)

        (summary,) = read_discovery(self.server).history
        self.assertEqual(summary.attempt, attempt)
        facts = summary.snapshot
        assert facts is not None  # noqa: S101 - the attempt holds a snapshot
        self.assertIsInstance(facts, SnapshotFacts)
        self.assertEqual(facts.collected_at, COLLECTED_AT)
        self.assertEqual(facts.os_pretty_name, "Ubuntu 26.04.1 LTS")
        self.assertEqual(facts.architecture.value, "x86_64")
        self.assertEqual(facts.cpu_count.outcome, ObservationOutcome.UNSUPPORTED)
        self.assertEqual(facts.memory_bytes.value, 4_121_137_152)
        self.assertEqual(facts.filesystem.value, COLLECTED.filesystem.value)
        self.assertEqual(
            [(component.component, component.package.outcome) for component in facts.components],
            [
                (component.component, component.package.outcome)
                for component in COLLECTED.components
            ],
        )

        (view,) = server_state(self.server).history
        self.assertEqual(view.collected_at, COLLECTED_AT)
        self.assertEqual(view.os_pretty_name, "Ubuntu 26.04.1 LTS")
        self.assertEqual(
            [(warning.label, warning.outcome) for warning in view.warnings],
            [("CPUs", ObservationOutcome.UNSUPPORTED)],
        )

    def test_a_summary_row_carries_the_attempt_fields_the_tables_show(self) -> None:
        older = self.record_older_snapshot(1)
        DiscoveryAttempt.objects.filter(pk=older.pk).update(host_key="ssh-ed25519 key")
        older.refresh_from_db()

        view = next(
            row for row in server_state(self.server).history if row.operation_id == older.pk
        )
        self.assertEqual(view.status, Status.VERIFIED)
        self.assertEqual(view.queued_at, older.queued_at)
        self.assertEqual(view.started_at, older.started_at)
        self.assertEqual(view.finished_at, older.finished_at)
        self.assertEqual(view.failure, older.failure)
        self.assertEqual(view.ssh_alias, "web.example.com")
        self.assertEqual(view.host_key, "ssh-ed25519 key")
        self.assertEqual(view.connection_revision, 1)
        self.assertEqual(view.original_target, "root@web.example.com:22")
        self.assertTrue(view.older_connection)
        self.assertEqual(view.collected_at, COLLECTED_AT)
        self.assertEqual(view.os_pretty_name, "Ubuntu 26.04.1 LTS")

    def test_a_summary_says_when_an_attempt_holds_no_snapshot(self) -> None:
        failed = record_attempt(self.server, AttemptStatus.FAILED, failure="Refused.")

        (summary,) = read_discovery(self.server).history
        self.assertEqual(summary.attempt, failed)
        self.assertIsNone(summary.snapshot)

        (view,) = server_state(self.server).history
        self.assertIsNone(view.snapshot)
        self.assertIsNone(view.collected_at)
        self.assertEqual(view.os_pretty_name, "")
        self.assertEqual(view.warnings, ())

    def test_reading_history_rebuilds_no_stored_snapshot(self) -> None:
        self.record_older_snapshot(1)
        self.record_older_snapshot(2)
        current = record_attempt(self.server, AttemptStatus.SUCCEEDED)
        save_snapshot(current, COLLECTED, COLLECTED_AT)

        with mock.patch.object(
            snapshot_module,
            "_read",
            side_effect=AssertionError("a history row rebuilt a full snapshot"),
        ):
            listed = history()
            rows = activity_rows()

        self.assertEqual(len(listed), 3)
        self.assertEqual([item.snapshot is not None for item in listed], [True, True, True])
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row.snapshot is not None for row in rows))

    def test_only_the_current_attempt_gets_its_full_snapshot(self) -> None:
        historical = self.record_older_snapshot(1)
        current = record_attempt(self.server, AttemptStatus.SUCCEEDED)
        save_snapshot(current, COLLECTED, COLLECTED_AT)

        real_read = snapshot_module._read

        def guard(row: DiscoverySnapshot, ssh_alias: str) -> Snapshot:
            if row.attempt_id != current.pk:
                raise AssertionError("rebuilt a historical attempt's snapshot")
            return real_read(row, ssh_alias)

        with mock.patch.object(snapshot_module, "_read", guard):
            discovery = read_discovery(self.server)

        self.assertEqual(discovery.attempt, current)
        self.assertIn(historical, [item.attempt for item in discovery.history])
        self.assertIsNotNone(discovery.snapshot)
        assert discovery.snapshot is not None  # noqa: S101 - the current attempt holds one
        observed = discovery.snapshot.collected
        self.assertEqual(discovery.snapshot.collected_at, COLLECTED_AT)
        self.assertEqual(
            [site.identifier for site in observed.sites.value],
            [site.identifier for site in COLLECTED.sites.value],
        )
        self.assertEqual(observed.components, COLLECTED.components)
        self.assertEqual(observed.os.value, COLLECTED.os.value)
