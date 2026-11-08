"""Server facts for the preparation gate, and the old predicate's unchanged behavior."""

from dataclasses import replace
from typing import ClassVar, override

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, COLLECTED_AT
from discovery.snapshot import Snapshot
from operations.activity_testing import record_change
from operations.models import RemoteOperation
from operations.preparation import EMPTY, SERVER, Freshness, Need, ReasonName, decide
from operations.services import ServerChanges, read_changes

from .discovery_state import AttemptView, DiscoveryState, Status
from .models import Server
from .preparation import decide_for_server, granted_needs, server_facts, stored_server_facts

AttemptStatus = RemoteOperation.Status
WORDING = {
    AttemptStatus.QUEUED: Status.QUEUED,
    AttemptStatus.RUNNING: Status.RUNNING,
    AttemptStatus.FAILED: Status.FAILED,
    AttemptStatus.SUCCEEDED: Status.VERIFIED,
}
SNAPSHOT = Snapshot(collected=COLLECTED, collected_at=COLLECTED_AT, ssh_alias="web")


def judged(standing: Standing | None) -> Snapshot:
    return replace(
        SNAPSHOT,
        collected=replace(
            COLLECTED,
            standing=HostJudgment(standing, (), (), ()) if standing is not None else None,
        ),
    )


def state(
    attempt_status: AttemptStatus | None,
    *,
    snapshot: Snapshot | None = SNAPSHOT,
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
        alias_usable=True,
        changes=ServerChanges([], None),
    )


class StoredServerFactsTests(SimpleTestCase):
    """The legacy predicate's standing and freshness, without a permission or active change."""

    def test_no_snapshot_or_no_standing_is_unobserved_and_allows_setup(self) -> None:
        for current in (
            state(None, snapshot=None),
            state(AttemptStatus.FAILED, snapshot=None),
            state(AttemptStatus.SUCCEEDED, snapshot=judged(None)),
        ):
            with self.subTest(attempt=current.attempt and current.attempt.status):
                facts = stored_server_facts(current)
                self.assertIs(facts.freshness, Freshness.UNOBSERVED)
                self.assertIsNone(facts.standing)
                self.assertFalse(facts.change_active)
                self.assertEqual(facts.granted, frozenset())
                self.assertTrue(decide(facts, None, EMPTY).allowed)

    def test_a_later_check_withholds_changes_while_a_snapshot_exists(self) -> None:
        for attempt_status, freshness in (
            (AttemptStatus.QUEUED, Freshness.CHECKING),
            (AttemptStatus.RUNNING, Freshness.CHECKING),
            (AttemptStatus.FAILED, Freshness.FAILED),
            (AttemptStatus.SUCCEEDED, Freshness.CURRENT),
        ):
            with self.subTest(attempt=attempt_status):
                current = state(attempt_status, snapshot=judged(Standing.TARGET_STACK))
                facts = stored_server_facts(current)
                self.assertIs(facts.freshness, freshness)
                self.assertEqual(facts.standing, Standing.TARGET_STACK.value)
                self.assertIs(
                    decide(facts, None, EMPTY).allowed,
                    attempt_status is AttemptStatus.SUCCEEDED,
                )

    def test_not_manageable_refuses_even_when_fresh(self) -> None:
        current = state(AttemptStatus.SUCCEEDED, snapshot=judged(Standing.NOT_MANAGEABLE))
        facts = stored_server_facts(current)
        self.assertEqual(facts.standing, Standing.NOT_MANAGEABLE.value)
        decision = decide(facts, None, EMPTY)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason and decision.reason.name, ReasonName.HOST_NOT_MANAGEABLE)

    def test_a_fresh_or_incomplete_host_still_offers_setup(self) -> None:
        for standing in (Standing.FRESH, Standing.INCOMPLETE_FOUNDATION):
            with self.subTest(standing=standing):
                current = state(AttemptStatus.SUCCEEDED, snapshot=judged(standing))
                facts = stored_server_facts(current)
                self.assertIs(facts.freshness, Freshness.CURRENT)
                self.assertTrue(decide(facts, None, EMPTY).allowed)


class GrantedNeedsTests(TestCase):
    user: ClassVar[User]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.user = get_user_model().objects.create_user("operator")

    def grant(self, *codenames: str) -> None:
        for codename in codenames:
            self.user.user_permissions.add(Permission.objects.get(codename=codename))

    def fresh_user(self) -> User:
        # Django caches a user's permissions on the instance; read a fresh one.
        return get_user_model().objects.get(pk=self.user.pk)

    def test_no_permissions_grants_nothing(self) -> None:
        self.assertEqual(granted_needs(self.user), frozenset())

    def test_each_permission_grants_its_need(self) -> None:
        self.grant("view_server", "view_changes", "change_site")
        self.assertEqual(granted_needs(self.fresh_user()), frozenset({Need.CHANGE}))
        self.grant("view_siteobservation")
        self.assertEqual(granted_needs(self.fresh_user()), frozenset({Need.CHANGE, Need.SITE}))
        self.grant("manage_secrets")
        self.assertEqual(
            granted_needs(self.fresh_user()),
            frozenset({Need.CHANGE, Need.SITE, Need.SECRET}),
        )
        self.grant("change_shared")
        self.assertEqual(
            granted_needs(self.fresh_user()),
            frozenset({Need.CHANGE, Need.SITE, Need.SECRET, Need.SHARED}),
        )
        self.grant("change_destructive")
        self.assertEqual(granted_needs(self.fresh_user()), frozenset(Need))

    def test_a_superuser_holds_every_need(self) -> None:
        root = get_user_model().objects.create_superuser("root", password=None)
        self.assertEqual(granted_needs(root), frozenset(Need))


class ServerFactsTests(TestCase):
    user: ClassVar[User]
    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.user = get_user_model().objects.create_user("operator")
        cls.server = Server.objects.create(name="Web", ssh_alias="web")
        for codename in (
            "view_server",
            "view_changes",
            "change_site",
            "view_siteobservation",
        ):
            cls.user.user_permissions.add(Permission.objects.get(codename=codename))

    def current(self) -> DiscoveryState:
        return DiscoveryState(
            server=self.server,
            attempt=None,
            snapshot=judged(Standing.TARGET_STACK),
            history=[],
            alias_usable=True,
            changes=read_changes(self.server),
        )

    def fresh_user(self) -> User:
        # Django caches a user's permissions on the instance; read a fresh one.
        return get_user_model().objects.get(pk=self.user.pk)

    def test_no_active_change_and_the_granted_needs(self) -> None:
        facts = server_facts(self.current(), self.user)
        self.assertFalse(facts.change_active)
        self.assertEqual(facts.granted, frozenset({Need.CHANGE, Need.SITE}))
        self.assertTrue(decide_for_server(self.current(), self.user, SERVER).allowed)

    def test_an_active_change_is_fact(self) -> None:
        record_change(self.server, status=RemoteOperation.Status.RUNNING)
        facts = server_facts(self.current(), self.user)
        self.assertTrue(facts.change_active)
        decision = decide_for_server(self.current(), self.user, SERVER)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason and decision.reason.name, ReasonName.CHANGE_IN_PROGRESS)

    def test_an_absent_need_is_reported_before_a_site(self) -> None:
        decision = decide_for_server(self.current(), self.user, SERVER)
        self.assertTrue(decision.allowed)
        self.user.user_permissions.clear()
        decision = decide_for_server(self.current(), self.fresh_user(), SERVER)
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason and decision.reason.name,
            ReasonName.MISSING_CHANGE_PERMISSION,
        )
