"""Site facts for the preparation gate, derived from one discovery snapshot."""

from dataclasses import replace
from typing import TypedDict, Unpack

from django.test import SimpleTestCase

from backups.observation import BackupResult, ObservedBackup
from discovery.fakes import COLLECTED, COLLECTED_AT
from discovery.models import ObservationOutcome, SiteState
from discovery.snapshot import (
    Observation,
    ObservedCache,
    ObservedRelease,
    ObservedSetting,
    ObservedSite,
    SiteAccount,
    Snapshot,
)
from operations.preparation import SiteFacts, SiteShape
from operations.services import ServerChanges
from servers.discovery_state import DiscoveryState
from servers.models import Server
from sites.bodies.common import PHP_TRANSITION_INCOMPLETE, SITE_GATED
from sites.bodies.pool import SitePool
from sites.preparation import site_facts

SNAPSHOT = Snapshot(collected=COLLECTED, collected_at=COLLECTED_AT, ssh_alias="web")
BASE_SITE = ObservedSite(
    "alpha",
    ("alpha.test",),
    "php85",
    SiteAccount(1001, 1001, "/var/www/alpha", "/usr/sbin/nologin"),
    SiteState.MANAGED,
    ObservationOutcome.OBSERVED,
    file="/etc/caddy/sites/alpha.caddy",
)
OBSERVED_SITES = Observation(ObservationOutcome.OBSERVED, ("caddy adapt",), "", (BASE_SITE,))
NO_SETTINGS: Observation[tuple[ObservedSetting, ...]] = Observation(
    ObservationOutcome.ABSENT, (), "", ()
)
NO_RELEASES: Observation[tuple[ObservedRelease, ...]] = Observation(
    ObservationOutcome.ABSENT, (), "", ()
)
NO_CACHE: Observation[tuple[ObservedCache, ...]] = Observation(
    ObservationOutcome.ABSENT, (), "", ()
)
NO_BACKUPS: Observation[tuple[ObservedBackup, ...]] = Observation(
    ObservationOutcome.ABSENT, (), "", ()
)


class SiteChanges(TypedDict, total=False):
    file: str
    state: SiteState
    missing: tuple[str, ...]
    application: str
    application_problem: str
    pool: SitePool | None
    log_rotation: str


def observed_site(**changes: Unpack[SiteChanges]) -> ObservedSite:
    return replace(BASE_SITE, **changes)


def snapshot(
    *,
    sites: Observation[tuple[ObservedSite, ...]] = OBSERVED_SITES,
    settings: Observation[tuple[ObservedSetting, ...]] = NO_SETTINGS,
    releases: Observation[tuple[ObservedRelease, ...]] = NO_RELEASES,
    cache: Observation[tuple[ObservedCache, ...]] = NO_CACHE,
    backups: Observation[tuple[ObservedBackup, ...]] = NO_BACKUPS,
) -> Snapshot:
    return replace(
        SNAPSHOT,
        collected=replace(
            COLLECTED,
            sites=sites,
            settings=settings,
            releases=releases,
            cache=cache,
            backups=backups,
        ),
    )


def read(world: Snapshot | None) -> DiscoveryState:
    return DiscoveryState(
        server=Server(name="Web", ssh_alias="web"),
        attempt=None,
        snapshot=world,
        history=[],
        alias_usable=True,
        changes=ServerChanges([], None),
    )


def facts(world: Snapshot | None, identifier: str = "alpha") -> SiteFacts:
    return site_facts(read(world), identifier)


class SiteFactsTests(SimpleTestCase):
    def test_a_missing_snapshot_or_unreadable_inventory_is_absent(self) -> None:
        unreadable = snapshot(
            sites=Observation(ObservationOutcome.INACCESSIBLE, (), "Not readable.", (BASE_SITE,))
        )
        for world in (None, unreadable):
            with self.subTest(world=world):
                derived = facts(world, "alpha")
                self.assertFalse(derived.present)
                self.assertIsNone(derived.shape)
                self.assertFalse(derived.convention)
                self.assertEqual(derived.missing, ())

    def test_an_absent_identifier_is_not_present(self) -> None:
        derived = facts(snapshot(), "absent1")
        self.assertFalse(derived.present)
        self.assertIsNone(derived.shape)

    def test_a_managed_site_on_the_convention_path(self) -> None:
        derived = facts(snapshot(), "alpha")
        self.assertTrue(derived.present)
        self.assertTrue(derived.convention)
        self.assertIs(derived.shape, SiteShape.MANAGED)
        self.assertEqual(derived.missing, ())
        self.assertFalse(derived.gated)
        self.assertFalse(derived.paused)
        self.assertFalse(derived.has_pool)
        self.assertFalse(derived.wordpress)
        self.assertFalse(derived.laravel)
        self.assertEqual(derived.application_problem, "")
        self.assertFalse(derived.releases_observed)
        self.assertFalse(derived.has_releases)
        self.assertFalse(derived.current_release)
        self.assertFalse(derived.retained_release)
        self.assertFalse(derived.has_cache)
        self.assertEqual(derived.log_rotation, "")

    def test_a_non_convention_path_and_each_shape(self) -> None:
        elsewhere = snapshot(
            sites=Observation(
                ObservationOutcome.OBSERVED,
                (),
                "",
                (observed_site(file="/etc/caddy/other/alpha.caddy"),),
            )
        )
        self.assertFalse(facts(elsewhere, "alpha").convention)
        for state, shape in (
            (SiteState.MANAGED, SiteShape.MANAGED),
            (SiteState.PARTLY_APPLIED, SiteShape.PARTLY_APPLIED),
            (SiteState.NOT_FOLLOWING, SiteShape.NOT_FOLLOWING),
        ):
            with self.subTest(state=state):
                world = snapshot(
                    sites=Observation(
                        ObservationOutcome.OBSERVED, (), "", (observed_site(state=state),)
                    )
                )
                self.assertIs(facts(world, "alpha").shape, shape)

    def test_a_partly_applied_site_carries_its_missing_problem(self) -> None:
        world = snapshot(
            sites=Observation(
                ObservationOutcome.OBSERVED,
                (),
                "",
                (
                    observed_site(
                        state=SiteState.PARTLY_APPLIED,
                        missing=(PHP_TRANSITION_INCOMPLETE,),
                    ),
                ),
            )
        )
        derived = facts(world, "alpha")
        self.assertEqual(derived.missing, (PHP_TRANSITION_INCOMPLETE,))
        self.assertFalse(derived.gated)

    def test_wordpress_identity_and_its_application_problem(self) -> None:
        world = snapshot(
            sites=Observation(
                ObservationOutcome.OBSERVED,
                (),
                "",
                (
                    observed_site(
                        application="wordpress",
                        application_problem="The install is incomplete.",
                    ),
                ),
            )
        )
        derived = facts(world, "alpha")
        self.assertTrue(derived.wordpress)
        self.assertEqual(derived.application_problem, "The install is incomplete.")

    def test_a_wordpress_partial_site_is_not_treated_as_complete_wordpress(self) -> None:
        world = snapshot(
            sites=Observation(
                ObservationOutcome.OBSERVED,
                (),
                "",
                (observed_site(application="wordpress_partial"),),
            )
        )
        self.assertFalse(facts(world, "alpha").wordpress)

    def test_the_pool_is_a_fact_only_when_observed(self) -> None:
        world = snapshot(
            sites=Observation(
                ObservationOutcome.OBSERVED, (), "", (observed_site(pool=SitePool()),)
            )
        )
        self.assertTrue(facts(world, "alpha").has_pool)

    def test_laravel_identity_comes_from_a_settings_row(self) -> None:
        world = snapshot(
            settings=Observation(
                ObservationOutcome.OBSERVED,
                (),
                "",
                (ObservedSetting("alpha", "laravel", "APP_KEY", "a" * 64),),
            )
        )
        self.assertTrue(facts(world, "alpha").laravel)

    def test_laravel_identity_comes_from_a_release_row(self) -> None:
        release = ObservedRelease("alpha", "release", "commit", 1, SiteState.MANAGED, True)
        world = snapshot(releases=Observation(ObservationOutcome.OBSERVED, (), "", (release,)))
        self.assertTrue(facts(world, "alpha").laravel)

    def test_laravel_identity_is_not_read_from_the_site_application(self) -> None:
        world = snapshot(
            sites=Observation(
                ObservationOutcome.OBSERVED, (), "", (observed_site(application="laravel"),)
            )
        )
        derived = facts(world, "alpha")
        self.assertFalse(derived.laravel)
        self.assertFalse(derived.wordpress)

    def test_release_rows_and_their_read_outcome(self) -> None:
        current = ObservedRelease("alpha", "release", "commit", 2, SiteState.MANAGED, True)
        retained = ObservedRelease("alpha", "old", "old", 1, SiteState.MANAGED, False)
        world = snapshot(
            releases=Observation(ObservationOutcome.OBSERVED, (), "", (current, retained))
        )
        derived = facts(world, "alpha")
        self.assertTrue(derived.releases_observed)
        self.assertTrue(derived.has_releases)
        self.assertTrue(derived.current_release)
        self.assertTrue(derived.retained_release)

    def test_an_unreadable_release_inventory_keeps_the_rows_it_returned(self) -> None:
        release = ObservedRelease("alpha", "release", "commit", 1, SiteState.MANAGED, True)
        world = snapshot(
            releases=Observation(ObservationOutcome.INACCESSIBLE, (), "Not readable.", (release,))
        )
        derived = facts(world, "alpha")
        self.assertFalse(derived.releases_observed)
        self.assertTrue(derived.has_releases)
        self.assertTrue(derived.current_release)

    def test_a_non_managed_release_is_not_a_rollback_target(self) -> None:
        release = ObservedRelease("alpha", "old", "old", 1, SiteState.NOT_FOLLOWING, False)
        world = snapshot(releases=Observation(ObservationOutcome.OBSERVED, (), "", (release,)))
        self.assertFalse(facts(world, "alpha").retained_release)

    def test_a_cache_row_is_a_fact(self) -> None:
        world = snapshot(
            cache=Observation(ObservationOutcome.OBSERVED, (), "", (ObservedCache("alpha", "on"),))
        )
        self.assertTrue(facts(world, "alpha").has_cache)

    def test_the_gate_and_paused_facts_come_from_the_missing_problem_and_backup(self) -> None:
        gated = observed_site(state=SiteState.PARTLY_APPLIED, missing=(SITE_GATED,))
        paused = BackupResult(
            result_class="partial",
            reason="backup_paused",
            scope="full",
            origin="",
            at="",
            point="",
            snapshots=0,
            size=0,
        )
        world = snapshot(
            sites=Observation(ObservationOutcome.OBSERVED, (), "", (gated,)),
            backups=Observation(
                ObservationOutcome.OBSERVED,
                (),
                "",
                (ObservedBackup("alpha", last=paused),),
            ),
        )
        derived = facts(world, "alpha")
        self.assertTrue(derived.gated)
        self.assertTrue(derived.paused)

    def test_a_gated_site_with_a_finished_backup_is_not_paused(self) -> None:
        gated = observed_site(state=SiteState.PARTLY_APPLIED, missing=(SITE_GATED,))
        finished = BackupResult(
            result_class="succeeded",
            reason="backup_complete",
            scope="full",
            origin="",
            at="",
            point="",
            snapshots=1,
            size=1,
        )
        world = snapshot(
            sites=Observation(ObservationOutcome.OBSERVED, (), "", (gated,)),
            backups=Observation(
                ObservationOutcome.OBSERVED,
                (),
                "",
                (ObservedBackup("alpha", last=finished),),
            ),
        )
        derived = facts(world, "alpha")
        self.assertTrue(derived.gated)
        self.assertFalse(derived.paused)

    def test_a_restore_interruption_counts_as_paused(self) -> None:
        gated = observed_site(state=SiteState.PARTLY_APPLIED, missing=(SITE_GATED,))
        restored = BackupResult(
            result_class="partial",
            reason="restore_paused",
            scope="database",
            origin="",
            at="",
            point="",
            snapshots=0,
            size=0,
        )
        world = snapshot(
            sites=Observation(ObservationOutcome.OBSERVED, (), "", (gated,)),
            backups=Observation(
                ObservationOutcome.OBSERVED,
                (),
                "",
                (ObservedBackup("alpha", last=restored),),
            ),
        )
        self.assertTrue(facts(world, "alpha").paused)

    def test_log_rotation_state_is_carried(self) -> None:
        world = snapshot(
            sites=Observation(
                ObservationOutcome.OBSERVED,
                (),
                "",
                (observed_site(log_rotation="supported"),),
            )
        )
        self.assertEqual(facts(world, "alpha").log_rotation, "supported")
