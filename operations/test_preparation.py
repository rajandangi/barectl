"""The preparation gate decides from typed facts alone (spec #507, ticket #509).

Every reason is produced from a literal fact record, and its sentence is asserted against
the wording the design fixes so a card, a template and a POST cannot drift apart.
"""

from dataclasses import replace
from typing import TypedDict, Unpack

from django.test import SimpleTestCase

from sites.bodies.common import PHP_TRANSITION_INCOMPLETE

from .preparation import (
    EMPTY,
    REASONS,
    SERVER,
    SITE,
    Decision,
    Freshness,
    Need,
    Reason,
    ReasonName,
    Requirements,
    ServerFacts,
    SiteFacts,
    SiteShape,
    decide,
)

MANAGED = "Target stack"
NOT_MANAGEABLE = "Not manageable"

SENTENCES: dict[ReasonName, str] = {
    ReasonName.HOST_NOT_MANAGEABLE: (
        "Barectl cannot manage this server, so it cannot prepare this change."
    ),
    ReasonName.CHECK_RUNNING: (
        "A connection check is running; wait for it to finish before preparing a change."
    ),
    ReasonName.CHECK_FAILED: (
        "The latest connection check failed; run it again before preparing a change."
    ),
    ReasonName.HOST_NOT_OBSERVED: (
        "Barectl has not read this server yet; check the connection first."
    ),
    ReasonName.HOST_NOT_READY: "Set up this server before preparing this change.",
    ReasonName.CHANGE_IN_PROGRESS: (
        "Another change is running for this server; wait for it to finish before preparing a "
        "change."
    ),
    ReasonName.MISSING_CHANGE_PERMISSION: (
        "Your account does not have permission to prepare changes."
    ),
    ReasonName.MISSING_SITE_PERMISSION: (
        "Your account does not have permission to change this site."
    ),
    ReasonName.MISSING_SECRET_PERMISSION: ("Changing this needs the manage-secrets permission."),
    ReasonName.MISSING_SHARED_PERMISSION: "Changing this needs the shared-change permission.",
    ReasonName.MISSING_DESTRUCTIVE_PERMISSION: (
        "Changing this needs the destructive-change permission."
    ),
    ReasonName.SITE_NOT_OBSERVED: (
        "Barectl has not observed this site; run a connection check before preparing a change."
    ),
    ReasonName.SITE_NOT_CONVENTIONAL: (
        "This site does not follow the supported convention, so Barectl cannot change it."
    ),
    ReasonName.SITE_NOT_FOLLOWING: (
        "This site does not follow the supported convention; Barectl can only remove it."
    ),
    ReasonName.SITE_PARTLY_APPLIED: (
        "This site is partly applied; finish the change that is already in progress first."
    ),
    ReasonName.SITE_NOT_MANAGED: "This change needs a managed site.",
    ReasonName.SITE_GATED: (
        "This site's maintenance gate is in place; reopen it before changing it."
    ),
    ReasonName.SITE_PAUSED: "This site's backups are paused; reopen it before changing it.",
    ReasonName.SITE_NOT_GATED: "This site is not gated, so there is nothing to reopen.",
    ReasonName.SITE_NOT_PAUSED: "This site is not paused, so there is nothing to reopen.",
    ReasonName.APPLICATION_NOT_WORDPRESS: "This change needs a WordPress site.",
    ReasonName.APPLICATION_NOT_LARAVEL: "This change needs a Laravel site.",
    ReasonName.APPLICATION_PROBLEM: (
        "This site's application has a problem Barectl could not resolve."
    ),
    ReasonName.POOL_NOT_OBSERVED: "Barectl has not observed this site's PHP settings.",
    ReasonName.RELEASES_NOT_OBSERVED: "Barectl could not read this site's releases.",
    ReasonName.RELEASES_PRESENT: (
        "This site already has releases; change its readiness only after they are removed."
    ),
    ReasonName.CURRENT_RELEASE_MISSING: "This site has no current release to change.",
    ReasonName.RETAINED_RELEASE_MISSING: ("This site has no retained release to roll back to."),
    ReasonName.CACHE_NOT_OBSERVED: "Barectl has not observed this site's object cache.",
    ReasonName.LOG_ROTATION_SUPPORTED: "Log rotation is already set up for this site.",
}

ALL_NEEDS = frozenset(Need)
CURRENT_SERVER = ServerFacts(
    standing=MANAGED,
    freshness=Freshness.CURRENT,
    change_active=False,
    granted=ALL_NEEDS,
)
MANAGED_SITE = SiteFacts(
    present=True,
    convention=True,
    shape=SiteShape.MANAGED,
    missing=(),
    gated=False,
    paused=False,
    has_pool=True,
    wordpress=False,
    laravel=False,
    application_problem="",
    releases_observed=True,
    has_releases=False,
    current_release=False,
    retained_release=False,
    has_cache=False,
    log_rotation="",
)


class ServerChanges(TypedDict, total=False):
    standing: str | None
    freshness: Freshness
    change_active: bool
    granted: frozenset[Need]


class SiteChanges(TypedDict, total=False):
    present: bool
    convention: bool
    shape: SiteShape | None
    missing: tuple[str, ...]
    gated: bool
    paused: bool
    has_pool: bool
    wordpress: bool
    laravel: bool
    application_problem: str
    releases_observed: bool
    has_releases: bool
    current_release: bool
    retained_release: bool
    has_cache: bool
    log_rotation: str


def server(**changes: Unpack[ServerChanges]) -> ServerFacts:
    return replace(CURRENT_SERVER, **changes)


def site(**changes: Unpack[SiteChanges]) -> SiteFacts:
    return replace(MANAGED_SITE, **changes)


def with_needs(*needs: Need) -> Requirements:
    return replace(SITE, needs=frozenset(needs))


class ReasonTableTests(SimpleTestCase):
    """One literal fact record per reason, asserted with the sentence an operator reads."""

    CASES: tuple[tuple[ReasonName, ServerFacts, SiteFacts | None, Requirements], ...] = (
        (
            ReasonName.HOST_NOT_MANAGEABLE,
            server(standing=NOT_MANAGEABLE),
            MANAGED_SITE,
            SERVER,
        ),
        (
            ReasonName.CHECK_RUNNING,
            server(freshness=Freshness.CHECKING),
            MANAGED_SITE,
            SERVER,
        ),
        (
            ReasonName.CHECK_FAILED,
            server(freshness=Freshness.FAILED),
            MANAGED_SITE,
            SERVER,
        ),
        (
            ReasonName.HOST_NOT_OBSERVED,
            server(standing=None, freshness=Freshness.UNOBSERVED),
            MANAGED_SITE,
            replace(SERVER, target_stack=True),
        ),
        (
            ReasonName.HOST_NOT_READY,
            server(standing="Fresh"),
            MANAGED_SITE,
            replace(SERVER, target_stack=True),
        ),
        (
            ReasonName.CHANGE_IN_PROGRESS,
            server(change_active=True),
            MANAGED_SITE,
            SERVER,
        ),
        (
            ReasonName.MISSING_CHANGE_PERMISSION,
            server(granted=frozenset({Need.SITE})),
            MANAGED_SITE,
            with_needs(Need.CHANGE, Need.SITE),
        ),
        (
            ReasonName.MISSING_SITE_PERMISSION,
            server(granted=frozenset({Need.CHANGE})),
            MANAGED_SITE,
            with_needs(Need.CHANGE, Need.SITE),
        ),
        (
            ReasonName.MISSING_SECRET_PERMISSION,
            server(granted=frozenset({Need.CHANGE, Need.SITE, Need.SHARED})),
            MANAGED_SITE,
            with_needs(Need.SECRET),
        ),
        (
            ReasonName.MISSING_SHARED_PERMISSION,
            server(granted=frozenset({Need.CHANGE, Need.SITE})),
            MANAGED_SITE,
            with_needs(Need.SHARED),
        ),
        (
            ReasonName.MISSING_DESTRUCTIVE_PERMISSION,
            server(granted=frozenset({Need.CHANGE, Need.SITE})),
            MANAGED_SITE,
            with_needs(Need.DESTRUCTIVE),
        ),
        (ReasonName.SITE_NOT_OBSERVED, CURRENT_SERVER, None, SITE),
        (
            ReasonName.SITE_NOT_CONVENTIONAL,
            CURRENT_SERVER,
            site(convention=False),
            SITE,
        ),
        (
            ReasonName.SITE_NOT_FOLLOWING,
            CURRENT_SERVER,
            site(shape=SiteShape.NOT_FOLLOWING),
            SITE,
        ),
        (
            ReasonName.SITE_PARTLY_APPLIED,
            CURRENT_SERVER,
            site(shape=SiteShape.PARTLY_APPLIED),
            replace(SITE, state=None),
        ),
        (
            ReasonName.SITE_NOT_MANAGED,
            CURRENT_SERVER,
            site(shape=SiteShape.PARTLY_APPLIED),
            replace(SITE, state=SiteShape.MANAGED, allow_partly_applied=True),
        ),
        (
            ReasonName.SITE_GATED,
            CURRENT_SERVER,
            site(shape=SiteShape.PARTLY_APPLIED, gated=True),
            replace(SITE, state=None, allow_partly_applied=True, open_site=True),
        ),
        (
            ReasonName.SITE_PAUSED,
            CURRENT_SERVER,
            site(shape=SiteShape.PARTLY_APPLIED, gated=True, paused=True),
            replace(SITE, state=None, allow_partly_applied=True, open_site=True),
        ),
        (
            ReasonName.SITE_NOT_GATED,
            CURRENT_SERVER,
            MANAGED_SITE,
            replace(SITE, gated=True),
        ),
        (
            ReasonName.SITE_NOT_PAUSED,
            CURRENT_SERVER,
            MANAGED_SITE,
            replace(SITE, paused=True),
        ),
        (
            ReasonName.APPLICATION_NOT_WORDPRESS,
            CURRENT_SERVER,
            MANAGED_SITE,
            replace(SITE, application="wordpress", no_application_problem=True),
        ),
        (
            ReasonName.APPLICATION_NOT_LARAVEL,
            CURRENT_SERVER,
            MANAGED_SITE,
            replace(SITE, application="laravel", no_application_problem=True),
        ),
        (
            ReasonName.APPLICATION_PROBLEM,
            CURRENT_SERVER,
            site(wordpress=True, application_problem="The install is incomplete."),
            replace(SITE, application="wordpress", no_application_problem=True),
        ),
        (
            ReasonName.POOL_NOT_OBSERVED,
            CURRENT_SERVER,
            site(has_pool=False),
            replace(SITE, pool=True),
        ),
        (
            ReasonName.RELEASES_NOT_OBSERVED,
            CURRENT_SERVER,
            site(releases_observed=False),
            replace(SITE, releases_observed=True),
        ),
        (
            ReasonName.RELEASES_PRESENT,
            CURRENT_SERVER,
            site(has_releases=True),
            replace(SITE, no_releases=True),
        ),
        (
            ReasonName.CURRENT_RELEASE_MISSING,
            CURRENT_SERVER,
            site(current_release=False),
            replace(SITE, current_release=True),
        ),
        (
            ReasonName.RETAINED_RELEASE_MISSING,
            CURRENT_SERVER,
            site(retained_release=False),
            replace(SITE, retained_release=True),
        ),
        (
            ReasonName.CACHE_NOT_OBSERVED,
            CURRENT_SERVER,
            site(has_cache=False),
            replace(SITE, cache=True),
        ),
        (
            ReasonName.LOG_ROTATION_SUPPORTED,
            CURRENT_SERVER,
            site(log_rotation="supported"),
            replace(SITE, rotation_unsupported=True),
        ),
    )

    def test_every_reason_comes_from_a_literal_fact_record(self) -> None:
        self.assertEqual({case[0] for case in self.CASES}, set(ReasonName))
        for name, facts, observed, requirements in self.CASES:
            with self.subTest(reason=name):
                decision = decide(facts, observed, requirements)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, Reason(name, SENTENCES[name]))
                self.assertEqual(
                    decision.reason.sentence if decision.reason else None, SENTENCES[name]
                )

    def test_the_reason_table_is_the_whole_vocabulary_and_the_fixed_wording(self) -> None:
        self.assertEqual(set(REASONS), set(ReasonName))
        self.assertEqual(set(SENTENCES), set(ReasonName))
        for name, sentence in SENTENCES.items():
            with self.subTest(reason=name):
                self.assertEqual(REASONS[name], sentence)


class AllowanceTests(SimpleTestCase):
    def test_a_current_managed_server_and_site_are_allowed(self) -> None:
        self.assertEqual(decide(CURRENT_SERVER, MANAGED_SITE, SERVER), Decision(True))
        self.assertEqual(decide(CURRENT_SERVER, MANAGED_SITE, SITE), Decision(True))
        self.assertEqual(decide(CURRENT_SERVER, MANAGED_SITE, EMPTY), Decision(True))

    def test_no_site_is_needed_when_the_requirement_does_not_name_one(self) -> None:
        self.assertEqual(decide(CURRENT_SERVER, None, SERVER), Decision(True))
        self.assertEqual(decide(CURRENT_SERVER, None, EMPTY), Decision(True))
        self.assertFalse(decide(CURRENT_SERVER, None, SITE).allowed)

    def test_an_unobserved_host_still_offers_setup(self) -> None:
        fresh = server(standing=None, freshness=Freshness.UNOBSERVED)
        self.assertEqual(decide(fresh, None, SERVER), Decision(True))

    def test_a_card_that_assumes_the_target_stack_withholds_until_it_is_read(self) -> None:
        target = replace(SERVER, target_stack=True)
        unobserved = server(standing=None, freshness=Freshness.UNOBSERVED)
        self.assertFalse(decide(unobserved, None, target).allowed)
        fresh = server(standing="Fresh", freshness=Freshness.CURRENT)
        decision = decide(fresh, None, target)
        self.assertFalse(decision.allowed)
        self.assertIs(decision.reason and decision.reason.name, ReasonName.HOST_NOT_READY)

    def test_a_partly_applied_site_completes_only_the_named_change(self) -> None:
        partly = site(shape=SiteShape.PARTLY_APPLIED, missing=(PHP_TRANSITION_INCOMPLETE,))
        completing = replace(SITE, state=None, completes=PHP_TRANSITION_INCOMPLETE)
        self.assertEqual(decide(CURRENT_SERVER, partly, completing), Decision(True))
        self.assertFalse(
            decide(CURRENT_SERVER, partly, replace(SITE, state=None, completes="Another.")).allowed
        )

    def test_a_partly_applied_site_can_be_allowed_generally(self) -> None:
        partly = site(shape=SiteShape.PARTLY_APPLIED, missing=("Another.",))
        requirements = replace(SITE, state=None, allow_partly_applied=True)
        self.assertEqual(decide(CURRENT_SERVER, partly, requirements), Decision(True))

    def test_removal_accepts_a_not_following_site(self) -> None:
        removal = Requirements(
            site=True,
            convention=False,
            allow_not_following=True,
            needs=frozenset({Need.CHANGE, Need.SITE}),
        )
        not_following = site(convention=False, shape=SiteShape.NOT_FOLLOWING)
        self.assertEqual(decide(CURRENT_SERVER, not_following, removal), Decision(True))


class PrecedenceTests(SimpleTestCase):
    """One fact record satisfies several refusals at once; the earliest one is reported."""

    WORST_SERVER = ServerFacts(
        standing=NOT_MANAGEABLE,
        freshness=Freshness.CHECKING,
        change_active=True,
        granted=frozenset({Need.SITE}),
    )
    WORST_SITE = SiteFacts(
        present=True,
        convention=False,
        shape=SiteShape.NOT_FOLLOWING,
        missing=(),
        gated=True,
        paused=True,
        has_pool=False,
        wordpress=False,
        laravel=False,
        application_problem="The install is incomplete.",
        releases_observed=False,
        has_releases=True,
        current_release=False,
        retained_release=False,
        has_cache=False,
        log_rotation="supported",
    )
    WORST_REQUIREMENTS = Requirements(
        needs=frozenset({Need.CHANGE, Need.SITE, Need.SECRET, Need.SHARED, Need.DESTRUCTIVE}),
        target_stack=True,
        site=True,
        convention=True,
        state=SiteShape.MANAGED,
        open_site=True,
        application="wordpress",
        no_application_problem=True,
        pool=True,
        releases_observed=True,
        no_releases=True,
        current_release=True,
        retained_release=True,
        cache=True,
        rotation_unsupported=True,
    )

    def assert_reason(
        self,
        expected: ReasonName,
        facts: ServerFacts,
        observed: SiteFacts | None,
        requirements: Requirements,
    ) -> None:
        decision = decide(facts, observed, requirements)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason and decision.reason.name, expected)

    def test_host_standing_outranks_every_other_refusal(self) -> None:
        self.assert_reason(
            ReasonName.HOST_NOT_MANAGEABLE,
            self.WORST_SERVER,
            self.WORST_SITE,
            self.WORST_REQUIREMENTS,
        )

    def test_freshness_outranks_an_active_change_permission_and_site_shape(self) -> None:
        checking = replace(self.WORST_SERVER, standing=MANAGED, freshness=Freshness.CHECKING)
        self.assert_reason(
            ReasonName.CHECK_RUNNING, checking, self.WORST_SITE, self.WORST_REQUIREMENTS
        )
        failed = replace(self.WORST_SERVER, standing=MANAGED, freshness=Freshness.FAILED)
        self.assert_reason(
            ReasonName.CHECK_FAILED, failed, self.WORST_SITE, self.WORST_REQUIREMENTS
        )

    def test_target_stack_follows_freshness_and_precedes_an_active_change(self) -> None:
        unobserved = replace(
            self.WORST_SERVER,
            standing=None,
            freshness=Freshness.UNOBSERVED,
            change_active=True,
        )
        self.assert_reason(
            ReasonName.HOST_NOT_OBSERVED, unobserved, self.WORST_SITE, self.WORST_REQUIREMENTS
        )
        fresh = replace(
            self.WORST_SERVER,
            standing="Fresh",
            freshness=Freshness.CURRENT,
            change_active=True,
        )
        self.assert_reason(
            ReasonName.HOST_NOT_READY, fresh, self.WORST_SITE, self.WORST_REQUIREMENTS
        )
        checking = replace(fresh, freshness=Freshness.CHECKING)
        self.assert_reason(
            ReasonName.CHECK_RUNNING, checking, self.WORST_SITE, self.WORST_REQUIREMENTS
        )

    def test_an_active_change_outranks_permission_and_site_shape(self) -> None:
        active = replace(
            self.WORST_SERVER,
            standing=MANAGED,
            freshness=Freshness.CURRENT,
            change_active=True,
        )
        self.assert_reason(
            ReasonName.CHANGE_IN_PROGRESS, active, self.WORST_SITE, self.WORST_REQUIREMENTS
        )

    def test_permission_outranks_site_shape(self) -> None:
        unpermitted = replace(
            self.WORST_SERVER,
            standing=MANAGED,
            freshness=Freshness.CURRENT,
            change_active=False,
            granted=frozenset(),
        )
        self.assert_reason(
            ReasonName.MISSING_CHANGE_PERMISSION,
            unpermitted,
            self.WORST_SITE,
            self.WORST_REQUIREMENTS,
        )

    def test_permission_reasons_follow_the_need_order(self) -> None:
        site_only = replace(
            self.WORST_SERVER,
            standing=MANAGED,
            freshness=Freshness.CURRENT,
            change_active=False,
            granted=frozenset({Need.SITE}),
        )
        self.assert_reason(
            ReasonName.MISSING_CHANGE_PERMISSION,
            site_only,
            self.WORST_SITE,
            self.WORST_REQUIREMENTS,
        )
        change_only = replace(site_only, granted=frozenset({Need.CHANGE}))
        self.assert_reason(
            ReasonName.MISSING_SITE_PERMISSION,
            change_only,
            self.WORST_SITE,
            self.WORST_REQUIREMENTS,
        )
        change_and_site = replace(site_only, granted=frozenset({Need.CHANGE, Need.SITE}))
        self.assert_reason(
            ReasonName.MISSING_SECRET_PERMISSION,
            change_and_site,
            self.WORST_SITE,
            self.WORST_REQUIREMENTS,
        )
        change_site_secret = replace(
            site_only, granted=frozenset({Need.CHANGE, Need.SITE, Need.SECRET})
        )
        self.assert_reason(
            ReasonName.MISSING_SHARED_PERMISSION,
            change_site_secret,
            self.WORST_SITE,
            self.WORST_REQUIREMENTS,
        )
        four = replace(
            site_only,
            granted=frozenset({Need.CHANGE, Need.SITE, Need.SECRET, Need.SHARED}),
        )
        self.assert_reason(
            ReasonName.MISSING_DESTRUCTIVE_PERMISSION,
            four,
            self.WORST_SITE,
            self.WORST_REQUIREMENTS,
        )

    def test_site_shape_outranks_the_cards_own_requirement(self) -> None:
        permitted = replace(
            self.WORST_SERVER,
            standing=MANAGED,
            freshness=Freshness.CURRENT,
            change_active=False,
            granted=ALL_NEEDS,
        )
        self.assert_reason(
            ReasonName.SITE_NOT_OBSERVED,
            permitted,
            None,
            self.WORST_REQUIREMENTS,
        )
        self.assert_reason(
            ReasonName.SITE_NOT_CONVENTIONAL,
            permitted,
            replace(self.WORST_SITE, shape=SiteShape.MANAGED),
            self.WORST_REQUIREMENTS,
        )
        self.assert_reason(
            ReasonName.SITE_NOT_FOLLOWING,
            permitted,
            replace(self.WORST_SITE, convention=True),
            self.WORST_REQUIREMENTS,
        )
        partly = replace(self.WORST_SITE, convention=True, shape=SiteShape.PARTLY_APPLIED)
        self.assert_reason(
            ReasonName.SITE_PARTLY_APPLIED,
            permitted,
            partly,
            replace(self.WORST_REQUIREMENTS, allow_not_following=True),
        )
