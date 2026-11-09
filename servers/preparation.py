"""Server facts for the preparation gate, derived from a stored discovery state (spec #507).

The gate itself is Django-free; this module is the one place a ``DiscoveryState`` and a
signed-in account become its typed facts.
"""

from dataclasses import replace
from typing import TYPE_CHECKING

from django.contrib.auth.models import AnonymousUser, User

from discovery.presentation import VIEW_SITES
from operations import preparation
from operations.consent import PREPARE_PERMISSIONS
from operations.models import CHANGE_DESTRUCTIVE, CHANGE_SHARED, MANAGE_SECRETS

if TYPE_CHECKING:
    from .discovery_state import DiscoveryState

type Account = User | AnonymousUser


def _freshness(state: DiscoveryState) -> preparation.Freshness:
    if state.snapshot is None or state.snapshot.collected.standing is None:
        return preparation.Freshness.UNOBSERVED
    if state.checking:
        return preparation.Freshness.CHECKING
    if state.snapshot_notice is not None:
        return preparation.Freshness.FAILED
    return preparation.Freshness.CURRENT


def stored_server_facts(state: DiscoveryState) -> preparation.ServerFacts:
    """Standing, freshness and contract recognition for a read-only check.

    A cache reading and a change both use these facts; only the requirements differ.
    """
    standing = state.snapshot.collected.standing if state.snapshot else None
    return preparation.ServerFacts(
        standing=standing.standing.value if standing is not None else None,
        freshness=_freshness(state),
        change_active=False,
        granted=frozenset(),
        outside_contract=state.outside_contract,
    )


def granted_needs(user: Account) -> frozenset[preparation.Need]:
    """The needs this account satisfies, from the engine's one permission vocabulary."""
    granted: set[preparation.Need] = set()
    if user.has_perms(PREPARE_PERMISSIONS):
        granted.add(preparation.Need.CHANGE)
    if user.has_perm(VIEW_SITES):
        granted.add(preparation.Need.SITE)
    if user.has_perm(MANAGE_SECRETS):
        granted.add(preparation.Need.SECRET)
    if user.has_perm(CHANGE_SHARED):
        granted.add(preparation.Need.SHARED)
    if user.has_perm(CHANGE_DESTRUCTIVE):
        granted.add(preparation.Need.DESTRUCTIVE)
    return frozenset(granted)


def server_facts(state: DiscoveryState, user: Account) -> preparation.ServerFacts:
    facts = stored_server_facts(state)
    return replace(
        facts,
        change_active=state.changes.polling,
        granted=granted_needs(user),
    )


def decide_for_server(
    state: DiscoveryState,
    user: Account,
    requirements: preparation.Requirements,
) -> preparation.Decision:
    return preparation.decide(server_facts(state, user), None, requirements)
