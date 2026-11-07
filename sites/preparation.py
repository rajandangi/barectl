"""Site facts for the preparation gate, derived from one observation (spec #507).

Laravel identity comes from the settings and release rows, never from
``ObservedSite.application``, which the producer never sets to ``"laravel"``.
"""

from dataclasses import replace
from typing import TYPE_CHECKING

from django.contrib.auth.models import AnonymousUser, User

from backups.observation import stopped_by_pause
from discovery.models import ObservationOutcome, SiteState
from discovery.snapshot import CollectedSnapshot, Snapshot
from operations import preparation
from servers.preparation import server_facts
from sites.bodies.common import SITE_GATED

if TYPE_CHECKING:
    from servers.discovery_state import DiscoveryState

type Account = User | AnonymousUser


def _absent() -> preparation.SiteFacts:
    return preparation.SiteFacts(
        present=False,
        convention=False,
        shape=None,
        missing=(),
        gated=False,
        paused=False,
        has_pool=False,
        wordpress=False,
        laravel=False,
        application_problem="",
        releases_observed=False,
        has_releases=False,
        current_release=False,
        retained_release=False,
        has_cache=False,
        log_rotation="",
    )


def _paused(collected: CollectedSnapshot, identifier: str, gated: bool) -> bool:
    if not gated:
        return False
    backup = next((row for row in collected.backups.value if row.identifier == identifier), None)
    return stopped_by_pause(backup.last if backup is not None else None)


def site_facts(
    snapshot: Snapshot | None,
    identifier: str,
    *,
    rotation: str | None = None,
) -> preparation.SiteFacts:
    """One site's facts from one observation.

    ``rotation`` replaces the snapshot's log-rotation value when a section renders read
    evidence newer than the snapshot, so its card and note read the same evidence.
    """
    if snapshot is None:
        return _absent()
    collected = snapshot.collected
    if collected.sites.outcome != ObservationOutcome.OBSERVED:
        return _absent()
    observed = next((site for site in collected.sites.value if site.identifier == identifier), None)
    if observed is None:
        return _absent()

    releases = collected.releases.value
    settings = collected.settings.value
    cache = collected.cache.value
    gated = SITE_GATED in observed.missing
    facts = preparation.SiteFacts(
        present=True,
        convention=observed.file == f"/etc/caddy/sites/{identifier}.caddy",
        shape=preparation.SiteShape(observed.state.value),
        missing=observed.missing,
        gated=gated,
        paused=_paused(collected, identifier, gated),
        has_pool=observed.pool is not None,
        wordpress=observed.application == "wordpress",
        laravel=any(
            row.identifier == identifier and row.application == "laravel" for row in settings
        )
        or any(row.identifier == identifier for row in releases),
        application_problem=observed.application_problem,
        releases_observed=collected.releases.outcome == ObservationOutcome.OBSERVED,
        has_releases=any(row.identifier == identifier for row in releases),
        current_release=any(row.identifier == identifier and row.current for row in releases),
        retained_release=any(
            row.identifier == identifier and row.state == SiteState.MANAGED and not row.current
            for row in releases
        ),
        has_cache=any(row.identifier == identifier for row in cache),
        log_rotation=observed.log_rotation,
    )
    return replace(facts, log_rotation=rotation) if rotation is not None else facts


def decide_for_site(
    state: DiscoveryState,
    user: Account,
    identifier: str,
    requirements: preparation.Requirements,
    *,
    rotation: str | None = None,
) -> preparation.Decision:
    return preparation.decide(
        server_facts(state, user),
        site_facts(state.snapshot, identifier, rotation=rotation),
        requirements,
    )
