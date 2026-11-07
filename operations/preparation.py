"""The one preparation gate every change card asks, from typed facts alone (spec #507).

The gate decides no consent level and declares no permission name: it receives the facts
and the caller's granted needs, and returns an allowance or the first failing reason.
docs/dashboard-workflows.md and docs/architecture.md#module-map.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum

# bootstrap.standing's values, repeated here so this module stays free of Django and every
# other app. A `Standing` member compares equal to these strings.
NOT_MANAGEABLE = "Not manageable"
TARGET_STACK = "Target stack"


class Freshness(StrEnum):
    """How much a stored observation can be relied on for a new change."""

    # No snapshot or no host judgment: setup is offered.
    UNOBSERVED = "unobserved"
    CURRENT = "current"
    # A check is queued or running.
    CHECKING = "checking"
    # The latest check failed.
    FAILED = "failed"


class Need(StrEnum):
    """A permission class a card may require, named without a Django permission string."""

    CHANGE = "change"  # PREPARE_PERMISSIONS
    SITE = "site"  # discovery.view_siteobservation
    SECRET = "secret"  # noqa: S105 - a permission class, not a credential
    SHARED = "shared"  # operations.change_shared
    DESTRUCTIVE = "destructive"  # operations.change_destructive


@dataclass(frozen=True)
class ServerFacts:
    standing: str | None
    freshness: Freshness
    # An active change preparation or change run, not a read.
    change_active: bool
    granted: frozenset[Need]


class SiteShape(StrEnum):
    MANAGED = "managed"
    PARTLY_APPLIED = "partly_applied"
    NOT_FOLLOWING = "not_following"


@dataclass(frozen=True)
class SiteFacts:
    # A site row from an observed inventory.
    present: bool
    # The file is /etc/caddy/sites/<identifier>.caddy.
    convention: bool
    shape: SiteShape | None
    missing: tuple[str, ...]
    # SITE_GATED is in missing.
    gated: bool
    # Gated and the last backup was interrupted by a pause or a restore.
    paused: bool
    has_pool: bool
    wordpress: bool
    # A Laravel settings row or any release row.
    laravel: bool
    application_problem: str
    releases_observed: bool
    has_releases: bool
    current_release: bool
    # A non-current release row for this identifier in MANAGED state.
    retained_release: bool
    has_cache: bool
    # "supported", "partial", "outside", "missing", "unavailable" or "".
    log_rotation: str


@dataclass(frozen=True)
class Requirements:
    needs: frozenset[Need] = frozenset()
    # The card assumes a host that has been read and is on the target stack. Setup does not.
    target_stack: bool = False
    site: bool = False
    # Only read when site=True.
    convention: bool = True
    allow_not_following: bool = False
    # The shape the card requires.
    state: SiteShape | None = None
    allow_partly_applied: bool = False
    # A partly applied site must have missing == (completes,).
    completes: str = ""
    # Not gated and not paused.
    open_site: bool = False
    # The site must be gated.
    gated: bool = False
    # The site must be paused.
    paused: bool = False
    # "wordpress" or "laravel".
    application: str = ""
    no_application_problem: bool = False
    pool: bool = False
    releases_observed: bool = False
    no_releases: bool = False
    current_release: bool = False
    retained_release: bool = False
    cache: bool = False
    rotation_unsupported: bool = False


class ReasonName(StrEnum):
    HOST_NOT_MANAGEABLE = "host_not_manageable"
    CHECK_RUNNING = "check_running"
    CHECK_FAILED = "check_failed"
    HOST_NOT_OBSERVED = "host_not_observed"
    HOST_NOT_READY = "host_not_ready"
    CHANGE_IN_PROGRESS = "change_in_progress"
    MISSING_CHANGE_PERMISSION = "missing_change_permission"
    MISSING_SITE_PERMISSION = "missing_site_permission"
    MISSING_SECRET_PERMISSION = "missing_secret_permission"  # noqa: S105 - a reason name
    MISSING_SHARED_PERMISSION = "missing_shared_permission"
    MISSING_DESTRUCTIVE_PERMISSION = "missing_destructive_permission"
    SITE_NOT_OBSERVED = "site_not_observed"
    SITE_NOT_CONVENTIONAL = "site_not_conventional"
    SITE_NOT_FOLLOWING = "site_not_following"
    SITE_PARTLY_APPLIED = "site_partly_applied"
    SITE_NOT_MANAGED = "site_not_managed"
    SITE_GATED = "site_gated"
    SITE_PAUSED = "site_paused"
    SITE_NOT_GATED = "site_not_gated"
    SITE_NOT_PAUSED = "site_not_paused"
    APPLICATION_NOT_WORDPRESS = "application_not_wordpress"
    APPLICATION_NOT_LARAVEL = "application_not_laravel"
    APPLICATION_PROBLEM = "application_problem"
    POOL_NOT_OBSERVED = "pool_not_observed"
    RELEASES_NOT_OBSERVED = "releases_not_observed"
    RELEASES_PRESENT = "releases_present"
    CURRENT_RELEASE_MISSING = "current_release_missing"
    RETAINED_RELEASE_MISSING = "retained_release_missing"
    CACHE_NOT_OBSERVED = "cache_not_observed"
    LOG_ROTATION_SUPPORTED = "log_rotation_supported"


@dataclass(frozen=True)
class Reason:
    name: ReasonName
    sentence: str


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: Reason | None = None


REASONS: Mapping[ReasonName, str] = {
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
    ReasonName.MISSING_SHARED_PERMISSION: ("Changing this needs the shared-change permission."),
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
    ReasonName.RETAINED_RELEASE_MISSING: "This site has no retained release to roll back to.",
    ReasonName.CACHE_NOT_OBSERVED: "Barectl has not observed this site's object cache.",
    ReasonName.LOG_ROTATION_SUPPORTED: "Log rotation is already set up for this site.",
}


type _Failure = Callable[[ServerFacts, SiteFacts | None, Requirements], bool]


def _observed(site: SiteFacts | None, requirements: Requirements) -> SiteFacts | None:
    if not requirements.site or site is None or not site.present:
        return None
    return site


def _host_not_manageable(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    return server.standing == NOT_MANAGEABLE


def _check_running(server: ServerFacts, site: SiteFacts | None, requirements: Requirements) -> bool:
    return server.freshness is Freshness.CHECKING


def _check_failed(server: ServerFacts, site: SiteFacts | None, requirements: Requirements) -> bool:
    return server.freshness is Freshness.FAILED


def _host_not_observed(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    return requirements.target_stack and server.standing is None


def _host_not_ready(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    return (
        requirements.target_stack
        and server.standing is not None
        and server.standing != TARGET_STACK
    )


def _change_in_progress(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    return server.change_active


def _missing(need: Need) -> _Failure:
    def refuses(server: ServerFacts, site: SiteFacts | None, requirements: Requirements) -> bool:
        return need in requirements.needs and need not in server.granted

    return refuses


def _site_not_observed(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    return requirements.site and (site is None or not site.present)


def _site_not_conventional(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    observed = _observed(site, requirements)
    return observed is not None and requirements.convention and not observed.convention


def _site_not_following(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    observed = _observed(site, requirements)
    return (
        observed is not None
        and observed.shape is SiteShape.NOT_FOLLOWING
        and not requirements.allow_not_following
    )


def _site_partly_applied(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    observed = _observed(site, requirements)
    if observed is None or observed.shape is not SiteShape.PARTLY_APPLIED:
        return False
    if requirements.allow_partly_applied:
        return False
    return not (requirements.completes and observed.missing == (requirements.completes,))


def _site_not_managed(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    observed = _observed(site, requirements)
    return (
        observed is not None
        and requirements.state is not None
        and observed.shape is not requirements.state
    )


def _site_gated(server: ServerFacts, site: SiteFacts | None, requirements: Requirements) -> bool:
    observed = _observed(site, requirements)
    # A paused site is gated too; it reports the more specific paused reason.
    return (
        observed is not None and requirements.open_site and observed.gated and not observed.paused
    )


def _site_paused(server: ServerFacts, site: SiteFacts | None, requirements: Requirements) -> bool:
    observed = _observed(site, requirements)
    return observed is not None and requirements.open_site and observed.paused


def _site_not_gated(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    observed = _observed(site, requirements)
    return observed is not None and requirements.gated and not observed.gated


def _site_not_paused(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    observed = _observed(site, requirements)
    return observed is not None and requirements.paused and not observed.paused


def _application_not_wordpress(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    observed = _observed(site, requirements)
    return (
        observed is not None and requirements.application == "wordpress" and not observed.wordpress
    )


def _application_not_laravel(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    observed = _observed(site, requirements)
    return observed is not None and requirements.application == "laravel" and not observed.laravel


def _application_problem(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    observed = _observed(site, requirements)
    return (
        observed is not None
        and requirements.no_application_problem
        and bool(observed.application_problem)
    )


def _pool_not_observed(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    observed = _observed(site, requirements)
    return observed is not None and requirements.pool and not observed.has_pool


def _releases_not_observed(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    observed = _observed(site, requirements)
    return (
        observed is not None and requirements.releases_observed and not observed.releases_observed
    )


def _releases_present(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    observed = _observed(site, requirements)
    return observed is not None and requirements.no_releases and observed.has_releases


def _current_release_missing(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    observed = _observed(site, requirements)
    return observed is not None and requirements.current_release and not observed.current_release


def _retained_release_missing(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    observed = _observed(site, requirements)
    return observed is not None and requirements.retained_release and not observed.retained_release


def _cache_not_observed(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    observed = _observed(site, requirements)
    return observed is not None and requirements.cache and not observed.has_cache


def _log_rotation_supported(
    server: ServerFacts, site: SiteFacts | None, requirements: Requirements
) -> bool:
    observed = _observed(site, requirements)
    return (
        observed is not None
        and requirements.rotation_unsupported
        and observed.log_rotation == "supported"
    )


# The one ordered reason list. Earlier refusals win, so a card cannot report a site problem
# when the host or the caller's permission already refuses the change.
_FAILURES: dict[ReasonName, _Failure] = {
    ReasonName.HOST_NOT_MANAGEABLE: _host_not_manageable,
    ReasonName.CHECK_RUNNING: _check_running,
    ReasonName.CHECK_FAILED: _check_failed,
    ReasonName.HOST_NOT_OBSERVED: _host_not_observed,
    ReasonName.HOST_NOT_READY: _host_not_ready,
    ReasonName.CHANGE_IN_PROGRESS: _change_in_progress,
    ReasonName.MISSING_CHANGE_PERMISSION: _missing(Need.CHANGE),
    ReasonName.MISSING_SITE_PERMISSION: _missing(Need.SITE),
    ReasonName.MISSING_SECRET_PERMISSION: _missing(Need.SECRET),
    ReasonName.MISSING_SHARED_PERMISSION: _missing(Need.SHARED),
    ReasonName.MISSING_DESTRUCTIVE_PERMISSION: _missing(Need.DESTRUCTIVE),
    ReasonName.SITE_NOT_OBSERVED: _site_not_observed,
    ReasonName.SITE_NOT_CONVENTIONAL: _site_not_conventional,
    ReasonName.SITE_NOT_FOLLOWING: _site_not_following,
    ReasonName.SITE_PARTLY_APPLIED: _site_partly_applied,
    ReasonName.SITE_NOT_MANAGED: _site_not_managed,
    ReasonName.SITE_GATED: _site_gated,
    ReasonName.SITE_PAUSED: _site_paused,
    ReasonName.SITE_NOT_GATED: _site_not_gated,
    ReasonName.SITE_NOT_PAUSED: _site_not_paused,
    ReasonName.APPLICATION_NOT_WORDPRESS: _application_not_wordpress,
    ReasonName.APPLICATION_NOT_LARAVEL: _application_not_laravel,
    ReasonName.APPLICATION_PROBLEM: _application_problem,
    ReasonName.POOL_NOT_OBSERVED: _pool_not_observed,
    ReasonName.RELEASES_NOT_OBSERVED: _releases_not_observed,
    ReasonName.RELEASES_PRESENT: _releases_present,
    ReasonName.CURRENT_RELEASE_MISSING: _current_release_missing,
    ReasonName.RETAINED_RELEASE_MISSING: _retained_release_missing,
    ReasonName.CACHE_NOT_OBSERVED: _cache_not_observed,
    ReasonName.LOG_ROTATION_SUPPORTED: _log_rotation_supported,
}

PRECEDENCE: tuple[ReasonName, ...] = tuple(_FAILURES)


SERVER = Requirements(needs=frozenset({Need.CHANGE}))
SITE = Requirements(
    site=True,
    convention=True,
    state=SiteShape.MANAGED,
    needs=frozenset({Need.CHANGE, Need.SITE}),
)
EMPTY = Requirements()


def decide(server: ServerFacts, site: SiteFacts | None, requirements: Requirements) -> Decision:
    """Return the allowance, or the first failing reason in the fixed precedence."""
    for name in PRECEDENCE:
        if _FAILURES[name](server, site, requirements):
            return Decision(False, Reason(name, REASONS[name]))
    return Decision(True)
