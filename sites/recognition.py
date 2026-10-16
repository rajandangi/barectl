"""Which target-stack site files and pools discovery recognized, from stored observations."""

from dataclasses import dataclass
from typing import Final

from discovery.models import ObservationOutcome, SiteState
from discovery.snapshot import CollectedSnapshot, ObservedSite

from .observation import UNREADABLE_SITE

# The reader's own findings, kept equal to sites/bodies/common.py by a fast test.
CADDY_OUTSIDE: Final = "The site has Caddy settings outside the supported configuration."
POOL_OUTSIDE: Final = "The site pool has settings outside the supported bounds."
ROUTE_ABSENT: Final = (
    "Native account, group, directory or pool evidence exists, but its Caddy route is absent."
)
RECOGNIZED: Final = "Recognized"
OUTSIDE: Final = "Outside supported settings"
ABSENT: Final = "Absent"
NOT_CONFIRMED: Final = "Not confirmed"


@dataclass(frozen=True)
class RecognizedFile:
    path: str
    identifier: str
    verdict: str
    finding: str = ""


def target_sites(collected: CollectedSnapshot) -> tuple[ObservedSite, ...]:
    return tuple(
        site
        for site in collected.sites.value
        if site.identifier and site.file.startswith("/etc/caddy/sites/")
    )


def site_files(collected: CollectedSnapshot) -> tuple[RecognizedFile, ...]:
    """docs/site-conventions.md#supported-configuration-grammar

    Every site file the reader returned had its adapted form compared with the convention,
    so only the Caddy finding marks the file itself as outside supported settings.
    """
    return tuple(_site_file(site) for site in target_sites(collected))


def _site_file(site: ObservedSite) -> RecognizedFile:
    finding = site.missing[0] if site.missing else ""
    if finding == CADDY_OUTSIDE:
        return RecognizedFile(site.file, site.identifier, OUTSIDE, finding)
    if finding == ROUTE_ABSENT:
        return RecognizedFile(site.file, site.identifier, ABSENT, finding)
    if finding == UNREADABLE_SITE:
        return RecognizedFile(site.file, site.identifier, NOT_CONFIRMED, finding)
    return RecognizedFile(site.file, site.identifier, RECOGNIZED)


def site_pools(collected: CollectedSnapshot) -> tuple[RecognizedFile, ...]:
    """The reader checks a pool only after the site's account, layout and commands, so a
    site stopped by another finding leaves its pool unconfirmed."""
    return tuple(_site_pool(site) for site in target_sites(collected) if site.php_version)


def _site_pool(site: ObservedSite) -> RecognizedFile:
    path = f"/etc/php-fpm/sites/{site.identifier}/{site.php_version}/pools/{site.identifier}.conf"
    finding = site.missing[0] if site.missing else ""
    if site.state == SiteState.MANAGED and site.outcome == ObservationOutcome.OBSERVED:
        return RecognizedFile(path, site.identifier, RECOGNIZED)
    if finding == POOL_OUTSIDE:
        return RecognizedFile(path, site.identifier, OUTSIDE, finding)
    return RecognizedFile(path, site.identifier, NOT_CONFIRMED, finding)
