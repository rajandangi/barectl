"""Which installed catalog builds a Barectl release can update (docs/php-versions.md).

An update compares the build an entry's Nix profile resolves to with the build this
Barectl release offers for the same entry and architecture. A profile is only updated when
both are known catalog builds; an unknown profile is reported by runtime reconstruction and
is never adopted here. Retired builds stay recognized, so a newer controller can update an
older server's build without first reinstalling the runtime.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from discovery.snapshot import ObservedSite

from .catalog import Architecture, Build, Kind, load

# The entries whose new build needs the stack's own services restarted after their profile
# changes (docs/target-architecture.md#nix).
SERVICE_ENTRIES: tuple[str, ...] = ("caddy", "haproxy")


@dataclass(frozen=True)
class CatalogUpdate:
    """One installed build this release replaces, and what the replacement reaches."""

    entry: str
    kind: Kind
    installed: Build
    offered: Build
    sites: tuple[str, ...] = ()

    @property
    def restarts_service(self) -> bool:
        return self.entry in SERVICE_ENTRIES


def usage_by_entry(sites: Iterable[ObservedSite]) -> dict[str, tuple[str, ...]]:
    """The sites each runtime entry serves, from the site observation."""
    found: dict[str, set[str]] = {}
    for site in sites:
        for entry in (site.php_version, site.node_runtime):
            if entry and site.identifier:
                found.setdefault(entry, set()).add(site.identifier)
    return {entry: tuple(sorted(identifiers)) for entry, identifiers in found.items()}


def installed_builds(architecture: Architecture, profiles: Mapping[str, str]) -> dict[str, Build]:
    """The recognized catalog build each installed profile resolves to."""
    recognised: dict[str, Build] = {}
    for entry, path in profiles.items():
        if not path:
            continue
        build = load().identify(architecture, path)
        if build is not None and build.entry == entry:
            recognised[entry] = build
    return recognised


def updates(
    architecture: Architecture,
    profiles: Mapping[str, str],
    usage: Mapping[str, tuple[str, ...]],
) -> tuple[CatalogUpdate, ...]:
    """Every installed profile whose build is older than the offered one, by entry."""
    offered = {build.entry: build for build in load().offered(architecture)}
    recognised = installed_builds(architecture, profiles)
    rows = []
    for entry in sorted(recognised):
        current, wanted = recognised[entry], offered.get(entry)
        if wanted is None or current.path == wanted.path:
            continue
        rows.append(
            CatalogUpdate(
                entry,
                current.kind,
                current,
                wanted,
                usage.get(entry, ()),
            )
        )
    return tuple(rows)
