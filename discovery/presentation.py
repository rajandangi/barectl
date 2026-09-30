"""The one place an observation is named and worded for the operator.

The server page and the warnings Activity lists agree because both come from here; a new
kind of observation is presented here, and templates only lay it out.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import NamedTuple

from django.template.defaultfilters import filesizeformat

from .models import FileType, ObservationOutcome, SiteResource
from .snapshot import (
    CollectedSnapshot,
    FilesystemSize,
    Observation,
    ObservedDatabase,
    ObservedSite,
    ObservedSiteResource,
    OsRelease,
    PathMetadata,
    PoolEntryObservation,
    ServiceUnit,
    SiteFileObservation,
    WebStackComponentObservation,
)

UNINSPECTED = (ObservationOutcome.INACCESSIBLE, ObservationOutcome.UNSUPPORTED)

NOT_REPORTED = "Not reported"


@dataclass(frozen=True)
class ShownObservation:
    label: str
    outcome: ObservationOutcome
    warning: str
    source: tuple[str, ...]
    # What the page shows for it, one line each: its value when observed, else its outcome.
    lines: tuple[str, ...]

    @property
    def observed(self) -> bool:
        return self.outcome == ObservationOutcome.OBSERVED


class Fact(NamedTuple):
    label: str
    text: str


@dataclass(frozen=True)
class ShownComponent:
    label: str
    package: ShownObservation
    service: ShownObservation


@dataclass(frozen=True)
class ShownEntry:
    name: str
    # What qualifies the name, such as a pool's PHP version; empty when nothing does.
    qualifier: str
    observation: ShownObservation


@dataclass(frozen=True)
class ShownCollection:
    observation: ShownObservation
    entries: tuple[ShownEntry, ...]


@dataclass(frozen=True)
class SnapshotPresentation:
    """Every observation of a snapshot as the server page shows it, in display order."""

    os: ShownObservation
    os_facts: tuple[Fact, ...]
    capacity: tuple[ShownObservation, ...]
    components: tuple[ShownComponent, ...]
    nginx_site_files: ShownCollection
    php_fpm_pools: ShownCollection

    @property
    def observations(self) -> list[ShownObservation]:
        shown = [self.os, *self.capacity]
        for component in self.components:
            shown += [component.package, component.service]
        for collection in (self.nginx_site_files, self.php_fpm_pools):
            shown.append(collection.observation)
            shown += (entry.observation for entry in collection.entries)
        return shown

    @property
    def warnings(self) -> list[ShownObservation]:
        """An observed or absent observation is a finding, and its note is not a warning."""
        return [item for item in self.observations if item.outcome in UNINSPECTED and item.warning]

    @property
    def capacity_sources(self) -> list[str]:
        return _distinct(shown.source for shown in self.capacity)

    @property
    def component_sources(self) -> list[str]:
        return _distinct(
            (*component.package.source, *component.service.source) for component in self.components
        )


def present(collected: CollectedSnapshot) -> SnapshotPresentation:
    os = collected.os
    return SnapshotPresentation(
        os=_scalar("Operating system", os, _display_name),
        os_facts=_os_facts(os.value) if os.observed and os.value else (),
        capacity=(
            _scalar("Architecture", collected.architecture, str),
            _scalar("CPUs", collected.cpu_count, lambda count: f"{count} available"),
            _scalar("Memory", collected.memory_bytes, _size),
            _scalar("Root filesystem", collected.filesystem, _filesystem),
        ),
        components=tuple(_component(component) for component in collected.components),
        nginx_site_files=ShownCollection(
            _shown("Nginx site files", collected.nginx_site_files, ()),
            tuple(_site_file(site) for site in collected.nginx_site_files.value),
        ),
        php_fpm_pools=ShownCollection(
            _shown("PHP-FPM pools", collected.php_fpm_pools, ()),
            tuple(_pool(pool) for pool in collected.php_fpm_pools.value),
        ),
    )


def _display_name(release: OsRelease) -> str:
    return release.pretty_name or release.name or release.id


def _os_facts(release: OsRelease) -> tuple[Fact, ...]:
    return (
        Fact("Operating system", _display_name(release)),
        Fact("Distribution ID", release.id or NOT_REPORTED),
        Fact("Version", release.version_id or NOT_REPORTED),
    )


def _shown[T](label: str, observation: Observation[T], lines: tuple[str, ...]) -> ShownObservation:
    return ShownObservation(
        label, observation.outcome, observation.warning, observation.source, lines
    )


def _scalar[T](
    label: str, observation: Observation[T | None], text: Callable[[T], str]
) -> ShownObservation:
    value = observation.value
    if observation.observed and value is not None:
        return _shown(label, observation, (text(value),))
    return _shown(label, observation, (observation.outcome.label,))


def _size(size_bytes: int) -> str:
    return f"{filesizeformat(size_bytes)} ({size_bytes} bytes)"


def _filesystem(size: FilesystemSize) -> str:
    total, avail = size.size_bytes, size.avail_bytes
    return (
        f"{filesizeformat(total)} total ({total} bytes), "
        f"{filesizeformat(avail)} available ({avail} bytes)"
    )


def _component(observed: WebStackComponentObservation) -> ShownComponent:
    name = observed.component.label
    package, service = observed.package, observed.service
    packages = (
        tuple(f"{item.name} {item.version}" for item in package.value)
        if package.observed
        else (f"Packages: {package.outcome.label}",)
    )
    # A partial service observation keeps the units it read; they are shown beside its alert.
    units = tuple(_unit_line(unit) for unit in service.value) or (
        f"Service units: {service.outcome.label}",
    )
    return ShownComponent(
        name,
        _shown(f"{name} packages", package, packages),
        _shown(f"{name} service units", service, units),
    )


def _unit_line(unit: ServiceUnit) -> str:
    # systemd found no unit to load, so its other states describe nothing.
    if unit.load_state == "not-found":
        return f"{unit.name} not found"
    line = f"{unit.name} {unit.active_state} ({unit.sub_state})"
    return f"{line}, {unit.unit_file_state}" if unit.unit_file_state else line


def _site_file(site: SiteFileObservation) -> ShownEntry:
    lines = (
        (*_listed("Listens on", site.listens), *_listed("Server names", site.server_names))
        if site.observed
        else (site.outcome.label,)
    )
    return ShownEntry(
        site.name,
        "",
        ShownObservation(
            f"Nginx site file {site.name}", site.outcome, site.warning, (site.source,), lines
        ),
    )


def _listed(heading: str, values: tuple[str, ...]) -> tuple[str, ...]:
    if not values:
        return ()
    first, *rest = values
    return (f"{heading} {first}", *rest)


def _pool(pool: PoolEntryObservation) -> ShownEntry:
    lines = (f"Listens on {pool.listen}",) if pool.observed else (pool.outcome.label,)
    return ShownEntry(
        pool.name,
        f"PHP {pool.version}",
        ShownObservation(
            f"PHP {pool.version} FPM pool {pool.name}",
            pool.outcome,
            pool.warning,
            (pool.source,),
            lines,
        ),
    )


def _distinct(sources: Iterable[tuple[str, ...]]) -> list[str]:
    return list(dict.fromkeys(read for source in sources for read in source))


# docs/ssh-connections.md#site-observations
SITES_NOTE = (
    "A site matches the supported convention when every resource listed for it agreed with "
    "the convention when Barectl read it. Barectl does not read sudo rules. A match is not a "
    "check that the site serves requests, and it does not allow changing the site through "
    "Barectl."
)
NOT_READ = "Not read"


@dataclass(frozen=True)
class ShownResource:
    label: str
    location: str
    # How the resource compares with the convention, or its outcome when not observed.
    verdict: str
    lines: tuple[str, ...]
    source: tuple[str, ...]
    warning: str
    # Whether the warning explains a difference or a missing finding, rather than a note.
    alert: bool


@dataclass(frozen=True)
class ShownSite:
    identifier: str
    summary: str
    facts: tuple[Fact, ...]
    resources: tuple[ShownResource, ...]
    # The site's optional database binding, which the convention summary does not count.
    database: ShownResource


@dataclass(frozen=True)
class ShownSites:
    """Site observations, which only accounts allowed to view them are shown."""

    observation: ShownObservation
    sites: tuple[ShownSite, ...]
    note: str = SITES_NOTE


def present_sites(sites: Observation[tuple[ObservedSite, ...]]) -> ShownSites:
    return ShownSites(_shown("Sites", sites, ()), tuple(_site(site) for site in sites.value))


def _site(site: ObservedSite) -> ShownSite:
    departing = sum(not resource.conforms for resource in site.resources)
    summary = (
        "Matches the supported site convention"
        if site.complete
        else f"Does not match the supported site convention: {departing} of "
        f"{len(site.resources)} resources differ from it or could not be confirmed"
    )
    return ShownSite(
        site.identifier,
        summary,
        _site_facts(site),
        tuple(_site_resource(resource) for resource in site.resources),
        _site_database(site.database),
    )


# docs/ssh-connections.md#site-database-observations
DATABASE_NOT_COLLECTED = "Not collected by this version of Barectl"


def _site_database(database: ObservedDatabase | None) -> ShownResource:
    if database is None:
        return ShownResource("Database", "", DATABASE_NOT_COLLECTED, (), (), "", alert=False)
    engine = database.engine.label if database.engine else ""
    if database.conforms:
        verdict = f"{engine} binding, as the convention requires"
    elif database.outcome == ObservationOutcome.OBSERVED:
        verdict = f"{engine} binding, differs from the convention"
    elif database.outcome == ObservationOutcome.ABSENT:
        verdict = "None"
    else:
        verdict = database.outcome.label
    facts = (
        ("Principal", database.principal),
        ("Database", database.database),
        ("Owner", database.owner),
        ("Authentication", database.authentication),
        ("Privileges", database.privileges),
        (
            "Encoding and collation",
            " with ".join(v for v in (database.character_set, database.collation) if v),
        ),
    )
    return ShownResource(
        "Database",
        "",
        verdict,
        tuple(f"{label}: {value}" for label, value in facts if value),
        database.source,
        database.warning,
        alert=bool(database.warning)
        and not database.conforms
        and database.outcome != ObservationOutcome.ABSENT,
    )


def _site_facts(site: ObservedSite) -> tuple[Fact, ...]:
    account = site.account
    pool = f"{site.pool_user}:{site.pool_group}" if site.pool_user and site.pool_group else ""
    return (
        Fact("Server names", ", ".join(site.server_names) or NOT_READ),
        Fact("Document root", site.document_root or NOT_READ),
        Fact("FastCGI socket", site.fastcgi_socket or NOT_READ),
        Fact("PHP version", site.php_version),
        Fact("Pool user and group", pool or NOT_READ),
        Fact(
            "Site user",
            f"UID {account.uid}, GID {account.gid}, home {account.home}, shell {account.shell}"
            if account
            else NOT_READ,
        ),
    )


def _site_resource(resource: ObservedSiteResource) -> ShownResource:
    if resource.conforms:
        verdict = "Observed, as the convention requires"
    elif resource.outcome == ObservationOutcome.OBSERVED:
        verdict = "Observed, differs from the convention"
    else:
        verdict = resource.outcome.label
    label = resource.resource.label
    # The comparison with other sites has no single file or account to name.
    location = "" if resource.resource == SiteResource.EXCLUSIVE else resource.location
    return ShownResource(
        label,
        location,
        verdict,
        _metadata_lines(resource.metadata),
        resource.source,
        resource.warning,
        alert=bool(resource.warning) and not resource.conforms,
    )


def _metadata_lines(metadata: PathMetadata | None) -> tuple[str, ...]:
    if metadata is None:
        return ()
    line = f"{metadata.file_type.label}, owned by {metadata.owner}:{metadata.group}"
    if metadata.file_type != FileType.SYMLINK:
        return (f"{line}, mode {metadata.mode:04o}",)
    target = f"Links to {metadata.link_target}" if metadata.link_target else ""
    return (line, target) if target else (line,)
