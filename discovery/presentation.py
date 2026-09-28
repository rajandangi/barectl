"""How the dashboard names and words each observation of a discovery snapshot.

``present`` turns a collected snapshot into the sections of the server page. It is the one
place an observation is named for the operator, so the page and the warnings Activity lists
agree; a new kind of observation is presented here, and templates only lay it out.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import NamedTuple

from django.template.defaultfilters import filesizeformat

from .models import ObservationOutcome
from .snapshot import (
    CollectedSnapshot,
    FilesystemSize,
    Observation,
    OsRelease,
    PoolEntryObservation,
    ServiceUnit,
    SiteFileObservation,
    WebStackComponentObservation,
)

# Outcomes where Barectl could not inspect what it looked for; see ObservationOutcome.
UNINSPECTED = (ObservationOutcome.INACCESSIBLE, ObservationOutcome.UNSUPPORTED)

NOT_REPORTED = "Not reported"


@dataclass(frozen=True)
class ShownObservation:
    """One observation or entry of a snapshot, named and worded for the operator."""

    label: str
    outcome: ObservationOutcome
    warning: str
    # The commands and files whose reads decided the outcome, in order.
    source: tuple[str, ...]
    # What the page shows for it, one line each: its value when observed, else its outcome.
    lines: tuple[str, ...]

    @property
    def observed(self) -> bool:
        return self.outcome == ObservationOutcome.OBSERVED


class Fact(NamedTuple):
    """One named value of an observation."""

    label: str
    text: str


@dataclass(frozen=True)
class ShownComponent:
    """A web-stack component with its package and service observations."""

    label: str
    package: ShownObservation
    service: ShownObservation


@dataclass(frozen=True)
class ShownEntry:
    """One Nginx site file or PHP-FPM pool, headed by its name."""

    name: str
    # What qualifies the name, such as a pool's PHP version; empty when nothing does.
    qualifier: str
    observation: ShownObservation


@dataclass(frozen=True)
class ShownCollection:
    """A collection observation, such as the PHP-FPM pools, and each entry it found."""

    observation: ShownObservation
    entries: tuple[ShownEntry, ...]


@dataclass(frozen=True)
class SnapshotPresentation:
    """Every observation of a snapshot as the server page shows it, in display order."""

    os: ShownObservation
    # The operating system's fields, shown only when it was observed.
    os_facts: tuple[Fact, ...]
    capacity: tuple[ShownObservation, ...]
    components: tuple[ShownComponent, ...]
    nginx_site_files: ShownCollection
    php_fpm_pools: ShownCollection

    @property
    def observations(self) -> list[ShownObservation]:
        """Every observation and entry of the snapshot, in display order."""
        shown = [self.os, *self.capacity]
        for component in self.components:
            shown += [component.package, component.service]
        for collection in (self.nginx_site_files, self.php_fpm_pools):
            shown.append(collection.observation)
            shown += (entry.observation for entry in collection.entries)
        return shown

    @property
    def warnings(self) -> list[ShownObservation]:
        """The observations whose warnings say what could not be inspected, in display order.

        Only inaccessible and unsupported observations count: an observed or absent one is
        a finding, and its note is not a warning.
        """
        return [item for item in self.observations if item.outcome in UNINSPECTED and item.warning]

    @property
    def capacity_sources(self) -> list[str]:
        """The distinct commands and files the capacity observations were read from, in order."""
        return _distinct(shown.source for shown in self.capacity)

    @property
    def component_sources(self) -> list[str]:
        """The distinct commands the component observations were read with, in order."""
        return _distinct(
            (*component.package.source, *component.service.source) for component in self.components
        )


def present(collected: CollectedSnapshot) -> SnapshotPresentation:
    """The snapshot's observations, named and worded for the operator."""
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
    """The name the page shows: the pretty name, else the name, else the ID."""
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
    """A single value, or the outcome in its place: a value is never shown unless observed."""
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
    """A unit's states, such as ``nginx.service active (running), enabled``."""
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
    """``values`` one per line, the first introduced by ``heading``; none when empty."""
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
