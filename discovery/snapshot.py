"""The discovery snapshot: what one successful attempt observed, and how it is kept.

Collectors return a ``CollectedSnapshot``. ``save_snapshot`` stores it and
``current_snapshot`` reads it back with equal values. Only this module knows how a snapshot
is stored.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import NamedTuple

from django.core.exceptions import ObjectDoesNotExist
from django.db.models import QuerySet

from servers.models import Server

from .models import (
    ComponentObservation,
    DiscoveryAttempt,
    DiscoverySnapshot,
    NginxSiteObservation,
    ObservationOutcome,
    PhpFpmPoolObservation,
    WebStackComponent,
)


@dataclass(frozen=True)
class Observation[T]:
    """One observation's outcome, the commands or files it was read from, and its value."""

    outcome: ObservationOutcome
    # The commands and files whose reads decided the outcome, in order.
    source: tuple[str, ...]
    warning: str
    value: T

    @property
    def observed(self) -> bool:
        return self.outcome == ObservationOutcome.OBSERVED


# Outcomes where Barectl could not inspect what it looked for; see ObservationOutcome.
UNINSPECTED = (ObservationOutcome.INACCESSIBLE, ObservationOutcome.UNSUPPORTED)


class ObservationWarning(NamedTuple):
    """A warning about something Barectl could not inspect, named for the operator."""

    observation: str
    outcome: ObservationOutcome
    warning: str


class Package(NamedTuple):
    """One installed dpkg package."""

    name: str
    version: str


class OsRelease(NamedTuple):
    """The os-release fields Barectl keeps. A field the file does not set is empty."""

    pretty_name: str
    name: str
    id: str
    version_id: str


class FilesystemSize(NamedTuple):
    size_bytes: int
    avail_bytes: int


@dataclass(frozen=True)
class WebStackComponentObservation:
    component: WebStackComponent
    package: Observation[tuple[Package, ...]]
    # One "unit state" line per queried unit, such as "nginx.service active (running), enabled".
    service: Observation[tuple[str, ...]]


@dataclass(frozen=True)
class SiteFileObservation:
    """One entry of the site directory, with the fields Barectl keeps from it."""

    name: str
    outcome: ObservationOutcome
    server_names: tuple[str, ...]
    listens: tuple[str, ...]
    source: str
    warning: str

    @property
    def observed(self) -> bool:
        return self.outcome == ObservationOutcome.OBSERVED


@dataclass(frozen=True)
class PoolEntryObservation:
    """One PHP-FPM pool, with the fields Barectl keeps from it."""

    version: str
    name: str
    outcome: ObservationOutcome
    listen: str
    source: str
    warning: str

    @property
    def observed(self) -> bool:
        return self.outcome == ObservationOutcome.OBSERVED


@dataclass(frozen=True)
class CollectedSnapshot:
    """Every observation of one discovery run. Scalar values are ``None`` unless observed."""

    os: Observation[OsRelease | None]
    architecture: Observation[str | None]
    cpu_count: Observation[int | None]
    memory_bytes: Observation[int | None]
    filesystem: Observation[FilesystemSize | None]
    components: tuple[WebStackComponentObservation, ...]
    nginx_site_files: Observation[tuple[SiteFileObservation, ...]]
    php_fpm_pools: Observation[tuple[PoolEntryObservation, ...]]

    @property
    def capacity(self) -> tuple[Observation[object], ...]:
        """The capacity observations, in display order."""
        return (self.architecture, self.cpu_count, self.memory_bytes, self.filesystem)

    @property
    def warnings(self) -> list[ObservationWarning]:
        """Warnings about what could not be inspected, labelled, in display order.

        Only inaccessible and unsupported observations count: an observed or absent one is
        a finding, and its note is not a warning.
        """
        labelled: list[tuple[str, ObservationOutcome, str]] = [
            ("Operating system", self.os.outcome, self.os.warning),
            ("Architecture", self.architecture.outcome, self.architecture.warning),
            ("CPUs", self.cpu_count.outcome, self.cpu_count.warning),
            ("Memory", self.memory_bytes.outcome, self.memory_bytes.warning),
            ("Root filesystem", self.filesystem.outcome, self.filesystem.warning),
        ]
        for component in self.components:
            name = component.component.label
            labelled += [
                (f"{name} packages", component.package.outcome, component.package.warning),
                (f"{name} service units", component.service.outcome, component.service.warning),
            ]
        sites, pools = self.nginx_site_files, self.php_fpm_pools
        labelled += [
            ("Nginx site files", sites.outcome, sites.warning),
            *((f"Nginx site file {site.name}", site.outcome, site.warning) for site in sites.value),
            ("PHP-FPM pools", pools.outcome, pools.warning),
            *(
                (f"PHP {pool.version} FPM pool {pool.name}", pool.outcome, pool.warning)
                for pool in pools.value
            ),
        ]
        return [
            ObservationWarning(observation, outcome, warning)
            for observation, outcome, warning in labelled
            if outcome in UNINSPECTED and warning
        ]

    @property
    def capacity_sources(self) -> list[str]:
        """The distinct commands and files the capacity observations were read from, in order."""
        return _distinct(observation.source for observation in self.capacity)

    @property
    def component_sources(self) -> list[str]:
        """The distinct commands the component observations were read with, in order."""
        return _distinct(
            (*component.package.source, *component.service.source) for component in self.components
        )


def _distinct(sources: Iterable[tuple[str, ...]]) -> list[str]:
    return list(dict.fromkeys(read for source in sources for read in source))


@dataclass(frozen=True)
class Snapshot:
    """A stored snapshot: its observations, when they were collected, and over which alias."""

    collected: CollectedSnapshot
    collected_at: datetime
    ssh_alias: str


def save_snapshot(
    attempt: DiscoveryAttempt, collected: CollectedSnapshot, collected_at: datetime
) -> None:
    """Store the attempt's snapshot as the server's current one, replacing any earlier one.

    Call it inside the transaction that marks the attempt succeeded.
    """
    os, fs = collected.os, collected.filesystem
    os_value = os.value or OsRelease("", "", "", "")
    snapshot = DiscoverySnapshot.objects.create(
        server=attempt.server,
        attempt=attempt,
        collected_at=collected_at,
        os_status=os.outcome,
        os_source=_joined(os.source),
        os_pretty_name=os_value.pretty_name,
        os_name=os_value.name,
        os_id=os_value.id,
        os_version_id=os_value.version_id,
        os_warning=os.warning,
        arch_status=collected.architecture.outcome,
        arch_value=collected.architecture.value or "",
        arch_source=_joined(collected.architecture.source),
        arch_warning=collected.architecture.warning,
        cpu_status=collected.cpu_count.outcome,
        cpu_count=collected.cpu_count.value,
        cpu_source=_joined(collected.cpu_count.source),
        cpu_warning=collected.cpu_count.warning,
        memory_status=collected.memory_bytes.outcome,
        memory_bytes=collected.memory_bytes.value,
        memory_source=_joined(collected.memory_bytes.source),
        memory_warning=collected.memory_bytes.warning,
        filesystem_status=fs.outcome,
        filesystem_size_bytes=fs.value.size_bytes if fs.value else None,
        filesystem_avail_bytes=fs.value.avail_bytes if fs.value else None,
        filesystem_source=_joined(fs.source),
        filesystem_warning=fs.warning,
        nginx_site_files_status=collected.nginx_site_files.outcome,
        nginx_site_files_source=_joined(collected.nginx_site_files.source),
        nginx_site_files_warning=collected.nginx_site_files.warning,
        php_fpm_pools_status=collected.php_fpm_pools.outcome,
        php_fpm_pools_source=_joined(collected.php_fpm_pools.source),
        php_fpm_pools_warning=collected.php_fpm_pools.warning,
    )
    ComponentObservation.objects.bulk_create(
        ComponentObservation(
            snapshot=snapshot,
            component=observed.component,
            package_status=observed.package.outcome,
            packages="\n".join(
                f"{package.name} {package.version}" for package in observed.package.value
            ),
            package_source=_joined(observed.package.source),
            package_warning=observed.package.warning,
            service_status=observed.service.outcome,
            units="\n".join(observed.service.value),
            service_source=_joined(observed.service.source),
            service_warning=observed.service.warning,
        )
        for observed in collected.components
    )
    NginxSiteObservation.objects.bulk_create(
        NginxSiteObservation(
            snapshot=snapshot,
            name=site.name,
            status=site.outcome,
            server_names="\n".join(site.server_names),
            listens="\n".join(site.listens),
            source=site.source,
            warning=site.warning,
        )
        for site in collected.nginx_site_files.value
    )
    PhpFpmPoolObservation.objects.bulk_create(
        PhpFpmPoolObservation(
            snapshot=snapshot,
            version=pool.version,
            name=pool.name,
            status=pool.outcome,
            listen=pool.listen,
            source=pool.source,
            warning=pool.warning,
        )
        for pool in collected.php_fpm_pools.value
    )
    # The history of a server's discovery stays on its attempts.
    DiscoverySnapshot.objects.filter(server=attempt.server).exclude(pk=snapshot.pk).delete()


class AttemptSnapshot(NamedTuple):
    """A discovery attempt and the snapshot it published, if it succeeded."""

    attempt: DiscoveryAttempt
    snapshot: Snapshot | None


_OBSERVATION_ROWS = ("components", "nginx_site_files", "php_fpm_pools")


def current_snapshot(server: Server) -> Snapshot | None:
    """The server's current snapshot, or ``None`` before its first successful attempt."""
    row = (
        DiscoverySnapshot.objects.filter(server=server)
        .select_related("attempt")
        .prefetch_related(*_OBSERVATION_ROWS)
        .first()
    )
    return None if row is None else _read(row, row.attempt.ssh_alias)


def attempt_snapshots(attempts: QuerySet[DiscoveryAttempt]) -> list[AttemptSnapshot]:
    """Each attempt with the snapshot it published, in the queryset's order.

    The snapshots are read in a fixed number of queries, however many attempts there are.
    """
    listed = attempts.select_related("snapshot").prefetch_related(
        *(f"snapshot__{rows}" for rows in _OBSERVATION_ROWS)
    )
    return [AttemptSnapshot(attempt, _published(attempt)) for attempt in listed]


def _published(attempt: DiscoveryAttempt) -> Snapshot | None:
    try:
        row = attempt.snapshot
    except ObjectDoesNotExist:
        return None
    return _read(row, attempt.ssh_alias)


def _read(row: DiscoverySnapshot, ssh_alias: str) -> Snapshot:
    collected = CollectedSnapshot(
        os=_observation(
            row.os_status,
            row.os_source,
            row.os_warning,
            OsRelease(row.os_pretty_name, row.os_name, row.os_id, row.os_version_id),
        ),
        architecture=_observation(
            row.arch_status, row.arch_source, row.arch_warning, row.arch_value
        ),
        cpu_count=_observation(row.cpu_status, row.cpu_source, row.cpu_warning, row.cpu_count),
        memory_bytes=_observation(
            row.memory_status, row.memory_source, row.memory_warning, row.memory_bytes
        ),
        filesystem=_observation(
            row.filesystem_status,
            row.filesystem_source,
            row.filesystem_warning,
            FilesystemSize(row.filesystem_size_bytes or 0, row.filesystem_avail_bytes or 0),
        ),
        components=tuple(
            WebStackComponentObservation(
                WebStackComponent(component.component),
                Observation(
                    ObservationOutcome(component.package_status),
                    _reads(component.package_source),
                    component.package_warning,
                    tuple(Package(*line.split(" ", 1)) for line in component.packages.splitlines()),
                ),
                Observation(
                    ObservationOutcome(component.service_status),
                    _reads(component.service_source),
                    component.service_warning,
                    tuple(component.units.splitlines()),
                ),
            )
            for component in row.components.all()
        ),
        nginx_site_files=Observation(
            ObservationOutcome(row.nginx_site_files_status),
            _reads(row.nginx_site_files_source),
            row.nginx_site_files_warning,
            tuple(
                SiteFileObservation(
                    site.name,
                    ObservationOutcome(site.status),
                    tuple(site.server_names.splitlines()),
                    tuple(site.listens.splitlines()),
                    site.source,
                    site.warning,
                )
                for site in row.nginx_site_files.all()
            ),
        ),
        php_fpm_pools=Observation(
            ObservationOutcome(row.php_fpm_pools_status),
            _reads(row.php_fpm_pools_source),
            row.php_fpm_pools_warning,
            tuple(
                PoolEntryObservation(
                    pool.version,
                    pool.name,
                    ObservationOutcome(pool.status),
                    pool.listen,
                    pool.source,
                    pool.warning,
                )
                for pool in row.php_fpm_pools.all()
            ),
        ),
    )
    return Snapshot(collected, row.collected_at, ssh_alias)


def _observation[T](outcome: str, source: str, warning: str, value: T) -> Observation[T | None]:
    """A stored scalar observation; its value exists only when it was observed."""
    observed = ObservationOutcome(outcome)
    return Observation(
        observed,
        _reads(source),
        warning,
        value if observed == ObservationOutcome.OBSERVED else None,
    )


def _joined(reads: tuple[str, ...]) -> str:
    """An observation's source as stored: one read per line."""
    return "\n".join(reads)


def _reads(stored: str) -> tuple[str, ...]:
    return tuple(stored.splitlines())
