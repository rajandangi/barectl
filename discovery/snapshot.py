"""docs/adr/0003-store-discovery-snapshots-in-typed-columns.md

``current_snapshot`` reads back what ``save_snapshot`` stored, with equal values.
"""

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
    FileType,
    NginxSiteObservation,
    ObservationOutcome,
    PhpFpmPoolObservation,
    ServiceUnitObservation,
    SiteResource,
    WebStackComponent,
)
from .models import SiteObservation as SiteRow
from .models import SiteResourceObservation as SiteResourceRow


@dataclass(frozen=True)
class Observation[T]:
    outcome: ObservationOutcome
    source: tuple[str, ...]
    warning: str
    value: T

    @property
    def observed(self) -> bool:
        return self.outcome == ObservationOutcome.OBSERVED


class Package(NamedTuple):
    name: str
    version: str


class ServiceUnit(NamedTuple):
    """A unit's states as systemd reports them.

    A unit without a unit file, such as one systemd could not find, has an empty unit-file
    state.
    """

    name: str
    load_state: str
    active_state: str
    sub_state: str
    unit_file_state: str


class OsRelease(NamedTuple):
    """A field the file does not set is empty."""

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
    # The states of each queried service unit, in query order.
    service: Observation[tuple[ServiceUnit, ...]]


@dataclass(frozen=True)
class SiteFileObservation:
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
    version: str
    name: str
    outcome: ObservationOutcome
    listen: str
    source: str
    warning: str

    @property
    def observed(self) -> bool:
        return self.outcome == ObservationOutcome.OBSERVED


class PathMetadata(NamedTuple):
    """A path's own metadata, as ``stat`` reports it without following a symbolic link."""

    file_type: FileType
    owner: str
    group: str
    # Permission bits, such as 0o644.
    mode: int
    # A symbolic link's target as written; empty for other file types.
    link_target: str


@dataclass(frozen=True)
class SiteResourceObservation:
    resource: SiteResource
    # The file, directory or account the resource is.
    location: str
    outcome: ObservationOutcome
    # Observed and as the site convention requires.
    conforms: bool
    metadata: PathMetadata | None
    source: tuple[str, ...]
    warning: str


class SiteAccount(NamedTuple):
    uid: int
    gid: int
    home: str
    shell: str


@dataclass(frozen=True)
class SiteObservation:
    """docs/ssh-connections.md#site-observations"""

    identifier: str
    # The site's own Nginx configuration: its server names, root and FastCGI socket.
    server_names: tuple[str, ...]
    document_root: str
    fastcgi_socket: str
    # The release's default PHP version, whose pool directory holds the site's pool.
    php_version: str
    # The runtime identity the site's pool declares.
    pool_user: str
    pool_group: str
    account: SiteAccount | None
    resources: tuple[SiteResourceObservation, ...]

    @property
    def complete(self) -> bool:
        """Whether every resource was observed as the supported site convention requires."""
        return all(resource.conforms for resource in self.resources)


@dataclass(frozen=True)
class CollectedSnapshot:
    """Scalar values are ``None`` unless observed."""

    os: Observation[OsRelease | None]
    architecture: Observation[str | None]
    cpu_count: Observation[int | None]
    memory_bytes: Observation[int | None]
    filesystem: Observation[FilesystemSize | None]
    components: tuple[WebStackComponentObservation, ...]
    nginx_site_files: Observation[tuple[SiteFileObservation, ...]]
    php_fpm_pools: Observation[tuple[PoolEntryObservation, ...]]
    sites: Observation[tuple[SiteObservation, ...]]

    @property
    def capacity(self) -> tuple[Observation[object], ...]:
        """The capacity observations, in display order."""
        return (self.architecture, self.cpu_count, self.memory_bytes, self.filesystem)


@dataclass(frozen=True)
class Snapshot:
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
        sites_status=collected.sites.outcome,
        sites_source=_joined(collected.sites.source),
        sites_warning=collected.sites.warning,
    )
    components = ComponentObservation.objects.bulk_create(
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
            service_source=_joined(observed.service.source),
            service_warning=observed.service.warning,
        )
        for observed in collected.components
    )
    ServiceUnitObservation.objects.bulk_create(
        ServiceUnitObservation(
            component=component,
            name=unit.name,
            load_state=unit.load_state,
            active_state=unit.active_state,
            sub_state=unit.sub_state,
            unit_file_state=unit.unit_file_state,
        )
        for component, observed in zip(components, collected.components, strict=True)
        for unit in observed.service.value
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
    _save_sites(snapshot, collected.sites.value)
    # The history of a server's discovery stays on its attempts.
    DiscoverySnapshot.objects.filter(server=attempt.server).exclude(pk=snapshot.pk).delete()


def _save_sites(snapshot: DiscoverySnapshot, sites: tuple[SiteObservation, ...]) -> None:
    rows = SiteRow.objects.bulk_create(
        SiteRow(
            snapshot=snapshot,
            identifier=site.identifier,
            server_names="\n".join(site.server_names),
            document_root=site.document_root,
            fastcgi_socket=site.fastcgi_socket,
            php_version=site.php_version,
            pool_user=site.pool_user,
            pool_group=site.pool_group,
            uid=site.account.uid if site.account else None,
            gid=site.account.gid if site.account else None,
            home=site.account.home if site.account else "",
            shell=site.account.shell if site.account else "",
        )
        for site in sites
    )
    SiteResourceRow.objects.bulk_create(
        SiteResourceRow(
            site=row,
            resource=resource.resource,
            location=resource.location,
            status=resource.outcome,
            conforms=resource.conforms,
            file_type=resource.metadata.file_type if resource.metadata else "",
            owner=resource.metadata.owner if resource.metadata else "",
            group=resource.metadata.group if resource.metadata else "",
            mode=resource.metadata.mode if resource.metadata else None,
            link_target=resource.metadata.link_target if resource.metadata else "",
            source=_joined(resource.source),
            warning=resource.warning,
        )
        for row, site in zip(rows, sites, strict=True)
        for resource in site.resources
    )


class AttemptSnapshot(NamedTuple):
    attempt: DiscoveryAttempt
    snapshot: Snapshot | None


_OBSERVATION_ROWS = (
    "components",
    "components__service_units",
    "nginx_site_files",
    "php_fpm_pools",
    "sites",
    "sites__resources",
)


def current_snapshot(server: Server) -> Snapshot | None:
    row = (
        DiscoverySnapshot.objects.filter(server=server)
        .select_related("attempt")
        .prefetch_related(*_OBSERVATION_ROWS)
        .first()
    )
    return None if row is None else _read(row, row.attempt.ssh_alias)


def has_snapshot(server: Server) -> bool:
    return DiscoverySnapshot.objects.filter(server=server).exists()


def attempt_snapshots(attempts: QuerySet[DiscoveryAttempt]) -> list[AttemptSnapshot]:
    """Each attempt with the snapshot it still holds, in the queryset's order.

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
                    tuple(
                        ServiceUnit(
                            unit.name,
                            unit.load_state,
                            unit.active_state,
                            unit.sub_state,
                            unit.unit_file_state,
                        )
                        for unit in component.service_units.all()
                    ),
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
        sites=Observation(
            ObservationOutcome(row.sites_status),
            _reads(row.sites_source),
            row.sites_warning,
            tuple(_read_site(site) for site in row.sites.all()),
        ),
    )
    return Snapshot(collected, row.collected_at, ssh_alias)


def _read_site(row: SiteRow) -> SiteObservation:
    account = (
        SiteAccount(row.uid, row.gid, row.home, row.shell)
        if row.uid is not None and row.gid is not None
        else None
    )
    return SiteObservation(
        identifier=row.identifier,
        server_names=tuple(row.server_names.splitlines()),
        document_root=row.document_root,
        fastcgi_socket=row.fastcgi_socket,
        php_version=row.php_version,
        pool_user=row.pool_user,
        pool_group=row.pool_group,
        account=account,
        resources=tuple(
            SiteResourceObservation(
                SiteResource(resource.resource),
                resource.location,
                ObservationOutcome(resource.status),
                resource.conforms,
                PathMetadata(
                    FileType(resource.file_type),
                    resource.owner,
                    resource.group,
                    resource.mode,
                    resource.link_target,
                )
                if resource.file_type and resource.mode is not None
                else None,
                _reads(resource.source),
                resource.warning,
            )
            for resource in row.resources.all()
        ),
    )


def _observation[T](outcome: str, source: str, warning: str, value: T) -> Observation[T | None]:
    observed = ObservationOutcome(outcome)
    return Observation(
        observed,
        _reads(source),
        warning,
        value if observed == ObservationOutcome.OBSERVED else None,
    )


def _joined(reads: tuple[str, ...]) -> str:
    return "\n".join(reads)


def _reads(stored: str) -> tuple[str, ...]:
    return tuple(stored.splitlines())
