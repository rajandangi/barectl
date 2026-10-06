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
    DatabaseEngine,
    DiscoveryAttempt,
    DiscoverySnapshot,
    ObservationOutcome,
    ServiceUnitObservation,
    SiteCertificateObservation,
    SiteDatabaseObservation,
    SiteObservation,
    SiteStage,
    SiteState,
    WebStackComponent,
)


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
class ObservedDatabase:
    """docs/ssh-connections.md#site-database-observations"""

    engine: DatabaseEngine | None
    outcome: ObservationOutcome
    # Observed, and the binding docs/site-conventions.md#database-convention describes.
    conforms: bool
    principal: str = ""
    database: str = ""
    # The authentication method, and for PostgreSQL the pg_hba.conf line that selects it.
    authentication: str = ""
    authentication_line: int | None = None
    privileges: str = ""
    character_set: str = ""
    collation: str = ""
    owner: str = ""
    source: tuple[str, ...] = ()
    warning: str = ""


class SiteAccount(NamedTuple):
    uid: int
    gid: int
    home: str
    shell: str


class ServedCertificate(NamedTuple):
    """The certificate one of the site's names is served, or an empty fingerprint.

    An empty fingerprint means the TLS probe could not read the served certificate.
    """

    name: str
    fingerprint: str


@dataclass(frozen=True)
class ObservedCertificate:
    """The public facts of an activated site's certificate."""

    outcome: ObservationOutcome
    # Observed, and the site's names and renewal configuration as the convention requires.
    conforms: bool
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    serial: str = ""
    # Lower-case hexadecimal SHA-256 of the DER certificate, without colons.
    fingerprint: str = ""
    # The DNS names the certificate's subjectAltName extension holds.
    names: tuple[str, ...] = ()
    served: tuple[ServedCertificate, ...] = ()
    # present, absent or inaccessible, as the renewal configuration's existence was read.
    renewal: str = ""
    source: tuple[str, ...] = ()
    warning: str = ""


@dataclass(frozen=True)
class ObservedSite:
    """docs/ssh-connections.md#site-observations

    An empty identifier is an enabled file or pool that does not follow the convention.
    """

    identifier: str
    server_names: tuple[str, ...]
    php_version: str
    account: SiteAccount | None
    state: SiteState
    outcome: ObservationOutcome
    # The first differing file, or the file of a blocked item; empty for a managed site.
    file: str = ""
    # The content Barectl expects at the changed file; empty when there is none.
    expected: str = ""
    # The convention resources that are absent.
    missing: tuple[str, ...] = ()
    # ``None`` when the snapshot was collected before database bindings were observed.
    database: ObservedDatabase | None = None
    # The site file's released form and the lineage its TLS block references.
    stage: SiteStage = SiteStage.HTTP
    certificate_reference: str = ""
    certificate_key_reference: str = ""
    # ``None`` for a site that does not serve HTTPS, and for snapshots collected before
    # activated forms were observed.
    certificate: ObservedCertificate | None = None


@dataclass(frozen=True)
class CollectedSnapshot:
    """Scalar values are ``None`` unless observed."""

    os: Observation[OsRelease | None]
    architecture: Observation[str | None]
    cpu_count: Observation[int | None]
    memory_bytes: Observation[int | None]
    filesystem: Observation[FilesystemSize | None]
    components: tuple[WebStackComponentObservation, ...]
    sites: Observation[tuple[ObservedSite, ...]]

    @property
    def capacity(self) -> tuple[Observation[object], ...]:
        """The capacity observations, in display order."""
        return (self.architecture, self.cpu_count, self.memory_bytes, self.filesystem)


@dataclass(frozen=True)
class Snapshot:
    collected: CollectedSnapshot
    collected_at: datetime
    ssh_alias: str
    revision: int = 0


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
    _save_sites(snapshot, collected.sites.value)
    # The history of a server's discovery stays on its attempts.
    DiscoverySnapshot.objects.filter(server=attempt.server).exclude(pk=snapshot.pk).delete()


def _save_sites(snapshot: DiscoverySnapshot, sites: tuple[ObservedSite, ...]) -> None:
    rows = SiteObservation.objects.bulk_create(
        SiteObservation(
            snapshot=snapshot,
            identifier=site.identifier,
            state=site.state,
            outcome=site.outcome,
            file=site.file,
            expected=site.expected,
            missing="\n".join(site.missing),
            server_names="\n".join(site.server_names),
            php_version=site.php_version,
            uid=site.account.uid if site.account else None,
            gid=site.account.gid if site.account else None,
            home=site.account.home if site.account else "",
            shell=site.account.shell if site.account else "",
            stage=site.stage,
            certificate_reference=site.certificate_reference,
            certificate_key_reference=site.certificate_key_reference,
        )
        for site in sites
    )
    SiteDatabaseObservation.objects.bulk_create(
        SiteDatabaseObservation(
            site=row,
            engine=database.engine or "",
            status=database.outcome,
            conforms=database.conforms,
            principal=database.principal,
            database=database.database,
            authentication=database.authentication,
            authentication_line=database.authentication_line,
            privileges=database.privileges,
            character_set=database.character_set,
            collation=database.collation,
            owner=database.owner,
            source=_joined(database.source),
            warning=database.warning,
        )
        for row, site in zip(rows, sites, strict=True)
        if (database := site.database) is not None
    )
    SiteCertificateObservation.objects.bulk_create(
        SiteCertificateObservation(
            site=row,
            status=certificate.outcome,
            conforms=certificate.conforms,
            issuer=certificate.issuer,
            not_before=certificate.not_before,
            not_after=certificate.not_after,
            serial=certificate.serial,
            fingerprint=certificate.fingerprint,
            names="\n".join(certificate.names),
            served="\n".join(f"{item.name} {item.fingerprint}" for item in certificate.served),
            renewal=certificate.renewal,
            source=_joined(certificate.source),
            warning=certificate.warning,
        )
        for row, site in zip(rows, sites, strict=True)
        if (certificate := site.certificate) is not None
    )


class AttemptSnapshot(NamedTuple):
    attempt: DiscoveryAttempt
    snapshot: Snapshot | None


_OBSERVATION_ROWS = (
    "components",
    "components__service_units",
    "sites",
    "sites__database",
    "sites__certificate",
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
        sites=Observation(
            ObservationOutcome(row.sites_status),
            _reads(row.sites_source),
            row.sites_warning,
            tuple(_read_site(site) for site in row.sites.all()),
        ),
    )
    return Snapshot(collected, row.collected_at, ssh_alias, row.pk)


def _read_site(row: SiteObservation) -> ObservedSite:
    account = (
        SiteAccount(row.uid, row.gid, row.home, row.shell)
        if row.uid is not None and row.gid is not None
        else None
    )
    return ObservedSite(
        identifier=row.identifier,
        server_names=tuple(row.server_names.splitlines()),
        php_version=row.php_version,
        account=account,
        state=SiteState(row.state),
        outcome=ObservationOutcome(row.outcome),
        file=row.file,
        expected=row.expected,
        missing=tuple(row.missing.splitlines()),
        database=_read_database(row),
        stage=SiteStage(row.stage),
        certificate_reference=row.certificate_reference,
        certificate_key_reference=row.certificate_key_reference,
        certificate=_read_certificate(row),
    )


def _read_certificate(row: SiteObservation) -> ObservedCertificate | None:
    try:
        certificate = row.certificate
    except ObjectDoesNotExist:
        return None
    served = []
    for line in certificate.served.splitlines():
        name, _, fingerprint = line.partition(" ")
        served.append(ServedCertificate(name, fingerprint))
    return ObservedCertificate(
        outcome=ObservationOutcome(certificate.status),
        conforms=certificate.conforms,
        issuer=certificate.issuer,
        not_before=certificate.not_before,
        not_after=certificate.not_after,
        serial=certificate.serial,
        fingerprint=certificate.fingerprint,
        names=tuple(certificate.names.splitlines()),
        served=tuple(served),
        renewal=certificate.renewal,
        source=_reads(certificate.source),
        warning=certificate.warning,
    )


def _read_database(row: SiteObservation) -> ObservedDatabase | None:
    try:
        database = row.database
    except ObjectDoesNotExist:
        return None
    return ObservedDatabase(
        engine=DatabaseEngine(database.engine) if database.engine else None,
        outcome=ObservationOutcome(database.status),
        conforms=database.conforms,
        principal=database.principal,
        database=database.database,
        authentication=database.authentication,
        authentication_line=database.authentication_line,
        privileges=database.privileges,
        character_set=database.character_set,
        collation=database.collation,
        owner=database.owner,
        source=_reads(database.source),
        warning=database.warning,
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
