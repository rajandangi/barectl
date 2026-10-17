"""docs/adr/0003-store-discovery-snapshots-in-typed-columns.md

``current_snapshot`` reads back what ``save_snapshot`` stored, with equal values.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import NamedTuple

from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q, QuerySet

from bootstrap.standing import HostJudgment, Standing
from runtimes.defaults import DefaultsObservation, decode_observation
from runtimes.observation import RuntimeObservation as ObservedRuntime
from servers.connections import connection_label
from servers.models import Server

from .models import (
    ComponentObservation,
    DiscoveryAttempt,
    DiscoverySnapshot,
    ObservationOutcome,
    ReleaseObservation,
    RuntimeObservation,
    ServiceUnitObservation,
    SiteObservation,
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
    """docs/adr/0015-recognize-only-the-convention.md"""

    component: WebStackComponent
    package: Observation[tuple[Package, ...]]
    # The states of each queried service unit, in query order.
    service: Observation[tuple[ServiceUnit, ...]]
    # Whether the installed packages follow the release's bootstrap profile.
    managed: bool = True
    # The packages outside the profile, and PostgreSQL majors or clusters it does not
    # support, each with what to remove or change.
    deviations: tuple[str, ...] = ()


class SiteAccount(NamedTuple):
    uid: int
    gid: int
    home: str
    shell: str


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
    # The convention resources that are absent.
    missing: tuple[str, ...] = ()
    node_runtime: str = ""


@dataclass(frozen=True)
class ObservedRelease:
    """One retained release directory of a site (docs/site-conventions.md)."""

    identifier: str
    name: str
    commit: str
    created: int
    state: SiteState
    current: bool


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
    standing: HostJudgment | None = None
    runtimes: tuple[ObservedRuntime, ...] = ()
    runtime_warning: str = ""
    runtime_defaults: DefaultsObservation | None = None
    releases: Observation[tuple[ObservedRelease, ...]] = field(
        default_factory=lambda: Observation(ObservationOutcome.ABSENT, (), "", ())
    )

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
        releases_status=collected.releases.outcome,
        releases_source=_joined(collected.releases.source),
        releases_warning=collected.releases.warning,
        runtime_warning=collected.runtime_warning,
        default_runtime_observed=collected.runtime_defaults is not None,
        default_php=collected.runtime_defaults.php if collected.runtime_defaults else "",
        default_node=collected.runtime_defaults.node if collected.runtime_defaults else "",
        default_php_problem=collected.runtime_defaults.php_problem
        if collected.runtime_defaults
        else "",
        default_node_problem=collected.runtime_defaults.node_problem
        if collected.runtime_defaults
        else "",
        default_php_choices="\n".join(collected.runtime_defaults.php_choices)
        if collected.runtime_defaults
        else "",
        default_node_choices="\n".join(collected.runtime_defaults.node_choices)
        if collected.runtime_defaults
        else "",
        host_standing=collected.standing.standing.value if collected.standing else "",
        host_standing_reasons="\n".join(collected.standing.reasons) if collected.standing else "",
        host_standing_warnings="\n".join(collected.standing.warnings) if collected.standing else "",
        host_foundation=(
            "\n".join(f"{stage}\t{state}" for stage, state in collected.standing.foundation)
            if collected.standing
            else ""
        ),
        host_evidence=(
            "\n".join(f"{label}\t{value}" for label, value in collected.standing.evidence)
            if collected.standing
            else ""
        ),
    )
    RuntimeObservation.objects.bulk_create(
        RuntimeObservation(
            snapshot=snapshot,
            entry=row.entry,
            path=row.path,
            generation=row.generation,
            version=row.version,
            extensions="\n".join(row.extensions),
            master_state=row.master_state,
            protections="\n".join(f"{key}\t{value}" for key, value in row.protections),
            problem=row.problem,
        )
        for row in collected.runtimes
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
            managed=observed.managed,
            deviations="\n".join(observed.deviations),
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
    _save_releases(snapshot, collected.releases.value)
    # The history of a server's discovery stays on its attempts.
    DiscoverySnapshot.objects.filter(
        server=attempt.server, attempt__connection=attempt.connection
    ).exclude(pk=snapshot.pk).delete()


def _save_sites(snapshot: DiscoverySnapshot, sites: tuple[ObservedSite, ...]) -> None:
    SiteObservation.objects.bulk_create(
        SiteObservation(
            snapshot=snapshot,
            identifier=site.identifier,
            state=site.state,
            outcome=site.outcome,
            file=site.file,
            missing="\n".join(site.missing),
            server_names="\n".join(site.server_names),
            php_version=site.php_version,
            node_runtime=site.node_runtime,
            uid=site.account.uid if site.account else None,
            gid=site.account.gid if site.account else None,
            home=site.account.home if site.account else "",
            shell=site.account.shell if site.account else "",
        )
        for site in sites
    )


def _save_releases(snapshot: DiscoverySnapshot, releases: tuple[ObservedRelease, ...]) -> None:
    ReleaseObservation.objects.bulk_create(
        ReleaseObservation(
            snapshot=snapshot,
            identifier=release.identifier,
            name=release.name,
            commit=release.commit,
            created=release.created,
            state=release.state,
            current=release.current,
        )
        for release in releases
    )


class AttemptSnapshot(NamedTuple):
    attempt: DiscoveryAttempt
    snapshot: Snapshot | None


_OBSERVATION_ROWS = (
    "runtimes",
    "components",
    "components__service_units",
    "sites",
    "releases",
)


def current_snapshot(server: Server) -> Snapshot | None:
    row = (
        DiscoverySnapshot.objects.filter(server=server)
        .filter(_current_connection(server))
        .select_related("attempt", "attempt__connection")
        .prefetch_related(*_OBSERVATION_ROWS)
        .first()
    )
    return None if row is None else _read(row, connection_label(row.attempt))


def has_snapshot(server: Server) -> bool:
    return (
        DiscoverySnapshot.objects.filter(server=server).filter(_current_connection(server)).exists()
    )


def _current_connection(server: Server) -> Q:
    return Q(attempt__connection__revision=server.connection_revision) | Q(
        attempt__connection__isnull=True, server__connection_revision=0
    )


def attempt_snapshots(attempts: QuerySet[DiscoveryAttempt]) -> list[AttemptSnapshot]:
    """Each attempt with the snapshot it still holds, in the queryset's order.

    The snapshots are read in a fixed number of queries, however many attempts there are.
    """
    listed = attempts.select_related("snapshot", "connection").prefetch_related(
        *(f"snapshot__{rows}" for rows in _OBSERVATION_ROWS)
    )
    return [AttemptSnapshot(attempt, _published(attempt)) for attempt in listed]


def _published(attempt: DiscoveryAttempt) -> Snapshot | None:
    try:
        row = attempt.snapshot
    except ObjectDoesNotExist:
        return None
    return _read(row, connection_label(attempt))


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
                managed=component.managed,
                deviations=tuple(component.deviations.splitlines()),
            )
            for component in row.components.all()
        ),
        sites=Observation(
            ObservationOutcome(row.sites_status),
            _reads(row.sites_source),
            row.sites_warning,
            tuple(_read_site(site) for site in row.sites.all()),
        ),
        releases=Observation(
            ObservationOutcome(row.releases_status),
            _reads(row.releases_source),
            row.releases_warning,
            tuple(_read_release(release) for release in row.releases.all()),
        ),
        runtime_warning=row.runtime_warning,
        runtime_defaults=decode_observation(
            {
                "php": row.default_php,
                "node": row.default_node,
                "php_problem": row.default_php_problem,
                "node_problem": row.default_node_problem,
                "php_choices": row.default_php_choices.splitlines(),
                "node_choices": row.default_node_choices.splitlines(),
            }
        )
        if row.default_runtime_observed
        else None,
        runtimes=tuple(
            ObservedRuntime(
                runtime.entry,
                runtime.path,
                runtime.generation,
                runtime.version,
                tuple(runtime.extensions.splitlines()),
                runtime.master_state,
                _read_pairs(runtime.protections),
                runtime.problem,
            )
            for runtime in row.runtimes.all()
        ),
        standing=(
            HostJudgment(
                Standing(row.host_standing),
                tuple(row.host_standing_reasons.splitlines()),
                tuple(row.host_standing_warnings.splitlines()),
                _read_pairs(row.host_foundation),
                _read_pairs(row.host_evidence),
            )
            if row.host_standing
            else None
        ),
    )
    return Snapshot(collected, row.collected_at, ssh_alias, row.pk)


def _read_pairs(text: str) -> tuple[tuple[str, str], ...]:
    return tuple(
        (stage, state)
        for line in text.splitlines()
        if "\t" in line
        for stage, _, state in (line.partition("\t"),)
    )


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
        node_runtime=row.node_runtime,
        account=account,
        state=SiteState(row.state),
        outcome=ObservationOutcome(row.outcome),
        file=row.file,
        missing=tuple(row.missing.splitlines()),
    )


def _read_release(row: ReleaseObservation) -> ObservedRelease:
    return ObservedRelease(
        identifier=row.identifier,
        name=row.name,
        commit=row.commit,
        created=row.created,
        state=SiteState(row.state),
        current=row.current,
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
