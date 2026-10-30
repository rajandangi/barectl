"""docs/adr/0003-store-discovery-snapshots-in-typed-columns.md

``current_snapshot`` reads back what ``save_snapshot`` stored, with equal values.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, NamedTuple

from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q, QuerySet

from automation.observation import ObservedSchedule
from automation.worker_observation import ObservedWorker
from automation.workers import WorkerDefinition
from bootstrap.standing import HostJudgment, Standing
from runtimes.defaults import DefaultsObservation, decode_observation
from runtimes.observation import RuntimeObservation as ObservedRuntime
from servers.connections import connection_label
from servers.models import Server
from sites.bodies.pool import SitePool

if TYPE_CHECKING:
    from backups.observation import ObservedBackup, OffsiteStorage
    from cache.models import CacheObservation
    from security.observation import SecurityState

from .models import (
    ComponentObservation,
    DiscoveryAttempt,
    DiscoverySnapshot,
    ObservationOutcome,
    ReleaseObservation,
    RuntimeObservation,
    ServiceUnitObservation,
    SettingObservation,
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


class SiteCertificate(NamedTuple):
    """A site's certificate state read from Caddy's own storage (docs/tls.md).

    ``state`` is one of ``http``, ``waiting``, ``issued``, ``renewal_due`` or ``failing``.
    """

    state: str
    issuer: str = ""
    not_after: int = 0
    error: str = ""
    names: tuple[str, ...] = ()


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
    # Whether Caddy serves the site over HTTPS, and the certificate evidence it holds.
    https: bool = False
    # The path Barectl checks after a change; "/" unless the operator chose another.
    readiness: str = "/"
    certificate: SiteCertificate | None = None
    # The pool's supported operator-tunable settings (docs/site-conventions.md).
    pool: SitePool | None = None
    # The site's application, read from native files without running PHP (docs/wordpress.md).
    application: str = "plain"
    application_version: str = ""
    application_problem: str = ""
    # The PHP object-cache client enabled for this site's own master (Phase C #390).
    client: str = ""
    # The supported state of the site's root-owned logrotate file (Phase C #389).
    log_rotation: str = ""


@dataclass(frozen=True)
class ObservedSetting:
    """One key of a site's private configuration, with its server-computed digest.

    ``value`` is present only for a key on the Laravel environment's fixed non-secret list;
    every secret value stays write-only (Phase B #383, ADR 0032).
    """

    identifier: str
    application: str
    key: str
    digest: str
    value: str = ""


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
class ObservedCache:
    """One site's object cache, from the instance and the application's own files.

    ``state`` is ``off``, ``on``, ``partial`` or ``unsupported``; the controller never
    keeps a cache's contents, only this observation and an on-demand reading.
    """

    identifier: str
    state: str
    memory_mib: int | None = None
    problem: str = ""
    plugin_version: str = ""
    client: str = ""
    unit_state: str = ""


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
    # The keys and server-computed digests of each site's private settings file.
    settings: Observation[tuple[ObservedSetting, ...]] = field(
        default_factory=lambda: Observation(ObservationOutcome.ABSENT, (), "", ())
    )
    # Each site's object cache instance and application wiring (Phase C #392).
    cache: Observation[tuple[ObservedCache, ...]] = field(
        default_factory=lambda: Observation(ObservationOutcome.ABSENT, (), "", ())
    )
    # Each WordPress site's scheduled work, as native evidence and the pure projection
    # record it (docs/automation.md, Phase C #357).
    automation: Observation[tuple[ObservedSchedule, ...]] = field(
        default_factory=lambda: Observation(ObservationOutcome.ABSENT, (), "", ())
    )
    # Each Laravel site's queue-worker definition and state, read from its units
    # (docs/automation.md, Phase C #266).
    workers: Observation[tuple[ObservedWorker, ...]] = field(
        default_factory=lambda: Observation(ObservationOutcome.ABSENT, (), "", ())
    )
    # Each site's backups and newest safe result, from native evidence (Phase D #396).
    backups: Observation[tuple[ObservedBackup, ...]] = field(
        default_factory=lambda: Observation(ObservationOutcome.ABSENT, (), "", ())
    )
    # The server's offsite storage setting, from native evidence (Phase D #403).
    offsite: Observation[OffsiteStorage | None] = field(
        default_factory=lambda: Observation(ObservationOutcome.ABSENT, (), "", None)
    )
    # The read-only security checks, from fixed root reads (Phase E #302).
    security: Observation[SecurityState | None] = field(
        default_factory=lambda: Observation(ObservationOutcome.ABSENT, (), "", None)
    )
    # Caddy's optional certificate contact email, from the main configuration (docs/tls.md).
    certificate_email: str = ""
    certificate_email_state: str = ""

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
        settings_status=collected.settings.outcome,
        settings_source=_joined(collected.settings.source),
        settings_warning=collected.settings.warning,
        cache_status=collected.cache.outcome,
        cache_source=_joined(collected.cache.source),
        cache_warning=collected.cache.warning,
        automation_status=collected.automation.outcome,
        automation_source=_joined(collected.automation.source),
        automation_warning=collected.automation.warning,
        workers_status=collected.workers.outcome,
        workers_source=_joined(collected.workers.source),
        workers_warning=collected.workers.warning,
        backups_status=collected.backups.outcome,
        backups_source=_joined(collected.backups.source),
        backups_warning=collected.backups.warning,
        offsite=_offsite_document(collected.offsite.value),
        offsite_status=collected.offsite.outcome,
        offsite_source=_joined(collected.offsite.source),
        offsite_warning=collected.offsite.warning,
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
        host_profiles=(
            "\n".join(f"{entry}\t{path}" for entry, path in collected.standing.profiles)
            if collected.standing
            else ""
        ),
        certificate_email=collected.certificate_email,
        certificate_email_state=collected.certificate_email_state,
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
    _save_cache(snapshot, collected.cache.value)
    _save_releases(snapshot, collected.releases.value)
    _save_settings(snapshot, collected.settings.value)
    _save_automation(snapshot, collected.automation.value)
    _save_workers(snapshot, collected.workers.value)
    _save_backups(snapshot, collected.backups.value)
    _save_security(snapshot, collected.security.value, collected.security.source)
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
            https=site.https,
            readiness=site.readiness,
            pool_process_manager=site.pool.process_manager if site.pool else "",
            pool_max_children=site.pool.max_children if site.pool else None,
            pool_start_servers=site.pool.start_servers if site.pool else None,
            pool_min_spare_servers=site.pool.min_spare_servers if site.pool else None,
            pool_max_spare_servers=site.pool.max_spare_servers if site.pool else None,
            pool_process_idle_timeout=site.pool.process_idle_timeout if site.pool else None,
            pool_slowlog_timeout=site.pool.slowlog_timeout if site.pool else None,
            pool_terminate_timeout=site.pool.terminate_timeout if site.pool else None,
            pool_memory_limit=site.pool.memory_limit if site.pool else None,
            pool_upload_max_filesize=site.pool.upload_max_filesize if site.pool else None,
            pool_post_max_size=site.pool.post_max_size if site.pool else None,
            certificate_state=site.certificate.state if site.certificate else "",
            certificate_issuer=site.certificate.issuer if site.certificate else "",
            certificate_not_after=site.certificate.not_after if site.certificate else 0,
            certificate_error=site.certificate.error if site.certificate else "",
            certificate_names="\n".join(site.certificate.names) if site.certificate else "",
            uid=site.account.uid if site.account else None,
            gid=site.account.gid if site.account else None,
            home=site.account.home if site.account else "",
            shell=site.account.shell if site.account else "",
            application=site.application,
            application_version=site.application_version,
            application_problem=site.application_problem,
            client=site.client,
            log_rotation=site.log_rotation,
        )
        for site in sites
    )


def _save_cache(snapshot: DiscoverySnapshot, cache: tuple[ObservedCache, ...]) -> None:
    from cache.models import CacheObservation

    CacheObservation.objects.bulk_create(
        CacheObservation(
            snapshot=snapshot,
            identifier=row.identifier,
            state=row.state,
            memory_mib=row.memory_mib,
            problem=row.problem,
            plugin_version=row.plugin_version,
            client=row.client,
            unit_state=row.unit_state,
        )
        for row in cache
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


def _save_settings(snapshot: DiscoverySnapshot, settings: tuple[ObservedSetting, ...]) -> None:
    SettingObservation.objects.bulk_create(
        SettingObservation(
            snapshot=snapshot,
            identifier=setting.identifier,
            application=setting.application,
            name=setting.key,
            digest=setting.digest,
            value=setting.value,
        )
        for setting in settings
    )


def _save_automation(snapshot: DiscoverySnapshot, schedules: tuple[ObservedSchedule, ...]) -> None:
    from automation.models import AutomationObservation

    AutomationObservation.objects.bulk_create(
        AutomationObservation(
            snapshot=snapshot,
            identifier=schedule.identifier,
            role=schedule.role,
            status=schedule.status,
            problem=schedule.problem,
            duplicate=schedule.duplicate,
            disable_wp_cron=schedule.disable_wp_cron,
            installed=schedule.installed,
            timer_active=schedule.timer_active,
            timer_enabled=schedule.timer_enabled,
            service_active=schedule.service_active,
            masked=schedule.masked,
            result=schedule.result,
            exec_status=schedule.exec_status,
            last_start_us=schedule.last_start_us,
            last_exit_us=schedule.last_exit_us,
            last_trigger_us=schedule.last_trigger_us,
            next_elapse_us=schedule.next_elapse_us,
            slice_populated=schedule.slice_populated,
        )
        for schedule in schedules
    )


def _save_workers(snapshot: DiscoverySnapshot, workers: tuple[ObservedWorker, ...]) -> None:
    from automation.models import WorkerObservation

    WorkerObservation.objects.bulk_create(
        WorkerObservation(
            snapshot=snapshot,
            identifier=worker.identifier,
            status=worker.status,
            queues="\n".join(worker.queues),
            processes=worker.processes,
            timeout=worker.timeout,
            active_processes=worker.active_processes,
            installed=worker.installed,
            enabled=worker.enabled,
            masked=worker.masked,
            start_limited=worker.start_limited,
            slice_populated=worker.slice_populated,
            result=worker.result,
            exec_status=worker.exec_status,
            last_start_us=worker.last_start_us,
            last_exit_us=worker.last_exit_us,
            nrestarts=worker.nrestarts,
            duplicate=worker.duplicate,
            problem=worker.problem,
        )
        for worker in workers
    )


def _save_security(
    snapshot: DiscoverySnapshot, state: SecurityState | None, state_source: tuple[str, ...]
) -> None:
    if state is None:
        return
    from security.models import (
        SecurityListener,
        SecurityObservation,
        SecurityPendingUpdate,
        SecurityRule,
    )

    row = SecurityObservation.objects.create(
        snapshot=snapshot,
        source=_joined(state_source),
        firewall_status=state.firewall.status,
        firewall_source=_joined(state.firewall.source),
        firewall_warning=state.firewall.warning,
        listeners_status=state.listeners.status,
        listeners_source=_joined(state.listeners.source),
        listeners_warning=state.listeners.warning,
        ssh_status=state.ssh.status,
        ssh_source=_joined(state.ssh.source),
        ssh_warning=state.ssh.warning,
        auto_updates_status=state.auto_updates.status,
        auto_updates_source=_joined(state.auto_updates.source),
        auto_updates_warning=state.auto_updates.warning,
        updates_status=state.updates.status,
        updates_source=_joined(state.updates.source),
        updates_warning=state.updates.warning,
        restart_status=state.restart.status,
        restart_source=_joined(state.restart.source),
        restart_warning=state.restart.warning,
        ufw_installed=state.firewall.value.ufw_installed if state.firewall.value else False,
        ufw_enabled=state.firewall.value.ufw_enabled if state.firewall.value else None,
        default_incoming=state.firewall.value.default_incoming if state.firewall.value else "",
        default_outgoing=state.firewall.value.default_outgoing if state.firewall.value else "",
        default_routed=state.firewall.value.default_routed if state.firewall.value else "",
        ipv6=state.firewall.value.ipv6 if state.firewall.value else None,
        logging=state.firewall.value.logging if state.firewall.value else "",
        outside="\n".join(state.firewall.value.outside) if state.firewall.value else "",
        firewall_conffiles_intact=state.firewall.value.conffiles_intact
        if state.firewall.value
        else None,
        password_authentication=state.ssh.value.password_authentication if state.ssh.value else "",
        keyboard_interactive=state.ssh.value.keyboard_interactive if state.ssh.value else "",
        permit_root_login=state.ssh.value.permit_root_login if state.ssh.value else "",
        ssh_ports="\n".join(str(port) for port in state.ssh.value.ports) if state.ssh.value else "",
        socket_ports="\n".join(str(port) for port in state.ssh.value.socket_ports)
        if state.ssh.value
        else "",
        accounts_without_keys="\n".join(state.ssh.value.accounts_without_keys)
        if state.ssh.value
        else "",
        per_source_penalties=state.ssh.value.per_source_penalties if state.ssh.value else "",
        auto_updates_enabled=state.auto_updates.value.enabled if state.auto_updates.value else None,
        list_update_timer=state.auto_updates.value.list_update_timer
        if state.auto_updates.value
        else "",
        upgrade_timer=state.auto_updates.value.upgrade_timer if state.auto_updates.value else "",
        automatic_reboot=state.auto_updates.value.automatic_reboot
        if state.auto_updates.value
        else None,
        allowed_origins="\n".join(state.auto_updates.value.allowed_origins)
        if state.auto_updates.value
        else "",
        last_upgrade=state.auto_updates.value.last_upgrade if state.auto_updates.value else "",
        conffile_matches=state.auto_updates.value.conffile_matches_package
        if state.auto_updates.value
        else None,
        newest_log_age=state.auto_updates.value.newest_log_age
        if state.auto_updates.value
        else None,
        list_age_seconds=state.updates.value.list_age_seconds if state.updates.value else None,
        restart_required=state.restart.value.required if state.restart.value else None,
        restart_packages="\n".join(state.restart.value.packages) if state.restart.value else "",
    )
    SecurityRule.objects.bulk_create(
        SecurityRule(
            security=row,
            kind=rule.kind,
            line=rule.line,
            action=rule.action,
            protocol=rule.protocol,
            ports=rule.ports,
            network=rule.network,
        )
        for rule in (state.firewall.value.rules if state.firewall.value else ())
    )
    SecurityListener.objects.bulk_create(
        SecurityListener(
            security=row,
            address=row_listener.address,
            port=row_listener.port,
            protocol=row_listener.protocol,
            process=row_listener.process,
            public=row_listener.public,
            expected=_expected_listener(
                row_listener, state.ssh.value.ports if state.ssh.value else ()
            ),
        )
        for row_listener in (state.listeners.value or ())
    )
    SecurityPendingUpdate.objects.bulk_create(
        SecurityPendingUpdate(
            security=row,
            name=update.name,
            installed=update.installed,
            candidate=update.candidate,
            archive=update.archive,
            classification=update.classification,
        )
        for update in (state.updates.value.pending if state.updates.value else ())
    )


def _expected_listener(listener: object, ssh_ports: tuple[int, ...]) -> bool:
    from security.observation import Listener

    if not isinstance(listener, Listener) or not listener.public:
        return False
    return (listener.protocol, listener.port) in {
        ("tcp", 80),
        ("tcp", 443),
        ("udp", 443),
        *{("tcp", port) for port in ssh_ports},
    }


def _offsite_document(value: object | None) -> dict[str, object]:
    from backups.observation import OffsiteStorage

    if not isinstance(value, OffsiteStorage):
        return {}
    return {
        "provider": value.provider,
        "bucket": value.bucket,
        "region": value.region,
        "endpoint": value.endpoint,
        "prefix": value.prefix,
        "prune": value.prune,
        "problem": value.problem,
        "sites": [source.identifier for source in value.sources],
        "sources": [
            {
                "site": source.identifier,
                "rows": list(source.rows),
                "problem": source.problem,
            }
            for source in value.sources
        ],
    }


def _source_rows(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, dict))


def _read_offsite(value: dict[str, object]) -> "OffsiteStorage | None":  # noqa: UP037
    from backups.observation import ConnectedSource, OffsiteStorage

    if not value:
        return None
    raw_sources = value.get("sources")
    sources: tuple[ConnectedSource, ...] = ()
    if isinstance(raw_sources, list):
        sources = tuple(
            ConnectedSource(
                str(row.get("site", "")),
                _source_rows(row.get("rows")),
                str(row.get("problem", "")),
            )
            for row in raw_sources
            if isinstance(row, dict)
        )
    return OffsiteStorage(
        str(value.get("provider", "")),
        str(value.get("bucket", "")),
        str(value.get("region", "")),
        str(value.get("endpoint", "")),
        str(value.get("prefix", "")),
        value.get("prune") is True,
        str(value.get("problem", "")),
        sources,
    )


def _save_backups(snapshot: DiscoverySnapshot, backups: tuple[ObservedBackup, ...]) -> None:
    from backups.integrity import record as record_integrity
    from backups.models import BackupObservation

    BackupObservation.objects.bulk_create(
        BackupObservation(
            snapshot=snapshot,
            identifier=backup.identifier,
            enabled=backup.enabled,
            profile=backup.profile,
            repository=backup.repository,
            server_key=backup.key,
            database=backup.database,
            database_problem=backup.database_problem,
            problems="\n".join(backup.problems),
            result_class=backup.last.result_class if backup.last else "",
            result_reason=backup.last.reason if backup.last else "",
            result_scope=backup.last.scope if backup.last else "",
            result_origin=backup.last.origin if backup.last else "",
            result_at=backup.last.at if backup.last else "",
            result_point=backup.last.point if backup.last else "",
            result_snapshots=backup.last.snapshots if backup.last else 0,
            result_bytes=backup.last.size if backup.last else 0,
            result_offsite=backup.last.offsite if backup.last else "",
            offsite=_offsite_document(backup.offsite),
            copy=(
                {
                    "class": backup.copy.result_class,
                    "reason": backup.copy.reason,
                    "point": backup.copy.point,
                    "at": backup.copy.at,
                }
                if backup.copy is not None
                else {}
            ),
        )
        for backup in backups
    )
    for backup in backups:
        record_integrity(snapshot.server, backup.identifier, backup.integrity)


class AttemptSnapshot(NamedTuple):
    attempt: DiscoveryAttempt
    snapshot: Snapshot | None


_OBSERVATION_ROWS = (
    "runtimes",
    "components",
    "components__service_units",
    "sites",
    "cache",
    "releases",
    "settings",
    "automation",
    "workers",
    "backups",
    "security__rules",
    "security__listeners",
    "security__pending_updates",
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
        cache=Observation(
            ObservationOutcome(row.cache_status),
            _reads(row.cache_source),
            row.cache_warning,
            tuple(_read_cache(item) for item in row.cache.all()),
        ),
        releases=Observation(
            ObservationOutcome(row.releases_status),
            _reads(row.releases_source),
            row.releases_warning,
            tuple(_read_release(release) for release in row.releases.all()),
        ),
        settings=Observation(
            ObservationOutcome(row.settings_status),
            _reads(row.settings_source),
            row.settings_warning,
            tuple(_read_setting(setting) for setting in row.settings.all()),
        ),
        automation=Observation(
            ObservationOutcome(row.automation_status),
            _reads(row.automation_source),
            row.automation_warning,
            tuple(_read_automation(automation) for automation in row.automation.all()),
        ),
        workers=Observation(
            ObservationOutcome(row.workers_status),
            _reads(row.workers_source),
            row.workers_warning,
            tuple(_read_worker(worker) for worker in row.workers.all()),
        ),
        backups=Observation(
            ObservationOutcome(row.backups_status),
            _reads(row.backups_source),
            row.backups_warning,
            tuple(_read_backup(backup) for backup in row.backups.all()),
        ),
        offsite=Observation(
            ObservationOutcome(row.offsite_status),
            _reads(row.offsite_source),
            row.offsite_warning,
            _read_offsite(row.offsite),
        ),
        security=_read_security(row),
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
                _read_pairs(row.host_profiles),
            )
            if row.host_standing
            else None
        ),
        certificate_email=row.certificate_email,
        certificate_email_state=row.certificate_email_state,
    )
    return Snapshot(collected, row.collected_at, ssh_alias, row.pk)


def _read_pairs(text: str) -> tuple[tuple[str, str], ...]:
    return tuple(
        (stage, state)
        for line in text.splitlines()
        if "\t" in line
        for stage, _, state in (line.partition("\t"),)
    )


def _read_cache(row: CacheObservation) -> ObservedCache:
    return ObservedCache(
        row.identifier,
        row.state,
        row.memory_mib,
        row.problem,
        row.plugin_version,
        row.client,
        row.unit_state,
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
        https=row.https,
        readiness=row.readiness,
        certificate=_read_certificate(row),
        pool=_read_pool(row),
        application=row.application,
        application_version=row.application_version,
        application_problem=row.application_problem,
        client=row.client,
        log_rotation=row.log_rotation,
    )


def _read_pool(row: SiteObservation) -> SitePool | None:
    if not row.pool_process_manager or row.pool_max_children is None:
        return None
    return SitePool(
        process_manager=row.pool_process_manager,
        max_children=row.pool_max_children,
        start_servers=row.pool_start_servers,
        min_spare_servers=row.pool_min_spare_servers,
        max_spare_servers=row.pool_max_spare_servers,
        process_idle_timeout=row.pool_process_idle_timeout,
        slowlog_timeout=row.pool_slowlog_timeout,
        terminate_timeout=row.pool_terminate_timeout,
        memory_limit=row.pool_memory_limit,
        upload_max_filesize=row.pool_upload_max_filesize,
        post_max_size=row.pool_post_max_size,
    )


def _read_certificate(row: SiteObservation) -> SiteCertificate | None:
    if not row.certificate_state:
        return None
    return SiteCertificate(
        state=row.certificate_state,
        issuer=row.certificate_issuer,
        not_after=row.certificate_not_after,
        error=row.certificate_error,
        names=tuple(row.certificate_names.splitlines()),
    )


def _read_setting(row: SettingObservation) -> ObservedSetting:
    return ObservedSetting(row.identifier, row.application, row.name, row.digest, row.value)


def _read_automation(row: object) -> ObservedSchedule:
    from automation.models import AutomationObservation
    from automation.status import ScheduleStatus

    if not isinstance(row, AutomationObservation):
        raise TypeError("Not an automation observation.")
    return ObservedSchedule(
        identifier=row.identifier,
        role=row.role,
        status=ScheduleStatus(row.status),
        problem=row.problem,
        duplicate=row.duplicate,
        disable_wp_cron=row.disable_wp_cron,
        installed=row.installed,
        timer_active=row.timer_active,
        timer_enabled=row.timer_enabled,
        service_active=row.service_active,
        masked=row.masked,
        result=row.result,
        exec_status=row.exec_status,
        last_start_us=row.last_start_us,
        last_exit_us=row.last_exit_us,
        last_trigger_us=row.last_trigger_us,
        next_elapse_us=row.next_elapse_us,
        slice_populated=row.slice_populated,
    )


def _read_security(row: DiscoverySnapshot) -> Observation[SecurityState | None]:
    from security.observation import (
        AutoUpdatesState,
        Check,
        FirewallRule,
        FirewallState,
        Listener,
        PendingUpdate,
        RestartState,
        SecurityState,
        SshState,
        UpdatesState,
    )

    try:
        stored = row.security
    except ObjectDoesNotExist:
        return Observation(ObservationOutcome.ABSENT, (), "", None)

    def check[T](status: str, source: str, warning: str, value: T | None) -> Check[T]:
        return Check(ObservationOutcome(status), _reads(source), warning, value)

    firewall = FirewallState(
        stored.ufw_installed,
        stored.ufw_enabled,
        stored.default_incoming,
        stored.default_outgoing,
        stored.default_routed,
        stored.ipv6,
        stored.logging,
        tuple(
            FirewallRule(
                rule.kind,
                rule.line,
                rule.action,
                rule.protocol,
                rule.ports,
                rule.network,
            )
            for rule in stored.rules.all()
        ),
        tuple(line for line in stored.outside.splitlines() if line),
        stored.firewall_conffiles_intact,
    )
    ssh = SshState(
        stored.password_authentication,
        stored.keyboard_interactive,
        stored.permit_root_login,
        tuple(int(port) for port in stored.ssh_ports.splitlines() if port.isdigit()),
        tuple(int(port) for port in stored.socket_ports.splitlines() if port.isdigit()),
        tuple(line for line in stored.accounts_without_keys.splitlines() if line),
        stored.per_source_penalties,
    )
    auto = AutoUpdatesState(
        stored.auto_updates_enabled is True,
        stored.list_update_timer,
        stored.upgrade_timer,
        stored.automatic_reboot,
        tuple(line for line in stored.allowed_origins.splitlines() if line),
        stored.conffile_matches,
        stored.last_upgrade,
        stored.newest_log_age,
    )
    updates = UpdatesState(
        stored.list_age_seconds,
        tuple(
            PendingUpdate(
                update.name,
                update.installed,
                update.candidate,
                update.archive,
                update.classification,
            )
            for update in stored.pending_updates.all()
        ),
    )
    restart = RestartState(
        stored.restart_required is True,
        tuple(line for line in stored.restart_packages.splitlines() if line),
    )
    listed = tuple(
        Listener(
            listener.address,
            listener.port,
            listener.protocol,
            listener.process,
            listener.public,
        )
        for listener in stored.listeners.all()
    )
    return Observation(
        ObservationOutcome.OBSERVED,
        _reads(stored.source),
        "",
        SecurityState(
            check(stored.firewall_status, stored.firewall_source, stored.firewall_warning, firewall)
            if stored.firewall_status == ObservationOutcome.OBSERVED
            else check(
                stored.firewall_status, stored.firewall_source, stored.firewall_warning, None
            ),
            check(
                stored.listeners_status, stored.listeners_source, stored.listeners_warning, listed
            )
            if stored.listeners_status == ObservationOutcome.OBSERVED
            else check(
                stored.listeners_status, stored.listeners_source, stored.listeners_warning, None
            ),
            check(stored.ssh_status, stored.ssh_source, stored.ssh_warning, ssh)
            if stored.ssh_status == ObservationOutcome.OBSERVED
            else check(stored.ssh_status, stored.ssh_source, stored.ssh_warning, None),
            check(
                stored.auto_updates_status,
                stored.auto_updates_source,
                stored.auto_updates_warning,
                auto,
            )
            if stored.auto_updates_status == ObservationOutcome.OBSERVED
            else check(
                stored.auto_updates_status,
                stored.auto_updates_source,
                stored.auto_updates_warning,
                None,
            ),
            check(stored.updates_status, stored.updates_source, stored.updates_warning, updates)
            if stored.updates_status == ObservationOutcome.OBSERVED
            else check(stored.updates_status, stored.updates_source, stored.updates_warning, None),
            check(stored.restart_status, stored.restart_source, stored.restart_warning, restart)
            if stored.restart_status == ObservationOutcome.OBSERVED
            else check(stored.restart_status, stored.restart_source, stored.restart_warning, None),
        ),
    )


def _read_backup(row: object) -> ObservedBackup:
    from backups.models import BackupObservation
    from backups.observation import BackupResult
    from backups.observation import ObservedBackup as Current

    if not isinstance(row, BackupObservation):
        raise TypeError("Not a backup observation.")
    from backups.observation import OffsiteCopy

    last = (
        BackupResult(
            row.result_class,
            row.result_reason,
            row.result_scope,
            row.result_origin,
            row.result_at,
            row.result_point,
            row.result_snapshots,
            row.result_bytes,
            row.result_offsite,
        )
        if row.result_class
        else None
    )
    copy = (
        OffsiteCopy(
            str(row.copy.get("class", "")),
            str(row.copy.get("reason", "")),
            str(row.copy.get("point", "")),
            str(row.copy.get("at", "")),
        )
        if row.copy
        else None
    )
    return Current(
        row.identifier,
        row.profile,
        row.repository,
        row.server_key,
        tuple(problem for problem in row.problems.splitlines() if problem),
        row.database,
        row.database_problem,
        last,
        _read_offsite(row.offsite),
        copy,
    )


def _read_worker(row: object) -> ObservedWorker:
    from automation.models import WorkerObservation
    from automation.worker_status import WorkerStatus

    if not isinstance(row, WorkerObservation):
        raise TypeError("Not a queue-worker observation.")
    definition = (
        WorkerDefinition(
            tuple(line for line in row.queues.splitlines() if line),
            row.processes,
            row.timeout,
        )
        if row.queues and row.timeout
        else None
    )
    return ObservedWorker(
        identifier=row.identifier,
        status=WorkerStatus(row.status),
        definition=definition,
        processes=row.processes,
        active_processes=row.active_processes,
        installed=row.installed,
        enabled=row.enabled,
        masked=row.masked,
        result=row.result,
        exec_status=row.exec_status,
        start_limited=row.start_limited,
        last_start_us=row.last_start_us,
        last_exit_us=row.last_exit_us,
        nrestarts=row.nrestarts,
        slice_populated=row.slice_populated,
        duplicate=row.duplicate,
        problem=row.problem,
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
