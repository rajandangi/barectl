"""The one place an observation is named and worded for the operator.

The server page and the warnings Activity lists agree because both come from here; a new
kind of observation is presented here, and templates only lay it out.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import NamedTuple

from django.template.defaultfilters import filesizeformat

from .models import (
    ApplicationState,
    ConfigurationState,
    CoreQualification,
    DatabaseEngine,
    LoaderState,
    ObservationOutcome,
    SchemaState,
    SiteRouting,
    SiteStage,
    SiteState,
)
from .snapshot import (
    CollectedSnapshot,
    FilesystemSize,
    Observation,
    ObservedApplication,
    ObservedDatabase,
    ObservedSite,
    OsRelease,
    ServiceUnit,
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
    # Whether the installed packages follow the release's bootstrap profile.
    managed: bool = True
    # The packages outside the profile, and PostgreSQL majors or clusters it does not
    # support, each with what to remove or change.
    deviations: tuple[str, ...] = ()


@dataclass(frozen=True)
class SnapshotPresentation:
    """Every observation of a snapshot as the server page shows it, in display order."""

    os: ShownObservation
    os_facts: tuple[Fact, ...]
    capacity: tuple[ShownObservation, ...]
    components: tuple[ShownComponent, ...]

    @property
    def observations(self) -> list[ShownObservation]:
        shown = [self.os, *self.capacity]
        for component in self.components:
            shown += [component.package, component.service]
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
    packages += observed.deviations
    # A partial service observation keeps the units it read; they are shown beside its alert.
    units = tuple(_unit_line(unit) for unit in service.value) or (
        f"Service units: {service.outcome.label}",
    )
    return ShownComponent(
        name,
        _shown(f"{name} packages", package, packages),
        _shown(f"{name} service units", service, units),
        observed.managed,
        observed.deviations,
    )


def _unit_line(unit: ServiceUnit) -> str:
    # systemd found no unit to load, so its other states describe nothing.
    if unit.load_state == "not-found":
        return f"{unit.name} not found"
    line = f"{unit.name} {unit.active_state} ({unit.sub_state})"
    return f"{line}, {unit.unit_file_state}" if unit.unit_file_state else line


def _distinct(sources: Iterable[tuple[str, ...]]) -> list[str]:
    return list(dict.fromkeys(read for source in sources for read in source))


# docs/ssh-connections.md#site-observations
VIEW_SITES = "discovery.view_siteobservation"
SITES_NOTE = (
    "A site observation has one state: managed, partly applied, changed outside Barectl, or "
    "not following the convention. Barectl does not read sudo rules, and a state is not a "
    "check that the site serves requests."
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
    # The site's database entry, which shows a warning that is no alert as a note and has
    # no source when it was not collected.
    database: bool = False
    # The site's certificate entry, with the same presentation rules as the database.
    certificate: bool = False
    # Whether the resource was observed, so a control knows it is present.
    present: bool = False
    # Whether a partly applied binding can be finished (docs/databases.md).
    partial: bool = False


@dataclass(frozen=True)
class ShownSite:
    identifier: str
    # The site's observed server names, so aliases lead and stay one site.
    domains: tuple[str, ...]
    php_version: str
    state: SiteState
    # The one state, worded for the operator; the observation outcome when not observed.
    verdict: str
    summary: str
    # The first differing file, or the file of a blocked item; empty for a managed site.
    file: str
    # The content Barectl expects at the changed file; empty when there is none.
    expected: str
    # The convention resources that are absent.
    missing: tuple[str, ...]
    facts: tuple[Fact, ...]
    # The site's optional database binding, which the convention summary does not count.
    database: ShownResource
    # The site's optional certificate, which the convention summary does not count.
    certificate: ShownResource
    # Whether the site is managed, so a change control knows it is eligible.
    complete: bool = False
    # Inaccessible or unsupported evidence, not drift from the convention.
    unread: bool = False
    # The engine of a binding that follows the database convention, so its connection
    # guidance (docs/databases.md#connecting) applies; None otherwise.
    database_engine: DatabaseEngine | None = None
    # The engine of a partly applied binding, so the page can offer to finish it.
    database_partial_engine: DatabaseEngine | None = None
    finishable: bool = False
    convention_revision: int = 3


@dataclass(frozen=True)
class ShownSites:
    """Site observations, which only accounts allowed to view them are shown."""

    observation: ShownObservation
    sites: tuple[ShownSite, ...]
    note: str = SITES_NOTE


def present_sites(sites: Observation[tuple[ObservedSite, ...]]) -> ShownSites:
    return ShownSites(_shown("Sites", sites, ()), tuple(_site(site) for site in sites.value))


def _site(site: ObservedSite) -> ShownSite:
    unread = site.outcome in UNINSPECTED
    verdict = site.outcome.label if unread else site.state.label
    return ShownSite(
        site.identifier,
        site.server_names,
        site.php_version,
        site.state,
        verdict,
        _summary(site, unread),
        site.file,
        site.expected,
        site.missing,
        _site_facts(site),
        _site_database(site.database),
        _site_certificate(site),
        complete=site.state == SiteState.MANAGED and site.outcome == ObservationOutcome.OBSERVED,
        unread=unread,
        convention_revision=site.convention_revision,
        finishable=(
            site.outcome == ObservationOutcome.OBSERVED
            and site.state == SiteState.PARTLY_APPLIED
            and site.stage == SiteStage.HTTP
        ),
        database_engine=site.database.engine
        if site.database is not None and site.database.conforms
        else None,
        database_partial_engine=site.database.engine
        if site.database is not None and site.database.partial
        else None,
    )


def _summary(site: ObservedSite, unread: bool) -> str:
    if unread:
        return "Not confirmed against the supported site convention."
    if site.state == SiteState.MANAGED:
        return "Matches the supported site convention."
    if site.state == SiteState.PARTLY_APPLIED:
        return "Partly applied: some of the site's convention resources are missing."
    if site.state == SiteState.CHANGED:
        return "Changed outside Barectl: a resource no longer matches the convention."
    return (
        "Not following the convention. Barectl expects a site identifier with exact "
        "Nginx and PHP-FPM files named <identifier>.conf, a dedicated site account "
        "and the supported directory layout. Bring the configuration into that "
        "convention through ordinary administration, then run discovery again."
    )


# docs/ssh-connections.md#site-database-observations
DATABASE_NOT_COLLECTED = "Not collected by this version of Barectl"


def _site_database(database: ObservedDatabase | None) -> ShownResource:
    if database is None:
        return ShownResource(
            "Database", "", DATABASE_NOT_COLLECTED, (), (), "", alert=False, database=True
        )
    engine = database.engine.label if database.engine else ""
    if database.conforms:
        verdict = f"{engine} binding, as the convention requires"
    elif database.outcome == ObservationOutcome.OBSERVED:
        verdict = f"{engine} binding, does not follow the convention"
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
        database=True,
        present=database.outcome == ObservationOutcome.OBSERVED,
        partial=database.partial,
    )


# docs/v0.3.md#tls-preparation-issuance-and-renewal
CERTIFICATE_NOT_COLLECTED = "Not collected by this version of Barectl"
CERTIFICATE_NOT_ACTIVATED = "Not activated"


def _site_certificate(site: ObservedSite) -> ShownResource:
    certificate = site.certificate
    if certificate is None:
        verdict = (
            CERTIFICATE_NOT_ACTIVATED if not site.stage.activated else CERTIFICATE_NOT_COLLECTED
        )
        return ShownResource("Certificate", "", verdict, (), (), "", alert=False, certificate=True)
    if certificate.conforms:
        verdict = "Observed, as the convention requires"
    elif certificate.outcome == ObservationOutcome.OBSERVED:
        verdict = "Observed, differs from the convention"
    elif certificate.outcome == ObservationOutcome.ABSENT:
        verdict = "None"
    else:
        verdict = certificate.outcome.label
    facts = (
        ("Nginx reference", site.certificate_reference),
        ("Nginx key reference", site.certificate_key_reference),
        ("Issuer", certificate.issuer),
        ("Expires", certificate.not_after),
        ("SHA-256 fingerprint", certificate.fingerprint),
        ("Names", ", ".join(certificate.names)),
        ("Renewal configuration", certificate.renewal),
        *(
            (f"Served fingerprint for {item.name}", item.fingerprint or "Not read")
            for item in certificate.served
        ),
    )
    return ShownResource(
        "Certificate",
        "",
        verdict,
        tuple(f"{label}: {value}" for label, value in facts if value),
        certificate.source,
        certificate.warning,
        alert=bool(certificate.warning)
        and not certificate.conforms
        and certificate.outcome != ObservationOutcome.ABSENT,
        certificate=True,
        present=certificate.outcome == ObservationOutcome.OBSERVED,
    )


def _site_facts(site: ObservedSite) -> tuple[Fact, ...]:
    account = site.account
    return (
        Fact("Server names", ", ".join(site.server_names) or NOT_READ),
        Fact("PHP version", site.php_version or NOT_READ),
        Fact("State", site.outcome.label if site.outcome in UNINSPECTED else site.state.label),
        Fact("File", site.file) if site.file else Fact("File", NOT_READ),
        Fact(
            "Site user",
            f"UID {account.uid}, GID {account.gid}, home {account.home}, shell {account.shell}"
            if account
            else NOT_READ,
        ),
    )


# docs/wordpress.md#passive-application-discovery
VIEW_APPLICATIONS = "discovery.view_siteapplicationobservation"
APPLICATION_NOT_COLLECTED = "Not collected by this version of Barectl"
_APPLICATION_SUMMARIES = {
    ApplicationState.ABSENT: "No WordPress application evidence was found on this site.",
    ApplicationState.CANDIDATE: (
        "WordPress release files are present, but nothing else confirms an installation. "
        "File presence alone is only a candidate."
    ),
    ApplicationState.PARTIAL: (
        "Some of the WordPress application's resources exist, but the evidence is incomplete."
    ),
    ApplicationState.INSTALLED: (
        "The files, private configuration, database binding, core tables and canonical "
        "options match the supported WordPress application."
    ),
    ApplicationState.BLOCKED: (
        "A resource was edited or is ambiguous, so actions that depend on the application "
        "are blocked until ordinary administration restores the supported form."
    ),
    ApplicationState.UNREADABLE: (
        "Barectl could not read all the evidence it needs. That is neither absence nor "
        "proof of an installation."
    ),
}
_QUALIFICATION_LINES = {
    CoreQualification.NOT_OBSERVED: "",
    CoreQualification.QUALIFIED: "The qualified release.",
    CoreQualification.NEWER: (
        "Newer than the qualified release: reported as found, never downgraded. Installation "
        "and maintenance need the qualified pair."
    ),
    CoreQualification.OLDER: "Older than the qualified release.",
    CoreQualification.UNRECOGNIZED: "Not a release version.",
}
_ROUTING_LINES = {
    SiteRouting.UNRECOGNIZED: "The site file is not a convention form, so its routing is unknown.",
    SiteRouting.PHP: "Generic PHP routing: no WordPress front controller.",
    SiteRouting.WORDPRESS_GATE: (
        "WordPress behind the provisioning gate: application paths answer 503."
    ),
    SiteRouting.WORDPRESS: "WordPress routing: front controller and upload restrictions.",
}


@dataclass(frozen=True)
class ShownApplication:
    """A site's WordPress evidence, worded for accounts allowed to view it."""

    state: ApplicationState
    verdict: str
    summary: str
    facts: tuple[Fact, ...]
    blocked: tuple[str, ...]
    limits: tuple[str, ...]
    warning: str
    source: tuple[str, ...]
    # False for a snapshot collected before application evidence was observed.
    collected: bool = True


def present_application(site: ObservedSite) -> ShownApplication:
    application = site.application
    if application is None:
        return ShownApplication(
            ApplicationState.UNREADABLE,
            APPLICATION_NOT_COLLECTED,
            "",
            (),
            (),
            (),
            "",
            (),
            collected=False,
        )
    return ShownApplication(
        application.state,
        application.state.label,
        _APPLICATION_SUMMARIES[application.state],
        _application_facts(site, application),
        application.blocked,
        application.limits,
        application.warning,
        application.source,
    )


def _application_facts(site: ObservedSite, application: ObservedApplication) -> tuple[Fact, ...]:
    version = application.core_version
    release = (
        f"{version}. {_QUALIFICATION_LINES[application.qualification]}".strip() if version else ""
    )
    facts = [
        Fact("Routing", _ROUTING_LINES[site.routing]),
        Fact("Canonical name", site.canonical_name or "None recorded"),
        Fact("Core version", release or NOT_READ),
        Fact("Release files", f"{application.markers_present} of {application.markers_total}"),
        Fact("Public loader", _LOADER_LINES.get(application.loader, NOT_READ)),
        Fact("Private configuration", _configuration_line(application)),
        Fact("Core tables", _schema_line(application)),
    ]
    if application.site_url or application.home_url:
        facts += [
            Fact("siteurl", application.site_url or NOT_READ),
            Fact("home", application.home_url or NOT_READ),
        ]
    return tuple(facts)


_LOADER_LINES = {
    LoaderState.ABSENT: "Absent",
    LoaderState.EXACT: "The fixed loader",
    LoaderState.OTHER: "Not the fixed loader",
}


def _configuration_line(application: ObservedApplication) -> str:
    match application.configuration:
        case ConfigurationState.SUPPORTED:
            return f"Supported grammar, SHA-256 {application.configuration_digest}"
        case ConfigurationState.ABSENT:
            return "Absent"
        case ConfigurationState.UNSUPPORTED:
            return "Not the supported grammar"
        case _:
            return NOT_READ


def _schema_line(application: ObservedApplication) -> str:
    match application.schema:
        case SchemaState.COMPLETE:
            return f"All {application.tables_present} core tables with their required columns"
        case SchemaState.PARTIAL:
            return f"{application.tables_present} core tables"
        case SchemaState.ALTERED:
            return "Altered or ambiguous"
        case SchemaState.ABSENT:
            return "No core tables"
        case _:
            return NOT_READ
