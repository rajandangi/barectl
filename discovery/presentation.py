"""The one place an observation is named and worded for the operator.

The server page and the warnings Activity lists agree because both come from here; a new
kind of observation is presented here, and templates only lay it out.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import NamedTuple

from django.template.defaultfilters import filesizeformat

from .models import DatabaseEngine, ObservationOutcome, SiteState
from .snapshot import (
    CollectedSnapshot,
    FilesystemSize,
    Observation,
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
        database_engine=site.database.engine
        if site.database is not None and site.database.conforms
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
    return "Not following the convention."


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
        verdict = f"{engine} binding, differs from the convention"
    elif database.outcome == ObservationOutcome.ABSENT:
        verdict = "None"
    else:
        verdict = database.outcome.label
    facts = (
        ("Principal", database.principal),
        ("Database", database.database),
        ("Owner", database.owner),
        ("Authentication", _authentication(database)),
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
    )


def _authentication(database: ObservedDatabase) -> str:
    if database.authentication_line is None:
        return database.authentication
    return f"{database.authentication}, pg_hba.conf line {database.authentication_line}"


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
        Fact("State", site.state.label),
        Fact("File", site.file) if site.file else Fact("File", NOT_READ),
        Fact(
            "Site user",
            f"UID {account.uid}, GID {account.gid}, home {account.home}, shell {account.shell}"
            if account
            else NOT_READ,
        ),
    )
