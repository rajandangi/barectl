"""The one place an observation is named and worded for the operator.

The server page and the warnings Activity lists agree because both come from here; a new
kind of observation is presented here, and templates only lay it out.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import NamedTuple

from django.template.defaultfilters import filesizeformat

from bootstrap.standing import HostJudgment

from .models import (
    ObservationOutcome,
    SiteState,
)
from .snapshot import (
    CollectedSnapshot,
    FilesystemSize,
    Observation,
    ObservedRelease,
    ObservedSite,
    OsRelease,
    ServiceUnit,
    SiteCertificate,
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
    standing: HostJudgment | None = None

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
        standing=collected.standing,
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
    "A site observation has one state: managed, partly applied, or not following the "
    "convention. Barectl does not read sudo rules, and a state is not a "
    "check that the site serves requests."
)
NOT_READ = "Not read"


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
    # The convention resources that are absent.
    missing: tuple[str, ...]
    facts: tuple[Fact, ...]
    # Whether the site is managed, so a change control knows it is eligible.
    complete: bool = False
    # Inaccessible or unsupported evidence, not drift from the convention.
    unread: bool = False


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
        site.missing,
        _site_facts(site),
        complete=site.state == SiteState.MANAGED and site.outcome == ObservationOutcome.OBSERVED,
        unread=unread,
    )


def _summary(site: ObservedSite, unread: bool) -> str:
    if unread:
        return "Not confirmed against the supported site convention."
    if site.state == SiteState.MANAGED:
        return "Matches the supported site convention."
    if site.state == SiteState.PARTLY_APPLIED:
        return "Partly applied: some of the site's convention resources are missing."
    return (
        "Not following the convention. Review the site's Caddy route, PHP pool, "
        "account and release layout through ordinary administration, then run discovery again."
    )


def _site_facts(site: ObservedSite) -> tuple[Fact, ...]:
    account = site.account
    return (
        Fact("Server names", ", ".join(site.server_names) or NOT_READ),
        Fact("PHP version", site.php_version or NOT_READ),
        Fact("HTTPS", "On" if site.https else "Off"),
        Fact("Readiness path", site.readiness),
        Fact("Application", _application(site)),
        Fact("Certificate", _certificate(site.certificate)),
        Fact("State", site.outcome.label if site.outcome in UNINSPECTED else site.state.label),
        Fact("File", site.file) if site.file else Fact("File", NOT_READ),
        Fact(
            "Site user",
            f"UID {account.uid}, GID {account.gid}, home {account.home}, shell {account.shell}"
            if account
            else NOT_READ,
        ),
    )


def _application(site: ObservedSite) -> str:
    if site.application == "wordpress":
        return f"WordPress {site.application_version}"
    if site.application == "wordpress_partial":
        return f"WordPress partly applied: {site.application_problem}"
    return "Plain PHP"


def _certificate(certificate: SiteCertificate | None) -> str:
    if certificate is None:
        return NOT_READ
    if certificate.state == "http":
        return "Not used (HTTP only)"
    if certificate.state == "waiting":
        return "Waiting for DNS and issuance"
    if certificate.state == "failing":
        return f"Caddy reports: {certificate.error}" if certificate.error else "Failing"
    detail = certificate.issuer or "an unknown issuer"
    expires = _expiry(certificate.not_after)
    if certificate.state == "renewal_due":
        return f"Renewal due: issued by {detail}, expires {expires}"
    return f"Issued by {detail}, expires {expires}"


def _expiry(not_after: int) -> str:
    if not_after <= 0:
        return NOT_READ
    try:
        from datetime import UTC, datetime

        return datetime.fromtimestamp(not_after, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
    except OverflowError, OSError, ValueError:
        return NOT_READ


@dataclass(frozen=True)
class ShownRelease:
    """One retained release of a site, for the Deployments section."""

    name: str
    commit: str
    created: str
    state: str
    current: bool


def present_releases(
    releases: Observation[tuple[ObservedRelease, ...]], identifier: str
) -> tuple[ShownRelease, ...]:
    """The site's releases, current first, newest first otherwise."""
    rows = [release for release in releases.value if release.identifier == identifier]
    rows.sort(key=lambda release: (not release.current, -release.created, release.name))
    return tuple(
        ShownRelease(
            release.name,
            release.commit[:12],
            _created(release.created),
            SiteState(release.state).label,
            release.current,
        )
        for release in rows
    )


def _created(seconds: int) -> str:
    if seconds <= 0:
        return NOT_READ
    try:
        from datetime import UTC, datetime

        return datetime.fromtimestamp(seconds, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
    except OverflowError, OSError, ValueError:
        return NOT_READ
