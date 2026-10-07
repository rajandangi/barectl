"""Web-stack component observations: installed packages and their service units."""

import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass, replace

from bootstrap.models import Action
from bootstrap.profiles import PROFILES

from ..models import ObservationOutcome, WebStackComponent
from ..releases import SupportedRelease
from ..snapshot import Observation, Package, ServiceUnit, WebStackComponentObservation
from ..ssh import RemoteShell
from .probes import (
    _Failed,
    _list_directory,
    _listing_command,
    _outside_layout,
    _run,
    _test,
)


def _collect_web_stack(
    shell: RemoteShell, release: SupportedRelease | None
) -> tuple[WebStackComponentObservation, ...]:
    installed = _installed_packages(shell, release)
    return tuple(_observe_component(shell, spec, installed, release) for spec in COMPONENT_SPECS)


def _observe_component(
    shell: RemoteShell,
    spec: _ComponentSpec,
    installed: _Packages | _Failed,
    release: SupportedRelease | None,
) -> WebStackComponentObservation:
    package, deviations = _package_observation(spec, installed, release)
    service, service_deviations = _observe_service(shell, spec, package, release)
    all_deviations = (*deviations, *service_deviations)
    return WebStackComponentObservation(
        spec.component,
        package,
        service,
        managed=not all_deviations,
        deviations=all_deviations,
    )


def _observe_service(
    shell: RemoteShell,
    spec: _ComponentSpec,
    package: Observation[tuple[Package, ...]],
    release: SupportedRelease | None,
) -> tuple[Observation[tuple[ServiceUnit, ...]], tuple[str, ...]]:
    if package.outcome != ObservationOutcome.OBSERVED:
        return Observation(package.outcome, package.source, package.warning, ()), ()
    if not package.value:
        return Observation(ObservationOutcome.ABSENT, package.source, "", ()), ()
    result = spec.service(shell, package.value, release)
    return result.observation, result.deviations


def _observe_installed[T](
    package: Observation[tuple[Package, ...]],
    collect: Callable[[tuple[Package, ...]], Observation[tuple[T, ...]]],
) -> Observation[tuple[T, ...]]:
    """docs/adr/0001-configuration-observations-depend-on-package-observation.md"""
    if package.outcome != ObservationOutcome.OBSERVED:
        return Observation(package.outcome, package.source, package.warning, ())
    return collect(package.value)


# docs/adr/0015-recognize-only-the-convention.md
_COMPONENT_ACTIONS = {
    WebStackComponent.NGINX: Action.NGINX,
    WebStackComponent.PHP_FPM: Action.PHP,
    WebStackComponent.MARIADB: Action.MARIADB,
    WebStackComponent.POSTGRESQL: Action.POSTGRESQL,
    WebStackComponent.CERTBOT: Action.CERTBOT,
}


def _profile_packages(release: SupportedRelease | None, spec: _ComponentSpec) -> frozenset[str]:
    """The release profile's exact package names that this component observes.

    An unsupported release has no profile; every supported release's names are then
    accepted, and the release itself is reported elsewhere.
    """
    versions = (release.version,) if release is not None else tuple(PROFILES)
    return frozenset(
        name
        for version in versions
        for name in PROFILES[version][_COMPONENT_ACTIONS[spec.component]].packages
        if spec.packages.fullmatch(name)
    )


def _outside_profile(spec: _ComponentSpec, release: SupportedRelease | None) -> str:
    action = _COMPONENT_ACTIONS[spec.component]
    if release is None:
        return f"any supported Ubuntu release's {action.label}"
    return f"the {release.name} {action.label}"


def _package_observation(
    spec: _ComponentSpec,
    installed: _Packages | _Failed,
    release: SupportedRelease | None,
) -> tuple[Observation[tuple[Package, ...]], tuple[str, ...]]:
    if isinstance(installed, _Failed):
        return Observation(installed.status, (installed.source,), installed.warning, ()), ()
    source = (installed.query, PACKAGE_NAMES_QUERY)
    profile = _profile_packages(release, spec)
    matched = sorted(
        name for name in installed.versions if name in profile and spec.packages.fullmatch(name)
    )
    outside = sorted(
        name for name in installed.names if spec.packages.fullmatch(name) and name not in profile
    )
    deviations = tuple(
        (
            f"{name} is installed but is not one of {_outside_profile(spec, release)} packages. "
            "Remove it, or replace it with the profile's package."
        )
        for name in outside
    )
    if not matched:
        return (
            Observation(
                ObservationOutcome.OBSERVED if outside else ObservationOutcome.ABSENT,
                source,
                f"The dpkg database lists no installed {spec.component.label} packages.",
                (),
            ),
            deviations,
        )
    packages = tuple(
        Package(name, version)
        for name in matched
        if (version := installed.versions[name]) is not None
    )
    if len(packages) != len(matched):
        return (
            Observation(
                ObservationOutcome.UNSUPPORTED,
                source,
                f"The dpkg database lists a {spec.component.label} package that is not fully "
                "installed, so Barectl does not report its version or service state.",
                (),
            ),
            deviations,
        )
    return Observation(ObservationOutcome.OBSERVED, source, "", packages), deviations


# https://manpages.debian.org/stable/dpkg/dpkg-query.1.en.html
# The status abbreviation: the selection (such as "i" install or "h" hold), the package
# state, and an optional "R" when the package needs reinstalling. Its trailing space is
# lost to whitespace splitting. "ii" is installed and "hi" installed and held; "un" is a
# package apt merely knows about, listed without a version.
PACKAGE_STATUS = re.compile(r"[uihrp][ncHUFWti]R?")
# Package states: installed, installed with triggers pending or awaited, and never or no
# longer installed ("c" keeps only configuration files). Any other state is unfinished.
INSTALLED_STATES = frozenset("iWt")
NOT_INSTALLED_STATES = frozenset("nc")

NO_DPKG_QUERY = (
    "The server has no dpkg-query command. Barectl reads package versions from the dpkg "
    "database and cannot inspect other installation formats."
)


@dataclass(frozen=True)
class _Packages:
    versions: dict[str, str | None]
    names: frozenset[str]
    query: str


def _package_query(release: SupportedRelease | None) -> str:
    names = sorted({name for spec in COMPONENT_SPECS for name in _profile_packages(release, spec)})
    return "dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\\n' " + " ".join(
        shlex.quote(name) for name in names
    )


def _installed_packages(
    shell: RemoteShell, release: SupportedRelease | None
) -> _Packages | _Failed:
    """The dpkg database's installed package versions by name, or why they could not be read.

    A package in an unfinished state, such as unpacked or half-configured, maps to ``None``:
    it is neither installed nor absent.
    """
    query = _package_query(release)
    # dpkg-query exits 1 when a queried package is absent, even while others are installed.
    output = _run(
        shell,
        query,
        accepted=frozenset((0, 1)),
        missing=NO_DPKG_QUERY,
    )
    if isinstance(output, _Failed):
        return output
    installed: dict[str, str | None] = {}
    for line in output.splitlines():
        match line.split():
            case [name, *version, status] if len(version) <= 1 and PACKAGE_STATUS.fullmatch(status):
                state = status[1]
                if state in INSTALLED_STATES and version:
                    installed[name] = version[0]
                elif state not in NOT_INSTALLED_STATES:
                    installed[name] = None
            case _:
                return _Failed(
                    ObservationOutcome.UNSUPPORTED,
                    f"{query} did not report package states in a supported format.",
                    query,
                )
    names_output = _run(shell, PACKAGE_NAMES_QUERY, missing=NO_DPKG_QUERY)
    if isinstance(names_output, _Failed):
        return names_output
    names: set[str] = set()
    for line in names_output.splitlines():
        match line.split():
            case [name, status] if PACKAGE_NAME.fullmatch(name) and PACKAGE_STATUS.fullmatch(
                status
            ):
                if status[1] not in NOT_INSTALLED_STATES:
                    names.add(name)
            case _:
                return _Failed(
                    ObservationOutcome.UNSUPPORTED,
                    f"{PACKAGE_NAMES_QUERY} did not report package states in a supported format.",
                    PACKAGE_NAMES_QUERY,
                )
    return _Packages(installed, frozenset(names), query)


# systemd reports these fixed tokens; anything else is not a supported format.
# https://www.freedesktop.org/software/systemd/man/latest/systemctl.html
LOAD_STATES = frozenset({"loaded", "not-found", "masked", "error", "bad-setting", "merged"})
ACTIVE_STATES = frozenset(
    {"active", "inactive", "failed", "activating", "deactivating", "reloading", "refreshing"}
)
UNIT_FILE_STATES = frozenset(
    {
        "enabled",
        "enabled-runtime",
        "disabled",
        "static",
        "generated",
        "transient",
        "indirect",
        "alias",
        "masked",
        "masked-runtime",
        "linked",
        "linked-runtime",
    }
)
UNIT_PROPERTY_MAX = 100
UNIT_NAME = re.compile(r"[A-Za-z0-9:@._-]{1,100}")
SUB_STATE = re.compile(r"[a-z-]{1,40}")

NO_SYSTEMCTL = "The server has no systemctl command, so Barectl cannot report service states."
SYSTEMCTL_UNAVAILABLE = (
    "Barectl could not read service states from systemd. The server may not be running "
    "systemd, or the SSH user may not be allowed to query it."
)
_SYSTEMCTL_FORMAT = "{} did not report service states in a supported format."
_UNIT_FORMAT = "systemctl did not report a service unit in a supported format."

_UNIT_PROPERTIES = ("Id", "LoadState", "ActiveState", "SubState", "UnitFileState")


def _unit_query(units: tuple[str, ...]) -> str:
    # PHP-FPM unit names derive from server-reported package names; quote them regardless.
    names = " ".join(shlex.quote(unit) for unit in units)
    properties = " ".join(f"-p {prop}" for prop in _UNIT_PROPERTIES)
    return f"systemctl show {names} {properties}"


def _observe_units(
    shell: RemoteShell, unit_names: tuple[str, ...]
) -> Observation[tuple[ServiceUnit, ...]]:
    command = _unit_query(unit_names)
    output = _run(
        shell,
        command,
        missing=NO_SYSTEMCTL,
        failed=SYSTEMCTL_UNAVAILABLE,
    )
    if isinstance(output, _Failed):
        return Observation(output.status, (command,), output.warning, ())
    records = _parse_unit_records(output)
    if not records:
        return Observation(
            ObservationOutcome.UNSUPPORTED, (command,), _SYSTEMCTL_FORMAT.format(command), ()
        )
    units: list[ServiceUnit] = []
    for queried, record in zip(unit_names, records, strict=False):
        unit = _service_unit(record)
        # An alias reports the unit it resolves to under another name, which is unsupported
        # rather than shown under the queried name.
        if unit is None or unit.name != queried:
            # The unit's reported name is server data, so the warning names no unit.
            return Observation(
                ObservationOutcome.UNSUPPORTED, (command,), _UNIT_FORMAT, tuple(units)
            )
        units.append(unit)
    if len(records) != len(unit_names):
        return Observation(ObservationOutcome.UNSUPPORTED, (command,), _UNIT_FORMAT, tuple(units))
    return Observation(ObservationOutcome.OBSERVED, (command,), "", tuple(units))


def _parse_unit_records(output: str) -> list[dict[str, str]] | None:
    """Split ``Prop=Value`` lines into per-unit records, or ``None`` when malformed.

    systemctl separates the records of several units with an empty line.
    """
    records: list[dict[str, str]] = []
    for line in output.splitlines():
        if not line:
            continue
        prop, separator, value = line.partition("=")
        if not separator or prop not in _UNIT_PROPERTIES or len(value) > UNIT_PROPERTY_MAX:
            return None
        if prop == "Id":
            records.append({"Id": value})
        elif records:
            records[-1][prop] = value
    return records


def _service_unit(record: dict[str, str]) -> ServiceUnit | None:
    unit = ServiceUnit(
        record.get("Id", ""),
        record.get("LoadState", ""),
        record.get("ActiveState", ""),
        record.get("SubState", ""),
        record.get("UnitFileState", ""),
    )
    if (
        UNIT_NAME.fullmatch(unit.name) is None
        or unit.load_state not in LOAD_STATES
        or unit.active_state not in ACTIVE_STATES
        or SUB_STATE.fullmatch(unit.sub_state) is None
        or (unit.unit_file_state and unit.unit_file_state not in UNIT_FILE_STATES)
    ):
        return None
    return unit


# docs/ssh-connections.md#postgresql-clusters
POSTGRESQL_CONF_ROOT = "/etc/postgresql"
POSTGRESQL_UMBRELLA = "postgresql.service"
POSTGRESQL_VERSION = re.compile(r"[0-9]{1,4}\.?[0-9]{1,4}")
# pg_createcluster accepts word characters, "." and "-". Barectl accepts their ASCII
# forms, which systemd unit names can hold without escaping.
CLUSTER_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
MAIN_CLUSTER = "main"


@dataclass(frozen=True)
class _MainCluster:
    """The release default major's main cluster, and what does not follow the profile.

    Other majors and clusters are named as deviations and never probed. ``failure`` records
    why the layout could not be read; ``units`` still holds what was found.
    """

    units: tuple[str, ...]
    commands: tuple[str, ...]
    deviations: tuple[str, ...]
    failure: _Failed | None


def _main_cluster(shell: RemoteShell, release: SupportedRelease) -> _MainCluster:
    """The release major's main cluster's unit, without scanning other majors or clusters."""
    major = release.postgresql
    directory = f"{POSTGRESQL_CONF_ROOT}/{major}"
    commands = [_listing_command(POSTGRESQL_CONF_ROOT)]
    listed = _list_directory(shell, POSTGRESQL_CONF_ROOT)
    if isinstance(listed, _Failed):
        return _MainCluster((), tuple(commands), (), _outside_layout(listed))
    deviations = [
        (
            f"PostgreSQL {version} is installed under {POSTGRESQL_CONF_ROOT}, but "
            f"{release.name} supports only PostgreSQL {major}. Barectl does not read it."
        )
        for version in sorted(e for e in listed if POSTGRESQL_VERSION.fullmatch(e))
        if version != major
    ]
    commands.append(_listing_command(directory, hidden=True))
    entries = _list_directory(shell, directory, hidden=True)
    if isinstance(entries, _Failed):
        return _MainCluster((), tuple(commands), tuple(deviations), _outside_layout(entries))
    names = [entry for entry in entries if CLUSTER_NAME.fullmatch(entry)]
    if skipped := len(entries) - len(names):
        # The names are server data; only the count is reported.
        deviations.append(
            f"{directory} lists {skipped} entries whose names Barectl does not support. "
            "They were not read."
        )
    deviations += [
        (
            f"PostgreSQL has cluster {name} under {directory}, but the profile supports only "
            "its main cluster. Barectl does not read it."
        )
        for name in sorted(names)
        if name != MAIN_CLUSTER
    ]
    conf = f"{directory}/{MAIN_CLUSTER}/postgresql.conf"
    units: tuple[str, ...] = ()
    if MAIN_CLUSTER in names and (_test(shell, "-e", conf) or _test(shell, "-L", conf)):
        units = (f"postgresql@{major}-{MAIN_CLUSTER}.service",)
    else:
        deviations.append(
            f"{release.name} PostgreSQL {major} has no main cluster under {directory}."
        )
    return _MainCluster(units, tuple(commands), tuple(deviations), None)


def _with_main_cluster(
    units: Observation[tuple[ServiceUnit, ...]], clusters: _MainCluster
) -> Observation[tuple[ServiceUnit, ...]]:
    """docs/ssh-connections.md#postgresql-clusters"""
    source = (*clusters.commands, *units.source)
    if clusters.failure is None:
        return replace(units, source=source)
    if units.outcome != ObservationOutcome.OBSERVED:
        # The unit query's failure explains the outcome; the listing's is added.
        warning = f"{units.warning} {clusters.failure.warning}"
        return replace(units, source=source, warning=warning)
    return Observation(clusters.failure.status, source, clusters.failure.warning, units.value)


@dataclass(frozen=True)
class _ServiceObservation:
    observation: Observation[tuple[ServiceUnit, ...]]
    deviations: tuple[str, ...] = ()


type _ServiceRule = Callable[
    [RemoteShell, tuple[Package, ...], SupportedRelease | None], _ServiceObservation
]


def _fixed_unit(unit: str) -> _ServiceRule:
    """The component runs as one documented unit, whatever packages provide it."""
    return lambda shell, _packages, _release: _ServiceObservation(_observe_units(shell, (unit,)))


def _unit_per_package(
    shell: RemoteShell, _packages: tuple[Package, ...], release: SupportedRelease | None
) -> _ServiceObservation:
    if release is None:
        return _ServiceObservation(
            Observation(
                ObservationOutcome.UNSUPPORTED,
                (),
                "The server is not a supported release, so Barectl does not know its default PHP.",
                (),
            )
        )
    return _ServiceObservation(_observe_units(shell, (f"php{release.php}-fpm.service",)))


def _umbrella_and_clusters(
    shell: RemoteShell,
    _packages: tuple[Package, ...],
    release: SupportedRelease | None,
) -> _ServiceObservation:
    if release is None:
        return _ServiceObservation(_observe_units(shell, (POSTGRESQL_UMBRELLA,)))
    clusters = _main_cluster(shell, release)
    units = (POSTGRESQL_UMBRELLA, *clusters.units)
    return _ServiceObservation(
        _with_main_cluster(_observe_units(shell, units), clusters), clusters.deviations
    )


@dataclass(frozen=True)
class _ComponentSpec:
    component: WebStackComponent
    # The package names, as the patterns report them, that belong to the component.
    packages: re.Pattern[str]
    service: _ServiceRule


# docs/ssh-connections.md#component-observations
COMPONENT_SPECS = (
    _ComponentSpec(WebStackComponent.NGINX, re.compile(r"nginx"), _fixed_unit("nginx.service")),
    _ComponentSpec(WebStackComponent.PHP_FPM, re.compile(r"php[0-9.]*-fpm"), _unit_per_package),
    _ComponentSpec(
        WebStackComponent.MARIADB,
        re.compile(r"mariadb-server(-core)?(-[0-9.]+)?"),
        _fixed_unit("mariadb.service"),
    ),
    _ComponentSpec(
        WebStackComponent.POSTGRESQL,
        re.compile(r"postgresql(-[0-9.]+)?"),
        _umbrella_and_clusters,
    ),
    _ComponentSpec(
        WebStackComponent.CERTBOT,
        re.compile(r"certbot"),
        _fixed_unit("certbot.timer"),
    ),
)
# Names and statuses only identify conflicts; versions and units come from the exact query.
# https://manpages.ubuntu.com/manpages/noble/man1/dpkg-query.1.html
PACKAGE_NAMES_QUERY = "dpkg-query -W -f='${Package} ${db:Status-Abbrev}\\n'"
PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]{0,199}")
