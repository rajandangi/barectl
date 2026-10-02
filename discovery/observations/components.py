"""Web-stack component observations: installed packages and their service units."""

import re
import shlex
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace

from ..models import ObservationOutcome, WebStackComponent
from ..snapshot import Observation, Package, ServiceUnit, WebStackComponentObservation
from ..ssh import RemoteShell
from .probes import (
    _bounded,
    _Failed,
    _list_directory,
    _listing_command,
    _outside_layout,
    _overall,
    _run,
    _test,
)


def _collect_web_stack(shell: RemoteShell) -> tuple[WebStackComponentObservation, ...]:
    installed = _installed_packages(shell)
    return tuple(_observe_component(shell, spec, installed) for spec in COMPONENT_SPECS)


def _observe_component(
    shell: RemoteShell, spec: _ComponentSpec, installed: dict[str, str | None] | _Failed
) -> WebStackComponentObservation:
    package = _package_observation(spec, installed)
    service = _observe_installed(package, lambda packages: spec.service(shell, packages))
    return WebStackComponentObservation(spec.component, package, service)


def _package_observation(
    spec: _ComponentSpec, installed: dict[str, str | None] | _Failed
) -> Observation[tuple[Package, ...]]:
    if isinstance(installed, _Failed):
        return Observation(installed.status, (PACKAGE_QUERY,), installed.warning, ())
    matched = sorted(name for name in installed if spec.packages.fullmatch(name))
    if not matched:
        return Observation(
            ObservationOutcome.ABSENT,
            (PACKAGE_QUERY,),
            f"The dpkg database lists no installed {spec.component.label} packages.",
            (),
        )
    packages = tuple(
        Package(name, version) for name in matched if (version := installed[name]) is not None
    )
    if len(packages) != len(matched):
        return Observation(
            ObservationOutcome.UNSUPPORTED,
            (PACKAGE_QUERY,),
            f"The dpkg database lists a {spec.component.label} package that is not fully "
            "installed, so Barectl does not report its version or service state.",
            (),
        )
    return Observation(ObservationOutcome.OBSERVED, (PACKAGE_QUERY,), "", packages)


def _observe_installed[T](
    package: Observation[tuple[Package, ...]],
    collect: Callable[[tuple[Package, ...]], Observation[tuple[T, ...]]],
) -> Observation[tuple[T, ...]]:
    """docs/adr/0001-configuration-observations-depend-on-package-observation.md"""
    if package.outcome != ObservationOutcome.OBSERVED:
        return Observation(package.outcome, package.source, package.warning, ())
    return collect(package.value)


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


def _installed_packages(shell: RemoteShell) -> dict[str, str | None] | _Failed:
    """The dpkg database's installed package versions by name, or why they could not be read.

    A package in an unfinished state, such as unpacked or half-configured, maps to ``None``:
    it is neither installed nor absent.
    """
    # dpkg-query exits 1 when one queried pattern matches nothing, even while others match.
    output = _run(
        shell,
        PACKAGE_QUERY,
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
                    f"{PACKAGE_QUERY} did not report package states in a supported format.",
                    PACKAGE_QUERY,
                )
    return installed


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
MAX_POSTGRESQL_VERSIONS = 20
MAX_CLUSTERS = 100


@dataclass(frozen=True)
class _Clusters:
    """The PostgreSQL clusters found in the Debian layout, and how they were found.

    ``failure`` records why the listing is incomplete; ``units`` still holds the clusters
    that were found. ``commands`` is the listing's source, so only the failure's status
    and warning are used.
    """

    units: tuple[str, ...]
    commands: tuple[str, ...]
    failure: _Failed | None


_TOO_MANY_VERSIONS = (
    f"{POSTGRESQL_CONF_ROOT} holds more than {MAX_POSTGRESQL_VERSIONS} PostgreSQL versions. "
    "They were not listed."
)
_TOO_MANY_CLUSTERS = (
    f"{POSTGRESQL_CONF_ROOT} holds more than {MAX_CLUSTERS} possible PostgreSQL clusters. "
    "They were not queried."
)
_NO_CLUSTERS = f"Barectl found no PostgreSQL clusters in {POSTGRESQL_CONF_ROOT}."


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _find_clusters(shell: RemoteShell) -> _Clusters:
    """Every cluster's unit name, loaded or not (docs/ssh-connections.md#postgresql-clusters)."""
    commands = [_listing_command(POSTGRESQL_CONF_ROOT)]
    listed = _list_directory(shell, POSTGRESQL_CONF_ROOT)
    if isinstance(listed, _Failed):
        return _Clusters((), tuple(commands), _outside_layout(listed))
    # postgresql-common ignores entries not named like a version; they hold no clusters.
    versions = sorted((e for e in listed if POSTGRESQL_VERSION.fullmatch(e)), key=_version_key)
    if len(versions) > MAX_POSTGRESQL_VERSIONS:
        too_many = _Failed(ObservationOutcome.UNSUPPORTED, _TOO_MANY_VERSIONS, POSTGRESQL_CONF_ROOT)
        return _Clusters((), tuple(commands), too_many)
    candidates: list[tuple[str, str]] = []
    failures: list[_Failed] = []
    for version in versions:
        directory = f"{POSTGRESQL_CONF_ROOT}/{version}"
        # postgresql-common reads every entry, including names that start with ".".
        commands.append(_listing_command(directory, hidden=True))
        entries = _list_directory(shell, directory, hidden=True)
        if isinstance(entries, _Failed):
            failures.append(entries)
            continue
        names = [entry for entry in entries if CLUSTER_NAME.fullmatch(entry)]
        if skipped := len(entries) - len(names):
            # The entries may be clusters Barectl cannot name in a unit, so the listing is
            # incomplete. Their names are server data and are never quoted.
            failures.append(
                _Failed(
                    ObservationOutcome.UNSUPPORTED,
                    f"{directory} lists {skipped} entries whose names Barectl does not "
                    "support. They were skipped.",
                    directory,
                )
            )
        candidates.extend((version, name) for name in names)
    if len(candidates) > MAX_CLUSTERS:
        # Every entry is checked with remote commands and every cluster shares one unit
        # query, so both stay bounded. A partial list would hide clusters.
        too_many = _Failed(ObservationOutcome.UNSUPPORTED, _TOO_MANY_CLUSTERS, POSTGRESQL_CONF_ROOT)
        return _Clusters((), tuple(commands), too_many)
    units: list[str] = []
    for version, name in candidates:
        found = _holds_cluster(shell, f"{POSTGRESQL_CONF_ROOT}/{version}/{name}")
        if isinstance(found, _Failed):
            failures.append(found)
        elif found:
            units.append(f"postgresql@{version}-{name}.service")
    return _Clusters(tuple(units), tuple(commands), _combined_failure(failures))


def _holds_cluster(shell: RemoteShell, directory: str) -> bool | _Failed:
    conf = f"{directory}/postgresql.conf"
    if _test(shell, "-e", conf) or _test(shell, "-L", conf):
        return True
    if _test(shell, "-d", directory):
        if _test(shell, "-x", directory):
            # A directory the SSH user can search that holds no postgresql.conf.
            return False
    elif _test(shell, "-e", directory):
        # Not a directory, so not a cluster.
        return False
    return _Failed(
        ObservationOutcome.INACCESSIBLE,
        f"The SSH user cannot search {directory}. Barectl does not use sudo.",
        directory,
    )


def _combined_failure(failures: Sequence[_Failed]) -> _Failed | None:
    """One failure for several: inaccessible only when permissions refused all of them."""
    if not failures:
        return None
    warnings: list[str] = []
    for failure in failures:
        _bounded(warnings, failure.warning)
    status = _overall((failure.status for failure in failures), listed_empty=False)
    return _Failed(status, " ".join(warnings), POSTGRESQL_CONF_ROOT)


def _with_clusters(
    units: Observation[tuple[ServiceUnit, ...]], clusters: _Clusters
) -> Observation[tuple[ServiceUnit, ...]]:
    """docs/ssh-connections.md#postgresql-clusters"""
    source = (*clusters.commands, *units.source)
    if clusters.failure is None:
        warning = units.warning or ("" if clusters.units else _NO_CLUSTERS)
        return replace(units, source=source, warning=warning)
    if units.outcome != ObservationOutcome.OBSERVED:
        # The unit query's failure explains the outcome; the listing's is added.
        warning = f"{units.warning} {clusters.failure.warning}"
        return replace(units, source=source, warning=warning)
    return Observation(clusters.failure.status, source, clusters.failure.warning, units.value)


type _ServiceRule = Callable[
    [RemoteShell, tuple[Package, ...]], Observation[tuple[ServiceUnit, ...]]
]


def _fixed_unit(unit: str) -> _ServiceRule:
    """The component runs as one documented unit, whatever packages provide it."""
    return lambda shell, _packages: _observe_units(shell, (unit,))


def _unit_per_package(
    shell: RemoteShell, packages: tuple[Package, ...]
) -> Observation[tuple[ServiceUnit, ...]]:
    return _observe_units(shell, tuple(f"{package.name}.service" for package in packages))


def _umbrella_and_clusters(
    shell: RemoteShell, _packages: tuple[Package, ...]
) -> Observation[tuple[ServiceUnit, ...]]:
    clusters = _find_clusters(shell)
    return _with_clusters(_observe_units(shell, (POSTGRESQL_UMBRELLA, *clusters.units)), clusters)


@dataclass(frozen=True)
class _ComponentSpec:
    component: WebStackComponent
    # The dpkg-query patterns that list the component's packages. They hold no quotes.
    globs: tuple[str, ...]
    # The package names, as the patterns report them, that belong to the component.
    packages: re.Pattern[str]
    service: _ServiceRule


# docs/ssh-connections.md#component-observations
COMPONENT_SPECS = (
    _ComponentSpec(
        WebStackComponent.NGINX, ("nginx",), re.compile(r"nginx"), _fixed_unit("nginx.service")
    ),
    _ComponentSpec(
        WebStackComponent.PHP_FPM, ("php*-fpm",), re.compile(r"php[0-9.]*-fpm"), _unit_per_package
    ),
    _ComponentSpec(
        WebStackComponent.MARIADB,
        ("mariadb-server*",),
        re.compile(r"mariadb-server(-core)?(-[0-9.]+)?"),
        _fixed_unit("mariadb.service"),
    ),
    _ComponentSpec(
        WebStackComponent.POSTGRESQL,
        ("postgresql", "postgresql-[0-9]*"),
        re.compile(r"postgresql(-[0-9.]+)?"),
        _umbrella_and_clusters,
    ),
    _ComponentSpec(
        WebStackComponent.CERTBOT,
        ("certbot",),
        re.compile(r"certbot"),
        _fixed_unit("certbot.timer"),
    ),
)
# The patterns are quoted, so the server's shell does not expand them; dpkg-query's own
# globs match the package names.
PACKAGE_QUERY = "dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\\n' " + " ".join(
    f"'{glob}'" for spec in COMPONENT_SPECS for glob in spec.globs
)
