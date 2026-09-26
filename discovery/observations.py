"""Read-only observations collected over a verified connection.

Every command here is a fixed string that only reads. None uses sudo, installs packages or
writes files. Only the fields Barectl displays are kept; raw remote output is discarded.
"""

import re
import shlex
from dataclasses import dataclass

from .models import ObservationStatus, ServiceComponent
from .ssh import RemoteShell

# The os-release specification: read /etc/os-release, falling back to /usr/lib/os-release.
# https://www.freedesktop.org/software/systemd/man/latest/os-release.html
OS_RELEASE_FILES = ("/etc/os-release", "/usr/lib/os-release")
OS_RELEASE_FIELDS = {"PRETTY_NAME": 200, "NAME": 200, "ID": 100, "VERSION_ID": 100}

# Capacity observations use only fixed read-only commands with the SSH user's own
# permissions. No sudo, no package installation, no writes. Maintainer sources, not
# Django endorsements:
# - uname -m: https://www.gnu.org/software/coreutils/manual/html_node/uname-invocation.html
# - nproc: https://www.gnu.org/software/coreutils/manual/html_node/nproc-invocation.html
# - /proc/meminfo MemTotal in kB: https://docs.kernel.org/filesystems/proc.html
# - df -B1 --output: https://www.gnu.org/software/coreutils/manual/html_node/df-invocation.html
ARCH_COMMAND = "uname -m"
CPU_COMMAND = "nproc"
MEMINFO_PATH = "/proc/meminfo"
FILESYSTEM_COMMAND = "df -B1 --output=size,avail,target /"
ARCH_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,100}")
# ASCII only: str.isdigit accepts characters such as "²" that int() rejects.
DIGITS = re.compile(r"[0-9]+")
MAX_CPU_COUNT = 1_000_000
# A POSIX shell exits 127 when a command is not found and 126 when it cannot run it.
# https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html#tag_19_08_02
COMMAND_NOT_FOUND = 127
COMMAND_NOT_EXECUTABLE = 126

# Web-stack service observations. Versions come from the dpkg database and service states
# from systemd, both read without sudo. The query's patterns are quoted, so the server's
# shell does not expand them; dpkg-query's own globs match the package names.
# https://manpages.debian.org/stable/dpkg/dpkg-query.1.en.html
PACKAGE_QUERY = (
    "dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\\n' 'nginx' 'php*-fpm' "
    "'mariadb-server*' 'postgresql' 'postgresql-[0-9]*'"
)
# The status abbreviation: the selection (such as "i" install or "h" hold), the package
# state, and an optional "R" when the package needs reinstalling. Its trailing space is
# lost to whitespace splitting. "ii" is installed and "hi" installed and held; "un" is a
# package apt merely knows about, listed without a version.
PACKAGE_STATUS = re.compile(r"[uihrp][ncHUFWti]R?")
# Package states: installed, installed with triggers pending or awaited, and never or no
# longer installed ("c" keeps only configuration files). Any other state is unfinished.
INSTALLED_STATES = frozenset("iWt")
NOT_INSTALLED_STATES = frozenset("nc")
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


@dataclass(frozen=True)
class _ComponentSpec:
    component: ServiceComponent
    # The dpkg package names the component accepts, as the query's patterns report them.
    packages: re.Pattern[str]
    # The systemd unit queried for the component, or "" when it is derived from each
    # installed package's name.
    unit: str


# The documented package patterns and service unit names. Only dpkg installations and
# these unit names are supported (docs/ssh-connections.md).
COMPONENT_SPECS = (
    _ComponentSpec(ServiceComponent.NGINX, re.compile(r"nginx"), "nginx.service"),
    _ComponentSpec(ServiceComponent.PHP_FPM, re.compile(r"php[0-9.]*-fpm"), ""),
    _ComponentSpec(
        ServiceComponent.MARIADB,
        re.compile(r"mariadb-server(-core)?(-[0-9.]+)?"),
        "mariadb.service",
    ),
    _ComponentSpec(
        ServiceComponent.POSTGRESQL, re.compile(r"postgresql(-[0-9.]+)?"), "postgresql.service"
    ),
)


_UNIT_PROPERTIES = ("Id", "LoadState", "ActiveState", "SubState", "UnitFileState")


def _unit_query(units: tuple[str, ...]) -> str:
    # PHP-FPM unit names derive from server-reported package names; quote them regardless.
    names = " ".join(shlex.quote(unit) for unit in units)
    properties = " ".join(f"-p {prop}" for prop in _UNIT_PROPERTIES)
    return f"systemctl show {names} {properties}"


@dataclass(frozen=True)
class ServiceComponentObservation:
    component: ServiceComponent
    package_status: ObservationStatus
    # One "name version" line per installed package, as the snapshot stores them.
    packages: tuple[str, ...]
    package_source: str
    package_warning: str
    service_status: ObservationStatus
    # One "unit state" line per queried unit, such as "nginx.service active (running), enabled".
    units: tuple[str, ...]
    service_source: str
    service_warning: str


@dataclass(frozen=True)
class _Units:
    status: ObservationStatus
    units: tuple[str, ...]
    source: str
    warning: str


# A missing package-query or systemctl command leaves the software uninspectable, which is
# unsupported rather than absent: Barectl cannot say the software is not there.
NO_DPKG_QUERY = (
    "The server has no dpkg-query command. Barectl reads package versions from the dpkg "
    "database and cannot inspect other installation formats."
)
NO_SYSTEMCTL = "The server has no systemctl command, so Barectl cannot report service states."
SYSTEMCTL_UNAVAILABLE = (
    "Barectl could not read service states from systemd. The server may not be running "
    "systemd, or the SSH user may not be allowed to query it."
)
_DPKG_QUERY_FORMAT = f"{PACKAGE_QUERY} did not report package states in a supported format."
_SYSTEMCTL_FORMAT = "{} did not report service states in a supported format."
_UNIT_FORMAT = "systemctl did not report a service unit in a supported format."


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
        missing=_Failed(ObservationStatus.UNSUPPORTED, NO_DPKG_QUERY),
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
                return _Failed(ObservationStatus.UNSUPPORTED, _DPKG_QUERY_FORMAT)
    return installed


def _observe_units(shell: RemoteShell, unit_names: tuple[str, ...]) -> _Units:
    """The systemd state of each named unit, or why it could not be observed."""
    command = _unit_query(unit_names)
    output = _run(
        shell,
        command,
        missing=_Failed(ObservationStatus.UNSUPPORTED, NO_SYSTEMCTL),
        failed=SYSTEMCTL_UNAVAILABLE,
    )
    if isinstance(output, _Failed):
        return _Units(output.status, (), command, output.warning)
    records = _parse_unit_records(output)
    if not records:
        return _Units(ObservationStatus.UNSUPPORTED, (), command, _SYSTEMCTL_FORMAT.format(command))
    units: list[str] = []
    for queried, record in zip(unit_names, records, strict=False):
        state = _unit_line(record)
        # An alias reports the unit it resolves to under another name; that is not the
        # documented unit, so it is unsupported rather than shown under the queried name.
        if state is None or record.get("Id") != queried:
            # The unit's reported name is server data, so the warning names no unit.
            return _Units(ObservationStatus.UNSUPPORTED, tuple(units), command, _UNIT_FORMAT)
        units.append(state)
    if len(records) != len(unit_names):
        return _Units(ObservationStatus.UNSUPPORTED, tuple(units), command, _UNIT_FORMAT)
    return _Units(ObservationStatus.OBSERVED, tuple(units), command, "")


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


def _unit_line(record: dict[str, str]) -> str | None:
    """One unit's display line, or ``None`` when systemd reported an unsupported format."""
    unit = record.get("Id", "")
    load = record.get("LoadState", "")
    active = record.get("ActiveState", "")
    sub = record.get("SubState", "")
    file_state = record.get("UnitFileState", "")
    if (
        UNIT_NAME.fullmatch(unit) is None
        or load not in LOAD_STATES
        or active not in ACTIVE_STATES
        or SUB_STATE.fullmatch(sub) is None
        or (file_state and file_state not in UNIT_FILE_STATES)
    ):
        return None
    if load == "not-found":
        return f"{unit} not found"
    state = f"{active} ({sub})"
    return f"{unit} {state}, {file_state}" if file_state else f"{unit} {state}"


def collect_service_stack(shell: RemoteShell) -> tuple[ServiceComponentObservation, ...]:
    """Observe every web-stack component's packages and service units, in display order."""
    installed = _installed_packages(shell)
    if isinstance(installed, _Failed):
        # No component can be inspected; none is reported as absent. The service
        # observations are not collected, so their verdict is the same uninspectable one.
        return tuple(
            ServiceComponentObservation(
                component=spec.component,
                package_status=installed.status,
                packages=(),
                package_source=PACKAGE_QUERY,
                package_warning=installed.warning,
                service_status=installed.status,
                units=(),
                service_source="",
                service_warning=installed.warning,
            )
            for spec in COMPONENT_SPECS
        )
    return tuple(_observe_component(shell, spec, installed) for spec in COMPONENT_SPECS)


def _observe_component(
    shell: RemoteShell, spec: _ComponentSpec, installed: dict[str, str | None]
) -> ServiceComponentObservation:
    matched = sorted(name for name in installed if spec.packages.fullmatch(name))
    if not matched:
        warning = f"The dpkg database lists no installed {spec.component.label} packages."
        return ServiceComponentObservation(
            component=spec.component,
            package_status=ObservationStatus.ABSENT,
            packages=(),
            package_source=PACKAGE_QUERY,
            package_warning=warning,
            # No unit is queried without an installed package; the absent verdict comes
            # from the same dpkg query, which is this observation's provenance.
            service_status=ObservationStatus.ABSENT,
            units=(),
            service_source=PACKAGE_QUERY,
            service_warning=warning,
        )
    if any(installed[name] is None for name in matched):
        # Software in an unfinished dpkg state may be partly present; it is not absent.
        warning = (
            f"The dpkg database lists a {spec.component.label} package that is not fully "
            "installed, so Barectl does not report its version or service state."
        )
        return ServiceComponentObservation(
            component=spec.component,
            package_status=ObservationStatus.UNSUPPORTED,
            packages=(),
            package_source=PACKAGE_QUERY,
            package_warning=warning,
            service_status=ObservationStatus.UNSUPPORTED,
            units=(),
            service_source=PACKAGE_QUERY,
            service_warning=warning,
        )
    unit_names = (spec.unit,) if spec.unit else tuple(f"{name}.service" for name in matched)
    observed = _observe_units(shell, unit_names)
    return ServiceComponentObservation(
        component=spec.component,
        package_status=ObservationStatus.OBSERVED,
        packages=tuple(f"{name} {installed[name]}" for name in matched),
        package_source=PACKAGE_QUERY,
        package_warning="",
        service_status=observed.status,
        units=observed.units,
        service_source=observed.source,
        service_warning=observed.warning,
    )


@dataclass(frozen=True)
class _Failed:
    status: ObservationStatus
    warning: str


def _read_file(shell: RemoteShell, path: str) -> str | _Failed:
    """Return a remote file's contents, or why it could not be observed."""
    result = shell.run(f"cat {path}")
    if result.truncated:
        return _Failed(
            ObservationStatus.UNSUPPORTED, f"{path} is larger than expected. It was not read."
        )
    if result.exit_status == 0:
        return result.stdout
    # Error text depends on the server's locale, so ask the shell instead.
    if shell.run(f"test -e {path}").exit_status != 0:
        return _Failed(ObservationStatus.ABSENT, f"The server has no {path}.")
    if shell.run(f"test -r {path}").exit_status != 0:
        return _Failed(
            ObservationStatus.INACCESSIBLE,
            f"The SSH user cannot read {path}. Barectl does not use sudo.",
        )
    return _Failed(ObservationStatus.UNSUPPORTED, f"{path} could not be read.")


@dataclass(frozen=True)
class OsRelease:
    status: ObservationStatus
    source: str = ""
    fields: tuple[tuple[str, str], ...] = ()
    warning: str = ""

    def get(self, name: str) -> str:
        return dict(self.fields).get(name, "")


def collect_os_release(shell: RemoteShell) -> OsRelease:
    for path in OS_RELEASE_FILES:
        text = _read_file(shell, path)
        if not isinstance(text, _Failed):
            return _parse_os_release(path, text)
        if text.status != ObservationStatus.ABSENT:
            return OsRelease(text.status, source=path, warning=text.warning)
    return OsRelease(
        ObservationStatus.ABSENT,
        warning="The server has neither /etc/os-release nor /usr/lib/os-release.",
    )


def _parse_os_release(path: str, text: str) -> OsRelease:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        name, separator, raw = line.strip().partition("=")
        if not separator or name not in OS_RELEASE_FIELDS:
            continue
        try:
            # Values use shell quoting; shlex parses it without executing anything.
            words = shlex.split(raw, comments=False)
        except ValueError:
            continue
        value = " ".join(words).strip()
        if value and value.isprintable():
            fields[name] = value[: OS_RELEASE_FIELDS[name]]
    if not fields.keys() & {"PRETTY_NAME", "NAME", "ID"}:
        return OsRelease(
            ObservationStatus.UNSUPPORTED,
            source=path,
            warning=f"{path} does not identify the operating system in a supported format.",
        )
    return OsRelease(ObservationStatus.OBSERVED, source=path, fields=tuple(fields.items()))


@dataclass(frozen=True)
class Architecture:
    status: ObservationStatus
    value: str = ""
    source: str = ARCH_COMMAND
    warning: str = ""


@dataclass(frozen=True)
class CpuCount:
    status: ObservationStatus
    count: int | None = None
    source: str = CPU_COMMAND
    warning: str = ""


@dataclass(frozen=True)
class Memory:
    status: ObservationStatus
    total_bytes: int | None = None
    source: str = MEMINFO_PATH
    warning: str = ""


@dataclass(frozen=True)
class Filesystem:
    status: ObservationStatus
    size_bytes: int | None = None
    avail_bytes: int | None = None
    source: str = FILESYSTEM_COMMAND
    warning: str = ""


def _run(
    shell: RemoteShell,
    command: str,
    *,
    accepted: frozenset[int] = frozenset({0}),
    missing: _Failed | None = None,
    failed: str | None = None,
) -> str | _Failed:
    """Return a fixed command's output, or why it could not be observed.

    ``accepted`` names the exit statuses that still produce parseable output. ``missing``
    replaces the absent verdict when a missing command leaves software uninspectable rather
    than absent, and ``failed`` replaces the warning for any other exit status.
    """
    result = shell.run(command)
    if result.truncated:
        return _Failed(
            ObservationStatus.UNSUPPORTED,
            f"{command} wrote more output than expected. It was not read.",
        )
    program = command.split()[0]
    if result.exit_status == COMMAND_NOT_FOUND:
        return missing or _Failed(ObservationStatus.ABSENT, f"The server has no {program} command.")
    if result.exit_status == COMMAND_NOT_EXECUTABLE:
        return _Failed(
            ObservationStatus.INACCESSIBLE,
            f"The SSH user cannot run {program}. Barectl does not use sudo.",
        )
    if result.exit_status not in accepted:
        return _Failed(ObservationStatus.UNSUPPORTED, failed or f"{command} failed.")
    return result.stdout


def collect_architecture(shell: RemoteShell) -> Architecture:
    output = _run(shell, ARCH_COMMAND)
    if isinstance(output, _Failed):
        return Architecture(output.status, warning=output.warning)
    value = output.strip()
    if ARCH_PATTERN.fullmatch(value) is None:
        return Architecture(
            ObservationStatus.UNSUPPORTED,
            warning=f"{ARCH_COMMAND} did not report the architecture in a supported format.",
        )
    return Architecture(ObservationStatus.OBSERVED, value=value)


def collect_cpu_count(shell: RemoteShell) -> CpuCount:
    output = _run(shell, CPU_COMMAND)
    if isinstance(output, _Failed):
        return CpuCount(output.status, warning=output.warning)
    text = output.strip()
    count = int(text) if DIGITS.fullmatch(text) else 0
    if not 1 <= count <= MAX_CPU_COUNT:
        return CpuCount(
            ObservationStatus.UNSUPPORTED,
            warning=f"{CPU_COMMAND} did not report the CPU count in a supported format.",
        )
    return CpuCount(ObservationStatus.OBSERVED, count=count)


def collect_memory(shell: RemoteShell) -> Memory:
    text = _read_file(shell, MEMINFO_PATH)
    if isinstance(text, _Failed):
        return Memory(text.status, warning=text.warning)
    for line in text.splitlines():
        name, _, rest = line.strip().partition(":")
        if name != "MemTotal":
            continue
        parts = rest.split()
        if len(parts) == 2 and parts[1] == "kB" and DIGITS.fullmatch(parts[0]):
            kilobytes = int(parts[0])
            if kilobytes > 0:
                return Memory(ObservationStatus.OBSERVED, total_bytes=kilobytes * 1024)
        break
    return Memory(
        ObservationStatus.UNSUPPORTED,
        warning=f"{MEMINFO_PATH} did not report memory in a supported format.",
    )


def collect_filesystem(shell: RemoteShell) -> Filesystem:
    output = _run(shell, FILESYSTEM_COMMAND)
    if isinstance(output, _Failed):
        return Filesystem(output.status, warning=output.warning)
    lines = [line.split() for line in output.splitlines() if line.strip()]
    # The first line is a header; the second describes the root filesystem.
    if len(lines) >= 2 and len(lines[1]) == 3 and lines[1][2] == "/":
        size, avail, _ = lines[1]
        if DIGITS.fullmatch(size) and DIGITS.fullmatch(avail):
            size_bytes, avail_bytes = int(size), int(avail)
            # A full filesystem has no available space, but it always has a size.
            if size_bytes > 0 and avail_bytes <= size_bytes:
                return Filesystem(
                    ObservationStatus.OBSERVED, size_bytes=size_bytes, avail_bytes=avail_bytes
                )
    return Filesystem(
        ObservationStatus.UNSUPPORTED,
        warning="The root filesystem capacity was not reported in a supported format.",
    )
