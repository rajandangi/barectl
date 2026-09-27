"""Read-only observations collected over a verified connection.

Every command here is a fixed string that only reads. None uses sudo, installs packages or
writes files. Only the fields Barectl displays are kept; raw remote output is discarded.
"""

import re
import shlex
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from typing import NamedTuple

from .models import ObservationOutcome, WebStackComponent
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

# Component observations. Package versions come from the dpkg database and service states
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

# Site and pool observations. The site directory and PHP version tree are fixed paths in
# the supported Debian and Ubuntu layouts, so they are read only where the dpkg database
# shows the component installed (docs/adr/0001). Entries reported by the server are
# validated against these patterns before they are read, stored or shown; anything else is
# skipped or reported as unsupported rather than interpreted.
SITES_ENABLED_DIR = "/etc/nginx/sites-enabled"
PHP_BASE_DIR = "/etc/php"
POOL_SUBPATH = "fpm/pool.d"
# Entries of the site directory; nginx includes every entry it holds.
SITE_ENTRY = re.compile(r"[A-Za-z0-9._-]{1,100}")
# Versioned PHP-FPM packages, such as "php8.3-fpm", name the PHP version they configure.
PHP_FPM_PACKAGE = re.compile(r"php([0-9]+(?:\.[0-9]+)*)-fpm")
# Pool configuration files; PHP-FPM's pool.d include matches *.conf only.
POOL_FILE = re.compile(r"[A-Za-z0-9._-]{1,95}\.conf")
# server_name and listen values Barectl stores. Regex and wildcard listen forms are
# server data that must not be interpreted, so a file using them is unsupported.
SERVER_NAME = re.compile(r"[A-Za-z0-9.*_-]{1,200}")
LISTEN_ADDRESS = re.compile(r"(?:unix:)?[A-Za-z0-9._:/\[\]*-]{1,200}")
POOL_NAME = re.compile(r"[A-Za-z0-9._-]{1,100}")
POOL_LISTEN = re.compile(r"[A-Za-z0-9._:/\[\]-]{1,200}")
# Bounds that keep a hostile file from holding the worker: nginx statements and tokens,
# and the number of sites, versions and pool files inspected per snapshot.
MAX_TOKEN = 200
MAX_TOKENS_PER_STATEMENT = 100
MAX_STATEMENTS = 2000
MAX_BLOCK_DEPTH = 50
MAX_LISTEN_FLAGS = 20
MAX_SERVER_NAMES = 100
MAX_LISTING_ENTRIES = 1000
MAX_SITES = 200
MAX_VERSIONS = 20
MAX_POOLS = 200
MAX_POOLS_PER_FILE = 50
MAX_OBSERVATION_WARNINGS = 20
MAX_WARNING = 500

# One nginx lexical token. Whitespace and # comments are skipped; quoted values become
# one token. Anything the regex cannot account for leaves a gap between matches, which
# makes the text unsupported.
NGINX_TOKEN = re.compile(
    r"""
      (?P<skipped>\s+|\#[^\n]*)
    | (?P<quoted>'[^']*'|"[^"]*")
    | (?P<word>[^{};'"\s#]+)
    | (?P<end>;)
    | (?P<open>\{)
    | (?P<close>\})
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
class _ComponentSpec:
    component: WebStackComponent
    # The dpkg package names the component accepts, as the query's patterns report them.
    packages: re.Pattern[str]
    # The systemd unit queried for the component, or "" when it is derived from each
    # installed package's name.
    unit: str


# The documented package patterns and service unit names. Only dpkg installations and
# these unit names are supported (docs/ssh-connections.md).
COMPONENT_SPECS = (
    _ComponentSpec(WebStackComponent.NGINX, re.compile(r"nginx"), "nginx.service"),
    _ComponentSpec(WebStackComponent.PHP_FPM, re.compile(r"php[0-9.]*-fpm"), ""),
    _ComponentSpec(
        WebStackComponent.MARIADB,
        re.compile(r"mariadb-server(-core)?(-[0-9.]+)?"),
        "mariadb.service",
    ),
    _ComponentSpec(
        WebStackComponent.POSTGRESQL, re.compile(r"postgresql(-[0-9.]+)?"), "postgresql.service"
    ),
)


_UNIT_PROPERTIES = ("Id", "LoadState", "ActiveState", "SubState", "UnitFileState")


def _unit_query(units: tuple[str, ...]) -> str:
    # PHP-FPM unit names derive from server-reported package names; quote them regardless.
    names = " ".join(shlex.quote(unit) for unit in units)
    properties = " ".join(f"-p {prop}" for prop in _UNIT_PROPERTIES)
    return f"systemctl show {names} {properties}"


@dataclass(frozen=True)
class WebStackComponentObservation:
    component: WebStackComponent
    package_status: ObservationOutcome
    # One "name version" line per installed package, as the snapshot stores them.
    packages: tuple[str, ...]
    package_source: str
    package_warning: str
    service_status: ObservationOutcome
    # One "unit state" line per queried unit, such as "nginx.service active (running), enabled".
    units: tuple[str, ...]
    service_source: str
    service_warning: str


@dataclass(frozen=True)
class _Units:
    status: ObservationOutcome
    units: tuple[str, ...]
    source: str
    warning: str


# A missing package-query or systemctl command leaves the software uninspectable: Barectl
# cannot say the software is not there.
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
                return _Failed(ObservationOutcome.UNSUPPORTED, _DPKG_QUERY_FORMAT)
    return installed


def _observe_units(shell: RemoteShell, unit_names: tuple[str, ...]) -> _Units:
    """The systemd state of each named unit, or why it could not be observed."""
    command = _unit_query(unit_names)
    output = _run(
        shell,
        command,
        missing=NO_SYSTEMCTL,
        failed=SYSTEMCTL_UNAVAILABLE,
    )
    if isinstance(output, _Failed):
        return _Units(output.status, (), command, output.warning)
    records = _parse_unit_records(output)
    if not records:
        return _Units(
            ObservationOutcome.UNSUPPORTED, (), command, _SYSTEMCTL_FORMAT.format(command)
        )
    units: list[str] = []
    for queried, record in zip(unit_names, records, strict=False):
        state = _unit_line(record)
        # An alias reports the unit it resolves to under another name; that is not the
        # documented unit, so it is unsupported rather than shown under the queried name.
        if state is None or record.get("Id") != queried:
            # The unit's reported name is server data, so the warning names no unit.
            return _Units(ObservationOutcome.UNSUPPORTED, tuple(units), command, _UNIT_FORMAT)
        units.append(state)
    if len(records) != len(unit_names):
        return _Units(ObservationOutcome.UNSUPPORTED, tuple(units), command, _UNIT_FORMAT)
    return _Units(ObservationOutcome.OBSERVED, tuple(units), command, "")


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


def collect_web_stack(shell: RemoteShell) -> tuple[WebStackComponentObservation, ...]:
    """Observe every web-stack component's packages and service units, in display order."""
    installed = _installed_packages(shell)
    if isinstance(installed, _Failed):
        # No component can be inspected; none is reported as absent. The service
        # observations are not collected, so their verdict is the same uninspectable one.
        return tuple(
            WebStackComponentObservation(
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
) -> WebStackComponentObservation:
    matched = sorted(name for name in installed if spec.packages.fullmatch(name))
    if not matched:
        warning = f"The dpkg database lists no installed {spec.component.label} packages."
        return WebStackComponentObservation(
            component=spec.component,
            package_status=ObservationOutcome.ABSENT,
            packages=(),
            package_source=PACKAGE_QUERY,
            package_warning=warning,
            # No unit is queried without an installed package; the absent verdict comes
            # from the same dpkg query, which is this observation's provenance.
            service_status=ObservationOutcome.ABSENT,
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
        return WebStackComponentObservation(
            component=spec.component,
            package_status=ObservationOutcome.UNSUPPORTED,
            packages=(),
            package_source=PACKAGE_QUERY,
            package_warning=warning,
            service_status=ObservationOutcome.UNSUPPORTED,
            units=(),
            service_source=PACKAGE_QUERY,
            service_warning=warning,
        )
    unit_names = (spec.unit,) if spec.unit else tuple(f"{name}.service" for name in matched)
    observed = _observe_units(shell, unit_names)
    return WebStackComponentObservation(
        component=spec.component,
        package_status=ObservationOutcome.OBSERVED,
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
    """Why a command, file or directory could not be read.

    Helpers never decide that something is absent: only a collector knows whether the
    thing it looked for may legitimately not exist. A missing command or path is reported
    as unsupported with ``missing`` set, and the collector decides what that means.
    """

    status: ObservationOutcome
    warning: str
    missing: bool = False


def _test(shell: RemoteShell, flag: str, path: str) -> bool:
    return shell.run(f"test {flag} {shlex.quote(path)}").exit_status == 0


def _path_missing(shell: RemoteShell, path: str) -> bool:
    """Whether a path ``test -e`` cannot see does not exist, rather than being hidden.

    ``test -e`` also fails when a parent directory cannot be searched, so the nearest
    existing ancestor decides: a searchable one means the path does not exist.
    """
    parent = path.rpartition("/")[0] or "/"
    if path == "/" or _test(shell, "-x", parent):
        return True
    if _test(shell, "-e", parent):
        return False
    return _path_missing(shell, parent)


def _unreadable(shell: RemoteShell, path: str) -> _Failed:
    """Why a remote file or directory could not be read."""
    # Error text depends on the server's locale, so ask the shell instead.
    if not _test(shell, "-e", path):
        if _path_missing(shell, path):
            return _Failed(
                ObservationOutcome.UNSUPPORTED, f"The server has no {path}.", missing=True
            )
    elif _test(shell, "-r", path):
        return _Failed(ObservationOutcome.UNSUPPORTED, f"{path} could not be read.")
    return _Failed(
        ObservationOutcome.INACCESSIBLE,
        f"The SSH user cannot read {path}. Barectl does not use sudo.",
    )


def _read_file(shell: RemoteShell, path: str) -> str | _Failed:
    """Return a remote file's contents, or why it could not be observed."""
    result = shell.run(f"cat {shlex.quote(path)}")
    if result.truncated:
        return _Failed(
            ObservationOutcome.UNSUPPORTED, f"{path} is larger than expected. It was not read."
        )
    if result.exit_status == 0:
        return result.stdout
    return _unreadable(shell, path)


@dataclass(frozen=True)
class OsRelease:
    status: ObservationOutcome
    source: str = ""
    fields: tuple[tuple[str, str], ...] = ()
    warning: str = ""

    def get(self, name: str) -> str:
        return dict(self.fields).get(name, "")


def collect_os_release(shell: RemoteShell) -> OsRelease:
    """Observe the operating system. Every server runs one, so it is never absent."""
    for path in OS_RELEASE_FILES:
        text = _read_file(shell, path)
        if not isinstance(text, _Failed):
            return _parse_os_release(path, text)
        if not text.missing:
            return OsRelease(text.status, source=path, warning=text.warning)
    return OsRelease(
        ObservationOutcome.UNSUPPORTED,
        warning=(
            "The server has neither /etc/os-release nor /usr/lib/os-release, so Barectl "
            "cannot identify the operating system."
        ),
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
            ObservationOutcome.UNSUPPORTED,
            source=path,
            warning=f"{path} does not identify the operating system in a supported format.",
        )
    return OsRelease(ObservationOutcome.OBSERVED, source=path, fields=tuple(fields.items()))


# Every server has an architecture, CPUs, memory and a root filesystem, so like the
# operating system these observations are never absent.
@dataclass(frozen=True)
class Architecture:
    status: ObservationOutcome
    value: str = ""
    source: str = ARCH_COMMAND
    warning: str = ""


@dataclass(frozen=True)
class CpuCount:
    status: ObservationOutcome
    count: int | None = None
    source: str = CPU_COMMAND
    warning: str = ""


@dataclass(frozen=True)
class Memory:
    status: ObservationOutcome
    total_bytes: int | None = None
    source: str = MEMINFO_PATH
    warning: str = ""


@dataclass(frozen=True)
class Filesystem:
    status: ObservationOutcome
    size_bytes: int | None = None
    avail_bytes: int | None = None
    source: str = FILESYSTEM_COMMAND
    warning: str = ""


def _run(
    shell: RemoteShell,
    command: str,
    *,
    accepted: frozenset[int] = frozenset({0}),
    missing: str | None = None,
    failed: str | None = None,
) -> str | _Failed:
    """Return a fixed command's output, or why it could not be observed.

    ``accepted`` names the exit statuses that still produce parseable output. A missing
    command leaves the observation uninspectable, never absent; ``missing`` replaces its
    warning, and ``failed`` replaces the warning for any other exit status.
    """
    result = shell.run(command)
    if result.truncated:
        return _Failed(
            ObservationOutcome.UNSUPPORTED,
            f"{command} wrote more output than expected. It was not read.",
        )
    program = command.split()[0]
    if result.exit_status == COMMAND_NOT_FOUND:
        return _Failed(
            ObservationOutcome.UNSUPPORTED,
            missing or f"The server has no {program} command, so Barectl cannot inspect this.",
            missing=True,
        )
    if result.exit_status == COMMAND_NOT_EXECUTABLE:
        return _Failed(
            ObservationOutcome.INACCESSIBLE,
            f"The SSH user cannot run {program}. Barectl does not use sudo.",
        )
    if result.exit_status not in accepted:
        return _Failed(ObservationOutcome.UNSUPPORTED, failed or f"{command} failed.")
    return result.stdout


def collect_architecture(shell: RemoteShell) -> Architecture:
    output = _run(shell, ARCH_COMMAND)
    if isinstance(output, _Failed):
        return Architecture(output.status, warning=output.warning)
    value = output.strip()
    if ARCH_PATTERN.fullmatch(value) is None:
        return Architecture(
            ObservationOutcome.UNSUPPORTED,
            warning=f"{ARCH_COMMAND} did not report the architecture in a supported format.",
        )
    return Architecture(ObservationOutcome.OBSERVED, value=value)


def collect_cpu_count(shell: RemoteShell) -> CpuCount:
    output = _run(shell, CPU_COMMAND)
    if isinstance(output, _Failed):
        return CpuCount(output.status, warning=output.warning)
    text = output.strip()
    count = int(text) if DIGITS.fullmatch(text) else 0
    if not 1 <= count <= MAX_CPU_COUNT:
        return CpuCount(
            ObservationOutcome.UNSUPPORTED,
            warning=f"{CPU_COMMAND} did not report the CPU count in a supported format.",
        )
    return CpuCount(ObservationOutcome.OBSERVED, count=count)


def collect_memory(shell: RemoteShell) -> Memory:
    text = _read_file(shell, MEMINFO_PATH)
    if isinstance(text, _Failed) and text.missing:
        return Memory(
            text.status,
            warning=f"The server has no {MEMINFO_PATH}, so Barectl cannot report memory.",
        )
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
                return Memory(ObservationOutcome.OBSERVED, total_bytes=kilobytes * 1024)
        break
    return Memory(
        ObservationOutcome.UNSUPPORTED,
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
                    ObservationOutcome.OBSERVED, size_bytes=size_bytes, avail_bytes=avail_bytes
                )
    return Filesystem(
        ObservationOutcome.UNSUPPORTED,
        warning="The root filesystem capacity was not reported in a supported format.",
    )


def _add_token(current: list[str], token: str) -> bool:
    """Append a directive token, or refuse one that breaks the bounds."""
    if len(token) > MAX_TOKEN or len(current) >= MAX_TOKENS_PER_STATEMENT:
        return False
    current.append(token)
    return True


type _NginxEvent = tuple[str, tuple[str, ...], tuple[str, ...]]


def _nginx_statement(current: list[str], blocks: list[str], events: list[_NginxEvent]) -> bool:
    if current:
        if len(events) >= MAX_STATEMENTS:
            return False
        events.append(("stmt", tuple(blocks), tuple(current)))
        current.clear()
    return True


def _nginx_open(current: list[str], blocks: list[str], events: list[_NginxEvent]) -> bool:
    # nginx blocks are named by a leading token, such as "server" or "location /".
    if not current or len(blocks) >= MAX_BLOCK_DEPTH or len(events) >= MAX_STATEMENTS:
        return False
    blocks.append(current[0])
    events.append(("block", tuple(blocks[:-1]), (current[0],)))
    current.clear()
    return True


def _nginx_close(current: list[str], blocks: list[str]) -> bool:
    if current or not blocks:
        return False
    blocks.pop()
    return True


def _nginx_event(
    kind: str,
    token: str,
    current: list[str],
    blocks: list[str],
    events: list[_NginxEvent],
) -> bool:
    if kind == "end":
        return _nginx_statement(current, blocks, events)
    if kind == "open":
        return _nginx_open(current, blocks, events)
    if kind == "close":
        return _nginx_close(current, blocks)
    return _add_token(current, token)


def _nginx_events(text: str) -> list[_NginxEvent] | None:
    """Split nginx configuration into "block" and "stmt" events, or ``None``.

    A "block" event carries the enclosing block names and the new block's name. A "stmt"
    event carries the enclosing block names and the directive's tokens. Quoted values are
    unquoted; comments run from ``#`` to the end of the line. Anything the supported
    syntax cannot account for, including unclosed blocks, unterminated quotes and
    directives without a semicolon, leaves a gap the lexer refuses.
    """
    events: list[_NginxEvent] = []
    blocks: list[str] = []
    current: list[str] = []
    pos = 0
    for match in NGINX_TOKEN.finditer(text):
        if match.start() != pos:
            return None
        pos = match.end()
        kind = match.lastgroup or ""
        if kind == "skipped":
            continue
        token = match.group()
        if kind == "quoted":
            token = token[1:-1]
        if not _nginx_event(kind, token, current, blocks, events):
            return None
    if pos != len(text) or current or blocks:
        return None
    return events


def _site_directive(tokens: tuple[str, ...], names: list[str], listens: list[str]) -> bool:
    """Record one server block directive's supported values, or refuse the file."""
    match tokens:
        case ("listen", address, *flags):
            if LISTEN_ADDRESS.fullmatch(address) is None or len(flags) > MAX_LISTEN_FLAGS:
                return False
            if address not in listens:
                listens.append(address)
        case ("server_name", *args):
            declared = [name for name in args if name]
            if (
                (not declared and any(args))
                or len(args) > MAX_SERVER_NAMES
                or any(SERVER_NAME.fullmatch(name) is None for name in declared)
            ):
                return False
            names.extend(name for name in declared if name not in names)
        case _:
            pass
    return True


class NginxSite(NamedTuple):
    server_names: tuple[str, ...]
    listens: tuple[str, ...]
    # The file includes other files where server blocks or their server_name and listen
    # directives may live. Barectl does not read them.
    includes: bool


def parse_nginx_site(text: str) -> NginxSite | None:
    """The site's server names and listen addresses, or ``None`` when unsupported.

    Only the ``server_name`` and ``listen`` directives of the file's ``server`` blocks
    are read. A file with malformed syntax, values outside the supported forms, or no
    ``server`` block at all is unsupported: Barectl does not guess what it shows.
    """
    events = _nginx_events(text)
    if events is None:
        return None
    names: list[str] = []
    listens: list[str] = []
    server_blocks = 0
    includes = False
    for kind, blocks, tokens in events:
        if kind == "block":
            if tokens[0] == "server":
                server_blocks += 1
            continue
        # Directives of a server block: the innermost enclosing block names it.
        at_server_level = not blocks or blocks[-1] == "server"
        if at_server_level and tokens[0] == "include":
            includes = True
        if not blocks or blocks[-1] != "server":
            continue
        if not _site_directive(tokens, names, listens):
            return None
    if server_blocks == 0:
        return None
    return NginxSite(tuple(names), tuple(listens), includes)


def _pool_section(line: str) -> str | None:
    """The name in a ``[name]`` section header, or ``None`` when unsupported."""
    if not line.endswith("]"):
        return None
    section = line[1:-1]
    return section if POOL_NAME.fullmatch(section) is not None else None


def _flush_pool(
    pools: list[tuple[str, str]], seen: set[str], name: str | None, listen: str | None
) -> bool:
    if name is None:
        return True
    # PHP-FPM matches section names case-insensitively and merges repeated sections;
    # Barectl does not merge them, so a repeated pool makes the file unsupported.
    if name.casefold() in seen:
        return False
    seen.add(name.casefold())
    pools.append((name, listen or ""))
    return len(pools) <= MAX_POOLS_PER_FILE


def _pool_section_start(
    line: str,
    pools: list[tuple[str, str]],
    seen: set[str],
    name: str | None,
    listen: str | None,
) -> tuple[str | None, str | None] | None:
    """Start the section a ``[name]`` header names, closing the previous pool."""
    section = _pool_section(line)
    if section is None or not _flush_pool(pools, seen, name, listen):
        return None
    # Global directives live in php-fpm.conf, not in a pool file. PHP-FPM matches the
    # section name case-insensitively.
    return (None, None) if section.casefold() == "global" else (section, None)


def _pool_listen(line: str, name: str | None, listen: str | None) -> tuple[str | None, bool]:
    """One ``key = value`` line's effect on the current pool's listen address."""
    key, _, value = line.partition("=")
    if key.strip() != "listen" or name is None:
        # Other directives, including env[...] entries that may hold secrets, are
        # discarded here, before anything is stored.
        return listen, True
    value = value.strip()
    # INI values may be quoted, and PHP-FPM expands $pool to the pool's name.
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    value = value.replace("$pool", name)
    if listen is not None or POOL_LISTEN.fullmatch(value) is None:
        return listen, False
    return value, True


class PoolFile(NamedTuple):
    # (pool name, listen address) pairs in file order.
    pools: tuple[tuple[str, str], ...]
    # The file includes other files where more pools may be declared. Barectl does not
    # read them.
    includes: bool


def parse_pool_file(text: str) -> PoolFile | None:
    """The file's pool names and listen addresses, or ``None`` when unsupported.

    PHP-FPM pool files are INI-style: a ``[name]`` section starts a pool and ``key =
    value`` lines configure it. Only the pool names and ``listen`` values are read. A
    pool without a listen address is kept with an empty one.
    """
    pools: list[tuple[str, str]] = []
    seen: set[str] = set()
    name: str | None = None
    listen: str | None = None
    includes = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in ";#":
            continue
        if line[0] == "[":
            if (started := _pool_section_start(line, pools, seen, name, listen)) is None:
                return None
            name, listen = started
        elif "=" in line:
            includes = includes or line.partition("=")[0].strip() == "include"
            value, ok = _pool_listen(line, name, listen)
            if not ok:
                return None
            listen = value
        else:
            return None
    if not _flush_pool(pools, seen, name, listen):
        return None
    return PoolFile(tuple(pools), includes)


@dataclass(frozen=True)
class SiteFileObservation:
    """One entry of the site directory, with the fields Barectl keeps from it."""

    name: str
    status: ObservationOutcome
    server_names: tuple[str, ...]
    listens: tuple[str, ...]
    source: str
    warning: str


@dataclass(frozen=True)
class SitesObservation:
    status: ObservationOutcome
    source: str
    warning: str
    sites: tuple[SiteFileObservation, ...]


@dataclass(frozen=True)
class PoolEntryObservation:
    """One PHP-FPM pool, with the fields Barectl keeps from it."""

    version: str
    name: str
    status: ObservationOutcome
    listen: str
    source: str
    warning: str


@dataclass(frozen=True)
class PoolsObservation:
    status: ObservationOutcome
    source: str
    warning: str
    pools: tuple[PoolEntryObservation, ...]


def _list_directory(shell: RemoteShell, path: str) -> list[str] | _Failed:
    """A directory's entry names, or why they could not be listed.

    ``-b`` escapes newlines and other nongraphic characters in names, so each entry is
    one line; escaped names fail the entry patterns and are skipped, never split.
    """
    result = shell.run(f"ls -1b {shlex.quote(path)}")
    if result.exit_status != 0 and not result.truncated:
        return _unreadable(shell, path)
    entries = result.stdout.splitlines()
    if result.truncated or len(entries) > MAX_LISTING_ENTRIES:
        return _Failed(
            ObservationOutcome.UNSUPPORTED,
            f"{path} holds more than {MAX_LISTING_ENTRIES} entries. It was not read.",
        )
    return entries


def _bounded(warnings: list[str], message: str) -> None:
    """Append a bounded warning once, stopping at the observation warning cap."""
    message = message[:MAX_WARNING]
    if len(warnings) < MAX_OBSERVATION_WARNINGS and message not in warnings:
        warnings.append(message)


def _overall(outcomes: Iterable[ObservationOutcome], *, listed_empty: bool) -> ObservationOutcome:
    """A collection's outcome from the outcomes of the entries it inspected.

    Anything observed makes the collection observed; the other entries remain partial
    results. Otherwise entries Barectl could not inspect leave no finding: inaccessible
    when permissions refused all of them, unsupported otherwise. When nothing was found,
    a listed location that held nothing to read is an observed empty collection;
    otherwise everything Barectl looked for is absent.
    """
    found = set(outcomes)
    if ObservationOutcome.OBSERVED in found:
        return ObservationOutcome.OBSERVED
    uninspected = found - {ObservationOutcome.ABSENT}
    if uninspected == {ObservationOutcome.INACCESSIBLE}:
        return ObservationOutcome.INACCESSIBLE
    if uninspected:
        return ObservationOutcome.UNSUPPORTED
    return ObservationOutcome.OBSERVED if listed_empty else ObservationOutcome.ABSENT


def _collection_warning(
    status: ObservationOutcome,
    warnings: Sequence[str],
    explanations: dict[ObservationOutcome, str],
    *,
    empty: bool,
) -> str:
    """The collection's warning: why it has its outcome, then what was skipped or refused."""
    parts = list(warnings)
    if status != ObservationOutcome.OBSERVED:
        parts.insert(0, explanations[status])
    elif empty:
        parts.append(explanations[status])
    return " ".join(parts)


_SITES_EXPLANATIONS = {
    ObservationOutcome.OBSERVED: f"No site configuration files are listed in {SITES_ENABLED_DIR}.",
    ObservationOutcome.ABSENT: f"None of the entries listed in {SITES_ENABLED_DIR} exist.",
    ObservationOutcome.INACCESSIBLE: (
        "The SSH user cannot read the site configuration files. Barectl does not use sudo."
    ),
    ObservationOutcome.UNSUPPORTED: (
        f"No file in {SITES_ENABLED_DIR} could be read as a supported Nginx site configuration."
    ),
}


def collect_nginx_sites(
    shell: RemoteShell, nginx: WebStackComponentObservation
) -> SitesObservation:
    """Observe the server's Nginx site configuration files, or why they could not be read.

    The files are read only when the Nginx package observation shows Nginx installed;
    otherwise the observation takes that outcome, as the service observation does.
    """
    if nginx.package_status != ObservationOutcome.OBSERVED:
        return SitesObservation(
            nginx.package_status, nginx.package_source, nginx.package_warning, ()
        )
    listed = _list_directory(shell, SITES_ENABLED_DIR)
    if isinstance(listed, _Failed) and listed.missing:
        return SitesObservation(
            ObservationOutcome.UNSUPPORTED,
            SITES_ENABLED_DIR,
            f"Nginx is installed, but the server has no {SITES_ENABLED_DIR}. Barectl reads "
            "Nginx site files only from the Debian layout.",
            (),
        )
    if isinstance(listed, _Failed):
        return SitesObservation(listed.status, SITES_ENABLED_DIR, listed.warning, ())
    names = [entry for entry in listed if SITE_ENTRY.fullmatch(entry)]
    warnings: list[str] = []
    skipped = len(listed) - len(names)
    if skipped:
        _bounded(
            warnings,
            f"{SITES_ENABLED_DIR} lists {skipped} entries whose names Barectl does not "
            "interpret. They were skipped.",
        )
    if len(names) > MAX_SITES:
        _bounded(
            warnings,
            f"{SITES_ENABLED_DIR} holds more site entries than Barectl reads. Only the "
            f"first {MAX_SITES} were read.",
        )
        names = names[:MAX_SITES]
    sites = [_observe_site(shell, name) for name in names]
    for site in sites:
        # An observed site carries a warning only when it includes files Barectl skips.
        if site.status == ObservationOutcome.OBSERVED and site.warning:
            _bounded(warnings, site.warning)
    status = _overall((site.status for site in sites), listed_empty=not sites)
    warning = _collection_warning(status, warnings, _SITES_EXPLANATIONS, empty=not sites)
    return SitesObservation(status, SITES_ENABLED_DIR, warning, tuple(sites))


def _observe_site(shell: RemoteShell, name: str) -> SiteFileObservation:
    path = f"{SITES_ENABLED_DIR}/{name}"
    text = _read_file(shell, path)
    if isinstance(text, _Failed):
        # The directory listed the entry, so an entry that does not exist, such as a
        # broken symlink, is a finding about that entry.
        status = ObservationOutcome.ABSENT if text.missing else text.status
        return SiteFileObservation(name, status, (), (), path, text.warning)
    parsed = parse_nginx_site(text)
    if parsed is None:
        return SiteFileObservation(
            name,
            ObservationOutcome.UNSUPPORTED,
            (),
            (),
            path,
            f"{path} does not define a supported Nginx site configuration. Only its "
            "server blocks' server_name and listen directives are read.",
        )
    warning = (
        f"{path} includes other configuration files. Barectl does not read them, so server "
        "names and listen addresses they declare are not shown."
        if parsed.includes
        else ""
    )
    return SiteFileObservation(
        name, ObservationOutcome.OBSERVED, parsed.server_names, parsed.listens, path, warning
    )


_POOLS_EXPLANATIONS = {
    ObservationOutcome.OBSERVED: f"No PHP-FPM pools are configured under {PHP_BASE_DIR}.",
    ObservationOutcome.ABSENT: (
        f"None of the PHP-FPM pool files listed under {PHP_BASE_DIR} exist."
    ),
    ObservationOutcome.INACCESSIBLE: (
        "The SSH user cannot read the PHP-FPM pool configuration. Barectl does not use sudo."
    ),
    ObservationOutcome.UNSUPPORTED: (
        f"No PHP-FPM pool configuration under {PHP_BASE_DIR} could be read in a supported form."
    ),
}
_POOL_CAP = f"More than {MAX_POOLS} PHP-FPM pools were found. The rest were skipped."


@dataclass
class _Pools:
    """PHP-FPM pools collected so far, with warnings and the outcomes of what was read."""

    pools: list[PoolEntryObservation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # Outcomes of pool directories and pool files that yielded no pools.
    outcomes: list[ObservationOutcome] = field(default_factory=list)
    # Whether any pool directory was listed.
    listed: bool = False
    capped: bool = False

    def fail(self, failure: _Failed) -> None:
        self.outcomes.append(failure.status)
        _bounded(self.warnings, failure.warning)

    def add(self, row: PoolEntryObservation, directory: str) -> None:
        for index, pool in enumerate(self.pools):
            if pool.version == row.version and pool.name.casefold() == row.name.casefold():
                # PHP-FPM merges repeated pool sections; Barectl does not guess the result.
                self.pools[index] = replace(
                    pool,
                    status=ObservationOutcome.UNSUPPORTED,
                    listen="",
                    warning=(
                        f"Pool {pool.name} is declared more than once under {directory}. "
                        "PHP-FPM merges the declarations; Barectl does not, so its listen "
                        "address is not shown."
                    ),
                )
                return
        if len(self.pools) >= MAX_POOLS:
            self.capped = True
            _bounded(self.warnings, _POOL_CAP)
            return
        self.pools.append(row)

    def observation(self) -> PoolsObservation:
        outcomes = [*self.outcomes, *(pool.status for pool in self.pools)]
        status = _overall(outcomes, listed_empty=self.listed)
        warning = _collection_warning(
            status, self.warnings, _POOLS_EXPLANATIONS, empty=not self.pools
        )
        return PoolsObservation(status, PHP_BASE_DIR, warning, tuple(self.pools))


def _collect_pools_of_version(shell: RemoteShell, version: str, found: _Pools) -> None:
    """One PHP version's pools into ``found``."""
    path = f"{PHP_BASE_DIR}/{version}/{POOL_SUBPATH}"
    entries = _list_directory(shell, path)
    if isinstance(entries, _Failed) and entries.missing:
        found.fail(
            _Failed(
                ObservationOutcome.UNSUPPORTED,
                f"PHP-FPM {version} is installed, but the server has no {path}. Barectl "
                "reads PHP-FPM pools only from the Debian layout.",
            )
        )
        return
    if isinstance(entries, _Failed):
        found.fail(entries)
        return
    found.listed = True
    files = [entry for entry in entries if POOL_FILE.fullmatch(entry)]
    skipped = len(entries) - len(files)
    if skipped:
        _bounded(
            found.warnings,
            f"{path} holds {skipped} entries that PHP-FPM would not load as pool files. "
            "They were skipped.",
        )
    for file in files:
        if found.capped:
            return
        _observe_pool_file(shell, version, file, found)


def collect_php_pools(
    shell: RemoteShell, php_fpm: WebStackComponentObservation
) -> PoolsObservation:
    """Observe the server's PHP-FPM pools, or why they could not be read.

    Pools are read only for the PHP versions of installed PHP-FPM packages; otherwise the
    observation takes the PHP-FPM package observation's outcome, as the service observation
    does. PHP version directories without PHP-FPM are never read.
    """
    if php_fpm.package_status != ObservationOutcome.OBSERVED:
        return PoolsObservation(
            php_fpm.package_status, php_fpm.package_source, php_fpm.package_warning, ()
        )
    versions = [
        match.group(1)
        for line in php_fpm.packages
        if (match := PHP_FPM_PACKAGE.fullmatch(line.partition(" ")[0]))
    ]
    versions.sort(key=lambda version: [int(part) for part in version.split(".")])
    if not versions:
        return PoolsObservation(
            ObservationOutcome.UNSUPPORTED,
            php_fpm.package_source,
            "The dpkg database lists no PHP-FPM package for a specific PHP version, so "
            "Barectl cannot locate its pool directory.",
            (),
        )
    found = _Pools()
    if len(versions) > MAX_VERSIONS:
        _bounded(
            found.warnings,
            f"More PHP-FPM versions are installed than Barectl reads. Only the first "
            f"{MAX_VERSIONS} were inspected.",
        )
        versions = versions[:MAX_VERSIONS]
    for version in versions:
        if found.capped:
            break
        _collect_pools_of_version(shell, version, found)
    return found.observation()


def _observe_pool_file(shell: RemoteShell, version: str, file: str, found: _Pools) -> None:
    """The pools of one pool configuration file into ``found``."""
    directory = f"{PHP_BASE_DIR}/{version}/{POOL_SUBPATH}"
    path = f"{directory}/{file}"
    text = _read_file(shell, path)
    if isinstance(text, _Failed):
        # The directory listed the file, so a file that does not exist, such as a broken
        # symlink, is a finding about that file.
        found.fail(replace(text, status=ObservationOutcome.ABSENT) if text.missing else text)
        return
    parsed = parse_pool_file(text)
    if parsed is None:
        found.fail(
            _Failed(
                ObservationOutcome.UNSUPPORTED,
                f"{path} does not define a supported PHP-FPM pool configuration. Only "
                "pool names and listen addresses are read.",
            )
        )
        return
    if parsed.includes:
        _bounded(
            found.warnings,
            f"{path} includes other configuration files. Barectl does not read them, so "
            "pools they declare are not shown.",
        )
    for name, listen in parsed.pools:
        found.add(
            PoolEntryObservation(
                version,
                name,
                ObservationOutcome.OBSERVED if listen else ObservationOutcome.UNSUPPORTED,
                listen,
                path,
                "" if listen else f"Pool {name} in {path} does not name a listen address.",
            ),
            directory,
        )
