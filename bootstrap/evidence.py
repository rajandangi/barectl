"""Native evidence for plan preparation, and the parsers that validate it.

Every value here was read from a managed server, so each parser accepts only the exact
shapes recorded from Ubuntu 24.04's tools, bounded in length and count. Anything else is
rejected with ``Unreadable``, which preparation records as incomplete evidence rather than
guessing. Nothing here decides eligibility; ``bootstrap.review`` does.
"""

import re
from dataclasses import dataclass, field
from typing import NamedTuple
from urllib.parse import urlsplit

from .models import Privilege
from .native import UnitEvidence

MAX_ENTRIES = 2000
_PACKAGE = r"[a-z0-9][a-z0-9+.-]{0,99}"
_VERSION = r"[A-Za-z0-9.+~:-]{1,100}"
_ARCH = r"[a-z0-9-]{1,20}"


class Unreadable(Exception):
    """Output that is not in a form Barectl interprets, with an operator-facing reason."""


# Platform ------------------------------------------------------------------------------

BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_UPTIME = re.compile(r"(\d{1,12})\.(\d{2}) \d{1,14}\.\d{2}")


def parse_boot_id(text: str) -> str:
    value = text.strip()
    if not BOOT_ID.fullmatch(value):
        raise Unreadable("The boot identity is not a systemd boot ID.")
    return value


def parse_uptime(text: str) -> int:
    """/proc/uptime's first field in hundredths of a second."""
    match = _UPTIME.fullmatch(text.strip())
    if match is None:
        raise Unreadable("/proc/uptime is not in the kernel's format.")
    return int(match[1]) * 100 + int(match[2])


class OsRelease(NamedTuple):
    id: str
    version_id: str
    pretty_name: str


_OS_LINE = re.compile(
    r'(ID|VERSION_ID|PRETTY_NAME)=(?:"([^"\\`$]{0,200})"|([A-Za-z0-9._-]{0,200}))'
)


def parse_os_release(text: str) -> OsRelease:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        match = _OS_LINE.fullmatch(line.strip())
        if match:
            fields[match[1]] = match[2] if match[2] is not None else match[3]
    return OsRelease(
        fields.get("ID", ""), fields.get("VERSION_ID", ""), fields.get("PRETTY_NAME", "")
    )


def parse_architecture(text: str) -> str:
    value = text.strip()
    if not re.fullmatch(_ARCH, value):
        raise Unreadable("dpkg did not report an architecture.")
    return value


def parse_versions(text: str) -> dict[str, str]:
    """``dpkg-query -W -f='${Package}\\t${Version}\\n'`` output."""
    versions: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(rf"({_PACKAGE})\t({_VERSION})", line)
        if match is None:
            raise Unreadable("dpkg-query reported package versions in an unknown form.")
        versions[match[1]] = match[2]
    return versions


# APT configuration ---------------------------------------------------------------------


class ConfigEntry(NamedTuple):
    """One line of ``apt-config dump``: a key, ending in ``::`` for a list item, and value."""

    key: str
    value: str

    @property
    def name(self) -> str:
        """The key as APT compares it: case-insensitive, without a list item's ``::``."""
        return self.key.removesuffix("::").lower()


_CONFIG_LINE = re.compile(r'([^\s"]{1,300}) "([^"\n]{0,2000})";')


def parse_apt_config(text: str) -> tuple[ConfigEntry, ...]:
    entries: list[ConfigEntry] = []
    for line in text.splitlines():
        match = _CONFIG_LINE.fullmatch(line)
        if match is None:
            raise Unreadable("apt-config reported the effective configuration in an unknown form.")
        entries.append(ConfigEntry(match[1], match[2]))
    if len(entries) > MAX_ENTRIES:
        raise Unreadable("The effective APT configuration is larger than Barectl reads.")
    return tuple(entries)


class IndexTarget(NamedTuple):
    """One Packages index APT would download, as ``apt-get indextargets`` describes it."""

    origin: str
    suite: str
    codename: str
    trusted: bool
    component: str
    architecture: str
    # The repository's URI without credentials, such as "http://archive.ubuntu.com/ubuntu".
    site: str


_FIELD = r"[A-Za-z0-9._ +-]{0,100}"


def parse_index_targets(text: str) -> tuple[IndexTarget, ...]:
    """Tab-separated fields: origin, suite, codename, trusted, component, arch, site."""
    targets: list[IndexTarget] = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 7 or not all(re.fullmatch(_FIELD, part) for part in parts[:6]):
            raise Unreadable("apt-get reported its index targets in an unknown form.")
        origin, suite, codename, trusted, component, architecture, site = parts
        if trusted not in {"", "yes", "no"}:
            raise Unreadable("apt-get reported an index's trust in an unknown form.")
        targets.append(
            IndexTarget(
                origin, suite, codename, trusted == "yes", component, architecture, _site(site)
            )
        )
    if len(targets) > MAX_ENTRIES:
        raise Unreadable("APT has more index targets than Barectl reads.")
    return tuple(targets)


def _site(value: str) -> str:
    """The repository's scheme, host and path, dropping any credentials in the URI."""
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        raise Unreadable("apt-get reported a repository address in an unknown form.") from None
    if not re.fullmatch(r"[a-z0-9+]{1,20}", parts.scheme) or len(value) > 500:
        raise Unreadable("apt-get reported a repository address in an unknown form.")
    return f"{parts.scheme}://{host}{port}{parts.path}"


class ConfiguredSource(NamedTuple):
    """One configured Packages index, whether or not it was ever downloaded."""

    # The repository's URI without credentials.
    site: str
    suite: str
    component: str


def parse_configured_sources(text: str) -> tuple[ConfiguredSource, ...]:
    """Tab-separated site, suite and component from ``apt-get indextargets --no-release-info``."""
    sources: list[ConfiguredSource] = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or not all(re.fullmatch(_FIELD, part) for part in parts[1:]):
            raise Unreadable("apt-get reported the configured sources in an unknown form.")
        sources.append(ConfiguredSource(_site(parts[0]), parts[1], parts[2]))
    if len(sources) > MAX_ENTRIES:
        raise Unreadable("APT has more configured sources than Barectl reads.")
    return tuple(dict.fromkeys(sources))


class FileDigest(NamedTuple):
    path: str
    digest: str


def parse_digests(text: str, algorithm_length: int) -> tuple[FileDigest, ...]:
    """``sha256sum`` or ``md5sum`` output. Escaped names (a leading backslash) are refused."""
    digests: list[FileDigest] = []
    for line in text.splitlines():
        match = re.fullmatch(rf"([0-9a-f]{{{algorithm_length}}})  (/[^\t\n\\]{{1,500}})", line)
        if match is None:
            raise Unreadable("A file digest was reported in an unknown form.")
        digests.append(FileDigest(match[2], match[1]))
    if len(digests) > MAX_ENTRIES:
        raise Unreadable("There are more files than Barectl reads.")
    return tuple(digests)


def parse_lines(text: str, pattern: re.Pattern[str], what: str) -> tuple[str, ...]:
    """Lines that each fully match ``pattern``, such as package or file names."""
    lines = tuple(line for line in text.splitlines() if line)
    if len(lines) > MAX_ENTRIES or not all(pattern.fullmatch(line) for line in lines):
        raise Unreadable(f"{what} was reported in an unknown form.")
    return lines


# Package database ----------------------------------------------------------------------


class PackageState(NamedTuple):
    """One package in the dpkg database."""

    name: str
    architecture: str
    version: str
    # dpkg's abbreviated status, such as "ii", "rc" or "hi"; a third letter is an error flag.
    status: str

    @property
    def installed(self) -> bool:
        """Installed and configured, with no error flag."""
        return len(self.status) == 2 and self.status[0] in "ih" and self.status[1] == "i"

    @property
    def absent(self) -> bool:
        """Unknown, or not installed and without configuration files left behind."""
        return len(self.status) == 2 and self.status[1] == "n"


def parse_package_states(text: str) -> tuple[PackageState, ...]:
    """``dpkg-query -W -f='${Package}\\t${Architecture}\\t${Version}\\t${db:Status-Abbrev}\\n'``."""
    states: list[PackageState] = []
    for line in text.splitlines():
        match = re.fullmatch(
            rf"({_PACKAGE})\t({_ARCH})?\t({_VERSION})?\t([uihrp][ncHUFWti][R ]?) ?", line
        )
        if match is None:
            raise Unreadable("dpkg-query reported package states in an unknown form.")
        states.append(PackageState(match[1], match[2] or "", match[3] or "", match[4].strip()))
    return tuple(states)


class Conffile(NamedTuple):
    path: str
    md5: str
    # dpkg no longer ships it, or removes it on upgrade; it is not part of the defaults.
    obsolete: bool


def parse_conffiles(text: str) -> tuple[Conffile, ...]:
    """``dpkg-query -W -f='${Package}\\n${Conffiles}\\n'``: indented lines after each package."""
    conffiles: list[Conffile] = []
    for line in text.splitlines():
        # A package line, or the empty line after a package without configuration files.
        if not line or re.fullmatch(_PACKAGE, line):
            continue
        match = re.fullmatch(
            r" (/[^\s\\]{1,500}) ([0-9a-f]{32}|newconffile)( obsolete| remove-on-upgrade)*", line
        )
        if match is None:
            raise Unreadable("dpkg-query reported configuration files in an unknown form.")
        conffiles.append(Conffile(match[1], match[2], bool(match[3])))
    return tuple(conffiles)


def parse_ucf_hashes(text: str) -> dict[str, str]:
    """``/var/lib/ucf/hashfile``: the MD5 of each file ucf installed, by path."""
    hashes: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{32})  (/[^\s\\]{1,500})", line)
        if match is None:
            raise Unreadable("ucf's registry is in an unknown form.")
        hashes[match[2]] = match[1]
    return hashes


# APT simulation ------------------------------------------------------------------------


class Transition(NamedTuple):
    """One action line of ``apt-get -s``."""

    # "Inst", "Conf", "Remv" or "Purg".
    action: str
    package: str
    # The version installed before, for upgrades, downgrades, reinstalls and removals.
    previous: str
    # The version installed or configured; empty for removals.
    version: str
    architecture: str
    origins: tuple[str, ...]


class Simulation(NamedTuple):
    transitions: tuple[Transition, ...]
    # Why APT's answer cannot be used, such as an error it reported; empty when usable.
    problems: tuple[str, ...]


_INST = re.compile(
    rf"(Inst|Conf) ({_PACKAGE})(?::{_ARCH})? (?:\[({_VERSION})\] )?"
    rf"\(({_VERSION}) ([^\[\]()]{{0,500}}) \[({_ARCH})\]\)(?: \[[^\]]{{0,500}}\])?"
)
_REMOVE = re.compile(
    rf"(Remv|Purg) ({_PACKAGE})(?::{_ARCH})? \[({_VERSION})\](?: \[[^\]]{{0,500}}\])?"
)
_SUMMARY = re.compile(
    r"(\d+) upgraded, (\d+) newly installed, (?:(\d+) downgraded, )?(?:(\d+) reinstalled, )?"
    r"(\d+) to remove and (\d+) not upgraded\."
)


def parse_simulation(text: str) -> Simulation:
    """Read ``apt-get -s install``: every action line strictly, checked against its summary.

    Lines that are not actions, such as APT's progress messages and package lists, are
    ignored; an action line in another form, an error or authentication warning, or counts
    that disagree with the summary make the simulation unusable.
    """
    transitions: list[Transition] = []
    problems: list[str] = []
    summaries: list[re.Match[str]] = []
    for line in text.splitlines():
        if line.startswith(("Inst ", "Conf ", "Remv ", "Purg ")):
            transitions.append(_action(line))
        elif line.startswith(("E: ", "Err")):
            problems.append("APT reported an error while simulating the installation.")
        elif "cannot be authenticated" in line or line.startswith("W: "):
            problems.append("APT reported a warning, such as unauthenticated packages.")
        elif summary := _SUMMARY.fullmatch(line):
            summaries.append(summary)
    if len(transitions) > 400:
        raise Unreadable("APT's simulation proposes more changes than Barectl reviews.")
    if not problems:
        problems.extend(_summary_problems(transitions, summaries))
    return Simulation(tuple(transitions), tuple(dict.fromkeys(problems)))


def _action(line: str) -> Transition:
    """One action line, which must be in exactly the form APT prints."""
    if line.startswith(("Remv ", "Purg ")):
        match = _REMOVE.fullmatch(line)
        if match is None:
            raise Unreadable("APT's simulation reported a removal in an unknown form.")
        return Transition(match[1], match[2], match[3], "", "", ())
    match = _INST.fullmatch(line)
    if match is None:
        raise Unreadable("APT's simulation reported a package action in an unknown form.")
    origins = tuple(origin.strip() for origin in match[5].split(",") if origin.strip())
    return Transition(match[1], match[2], match[3] or "", match[4], match[6], origins)


def _summary_problems(transitions: list[Transition], summaries: list[re.Match[str]]) -> list[str]:
    if len(summaries) != 1:
        return ["APT's simulation did not report one summary of its changes."]
    counts = [int(value or 0) for value in summaries[0].groups()]
    upgraded, installed, downgraded, reinstalled, removed = counts[:5]
    unpacks = [t for t in transitions if t.action == "Inst"]
    new = sum(1 for t in unpacks if not t.previous)
    changed = sum(1 for t in unpacks if t.previous)
    removals = sum(1 for t in transitions if t.action in {"Remv", "Purg"})
    if (new, changed, removals) != (installed, upgraded + downgraded + reinstalled, removed):
        return ["APT's simulated actions do not match its own summary."]
    return []


# Service units and listeners ------------------------------------------------------------


@dataclass(frozen=True)
class UnitState:
    """A service unit as ``systemctl show`` reports it."""

    name: str
    load_state: str
    active_state: str
    sub_state: str
    unit_file_state: str
    fragment_path: str
    drop_in_paths: tuple[str, ...] = field(default=())


UNIT_PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "FragmentPath",
    "DropInPaths",
)


def parse_unit(text: str, name: str) -> UnitState:
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in UNIT_PROPERTIES or len(value) > 2000:
            raise Unreadable("systemctl reported the service unit in an unknown form.")
        values[key] = value
    if set(values) != set(UNIT_PROPERTIES) or values["Id"] != name:
        raise Unreadable("systemctl did not report the service unit's state.")
    token = re.compile(r"[a-z-]{0,30}")
    states = (values["LoadState"], values["ActiveState"], values["SubState"])
    if not all(token.fullmatch(state) for state in (*states, values["UnitFileState"])):
        raise Unreadable("systemctl reported unknown service unit states.")
    return UnitState(
        name,
        *states,
        values["UnitFileState"],
        values["FragmentPath"],
        tuple(values["DropInPaths"].split()),
    )


class Listener(NamedTuple):
    """A listening TCP socket on the profile's port."""

    address: str
    # The processes holding it, when privileged inspection could attribute it.
    processes: tuple[str, ...] | None


_LISTEN = re.compile(r"LISTEN\s+\d+\s+\d+\s+(\S{1,100}):(\d{1,5})\s+\S+(?:\s+(users:\(.*\)))?\s*")


def parse_listeners(text: str, port: int, *, attributed: bool) -> tuple[Listener, ...]:
    """``ss -Hltn`` output for one port, with ``-p`` process names when ``attributed``."""
    listeners: list[Listener] = []
    for line in text.splitlines():
        match = _LISTEN.fullmatch(line)
        if match is None or int(match[2]) != port:
            raise Unreadable("ss reported listening sockets in an unknown form.")
        processes = None
        if attributed:
            processes = tuple(sorted(set(re.findall(r'\("([^"]{1,64})",pid=\d+', match[3] or ""))))
        listeners.append(Listener(match[1], processes))
    return tuple(listeners)


# Configuration trees --------------------------------------------------------------------


class TreeEntry(NamedTuple):
    """One entry of a configuration directory, as ``find -printf '%y\\t%p\\t%l\\n'`` lists it."""

    # find's type letter: "d" directory, "f" file, "l" symbolic link, others refused.
    kind: str
    path: str
    # A link's target; empty otherwise.
    target: str


def parse_tree(text: str, root: str) -> tuple[TreeEntry, ...]:
    entries: list[TreeEntry] = []
    for line in text.splitlines():
        parts = line.split("\t")
        if (
            len(parts) != 3
            or len(parts[0]) != 1
            or not (parts[1] == root or parts[1].startswith(f"{root}/"))
            or any(len(part) > 500 or "\\" in part for part in parts)
        ):
            raise Unreadable(f"The files under {root} were listed in an unknown form.")
        entries.append(TreeEntry(*parts))
    if len(entries) > MAX_ENTRIES:
        raise Unreadable(f"{root} has more files than Barectl reads.")
    return tuple(entries)


@dataclass(frozen=True)
class ConfigTree:
    """A web-stack configuration directory and what preparation could read of it."""

    root: str
    exists: bool
    entries: tuple[TreeEntry, ...] = ()
    # MD5 digests of the regular files that could be read, by path.
    digests: dict[str, str] = field(default_factory=dict)


# Evidence -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Platform:
    boot_id: str
    uptime_centiseconds: int | None
    os: OsRelease
    systemd: bool
    architecture: str
    # Versions of apt, dpkg and systemd from the dpkg database.
    tools: dict[str, str]
    privilege: Privilege
    # The privileged listener query is authorized, so listeners can be attributed.
    listener_privilege: bool


@dataclass(frozen=True)
class AptEvidence:
    config: tuple[ConfigEntry, ...]
    # SHA-256 digests of the files under /etc/apt, except authentication files.
    files: tuple[FileDigest, ...]
    # Source files that set authentication-related options.
    source_overrides: tuple[str, ...]
    # The configured sources, read without the downloaded Release files.
    sources: tuple[ConfiguredSource, ...]
    targets: tuple[IndexTarget, ...]
    # SHA-256 digests of the downloaded InRelease files.
    releases: tuple[FileDigest, ...]
    # bootstrap.native.APT_DIGEST, read before and after the other APT evidence; an apply
    # payload recomputes it on the server. Empty when it could not be read.
    digest: str = ""
    # The two reads differed: the configuration changed while preparation read it.
    changed_while_read: bool = False


@dataclass(frozen=True)
class PackageEvidence:
    audit: str
    holds: tuple[str, ...]
    states: tuple[PackageState, ...]
    automatic: tuple[str, ...]
    # APT's simulation of installing the missing root packages; ``None`` when none is missing.
    simulation: Simulation | None


@dataclass(frozen=True)
class WebEvidence:
    units: tuple[UnitState, ...]
    trees: tuple[ConfigTree, ...]
    conffiles: tuple[Conffile, ...]
    ucf: dict[str, str]
    listeners: tuple[Listener, ...] | None


@dataclass(frozen=True)
class Evidence:
    """Everything one preparation read. A part it could not read is ``None``.

    ``gaps`` explains, in the operator's words, each read that failed; preparation refuses
    a plan with any gap as incomplete evidence.
    """

    platform: Platform | None
    apt: AptEvidence | None
    packages: PackageEvidence | None
    web: WebEvidence | None
    gaps: tuple[str, ...]
    # The retained bootstrap units, for a cleanup of finished runs.
    units: tuple[UnitEvidence, ...] | None = None
