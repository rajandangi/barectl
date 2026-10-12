"""docs/ssh-connections.md#plan-preparation

Parsers accept only the forms recorded from the supported release's tools, bounded in
length and count; anything else is ``Unreadable``, never guessed.
"""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
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
    for number, line in enumerate(text.splitlines(), start=1):
        match = _CONFIG_LINE.fullmatch(line)
        if match is None:
            # Only the line's number: a value can hold credentials, such as a proxy's.
            raise Unreadable(
                "apt-config reported the effective configuration in an unknown form at line "
                f"{number}."
            )
        entries.append(ConfigEntry(match[1], match[2]))
    if len(entries) > MAX_ENTRIES:
        raise Unreadable("The effective APT configuration is larger than Barectl reads.")
    return tuple(entries)


class IndexTarget(NamedTuple):
    """One Packages index APT would download, as ``apt-get indextargets`` describes it."""

    origin: str
    suite: str
    codename: str
    # The suite as the source configures it, which ``apt-cache madison`` names.
    release: str
    trusted: bool
    component: str
    architecture: str
    # The repository's URI without credentials, such as "http://archive.ubuntu.com/ubuntu".
    site: str


_FIELD = r"[A-Za-z0-9._ +-]{0,100}"
_TARGET_FIELDS = ("origin", "suite", "codename", "release", "trust", "component", "architecture")
# APT prints a field that the downloaded Release file lacks as the field's placeholder.
_RELEASE_FILE_FIELDS = {"origin": "$(ORIGIN)", "suite": "$(SUITE)", "codename": "$(CODENAME)"}


def parse_index_targets(text: str) -> tuple[IndexTarget, ...]:
    """Tab-separated fields: origin, suite, codename, release, trusted, component, arch, site."""
    targets: list[IndexTarget] = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 8:
            raise Unreadable(
                f"apt-get reported its index targets in an unknown form: a target has "
                f"{len(parts)} fields instead of 8."
            )
        address = _site(parts[7])
        fields = [
            "" if value == _RELEASE_FILE_FIELDS.get(name) else value
            for name, value in zip(_TARGET_FIELDS, parts[:7], strict=True)
        ]
        for name, value in zip(_TARGET_FIELDS, fields, strict=True):
            if not re.fullmatch(_FIELD, value):
                raise Unreadable(
                    f"apt-get reported its index targets in an unknown form: the {name} of "
                    f"an index from {address} is not in a form Barectl reads."
                )
        origin, suite, codename, release, trusted, component, architecture = fields
        if trusted not in {"", "yes", "no"}:
            raise Unreadable("apt-get reported an index's trust in an unknown form.")
        targets.append(
            IndexTarget(
                origin,
                suite,
                codename,
                release,
                trusted == "yes",
                component,
                architecture,
                address,
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
        if len(parts) != 3:
            raise Unreadable("apt-get reported the configured sources in an unknown form.")
        address = _site(parts[0])
        if not all(re.fullmatch(_FIELD, part) for part in parts[1:]):
            raise Unreadable(
                "apt-get reported the configured sources in an unknown form: the suite or "
                f"component of a source at {address} is not in a form Barectl reads."
            )
        sources.append(ConfiguredSource(address, parts[1], parts[2]))
    if len(sources) > MAX_ENTRIES:
        raise Unreadable("APT has more configured sources than Barectl reads.")
    return tuple(dict.fromkeys(sources))


class Offer(NamedTuple):
    """One package version that one downloaded Packages index offers."""

    package: str
    version: str
    # The index, named as ``IndexTarget`` names it.
    site: str
    release: str
    component: str
    architecture: str


_WORD = r"[A-Za-z0-9._+-]{1,100}"
_OFFER = re.compile(
    rf" {{0,9}}({_PACKAGE})(?::{_ARCH})? \| {{0,9}}({_VERSION}) \| (\S{{1,500}}) (.{{1,300}})"
)
_OFFERED_BINARY = re.compile(rf"({_WORD})/({_WORD}) ({_ARCH}) Packages")
_OFFERED_SOURCE = re.compile(rf"{_WORD}/{_WORD} Sources")


def parse_offers(text: str) -> tuple[Offer, ...]:
    """``apt-cache madison``: every version of the named packages each index offers.

    Source package lines are skipped, since no source package is installed.
    """
    offers: list[Offer] = []
    for line in text.splitlines():
        match = _OFFER.fullmatch(line)
        if match is None:
            raise Unreadable("apt-cache reported the versions sources offer in an unknown form.")
        site = _site(match[3])
        if _OFFERED_SOURCE.fullmatch(match[4]):
            continue
        index = _OFFERED_BINARY.fullmatch(match[4])
        if index is None:
            raise Unreadable(
                "apt-cache reported the versions sources offer in an unknown form: an index "
                f"of {site} is not described as Barectl reads it."
            )
        offers.append(Offer(match[1], match[2], site, index[1], index[2], index[3]))
    if len(offers) > MAX_ENTRIES:
        raise Unreadable("APT's sources offer more versions than Barectl reads.")
    return tuple(offers)


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


class ReleaseValidity(NamedTuple):
    path: str
    origin: str
    suite: str
    valid_until: datetime | None


class ReleaseValidities(NamedTuple):
    # The server's clock when it read the files.
    now: datetime
    releases: tuple[ReleaseValidity, ...]


# A repository's port is part of its lists' file names, such as 127.0.0.1:8750_dists_...
_RELEASE_FIELD = re.compile(
    r"(/var/lib/apt/lists/[^/\s]{1,250}_InRelease):(Origin|Suite|Valid-Until): ?(.{0,200})"
)


def parse_release_validity(text: str) -> ReleaseValidities:
    """The server's clock in seconds, then ``grep -H`` lines of the InRelease files' fields."""
    lines = text.splitlines()
    if not lines or not re.fullmatch(r"\d{1,12}", lines[0]):
        raise Unreadable("The server's clock was not reported in seconds.")
    now = datetime.fromtimestamp(int(lines[0]), UTC)
    fields: dict[str, dict[str, str]] = {}
    for line in lines[1:]:
        match = _RELEASE_FIELD.fullmatch(line)
        if match is None:
            raise Unreadable("A Release file's fields were reported in an unknown form.")
        path, name, value = match.groups()
        entry = fields.setdefault(path, {})
        if name in entry:
            raise Unreadable("A Release file repeats a field.")
        entry[name] = value.strip()
    if len(fields) > MAX_ENTRIES:
        raise Unreadable("There are more Release files than Barectl reads.")
    return ReleaseValidities(
        now,
        tuple(
            ReleaseValidity(
                path,
                entry.get("Origin", ""),
                entry.get("Suite", ""),
                _release_date(entry["Valid-Until"]) if "Valid-Until" in entry else None,
            )
            for path, entry in sorted(fields.items())
        ),
    )


def _release_date(value: str) -> datetime:
    """A Release file's date, such as ``Sat, 03 Oct 2026 12:00:00 UTC``."""
    try:
        date = parsedate_to_datetime(value)
    except TypeError, ValueError:
        raise Unreadable("A Release file's Valid-Until date is in an unknown form.") from None
    return date if date.tzinfo is not None else date.replace(tzinfo=UTC)


def parse_lines(text: str, pattern: re.Pattern[str], what: str) -> tuple[str, ...]:
    lines = tuple(line for line in text.splitlines() if line)
    if len(lines) > MAX_ENTRIES or not all(pattern.fullmatch(line) for line in lines):
        raise Unreadable(f"{what} was reported in an unknown form.")
    return lines


# Package database ----------------------------------------------------------------------


class PackageState(NamedTuple):
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
    """Read ``apt-get -s install``: every action line strictly, checked against its summary."""
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


_SOCKET_LISTEN = re.compile(
    r"u_(?:str|seq|dgr)\s+LISTEN\s+\d+\s+\d+\s+(/\S{1,200})\s+\d+\s+\*\s+\d+\s*"
)


def parse_socket_listeners(text: str) -> tuple[str, ...]:
    """``ss -Hlx src <path>`` output: the paths of the listening Unix sockets."""
    paths: list[str] = []
    for line in text.splitlines():
        match = _SOCKET_LISTEN.fullmatch(line)
        if match is None:
            raise Unreadable("ss reported listening local sockets in an unknown form.")
        paths.append(match[1])
    return tuple(paths)


_FILE_TYPE = re.compile(
    r"(directory|regular (?:empty )?file|symbolic link|[a-z ]{1,40}) ([a-z0-9_.-]{1,32}|UNKNOWN)"
)


def parse_file_type(text: str) -> str:
    """``stat -c '%F %U'``: the file's type and owner, such as ``directory mysql``."""
    value = text.strip()
    if not _FILE_TYPE.fullmatch(value):
        raise Unreadable("stat reported a data directory in an unknown form.")
    return value


class AlternativeState(NamedTuple):
    """``update-alternatives --query``: an alternative's mode and current value."""

    status: str
    value: str


def parse_alternative(text: str) -> AlternativeState:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        name, separator, value = line.partition(": ")
        if separator and name in {"Status", "Value"}:
            fields[name] = value
    status, value = fields.get("Status", ""), fields.get("Value", "")
    if status not in {"auto", "manual"} or not re.fullmatch(r"/[^\s\\]{1,300}", value):
        raise Unreadable("update-alternatives reported an alternative in an unknown form.")
    return AlternativeState(status, value)


def parse_path(text: str) -> str:
    """``readlink -f``: the resolved path, or empty when it printed nothing."""
    value = text.strip()
    if value and not re.fullmatch(r"/[^\s\\]{0,300}", value):
        raise Unreadable("readlink reported a path in an unknown form.")
    return value


@dataclass(frozen=True)
class Readiness:
    """The profile's final check, as preparation could run it with privilege.

    ``state`` is "read" when the check ran, with its exit status and output; "stopped"
    when the service does not run; "unprivileged" when the SSH user is not root and sudo
    does not authorize the exact check.
    """

    state: str
    exit_status: int = 0
    output: str = ""


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
    # The privileged listener query is authorized for this port, so listeners can be
    # attributed; ``None`` when none was checked.
    listener_privilege: bool
    listener_port: int | None = None


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
    # bootstrap.native.APT_DIGEST; empty when it could not be read.
    digest: str = ""
    changed_while_read: bool = False
    # ``None`` when the Release files could not be read.
    validity: ReleaseValidities | None = None


@dataclass(frozen=True)
class PackageEvidence:
    audit: str
    holds: tuple[str, ...]
    states: tuple[PackageState, ...]
    automatic: tuple[str, ...]
    # APT's simulation of installing the missing root packages; ``None`` when none is missing.
    simulation: Simulation | None
    # Packages of the software's other releases that are installed or left configuration.
    releases: tuple[PackageState, ...] = ()
    # Every version any index offers of the packages the simulation would change.
    offers: tuple[Offer, ...] = ()
    # Packages matching the profile's conflicts that are installed or left configuration.
    conflicts: tuple[PackageState, ...] = ()
    # The installed version a pinned root must be requested at when no source offers the
    # root at it, so nothing was simulated; empty otherwise.
    unpinned: str = ""


@dataclass(frozen=True)
class WebEvidence:
    units: tuple[UnitState, ...]
    trees: tuple[ConfigTree, ...]
    conffiles: tuple[Conffile, ...]
    ucf: dict[str, str]
    listeners: tuple[Listener, ...] | None
    # The paths of Unix sockets listening at the profile's socket.
    sockets: tuple[str, ...] = ()
    # The entries directly under each of the profile's layout directories, by directory.
    layout: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # The type and owner of each of the profile's paths, such as "directory mysql"; empty
    # for a path that does not exist.
    data: dict[str, str] = field(default_factory=dict)
    # The profile's alternative, ``None`` when it does not exist, and what its link
    # resolves to.
    alternative: AlternativeState | None = None
    resolved: str = ""
    # The effective configuration's report, when the profile reads one.
    defaults: str = ""
    readiness: Readiness = field(default_factory=lambda: Readiness("stopped"))
    # What php-fpm -m lists, when the profile enables PHP modules.
    modules: str = ""
    # What the selected CLI's php -m lists, when the profile compares it with PHP-FPM.
    cli_modules: str = ""


@dataclass(frozen=True)
class PhpSourceEvidence:
    admitted: bool
    refusals: tuple[str, ...] = ()
    digest: str = ""


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
    # Profile.revalidation's digest; empty when it could not be read.
    package_digest: str = ""
    package_changed_while_read: bool = False
    php_source: PhpSourceEvidence | None = None
