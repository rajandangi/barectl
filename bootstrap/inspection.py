"""docs/ssh-connections.md#plan-preparation"""

import functools
import re
import shlex
from collections.abc import Callable, Iterable
from typing import Final

from discovery.ssh import CommandResult, RemoteShell

from . import native, profiles, releases
from .evidence import (
    UNIT_PROPERTIES,
    AptEvidence,
    Conffile,
    ConfigTree,
    Evidence,
    Offer,
    OsRelease,
    PackageEvidence,
    PackageState,
    Platform,
    Simulation,
    UnitState,
    Unreadable,
    WebEvidence,
    parse_apt_config,
    parse_architecture,
    parse_boot_id,
    parse_conffiles,
    parse_configured_sources,
    parse_digests,
    parse_index_targets,
    parse_lines,
    parse_listeners,
    parse_offers,
    parse_os_release,
    parse_package_states,
    parse_release_validity,
    parse_simulation,
    parse_socket_listeners,
    parse_tree,
    parse_ucf_hashes,
    parse_unit,
    parse_uptime,
    parse_versions,
)
from .models import Action, Privilege
from .profiles import Profile

BOOT_ID: Final = "cat /proc/sys/kernel/random/boot_id"
UPTIME: Final = "cat /proc/uptime"
OS_RELEASE: Final = "cat /etc/os-release"
# sd_booted(3): systemd is the running system manager when this directory exists.
SYSTEMD: Final = "test -d /run/systemd/system"
ARCHITECTURE: Final = "dpkg --print-architecture"
TOOL_VERSIONS: Final = "dpkg-query -W -f='${Package}\\t${Version}\\n' apt dpkg systemd"
USER_ID: Final = "id -u"
# Listing the command a later apply submits through runs nothing.
SUDO_APPLY: Final = f"sudo -n -l {profiles.APPLY_ENTRYPOINT}"
APT_CONFIG: Final = "LC_ALL=C apt-config dump"
# Every file under /etc/apt except authentication files, which can hold credentials.
APT_FILES: Final = (
    "find /etc/apt -xdev -type f ! -path '/etc/apt/auth.conf*' -exec sha256sum -- {} +"
)
# Source files that disable or weaken authentication for a repository.
_AUTH_OPTIONS = (
    "^[^#]*(^|[[:space:][])(trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure"
    "|check-valid-until)[[:space:]]*[=:]"
)
SOURCE_OVERRIDES: Final = (
    "find /etc/apt -maxdepth 2 -xdev -type f \\( -path /etc/apt/sources.list -o -path "
    f"'/etc/apt/sources.list.d/*' \\) -exec grep -qiE -- {shlex.quote(_AUTH_OPTIONS)} {{}} \\; "
    "-print"
)
INDEX_TARGETS: Final = (
    "LC_ALL=C apt-get indextargets --format "
    "'$(ORIGIN)|$(SUITE)|$(CODENAME)|$(RELEASE)|$(TRUSTED)|$(COMPONENT)|$(ARCHITECTURE)"
    "|$(SITE)' "
    "'Created-By: Packages'"
)
# The configured sources, which APT lists even before any index was downloaded.
CONFIGURED_SOURCES: Final = (
    "LC_ALL=C apt-get indextargets --no-release-info --format "
    "'$(SITE)|$(RELEASE)|$(COMPONENT)' 'Created-By: Packages'"
)
RELEASES: Final = (
    "find /var/lib/apt/lists -maxdepth 1 -type f -name '*_InRelease' -exec sha256sum -- {} +"
)
# grep exits 1 when no InRelease file has any of these fields.
RELEASE_VALIDITY: Final = (
    "date -u +%s; find /var/lib/apt/lists -maxdepth 1 -type f -name '*_InRelease' "
    "-exec grep -H -E '^(Origin|Suite|Valid-Until):' -- {} +"
)
DPKG_AUDIT: Final = "LC_ALL=C dpkg --audit"
HOLDS: Final = "apt-mark showhold"
UCF_HASHES: Final = "cat /var/lib/ucf/hashfile"
_STATE_FORMAT = "'${Package}\\t${Architecture}\\t${Version}\\t${db:Status-Abbrev}\\n'"


def package_states(names: Iterable[str]) -> str:
    return f"dpkg-query -W -f={_STATE_FORMAT} {' '.join(names)}"


def release_states(pattern: str) -> str:
    return f"dpkg-query -W -f={_STATE_FORMAT} {shlex.quote(pattern)}"


def automatic_marks(names: Iterable[str]) -> str:
    return f"apt-mark showauto {' '.join(names)}"


def manual_marks(names: Iterable[str]) -> str:
    return f"apt-mark showmanual {' '.join(names)}"


# The addresses ss reports for a socket listening on every IPv4 and every IPv6 address.
WILDCARD_LISTENERS: Final = ("0.0.0.0", "[::]")  # noqa: S104 - reported addresses, not a bind


def simulate(names: Iterable[str]) -> str:
    return (
        "LC_ALL=C apt-get -s -o APT::Install-Recommends=0 -o APT::Install-Suggests=0 "
        f"install {' '.join(names)}"
    )


def offers(names: Iterable[str]) -> str:
    return f"LC_ALL=C apt-cache madison {' '.join(names)}"


def unit_state(name: str) -> str:
    return f"systemctl show {name} " + " ".join(f"-p {prop}" for prop in UNIT_PROPERTIES)


def exists(path: str) -> str:
    return f"test -e {path}"


def tree(root: str) -> str:
    return f"find {root} -xdev -printf '%y\\t%p\\t%l\\n'"


def tree_digests(root: str) -> str:
    return f"find {root} -xdev -type f -exec md5sum -- {{}} +"


def conffiles(names: Iterable[str]) -> str:
    return f"dpkg-query -W -f='${{Package}}\\n${{Conffiles}}\\n' {' '.join(names)}"


def listeners(port: int, privilege: Privilege, *, attributed: bool) -> str:
    """The listening TCP sockets on ``port``, with process names when ``attributed``."""
    if not attributed:
        return f"ss -Hltn sport = :{port}"
    query = _privileged_listeners(port)
    return f"sudo -n {query}" if privilege == Privilege.SUDO else query


def _privileged_listeners(port: int) -> str:
    return f"/usr/bin/ss -Hltnp sport = :{port}"


def sudo_listeners(port: int) -> str:
    return f"sudo -n -l {_privileged_listeners(port)}"


def socket_listeners(path: str) -> str:
    """The Unix sockets listening at ``path``; readable without privilege."""
    return f"ss -Hlx src {path}"


def entries(directory: str) -> str:
    return f"find {directory} -mindepth 1 -maxdepth 1 -printf '%f\\n'"


class _Reader:
    def __init__(self, shell: RemoteShell) -> None:
        self.shell = shell
        self.gaps: list[str] = []

    def read(self, command: str, what: str, *, ok: tuple[int, ...] = (0,)) -> str | None:
        result = self.shell.run(command)
        if result.truncated:
            self.gaps.append(f"{what} was larger than Barectl reads.")
            return None
        if result.exit_status not in ok:
            self.gaps.append(f"Barectl could not read {what}{_because(result)}")
            return None
        return result.stdout

    def status(self, command: str) -> int:
        return self.shell.run(command).exit_status

    def parse[T](self, text: str | None, parser: Callable[[str], T]) -> T | None:
        if text is None:
            return None
        try:
            return parser(text)
        except Unreadable as unreadable:
            self.gaps.append(str(unreadable))
            return None


def _because(result: CommandResult) -> str:
    if result.exit_status == 127:
        return ": the command is not installed."
    if result.exit_status == 126:
        return ": the SSH user cannot run the command."
    return "."


def inspect(shell: RemoteShell, action: Action) -> Evidence:
    """docs/adr/0008-review-each-ubuntu-release-by-its-own-policy.md#the-release-decides-every-rule"""
    reader = _Reader(shell)
    platform = _platform(reader)
    release = releases.of(platform.os) if platform is not None else None
    if release is None:
        return Evidence(platform, None, None, None, tuple(reader.gaps))
    if action == Action.CLEAR_RESULTS:
        units = _retained(reader)
        return Evidence(platform, None, None, None, tuple(reader.gaps), units)
    apt = _apt(reader)
    if action == Action.METADATA_REFRESH:
        return Evidence(platform, apt, None, None, tuple(reader.gaps))
    profile = profiles.profile(release, action)
    before = _package_digest(reader, profile)
    packages = _packages(reader, profile)
    installed = {state.name for state in packages.states if state.installed} if packages else set()
    privilege = platform.privilege if platform else Privilege.UNAVAILABLE
    attributed = bool(platform and platform.listener_privilege)
    web = _web(reader, profile, installed, privilege, attributed=attributed)
    after = _package_digest(reader, profile)
    return Evidence(
        platform,
        apt,
        packages,
        web,
        tuple(reader.gaps),
        package_digest=after or "",
        package_changed_while_read=before is not None and after is not None and before != after,
    )


def _package_digest(reader: _Reader, profile: Profile) -> str | None:
    return reader.parse(
        reader.read(profile.revalidation, "the digest of the package and service evidence"),
        _digest,
    )


def _platform(reader: _Reader) -> Platform | None:
    uptime = reader.parse(reader.read(UPTIME, "the server's uptime"), parse_uptime)
    boot_id = reader.parse(reader.read(BOOT_ID, "the boot identity"), parse_boot_id)
    os = reader.parse(reader.read(OS_RELEASE, "/etc/os-release"), parse_os_release)
    architecture = reader.parse(
        reader.read(ARCHITECTURE, "dpkg's architecture"), parse_architecture
    )
    tools = reader.parse(reader.read(TOOL_VERSIONS, "the package tool versions"), parse_versions)
    systemd = reader.status(SYSTEMD) == 0
    user = reader.read(USER_ID, "the SSH user's identity")
    privilege = Privilege.UNAVAILABLE
    listener_privilege = False
    if user is not None and user.strip() == "0":
        privilege = Privilege.ROOT
        listener_privilege = True
    elif _authorized(reader, SUDO_APPLY, profiles.APPLY_ENTRYPOINT):
        privilege = Privilege.SUDO
        port = profiles.HTTP_PORT
        listener_privilege = _authorized(reader, sudo_listeners(port), _privileged_listeners(port))
    return Platform(
        boot_id or "",
        uptime,
        os or OsRelease("", "", ""),
        systemd,
        architecture or "",
        tools or {},
        privilege,
        listener_privilege,
    )


def _retained(reader: _Reader) -> tuple[native.UnitEvidence, ...] | None:
    return reader.parse(
        reader.read(native.RETAINED_STATES, "the retained bootstrap units"), _retained_states
    )


def _retained_states(text: str) -> tuple[native.UnitEvidence, ...]:
    try:
        _, units = native.parse_retained_states(text)
    except native.Unreadable:
        raise Unreadable("The retained bootstrap units are in an unknown form.") from None
    return tuple(units)


def _authorized(reader: _Reader, listing: str, command: str) -> bool:
    """Whether ``sudo -n -l`` lists ``command`` as authorized without a password."""
    result = reader.shell.run(listing)
    return result.exit_status == 0 and result.stdout.strip() == command


def _apt(reader: _Reader) -> AptEvidence | None:
    before = _apt_digest(reader)
    config = reader.parse(
        reader.read(APT_CONFIG, "the effective APT configuration"), parse_apt_config
    )
    files = reader.parse(
        reader.read(APT_FILES, "the files under /etc/apt"), lambda text: parse_digests(text, 64)
    )
    overrides = reader.parse(
        reader.read(SOURCE_OVERRIDES, "the APT source options"),
        lambda text: parse_lines(text, _SOURCE_FILE, "An APT source file"),
    )
    targets = reader.parse(
        reader.read(INDEX_TARGETS, "APT's index targets"),
        lambda text: parse_index_targets(text.replace("|", "\t")),
    )
    sources = reader.parse(
        reader.read(CONFIGURED_SOURCES, "APT's configured sources"),
        lambda text: parse_configured_sources(text.replace("|", "\t")),
    )
    releases = reader.parse(
        reader.read(RELEASES, "the downloaded Release files"),
        lambda text: parse_digests(text, 64),
    )
    validity = reader.parse(
        reader.read(RELEASE_VALIDITY, "the Release files' validity", ok=(0, 1)),
        parse_release_validity,
    )
    if config is None or files is None or overrides is None:
        return None
    if sources is None or targets is None:
        return None
    after = _apt_digest(reader)
    return AptEvidence(
        config,
        files,
        overrides,
        sources,
        targets,
        releases or (),
        digest=after or "",
        changed_while_read=before is not None and after is not None and before != after,
        validity=validity,
    )


def _apt_digest(reader: _Reader) -> str | None:
    return reader.parse(
        reader.read(native.APT_DIGEST, "the digest of the APT configuration"), _digest
    )


def _digest(text: str) -> str:
    try:
        return native.parse_digest(text)
    except native.Unreadable:
        raise Unreadable("A digest of the server's evidence is in an unknown form.") from None


_SOURCE_FILE = re.compile(r"/etc/apt/sources\.list(\.d/[^\s\\]{1,200})?")


def _packages(reader: _Reader, profile: Profile) -> PackageEvidence | None:
    audit = reader.read(
        DPKG_AUDIT,
        "dpkg's audit of the package database, which dpkg refuses to accounts other than "
        "root while an interrupted package change is unfinished; finish it with "
        "sudo dpkg --configure -a, then prepare again",
    )
    holds = reader.parse(
        reader.read(HOLDS, "the held packages"),
        lambda text: parse_lines(text, _PACKAGE_WITH_ARCH, "A held package"),
    )
    queried = profile.packages
    states = _states(reader, queried)
    if states is None or audit is None or holds is None:
        return None
    by_name = {state.name: state for state in states}
    missing = [root for root in profile.roots if root not in by_name or not by_name[root].installed]
    simulation = None
    offered: tuple[Offer, ...] = ()
    if missing and all(root not in by_name or by_name[root].absent for root in missing):
        simulated = _simulate(reader, missing, queried)
        if simulated is None:
            return None
        simulation, more, offered = simulated
        states = states + more
    releases: tuple[PackageState, ...] = ()
    if profile.releases is not None:
        found = reader.parse(
            reader.read(
                release_states(profile.releases.pattern), "the other releases' packages", ok=(0, 1)
            ),
            parse_package_states,
        )
        if found is None:
            return None
        releases = tuple(
            state
            for state in found
            if not state.absent and not state.name.startswith(profile.releases.supported)
        )
    installed = sorted({state.name for state in states if state.installed})
    automatic: tuple[str, ...] = ()
    if installed:
        marks = reader.parse(
            reader.read(automatic_marks(installed), "the automatic installation marks"),
            lambda text: parse_lines(text, _PACKAGE_WITH_ARCH, "An automatic installation mark"),
        )
        if marks is None:
            return None
        automatic = marks
    return PackageEvidence(audit, holds, states, automatic, simulation, releases, offered)


def _simulate(
    reader: _Reader, missing: list[str], queried: tuple[str, ...]
) -> tuple[Simulation, tuple[PackageState, ...], tuple[Offer, ...]] | None:
    text = reader.read(simulate(missing), "APT's simulation of the installation", ok=(0, 100))
    simulation = reader.parse(text, parse_simulation)
    if simulation is None:
        return None
    changed = tuple(dict.fromkeys(t.package for t in simulation.transitions))
    states: tuple[PackageState, ...] | None = ()
    extra = tuple(name for name in changed if name not in queried)
    if extra:
        states = _states(reader, extra)
    offered: tuple[Offer, ...] | None = ()
    if changed:
        offered = reader.parse(
            reader.read(offers(changed), "the versions APT's sources offer"), parse_offers
        )
    if states is None or offered is None:
        return None
    return simulation, states, offered


_PACKAGE_WITH_ARCH = re.compile(r"[a-z0-9][a-z0-9+.-]{0,99}(:[a-z0-9-]{1,20})?")


def _states(reader: _Reader, names: Iterable[str]) -> tuple[PackageState, ...] | None:
    # dpkg-query exits 1 when some packages are unknown, which is not a failure here.
    return reader.parse(
        reader.read(package_states(names), "the package states", ok=(0, 1)),
        parse_package_states,
    )


def _web(
    reader: _Reader,
    profile: Profile,
    installed: set[str],
    privilege: Privilege,
    *,
    attributed: bool,
) -> WebEvidence | None:
    units: list[UnitState] = []
    for name in profile.units:
        text = reader.read(unit_state(name), f"the state of {name}")
        unit = reader.parse(text, functools.partial(parse_unit, name=name))
        if unit is not None:
            units.append(unit)
    trees = [_tree(reader, spec.root) for spec in profile.trees]
    owners = sorted({spec.owner for spec in profile.trees if spec.owner in installed})
    found: tuple[Conffile, ...] | None = ()
    if owners:
        found = reader.parse(
            reader.read(conffiles(owners), "the packages' configuration files", ok=(0, 1)),
            parse_conffiles,
        )
    ucf: dict[str, str] | None = {}
    if profile.ucf and any(spec.owner in installed for spec in profile.trees):
        ucf = reader.parse(reader.read(UCF_HASHES, "ucf's registry"), parse_ucf_hashes)
    found_listeners = None
    if profile.port:
        found_listeners = reader.parse(
            reader.read(
                listeners(profile.port, privilege, attributed=attributed),
                "the listening sockets",
            ),
            lambda text: parse_listeners(text, profiles.HTTP_PORT, attributed=attributed),
        )
    sockets: tuple[str, ...] | None = ()
    if profile.socket is not None:
        sockets = reader.parse(
            reader.read(socket_listeners(profile.socket), "the listening local sockets"),
            parse_socket_listeners,
        )
    layout = {directory: _entries(reader, directory) for directory in profile.layout}
    if (
        len(units) != len(profile.units)
        or any(item is None for item in trees)
        or found is None
        or ucf is None
        or (profile.port and found_listeners is None)
        or sockets is None
        or any(names is None for names in layout.values())
    ):
        return None
    return WebEvidence(
        tuple(units),
        tuple(item for item in trees if item is not None),
        found,
        ucf,
        found_listeners,
        sockets,
        {directory: names for directory, names in layout.items() if names is not None},
    )


def _entries(reader: _Reader, directory: str) -> tuple[str, ...] | None:
    """The names directly under ``directory``; empty when it does not exist."""
    present = reader.status(exists(directory))
    if present == 1:
        return ()
    if present != 0:
        reader.gaps.append(f"Barectl could not check whether {directory} exists.")
        return None
    return reader.parse(
        reader.read(entries(directory), f"the entries of {directory}"),
        lambda text: parse_lines(text, _ENTRY, f"An entry of {directory}"),
    )


_ENTRY = re.compile(r"[A-Za-z0-9._+-]{1,100}")


def _tree(reader: _Reader, root: str) -> ConfigTree | None:
    present = reader.status(exists(root))
    if present == 1:
        return ConfigTree(root, exists=False)
    if present != 0:
        reader.gaps.append(f"Barectl could not check whether {root} exists.")
        return None
    entries = reader.parse(
        reader.read(tree(root), f"the files under {root}"),
        lambda text: parse_tree(text, root),
    )
    # md5sum exits 1 when it cannot read a file; the review finds that file undigested.
    digests = reader.parse(
        reader.read(tree_digests(root), f"the files under {root}", ok=(0, 1)),
        lambda text: parse_digests(text, 32),
    )
    if entries is None or digests is None:
        return None
    return ConfigTree(root, True, entries, {item.path: item.digest for item in digests})
