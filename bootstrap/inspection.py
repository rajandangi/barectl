"""docs/ssh-connections.md#plan-preparation"""

import dataclasses
import functools
import re
import shlex
from collections.abc import Callable, Iterable
from typing import Final

from discovery.ssh import CommandResult, RemoteShell

from . import native, php_supply, profiles, releases
from .evidence import (
    UNIT_PROPERTIES,
    AlternativeState,
    AptEvidence,
    Conffile,
    ConfigTree,
    Evidence,
    Offer,
    OsRelease,
    PackageEvidence,
    PackageState,
    Platform,
    Readiness,
    Simulation,
    UnitState,
    Unreadable,
    WebEvidence,
    parse_alternative,
    parse_apt_config,
    parse_architecture,
    parse_boot_id,
    parse_conffiles,
    parse_configured_sources,
    parse_digests,
    parse_file_type,
    parse_index_targets,
    parse_lines,
    parse_listeners,
    parse_offers,
    parse_os_release,
    parse_package_states,
    parse_path,
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


def conflict_states(patterns: Iterable[str]) -> str:
    return f"dpkg-query -W -f={_STATE_FORMAT} {' '.join(map(shlex.quote, patterns))}"


def automatic_marks(names: Iterable[str]) -> str:
    return f"apt-mark showauto {' '.join(names)}"


def manual_marks(names: Iterable[str]) -> str:
    return f"apt-mark showmanual {' '.join(names)}"


def simulate(names: Iterable[str]) -> str:
    return (
        "LC_ALL=C apt-get -s -o APT::Install-Recommends=0 -o APT::Install-Suggests=0 "
        f"install {' '.join(shlex.quote(name) for name in names)}"
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


def file_type(path: str) -> str:
    return f"stat -c '%F %U' -- {path}"


def present(path: str) -> str:
    """Exits 0 when ``path`` exists, including as a dangling symbolic link."""
    return f"test -e {path} || test -L {path}"


def alternative(name: str) -> str:
    return f"update-alternatives --query {name}"


def resolve(path: str) -> str:
    return f"readlink -f -- {path}"


class Reader:
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


def inspect(
    shell: RemoteShell, action: Action, *, version: str | None = None, supply: str = "ubuntu"
) -> Evidence:
    """docs/adr/0008-review-each-ubuntu-release-by-its-own-policy.md#the-release-decides-every-rule"""
    reader = Reader(shell)
    platform = read_platform(reader)
    release = releases.of(platform.os) if platform is not None else None
    if release is None:
        return Evidence(platform, None, None, None, tuple(reader.gaps))
    if action == Action.CLEAR_RESULTS:
        units = _retained(reader)
        return Evidence(platform, None, None, None, tuple(reader.gaps), units)
    apt = _apt(reader)
    source = None
    if platform is not None and (
        supply == "sury"
        or (
            apt is not None
            and any(
                item.path
                in {php_supply.KEY_FILE, php_supply.SOURCE_FILE, php_supply.PREFERENCE_FILE}
                for item in apt.files
            )
        )
    ):
        from . import php_trust

        source = php_trust.collect(
            shell,
            release,
            platform.architecture,
            platform.privilege,
            indexes=action != Action.METADATA_REFRESH,
        )
    if action == Action.METADATA_REFRESH:
        return Evidence(platform, apt, None, None, tuple(reader.gaps), php_source=source)
    try:
        profile = profiles.profile(release, action, version=version, supply=supply)
    except ValueError:
        return Evidence(
            platform, apt, None, None, (*reader.gaps, "The requested PHP selection is unavailable.")
        )
    if platform is not None and profile.port is not None:
        platform = _listener_privilege(reader, platform, profile.port)
    before = _package_digest(reader, profile)
    packages = _packages(reader, profile)
    installed = {state.name for state in packages.states if state.installed} if packages else set()
    privilege = platform.privilege if platform else Privilege.UNAVAILABLE
    attributed = bool(platform and platform.listener_privilege)
    web = _web(reader, profile, installed, privilege, attributed=attributed)
    if web is not None and profile.readiness and profile.roots[0] in installed:
        web = dataclasses.replace(web, readiness=_readiness(reader, profile, web, privilege))
    if web is not None and profile.module_list and _lists_modules(profile, installed):
        listed = reader.read(profile.module_list, "the modules PHP-FPM loads")
        web = dataclasses.replace(web, modules=listed or "")
        if profile.cli_module_list:
            cli = reader.read(profile.cli_module_list, "the modules the PHP CLI loads")
            web = dataclasses.replace(web, cli_modules=cli or "")
    after = _package_digest(reader, profile)
    return Evidence(
        platform,
        apt,
        packages,
        web,
        tuple(reader.gaps),
        package_digest=after or "",
        package_changed_while_read=before is not None and after is not None and before != after,
        php_source=source,
    )


def _lists_modules(profile: Profile, installed: set[str]) -> bool:
    """Whether the profile's modules are read: a driver's once installed; a profile with
    required built-ins whenever the PHP it builds on is installed."""
    if profile.builtins:
        return all(name in installed for name in profile.prerequisites)
    return profile.roots[0] in installed


def _package_digest(reader: Reader, profile: Profile) -> str | None:
    return reader.parse(
        reader.read(profile.revalidation, "the digest of the package and service evidence"),
        _digest,
    )


def read_platform(reader: Reader) -> Platform | None:
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
    if user is not None and user.strip() == "0":
        privilege = Privilege.ROOT
    elif _authorized(reader, SUDO_APPLY, profiles.APPLY_ENTRYPOINT):
        privilege = Privilege.SUDO
    return Platform(
        boot_id or "",
        uptime,
        os or OsRelease("", "", ""),
        systemd,
        architecture or "",
        tools or {},
        privilege,
        listener_privilege=False,
    )


def _listener_privilege(reader: Reader, platform: Platform, port: int) -> Platform:
    """Whether the profile's listener query may run with privilege, checked for its port."""
    match platform.privilege:
        case Privilege.ROOT:
            allowed = True
        case Privilege.SUDO:
            allowed = _authorized(reader, sudo_listeners(port), _privileged_listeners(port))
        case _:
            allowed = False
    return dataclasses.replace(platform, listener_privilege=allowed, listener_port=port)


def _readiness(reader: Reader, profile: Profile, web: WebEvidence, privilege: str) -> Readiness:
    """docs/bootstrap.md#mariadb: the profile's final check, run while its service runs."""
    running = any(
        unit.name == profile.serving_unit and unit.active_state == "active" for unit in web.units
    )
    if not running:
        return Readiness("stopped")
    argv = list(profile.check.argv)
    if privilege == Privilege.SUDO:
        if reader.status(native.authorization(argv)) != 0:
            return Readiness("unprivileged")
    elif privilege != Privilege.ROOT:
        return Readiness("unprivileged")
    result = reader.shell.run(native.privileged(argv, root=privilege == Privilege.ROOT))
    if result.truncated:
        reader.gaps.append("The administrative check printed more than Barectl reads.")
    return Readiness("read", result.exit_status, result.stdout.rstrip("\n"))


def _retained(reader: Reader) -> tuple[native.UnitEvidence, ...] | None:
    return reader.parse(
        reader.read(native.RETAINED_STATES, "the retained bootstrap units"), _retained_states
    )


def _retained_states(text: str) -> tuple[native.UnitEvidence, ...]:
    try:
        _, units = native.parse_retained_states(text)
    except native.Unreadable:
        raise Unreadable("The retained bootstrap units are in an unknown form.") from None
    return tuple(units)


def _authorized(reader: Reader, listing: str, command: str) -> bool:
    """Whether ``sudo -n -l`` lists ``command`` as authorized without a password."""
    result = reader.shell.run(listing)
    return result.exit_status == 0 and result.stdout.strip() == command


def _apt(reader: Reader) -> AptEvidence | None:
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


def _apt_digest(reader: Reader) -> str | None:
    return reader.parse(
        reader.read(native.APT_DIGEST, "the digest of the APT configuration"), _digest
    )


def _digest(text: str) -> str:
    try:
        return native.parse_digest(text)
    except native.Unreadable:
        raise Unreadable("A digest of the server's evidence is in an unknown form.") from None


_SOURCE_FILE = re.compile(r"/etc/apt/sources\.list(\.d/[^\s\\]{1,200})?")


def _packages(reader: Reader, profile: Profile) -> PackageEvidence | None:
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
    installation = _installation(reader, profile, by_name, queried)
    if installation is None:
        return None
    simulation, more, offered, unpinned = installation
    states = states + more
    supplied = _php_supply_packages(reader, profile, states, offered)
    if supplied is None:
        return None
    states, offered = supplied
    origins = _established_offers(reader, profile, by_name)
    if origins is None:
        return None
    offered = (*offered, *origins)
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
            if not state.absent
            and not state.name.startswith(profile.releases.supported)
            and not (profile.php_supply == "sury" and state.name in php_supply.allowed_packages())
        )
    conflicts = _conflicts(reader, profile)
    if conflicts is None:
        return None
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
    return PackageEvidence(
        audit, holds, states, automatic, simulation, releases, offered, conflicts, unpinned
    )


def _php_supply_packages(
    reader: Reader,
    profile: Profile,
    states: tuple[PackageState, ...],
    offered: tuple[Offer, ...],
) -> tuple[tuple[PackageState, ...], tuple[Offer, ...]] | None:
    if profile.php_supply != "sury":
        return states, offered
    found = reader.parse(
        reader.read(release_states("php*"), "the installed PHP supply", ok=(0, 1)),
        parse_package_states,
    )
    if found is None:
        return None
    known = {state.name for state in states}
    states = (*states, *(state for state in found if state.name not in known))
    installed_php = [state.name for state in found if state.installed]
    if installed_php:
        existing = reader.parse(
            reader.read(offers(installed_php), "the installed PHP supply's exact offers"),
            parse_offers,
        )
        if existing is None:
            return None
        offered = (*offered, *existing)
    return states, offered


type _Installation = tuple[Simulation | None, tuple[PackageState, ...], tuple[Offer, ...], str]


def _installation(
    reader: Reader, profile: Profile, by_name: dict[str, PackageState], queried: tuple[str, ...]
) -> _Installation | None:
    """APT's simulation of installing the missing roots, the other packages it changes
    and their offers, and the version a pinned root was not offered at."""
    missing = [root for root in profile.roots if root not in by_name or not by_name[root].installed]
    if not missing or any(root in by_name and not by_name[root].absent for root in missing):
        return None, (), (), ""
    # A profile never installs what it builds on, so nothing is simulated without it.
    if any(name not in by_name or not by_name[name].installed for name in profile.prerequisites):
        return None, (), (), ""
    requested = _pinned(reader, profile, by_name, missing)
    if requested is None:
        return None
    if isinstance(requested, str):
        return None, (), (), requested
    simulated = _simulate(reader, requested, queried)
    if simulated is None:
        return None
    simulation, more, offered = simulated
    return simulation, more, offered, ""


def _pinned(
    reader: Reader, profile: Profile, by_name: dict[str, PackageState], missing: list[str]
) -> list[str] | str | None:
    """What the simulation requests: each missing root, a pinned one at its package's
    installed version; that version instead when no source offers the root at it."""
    pinned = profile.pinned
    if pinned is None:
        return missing
    roots = [root for root in pinned[0] if root in missing]
    state = by_name.get(pinned[1])
    if not roots or state is None or not state.installed:
        return missing
    found = reader.parse(
        reader.read(offers(roots), f"the versions APT's sources offer of {' '.join(roots)}"),
        parse_offers,
    )
    if found is None:
        return None
    offered = {(offer.package, offer.version) for offer in found}
    if any((root, state.version) not in offered for root in roots):
        return state.version
    return [f"{name}={state.version}" if name in roots else name for name in missing]


def _conflicts(reader: Reader, profile: Profile) -> tuple[PackageState, ...] | None:
    """Packages matching the profile's conflicts that are installed or left configuration."""
    if not profile.conflicts:
        return ()
    found = reader.parse(
        reader.read(conflict_states(profile.conflicts), "the conflicting packages", ok=(0, 1)),
        parse_package_states,
    )
    return None if found is None else tuple(state for state in found if not state.absent)


def _established_offers(
    reader: Reader, profile: Profile, by_name: dict[str, PackageState]
) -> tuple[Offer, ...] | None:
    """docs/bootstrap.md#mariadb: the versions offered of a database engine's installed
    roots, whose origin the review checks."""
    established = [root for root in profile.roots if root in by_name and by_name[root].installed]
    if not profile.readiness or not established:
        return ()
    return reader.parse(
        reader.read(offers(established), "the versions APT's sources offer"), parse_offers
    )


def _simulate(
    reader: Reader, missing: list[str], queried: tuple[str, ...]
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


def _states(reader: Reader, names: Iterable[str]) -> tuple[PackageState, ...] | None:
    # dpkg-query exits 1 when some packages are unknown, which is not a failure here.
    return reader.parse(
        reader.read(package_states(names), "the package states", ok=(0, 1)),
        parse_package_states,
    )


def _web(
    reader: Reader,
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
    owners = sorted(
        name
        for name in {name for spec in profile.trees for name in (spec.owner, *spec.packages)}
        if name in installed
    )
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
            functools.partial(parse_listeners, port=profile.port, attributed=attributed),
        )
    sockets: tuple[str, ...] | None = ()
    if profile.socket is not None:
        sockets = reader.parse(
            reader.read(socket_listeners(profile.socket), "the listening local sockets"),
            parse_socket_listeners,
        )
    layout = {directory: _entries(reader, directory) for directory in profile.listings}
    data = {path: _file_type(reader, path) for path in profile.paths}
    configured = _configuration(reader, profile)
    if (
        len(units) != len(profile.units)
        or any(item is None for item in trees)
        or found is None
        or ucf is None
        or (profile.port and found_listeners is None)
        or sockets is None
        or any(names is None for names in layout.values())
        or any(kind is None for kind in data.values())
        or configured is None
    ):
        return None
    alternatives, resolved, defaults = configured
    return WebEvidence(
        tuple(units),
        tuple(item for item in trees if item is not None),
        found,
        ucf,
        found_listeners,
        sockets,
        {directory: names for directory, names in layout.items() if names is not None},
        {path: kind for path, kind in data.items() if kind is not None},
        alternatives,
        resolved,
        defaults,
    )


def _configuration(
    reader: Reader, profile: Profile
) -> tuple[AlternativeState | None, str, str] | None:
    """The profile's alternative, where its link resolves, and the effective configuration."""
    alternatives: AlternativeState | None = None
    resolved = ""
    if profile.alternative is not None:
        name = profile.alternative.name
        result = reader.shell.run(alternative(name))
        # update-alternatives exits 2 for an alternative that does not exist.
        if result.truncated or result.exit_status not in {0, 2}:
            reader.gaps.append(f"Barectl could not read the {name} alternative{_because(result)}")
            return None
        if result.exit_status == 0:
            alternatives = reader.parse(result.stdout, parse_alternative)
            if alternatives is None:
                return None
        found = reader.parse(
            reader.read(
                resolve(profile.alternative.link), f"{profile.alternative.link}", ok=(0, 1)
            ),
            parse_path,
        )
        if found is None:
            return None
        resolved = found
    defaults = ""
    if profile.defaults is not None:
        # Fails while the server is not installed, which the review then ignores.
        result = reader.shell.run(profile.defaults.command)
        if result.truncated:
            reader.gaps.append("The effective configuration was larger than Barectl reads.")
            return None
        if result.exit_status == 0:
            defaults = profile.effective(result.stdout)
    return alternatives, resolved, defaults


def _file_type(reader: Reader, path: str) -> str | None:
    """The type and owner of ``path``; empty when it does not exist."""
    found = reader.status(present(path))
    if found == 1:
        return ""
    if found != 0:
        reader.gaps.append(f"Barectl could not check whether {path} exists.")
        return None
    return reader.parse(reader.read(file_type(path), f"the type of {path}"), parse_file_type)


def _entries(reader: Reader, directory: str) -> tuple[str, ...] | None:
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


def _tree(reader: Reader, root: str) -> ConfigTree | None:
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
