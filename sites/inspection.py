"""Site preparation's read-only evidence (docs/ssh-connections.md#site-preparation).

Nothing here writes: no syntax check, no request to a site and no staging. Every command
is bounded by the connection's output limit, and a truncated or unreadable answer is a gap
that refuses the plan rather than an empty finding.
"""

import functools
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

from bootstrap import inspection as bootstrap_inspection
from bootstrap import native as bootstrap_native
from bootstrap import php_trust
from bootstrap.evidence import (
    Conffile,
    Listener,
    PackageState,
    Platform,
    UnitState,
    Unreadable,
    parse_conffiles,
    parse_digests,
    parse_listeners,
    parse_package_states,
    parse_socket_listeners,
    parse_ucf_hashes,
    parse_unit,
)
from bootstrap.inspection import Reader
from bootstrap.models import Privilege
from bootstrap.php_supply import ELIGIBLE_BRANCHES
from bootstrap.releases import Release
from bootstrap.releases import of as release_of
from discovery.observations.parsers import declared_server_names
from discovery.ssh import RemoteShell

from . import native
from .convention import (
    SITES_AVAILABLE,
    SITES_ENABLED,
    TLS_DEFAULT_PATH,
    SitePaths,
    recognize_site,
)

LOGIN_DEFS: Final = "cat /etc/login.defs"
USERADD_DEFAULTS: Final = "cat /etc/default/useradd"
NSSWITCH: Final = "grep -E '^(passwd|group):' /etc/nsswitch.conf"
SUBORDINATE: Final = "test -e /etc/subuid"
USER_IDS: Final = "cut -d: -f3 /etc/passwd"
GROUP_IDS: Final = "cut -d: -f3 /etc/group"
_CANDIDATE = re.compile(r"[a-z][a-z0-9]{2,23}\.conf")
_ACCOUNT = re.compile(r"[a-z_][a-z0-9_.-]{0,31}")
_NUMBER = re.compile(r"[0-9]{1,10}")
_SETTING = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,40}")


def packages(php: str) -> tuple[str, ...]:
    return ("nginx", "nginx-common", f"php{php}-fpm", f"php{php}-cli", f"php{php}-common")


def account(database: str, name: str) -> str:
    return f"getent {database} {name}"


def groups_of(user: str) -> str:
    return f"id -G {user}"


@dataclass(frozen=True)
class TreeItem:
    """One entry under the Nginx or PHP-FPM configuration trees, with its metadata."""

    kind: str
    mode: int
    uid: int
    gid: int
    links: int
    size: int
    # The filesystem it is on; find -xdev lists a mount point but nothing below it.
    device: int
    path: str
    target: str


@dataclass(frozen=True)
class PathState:
    """A path's own metadata as root saw it; ``kind`` is empty when it does not exist."""

    path: str
    kind: str = ""
    mode: int = 0
    uid: int = 0
    gid: int = 0
    links: int = 0
    owner: str = ""
    group: str = ""

    @property
    def present(self) -> bool:
        return bool(self.kind)


@dataclass(frozen=True)
class Accounts:
    # The passwd and group records of the site user and group, when they exist.
    user: str
    group: str
    web_user: bool
    web_group: bool
    uids: frozenset[int]
    gids: frozenset[int]
    # The site user's groups, when the user exists.
    groups: str = ""
    password_locked: bool | None = None


@dataclass(frozen=True)
class Policy:
    login_defs: dict[str, str]
    # The /etc/default/useradd settings, by name.
    useradd: dict[str, str]
    nsswitch: dict[str, tuple[str, ...]]
    subordinate: bool


@dataclass
class SiteEvidence:
    paths: SitePaths | None
    platform: Platform | None
    release: Release | None
    gaps: list[str] = field(default_factory=list)
    # Root, or noninteractive sudo authorized for every privileged read.
    read_privilege: bool = False
    packages: tuple[PackageState, ...] | None = None
    other_releases: tuple[PackageState, ...] | None = None
    units: tuple[UnitState, ...] | None = None
    conffiles: tuple[Conffile, ...] | None = None
    ucf: dict[str, str] | None = None
    tree: tuple[TreeItem, ...] | None = None
    md5: dict[str, str] | None = None
    # The candidate convention files' bytes, by path; others are never read.
    contents: dict[str, str] = field(default_factory=dict)
    # The declared server names of the enabled Nginx site files, by enablement path.
    foreign: dict[str, tuple[str, ...]] = field(default_factory=dict)
    oversized: list[str] = field(default_factory=list)
    states: dict[str, PathState] | None = None
    listeners: tuple[Listener, ...] | None = None
    socket_listening: bool | None = None
    accounts: Accounts | None = None
    policy: Policy | None = None
    digest: str = ""
    changed_while_read: bool = False
    php_supply: str = "ubuntu"


class _Privileged:
    """Runs fixed read-only argv as root, directly or through ``sudo -n``."""

    def __init__(self, reader: Reader, root: bool) -> None:
        self.reader = reader
        self.root = root
        self.denied = False

    def read(self, argv: list[str], what: str, *, ok: tuple[int, ...] = (0,)) -> str | None:
        shell = self.reader.shell
        if not self.root and shell.run(bootstrap_native.authorization(argv)).exit_status != 0:
            self.denied = True
            return None
        return self.reader.read(bootstrap_native.privileged(argv, root=self.root), what, ok=ok)


def inspect(
    shell: RemoteShell,
    identifier: str,
    token: str,
    *,
    php_version: str = "",
    convention_revision: int | None = None,
) -> SiteEvidence:
    """``token`` names the plan's temporary probe, whose path must be free."""
    reader = Reader(shell)
    platform = bootstrap_inspection.read_platform(reader)
    release = release_of(platform.os) if platform is not None else None
    if release is None or platform is None:
        return SiteEvidence(None, platform, release, reader.gaps)
    root = platform.privilege == Privilege.ROOT
    privileged = _Privileged(reader, root)
    source = f"{SITES_AVAILABLE}/{identifier}.conf"
    text = privileged.read(native.content(source), source, ok=(0, 1))
    recognized = recognize_site(identifier, text) if text is not None else None
    if convention_revision is None:
        convention_revision = recognized.revision if recognized is not None else 3
    if not php_version:
        php_version = recognized.php_version if recognized is not None else ""
    if convention_revision == 3 and php_version and php_version != release.php:
        reader.gaps.append(
            "A released legacy site can select only its Ubuntu release's default PHP branch."
        )
        return SiteEvidence(None, platform, release, reader.gaps)
    try:
        paths = SitePaths(identifier, php_version or release.php, revision=convention_revision)
    except ValueError:
        reader.gaps.append("The requested PHP branch or site convention revision is not supported.")
        return SiteEvidence(None, platform, release, reader.gaps)
    evidence = SiteEvidence(paths, platform, release, reader.gaps)
    digest = native.script(native.site_digest(paths))
    before = reader.parse(privileged.read(digest, "the site evidence digest"), _digest)
    if privileged.denied:
        return evidence
    supply = php_trust.observed_supply(shell, release, platform.architecture)
    if supply is None:
        reader.gaps.append(
            "The installed PHP supply could not be authenticated from native evidence."
        )
        evidence.php_supply = "unknown"
    else:
        evidence.php_supply = supply
    evidence.read_privilege = True
    _packages(reader, evidence, paths.php)
    _configuration(reader, privileged, evidence, paths, token)
    _accounts(reader, privileged, evidence, paths)
    evidence.policy = _policy(reader)
    after = reader.parse(privileged.read(digest, "the site evidence digest"), _digest)
    evidence.read_privilege = not privileged.denied
    evidence.digest = after or ""
    evidence.changed_while_read = before is not None and after is not None and before != after
    return evidence


def inspect_trees(
    shell: RemoteShell, platform: Platform, release: Release, *, php_version: str = ""
) -> SiteEvidence:
    """The Nginx and PHP-FPM trees with their digests and candidate convention files, read
    as root, and the packages' defaults, for judging a tree by the site grammar
    (docs/databases.md#site-aware-readiness)."""
    reader = Reader(shell)
    evidence = SiteEvidence(None, platform, release, reader.gaps)
    privileged = _Privileged(reader, platform.privilege == Privilege.ROOT)
    php = php_version or release.php
    _defaults(reader, evidence, packages(php)[1:])
    _trees(reader, privileged, evidence, php)
    evidence.read_privilege = not privileged.denied
    return evidence


def _digest(text: str) -> str:
    try:
        return bootstrap_native.parse_digest(text)
    except bootstrap_native.Unreadable:
        raise Unreadable("A digest of the server's evidence is in an unknown form.") from None


def _packages(reader: Reader, evidence: SiteEvidence, php: str) -> None:
    names = packages(php)
    evidence.packages = reader.parse(
        reader.read(bootstrap_inspection.package_states(names), "the package states", ok=(0, 1)),
        parse_package_states,
    )
    found = reader.parse(
        reader.read(
            bootstrap_inspection.release_states("php[0-9]*"),
            "the PHP releases' packages",
            ok=(0, 1),
        ),
        parse_package_states,
    )
    if found is not None:
        prefix = f"php{php}-"
        evidence.other_releases = tuple(
            state
            for state in found
            if not state.absent
            and re.fullmatch(r"php[0-9.]+-.*", state.name)
            and not state.name.startswith(prefix)
        )
    units = []
    for name in ("nginx.service", f"php{php}-fpm.service"):
        unit = reader.parse(
            reader.read(bootstrap_inspection.unit_state(name), f"the state of {name}"),
            functools.partial(parse_unit, name=name),
        )
        if unit is not None:
            units.append(unit)
    evidence.units = tuple(units) if len(units) == 2 else None
    branches = sorted(
        {php}
        | {
            state.name.removeprefix("php").removesuffix("-fpm")
            for state in found or ()
            if state.installed
            and state.name in {f"php{branch}-fpm" for branch in ELIGIBLE_BRANCHES}
        }
    )
    defaults = ("nginx-common", *(name for branch in branches for name in packages(branch)[2:]))
    _defaults(reader, evidence, defaults)


def _defaults(reader: Reader, evidence: SiteEvidence, names: tuple[str, ...]) -> None:
    """The configuration files the packages and ucf installed, with their digests."""
    evidence.conffiles = reader.parse(
        reader.read(
            bootstrap_inspection.conffiles(names),
            "the packages' configuration files",
            ok=(0, 1),
        ),
        parse_conffiles,
    )
    evidence.ucf = reader.parse(
        reader.read(bootstrap_inspection.UCF_HASHES, "ucf's registry"), parse_ucf_hashes
    )


def _configuration(
    reader: Reader, privileged: _Privileged, evidence: SiteEvidence, paths: SitePaths, token: str
) -> None:
    _trees(reader, privileged, evidence, paths.php)
    _foreign_sites(reader, privileged, evidence)
    states = reader.parse(
        privileged.read(native.path_states(paths, paths.probe(token)), "the site's paths"),
        functools.partial(parse_states, expected=expected_paths(paths, token)),
    )
    evidence.states = states
    evidence.listeners = reader.parse(
        privileged.read(native.listeners(), "the listening sockets on port 80"),
        lambda text: parse_listeners(text, 80, attributed=True),
    )
    sockets = reader.parse(
        reader.read(bootstrap_inspection.socket_listeners(paths.socket), "the site's socket"),
        parse_socket_listeners,
    )
    evidence.socket_listening = None if sockets is None else paths.socket in sockets


def _trees(reader: Reader, privileged: _Privileged, evidence: SiteEvidence, php: str) -> None:
    evidence.tree = reader.parse(
        privileged.read(
            native.tree_listing(php, all_branches=True), "the Nginx and PHP-FPM configuration"
        ),
        parse_tree,
    )
    digests = reader.parse(
        privileged.read(
            native.tree_digests(php, all_branches=True), "the configuration files' digests"
        ),
        lambda text: parse_digests(text, 32),
    )
    evidence.md5 = None if digests is None else {item.path: item.digest for item in digests}
    if evidence.tree is not None:
        _contents(reader, privileged, evidence, php)


def _foreign_sites(reader: Reader, privileged: _Privileged, evidence: SiteEvidence) -> None:
    """The declared server names of the enabled site files, which are the only values read
    from a foreign file (docs/sites.md#admission)."""
    enabled = [
        item.path
        for item in evidence.tree or ()
        if item.kind == "l"
        and item.path.startswith(f"{SITES_ENABLED}/")
        and item.path != f"{SITES_ENABLED}/default"
    ]
    if len(enabled) > native.MAX_FOREIGN_FILES:
        reader.gaps.append(
            f"More than {native.MAX_FOREIGN_FILES} sites are enabled, more than Barectl reads."
        )
        return
    for path in enabled:
        argv = native.foreign_content(path)
        if argv is None:
            continue
        text = privileged.read(argv, path)
        if text is None:
            continue
        names = declared_server_names(text)
        if names is not None:
            evidence.foreign[path] = names


def expected_paths(paths: SitePaths, token: str) -> frozenset[str]:
    return frozenset(
        (
            *native.ancestors(paths),
            paths.boundary,
            paths.public,
            paths.private,
            paths.placeholder,
            paths.probe(token),
            paths.source,
            paths.link,
            paths.pool,
            paths.socket,
            *paths.certificates,
            *paths.challenge_parents,
        )
    )


def _contents(reader: Reader, privileged: _Privileged, evidence: SiteEvidence, php: str) -> None:
    """Read the regular files whose names the convention could have generated."""
    directories = (
        SITES_AVAILABLE,
        *(f"/etc/php/{branch}/fpm/pool.d" for branch in ELIGIBLE_BRANCHES),
    )
    packaged = {item.path for item in evidence.conffiles or ()} | set(evidence.ucf or {})
    candidates = [
        item.path
        for item in evidence.tree or ()
        if item.kind == "f"
        and item.path not in packaged
        and item.path.rsplit("/", 1)[0] in directories
        and _CANDIDATE.fullmatch(item.path.rsplit("/", 1)[1])
    ]
    if any(item.path == TLS_DEFAULT_PATH for item in evidence.tree or ()):
        candidates.append(TLS_DEFAULT_PATH)
    if len(candidates) > native.MAX_CANDIDATE_FILES:
        reader.gaps.append(
            f"There are more than {native.MAX_CANDIDATE_FILES} site and pool files, more than "
            "Barectl reads."
        )
        return
    for path in candidates:
        text = privileged.read(native.content(path), path)
        if text is None:
            continue
        if len(text.encode()) > native.MAX_FILE:
            evidence.oversized.append(path)
        else:
            evidence.contents[path] = text


def _accounts(
    reader: Reader, privileged: _Privileged, evidence: SiteEvidence, paths: SitePaths
) -> None:
    user = paths.user
    records = {}
    for database, name in (
        ("passwd", user),
        ("group", user),
        ("passwd", "www-data"),
        ("group", "www-data"),
    ):
        # getent exits 2 when the database has no such entry.
        records[database, name] = reader.read(
            account(database, name), f"the {database} entry of {name}", ok=(0, 2)
        )
    uids = reader.parse(reader.read(USER_IDS, "the user IDs"), _numbers)
    gids = reader.parse(reader.read(GROUP_IDS, "the group IDs"), _numbers)
    if any(value is None for value in records.values()) or uids is None or gids is None:
        return
    passwd = (records["passwd", user] or "").strip()
    groups = ""
    locked = None
    if passwd:
        groups = reader.read(groups_of(user), f"the groups of {user}") or ""
        lock = privileged.read(native.password_lock(user), f"the password lock of {user}")
        locked = None if lock is None else lock.strip() in {"!", "*"}
    evidence.accounts = Accounts(
        user=passwd,
        group=(records["group", user] or "").strip(),
        web_user=bool((records["passwd", "www-data"] or "").strip()),
        web_group=bool((records["group", "www-data"] or "").strip()),
        uids=uids,
        gids=gids,
        groups=groups.strip(),
        password_locked=locked,
    )


def _numbers(text: str) -> frozenset[int]:
    lines = text.splitlines()
    if not all(_NUMBER.fullmatch(line) for line in lines):
        raise Unreadable("The account database lists IDs in an unknown form.")
    return frozenset(int(line) for line in lines)


def _policy(reader: Reader) -> Policy | None:
    defs = reader.parse(reader.read(LOGIN_DEFS, "/etc/login.defs"), _settings(assignment=False))
    useradd = reader.parse(
        reader.read(USERADD_DEFAULTS, "/etc/default/useradd", ok=(0, 1)),
        _settings(assignment=True),
    )
    nsswitch = reader.parse(reader.read(NSSWITCH, "/etc/nsswitch.conf", ok=(0, 1)), _nsswitch)
    subordinate = reader.status(SUBORDINATE) == 0
    if defs is None or useradd is None or nsswitch is None:
        return None
    return Policy(defs, useradd, nsswitch, subordinate)


def _settings(*, assignment: bool) -> Callable[[str], dict[str, str]]:
    """``KEY value`` lines of login.defs, or ``KEY=value`` lines of useradd's defaults."""

    def parse(text: str) -> dict[str, str]:
        settings: dict[str, str] = {}
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if assignment:
                key, _, value = stripped.partition("=")
            else:
                key, _, value = stripped.partition(" ")
                key = key.split("\t", 1)[0]
                value = stripped[len(key) :]
            if not _SETTING.fullmatch(key):
                raise Unreadable("An account policy file is in an unknown form.")
            settings[key] = value.strip()[:200]
        return settings

    return parse


def _nsswitch(text: str) -> dict[str, tuple[str, ...]]:
    found: dict[str, tuple[str, ...]] = {}
    for line in text.splitlines():
        database, _, sources = line.partition(":")
        found[database.strip()] = tuple(sources.split("#", 1)[0].split())
    return found


def parse_tree(text: str) -> tuple[TreeItem, ...]:
    items: list[TreeItem] = []
    for line in text.splitlines():
        parts = line.split("\t")
        if (
            len(parts) != 9
            or len(parts[0]) != 1
            or not all(_NUMBER.fullmatch(part) for part in parts[2:7])
            or not re.fullmatch(r"[0-7]{1,4}", parts[1])
            or not parts[7].startswith("/etc/")
            or any(len(part) > 500 or "\\" in part for part in parts)
        ):
            raise Unreadable("The configuration files were listed in an unknown form.")
        kind, mode, uid, gid, links, size, device, path, target = parts
        items.append(
            TreeItem(
                kind,
                int(mode, 8),
                int(uid),
                int(gid),
                int(links),
                int(size),
                int(device),
                path,
                target,
            )
        )
    if len(items) > native.MAX_TREE_ENTRIES:
        raise Unreadable(
            f"The configuration has more than {native.MAX_TREE_ENTRIES} entries, more than "
            "Barectl reads."
        )
    return tuple(items)


_FILE_TYPES = {0o100000: "f", 0o040000: "d", 0o120000: "l", 0o140000: "s"}


def parse_states(text: str, expected: frozenset[str]) -> dict[str, PathState]:
    states: dict[str, PathState] = {}
    for line in text.splitlines():
        absent = re.fullmatch(r"absent (/\S{0,200})", line)
        if absent and absent[1] in expected:
            states[absent[1]] = PathState(absent[1])
            continue
        match = re.fullmatch(
            r"([0-9a-f]{1,8}) ([0-9]{1,10}) ([0-9]{1,10}) ([0-9]{1,10}) (\S{1,32}) (\S{1,32}) "
            r"(/\S{0,200})",
            line,
        )
        if match is None or match[7] not in expected:
            raise Unreadable("The site's paths were described in an unknown form.")
        raw = int(match[1], 16)
        states[match[7]] = PathState(
            match[7],
            _FILE_TYPES.get(raw & 0o170000, "o"),
            raw & 0o7777,
            int(match[2]),
            int(match[3]),
            int(match[4]),
            match[5] if _ACCOUNT.fullmatch(match[5]) else "",
            match[6] if _ACCOUNT.fullmatch(match[6]) else "",
        )
    if set(states) != expected:
        raise Unreadable("Not every site path was described.")
    return states
