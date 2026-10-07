"""Site recognition from native evidence (docs/ssh-connections.md#site-observations).

Names from the convention locate candidates. A site is recognized only by rendering the
convention's expected files and account attributes for the candidate identifier and
comparing them with native evidence (docs/adr/0015-recognize-only-the-convention.md).
"""

import re
import shlex
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cached_property
from typing import NamedTuple

from ..models import FileType, ObservationOutcome, SiteStage, SiteState
from ..releases import SupportedRelease, supported
from ..snapshot import (
    Observation,
    ObservedSite,
    OsRelease,
    SiteAccount,
    WebStackComponentObservation,
)
from ..ssh import RemoteShell
from .components import _observe_installed
from .configuration import (
    PHP_BASE_DIR,
    POOL_SUBPATH,
    SITES_AVAILABLE_DIR,
    SITES_ENABLED_DIR,
    ListedDirectory,
    _collect_nginx_sites,
    _collect_php_pools,
)
from .parsers import SITE_POOL_FIXED, declared_server_names
from .probes import (
    _bounded,
    _Failed,
    _overall,
    _path_missing,
    _read_file,
    _run,
    _test,
)

# docs/site-conventions.md#site-identity-and-layout
CANDIDATE_FILE = re.compile(r"([a-z][a-z0-9]{2,23})\.conf")
# Names the distribution's own configuration already uses: the www pool and /var/www/html.
RESERVED = frozenset({"www", "html"})
# The distribution's own enabled site, which is never a Barectl site or a foreign item.
DISTRIBUTION_SITE = "default"
WEB_ROOT = "/var/www"
SOCKET_DIR = "/run/php"
CHALLENGE_ROOT = "/var/lib/letsencrypt"
CERTIFICATE_ROOT = "/etc/letsencrypt/live"
NOLOGIN = "/usr/sbin/nologin"
WEB_USER = "www-data"
ROOT = "root"
CONF_D_DIR = "/etc/nginx/conf.d"
# docs/site-conventions.md#tls-convention: the shared default TLS rejection server.
TLS_DEFAULT_NAME = "tls-default-reject.conf"
TLS_DEFAULT_PATH = f"{CONF_D_DIR}/{TLS_DEFAULT_NAME}"
STAT_FORMAT = "%n %f %u %U %g %G %h"
# docs/ssh-connections.md#what-each-candidate-reads
DEFAULT_UID_RANGE = (1000, 60000)
NOBODY = 65534
MAX_SITE_CANDIDATES = 50
ACCOUNT_NAME = re.compile(r"[a-z_][a-z0-9_.-]{0,31}")
NUMBER = re.compile(r"[0-9]{1,10}")
HEX = re.compile(r"[0-9a-f]{1,8}")
LOGIN_DEFS = "/etc/login.defs"
SHADOW = "/etc/shadow"
ABSENT = ObservationOutcome.ABSENT
OBSERVED = ObservationOutcome.OBSERVED
INACCESSIBLE = ObservationOutcome.INACCESSIBLE
UNSUPPORTED = ObservationOutcome.UNSUPPORTED

_FILE_TYPES = {
    0o100000: FileType.FILE,
    0o040000: FileType.DIRECTORY,
    0o120000: FileType.SYMLINK,
    0o140000: FileType.SOCKET,
}
_ARTICLES = {
    FileType.FILE: "a regular file",
    FileType.DIRECTORY: "a directory",
    FileType.SYMLINK: "a symbolic link",
    FileType.SOCKET: "a socket",
    FileType.OTHER: "another type of file",
}


def render_tls_default() -> str:
    """The shared default TLS rejection server, byte for byte."""
    return (
        "# Barectl's default TLS rejection server: "
        "https://github.com/rajandangi/barectl/blob/main/docs/site-conventions.md#tls-convention\n"
        "server {\n"
        "\tlisten 443 ssl default_server;\n"
        "\tlisten [::]:443 ssl default_server;\n"
        "\tssl_reject_handshake on;\n"
        "}\n"
    )


class FileFacts(NamedTuple):
    """A path's own type, numeric owner and group, permission bits and hard link count."""

    file_type: FileType
    uid: int
    gid: int
    mode: int
    links: int


_TLS_DEFAULT_FACTS = FileFacts(FileType.FILE, 0, 0, 0o644, 1)


def is_tls_default(text: str | None, facts: FileFacts) -> bool:
    """Whether the file at ``TLS_DEFAULT_PATH`` is exactly the convention's."""
    return facts == _TLS_DEFAULT_FACTS and text == render_tls_default()


@dataclass(frozen=True)
class SiteLayout:
    """Where the convention places a site's resources."""

    identifier: str
    version: str

    @property
    def user(self) -> str:
        return f"s{self.identifier}"

    @property
    def enabled(self) -> str:
        return f"{SITES_ENABLED_DIR}/{self.identifier}.conf"

    @property
    def source(self) -> str:
        return f"{SITES_AVAILABLE_DIR}/{self.identifier}.conf"

    @property
    def boundary(self) -> str:
        return f"{WEB_ROOT}/{self.identifier}"

    @property
    def public(self) -> str:
        return f"{self.boundary}/public"

    @property
    def private(self) -> str:
        return f"{self.boundary}/private"

    @property
    def ssh(self) -> str:
        return f"{self.boundary}/.ssh"

    @property
    def webroot(self) -> str:
        return f"{CHALLENGE_ROOT}/{self.identifier}"

    @property
    def pool(self) -> str:
        return f"{PHP_BASE_DIR}/{self.version}/{POOL_SUBPATH}/{self.identifier}.conf"

    @property
    def socket(self) -> str:
        return f"{SOCKET_DIR}/{self.user}.sock"

    @property
    def paths(self) -> tuple[str, ...]:
        return (
            self.enabled,
            self.source,
            self.boundary,
            self.public,
            self.private,
            self.ssh,
            self.pool,
            self.socket,
        )

    @property
    def link_targets(self) -> tuple[str, str]:
        # The absolute target, and the relative one that resolves to it.
        return (self.source, f"../sites-available/{self.identifier}.conf")

    def pool_settings(self) -> dict[str, str]:
        return {"user": self.user, "group": self.user, "listen": self.socket, **SITE_POOL_FIXED}


class _Node(NamedTuple):
    file_type: FileType
    owner: str
    group: str
    mode: int
    # The stat command that described it.
    source: str
    uid: int
    gid: int
    links: int

    @property
    def facts(self) -> FileFacts:
        return FileFacts(self.file_type, self.uid, self.gid, self.mode, self.links)

    def describe(self) -> str:
        return (
            f"{_ARTICLES[self.file_type]} owned by {self.owner}:{self.group} "
            f"with mode {self.mode:04o}"
        )


class _Expected(NamedTuple):
    file_type: FileType
    owner: str
    group: str
    # None for symbolic links, whose permission bits nothing uses.
    mode: int | None

    def problems(self, path: str, node: _Node) -> list[str]:
        matches = (
            node.file_type == self.file_type
            and (node.owner, node.group) == (self.owner, self.group)
            and self.mode in {None, node.mode}
        )
        if matches:
            return []
        mode = "" if self.mode is None else f" with mode {self.mode:04o}"
        expected = f"{_ARTICLES[self.file_type]} owned by {self.owner}:{self.group}{mode}"
        return [f"{path} must be {expected}; it is {node.describe()}."]


type _Found = _Node | _Failed


@dataclass(frozen=True)
class _Check:
    """One convention resource: present and matching, absent, differing, or unreadable."""

    path: str
    matched: bool = False
    missing: bool = False
    # The content Barectl expects, for a differing file it can render.
    expected: str = ""
    outcome: ObservationOutcome = ObservationOutcome.OBSERVED
    warning: str = ""

    @property
    def drift(self) -> bool:
        return not self.matched and not self.missing and self.outcome == ObservationOutcome.OBSERVED


def _one(path: str) -> _Check:
    return _Check(path, matched=True)


def _absent(path: str, warning: str = "") -> _Check:
    return _Check(path, missing=True, warning=warning)


def _drift(path: str, warning: str, expected: str = "") -> _Check:
    return _Check(path, expected=expected, warning=warning)


def _unreadable_check(path: str, failure: _Failed) -> _Check:
    return _Check(path, outcome=failure.status, warning=failure.warning)


def _from_failure(path: str, failure: _Failed) -> _Check:
    if failure.status == ABSENT or failure.missing:
        return _absent(path, failure.warning)
    return _unreadable_check(path, failure)


def _stat_command(paths: Iterable[str]) -> str:
    return f"stat -c {shlex.quote(STAT_FORMAT)} -- {' '.join(shlex.quote(p) for p in paths)}"


def _stat_paths(shell: RemoteShell, paths: tuple[str, ...]) -> dict[str, _Found]:
    """Each path's own metadata from one ``stat``; a symbolic link is described, not followed."""
    command = _stat_command(paths)
    output = _run(shell, command, accepted=frozenset({0, 1}))
    if isinstance(output, _Failed):
        return dict.fromkeys(paths, output)
    found: dict[str, _Found] = {}
    for line in output.splitlines():
        node = _parse_stat(line, paths, command)
        if node is None:
            failure = _Failed(UNSUPPORTED, "stat did not report in a supported format.", command)
            return dict.fromkeys(paths, failure)
        found[node[0]] = node[1]
    for path in paths:
        if path not in found:
            found[path] = _absence(shell, path, command)
    return found


def _parse_stat(line: str, paths: tuple[str, ...], command: str) -> tuple[str, _Node] | None:
    match line.split(" "):
        case [name, raw, uid, owner, gid, group, links] if (
            name in paths
            and HEX.fullmatch(raw)
            and NUMBER.fullmatch(uid)
            and NUMBER.fullmatch(gid)
            and ACCOUNT_NAME.fullmatch(owner)
            and ACCOUNT_NAME.fullmatch(group)
            and NUMBER.fullmatch(links)
        ):
            mode = int(raw, 16)
            file_type = _FILE_TYPES.get(mode & 0o170000, FileType.OTHER)
            return name, _Node(
                file_type, owner, group, mode & 0o7777, command, int(uid), int(gid), int(links)
            )
        case _:
            return None


def _absence(shell: RemoteShell, path: str, command: str) -> _Failed:
    """Why ``stat`` did not describe a path, confirmed with ``test``."""
    if _test(shell, "-e", path) or _test(shell, "-L", path):
        return _Failed(UNSUPPORTED, f"stat did not describe {path}.", command)
    if _path_missing(shell, path):
        return _Failed(ABSENT, f"{path} does not exist.", command, missing=True)
    return _Failed(
        INACCESSIBLE, f"The SSH user cannot see {path}. Barectl does not use sudo.", command
    )


def _ipv6(text: str) -> bool:
    return "\tlisten [::]:80;\n" in text or "\tlisten [::]:443 ssl;\n" in text


def _stage(text: str) -> str:
    """The released form a candidate's file declares, HTTP when it declares none."""
    if "ssl_certificate " in text:
        return "redirect" if "return 301 https://" in text else "https"
    if "location ^~ /.well-known/acme-challenge/" in text:
        return "challenge"
    return "http"


@dataclass
class _Sites:
    """One discovery's site candidates and the evidence they share."""

    shell: RemoteShell
    release: SupportedRelease
    enabled: ListedDirectory
    available: ListedDirectory
    pools: ListedDirectory
    warnings: list[str] = field(default_factory=list)

    def candidates(self) -> list[str]:
        # A candidate is named by a site file, never by a pool alone: a pool file that
        # follows no site file is foreign configuration (docs/adr/0015).
        names = [*self.available.names, *self.enabled.names]
        identifiers = sorted(
            {
                match.group(1)
                for name in names
                if (match := CANDIDATE_FILE.fullmatch(name)) and match.group(1) not in RESERVED
            }
        )
        if len(identifiers) > MAX_SITE_CANDIDATES:
            _bounded(
                self.warnings,
                f"More than {MAX_SITE_CANDIDATES} sites are named in the configuration. Only "
                f"the first {MAX_SITE_CANDIDATES} were inspected.",
            )
        return identifiers[:MAX_SITE_CANDIDATES]

    def foreign(self, candidates: set[str]) -> list[ObservedSite]:
        """Enabled site files and pool files that follow no convention candidate."""
        found: list[ObservedSite] = []
        for name in self.enabled.names:
            if name == DISTRIBUTION_SITE:
                continue
            match = CANDIDATE_FILE.fullmatch(name)
            if match and match.group(1) not in RESERVED and match.group(1) in candidates:
                continue
            found.append(self._foreign_site(name))
        for name in self.pools.names:
            # PHP-FPM's pool include loads only *.conf files.
            if not name.endswith(".conf"):
                continue
            match = CANDIDATE_FILE.fullmatch(name)
            if match and match.group(1) not in RESERVED and match.group(1) in candidates:
                continue
            # The distribution's own pool (www) is a packaged file, never a blocked item.
            if match and match.group(1) in RESERVED:
                continue
            found.append(self._blocked(f"{self.pools.path}/{name}", ()))
        return found

    def _foreign_site(self, name: str) -> ObservedSite:
        path = f"{SITES_ENABLED_DIR}/{name}"
        text = _read_file(self.shell, path)
        if isinstance(text, _Failed):
            return self._blocked(path, (), text.status)
        names = declared_server_names(text)
        if names is None:
            return self._blocked(path, (), UNSUPPORTED)
        return self._blocked(path, names)

    def _blocked(
        self, path: str, names: tuple[str, ...], outcome: ObservationOutcome = OBSERVED
    ) -> ObservedSite:
        return ObservedSite(
            identifier="",
            server_names=names,
            php_version=self.release.php,
            account=None,
            state=SiteState.NOT_FOLLOWING,
            outcome=outcome,
            file=path,
        )

    def observe(self, identifier: str) -> ObservedSite | None:
        layout = SiteLayout(identifier, self.release.php)
        nodes = _stat_paths(self.shell, layout.paths)
        source, names, stage = self._nginx(layout, nodes[layout.source])
        account_check, account = self._account(layout)
        checks = [
            source,
            self._pool(layout, nodes[layout.pool]),
            self._enabled(layout, nodes[layout.enabled]),
            self._directory(layout.boundary, nodes[layout.boundary], ROOT, ROOT, 0o755),
            self._directory(layout.public, nodes[layout.public], layout.user, WEB_USER, 0o750),
            self._directory(layout.private, nodes[layout.private], layout.user, layout.user, 0o700),
            self._ssh(layout, nodes[layout.ssh]),
            self._socket(layout, nodes[layout.socket]),
        ]
        if stage != "http":
            checks.append(self._webroot(layout))
        checks.append(account_check)
        checks.append(self._ancestors())
        if all(check.missing for check in checks):
            return None
        state, file, expected, missing = _verdict(tuple(checks))
        activated = stage in {"https", "redirect"}
        lineage = f"{CERTIFICATE_ROOT}/{identifier}"
        return ObservedSite(
            identifier=identifier,
            server_names=names,
            php_version=self.release.php,
            account=account,
            state=state,
            outcome=_outcome(tuple(checks)),
            file=file,
            expected=expected,
            missing=missing,
            stage=SiteStage(stage),
            certificate_reference=f"{lineage}/fullchain.pem" if activated else "",
            certificate_key_reference=f"{lineage}/privkey.pem" if activated else "",
        )

    def _nginx(self, layout: SiteLayout, found: _Found) -> tuple[_Check, tuple[str, ...], str]:
        from sites.convention import Stage, recognize_site, render_site

        if isinstance(found, _Failed):
            return _from_failure(layout.source, found), (), "http"
        problems = _Expected(FileType.FILE, ROOT, ROOT, 0o644).problems(layout.source, found)
        text = _read_file(self.shell, layout.source)
        if isinstance(text, _Failed):
            return _from_failure(layout.source, text), (), "http"
        recognized = recognize_site(layout.identifier, text)
        if recognized is not None:
            if problems:
                return (
                    _drift(
                        layout.source,
                        " ".join(problems),
                        render_site(
                            layout.identifier,
                            recognized.names,
                            ipv6=recognized.ipv6,
                            stage=recognized.stage,
                        ),
                    ),
                    recognized.names,
                    recognized.stage.value,
                )
            return _one(layout.source), recognized.names, recognized.stage.value
        names = declared_server_names(text)
        expected = ""
        if names and 1 <= len(names) <= 10:
            expected = render_site(
                layout.identifier, names, ipv6=_ipv6(text), stage=Stage(_stage(text))
            )
        warning = " ".join(problems) or f"{layout.source} differs from the convention's site file."
        return _drift(layout.source, warning, expected), names or (), _stage(text)

    def _pool(self, layout: SiteLayout, found: _Found) -> _Check:
        from sites.convention import recognize_pool, render_pool

        if isinstance(found, _Failed):
            return _from_failure(layout.pool, found)
        problems = _Expected(FileType.FILE, ROOT, ROOT, 0o644).problems(layout.pool, found)
        text = _read_file(self.shell, layout.pool)
        if isinstance(text, _Failed):
            return _from_failure(layout.pool, text)
        if not problems and recognize_pool(layout.identifier, text):
            return _one(layout.pool)
        warning = " ".join(problems) or f"{layout.pool} differs from the convention's pool file."
        return _drift(layout.pool, warning, render_pool(layout.identifier))

    def _enabled(self, layout: SiteLayout, found: _Found) -> _Check:
        if isinstance(found, _Failed):
            if found.status == ABSENT:
                return _absent(layout.enabled, f"The site is not enabled: {found.warning}")
            return _unreadable_check(layout.enabled, found)
        problems = _Expected(FileType.SYMLINK, ROOT, ROOT, None).problems(layout.enabled, found)
        if found.file_type != FileType.SYMLINK:
            warning = " ".join(problems) or f"{layout.enabled} must link to {layout.source}."
            return _drift(layout.enabled, warning)
        command = f"readlink {shlex.quote(layout.enabled)}"
        target = _run(self.shell, command)
        if isinstance(target, _Failed):
            return _unreadable_check(layout.enabled, target)
        if target.removesuffix("\n") not in layout.link_targets:
            return _drift(layout.enabled, f"{layout.enabled} must link to {layout.source}.")
        if problems:
            return _drift(layout.enabled, " ".join(problems))
        return _one(layout.enabled)

    def _directory(self, path: str, found: _Found, owner: str, group: str, mode: int) -> _Check:
        if isinstance(found, _Failed):
            return _from_failure(path, found)
        problems = _Expected(FileType.DIRECTORY, owner, group, mode).problems(path, found)
        return _drift(path, " ".join(problems)) if problems else _one(path)

    def _webroot(self, layout: SiteLayout) -> _Check:
        # docs/site-conventions.md#challenge-route
        nodes = _stat_paths(self.shell, (layout.webroot,))
        return self._directory(layout.webroot, nodes[layout.webroot], ROOT, WEB_USER, 0o750)

    def _ssh(self, layout: SiteLayout, found: _Found) -> _Check:
        # The convention requires that the account's home holds no SSH keys.
        if isinstance(found, _Failed):
            if found.status == ABSENT:
                return _one(layout.ssh)
            return _unreadable_check(layout.ssh, found)
        return _drift(layout.ssh, f"{layout.ssh} must not exist.")

    def _socket(self, layout: SiteLayout, found: _Found) -> _Check:
        if isinstance(found, _Failed):
            if found.status == ABSENT:
                return _absent(
                    layout.socket,
                    f"{layout.socket} does not exist, so no running PHP-FPM pool provides the "
                    "socket the site's Nginx configuration names.",
                )
            return _unreadable_check(layout.socket, found)
        problems = _Expected(FileType.SOCKET, WEB_USER, WEB_USER, 0o600).problems(
            layout.socket, found
        )
        return _drift(layout.socket, " ".join(problems)) if problems else _one(layout.socket)

    def _ancestors(self) -> _Check:
        owners = _ancestor_owners(self.release.php)
        paths = tuple(owners)
        nodes = _stat_paths(self.shell, paths)
        location = "Parent directories"
        failures = [found for found in nodes.values() if isinstance(found, _Failed)]
        if failures:
            outcome = _overall((failure.status for failure in failures), listed_empty=False)
            warning = " ".join(dict.fromkeys(failure.warning for failure in failures))
            return _Check(location, outcome=outcome, warning=warning)
        problems = [
            f"{path} must be a directory owned by {owner} that only its owner can write; it is "
            f"{node.describe()}."
            for path, owner in owners.items()
            if isinstance(node := nodes[path], _Node)
            and (node.file_type != FileType.DIRECTORY or node.owner != owner or node.mode & 0o022)
        ]
        return _drift(location, " ".join(problems)) if problems else _one(location)

    @cached_property
    def uid_range(self) -> tuple[tuple[int, int], tuple[str, ...]]:
        """The normal accounts' UID range, and the file it was read from, if any."""
        text = _read_file(self.shell, LOGIN_DEFS)
        if isinstance(text, _Failed):
            return DEFAULT_UID_RANGE, ()
        values = dict.fromkeys(("UID_MIN", "UID_MAX"), "")
        for line in text.splitlines():
            key, *rest = line.split()[:2] or [""]
            if key in values and rest and NUMBER.fullmatch(rest[0]):
                values[key] = rest[0]
        low = int(values["UID_MIN"] or DEFAULT_UID_RANGE[0])
        high = int(values["UID_MAX"] or DEFAULT_UID_RANGE[1])
        return (low, high), (LOGIN_DEFS,)

    @cached_property
    def shadow_readable(self) -> bool:
        return _test(self.shell, "-r", SHADOW)

    def _account(self, layout: SiteLayout) -> tuple[_Check, SiteAccount | None]:
        user = layout.user
        (low, high), _ = self.uid_range
        commands = (f"getent passwd {user}", f"getent group {user}", f"id -G {user}")
        passwd = _run(self.shell, commands[0], accepted=frozenset({0, 2}))
        if isinstance(passwd, _Failed) or not passwd:
            failure = passwd or _Failed(
                ABSENT, f"The account database has no user {user}.", commands[0]
            )
            return _from_failure(user, failure), None
        record = _account_record(passwd, user, 7)
        if record is None or not (NUMBER.fullmatch(record[2]) and NUMBER.fullmatch(record[3])):
            failure = _Failed(
                UNSUPPORTED, f"getent did not describe {user} in a supported format.", commands[0]
            )
            return _unreadable_check(user, failure), None
        account = SiteAccount(int(record[2]), int(record[3]), record[5][:200], record[6][:200])
        group = _run(self.shell, commands[1], accepted=frozenset({0, 2}))
        groups = _run(self.shell, commands[2])
        for output in (group, groups):
            if isinstance(output, _Failed):
                return _unreadable_check(user, output), account
        problems = [
            *_identity_problems(account, layout, (low, high)),
            *_group_problems(str(group), str(groups), account, user),
        ]
        if problems:
            return _drift(user, " ".join(problems)), account
        # The password lock is its own read; without it the account is not drift.
        if not self.shadow_readable:
            failure = _Failed(
                INACCESSIBLE,
                f"The SSH user cannot read {SHADOW}, so Barectl cannot tell whether the "
                f"password of {user} is locked. Barectl does not use sudo.",
                f"test -r {SHADOW}",
            )
            return _unreadable_check(user, failure), account
        command = f"getent shadow {user} | cut -d: -f2 | cut -c1"
        output = _run(self.shell, command)
        if isinstance(output, _Failed):
            return _unreadable_check(user, output), account
        if not output:
            return _drift(
                f"{user} password", f"The shadow database has no lock for {user}."
            ), account
        if output.strip() not in {"!", "*"}:
            return _drift(f"{user} password", f"The password of {user} must be locked."), account
        return _one(user), account

    def observation(
        self, sites: tuple[ObservedSite, ...], unlisted: Iterable[ObservationOutcome] = ()
    ) -> Observation[tuple[ObservedSite, ...]]:
        # A site observation exists whenever the server named one; an unreadable resource
        # keeps its own site outcome without hiding the site (docs/adr/0015).
        status = OBSERVED if sites else _overall(unlisted, listed_empty=True)
        warnings = list(self.warnings)
        if self.pools.failure is not None and self.pools.failure.warning:
            _bounded(warnings, self.pools.failure.warning)
        if not sites and status == OBSERVED:
            warnings.append(
                f"No file in {SITES_ENABLED_DIR} or {SITES_AVAILABLE_DIR} is named like a site."
            )
        return Observation(
            status,
            (SITES_ENABLED_DIR, SITES_AVAILABLE_DIR, self.pools.path),
            " ".join(dict.fromkeys(warnings)),
            sites,
        )


def _verdict(checks: tuple[_Check, ...]) -> tuple[SiteState, str, str, tuple[str, ...]]:
    drift = next((check for check in checks if check.drift), None)
    if drift is not None:
        return SiteState.CHANGED, drift.path, drift.expected, ()
    missing = tuple(check.path for check in checks if check.missing)
    if missing:
        return SiteState.PARTLY_APPLIED, "", "", missing
    return SiteState.MANAGED, "", "", ()


def _outcome(checks: tuple[_Check, ...]) -> ObservationOutcome:
    unreadable = [
        check.outcome
        for check in checks
        if not check.matched and not check.missing and not check.drift
    ]
    if unreadable:
        return _overall(unreadable, listed_empty=False)
    return OBSERVED


def _ancestor_owners(version: str) -> dict[str, str]:
    # The directories above the site's resources, their packaged owners, and the rule
    # that no one else may write to them (docs/ssh-connections.md#what-each-candidate-reads).
    return {
        WEB_ROOT: ROOT,
        "/etc/nginx": ROOT,
        SITES_AVAILABLE_DIR: ROOT,
        SITES_ENABLED_DIR: ROOT,
        f"{PHP_BASE_DIR}/{version}/{POOL_SUBPATH}": ROOT,
        SOCKET_DIR: WEB_USER,
    }


def _account_record(output: str, name: str, fields: int) -> list[str] | None:
    lines = output.splitlines()
    if len(lines) != 1:
        return None
    parts = lines[0].split(":")
    return parts if len(parts) == fields and parts[0] == name else None


def _identity_problems(
    account: SiteAccount, layout: SiteLayout, uid_range: tuple[int, int]
) -> list[str]:
    problems = []
    low, high = uid_range
    if not low <= account.uid <= high or account.uid == NOBODY:
        problems.append(
            f"{layout.user} has UID {account.uid}, outside the normal accounts' {low} to {high}."
        )
    if account.home != layout.boundary:
        problems.append(f"The home of {layout.user} must be {layout.boundary}.")
    if account.shell != NOLOGIN:
        problems.append(f"The shell of {layout.user} must be {NOLOGIN}.")
    return problems


def _group_problems(group: str, groups: str, account: SiteAccount, user: str) -> list[str]:
    if not group:
        return [f"The account database has no group {user}."]
    record = _account_record(group, user, 4)
    if record is None or record[2] != str(account.gid):
        return [f"The primary group of {user} must be its own group {user}."]
    problems = []
    if record[3]:
        problems.append(f"The group {user} must have no other members.")
    if groups.split() != [str(account.gid)]:
        problems.append(f"{user} must belong to no group but its own.")
    return problems


def _collect_sites(
    shell: RemoteShell,
    os: Observation[OsRelease | None],
    nginx: WebStackComponentObservation,
) -> Observation[tuple[ObservedSite, ...]]:
    """docs/adr/0001-configuration-observations-depend-on-package-observation.md"""
    return _observe_installed(nginx.package, lambda _packages: _observe_sites(shell, os))


def _observe_sites(
    shell: RemoteShell, os: Observation[OsRelease | None]
) -> Observation[tuple[ObservedSite, ...]]:
    release = supported(os.value.id, os.value.version_id) if os.observed and os.value else None
    if release is None:
        return Observation(
            UNSUPPORTED,
            os.source,
            "The server is not a supported release, so Barectl does not know which PHP "
            "version its sites use.",
            (),
        )
    enabled, available = _collect_nginx_sites(shell)
    if enabled.failure is not None:
        failure = enabled.failure
        return Observation(failure.status, (SITES_ENABLED_DIR,), failure.warning, ())
    pools = _collect_php_pools(shell, release.php)
    sites = _Sites(shell, release, enabled, available, pools)
    candidates = sites.candidates()
    observed = [site for name in candidates if (site := sites.observe(name)) is not None]
    observed.extend(sites.foreign(set(candidates)))
    unlisted = [pools.failure.status] if pools.failure is not None else []
    return sites.observation(tuple(observed), unlisted)
