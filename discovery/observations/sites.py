"""Site reconstruction from native evidence (docs/ssh-connections.md#site-observations).

Names from the convention only locate candidates. A site is complete when resolved
directives, the account database and each path's own metadata agree with
docs/site-conventions.md.
"""

import re
import shlex
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from functools import cached_property
from typing import NamedTuple

from ..models import FileType, ObservationOutcome, SiteResource
from ..releases import SupportedRelease, supported
from ..snapshot import (
    Observation,
    ObservedSite,
    ObservedSiteResource,
    OsRelease,
    Package,
    PathMetadata,
    SiteAccount,
    WebStackComponentObservation,
)
from ..ssh import RemoteShell
from .components import PACKAGE_QUERY, _observe_installed
from .configuration import (
    PACKAGED_FASTCGI,
    PHP_BASE_DIR,
    PHP_FPM_PACKAGE,
    POOL_SUBPATH,
    SITES_ENABLED_DIR,
    EnabledSites,
    FpmPools,
)
from .parsers import (
    SITE_POOL_FIXED,
    NginxBlock,
    NginxReferences,
    PoolSection,
    parse_nginx_tree,
    parse_pool_sections,
)
from .probes import (
    _bounded,
    _Failed,
    _list_directory,
    _outside_layout,
    _overall,
    _path_missing,
    _read_file,
    _run,
    _test,
    _unreadable,
)

# docs/site-conventions.md#site-identity-and-layout
CANDIDATE_FILE = re.compile(r"([a-z][a-z0-9]{2,23})\.conf")
# Names the distribution's own configuration already uses: the www pool and /var/www/html.
RESERVED = frozenset({"www", "html"})
SITES_AVAILABLE_DIR = "/etc/nginx/sites-available"
CONF_D_DIR = "/etc/nginx/conf.d"
WEB_ROOT = "/var/www"
SOCKET_DIR = "/run/php"
NOLOGIN = "/usr/sbin/nologin"
WEB_USER = "www-data"
ROOT = "root"
FASTCGI_INCLUDE = PACKAGED_FASTCGI
FASTCGI_CONF = f"/etc/nginx/{FASTCGI_INCLUDE}"
CONFFILES_QUERY = "dpkg-query -W -f='${Conffiles}\\n' nginx-common"
FASTCGI_DIGEST = f"md5sum {FASTCGI_CONF}"
LOGIN_DEFS = "/etc/login.defs"
SHADOW = "/etc/shadow"
STAT_FORMAT = "%n %f %u %U %g %G"
# docs/ssh-connections.md#what-each-candidate-reads
DEFAULT_UID_RANGE = (1000, 60000)
NOBODY = 65534
MAX_SITE_CANDIDATES = 50
MAX_SERVER_NAMES = 10
MAX_DNS_NAME = 253
ACCOUNT_NAME = re.compile(r"[a-z_][a-z0-9_.-]{0,31}")
DIRECTIVE_NAME = re.compile(r"[a-z_0-9]{1,40}")
INCLUDED_PATH = re.compile(r"[A-Za-z0-9._/*-]{1,200}")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
HEX = re.compile(r"[0-9a-f]{1,8}")
NUMBER = re.compile(r"[0-9]{1,10}")
MD5 = re.compile(r"[0-9a-f]{32}")
ABSENT = ObservationOutcome.ABSENT
OBSERVED = ObservationOutcome.OBSERVED
INACCESSIBLE = ObservationOutcome.INACCESSIBLE
UNSUPPORTED = ObservationOutcome.UNSUPPORTED
IPV4_HTTP = "80"
IPV6_HTTP = "[::]:80"

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
_SERVER_DIRECTIVES = frozenset({"listen", "server_name", "root", "index", "autoindex", "include"})
# The same listen addresses, as nginx accepts them.
_LISTEN_ALIASES = {"*:80": IPV4_HTTP, "0.0.0.0:80": IPV4_HTTP}


def _listen(address: str) -> str:
    return _LISTEN_ALIASES.get(address, address)


def _socket_path(value: str) -> str:
    """A Unix socket path as the kernel resolves it, for comparing spellings of one socket."""
    path = re.sub("/+", "/", value.removeprefix("unix:"))
    if path.startswith("/var/run/"):
        path = path.removeprefix("/var")
    return path.rstrip("/") or "/"


@dataclass(frozen=True)
class _Layout:
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

    def metadata(self, link_target: str = "") -> PathMetadata:
        return PathMetadata(self.file_type, self.owner, self.group, self.mode, link_target)

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
        case [name, raw, uid, owner, gid, group] if (
            name in paths
            and HEX.fullmatch(raw)
            and NUMBER.fullmatch(uid)
            and NUMBER.fullmatch(gid)
            and ACCOUNT_NAME.fullmatch(owner)
            and ACCOUNT_NAME.fullmatch(group)
        ):
            mode = int(raw, 16)
            file_type = _FILE_TYPES.get(mode & 0o170000, FileType.OTHER)
            return name, _Node(file_type, owner, group, mode & 0o7777, command)
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


def _resource(
    resource: SiteResource,
    location: str,
    found: _Found,
    problems: Iterable[str] = (),
    *,
    source: tuple[str, ...] = (),
    link_target: str = "",
) -> ObservedSiteResource:
    """A resource from its path's metadata and any other ways it departs from the convention."""
    if isinstance(found, _Failed):
        return _failed_resource(resource, location, found, source=source)
    listed = list(problems)
    return ObservedSiteResource(
        resource,
        location,
        OBSERVED,
        not listed,
        found.metadata(link_target),
        (found.source, *source),
        " ".join(listed),
    )


def _failed_resource(
    resource: SiteResource,
    location: str,
    failure: _Failed,
    metadata: PathMetadata | None = None,
    *,
    source: tuple[str, ...] = (),
) -> ObservedSiteResource:
    return ObservedSiteResource(
        resource,
        location,
        failure.status,
        False,
        metadata,
        (failure.source, *source),
        failure.warning,
    )


def _unsupported(resource: ObservedSiteResource, warning: str) -> ObservedSiteResource:
    return ObservedSiteResource(
        resource.resource,
        resource.location,
        UNSUPPORTED,
        False,
        resource.metadata,
        resource.source,
        f"{warning} {resource.warning}".strip(),
    )


def _dns_name(name: str) -> str | None:
    """The canonical form of an explicit DNS name, or ``None`` for anything else.

    nginx compares names case-insensitively, and a terminal dot names the same host.
    """
    canonical = name.lower().removesuffix(".")
    labels = canonical.split(".")
    if (
        len(canonical) > MAX_DNS_NAME
        or not all(DNS_LABEL.fullmatch(label) for label in labels)
        or labels[-1].isdigit()
    ):
        return None
    return canonical


def _directive(name: str) -> str:
    return f"the {name}" if DIRECTIVE_NAME.fullmatch(name) else "an unrecognized"


@dataclass
class _NginxCheck:
    """What the site's Nginx file declares, and how it departs from the convention."""

    layout: _Layout
    names: list[str] = field(default_factory=list)
    listens: list[str] = field(default_factory=list)
    root: str = ""
    socket: str = ""
    problems: list[str] = field(default_factory=list)
    # Files included beyond the packaged FastCGI parameters.
    includes: list[str] = field(default_factory=list)

    def problem(self, text: str) -> None:
        _bounded(self.problems, text)

    def check(self, tree: NginxBlock) -> None:
        for tokens in tree.directives:
            self._outside(tokens)
        if [block.header for block in tree.blocks] != [("server",)]:
            self.problem("It must declare exactly one server block and no other block.")
            return
        (server,) = tree.blocks
        self._server(server)
        self._locations(server)

    def _outside(self, tokens: tuple[str, ...]) -> None:
        if tokens[0] == "include":
            self._include(tokens)
        else:
            self.problem(f"It declares {_directive(tokens[0])} directive outside its server block.")

    def _include(self, tokens: tuple[str, ...]) -> None:
        value = tokens[1] if len(tokens) == 2 else ""
        self.includes.append(value if INCLUDED_PATH.fullmatch(value) else "another file")

    def _server(self, server: NginxBlock) -> None:
        declared: dict[str, list[tuple[str, ...]]] = {}
        for name, *values in server.directives:
            if name not in _SERVER_DIRECTIVES:
                self.problem(f"It uses {_directive(name)} directive the convention does not use.")
            elif name == "include":
                self._include((name, *values))
            else:
                declared.setdefault(name, []).append(tuple(values))
        self._listens(declared.get("listen", []))
        self._server_names(declared.get("server_name", []))
        roots = declared.get("root", [])
        if len(roots) == 1 and len(roots[0]) == 1:
            self.root = roots[0][0]
        if self.root != self.layout.public:
            self.problem(f"Its root must be {self.layout.public}.")
        if declared.get("index") != [("index.php", "index.html")]:
            self.problem("It must set index to index.php index.html.")
        if declared.get("autoindex") != [("off",)]:
            self.problem("It must set autoindex off.")

    def _listens(self, listens: list[tuple[str, ...]]) -> None:
        self.listens = [_listen(values[0]) for values in listens if values]
        if (
            any(len(values) != 1 for values in listens)
            or len(set(self.listens)) != len(listens)
            or not set(self.listens) <= {IPV4_HTTP, IPV6_HTTP}
            or IPV4_HTTP not in self.listens
        ):
            self.problem(
                "It must listen on port 80, and optionally [::]:80, without flags such as "
                "default_server."
            )

    def _server_names(self, directives: list[tuple[str, ...]]) -> None:
        declared = [name for values in directives for name in values]
        canonical = [_dns_name(name) for name in declared]
        self.names = [name for name in canonical if name is not None]
        if (
            len(directives) != 1
            or not 1 <= len(declared) <= MAX_SERVER_NAMES
            or len(self.names) != len(declared)
            or len(set(self.names)) != len(self.names)
        ):
            self.problem(
                f"It must declare 1 to {MAX_SERVER_NAMES} distinct explicit DNS names in one "
                "server_name directive, without wildcards, regular expressions or addresses."
            )

    def _locations(self, server: NginxBlock) -> None:
        """docs/site-conventions.md#supported-configuration-grammar"""
        expected: dict[tuple[str, ...], set[tuple[str, ...]]] = {
            ("location", "/"): {("try_files", "$uri", "$uri/", "=404")},
            ("location", "~", "/\\."): {("deny", "all")},
            ("location", "~", "\\.php$"): {
                ("try_files", "$uri", "=404"),
                ("include", FASTCGI_INCLUDE),
                ("fastcgi_param", "HTTP_PROXY", ""),
                ("fastcgi_pass", f"unix:{self.layout.socket}"),
            },
        }
        headers = [block.header for block in server.blocks]
        for block in server.blocks:
            self._location(block, expected.get(block.header))
        if sorted(headers) != sorted(expected) or headers.index(
            ("location", "~", "/\\.")
        ) > headers.index(("location", "~", "\\.php$")):
            self.problem(
                "It must declare exactly the convention's locations: /, then dotfiles "
                "refused before PHP scripts."
            )

    def _location(self, block: NginxBlock, expected: set[tuple[str, ...]] | None) -> None:
        for tokens in block.directives:
            if tokens[0] == "include" and tokens != ("include", FASTCGI_INCLUDE):
                self._include(tokens)
            if tokens[0] == "fastcgi_pass" and len(tokens) == 2:
                self.socket = _socket_path(tokens[1])
        if block.blocks or set(block.directives) != expected:
            self.problem(
                f"Its location {' '.join(block.header[1:])} does not match the convention."
            )


class _Facts(NamedTuple):
    """What nginx loads for the site: its names, root and socket, and its listen addresses."""

    names: tuple[str, ...] = ()
    root: str = ""
    socket: str = ""
    listens: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Reading[T]:
    resource: ObservedSiteResource
    value: T


@dataclass
class _Sites:
    """One discovery's site candidates and the evidence they share."""

    shell: RemoteShell
    release: SupportedRelease
    php: Observation[tuple[Package, ...]]
    enabled: EnabledSites
    pools: FpmPools
    warnings: list[str] = field(default_factory=list)
    failures: list[_Failed] = field(default_factory=list)

    def candidates(self) -> list[str]:
        names = [entry.name for entry in self.enabled.observation.value]
        available = _list_directory(self.shell, SITES_AVAILABLE_DIR)
        if isinstance(available, _Failed):
            self.failures.append(_outside_layout(available))
            _bounded(self.warnings, self.failures[-1].warning)
        else:
            names += available
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

    @cached_property
    def fastcgi(self) -> ObservedSiteResource:
        return _fastcgi(self.shell)

    @cached_property
    def ancestors(self) -> ObservedSiteResource:
        return _ancestors(self.shell, self.release.php)

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

    @cached_property
    def conf_d(self) -> _Failed | None:
        """Why configuration in conf.d may declare server blocks, or ``None`` if none does."""
        listed = _list_directory(self.shell, CONF_D_DIR)
        if isinstance(listed, _Failed):
            return None if listed.missing else listed
        if any(name.endswith(".conf") for name in listed):
            return _Failed(
                UNSUPPORTED,
                f"{CONF_D_DIR} holds configuration files, which Barectl does not read.",
                CONF_D_DIR,
            )
        return None

    def observe(self, identifier: str) -> ObservedSite:
        layout = _Layout(identifier, self.release.php)
        nodes = _stat_paths(self.shell, layout.paths)
        enabled, loaded = _enabled(self.shell, layout, nodes[layout.enabled])
        nginx = _nginx_source(self.shell, layout, nodes[layout.source], loaded=loaded)
        pool = self._pool(layout, nodes[layout.pool])
        account = self._account(layout, nodes[layout.ssh])
        user = layout.user
        return ObservedSite(
            identifier=identifier,
            server_names=nginx.value.names,
            document_root=nginx.value.root,
            fastcgi_socket=nginx.value.socket,
            php_version=self.release.php,
            pool_user=pool.value[0],
            pool_group=pool.value[1],
            account=account.value,
            resources=(
                enabled,
                nginx.resource,
                self.fastcgi,
                self.ancestors,
                self._directory(SiteResource.BOUNDARY, nodes, layout.boundary, ROOT, ROOT, 0o755),
                self._directory(
                    SiteResource.DOCUMENT_ROOT, nodes, layout.public, user, WEB_USER, 0o750
                ),
                self._directory(SiteResource.PRIVATE, nodes, layout.private, user, user, 0o700),
                pool.resource,
                _socket(layout, nodes[layout.socket]),
                account.resource,
                self._password(layout),
                self._exclusive(layout, nginx.value),
            ),
        )

    @staticmethod
    def _directory(
        resource: SiteResource,
        nodes: Mapping[str, _Found],
        path: str,
        owner: str,
        group: str,
        mode: int,
    ) -> ObservedSiteResource:
        found = nodes[path]
        expected = _Expected(FileType.DIRECTORY, owner, group, mode)
        problems = [] if isinstance(found, _Failed) else expected.problems(path, found)
        return _resource(resource, path, found, problems)

    def _pool(self, layout: _Layout, found: _Found) -> _Reading[tuple[str, str]]:
        unread = self._pool_unread()
        if unread is not None:
            return _Reading(_failed_resource(SiteResource.POOL, layout.pool, unread), ("", ""))
        return _pool_file(self.shell, layout, found)

    def _pool_unread(self) -> _Failed | None:
        """Why the site's pool cannot be read from the default version's pool directory."""
        if not self.php.observed:
            return _Failed(self.php.outcome, self.php.warning, PACKAGE_QUERY)
        installed = {
            match.group(1)
            for package in self.php.value
            if (match := PHP_FPM_PACKAGE.fullmatch(package.name))
        }
        if self.release.php not in installed:
            return _Failed(
                ABSENT,
                f"PHP {self.release.php}-FPM, the default PHP version of {self.release.name}, "
                "is not installed.",
                PACKAGE_QUERY,
            )
        return self.pools.unread.get(self.release.php)

    def _account(self, layout: _Layout, ssh: _Found) -> _Reading[SiteAccount | None]:
        uid_range, defs = self.uid_range
        return _account(self.shell, layout, ssh, uid_range, defs)

    def _password(self, layout: _Layout) -> ObservedSiteResource:
        """Whether the site user's password is locked; only its first character is read."""
        user, resource = layout.user, SiteResource.PASSWORD
        if not self.shadow_readable:
            failure = _Failed(
                INACCESSIBLE,
                f"The SSH user cannot read {SHADOW}, so Barectl cannot tell whether the "
                f"password of {user} is locked. Barectl does not use sudo.",
                f"test -r {SHADOW}",
            )
            return _failed_resource(resource, user, failure)
        command = f"getent shadow {user} | cut -d: -f2 | cut -c1"
        output = _run(self.shell, command)
        if isinstance(output, _Failed):
            return _failed_resource(resource, user, output)
        if not output:
            failure = _Failed(ABSENT, f"The shadow database has no entry for {user}.", command)
            return _failed_resource(resource, user, failure)
        locked = output.strip() in {"!", "*"}
        warning = "" if locked else f"The password of {user} must be locked."
        return ObservedSiteResource(resource, user, OBSERVED, locked, None, (command,), warning)

    def _exclusive(self, layout: _Layout, facts: _Facts) -> ObservedSiteResource:
        conflicts: list[str] = []
        unknown: list[_Failed] = []
        self._main_configuration(unknown)
        self._other_site_files(layout, facts, conflicts, unknown)
        self._other_pools(layout, conflicts, unknown)
        source = (SITES_ENABLED_DIR, CONF_D_DIR, *self.pools.observation.source)
        location = "Other Nginx site files and PHP-FPM pools"
        warning = " ".join(dict.fromkeys([*conflicts, *(item.warning for item in unknown)]))
        if conflicts or not unknown:
            return ObservedSiteResource(
                SiteResource.EXCLUSIVE, location, OBSERVED, not conflicts, None, source, warning
            )
        outcome = _overall((item.status for item in unknown), listed_empty=False)
        return ObservedSiteResource(
            SiteResource.EXCLUSIVE, location, outcome, False, None, source, warning
        )

    def _main_configuration(self, unknown: list[_Failed]) -> None:
        """What the main configuration files load beyond the Debian directories."""
        if self.enabled.main_extras:
            unknown.append(
                _Failed(
                    UNSUPPORTED,
                    f"/etc/nginx/nginx.conf declares {', '.join(self.enabled.main_extras)}, "
                    "which Barectl does not read.",
                    "/etc/nginx/nginx.conf",
                )
            )
        for version, extras in self.pools.main_extras.items():
            if extras:
                path = f"{PHP_BASE_DIR}/{version}/fpm/php-fpm.conf"
                unknown.append(
                    _Failed(
                        UNSUPPORTED,
                        f"{path} declares {', '.join(extras)}, which Barectl does not read.",
                        path,
                    )
                )
        if self.conf_d is not None:
            unknown.append(self.conf_d)

    def _other_site_files(
        self, layout: _Layout, facts: _Facts, conflicts: list[str], unknown: list[_Failed]
    ) -> None:
        if not self.enabled.fully_listed:
            unknown.append(
                _Failed(
                    UNSUPPORTED,
                    f"Barectl did not read every entry in {SITES_ENABLED_DIR}, so another "
                    "site may declare the same names, root or socket.",
                    SITES_ENABLED_DIR,
                )
            )
        known: list[NginxReferences] = []
        for entry in self.enabled.observation.value:
            if entry.name == f"{layout.identifier}.conf" or entry.outcome == ABSENT:
                continue
            references = self.enabled.references.get(entry.name)
            if entry.outcome != OBSERVED:
                unknown.append(
                    _Failed(
                        entry.outcome,
                        f"{entry.warning} It may declare the same names, root or socket.",
                        entry.source,
                    )
                )
            elif references is None or references.dynamic:
                unknown.append(
                    _Failed(
                        UNSUPPORTED,
                        f"Barectl cannot tell which paths and sockets {entry.source} uses.",
                        entry.source,
                    )
                )
            else:
                known.append(references)
            conflicts += _shared(entry.source, entry.server_names, references, layout, facts)
        if not unknown:
            conflicts += _default_server(facts, known)

    def _other_pools(self, layout: _Layout, conflicts: list[str], unknown: list[_Failed]) -> None:
        if self.pools.gap is not None:
            unknown.append(
                _Failed(
                    self.pools.gap,
                    "Barectl could not read every PHP-FPM pool, so another pool may listen on "
                    f"{layout.socket} or run as {layout.user}.",
                    PHP_BASE_DIR,
                )
            )
        for pool in self.pools.observation.value:
            if (pool.version, pool.name, pool.source) == (
                layout.version,
                layout.identifier,
                layout.pool,
            ):
                continue
            named = f"PHP {pool.version} pool {pool.name} in {pool.source}"
            if pool.listen and _socket_path(pool.listen) == layout.socket:
                conflicts.append(f"{named} also listens on {layout.socket}.")
            if pool.name.casefold() == layout.identifier:
                conflicts.append(f"{named} has the site's name.")
            if self.pools.users.get((pool.version, pool.name)) == layout.user:
                conflicts.append(f"{named} also runs as {layout.user}.")

    def observation(self, sites: tuple[ObservedSite, ...]) -> Observation[tuple[ObservedSite, ...]]:
        outcomes = [*(failure.status for failure in self.failures), *(OBSERVED for _ in sites)]
        status = _overall(outcomes, listed_empty=not self.failures)
        warnings = list(self.warnings)
        if not sites and status == OBSERVED:
            warnings.append(
                f"No file in {SITES_ENABLED_DIR} or {SITES_AVAILABLE_DIR} is named like a site."
            )
        return Observation(
            status, (SITES_ENABLED_DIR, SITES_AVAILABLE_DIR), " ".join(warnings), sites
        )


def _shared(
    source: str,
    server_names: tuple[str, ...],
    references: NginxReferences | None,
    layout: _Layout,
    facts: _Facts,
) -> list[str]:
    """How another site file shares the site's names, paths or socket."""
    conflicts = []
    shared = sorted(set(facts.names) & {_dns_name(name) or name for name in server_names})
    if shared:
        conflicts.append(f"{source} also declares {', '.join(shared)}.")
    if references is None:
        return conflicts
    boundary = layout.boundary
    if any(p.rstrip("/") == boundary or p.startswith(f"{boundary}/") for p in references.paths):
        conflicts.append(f"{source} also uses paths in {boundary}.")
    if layout.socket in {_socket_path(value) for value in references.fastcgi_passes}:
        conflicts.append(f"{source} also passes requests to {layout.socket}.")
    return conflicts


def _default_server(facts: _Facts, others: list[NginxReferences]) -> list[str]:
    """How the site could answer requests for names no site declares.

    nginx gives such requests to the default server of the address they arrive on.
    """
    defaults = {_listen(address) for references in others for address in references.defaults}
    conflicts = [
        f"No other enabled site file is the default server for {address}, so this site "
        "would answer requests for unknown names."
        for address in facts.listens
        if address not in defaults
    ]
    if IPV6_HTTP in defaults and facts.listens and IPV6_HTTP not in facts.listens:
        conflicts.append("The default server listens on [::]:80, so the site must too.")
    return conflicts


def _enabled(
    shell: RemoteShell, layout: _Layout, found: _Found
) -> tuple[ObservedSiteResource, bool]:
    """The enablement resource, and whether nginx loads exactly the site's source through it."""
    resource = SiteResource.NGINX_ENABLED
    if isinstance(found, _Failed):
        if found.status == ABSENT:
            found = _Failed(ABSENT, f"The site is not enabled: {found.warning}", found.source)
        return _resource(resource, layout.enabled, found), False
    problems = _Expected(FileType.SYMLINK, ROOT, ROOT, None).problems(layout.enabled, found)
    if found.file_type != FileType.SYMLINK:
        return _resource(resource, layout.enabled, found, problems), False
    command = f"readlink {shlex.quote(layout.enabled)}"
    target = _run(shell, command)
    if isinstance(target, _Failed):
        return _failed_resource(resource, layout.enabled, target, found.metadata()), False
    written = target.removesuffix("\n")
    if written not in layout.link_targets:
        problems.append(f"{layout.enabled} must link to {layout.source}.")
        written = written if INCLUDED_PATH.fullmatch(written) else ""
    observed = _resource(
        resource, layout.enabled, found, problems, source=(command,), link_target=written
    )
    return observed, observed.conforms


def _nginx_source(
    shell: RemoteShell, layout: _Layout, found: _Found, *, loaded: bool
) -> _Reading[_Facts]:
    """The site's Nginx file, read through its link when nginx loads it that way.

    Its names, root and socket are the site's only when nginx loads exactly that file and
    it includes nothing Barectl does not read.
    """
    resource = SiteResource.NGINX_SOURCE
    if isinstance(found, _Failed):
        return _Reading(_resource(resource, layout.source, found), _Facts())
    problems = _Expected(FileType.FILE, ROOT, ROOT, 0o644).problems(layout.source, found)
    read = layout.enabled if loaded else layout.source
    text = _read_file(shell, read)
    tree = None if isinstance(text, _Failed) else parse_nginx_tree(text)
    if tree is None:
        failure = (
            text
            if isinstance(text, _Failed)
            else _Failed(
                UNSUPPORTED, f"{read} is not in a supported Nginx configuration form.", read
            )
        )
        observed = _failed_resource(resource, layout.source, failure, found.metadata())
        return _Reading(observed, _Facts())
    check = _NginxCheck(layout)
    check.check(tree)
    observed = _resource(
        resource, layout.source, found, [*problems, *check.problems], source=(read,)
    )
    if check.includes:
        included = ", ".join(dict.fromkeys(check.includes))
        observed = _unsupported(
            observed,
            f"{read} includes {included}, which Barectl does not read, so its effective "
            "root and socket are unknown.",
        )
    if not loaded or check.includes:
        return _Reading(observed, _Facts())
    return _Reading(
        observed, _Facts(tuple(check.names), check.root, check.socket, tuple(check.listens))
    )


def _pool_file(shell: RemoteShell, layout: _Layout, found: _Found) -> _Reading[tuple[str, str]]:
    if isinstance(found, _Failed):
        return _Reading(_resource(SiteResource.POOL, layout.pool, found), ("", ""))
    problems = _Expected(FileType.FILE, ROOT, ROOT, 0o644).problems(layout.pool, found)
    text = _read_file(shell, layout.pool)
    sections = None if isinstance(text, _Failed) else parse_pool_sections(text)
    if sections is None:
        failure = (
            text
            if isinstance(text, _Failed)
            else _Failed(
                UNSUPPORTED,
                f"{layout.pool} is not in a supported PHP-FPM pool configuration form.",
                layout.pool,
            )
        )
        return _Reading(
            _failed_resource(SiteResource.POOL, layout.pool, failure, found.metadata()), ("", "")
        )
    section, pool_problems = _pool_problems(sections, layout)
    resource = _resource(
        SiteResource.POOL, layout.pool, found, [*problems, *pool_problems], source=(layout.pool,)
    )
    if any(declared.includes for declared in sections):
        resource = _unsupported(
            resource,
            f"{layout.pool} includes other files, which Barectl does not read, so the pool's "
            "effective settings are unknown.",
        )
    if section is None:
        return _Reading(resource, ("", ""))
    settings = dict(section.settings)
    user, group = (
        value if ACCOUNT_NAME.fullmatch(value := settings.get(key, "")) else ""
        for key in ("user", "group")
    )
    return _Reading(resource, (user, group))


def _pool_problems(
    sections: tuple[PoolSection, ...], layout: _Layout
) -> tuple[PoolSection | None, list[str]]:
    """The site's pool section, and how the file departs from the convention."""
    problems: list[str] = []
    if [section.name for section in sections] != [layout.identifier]:
        problems.append(f"{layout.pool} must declare the pool {layout.identifier} and no other.")
    section = next((item for item in sections if item.name == layout.identifier), None)
    if section is None:
        return None, problems
    settings = dict(section.settings)
    for key, expected in layout.pool_settings().items():
        actual = settings.get(key)
        if actual is None:
            problems.append(f"The pool does not set {key} = {expected}.")
        elif actual != expected:
            problems.append(f"The pool sets {key} = {actual}, not {expected}.")
    if section.others:
        problems.append(
            f"The pool declares {section.others} other setting"
            f"{'s' if section.others > 1 else ''}, which the convention does not use."
        )
    return section, problems


def _socket(layout: _Layout, found: _Found) -> ObservedSiteResource:
    if isinstance(found, _Failed):
        if found.status == ABSENT:
            found = _Failed(
                ABSENT,
                f"{layout.socket} does not exist, so no running PHP-FPM pool provides the "
                "socket the site's Nginx configuration names.",
                found.source,
            )
        return _resource(SiteResource.SOCKET, layout.socket, found)
    expected = _Expected(FileType.SOCKET, WEB_USER, WEB_USER, 0o600)
    return _resource(
        SiteResource.SOCKET, layout.socket, found, expected.problems(layout.socket, found)
    )


# The directories above the site's resources, their packaged owners, and the rule that no
# one else may write to them (docs/ssh-connections.md#what-each-candidate-reads).
def _ancestor_owners(version: str) -> dict[str, str]:
    return {
        WEB_ROOT: ROOT,
        "/etc/nginx": ROOT,
        SITES_AVAILABLE_DIR: ROOT,
        SITES_ENABLED_DIR: ROOT,
        f"{PHP_BASE_DIR}/{version}/{POOL_SUBPATH}": ROOT,
        SOCKET_DIR: WEB_USER,
    }


def _ancestors(shell: RemoteShell, version: str) -> ObservedSiteResource:
    owners = _ancestor_owners(version)
    paths = tuple(owners)
    nodes = _stat_paths(shell, paths)
    command = _stat_command(paths)
    location = "Parent directories"
    failures = [found for found in nodes.values() if isinstance(found, _Failed)]
    if failures:
        outcome = _overall((failure.status for failure in failures), listed_empty=False)
        warning = " ".join(dict.fromkeys(failure.warning for failure in failures))
        return ObservedSiteResource(
            SiteResource.ANCESTORS, location, outcome, False, None, (command,), warning
        )
    problems = [
        f"{path} must be a directory owned by {owner} that only its owner can write; it is "
        f"{node.describe()}."
        for path, owner in owners.items()
        if isinstance(node := nodes[path], _Node)
        and (node.file_type != FileType.DIRECTORY or node.owner != owner or node.mode & 0o022)
    ]
    return ObservedSiteResource(
        SiteResource.ANCESTORS,
        location,
        OBSERVED,
        not problems,
        None,
        (command,),
        " ".join(problems),
    )


def _account_record(output: str, name: str, fields: int) -> list[str] | None:
    lines = output.splitlines()
    if len(lines) != 1:
        return None
    parts = lines[0].split(":")
    return parts if len(parts) == fields and parts[0] == name else None


def _account(
    shell: RemoteShell,
    layout: _Layout,
    ssh: _Found,
    uid_range: tuple[int, int],
    defs: tuple[str, ...],
) -> _Reading[SiteAccount | None]:
    user = layout.user
    commands = (f"getent passwd {user}", f"getent group {user}", f"id -G {user}")
    # getent exits 2 when the database has no such entry.
    passwd = _run(shell, commands[0], accepted=frozenset({0, 2}))
    if isinstance(passwd, _Failed) or not passwd:
        failure = passwd or _Failed(
            ABSENT, f"The account database has no user {user}.", commands[0]
        )
        return _Reading(_failed_resource(SiteResource.USER, user, failure), None)
    record = _account_record(passwd, user, 7)
    if record is None or not (NUMBER.fullmatch(record[2]) and NUMBER.fullmatch(record[3])):
        failure = _Failed(
            UNSUPPORTED, f"getent did not describe {user} in a supported format.", commands[0]
        )
        return _Reading(_failed_resource(SiteResource.USER, user, failure), None)
    account = SiteAccount(int(record[2]), int(record[3]), record[5][:200], record[6][:200])
    group = _run(shell, commands[1], accepted=frozenset({0, 2}))
    groups = _run(shell, commands[2])
    for output in (group, groups, ssh):
        if isinstance(output, _Failed) and not (output is ssh and output.status == ABSENT):
            return _Reading(_failed_resource(SiteResource.USER, user, output), account)
    problems = [
        *_identity_problems(account, layout, uid_range),
        *_group_problems(str(group), str(groups), account, user),
    ]
    if isinstance(ssh, _Node):
        problems.append(f"{layout.ssh} must not exist; SSH keys there would let {user} log in.")
    source = (*commands, ssh.source, *defs)
    resource = ObservedSiteResource(
        SiteResource.USER, user, OBSERVED, not problems, None, source, " ".join(problems)
    )
    return _Reading(resource, account)


def _identity_problems(
    account: SiteAccount, layout: _Layout, uid_range: tuple[int, int]
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


def _fastcgi(shell: RemoteShell) -> ObservedSiteResource:
    """Whether fastcgi.conf is the file the nginx-common package installed."""
    resource, location = SiteResource.FASTCGI, FASTCGI_CONF
    conffiles = _run(shell, CONFFILES_QUERY)
    if isinstance(conffiles, _Failed):
        return _failed_resource(resource, location, conffiles)
    packaged = [
        parts[1]
        for line in conffiles.splitlines()
        if len(parts := line.split()) >= 2 and parts[0] == FASTCGI_CONF
    ]
    if len(packaged) != 1 or MD5.fullmatch(packaged[0]) is None:
        failure = _Failed(
            UNSUPPORTED,
            f"The nginx-common package does not list {FASTCGI_CONF} as its configuration.",
            CONFFILES_QUERY,
        )
        return _failed_resource(resource, location, failure)
    digest = _run(shell, FASTCGI_DIGEST)
    if isinstance(digest, _Failed):
        failure = digest if digest.missing else _unreadable(shell, FASTCGI_CONF)
        return _failed_resource(resource, location, failure)
    matches = digest.split(" ", 1)[0] == packaged[0]
    return ObservedSiteResource(
        resource,
        location,
        OBSERVED,
        matches,
        None,
        (CONFFILES_QUERY, FASTCGI_DIGEST),
        ""
        if matches
        else f"{FASTCGI_CONF} differs from the file the nginx-common package installed.",
    )


def _collect_sites(
    shell: RemoteShell,
    os: Observation[OsRelease | None],
    nginx: WebStackComponentObservation,
    php: WebStackComponentObservation,
    enabled: EnabledSites,
    pools: FpmPools,
) -> Observation[tuple[ObservedSite, ...]]:
    """docs/adr/0001-configuration-observations-depend-on-package-observation.md"""
    return _observe_installed(
        nginx.package, lambda _packages: _observe_sites(shell, os, php, enabled, pools)
    )


def _observe_sites(
    shell: RemoteShell,
    os: Observation[OsRelease | None],
    php: WebStackComponentObservation,
    enabled: EnabledSites,
    pools: FpmPools,
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
    if not enabled.listed:
        site_files = enabled.observation
        return Observation(site_files.outcome, site_files.source, site_files.warning, ())
    sites = _Sites(shell, release, php.package, enabled, pools)
    return sites.observation(tuple(sites.observe(name) for name in sites.candidates()))
