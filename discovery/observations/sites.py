"""Site reconstruction from native evidence (docs/ssh-connections.md#site-observations).

Names from the convention only locate candidates. A site is complete when resolved
directives, the account database and each path's own metadata agree with
docs/site-conventions.md.
"""

import re
import shlex
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cached_property
from typing import NamedTuple

from bootstrap.releases import RELEASES

from ..models import FileType, ObservationOutcome, SiteResource
from ..snapshot import (
    Observation,
    OsRelease,
    Package,
    PathMetadata,
    SiteAccount,
    SiteObservation,
    SiteResourceObservation,
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
from .parsers import NginxBlock, PoolSection, parse_nginx_tree, parse_pool_sections
from .probes import (
    _bounded,
    _Failed,
    _list_directory,
    _outside_layout,
    _overall,
    _path_missing,
    _read_file,
    _run,
    _unreadable,
)

# docs/site-conventions.md#site-identity-and-layout
CANDIDATE_FILE = re.compile(r"([a-z][a-z0-9]{2,23})\.conf")
SITES_AVAILABLE_DIR = "/etc/nginx/sites-available"
CONF_D_DIR = "/etc/nginx/conf.d"
WEB_ROOT = "/var/www"
SOCKET_DIR = "/run/php"
NOLOGIN = "/usr/sbin/nologin"
WEB_USER = "www-data"
ROOT = "root"
# docs/site-conventions.md#supported-configuration-grammar
FASTCGI_INCLUDE = PACKAGED_FASTCGI
FASTCGI_CONF = f"/etc/nginx/{FASTCGI_INCLUDE}"
CONFFILES_QUERY = "dpkg-query -W -f='${Conffiles}\\n' nginx-common"
FASTCGI_DIGEST = f"md5sum {FASTCGI_CONF}"
STAT_FORMAT = "%n %f %u %U %g %G"
# Ubuntu's default UID_MIN starts normal accounts; 65534 is nobody.
FIRST_NORMAL_UID = 1000
NOBODY = 65534
MAX_SITES = 50
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
# The fixed pool settings (docs/site-conventions.md#supported-configuration-grammar), with
# the user, group and socket, which depend on the site, added per site.
_POOL_SETTINGS = {
    "listen.owner": WEB_USER,
    "listen.group": WEB_USER,
    "listen.mode": "0600",
    "pm": "ondemand",
    "pm.max_children": "5",
    "pm.process_idle_timeout": "10s",
    "clear_env": "yes",
    "security.limit_extensions": ".php",
}
_LISTENS = ("80", "[::]:80")
_SERVER_DIRECTIVES = frozenset({"listen", "server_name", "root", "index", "autoindex", "include"})


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
    def pool_dir(self) -> str:
        return f"{PHP_BASE_DIR}/{self.version}/{POOL_SUBPATH}"

    @property
    def pool(self) -> str:
        return f"{self.pool_dir}/{self.identifier}.conf"

    @property
    def socket(self) -> str:
        return f"{SOCKET_DIR}/{self.user}.sock"

    @property
    def link_targets(self) -> tuple[str, str]:
        # The absolute target, and the relative one that resolves to it.
        return (self.source, f"../sites-available/{self.identifier}.conf")

    def pool_settings(self) -> dict[str, str]:
        return {
            "user": self.user,
            "group": self.user,
            "listen": self.socket,
            **_POOL_SETTINGS,
        }


class _Node(NamedTuple):
    file_type: FileType
    owner: str
    group: str
    mode: int

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


def _stat_command(path: str) -> str:
    return f"stat -c {shlex.quote(STAT_FORMAT)} -- {shlex.quote(path)}"


def _stat(shell: RemoteShell, path: str) -> _Node | _Failed:
    """The path's own metadata; a symbolic link is described, not followed."""
    command = _stat_command(path)
    output = _run(shell, command, accepted=frozenset({0, 1}))
    if isinstance(output, _Failed):
        return output
    if not output:
        if _path_missing(shell, path):
            return _Failed(ABSENT, f"{path} does not exist.", command, missing=True)
        return _Failed(
            INACCESSIBLE, f"The SSH user cannot see {path}. Barectl does not use sudo.", command
        )
    return _parse_stat(path, command, output)


def _parse_stat(path: str, command: str, output: str) -> _Node | _Failed:
    match output.removesuffix("\n").split(" "):
        case [name, raw, uid, owner, gid, group] if (
            name == path
            and HEX.fullmatch(raw)
            and NUMBER.fullmatch(uid)
            and NUMBER.fullmatch(gid)
            and ACCOUNT_NAME.fullmatch(owner)
            and ACCOUNT_NAME.fullmatch(group)
        ):
            mode = int(raw, 16)
            file_type = _FILE_TYPES.get(mode & 0o170000, FileType.OTHER)
            return _Node(file_type, owner, group, mode & 0o7777)
        case _:
            return _Failed(
                UNSUPPORTED, f"stat did not describe {path} in a supported format.", command
            )


def _resource(
    resource: SiteResource,
    location: str,
    found: _Node | _Failed,
    problems: Iterable[str] = (),
    *,
    source: tuple[str, ...] = (),
    link_target: str = "",
) -> SiteResourceObservation:
    """A resource from its path's metadata and any other ways it departs from the convention."""
    if isinstance(found, _Failed):
        return SiteResourceObservation(
            resource, location, found.status, False, None, (found.source, *source), found.warning
        )
    listed = list(problems)
    return SiteResourceObservation(
        resource,
        location,
        OBSERVED,
        not listed,
        found.metadata(link_target),
        (_stat_command(location), *source),
        " ".join(listed),
    )


def _failed_resource(
    resource: SiteResource, location: str, failure: _Failed, metadata: PathMetadata | None = None
) -> SiteResourceObservation:
    return SiteResourceObservation(
        resource, location, failure.status, False, metadata, (failure.source,), failure.warning
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
    root: str = ""
    socket: str = ""
    problems: list[str] = field(default_factory=list)
    # Files included beyond the packaged FastCGI parameters; they leave the effective
    # configuration unknown.
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
        if declared.get("autoindex", [("off",)]) != [("off",)]:
            self.problem("It must not enable directory listings.")

    def _listens(self, listens: list[tuple[str, ...]]) -> None:
        addresses = [values[0] for values in listens if len(values) == 1]
        if (
            len(addresses) != len(listens)
            or len(set(addresses)) != len(addresses)
            or not set(addresses) <= set(_LISTENS)
            or _LISTENS[0] not in addresses
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
        expected: dict[tuple[str, ...], set[tuple[str, ...]]] = {
            ("location", "/"): {("try_files", "$uri", "$uri/", "=404")},
            ("location", "~", "/\\."): {("deny", "all")},
            ("location", "~", "\\.php$"): {
                ("try_files", "$uri", "=404"),
                ("include", FASTCGI_INCLUDE),
                # Clears the Proxy request header, which PHP would expose as HTTP_PROXY.
                ("fastcgi_param", "HTTP_PROXY", ""),
                ("fastcgi_pass", f"unix:{self.layout.socket}"),
            },
        }
        headers = [block.header for block in server.blocks]
        for block in server.blocks:
            self._location(block, expected.get(block.header))
        # Regular expression locations match in order, so dotfiles are refused first.
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
                self.socket = tokens[1].removeprefix("unix:")
        if block.blocks or set(block.directives) != expected:
            self.problem(
                f"Its location {' '.join(block.header[1:])} does not match the convention."
            )

    def effective(self) -> tuple[str, str]:
        """The root and socket, unless included files may override them."""
        return ("", "") if self.includes else (self.root, self.socket)


@dataclass(frozen=True)
class _Reading[T]:
    resource: SiteResourceObservation
    value: T


@dataclass
class _Sites:
    """One discovery's site candidates and the evidence they share."""

    shell: RemoteShell
    version: str
    release: str
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
            {match.group(1) for name in names if (match := CANDIDATE_FILE.fullmatch(name))}
        )
        if len(identifiers) > MAX_SITES:
            _bounded(
                self.warnings,
                f"More than {MAX_SITES} sites are named in the configuration. Only the first "
                f"{MAX_SITES} were inspected.",
            )
        return identifiers[:MAX_SITES]

    @cached_property
    def fastcgi(self) -> SiteResourceObservation:
        return _fastcgi(self.shell)

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

    def observe(self, identifier: str) -> SiteObservation:
        layout = _Layout(identifier, self.version)
        nginx = _nginx_source(self.shell, layout)
        pool = self._pool(layout)
        account = _account(self.shell, layout)
        user = layout.user
        return SiteObservation(
            identifier=identifier,
            server_names=tuple(nginx.value.names),
            document_root=nginx.value.effective()[0],
            fastcgi_socket=nginx.value.effective()[1],
            php_version=self.version,
            pool_user=pool.value[0],
            pool_group=pool.value[1],
            account=account.value,
            resources=(
                _enabled(self.shell, layout),
                nginx.resource,
                self.fastcgi,
                self._directory(SiteResource.BOUNDARY, layout.boundary, ROOT, ROOT, 0o755),
                self._directory(SiteResource.DOCUMENT_ROOT, layout.public, user, WEB_USER, 0o750),
                self._directory(SiteResource.PRIVATE, layout.private, user, user, 0o700),
                pool.resource,
                _socket(self.shell, layout),
                account.resource,
                self._exclusive(layout, nginx.value.names),
            ),
        )

    def _directory(
        self, resource: SiteResource, path: str, owner: str, group: str, mode: int
    ) -> SiteResourceObservation:
        found = _stat(self.shell, path)
        expected = _Expected(FileType.DIRECTORY, owner, group, mode)
        problems = [] if isinstance(found, _Failed) else expected.problems(path, found)
        return _resource(resource, path, found, problems)

    def _pool(self, layout: _Layout) -> _Reading[tuple[str, str]]:
        unread = self._pool_unread(layout)
        if unread is not None:
            return _Reading(_failed_resource(SiteResource.POOL, layout.pool, unread), ("", ""))
        return _pool_file(self.shell, layout)

    def _pool_unread(self, layout: _Layout) -> _Failed | None:
        """Why the site's pool cannot be read from the default version's pool directory."""
        if not self.php.observed:
            return _Failed(self.php.outcome, self.php.warning, PACKAGE_QUERY)
        installed = {
            match.group(1)
            for package in self.php.value
            if (match := PHP_FPM_PACKAGE.fullmatch(package.name))
        }
        if self.version not in installed:
            return _Failed(
                ABSENT,
                f"PHP {self.version}-FPM, the default PHP version of {self.release}, is not "
                "installed.",
                PACKAGE_QUERY,
            )
        return self.pools.unread.get(self.version)

    def _exclusive(self, layout: _Layout, names: list[str]) -> SiteResourceObservation:
        conflicts: list[str] = []
        unknown: list[_Failed] = []
        self._other_site_files(layout, set(names), conflicts, unknown)
        self._other_pools(layout, conflicts, unknown)
        if self.conf_d is not None:
            unknown.append(self.conf_d)
        source = (SITES_ENABLED_DIR, CONF_D_DIR, *self.pools.observation.source)
        location = "Other Nginx site files and PHP-FPM pools"
        warning = " ".join(dict.fromkeys([*conflicts, *(item.warning for item in unknown)]))
        if conflicts or not unknown:
            return SiteResourceObservation(
                SiteResource.EXCLUSIVE, location, OBSERVED, not conflicts, None, source, warning
            )
        outcome = _overall((item.status for item in unknown), listed_empty=False)
        return SiteResourceObservation(
            SiteResource.EXCLUSIVE, location, outcome, False, None, source, warning
        )

    def _other_site_files(
        self, layout: _Layout, names: set[str], conflicts: list[str], unknown: list[_Failed]
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
            shared = sorted(names & {_dns_name(name) or name for name in entry.server_names})
            if shared:
                conflicts.append(f"{entry.source} also declares {', '.join(shared)}.")
            if references is not None and _shares(references.paths, layout.boundary):
                conflicts.append(f"{entry.source} also uses paths in {layout.boundary}.")
            if references is not None and f"unix:{layout.socket}" in references.fastcgi_passes:
                conflicts.append(f"{entry.source} also passes requests to {layout.socket}.")

    def _other_pools(self, layout: _Layout, conflicts: list[str], unknown: list[_Failed]) -> None:
        pools = self.pools.observation
        if self.pools.gap is not None:
            unknown.append(
                _Failed(
                    self.pools.gap,
                    "Barectl could not read every PHP-FPM pool, so another pool may listen on "
                    f"{layout.socket}.",
                    PHP_BASE_DIR,
                )
            )
        for pool in pools.value:
            own = (pool.version, pool.name, pool.source) == (
                layout.version,
                layout.identifier,
                layout.pool,
            )
            if pool.listen == layout.socket and not own:
                conflicts.append(
                    f"PHP {pool.version} pool {pool.name} in {pool.source} also listens on "
                    f"{layout.socket}."
                )

    def observation(
        self, sites: tuple[SiteObservation, ...]
    ) -> Observation[tuple[SiteObservation, ...]]:
        outcomes = [*(failure.status for failure in self.failures), *(OBSERVED for _ in sites)]
        status = _overall(outcomes, listed_empty=not self.failures)
        warnings = list(self.warnings)
        if not sites and status == OBSERVED:
            warnings.append(
                f"No file in {SITES_ENABLED_DIR} or {SITES_AVAILABLE_DIR} is named like a site."
            )
        source = (SITES_ENABLED_DIR, SITES_AVAILABLE_DIR)
        return Observation(status, source, " ".join(warnings), sites)


def _shares(paths: Iterable[str], boundary: str) -> bool:
    return any(path.rstrip("/") == boundary or path.startswith(f"{boundary}/") for path in paths)


def _enabled(shell: RemoteShell, layout: _Layout) -> SiteResourceObservation:
    found = _stat(shell, layout.enabled)
    if isinstance(found, _Failed):
        if found.status == ABSENT:
            found = _Failed(ABSENT, f"The site is not enabled: {found.warning}", found.source)
        return _resource(SiteResource.NGINX_ENABLED, layout.enabled, found)
    expected = _Expected(FileType.SYMLINK, ROOT, ROOT, None)
    problems = expected.problems(layout.enabled, found)
    if found.file_type != FileType.SYMLINK:
        return _resource(SiteResource.NGINX_ENABLED, layout.enabled, found, problems)
    command = f"readlink {shlex.quote(layout.enabled)}"
    target = _run(shell, command)
    if isinstance(target, _Failed):
        return _failed_resource(
            SiteResource.NGINX_ENABLED, layout.enabled, target, found.metadata()
        )
    written = target.removesuffix("\n")
    if written not in layout.link_targets:
        problems.append(f"{layout.enabled} must link to {layout.source}.")
        written = written if INCLUDED_PATH.fullmatch(written) else ""
    return _resource(
        SiteResource.NGINX_ENABLED,
        layout.enabled,
        found,
        problems,
        source=(command,),
        link_target=written,
    )


def _nginx_source(shell: RemoteShell, layout: _Layout) -> _Reading[_NginxCheck]:
    check = _NginxCheck(layout)
    found = _stat(shell, layout.source)
    if isinstance(found, _Failed):
        return _Reading(_resource(SiteResource.NGINX_SOURCE, layout.source, found), check)
    problems = _Expected(FileType.FILE, ROOT, ROOT, 0o644).problems(layout.source, found)
    text = _read_file(shell, layout.source)
    if isinstance(text, _Failed):
        resource = _failed_resource(
            SiteResource.NGINX_SOURCE, layout.source, text, found.metadata()
        )
        return _Reading(resource, check)
    tree = parse_nginx_tree(text)
    if tree is None:
        failure = _Failed(
            UNSUPPORTED,
            f"{layout.source} is not in a supported Nginx configuration form.",
            layout.source,
        )
        resource = _failed_resource(
            SiteResource.NGINX_SOURCE, layout.source, failure, found.metadata()
        )
        return _Reading(resource, check)
    check.check(tree)
    resource = _resource(
        SiteResource.NGINX_SOURCE,
        layout.source,
        found,
        [*problems, *check.problems],
        source=(layout.source,),
    )
    if check.includes:
        # The included files may declare the site's root, socket or names.
        included = ", ".join(dict.fromkeys(check.includes))
        resource = SiteResourceObservation(
            resource.resource,
            resource.location,
            UNSUPPORTED,
            False,
            resource.metadata,
            resource.source,
            f"{layout.source} includes {included}, which Barectl does not read, so its "
            f"effective root and socket are unknown. {resource.warning}".strip(),
        )
    return _Reading(resource, check)


def _pool_file(shell: RemoteShell, layout: _Layout) -> _Reading[tuple[str, str]]:
    found = _stat(shell, layout.pool)
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
        resource = SiteResourceObservation(
            resource.resource,
            resource.location,
            UNSUPPORTED,
            False,
            resource.metadata,
            resource.source,
            f"{layout.pool} includes other files, which Barectl does not read, so the pool's "
            f"effective settings are unknown. {resource.warning}".strip(),
        )
    if section is None:
        return _Reading(resource, ("", ""))
    settings = dict(section.settings)
    identity = tuple(
        value if ACCOUNT_NAME.fullmatch(value := settings.get(key, "")) else ""
        for key in ("user", "group")
    )
    return _Reading(resource, (identity[0], identity[1]))


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


def _socket(shell: RemoteShell, layout: _Layout) -> SiteResourceObservation:
    found = _stat(shell, layout.socket)
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


def _account_record(output: str, name: str, fields: int) -> list[str] | None:
    lines = output.splitlines()
    if len(lines) != 1:
        return None
    parts = lines[0].split(":")
    return parts if len(parts) == fields and parts[0] == name else None


def _account(shell: RemoteShell, layout: _Layout) -> _Reading[SiteAccount | None]:
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
    group = _run(shell, commands[1], accepted=frozenset({0, 2}))
    if isinstance(group, _Failed):
        return _Reading(_failed_resource(SiteResource.USER, user, group), None)
    account = SiteAccount(int(record[2]), int(record[3]), record[5][:200], record[6][:200])
    groups = _run(shell, commands[2])
    problems = [
        *_identity_problems(account, layout),
        *_group_problems(group, groups, account, user),
    ]
    resource = SiteResourceObservation(
        SiteResource.USER, user, OBSERVED, not problems, None, commands, " ".join(problems)
    )
    return _Reading(resource, account)


def _identity_problems(account: SiteAccount, layout: _Layout) -> list[str]:
    problems = []
    if account.uid < FIRST_NORMAL_UID or account.uid == NOBODY:
        problems.append(f"{layout.user} has UID {account.uid}, not a normal account's.")
    if account.home != layout.boundary:
        problems.append(f"The home of {layout.user} must be {layout.boundary}.")
    if account.shell != NOLOGIN:
        problems.append(f"The shell of {layout.user} must be {NOLOGIN}.")
    return problems


def _group_problems(
    group: str, groups: str | _Failed, account: SiteAccount, user: str
) -> list[str]:
    if not group:
        return [f"The account database has no group {user}."]
    record = _account_record(group, user, 4)
    if record is None or record[2] != str(account.gid):
        return [f"The primary group of {user} must be its own group {user}."]
    problems = []
    if record[3]:
        problems.append(f"The group {user} must have no other members.")
    if isinstance(groups, _Failed) or groups.split() != [str(account.gid)]:
        problems.append(f"{user} must belong to no group but its own.")
    return problems


def _fastcgi(shell: RemoteShell) -> SiteResourceObservation:
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
    actual = digest.split(" ", 1)[0]
    matches = actual == packaged[0]
    return SiteResourceObservation(
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


def _default_php(os: Observation[OsRelease | None]) -> tuple[str, str] | None:
    """The release's default PHP version and name, on a supported release."""
    release = os.value if os.observed else None
    policy = RELEASES.get(release.version_id) if release and release.id == "ubuntu" else None
    return (policy.php, policy.name) if policy else None


def _collect_sites(
    shell: RemoteShell,
    os: Observation[OsRelease | None],
    nginx: WebStackComponentObservation,
    php: WebStackComponentObservation,
    enabled: EnabledSites,
    pools: FpmPools,
) -> Observation[tuple[SiteObservation, ...]]:
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
) -> Observation[tuple[SiteObservation, ...]]:
    default = _default_php(os)
    if default is None:
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
    sites = _Sites(shell, default[0], default[1], php.package, enabled, pools)
    return sites.observation(tuple(sites.observe(name) for name in sites.candidates()))
