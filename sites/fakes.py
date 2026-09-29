"""A simulated Ubuntu server as site preparation reads it.

``SiteServer`` answers site preparation's commands on a ``discovery.fakes.FakeServer`` in
the shapes recorded from the disposable acceptance servers, on top of
``bootstrap.fakes.UbuntuServer`` with the Nginx and PHP profiles installed. Tests change
its fields, such as existing sites, accounts or listeners, and ``answer`` writes the
answers. ``site_read_only`` states independently which command shapes preparation may run.
"""

import hashlib
import re
import shlex
from dataclasses import dataclass, field
from typing import ClassVar, override

from django.http import HttpResponseBase

from bootstrap import inspection as bootstrap_inspection
from bootstrap.fakes import (
    NOBLE_PACKAGING,
    PREPARATION_READ_ONLY,
    Packaging,
    PreparationTestCase,
    UbuntuServer,
)
from discovery.fakes import READ_ONLY
from discovery.ssh import CommandResult

from . import inspection, native
from .convention import SitePaths, render_pool, render_site

# The command shapes site preparation may run besides bootstrap preparation's platform
# reads, stated independently of sites.native: fixed root reads through /usr/bin/sh -c and
# head of a convention file, each directly as root or through sudo -n, which is also only
# asked to list an authorization.
_ENV = "export LC_ALL=C PATH=/usr/sbin:/usr/bin; "
_TREES = r"/etc/nginx /etc/php/8\.[35]/fpm /etc/php/8\.[35]/mods-available"
_ROOT_SCRIPTS = re.compile(
    r"\{ " + re.escape(_ENV) + r"find [^>]* \} 2>/dev/null \| LC_ALL=C sort \| sha256sum"
    rf"|{re.escape(_ENV)}find {_TREES} -xdev -printf '[^']*'"
    rf"|{re.escape(_ENV)}find {_TREES} -xdev -type f -exec md5sum -- \{{\}} \+"
    rf"|{re.escape(_ENV)}for p in [/a-z0-9. -]+; do if \[ -e \"\$p\" \] \|\| \[ -L \"\$p\" \]; "
    r"then stat -c '[^']*' -- \"\$p\" \|\| echo \"unreadable \$p\"; "
    r"else echo \"absent \$p\"; fi; done"
    rf"|{re.escape(_ENV)}ss -Hltnp sport = :80"
    rf"|{re.escape(_ENV)}getent shadow s[a-z0-9]{{3,24}} \| cut -d: -f2 \| cut -c1",
    re.DOTALL,
)
_HEAD = re.compile(
    r"/usr/bin/head -c 8193 -- "
    r"/etc/(nginx/sites-available|php/8\.[35]/fpm/pool\.d)/[a-z][a-z0-9]{2,23}\.conf"
)
_PLAIN = re.compile(
    r"getent (passwd|group) (s[a-z0-9]{3,24}|www-data)"
    r"|id -G s[a-z0-9]{3,24}"
    r"|cut -d: -f3 /etc/(passwd|group)"
    r"|cat /etc/(login\.defs|default/useradd)"
    r"|grep -E '\^\(passwd\|group\):' /etc/nsswitch\.conf"
    r"|test -e /etc/subuid"
    r"|ss -Hlx src /run/php/s[a-z0-9]{3,24}\.sock"
    r"|dpkg-query -W -f='[^']*' nginx-common php8\.[35]-fpm php8\.[35]-cli php8\.[35]-common"
)


def site_read_only(command: str) -> bool:
    if _PLAIN.fullmatch(command):
        return True
    try:
        argv = shlex.split(command)
    except ValueError:
        return False
    if argv[:3] == ["sudo", "-n", "-l"]:
        argv = argv[3:]
    elif argv[:2] == ["sudo", "-n"]:
        argv = argv[2:]
    if argv[:2] == ["/usr/bin/sh", "-c"] and len(argv) == 3:
        return _ROOT_SCRIPTS.fullmatch(argv[2]) is not None
    return _HEAD.fullmatch(" ".join(argv)) is not None and len(argv) == 5


LOGIN_DEFS = (
    "# /etc/login.defs - Configuration control definitions for the login package.\n"
    "MAIL_DIR        /var/mail\n"
    "HOME_MODE\t0750\n"
    "UID_MIN\t\t\t 1000\n"
    "UID_MAX\t\t\t60000\n"
    "GID_MIN\t\t\t 1000\n"
    "GID_MAX\t\t\t60000\n"
    "SUB_UID_COUNT\t\t    65536\n"
    "USERGROUPS_ENAB yes\n"
    "ENCRYPT_METHOD SHA512\n"
)
USERADD = "# useradd defaults file\nSHELL=/bin/sh\n"
NSSWITCH = "passwd:         files\ngroup:          files\n"
POSIX_MD5 = "0f55f144c06b074b7c0a498928001452"
_ROOT_DIRECTORY = ("d", 0o755, 0, 0, "root", "root")


@dataclass(frozen=True)
class Node:
    """A path's own metadata: find's type letter, mode, owners by number and name."""

    kind: str
    mode: int
    uid: int
    gid: int
    owner: str
    group: str
    target: str = ""
    links: int = 1


@dataclass
class SiteServer:
    """A server with the stock Nginx and default PHP profiles. Change fields, then ``answer``."""

    packaging: Packaging = NOBLE_PACKAGING
    # "sudo" authorizes every read, "narrow" only systemd-run, "root" is the SSH user.
    privilege: str = "sudo"
    # Convention sites already on the server: identifier to (names, IPv6, enabled).
    sites: dict[str, tuple[tuple[str, ...], bool, bool]] = field(default_factory=dict)
    # Convention pools already on the server, by identifier.
    pools: set[str] = field(default_factory=set)
    # Other files under the trees, by path, with their bytes; md5 follows the bytes.
    files: dict[str, str] = field(default_factory=dict)
    # Distribution files whose bytes were changed.
    changed: set[str] = field(default_factory=set)
    # Other links under the trees, by path, with their targets.
    links: dict[str, str] = field(default_factory=dict)
    # Paths removed from the stock trees.
    removed: set[str] = field(default_factory=set)
    # Site paths that exist, with their metadata.
    paths: dict[str, Node] = field(default_factory=dict)
    # Accounts beside the system's: name to (uid, gid).
    accounts: dict[str, tuple[int, int]] = field(default_factory=dict)
    locked: bool = True
    listeners: tuple[tuple[str, str], ...] = (("0.0.0.0", "nginx"), ("[::]", "nginx"))  # noqa: S104
    sockets: set[str] = field(default_factory=set)
    login_defs: str = LOGIN_DEFS
    useradd: str = USERADD
    nsswitch: str = NSSWITCH
    # The second digest read differs from the first, as when something changed meanwhile.
    changing: bool = False
    # Tree entries on another filesystem than their tree, such as mount points.
    mounts: set[str] = field(default_factory=set)
    # Commands whose output is larger than a read returns.
    truncated: set[str] = field(default_factory=set)
    ubuntu: UbuntuServer = field(init=False)
    digests: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self.ubuntu = UbuntuServer(
            self.packaging, nginx="installed", php="installed", privilege=self._ssh_privilege
        )

    @property
    def _ssh_privilege(self) -> str:
        return {"root": "root", "none": "none"}.get(self.privilege, "sudo")

    @property
    def php(self) -> str:
        return self.packaging.release.php

    def site_paths(self, identifier: str) -> SitePaths:
        return SitePaths(identifier, self.php)

    def answer(self, remote: object) -> None:
        self.ubuntu.privilege = self._ssh_privilege
        self.ubuntu.answer(remote)  # type: ignore[arg-type]
        answers = remote.answers  # type: ignore[attr-defined]
        if self._answer not in answers:
            answers.insert(0, self._answer)

    # Answers ---------------------------------------------------------------------------

    def _answer(self, command: str) -> CommandResult | None:
        if command in self.truncated:
            return CommandResult(0, "x" * 10, truncated=True)
        root = self.privilege == "root"
        for prefix, listing in (("sudo -n -l ", True), ("sudo -n ", False), ("", False)):
            if not command.startswith(prefix):
                continue
            argv = _argv(command.removeprefix(prefix))
            if argv is None:
                continue
            if prefix and root:
                return None
            if not prefix and not root:
                return CommandResult(126, "")
            allowed = self.privilege in {"sudo", "root"}
            if listing:
                return CommandResult(
                    0 if allowed else 1, f"{shlex.join(argv)}\n" if allowed else ""
                )
            if not allowed:
                return CommandResult(1, "sudo: a password is required\n")
            return self._privileged(argv)
        return self._plain(command)

    def _privileged(self, argv: list[str]) -> CommandResult:
        if argv[0] == native.HEAD:
            path = argv[-1]
            text = self._tree_files().get(path)
            return CommandResult(0, text) if text is not None else CommandResult(1, "")
        script = argv[2]
        if script.startswith("{ "):
            self.digests += 1
            state = repr((self._state(), self.changing and self.digests > 1))
            return CommandResult(0, f"{hashlib.sha256(state.encode()).hexdigest()}  -\n")
        if "-printf" in script:
            return CommandResult(0, self._listing())
        if "md5sum" in script:
            files = self._tree_files()
            text = "".join(f"{_md5(files[p], p, self)}  {p}\n" for p in sorted(files))
            return CommandResult(0, text)
        if script.endswith("ss -Hltnp sport = :80"):
            lines = [
                f'LISTEN 0      511    {address}:80 0.0.0.0:* users:(("{process}",pid=811,fd=5))'
                for address, process in self.listeners
            ]
            return CommandResult(0, "".join(f"{line}\n" for line in lines))
        if "getent shadow" in script:
            user = re.search(r"getent shadow (\S+)", script)
            exists = user is not None and user[1] in self.accounts
            return CommandResult(0, ("!\n" if self.locked else "$\n") if exists else "")
        if script.startswith("export LC_ALL=C PATH=/usr/sbin:/usr/bin; for p in "):
            return CommandResult(0, self._states(script))
        return CommandResult(127, "")

    def _plain(self, command: str) -> CommandResult | None:
        php = self.php
        match = re.fullmatch(r"getent (passwd|group) (\S+)", command)
        if match:
            return self._getent(match[1], match[2])
        match = re.fullmatch(r"id -G (\S+)", command)
        if match and match[1] in self.accounts:
            return CommandResult(0, f"{self.accounts[match[1]][1]}\n")
        uids = [0, 33, 100, 101, 993, 1001, 1002, *(uid for uid, _ in self.accounts.values())]
        gids = [0, 33, 100, 101, 993, 1001, 1002, *(gid for _, gid in self.accounts.values())]
        socket = re.fullmatch(r"ss -Hlx src (\S+)", command)
        results = {
            inspection.USER_IDS: "".join(f"{uid}\n" for uid in uids),
            inspection.GROUP_IDS: "".join(f"{gid}\n" for gid in gids),
            inspection.LOGIN_DEFS: self.login_defs,
            inspection.USERADD_DEFAULTS: self.useradd,
            inspection.NSSWITCH: self.nsswitch,
            bootstrap_inspection.conffiles(inspection.packages(php)[1:]): self._conffiles(),
            bootstrap_inspection.UCF_HASHES: "".join(
                f"{md5}  {path}\n"
                for path, md5 in {
                    **self.packaging.php_ucf,
                    f"/etc/php/{php}/mods-available/posix.ini": POSIX_MD5,
                }.items()
            ),
        }
        if command in results:
            return CommandResult(0, results[command])
        if command == inspection.SUBORDINATE:
            return CommandResult(0, "")
        if socket and socket[1].startswith("/run/php/s"):
            listening = socket[1] in self.sockets
            line = f"u_str LISTEN 0      511    {socket[1]} 2247233 * 0\n"
            return CommandResult(0, line if listening else "")
        return None

    def _getent(self, database: str, name: str) -> CommandResult:
        if name == "www-data":
            record = "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
            return CommandResult(0, f"{record if database == 'passwd' else 'www-data:x:33:'}\n")
        if name not in self.accounts:
            return CommandResult(2, "")
        uid, gid = self.accounts[name]
        home = f"/var/www/{name[1:]}"
        if database == "passwd":
            return CommandResult(0, f"{name}:x:{uid}:{gid}::{home}:/usr/sbin/nologin\n")
        return CommandResult(0, f"{name}:x:{gid}:\n")

    # The configuration trees -------------------------------------------------------------

    def _defaults(self) -> dict[str, str]:
        """The stock files under the trees and their packaged MD5 digests."""
        php = f"/etc/php/{self.php}"
        packaged = {
            **self.packaging.nginx_conffiles,
            **self.packaging.php_conffiles,
            **self.packaging.php_ucf,
            f"{php}/mods-available/posix.ini": POSIX_MD5,
        }
        return {
            path: digest
            for path, digest in packaged.items()
            if path.startswith(("/etc/nginx/", f"{php}/fpm/", f"{php}/mods-available/"))
            and path not in self.removed
        }

    def _tree_files(self) -> dict[str, str]:
        """Every regular file under the trees, with bytes for those preparation may read."""
        files = dict.fromkeys(self._defaults(), "")
        for identifier, (names, ipv6, _) in self.sites.items():
            files[self.site_paths(identifier).source] = render_site(identifier, names, ipv6=ipv6)
        for identifier in self.pools:
            files[self.site_paths(identifier).pool] = render_pool(identifier)
        files.update(self.files)
        return files

    def _tree_links(self) -> dict[str, str]:
        php = f"/etc/php/{self.php}"
        module = self.packaging.php_module
        links = {
            "/etc/nginx/sites-enabled/default": "/etc/nginx/sites-available/default",
            f"{php}/fpm/conf.d/10-{module}.ini": f"{php}/mods-available/{module}.ini",
            f"{php}/fpm/conf.d/20-posix.ini": f"{php}/mods-available/posix.ini",
        }
        for identifier, (_, _, enabled) in self.sites.items():
            paths = self.site_paths(identifier)
            if enabled:
                links[paths.link] = paths.source
        links.update(self.links)
        return {path: target for path, target in links.items() if path not in self.removed}

    def _listing(self) -> str:
        files, links = self._tree_files(), self._tree_links()
        php = f"/etc/php/{self.php}"
        roots = ("/etc/nginx", f"{php}/fpm", f"{php}/mods-available")
        directories = set(roots) | {
            "/etc/nginx/sites-available",
            "/etc/nginx/sites-enabled",
            "/etc/nginx/conf.d",
            "/etc/nginx/snippets",
            f"{php}/fpm/conf.d",
            f"{php}/fpm/pool.d",
        }
        directories |= {path.rsplit("/", 1)[0] for path in (*files, *links)}
        lines = [
            f"d\t755\t0\t0\t2\t4096\t{self._device(path)}\t{path}\t" for path in sorted(directories)
        ]
        for path, text in sorted(files.items()):
            node = self.paths.get(path)
            mode, uid, gid = (node.mode, node.uid, node.gid) if node else (0o644, 0, 0)
            lines.append(
                f"f\t{mode:o}\t{uid}\t{gid}\t1\t{len(text)}\t{self._device(path)}\t{path}\t"
            )
        lines += [
            f"l\t777\t0\t0\t1\t30\t{self._device(path)}\t{path}\t{target}"
            for path, target in sorted(links.items())
        ]
        return "\n".join(lines) + "\n"

    def _device(self, path: str) -> int:
        return 2050 if path in self.mounts else 2049

    def _conffiles(self) -> str:
        packaging, php = self.packaging, self.php
        nginx = "".join(f" {path} {md5}\n" for path, md5 in packaging.nginx_conffiles.items())
        fpm = "".join(f" {path} {md5}\n" for path, md5 in packaging.php_conffiles.items())
        return f"nginx-common\n{nginx}php{php}-fpm\n{fpm}php{php}-cli\n\nphp{php}-common\n\n"

    # Site paths ------------------------------------------------------------------------

    def _states(self, script: str) -> str:
        quoted = script.split(" for p in ", 1)[1].split("; do ", 1)[0]
        lines = []
        for path in shlex.split(quoted):
            node = self._node(path)
            if node is None:
                lines.append(f"absent {path}")
                continue
            kinds = {"d": 0o040000, "f": 0o100000, "l": 0o120000, "s": 0o140000}
            raw = kinds[node.kind] | node.mode
            lines.append(
                f"{raw:x} {node.uid} {node.gid} {node.links} {node.owner} {node.group} {path}"
            )
        return "\n".join(lines) + "\n"

    def _node(self, path: str) -> Node | None:
        if path in self.paths:
            return self.paths[path]
        if path == "/run/php":
            return Node("d", 0o755, 33, 33, "www-data", "www-data")
        if path in {"/", "/var", "/var/www", "/etc", "/etc/php"} or path.startswith(
            ("/etc/nginx", f"/etc/php/{self.php}")
        ):
            files, links = self._tree_files(), self._tree_links()
            if path in files:
                return Node("f", 0o644, 0, 0, "root", "root")
            if path in links:
                return Node("l", 0o777, 0, 0, "root", "root", links[path])
            directory = path in {"/", "/var", "/var/www", "/etc", "/etc/php"} or any(
                other.startswith(f"{path}/") for other in (*files, *links)
            )
            if directory or path in {f"/etc/php/{self.php}/fpm/pool.d", "/etc/nginx/sites-enabled"}:
                return Node(*_ROOT_DIRECTORY)
        return None

    def _state(self) -> object:
        return (
            sorted(self.sites.items()),
            sorted(self.pools),
            sorted(self.files.items()),
            sorted(self.changed),
            sorted(self.links.items()),
            sorted(self.removed),
            sorted(self.paths.items()),
            sorted(self.accounts.items()),
            self.listeners,
            sorted(self.sockets),
            self.login_defs,
            self.useradd,
            self.nsswitch,
        )

    def add_site(
        self,
        identifier: str,
        names: tuple[str, ...],
        *,
        uid: int = 1003,
        complete: bool = True,
    ) -> None:
        """A site another controller or an administrator created by the convention."""
        paths = self.site_paths(identifier)
        user = paths.user
        self.sites[identifier] = (names, True, True)
        self.pools.add(identifier)
        if not complete:
            return
        self.accounts[user] = (uid, uid)
        self.paths[paths.boundary] = Node(*_ROOT_DIRECTORY)
        self.paths[paths.public] = Node("d", 0o750, uid, 33, user, "www-data")
        self.paths[paths.private] = Node("d", 0o700, uid, uid, user, user)
        self.paths[paths.socket] = Node("s", 0o600, 33, 33, "www-data", "www-data")
        self.sockets.add(paths.socket)


def _argv(command: str) -> list[str] | None:
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    if argv[:2] == [native.SHELL, "-c"] and len(argv) == 3:
        return argv
    if argv[:1] == [native.HEAD] and len(argv) == 5:
        return argv
    return None


def _md5(text: str, path: str, server: SiteServer) -> str:
    defaults = server._defaults()
    if path in defaults and path not in server.files:
        return "0" * 32 if path in server.changed else defaults[path]
    return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()


SITE_PERMISSIONS = ("view_server", "view_siteplan", "prepare_siteplan")


class SiteTestCase(PreparationTestCase):
    """Site preparation through requests and the worker, against a simulated server."""

    packaging: ClassVar[Packaging] = NOBLE_PACKAGING
    site: SiteServer

    @override
    def setUp(self) -> None:
        super().setUp()
        self.site = SiteServer(self.packaging)

    @override
    def assert_read_only(self) -> None:
        for command in self.remote.commands:
            self.assertTrue(
                READ_ONLY.fullmatch(command)
                or PREPARATION_READ_ONLY.fullmatch(command)
                or site_read_only(command),
                f"Not a read-only command: {command}",
            )

    def prepare_site(
        self,
        identifier: str = "shop",
        names: str = "shop.example.com www.shop.example.com",
        *,
        perms: tuple[str, ...] = SITE_PERMISSIONS,
    ) -> HttpResponseBase:
        """Request a site preparation as an operator with ``perms``, then run the worker."""
        self.sign_in_with(*perms)
        self.site.answer(self.remote)
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/prepare/",
            {"identifier": identifier, "names": names},
        )
        self.run_worker()
        return response
