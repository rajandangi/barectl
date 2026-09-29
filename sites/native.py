"""The fixed native commands of site preparation and its draft apply payload.

docs/ssh-connections.md#site-preparation. Every read that feeds the revalidation digest runs
as root, so the digest preparation records is the one the payload recomputes as root.
"""

import hashlib
import re
import shlex
from dataclasses import dataclass
from typing import Final

from bootstrap import native as bootstrap_native

from .convention import NOLOGIN, SITES_ENABLED, WEB_USER, SitePaths, probe_marker

SHELL: Final = "/usr/bin/sh"
HEAD: Final = "/usr/bin/head"
# docs/ssh-connections.md#site-preparation: the largest file preparation reads to recognize.
MAX_FILE: Final = 8192
MAX_TREE_ENTRIES: Final = 2000
MAX_CANDIDATE_FILES: Final = 200
_ENV = "export LC_ALL=C PATH=/usr/sbin:/usr/bin"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[a-z0-9][a-z0-9.-]{0,45}")
_ACCOUNT_FILES = (
    "sha256sum /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/subuid /etc/subgid 2>&1 "
    "| sha256sum"
)
_CONVENTION_FILE = re.compile(
    r"/etc/(nginx/sites-available|php/8\.[0-9]/fpm/pool\.d)/[a-z][a-z0-9]{2,23}\.conf"
)


def _trees(php: str) -> str:
    return f"/etc/nginx /etc/php/{php}/fpm /etc/php/{php}/mods-available"


def _ancestors(paths: SitePaths) -> tuple[str, ...]:
    php = f"/etc/php/{paths.php}"
    return (
        "/",
        "/var",
        "/var/www",
        "/etc",
        "/etc/nginx",
        "/etc/nginx/sites-available",
        SITES_ENABLED,
        "/etc/php",
        php,
        f"{php}/fpm",
        paths.pool_directory,
        "/run/php",
    )


def ancestors(paths: SitePaths) -> tuple[str, ...]:
    """The directories above the site's resources that must be root's and safe."""
    return _ancestors(paths)


def site_digest(paths: SitePaths) -> str:
    """docs/ssh-connections.md#the-revalidation-digest"""
    php, user = paths.php, paths.user
    trees = _trees(php)
    unit = paths.fpm_service
    state = "'${Package} ${Version} ${db:Status-Abbrev}\\n'"
    parts = [
        _ENV,
        f"find {trees} -xdev -printf '%y %m %U %G %n %p %l\\n'",
        "find /var/www -xdev -maxdepth 2 -printf '%y %m %U %G %n %p %l\\n'",
        f"find {trees} -xdev -type f -exec sha256sum -- {{}} +",
        (
            "sha256sum /etc/nginx/modules-enabled/* /etc/passwd /etc/group /etc/subuid "
            "/etc/subgid /etc/login.defs /etc/default/useradd /etc/nsswitch.conf"
        ),
        f"stat -c '%f %u %g %h %d %i %n' {' '.join(_ancestors(paths))}",
        (
            "ls -1a /etc/letsencrypt/live /etc/letsencrypt/archive /etc/letsencrypt/renewal "
            "/var/lib/letsencrypt"
        ),
        f"getent passwd {user} {WEB_USER}",
        f"getent group {user} {WEB_USER}",
        (
            "systemctl show -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState "
            f"-p FragmentPath -p DropInPaths nginx.service {unit}"
        ),
        f"dpkg-query -W -f={state} nginx nginx-common php{php}-fpm php{php}-cli php{php}-common",
        "ss -Hltn sport = :80 | awk '{print $4}'",
        f"ss -Hlx src {paths.socket}",
    ]
    return "{ " + "; ".join(parts) + "; } 2>/dev/null | LC_ALL=C sort | sha256sum"


def script(text: str) -> list[str]:
    return [SHELL, "-c", text]


def tree_listing(php: str) -> list[str]:
    return script(
        f"{_ENV}; find {_trees(php)} -xdev -printf '%y\\t%m\\t%U\\t%G\\t%n\\t%s\\t%p\\t%l\\n'"
    )


def tree_digests(php: str) -> list[str]:
    return script(f"{_ENV}; find {_trees(php)} -xdev -type f -exec md5sum -- {{}} +")


def path_states(paths: SitePaths, token_path: str) -> list[str]:
    """Each ancestor's own metadata, then whether each target exists and its metadata.

    ``stat`` describes a symbolic link itself; a line ``absent <path>`` is a path that
    neither ``test -e`` nor ``test -L`` finds.
    """
    targets = (
        paths.boundary,
        paths.public,
        paths.private,
        paths.placeholder,
        token_path,
        paths.source,
        paths.link,
        paths.pool,
        paths.socket,
        *paths.certificates,
    )
    quoted = " ".join(shlex.quote(path) for path in (*_ancestors(paths), *targets))
    return script(
        f"{_ENV}; for p in {quoted}; do "
        'if [ -e "$p" ] || [ -L "$p" ]; then '
        'stat -c \'%f %u %g %h %U %G %n\' -- "$p" || echo "unreadable $p"; '
        'else echo "absent $p"; fi; done'
    )


def listeners() -> list[str]:
    return script(f"{_ENV}; ss -Hltnp sport = :80")


def password_lock(user: str) -> list[str]:
    """Only the first character of the site user's password field, never the hash."""
    return script(f"{_ENV}; getent shadow {user} | cut -d: -f2 | cut -c1")


def content(path: str) -> list[str]:
    if not _CONVENTION_FILE.fullmatch(path):
        raise ValueError("Not a convention file.")
    return [HEAD, "-c", str(MAX_FILE + 1), "--", path]


# The draft apply payload ----------------------------------------------------------------


class Exit:
    """docs/sites.md#applying (not offered yet): the payload's boundaries after admission."""

    DRIFT = bootstrap_native.Exit.DRIFT
    ACCOUNT_BUSY = 31
    ACCOUNT = 40
    ACCOUNT_MISMATCH = 41
    DIRECTORIES = 42
    CONTENT = 43
    POOL = 44
    POOL_WITHDRAWN = 45
    POOL_INVALID = 46
    FPM_RELOAD = 47
    SOCKET = 48
    SITE_FILE = 49
    SITE_LINK = 50
    LINK_WITHDRAWN = 51
    NGINX_INVALID = 52
    NGINX_RELOAD = 53
    NOT_SERVING = 54
    PROBE_LEFT = 55


@dataclass(frozen=True)
class GeneratedFile:
    directory: str
    name: str
    owner: str
    group: str
    mode: str
    text: str

    @property
    def path(self) -> str:
        return f"{self.directory}/{self.name}"

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.text.encode()).hexdigest()


@dataclass(frozen=True)
class Step:
    name: str
    text: str


@dataclass(frozen=True)
class SiteChange:
    """What one reviewed site creation publishes, as the payload needs it."""

    paths: SitePaths
    names: tuple[str, ...]
    ipv6: bool
    token: str
    digest: str
    uid_range: tuple[int, int]
    gid_range: tuple[int, int]
    placeholder: GeneratedFile
    probe: GeneratedFile
    pool: GeneratedFile
    site: GeneratedFile


def _publish(file: GeneratedFile, code: int) -> str:
    """The file's exact lines, published by the payload's ``w`` helper."""
    lines = " ".join(shlex.quote(line) for line in file.text.removesuffix("\n").split("\n"))
    return (
        f"printf '%s\\n' {lines} | w {file.directory} {file.name} {file.owner}:{file.group} "
        f"{file.mode} {file.sha256} || x {code}"
    )


def _writer(suffix: str) -> str:
    """Stage beside the destination, check its bytes, then link it into place, which fails
    rather than replacing anything that appeared since revalidation."""
    return (
        f'w(){{ s="$1/.$2.{suffix}"; cat >"$s" && chown "$3" "$s" && chmod "$4" "$s" '
        '&& sync -- "$s" && [ "$(sha256sum <"$s" | cut -d\' \' -f1)" = "$5" ] '
        '&& a "$1" && [ ! -e "$1/$2" ] && [ ! -L "$1/$2" ] && ln -T -- "$s" "$1/$2" '
        '&& rm -f -- "$s" && sync -- "$1"; }'
    )


def _check_change(change: SiteChange) -> None:
    if not _DIGEST.fullmatch(change.digest):
        raise ValueError("Not a valid digest.")
    if not change.names or not all(_NAME.fullmatch(name) for name in change.names):
        raise ValueError("Not valid names.")
    low, high = change.uid_range
    glow, ghigh = change.gid_range
    if not (0 < low <= high < 2**31 and 0 < glow <= ghigh < 2**31):
        raise ValueError("Not a valid ID range.")


def site_steps(unit: str, boot_id: str, deadline: int, change: SiteChange) -> list[Step]:
    """docs/sites.md#applying: each named fragment of the draft payload, in order."""
    _check_change(change)
    paths = change.paths
    user, php = paths.user, paths.php
    probe = change.probe.path
    suffix = unit.removeprefix(bootstrap_native.UNIT_PREFIX).removesuffix(".service")
    low, high = change.uid_range
    glow, ghigh = change.gid_range
    home = paths.boundary
    reviewed = site_digest(paths)
    client = (
        "k(){ /usr/bin/php" + php + " -n -r '"
        "[$a,$h,$p]=array_slice($argv,1);$f=@fsockopen($a,80,$e,$s,5);if(!$f)exit(1);"
        "stream_set_timeout($f,5);"
        'fwrite($f,"GET $p HTTP/1.0\\r\\nHost: $h\\r\\nConnection: close\\r\\n\\r\\n");'
        "$r=stream_get_contents($f,8192);fclose($f);"
        'if(!preg_match("#^HTTP/1\\.[01] 200 #",$r))exit(2);'
        '$b=strpos($r,"\\r\\n\\r\\n");echo $b===false?"":substr($r,$b+4);'
        '\' "$1" "$2" "$3"; }'
    )
    addresses = "127.0.0.1 [::1]" if change.ipv6 else "127.0.0.1"
    ready = f"Site {paths.identifier} is ready."
    marker = probe_marker(change.token)
    return [
        Step(
            "admission",
            "; ".join(bootstrap_native.admission(unit, boot_id, deadline)),
        ),
        Step(
            "helpers",
            "; ".join(
                (
                    "export PATH=/usr/sbin:/usr/bin; umask 077; set -C",
                    'm(){ [ "$(stat -c \'%F %U %G %a\' -- "$1")" = "$2" ]; }',
                    (
                        'a(){ for d in "$@"; do [ ! -L "$d" ] && '
                        "[ \"$(stat -c '%F %u %g' -- \"$d\")\" = 'directory 0 0' ] && "
                        "[ $((0$(stat -c '%a' -- \"$d\") & 022)) -eq 0 ] || return 1; done; }"
                    ),
                    (
                        f"r(){{ if [ -f {probe} ] && [ ! -L {probe} ] && "
                        f"[ \"$(sha256sum <{probe} | cut -d' ' -f1)\" = {change.probe.sha256} ]; "
                        f"then rm -f -- {probe}; fi; [ ! -e {probe} ] && [ ! -L {probe} ]; }}"
                    ),
                    'x(){ r; exit "$1"; }',
                    _writer(suffix),
                    client,
                )
            ),
        ),
        Step(
            "revalidation",
            "; ".join(
                (
                    f'[ "$({reviewed} | cut -d" " -f1)" = {change.digest} ] || exit {Exit.DRIFT}',
                    (
                        f"for p in {paths.boundary} {paths.source} {paths.link} {paths.pool} "
                        f"{paths.socket}; do "
                        f'[ ! -e "$p" ] && [ ! -L "$p" ] || exit {Exit.DRIFT}; done'
                    ),
                    f"a {' '.join(_ancestors(paths)[:-1])} || exit {Exit.DRIFT}",
                    (
                        f"for b in /usr/sbin/useradd /usr/sbin/nginx /usr/sbin/php-fpm{php} "
                        f'/usr/bin/php{php}; do [ -x "$b" ] || exit {Exit.DRIFT}; done'
                    ),
                )
            ),
        ),
        Step(
            "account",
            "; ".join(
                (
                    f"b=$({_ACCOUNT_FILES})",
                    (
                        "if ! useradd --user-group --no-create-home "
                        f"--home-dir {home} --shell /usr/sbin/nologin --no-log-init {user}; then "
                        f'c=$({_ACCOUNT_FILES}); [ "$b" = "$c" ] && '
                        f"! getent passwd {user} >/dev/null && ! getent group {user} >/dev/null "
                        f"&& exit {Exit.ACCOUNT_BUSY}; exit {Exit.ACCOUNT}; fi"
                    ),
                    f"u=$(id -u {user}) && g=$(id -g {user}) || x {Exit.ACCOUNT_MISMATCH}",
                    (
                        f'[ "$(getent passwd {user})" = "{user}:x:$u:$g::{home}:{NOLOGIN}" ]'
                        f' && [ "$(getent group {user})" = "{user}:x:$g:" ]'
                        f' && [ "$(id -G {user})" = "$g" ]'
                        f" && [ \"$(getent shadow {user} | cut -d: -f2 | cut -c1)\" = '!' ]"
                        f' && [ "$u" -ge {low} ] && [ "$u" -le {high} ]'
                        f' && [ "$g" -ge {glow} ] && [ "$g" -le {ghigh} ]'
                        f" || x {Exit.ACCOUNT_MISMATCH}"
                    ),
                    f'echo "barectl-site: account {user} $u $g"',
                )
            ),
        ),
        Step(
            "directories",
            "; ".join(
                (
                    f"mkdir -m 0755 -- {home} || x {Exit.DIRECTORIES}",
                    (
                        f"mkdir -m 0750 -- {paths.public} && chown root:{WEB_USER} {paths.public} "
                        f"|| x {Exit.DIRECTORIES}"
                    ),
                    (
                        f'mkdir -m 0700 -- {paths.private} && chown "$u:$g" {paths.private} '
                        f"|| x {Exit.DIRECTORIES}"
                    ),
                    (
                        f"m {home} 'directory root root 755' && "
                        f"m {paths.private} 'directory {user} {user} 700' && "
                        f"sync -- {home} {paths.public} {paths.private} || x {Exit.DIRECTORIES}"
                    ),
                )
            ),
        ),
        Step("placeholder", _publish(change.placeholder, Exit.CONTENT)),
        Step("probe", _publish(change.probe, Exit.CONTENT)),
        Step(
            "document root",
            f"chown {user}:{WEB_USER} {paths.public} && "
            f"m {paths.public} 'directory {user} {WEB_USER} 750' || x {Exit.CONTENT}",
        ),
        Step("pool", _publish(change.pool, Exit.POOL)),
        Step(
            "pool validation",
            (
                f"if ! php-fpm{php} -t >/dev/null 2>&1; then "
                f"m {paths.pool} 'regular file root root 644' && "
                f"[ \"$(sha256sum <{paths.pool} | cut -d' ' -f1)\" = {change.pool.sha256} ] && "
                f"rm -f -- {paths.pool} && php-fpm{php} -t >/dev/null 2>&1 "
                f"&& x {Exit.POOL_WITHDRAWN}; x {Exit.POOL_INVALID}; fi"
            ),
        ),
        Step(
            "pool reload",
            "; ".join(
                (
                    f"systemctl reload {paths.fpm_service} || x {Exit.FPM_RELOAD}",
                    (
                        f"i=0; while [ $i -lt 50 ]; do [ -S {paths.socket} ] && "
                        f"m {paths.socket} 'socket {WEB_USER} {WEB_USER} 600' && "
                        f"ss -Hlx src {paths.socket} | grep -q . && break; "
                        "sleep 0.2; i=$((i + 1)); done"
                    ),
                    f"[ $i -lt 50 ] || x {Exit.SOCKET}",
                )
            ),
        ),
        Step("site file", _publish(change.site, Exit.SITE_FILE)),
        Step(
            "site link",
            (
                f"a {SITES_ENABLED} && [ ! -e {paths.link} ] && [ ! -L {paths.link} ] && "
                f"ln -sT -- {paths.source} {paths.link} && sync -- {SITES_ENABLED} "
                f"|| x {Exit.SITE_LINK}"
            ),
        ),
        Step(
            "site validation",
            (
                "if ! nginx -t -q; then "
                f'[ "$(readlink -- {paths.link})" = {paths.source} ] && '
                f"[ \"$(stat -c '%U' -- {paths.link})\" = root ] && rm -f -- {paths.link} && "
                f"nginx -t -q && x {Exit.LINK_WITHDRAWN}; x {Exit.NGINX_INVALID}; fi"
            ),
        ),
        Step("site reload", f"systemctl reload nginx.service || x {Exit.NGINX_RELOAD}"),
        Step(
            "serving",
            "; ".join(
                (
                    (
                        "i=0; while [ $i -lt 50 ]; do ok=1; "
                        f"for d in {addresses}; do for n in {' '.join(change.names)}; do "
                        f'k "$d" "$n" / | grep -qxF {shlex.quote(ready)} || ok=0; done; '
                        f'k "$d" unknown-{change.token}.invalid / | '
                        f"grep -qxF {shlex.quote(ready)} && ok=0; done; "
                        f'[ "$(k 127.0.0.1 {change.names[0]} /{change.probe.name})" = '
                        f'"{marker}$u $g" ] || ok=0; '
                        '[ "$ok" -eq 1 ] && break; sleep 0.2; i=$((i + 1)); done'
                    ),
                    (
                        f'if [ "$ok" -ne 1 ]; then r || exit {Exit.PROBE_LEFT}; '
                        f"exit {Exit.NOT_SERVING}; fi"
                    ),
                )
            ),
        ),
        Step(
            "probe removal",
            f"r || exit {Exit.PROBE_LEFT}; echo 'barectl-site: verified'; exit 0",
        ),
    ]


def site_payload(unit: str, boot_id: str, deadline: int, change: SiteChange) -> str:
    return "; ".join(step.text for step in site_steps(unit, boot_id, deadline, change))
