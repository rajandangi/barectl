"""The challenge route's apply payload and verification (docs/tls.md#applying).

The payload replaces the site file in place: it keeps the preimage as a root-only backup,
checks the candidate with nginx -t before reloading, and restores the preimage when the
candidate is refused (docs/adr/0012-publish-site-files-without-replacing-them.md#replacement).
"""

import hashlib
import re
import shlex
from dataclasses import dataclass

from bootstrap import native as bootstrap_native
from sites import native as site_native
from sites.convention import (
    BACKUP_DIRECTORY,
    CHALLENGE_ROOT,
    PROBE_TOKEN,
    SITES_AVAILABLE,
    WEB_USER,
    SitePaths,
    Stage,
    render_site,
)

_NAME = re.compile(r"[a-z0-9][a-z0-9.-]{0,45}")
_DIGEST = re.compile(r"[0-9a-f]{64}")


class Exit:
    """docs/tls.md#recovering-a-partial-challenge-route: boundaries after admission."""

    DRIFT = bootstrap_native.Exit.DRIFT
    DIRECTORIES = 56
    REPLACEMENT = 57
    RESTORED = 58
    NOT_RESTORED = 59
    NGINX_RELOAD = 90
    NOT_SERVING = 91
    PROBE_LEFT = 92


def probe_content(token: str) -> str:
    if not PROBE_TOKEN.fullmatch(token):
        raise ValueError("Not a valid probe token.")
    return f"barectl-challenge {token}\n"


def status_client(php: str) -> str:
    """``s ADDRESS HOST PATH``: the status code of an HTTP/1.0 GET, a space, then its body.

    The PHP CLI is the site's prerequisite; ``-n`` ignores php.ini.
    """
    if not re.fullmatch(r"8\.[0-9]", php):
        raise ValueError("Not a PHP version.")
    return (
        "s(){ /usr/bin/php" + php + " -n -r '"
        "[$a,$h,$p]=array_slice($argv,1);$f=@fsockopen($a,80,$e,$s,5);if(!$f)exit(1);"
        "stream_set_timeout($f,5);"
        'fwrite($f,"GET $p HTTP/1.0\\r\\nHost: $h\\r\\nConnection: close\\r\\n\\r\\n");'
        "$r=stream_get_contents($f,8192);fclose($f);"
        'if(!preg_match("#^HTTP/1\\.[01] ([0-9]{3}) #",$r,$m))exit(2);'
        '$b=strpos($r,"\\r\\n\\r\\n");echo $m[1]," ",$b===false?"":substr($r,$b+4);'
        '\' "$1" "$2" "$3"; }'
    )


@dataclass(frozen=True)
class ChallengeChange:
    """What one reviewed challenge route changes, as the payload needs it."""

    paths: SitePaths
    names: tuple[str, ...]
    ipv6: bool
    token: str
    digest: str
    preimage: str
    content: str

    @property
    def preimage_sha256(self) -> str:
        return hashlib.sha256(self.preimage.encode()).hexdigest()

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.content.encode()).hexdigest()


def _check(change: ChallengeChange) -> None:
    """Every value the payload interpolates is the convention's, or it is refused."""
    if not _DIGEST.fullmatch(change.digest):
        raise ValueError("Not a valid digest.")
    if not change.names or not all(_NAME.fullmatch(name) for name in change.names):
        raise ValueError("Not valid names.")
    probe_content(change.token)
    identifier = change.paths.identifier
    php_version = change.paths.php if change.paths.revision == 4 else ""
    http = render_site(identifier, change.names, ipv6=change.ipv6, php_version=php_version)
    challenge = render_site(
        identifier, change.names, ipv6=change.ipv6, stage=Stage.CHALLENGE, php_version=php_version
    )
    if change.preimage != http or change.content != challenge:
        raise ValueError("The site file is not the convention's.")


def _lines(text: str) -> str:
    return " ".join(shlex.quote(line) for line in text.removesuffix("\n").split("\n"))


def challenge_steps(
    unit: str, boot_id: str, deadline: int, change: ChallengeChange
) -> list[site_native.Step]:
    """docs/tls.md#applying: each named fragment of the payload, in order."""
    _check(change)
    paths = change.paths
    suffix = unit.removeprefix(bootstrap_native.UNIT_PREFIX).removesuffix(".service")
    source, webroot = paths.source, paths.webroot
    backup = paths.backup(suffix)
    stage = f"{SITES_AVAILABLE}/.{paths.identifier}.conf.{suffix}"
    wellknown = f"{webroot}/.well-known"
    challenges = f"{wellknown}/acme-challenge"
    probe = paths.challenge_probe(change.token)
    body = probe_content(change.token).removesuffix("\n")
    uri = probe.removeprefix(webroot)
    addresses = "127.0.0.1 [::1]" if change.ipv6 else "127.0.0.1"
    names = " ".join(change.names)
    old, new = change.preimage_sha256, change.content_sha256
    sha = "sha256sum <{0} | cut -d' ' -f1"
    reviewed = site_native.site_digest(paths)
    return [
        site_native.Step(
            "admission", "; ".join(bootstrap_native.admission(unit, boot_id, deadline))
        ),
        site_native.Step(
            "helpers",
            "; ".join(
                (
                    "export PATH=/usr/sbin:/usr/bin; umask 077; set -C",
                    'm(){ [ "$(stat -c \'%F %U %G %a\' -- "$1")" = "$2" ]; }',
                    'f(){ [ ! -L "$1" ] && m "$1" "$2" && [ "$(stat -c %h -- "$1")" = 1 ]; }',
                    (
                        'a(){ for d in "$@"; do while :; do [ ! -L "$d" ] && '
                        "[ \"$(stat -c '%F %u' -- \"$d\")\" = 'directory 0' ] && "
                        "[ $((0$(stat -c '%a' -- \"$d\") & 022)) -eq 0 ] || return 1; "
                        '[ "$d" = / ] && break; d=$(dirname -- "$d"); done; done; }'
                    ),
                    (
                        f"r(){{ if [ -f {probe} ] && [ ! -L {probe} ] && "
                        f'[ "$({sha.format(probe)})" = '
                        f"{hashlib.sha256(probe_content(change.token).encode()).hexdigest()} ]; "
                        f"then rm -f -- {probe}; fi; rmdir -- {challenges} {wellknown} "
                        f"2>/dev/null; [ ! -e {probe} ] && [ ! -L {probe} ]; }}"
                    ),
                    f'x(){{ r || exit {Exit.PROBE_LEFT}; exit "$1"; }}',
                    status_client(paths.php),
                )
            ),
        ),
        site_native.Step(
            "revalidation",
            "; ".join(
                (
                    f'[ "$({reviewed} | cut -d" " -f1)" = {change.digest} ] || exit {Exit.DRIFT}',
                    (
                        f"f {source} 'regular file root root 644' && "
                        f'[ "$({sha.format(source)})" = {old} ] || exit {Exit.DRIFT}'
                    ),
                    (
                        f"for p in {webroot} {backup} {stage}; do "
                        f'[ ! -e "$p" ] && [ ! -L "$p" ] || exit {Exit.DRIFT}; done'
                    ),
                    f"a {SITES_AVAILABLE} /var/lib /var/backups || exit {Exit.DRIFT}",
                    (
                        f"for p in {CHALLENGE_ROOT}:755 {BACKUP_DIRECTORY}:700; do "
                        'd=${p%:*}; if [ -e "$d" ] || [ -L "$d" ]; then [ ! -L "$d" ] && '
                        f'm "$d" "directory root root ${{p#*:}}" || exit {Exit.DRIFT}; fi; done'
                    ),
                    (
                        f"[ -x /usr/bin/php{paths.php} ] && [ -x /usr/sbin/nginx ] "
                        f"|| exit {Exit.DRIFT}"
                    ),
                    f"b=$(s 127.0.0.1 {change.names[0]} / | head -c 3)",
                )
            ),
        ),
        site_native.Step(
            "directories",
            "; ".join(
                (
                    (
                        f"[ -d {CHALLENGE_ROOT} ] || mkdir -m 0755 -- {CHALLENGE_ROOT} "
                        f"|| x {Exit.DIRECTORIES}"
                    ),
                    (
                        f"mkdir -m 0750 -- {webroot} && chown root:{WEB_USER} {webroot} && "
                        f"m {webroot} 'directory root {WEB_USER} 750' || x {Exit.DIRECTORIES}"
                    ),
                    (
                        f"[ -d {BACKUP_DIRECTORY} ] || mkdir -m 0700 -- {BACKUP_DIRECTORY} "
                        f"|| x {Exit.DIRECTORIES}"
                    ),
                    f"a {CHALLENGE_ROOT} {BACKUP_DIRECTORY} || x {Exit.DIRECTORIES}",
                    (
                        f"cat -- {source} >{backup} && f {backup} 'regular file root root 600' "
                        f'&& [ "$({sha.format(backup)})" = {old} ] && '
                        f"sync -- {backup} {BACKUP_DIRECTORY} {webroot} {CHALLENGE_ROOT} "
                        f"|| x {Exit.DIRECTORIES}"
                    ),
                )
            ),
        ),
        site_native.Step(
            "replacement",
            "; ".join(
                (
                    (
                        f"printf '%s\\n' {_lines(change.content)} >{stage} && "
                        f"chmod 0644 {stage} && sync -- {stage} && "
                        f'[ "$({sha.format(stage)})" = {new} ] && a {SITES_AVAILABLE} && '
                        f"f {source} 'regular file root root 644' && "
                        f'[ "$({sha.format(source)})" = {old} ] && '
                        f"mv -T -- {stage} {source} && sync -- {SITES_AVAILABLE} "
                        f"|| {{ rm -f -- {stage}; x {Exit.REPLACEMENT}; }}"
                    ),
                )
            ),
        ),
        site_native.Step(
            "validation",
            (
                "if ! nginx -t -q; then "
                f'[ "$({sha.format(source)})" = {new} ] && cat -- {backup} >{stage} && '
                f"chmod 0644 {stage} && "
                f'[ "$({sha.format(stage)})" = {old} ] && mv -T -- {stage} {source} && '
                f"sync -- {SITES_AVAILABLE} && nginx -t -q && x {Exit.RESTORED}; "
                f"rm -f -- {stage}; x {Exit.NOT_RESTORED}; fi"
            ),
        ),
        site_native.Step("reload", f"systemctl reload nginx.service || x {Exit.NGINX_RELOAD}"),
        site_native.Step(
            "probe",
            (
                f"mkdir -m 0755 -- {wellknown} {challenges} && "
                f"printf '%s\\n' {shlex.quote(body)} >{probe} && chmod 0644 {probe} "
                f"|| x {Exit.NOT_SERVING}"
            ),
        ),
        site_native.Step(
            "serving",
            "; ".join(
                (
                    (
                        "i=0; while [ $i -lt 50 ]; do ok=1; "
                        f"for d in {addresses}; do for n in {names}; do "
                        f'[ "$(s "$d" "$n" {uri})" = {shlex.quote(f"200 {body}")} ] || ok=0; '
                        f'[ "$(s "$d" "$n" {uri}.php | head -c 3)" = 404 ] || ok=0; '
                        f'[ "$(s "$d" "$n" /.well-known/acme-challenge/ | head -c 3)" = 404 ] '
                        "|| ok=0; done; done; "
                        f'[ "$(s 127.0.0.1 {change.names[0]} / | head -c 3)" = "$b" ] || ok=0; '
                        '[ "$ok" -eq 1 ] && break; sleep 0.2; i=$((i + 1)); done'
                    ),
                    f'[ "$ok" -eq 1 ] || x {Exit.NOT_SERVING}',
                )
            ),
        ),
        site_native.Step(
            "probe removal",
            f"r || exit {Exit.PROBE_LEFT}; echo 'barectl-tls: challenge route verified'; exit 0",
        ),
    ]


def challenge_payload(unit: str, boot_id: str, deadline: int, change: ChallengeChange) -> str:
    return "; ".join(step.text for step in challenge_steps(unit, boot_id, deadline, change))


def challenge_state(paths: SitePaths, token: str, backup: str) -> list[str]:
    """docs/tls.md#applying: the route's native state after a run, as root."""
    probe = paths.challenge_probe(token)
    checked = (
        paths.source,
        paths.link,
        CHALLENGE_ROOT,
        paths.webroot,
        f"{paths.webroot}/.well-known",
        probe,
        BACKUP_DIRECTORY,
        backup,
    )
    quoted = " ".join(shlex.quote(path) for path in checked)
    return site_native.script(
        "; ".join(
            (
                "export LC_ALL=C PATH=/usr/sbin:/usr/bin",
                (
                    f"for p in {quoted}; do "
                    'if [ -e "$p" ] || [ -L "$p" ]; then '
                    "stat -c 'path %F|%U|%G|%a|%h|%n' -- \"$p\"; "
                    'else echo "absent $p"; fi; done'
                ),
                f'echo "target $(readlink -- {paths.link})"',
                (
                    f"for p in {paths.source} {shlex.quote(backup)}; do "
                    '[ -f "$p" ] && echo "sha $(sha256sum <"$p" | cut -d" " -f1) $p"; done'
                ),
                (
                    'echo "unit $(systemctl show -p ActiveState --value nginx.service)/'
                    '$(systemctl show -p SubState --value nginx.service)"'
                ),
                "nginx -t -q 2>/dev/null && echo 'nginx valid' || echo 'nginx invalid'",
            )
        )
    )
