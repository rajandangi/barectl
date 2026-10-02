"""The HTTPS activation's apply payload and verification (docs/tls.md#activation).

The payload publishes the shared default TLS rejection server, replaces the site file with
the reviewed HTTPS candidate while keeping the preimage as a root-only backup, verifies the
served certificate for every name, then replaces it with the reviewed redirect candidate and
verifies the redirect, the challenge route and the served certificate again. A refused
candidate is restored; a failed redirect leaves the verified HTTPS candidate in place.
"""

import hashlib
import re
import shlex
from dataclasses import dataclass

from bootstrap import native as bootstrap_native
from sites import native as site_native
from sites.convention import (
    BACKUP_DIRECTORY,
    SITES_AVAILABLE,
    TLS_CONF_DIRECTORY,
    TLS_DEFAULT_PATH,
    SitePaths,
    Stage,
    render_site,
    render_tls_default,
)

from . import issuance_native
from . import native as challenge_native

_NAME = re.compile(r"[a-z0-9][a-z0-9.-]{0,45}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
DEFAULT_DIRECTORY = TLS_CONF_DIRECTORY
DEFAULT_PATH = TLS_DEFAULT_PATH
DEFAULT_CONTENT = render_tls_default()


class Exit:
    """docs/tls.md#recovering-a-partial-activation: boundaries after admission."""

    DRIFT = bootstrap_native.Exit.DRIFT
    DIRECTORIES = 56
    DEFAULT = 57
    REPLACEMENT = 58
    RESTORED = 59
    NOT_RESTORED = 60
    NGINX_RELOAD = 90
    NOT_SERVING = 91
    REDIRECT = 92
    NOT_REDIRECTING = 93
    RESTORE_FAILED = 94


@dataclass(frozen=True)
class ActivationChange:
    """What one reviewed activation changes, as the payload needs it."""

    paths: SitePaths
    names: tuple[str, ...]
    ipv6: bool
    digest: str
    preimage: str
    https_content: str
    redirect_content: str
    fingerprint: str
    # The lineage read's digest, rechecked before anything is published.
    lineage_digest: str
    default_content: str
    default_exists: bool

    @property
    def redirect_only(self) -> bool:
        return self.preimage == self.https_content

    @property
    def preimage_sha256(self) -> str:
        return hashlib.sha256(self.preimage.encode()).hexdigest()

    @property
    def https_sha256(self) -> str:
        return hashlib.sha256(self.https_content.encode()).hexdigest()

    @property
    def redirect_sha256(self) -> str:
        return hashlib.sha256(self.redirect_content.encode()).hexdigest()

    @property
    def default_sha256(self) -> str:
        return hashlib.sha256(self.default_content.encode()).hexdigest()


def _check(change: ActivationChange) -> None:
    """Every value the payload interpolates is the convention's, or it is refused."""
    if (
        not _DIGEST.fullmatch(change.digest)
        or not _DIGEST.fullmatch(change.fingerprint)
        or not _DIGEST.fullmatch(change.lineage_digest)
    ):
        raise ValueError("Not a valid digest.")
    if not change.names or not all(_NAME.fullmatch(name) for name in change.names):
        raise ValueError("Not valid names.")
    if change.default_content != DEFAULT_CONTENT:
        raise ValueError("The default rejection server is not the convention's.")
    identifier = change.paths.identifier
    forms = {
        Stage.CHALLENGE: render_site(
            identifier, change.names, ipv6=change.ipv6, stage=Stage.CHALLENGE
        ),
        Stage.HTTPS: render_site(identifier, change.names, ipv6=change.ipv6, stage=Stage.HTTPS),
        Stage.REDIRECT: render_site(
            identifier, change.names, ipv6=change.ipv6, stage=Stage.REDIRECT
        ),
    }
    if change.preimage not in {forms[Stage.CHALLENGE], forms[Stage.HTTPS]}:
        raise ValueError("The site file is not the convention's.")
    if change.https_content != (change.preimage if change.redirect_only else forms[Stage.HTTPS]):
        raise ValueError("The HTTPS candidate is not the convention's.")
    if change.redirect_content != forms[Stage.REDIRECT]:
        raise ValueError("The redirect candidate is not the convention's.")


def _lines(text: str) -> str:
    return " ".join(shlex.quote(line) for line in text.removesuffix("\n").split("\n"))


def _served_check(names: tuple[str, ...], fingerprint: str) -> str:
    """The served certificate for every name must be the reviewed lineage's DER bytes.

    No ``-quiet``: it implies ``-ign_eof``, so s_client would wait for the server's
    keepalive close instead of finishing when nothing is sent. ``timeout`` bounds a stalled
    handshake.
    """
    return (
        "t(){ for n in "
        + " ".join(names)
        + "; do f=$(timeout 5 openssl s_client -connect 127.0.0.1:443 "
        '-servername "$n" </dev/null 2>/dev/null | openssl x509 -outform DER 2>/dev/null '
        '| sha256sum | cut -d" " -f1); [ "$f" = ' + fingerprint + " ] || return 1; done; }"
    )


def _sni_served() -> str:
    """Whether an unknown SNI still receives a certificate at all (it must not)."""
    return (
        "u(){ timeout 5 openssl s_client -connect 127.0.0.1:443 </dev/null 2>/dev/null "
        "| openssl x509 -noout 2>/dev/null; }"
    )


def _host_served(placeholder: str) -> str:
    """Whether a Host different from valid SNI serves the site's placeholder (it must not)."""
    return (
        "h(){ printf 'GET / HTTP/1.0\\r\\nHost: barectl-unmatched.invalid\\r\\n\\r\\n' "
        '| timeout 5 openssl s_client -quiet -connect 127.0.0.1:443 -servername "$1" '
        "2>/dev/null | grep -qiF " + shlex.quote(placeholder) + "; }"
    )


def activation_steps(
    unit: str, boot_id: str, deadline: int, change: ActivationChange
) -> list[site_native.Step]:
    """docs/tls.md#activation: each named fragment of the payload, in order."""
    _check(change)
    paths = change.paths
    suffix = unit.removeprefix(bootstrap_native.UNIT_PREFIX).removesuffix(".service")
    source = paths.source
    backup = paths.backup(suffix)
    stage = f"{SITES_AVAILABLE}/.{paths.identifier}.conf.{suffix}"
    default_stage = f"{DEFAULT_DIRECTORY}/.{paths.identifier}.tls-default.{suffix}"
    reviewed = site_native.site_digest(paths)
    sha = "sha256sum <{0} | cut -d' ' -f1"
    old, https, redirect = (
        change.preimage_sha256,
        change.https_sha256,
        change.redirect_sha256,
    )
    default = change.default_sha256
    placeholder = f"Site {paths.identifier} is ready."
    serve = _served_check(change.names, change.fingerprint)
    https_publish = (
        "true"
        if change.redirect_only
        else "; ".join(
            (
                (
                    f"printf '%s\\n' {_lines(change.https_content)} >{stage} && "
                    f"chmod 0644 {stage} && sync -- {stage} && "
                    f'[ "$({sha.format(stage)})" = {https} ] && a {SITES_AVAILABLE} && '
                    f"f {source} 'regular file root root 644' && "
                    f'[ "$({sha.format(source)})" = {old} ] && '
                    f"mv -T -- {stage} {source} && sync -- {SITES_AVAILABLE} "
                    f"|| {{ rm -f -- {stage}; x {Exit.REPLACEMENT}; }}"
                ),
                (
                    "if ! nginx -t -q; then "
                    f'[ "$({sha.format(source)})" = {https} ] && '
                    f"cat -- {backup} >{stage} && chmod 0644 {stage} && "
                    f'[ "$({sha.format(stage)})" = {old} ] && mv -T -- {stage} {source} && '
                    f"sync -- {SITES_AVAILABLE} && nginx -t -q && x {Exit.RESTORED}; "
                    f"rm -f -- {stage}; x {Exit.NOT_RESTORED}; fi"
                ),
                f"systemctl reload nginx.service || x {Exit.NGINX_RELOAD}",
            )
        )
    )
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
                    'x(){ exit "$1"; }',
                    challenge_native.status_client(paths.php),
                    serve,
                    _sni_served(),
                    _host_served(placeholder),
                )
            ),
        ),
        site_native.Step(
            "revalidation",
            "; ".join(
                (
                    (
                        f'[ "$({reviewed} | cut -d" " -f1)" = {change.digest} ] '
                        f"|| {{ echo 'barectl-tls: drift: site'; exit {Exit.DRIFT}; }}"
                    ),
                    (
                        f"f {source} 'regular file root root 644' && "
                        f'[ "$({sha.format(source)})" = {old} ] || exit {Exit.DRIFT}'
                    ),
                    (
                        f"for p in {stage} {default_stage} {backup}; do "
                        f'[ ! -e "$p" ] && [ ! -L "$p" ] || exit {Exit.DRIFT}; done'
                    ),
                    (
                        f"if [ -e {DEFAULT_PATH} ] || [ -L {DEFAULT_PATH} ]; then "
                        f"f {DEFAULT_PATH} 'regular file root root 644' && "
                        f'[ "$({sha.format(DEFAULT_PATH)})" = {default} ] '
                        f"|| exit {Exit.DRIFT}; fi"
                    ),
                    (
                        f'[ "$({{ {issuance_native.lineage_text(change.paths.identifier)}; }} '
                        f'2>&1 | sha256sum | cut -d" " -f1)" = {change.lineage_digest} ] '
                        f"|| {{ echo 'barectl-tls: drift: lineage'; exit {Exit.DRIFT}; }}"
                    ),
                    f"a {SITES_AVAILABLE} {DEFAULT_DIRECTORY} /var/backups || exit {Exit.DRIFT}",
                    (
                        f"[ -x /usr/bin/php{paths.php} ] && [ -x /usr/sbin/nginx ] "
                        f"|| exit {Exit.DRIFT}"
                    ),
                    f"nginx -t -q || exit {Exit.DRIFT}",
                )
            ),
        ),
        site_native.Step(
            "default",
            (
                f"if [ ! -e {DEFAULT_PATH} ] && [ ! -L {DEFAULT_PATH} ]; then "
                f"printf '%s\\n' {_lines(change.default_content)} >{default_stage} && "
                f"chmod 0644 {default_stage} && sync -- {default_stage} && "
                f'[ "$({sha.format(default_stage)})" = {default} ] && '
                f"a {DEFAULT_DIRECTORY} && mv -T -- {default_stage} {DEFAULT_PATH} && "
                f"sync -- {DEFAULT_DIRECTORY} || {{ rm -f -- {default_stage}; "
                f"x {Exit.DEFAULT}; }}; "
                f"fi; "
                f"f {DEFAULT_PATH} 'regular file root root 644' && "
                f'[ "$({sha.format(DEFAULT_PATH)})" = {default} ] || x {Exit.DEFAULT}'
            ),
        ),
        site_native.Step(
            "directories",
            "; ".join(
                (
                    (
                        f"[ -d {BACKUP_DIRECTORY} ] || mkdir -m 0700 -- {BACKUP_DIRECTORY} "
                        f"|| x {Exit.DIRECTORIES}"
                    ),
                    (
                        f"cat -- {source} >{backup} && f {backup} 'regular file root root 600' "
                        f'&& [ "$({sha.format(backup)})" = {old} ] && '
                        f"sync -- {backup} {BACKUP_DIRECTORY} || x {Exit.DIRECTORIES}"
                    ),
                )
            ),
        ),
        site_native.Step("https", https_publish),
        site_native.Step(
            "https serving",
            "; ".join(
                (
                    (
                        "i=0; while [ $i -lt 50 ]; do t && ! u && break; "
                        "sleep 0.2; i=$((i + 1)); done"
                    ),
                    f"t || x {Exit.NOT_SERVING}",
                    f"! u || x {Exit.NOT_SERVING}",
                )
            ),
        ),
        site_native.Step(
            "redirect",
            "; ".join(
                (
                    (
                        f"printf '%s\\n' {_lines(change.redirect_content)} >{stage} && "
                        f"chmod 0644 {stage} && sync -- {stage} && "
                        f'[ "$({sha.format(stage)})" = {redirect} ] && '
                        f"a {SITES_AVAILABLE} && f {source} 'regular file root root 644' && "
                        f'[ "$({sha.format(source)})" = {https} ] && '
                        f"mv -T -- {stage} {source} && sync -- {SITES_AVAILABLE} "
                        f"|| {{ rm -f -- {stage}; x {Exit.REDIRECT}; }}"
                    ),
                    (
                        "if ! nginx -t -q; then "
                        f"printf '%s\\n' {_lines(change.https_content)} >{stage} && "
                        f"chmod 0644 {stage} && "
                        f'[ "$({sha.format(stage)})" = {https} ] && mv -T -- {stage} {source} '
                        f"&& sync -- {SITES_AVAILABLE} && nginx -t -q "
                        f"|| x {Exit.RESTORE_FAILED}; x {Exit.REDIRECT}; fi"
                    ),
                    f"systemctl reload nginx.service || x {Exit.REDIRECT}",
                )
            ),
        ),
        site_native.Step(
            "redirect serving",
            "; ".join(
                (
                    (
                        "i=0; while [ $i -lt 50 ]; do "
                        f"r=$(s 127.0.0.1 {change.names[0]} / | head -c 3); "
                        f"c=$(s 127.0.0.1 {change.names[0]} "
                        f"/.well-known/acme-challenge/missing | head -c 3); "
                        '[ "$r" = 301 ] && [ "$c" = 404 ] && t && break; '
                        "sleep 0.2; i=$((i + 1)); done"
                    ),
                    (
                        f'[ "$(s 127.0.0.1 {change.names[0]} / | head -c 3)" = 301 ] '
                        f"|| x {Exit.NOT_REDIRECTING}"
                    ),
                    (
                        f'[ "$(s 127.0.0.1 {change.names[0]} '
                        f'/.well-known/acme-challenge/missing | head -c 3)" = 404 ] '
                        f"|| x {Exit.NOT_REDIRECTING}"
                    ),
                    f"t || x {Exit.NOT_REDIRECTING}",
                    f"! h {change.names[0]} || x {Exit.NOT_REDIRECTING}",
                    f"! u || x {Exit.NOT_SERVING}",
                )
            ),
        ),
        site_native.Step(
            "finish",
            "echo 'barectl-tls: HTTPS activation verified'; exit 0",
        ),
    ]


def activation_payload(unit: str, boot_id: str, deadline: int, change: ActivationChange) -> str:
    return "; ".join(step.text for step in activation_steps(unit, boot_id, deadline, change))


def config_argv() -> list[str]:
    """The shared rejection server's state and every effective 443 default server."""
    return site_native.script(
        "; ".join(
            (
                "export LC_ALL=C PATH=/usr/sbin:/usr/bin",
                (
                    f"if [ -e {DEFAULT_PATH} ] || [ -L {DEFAULT_PATH} ]; then "
                    f"stat -c 'path %F|%U|%G|%a|%h|%n' -- {DEFAULT_PATH}; "
                    f"[ -f {DEFAULT_PATH} ] && "
                    f"echo \"sha $(sha256sum <{DEFAULT_PATH} | cut -d' ' -f1)\"; "
                    "else echo 'absent'; fi"
                ),
                "nginx -T 2>/dev/null | grep -E 'listen .*443.*default_server' || true",
            )
        )
    )


def activation_state(
    paths: SitePaths, names: tuple[str, ...], fingerprint: str, backup: str
) -> list[str]:
    """docs/tls.md#activation: the activated site's native state after a run, as root."""
    source = paths.source
    placeholder = f"Site {paths.identifier} is ready."
    serve = _served_check(names, fingerprint)
    sni = _sni_served()
    host = _host_served(placeholder)
    return site_native.script(
        "; ".join(
            (
                "export LC_ALL=C PATH=/usr/sbin:/usr/bin",
                (
                    f"for p in {shlex.quote(source)} {shlex.quote(backup)} "
                    f"{shlex.quote(DEFAULT_PATH)}; do "
                    'if [ -e "$p" ] || [ -L "$p" ]; then '
                    "stat -c 'path %F|%U|%G|%a|%h|%n' -- \"$p\"; "
                    'else echo "absent $p"; fi; done'
                ),
                (
                    f"for p in {shlex.quote(source)} {shlex.quote(backup)} "
                    f"{shlex.quote(DEFAULT_PATH)}; do "
                    '[ -f "$p" ] && echo "sha $(sha256sum <"$p" | cut -d" " -f1) $p"; done'
                ),
                "nginx -t -q 2>/dev/null && echo 'nginx valid' || echo 'nginx invalid'",
                challenge_native.status_client(paths.php),
                serve,
                sni,
                host,
                (
                    "for n in " + " ".join(names) + "; do "
                    "f=$(timeout 5 openssl s_client -connect 127.0.0.1:443 "
                    '-servername "$n" </dev/null 2>/dev/null | openssl x509 -outform DER '
                    '2>/dev/null | sha256sum | cut -d" " -f1); echo "served $n $f"; done'
                ),
                "t && echo 'served verified' || echo 'served mismatch'",
                "u && echo 'unknown served' || echo 'unknown rejected'",
                (f"h {shlex.quote(names[0])} && echo 'host served' || echo 'host not served'"),
                (
                    f"r=$(s 127.0.0.1 {shlex.quote(names[0])} / | head -c 3); "
                    f"c=$(s 127.0.0.1 {shlex.quote(names[0])} "
                    "/.well-known/acme-challenge/missing | head -c 3); "
                    'echo "redirect $r challenge $c"'
                ),
            )
        )
    )
