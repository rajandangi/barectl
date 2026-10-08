"""The WordPress PHP runtime run's own native steps and verification read.

docs/wordpress.md#php-runtime. The package transaction, its guard and the pool reload are
bootstrap's (docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md);
these steps follow the reload, as root, and ask the site's own pool and the selected CLI,
run as the site user, which capabilities they load.
"""

import shlex
from typing import Final

from bootstrap import native as bootstrap_native
from databases.binding import fastcgi_client
from sites import native as site_native
from sites.convention import SitePaths

from . import runtime


class Exit:
    """The payload's boundaries after the package transaction changed the server."""

    PROBE_FAILED: Final = 41
    CAPABILITIES_DIFFER: Final = 42
    PROBE_LEFT: Final = 43


def probe_steps(
    unit: str, *, paths: SitePaths, token: str, uid: int, content: str
) -> tuple[str, ...]:
    """Each named fragment, in order; every one exits the unit on failure after removing the
    probe it published."""
    if content != runtime.render_probe(token) or not 0 < uid < 2**31:
        raise ValueError("The probe is not the convention's.")
    identifier, php = paths.identifier, paths.php
    probe = runtime.probe_path(identifier, token)
    boundary = f"/var/www/{identifier}"
    expected = shlex.quote(runtime.expected_probe(token, uid))
    sha256 = runtime.digest(content)
    suffix = unit.removeprefix(bootstrap_native.UNIT_PREFIX).removesuffix(".service")
    path, directory = shlex.quote(probe), shlex.quote(boundary)
    owner = f"root:s{identifier}"
    helpers = "; ".join(
        (
            "export LC_ALL=C PATH=/usr/sbin:/usr/bin; umask 077; set -C",
            (
                'a(){ for d in "$@"; do while :; do [ ! -L "$d" ] && '
                "[ \"$(stat -c '%F %u' -- \"$d\")\" = 'directory 0' ] && "
                "[ $((0$(stat -c '%a' -- \"$d\") & 022)) -eq 0 ] || return 1; "
                '[ "$d" = / ] && break; d=$(dirname -- "$d"); done; done; }'
            ),
            (
                f"r(){{ if [ -f {path} ] && [ ! -L {path} ] && "
                f"[ \"$(sha256sum <{path} | cut -d' ' -f1)\" = {sha256} ]; "
                f"then rm -f -- {path}; fi; [ ! -e {path} ] && [ ! -L {path} ]; }}"
            ),
            f'x(){{ r || exit {Exit.PROBE_LEFT}; exit "$1"; }}',
            site_native.writer(suffix),
            fastcgi_client(php),
        )
    )
    request = f"f {shlex.quote(paths.socket)} {path}"
    cli = f"runuser -u s{identifier} -- /usr/bin/env -i /usr/bin/php{php} {path}"
    return (
        helpers,
        (
            f"[ ! -e {path} ] && [ ! -L {path} ] && a {directory} || exit {Exit.PROBE_FAILED}; "
            f'for b in /usr/bin/php{php} /usr/bin/env /usr/sbin/runuser; do [ -x "$b" ] '
            f"|| exit {Exit.PROBE_FAILED}; done"
        ),
        (
            f"printf '%s' {shlex.quote(content)} | w {directory} {probe.rpartition('/')[2]} "
            f"{owner} 0640 {sha256} || x {Exit.PROBE_FAILED}"
        ),
        f'[ "$({request})" = {expected} ] || x {Exit.CAPABILITIES_DIFFER}',
        f'[ "$({cli})" = {expected} ] || x {Exit.CAPABILITIES_DIFFER}',
        f"r || exit {Exit.PROBE_LEFT}; echo 'barectl-wordpress: verified'",
    )
