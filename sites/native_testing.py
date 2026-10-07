"""Native disposable-server fixtures for site qualification."""

import shlex

from discovery.fakes import pool_config, site_config

# The provisioned root-only site, which site admission refuses, set aside for most tests.
SET_ASIDE = (
    "mv /etc/nginx/sites-enabled/private /root/private.link && "
    "mv /etc/nginx/sites-available/private /root/private.site"
)
PUT_BACK = (
    "test -e /etc/nginx/sites-available/private || "
    "mv /root/private.site /etc/nginx/sites-available/private; "
    "test -L /etc/nginx/sites-enabled/private || "
    "mv /root/private.link /etc/nginx/sites-enabled/private; true"
)
SUDOERS = "/etc/sudoers.d/deploy"


def snapshot(php: str) -> str:
    """What preparation must leave as it was, read as root."""
    return "; ".join(
        (
            (
                "find /etc /var/www /run/php /var/backups -xdev "
                "-printf '%p %y %m %U %G %s %T@\\n' 2>/dev/null | LC_ALL=C sort | sha256sum"
            ),
            "sha256sum /etc/passwd /etc/group /etc/shadow /etc/gshadow",
            # The master PIDs only: a reload another test's cleanup triggers can be
            # settling while this snapshot runs, and then the workers' PIDs differ
            # even though preparation changed nothing.
            "echo nginx $(cat /run/nginx.pid)",
            (f"echo fpm $(systemctl show -p MainPID --value php{php}-fpm.service)"),
            "echo; stat -c '%n %s' /var/log/nginx/* /var/log/php*-fpm.log 2>/dev/null",
            "systemctl list-units --all --plain --no-legend 'barectl-apply-*'",
            "find /etc/nginx /etc/php /var/www -name '.*' 2>/dev/null",
        )
    )


def _write(path: str, content: str, mode: str) -> str:
    return f"printf %s {shlex.quote(content)} >{path} && chmod {mode} {path}"


def create_site(identifier: str, names: tuple[str, ...], php: str) -> str:
    """The administrator's own commands for a site that meets the convention."""
    user = f"s{identifier}"
    return " && ".join(
        (
            (
                f"useradd --home-dir /var/www/{identifier} --no-create-home "
                f"--shell /usr/sbin/nologin --user-group {user}"
            ),
            f"install -d -o root -g root -m 755 /var/www/{identifier}",
            f"install -d -o {user} -g www-data -m 750 /var/www/{identifier}/public",
            f"install -d -o {user} -g {user} -m 700 /var/www/{identifier}/private",
            _write(
                f"/etc/nginx/sites-available/{identifier}.conf",
                site_config(identifier, names),
                "644",
            ),
            (
                f"ln -s /etc/nginx/sites-available/{identifier}.conf "
                f"/etc/nginx/sites-enabled/{identifier}.conf"
            ),
            _write(f"/etc/php/{php}/fpm/pool.d/{identifier}.conf", pool_config(identifier), "644"),
            "nginx -t -q",
            f"php-fpm{php} -t 2>/dev/null",
            f"systemctl reload php{php}-fpm",
            "systemctl reload nginx",
            f"for _ in $(seq 50); do test -S /run/php/{user}.sock && break; sleep 0.2; done",
            f"test -S /run/php/{user}.sock",
        )
    )


def _socket_cleanup(identifier: str) -> str:
    """Wait for the pool reload to close the site's socket, then remove any lingering file.

    A present socket is not absent, so a stale one would block the identifier's next plan.
    """
    socket = f"/run/php/s{identifier}.sock"
    return f"for _ in $(seq 50); do test -S {socket} || break; sleep 0.2; done; rm -f {socket}"


def remove_site(identifier: str, php: str) -> str:
    return "; ".join(
        (
            f"rm -f /etc/nginx/sites-enabled/{identifier}.conf",
            f"rm -f /etc/nginx/sites-available/{identifier}.conf",
            f"rm -f /etc/php/{php}/fpm/pool.d/{identifier}.conf",
            # Files an interrupted run staged beside their destinations.
            f"rm -f /etc/nginx/sites-available/.{identifier}.conf.*",
            f"rm -f /etc/php/{php}/fpm/pool.d/.{identifier}.conf.*",
            # A service a broken fixture stopped is started again.
            f"systemctl reload php{php}-fpm 2>/dev/null || systemctl restart php{php}-fpm",
            "systemctl reload nginx 2>/dev/null || systemctl restart nginx",
            _socket_cleanup(identifier),
            f"rm -rf /var/www/{identifier}",
            # A challenge route's webroot and recovery preimages.
            f"rm -rf /var/lib/letsencrypt/{identifier} /var/backups/nginx/{identifier}.conf.*",
            f"id s{identifier} >/dev/null 2>&1 && userdel s{identifier}",
            f"getent group s{identifier} >/dev/null && groupdel s{identifier}",
            "true",
        )
    )
