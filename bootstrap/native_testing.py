"""Shared package fixtures for disposable native-server acceptance tests."""

import os

from . import profiles, releases
from .models import Action

FIXTURES = all(
    os.environ.get(f"BARECTL_SSH_TEST_{name}")
    for name in ("HOST", "PORT", "USER", "KEY", "KNOWN_HOSTS", "CONTAINER", "UNPRIVILEGED_USER")
)
RELEASE = releases.RELEASES[os.environ.get("BARECTL_SSH_TEST_RELEASE", "24.04")]
REMOVE_NGINX = (
    "set -e; systemctl stop nginx; mv /etc/nginx /root/etc-nginx; "
    "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq nginx nginx-common >/dev/null"
)
RESTORE_NGINX = (
    "set -e; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-download nginx "
    ">/dev/null; rm -rf /etc/nginx; mv /root/etc-nginx /etc/nginx; systemctl restart nginx"
)

NGINX = profiles.profile(RELEASE, Action.NGINX)
PHP = profiles.profile(RELEASE, Action.PHP)
PHP_FPM, PHP_CLI = PHP.roots
MARIADB = profiles.profile(RELEASE, Action.MARIADB)
PACKAGES = " ".join(name for name in MARIADB.packages if name != "needrestart")
RECOVER = (
    "export DEBIAN_FRONTEND=noninteractive; "
    "for i in 1 2 3 4 5; do "
    "o=$(dpkg --configure -a 2>&1; apt-get install -y -q -f 2>&1) && break; "
    "printf '%s\\n' \"$o\"; "
    "r=$(printf '%s\\n' \"$o\" "
    "| sed -n 's/^dpkg: error processing package \\([^ ]*\\) (--configure):$/\\1/p' | sort -u); "
    '[ -n "$r" ] || break; '
    "apt-get install -y -q --reinstall $r || dpkg --remove --force-remove-reinstreq $r; "
    "done"
)
REMOVE_MARIADB = (
    "systemctl stop mariadb 2>/dev/null; pkill -f '[b]arectl-test-listener'; "
    "apt-mark unhold mariadb-server >/dev/null 2>&1; "
    f"{RECOVER} >/dev/null 2>&1; "
    "dpkg --purge mysql-server-8.0 >/dev/null 2>&1; "
    "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "
    f"{PACKAGES} libmariadb3 >/dev/null 2>&1; "
    "rm -rf /var/lib/mysql /var/lib/mariadb /var/lib/mysql-files /etc/mysql /var/log/mysql "
    "/run/mysqld /root/mysql-server; true"
)
INSTALL_MARIADB = (
    "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o APT::Install-Recommends=0 "
    "mariadb-server >/dev/null"
)
