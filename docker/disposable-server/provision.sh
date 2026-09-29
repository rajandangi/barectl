#!/bin/sh
# Give the disposable server the state the acceptance tests exercise. Runs as root in the
# container after systemd has started. The PHP and PostgreSQL versions are the release's
# distribution defaults.
set -eu
export DEBIAN_FRONTEND=noninteractive
. /etc/os-release
case $VERSION_ID in
24.04) php=8.3 postgresql=16 ;;
26.04) php=8.5 postgresql=18 ;;
*)
    echo "Unsupported release $VERSION_ID." >&2
    exit 1
    ;;
esac
apt-get update -qq
apt-get install -y -qq nginx "php$php-fpm" postgresql >/dev/null
# Beside the running main cluster: a stopped cluster and one systemd does not load.
pg_createcluster "$postgresql" archive >/dev/null
pg_createcluster "$postgresql" reports --start-conf manual >/dev/null
systemctl daemon-reload
# A site file only root can read, beside the stock default site.
install -m 600 /dev/null /etc/nginx/sites-available/private
ln -s ../sites-available/private /etc/nginx/sites-enabled/private
