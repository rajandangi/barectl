#!/bin/sh
# Give the disposable server the state the acceptance tests exercise. Runs as root in the
# container after systemd has started. The PHP and PostgreSQL versions are Ubuntu 26.04's
# distribution defaults.
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nginx php8.5-fpm postgresql >/dev/null
# Beside the running main cluster: a stopped cluster and one systemd does not load.
pg_createcluster 18 archive >/dev/null
pg_createcluster 18 reports --start-conf manual >/dev/null
systemctl daemon-reload
# A site file only root can read, beside the stock default site.
install -m 600 /dev/null /etc/nginx/sites-available/private
ln -s ../sites-available/private /etc/nginx/sites-enabled/private
