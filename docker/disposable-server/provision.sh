#!/bin/sh
# Give the disposable server the state the acceptance tests exercise. Runs as root in the
# container after systemd has started.
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nginx php8.3-fpm postgresql >/dev/null
# Beside the running 16/main cluster: a stopped cluster and one systemd does not load.
pg_createcluster 16 archive >/dev/null
pg_createcluster 16 reports --start-conf manual >/dev/null
systemctl daemon-reload
# A site file only root can read, beside the stock default site.
install -m 600 /dev/null /etc/nginx/sites-available/private
ln -s ../sites-available/private /etc/nginx/sites-enabled/private
