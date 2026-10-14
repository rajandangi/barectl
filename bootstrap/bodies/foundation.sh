# shellcheck shell=sh
# docs/bootstrap.md#host-foundation
set -eu
reported=0
result() { reported=1; printf 'barectl-result %s\n' "$1"; }
refused() { result "{\"class\":\"refused\",\"reason\":\"$1\"}"; exit 1; }
finish() {
  status=$?
  if [ "$reported" -eq 0 ] && [ "$status" -ne 0 ]; then
    result '{"class":"partial","reason":"foundation"}'
  fi
  [ -z "${work:-}" ] || rm -rf -- "$work"
  rm -f -- "$0"
}
trap finish EXIT
trap 'result "{\"class\":\"timed_out\"}"; exit 3' TERM
stage() { printf 'barectl-stage %s\n' "$1"; }
expected=${1:?precondition digest}
installer_url=${2:?installer URL}
installer_sha256=${3:?installer digest}
caddy_path=${4:?Caddy store path}
composer_path=${5:?Composer store path}
wp_path=${6:?WP-CLI store path}
# FOUNDATION_READ
stage preflight
[ "$(foundation_digest)" = "$expected" ] || refused precondition
[ "$(id -u)" = 0 ] || refused privilege
os_id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
os_version=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
[ "$os_id" = ubuntu ] && [ "$os_version" = 26.04 ] || refused platform
apt --version | grep -Eq '^apt 3\.2\.' || refused platform
dpkg --version | grep -Eq "version 1\.23\." || refused platform
systemctl --version | grep -Eq '^systemd 259([ .(]|$)' || refused platform
case $(uname -m) in x86_64|aarch64) ;; *) refused platform ;; esac
[ "$(df -B1 --output=avail / | tail -1)" -ge 4294967296 ] || refused headroom
available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
[ "$available" -ge 921600 ] || refused headroom
# No supported partial installer recovery exists upstream.
if [ -e /nix ] || [ -e /etc/nix ]; then refused nix_incomplete; fi
if getent passwd | awk -F: '$3>=30001 && $3<=30032 {found=1} END {exit !found}'; then refused foreign_stack; fi
if getent passwd caddy >/dev/null; then refused foreign_stack; fi
if getent group nixbld >/dev/null || getent group caddy >/dev/null; then refused foreign_stack; fi
if dpkg-query -W -f='${Package} ${db:Status-Status}\n' | \
  awk '$2=="installed" && ($1 ~ /^(nginx|apache2|lighttpd|caddy|openlitespeed|php)/) {found=1} END {exit !found}'; then refused foreign_stack; fi
[ -z "$(ss -Hlnpt '( sport = :80 or sport = :443 )')" ] || refused foreign_stack
for path in /etc/caddy /etc/systemd/system/caddy.service /etc/systemd/journald.conf.d/50-barectl.conf \
  /usr/local/cpanel /usr/local/psa /usr/local/directadmin /usr/local/hestia /usr/local/vesta \
  /usr/local/CyberCP /usr/local/ispconfig /etc/webmin /www/server /etc/runcloud /home/clp; do
  [ ! -e "$path" ] && [ ! -L "$path" ] || refused foreign_stack
done
work=$(mktemp -d /run/barectl-foundation.XXXXXXXX)
chmod 700 "$work"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  "$installer_url" -o "$work/nix.tar.xz" || refused download
printf '%s  %s\n' "$installer_sha256" "$work/nix.tar.xz" | sha256sum -c - >/dev/null || refused installer_digest
stage Nix
tar -xJf "$work/nix.tar.xz" -C "$work"
installer=$(find "$work" -mindepth 2 -maxdepth 2 -type f -name install)
[ -n "$installer" ] || refused installer_digest
/usr/bin/env HOME=/root USER=root "$installer" --daemon --yes --no-channel-add
cat > /etc/nix/nix.conf <<'CONFIG'
allowed-users = root
trusted-users = root
substituters = https://cache.nixos.org
trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
max-jobs = 0
fallback = false
CONFIG
systemctl restart nix-daemon.service
stage catalog
nixbin=/nix/var/nix/profiles/default/bin
"$nixbin/nix-store" --realise "$caddy_path" "$composer_path" "$wp_path" \
  --option max-jobs 0 --option fallback false
install -d -m 755 /nix/var/nix/profiles/barectl
"$nixbin/nix-env" --profile /nix/var/nix/profiles/barectl/caddy --set "$caddy_path"
"$nixbin/nix-env" --profile /nix/var/nix/profiles/barectl/composer --set "$composer_path"
"$nixbin/nix-env" --profile /nix/var/nix/profiles/barectl/wp-cli --set "$wp_path"
[ "$(readlink -f /nix/var/nix/profiles/barectl/caddy)" = "$caddy_path" ] || exit 2
[ "$(readlink -f /nix/var/nix/profiles/barectl/composer)" = "$composer_path" ] || exit 2
[ "$(readlink -f /nix/var/nix/profiles/barectl/wp-cli)" = "$wp_path" ] || exit 2
stage Caddy
groupadd --system caddy
useradd --system --gid caddy --home-dir /var/lib/caddy --shell /usr/sbin/nologin caddy
install -d -m 700 -o caddy -g caddy /var/lib/caddy
install -d -m 755 /etc/caddy /etc/caddy/sites
cat > /etc/caddy/Caddyfile <<'CONFIG'
{
	admin unix//run/caddy/admin.sock|0600
	auto_https off
	servers {
		strict_sni_host on
	}
}
import sites/*.caddy
:80 {
	respond 404
}
CONFIG
cat > /etc/systemd/system/caddy.service <<'UNIT'
[Unit]
Description=Caddy
Documentation=https://caddyserver.com/docs/
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
ExecStart=/nix/var/nix/profiles/barectl/caddy/bin/caddy run --environ --config /etc/caddy/Caddyfile --adapter caddyfile
ExecReload=/nix/var/nix/profiles/barectl/caddy/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address unix//run/caddy/admin.sock
TimeoutStopSec=5s
LimitNOFILE=1048576
PrivateTmp=true
ProtectSystem=full
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
UMask=0077
RuntimeDirectory=caddy
RuntimeDirectoryMode=0700
StateDirectory=caddy
StateDirectoryMode=0700
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
"$caddy_path/bin/caddy" validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl daemon-reload
systemctl enable --now caddy.service
stage journald
install -d -m 755 /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=persistent\n' > /etc/systemd/journald.conf.d/50-barectl.conf
systemctl restart systemd-journald.service
journalctl --flush
stage verify
systemctl is-active --quiet nix-daemon.service caddy.service
[ "$(stat -c '%a' /run/caddy/admin.sock)" = 600 ]
[ "$(stat -c '%a' /run/caddy)" = 700 ]
[ -z "$(ss -Hlnpt '( sport = :2019 )')" ]
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' -H 'Host: barectl-unknown.invalid' http://127.0.0.1/)" = 404 ]
"$caddy_path/bin/caddy" validate --config /etc/caddy/Caddyfile --adapter caddyfile
result '{"class":"succeeded"}'
