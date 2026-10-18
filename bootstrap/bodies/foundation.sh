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
haproxy_path=${7:?HAProxy store path}
nix_mode=${8:?reviewed Nix stage}
caddy_mode=${9:?reviewed Caddy stage}
case "$nix_mode" in install|keep) ;; *) refused evidence ;; esac
case "$caddy_mode" in install|keep|refresh) ;; *) refused evidence ;; esac
# FOUNDATION_READ
stage preflight
[ "$(foundation_digest)" = "$expected" ] || refused precondition
[ "$(id -u)" = 0 ] || refused privilege
# PROXY_INVENTORY_PREFLIGHT
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
if [ "$nix_mode" = install ]; then
  [ ! -e /nix ] && [ ! -e /etc/nix ] || refused nix_incomplete
  if getent passwd | awk -F: '$3>=30001 && $3<=30032 {found=1} END {exit !found}'; then refused foreign_stack; fi
  if getent group nixbld >/dev/null || getent group 30000 >/dev/null; then refused foreign_stack; fi
else
  [ "$(stat -c '%u %g %a' /etc/nix/nix.conf)" = '0 0 644' ] || refused nix_incomplete
  [ "$(/nix/var/nix/profiles/default/bin/nix --version)" = 'nix (Nix) 2.35.2' ] || refused nix_incomplete
fi
if [ "$caddy_mode" = install ]; then
  if getent passwd caddy >/dev/null; then refused foreign_stack; fi
  if getent group caddy >/dev/null; then refused foreign_stack; fi
  for path in /etc/caddy /etc/systemd/system/caddy.service /var/lib/caddy; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || refused foreign_stack
  done
else
  [ "$(systemctl show --value -p User caddy.service)" = caddy ] || refused foreign_stack
  [ "$(systemctl show --value -p Group caddy.service)" = caddy ] || refused foreign_stack
fi
if dpkg-query -W -f='${Package} ${db:Status-Status}\n' | \
  awk '$2=="installed" && ($1 ~ /^(nginx|apache2|lighttpd|caddy|haproxy|openlitespeed|php)/) {found=1} END {exit !found}'; then refused foreign_stack; fi
listeners=$(ss -Hlnpt '( sport = :80 or sport = :443 )')
if [ "$caddy_mode" != install ]; then
  pid=$(systemctl show --value -p MainPID caddy.service)
  if [ "$pid" -gt 0 ] 2>/dev/null && [ "$(readlink -f "/proc/$pid/exe")" = "$caddy_path/bin/caddy" ]; then
    listeners=$(printf '%s\n' "$listeners" | grep -v "pid=$pid," || true)
  fi
fi
[ -z "$listeners" ] || refused foreign_stack
for path in /usr/local/cpanel /usr/local/psa /usr/local/directadmin /usr/local/hestia /usr/local/vesta \
  /usr/local/CyberCP /usr/local/ispconfig /etc/webmin /www/server /etc/runcloud /home/clp; do
  [ ! -e "$path" ] && [ ! -L "$path" ] || refused foreign_stack
done
journal=/etc/systemd/journald.conf.d/50-barectl.conf
if [ -e "$journal" ] || [ -L "$journal" ]; then
  [ "$(stat -c '%u %g %a' "$journal")" = '0 0 644' ] || refused foreign_stack
  [ "$(systemd-analyze cat-config systemd/journald.conf | sed -n 's/^Storage=//p' | tail -1)" = persistent ] || refused foreign_stack
fi
if [ "$nix_mode" = install ]; then
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
else
  stage Nix
fi
for entry in "caddy|$caddy_path" "composer|$composer_path" "wp-cli|$wp_path" "haproxy|$haproxy_path"; do
  name=${entry%%|*}
  target=${entry#*|}
  profile="/nix/var/nix/profiles/barectl/$name"
  if [ -e "$profile" ] || [ -L "$profile" ]; then
    [ "$(readlink -f "$profile")" = "$target" ] || refused evidence
  fi
done
stage catalog
nixbin=/nix/var/nix/profiles/default/bin
"$nixbin/nix-store" --realise "$caddy_path" "$composer_path" "$wp_path" "$haproxy_path" \
  --option max-jobs 0 --option fallback false
install -d -m 755 /nix/var/nix/profiles/barectl
for entry in "caddy|$caddy_path" "composer|$composer_path" "wp-cli|$wp_path" "haproxy|$haproxy_path"; do
  name=${entry%%|*}
  target=${entry#*|}
  profile="/nix/var/nix/profiles/barectl/$name"
  if [ -e "$profile" ] || [ -L "$profile" ]; then
    [ "$(readlink -f "$profile")" = "$target" ] || refused evidence
  else
    "$nixbin/nix-env" --profile "$profile" --set "$target"
  fi
done
[ "$(readlink -f /nix/var/nix/profiles/barectl/caddy)" = "$caddy_path" ] || exit 2
[ "$(readlink -f /nix/var/nix/profiles/barectl/composer)" = "$composer_path" ] || exit 2
[ "$(readlink -f /nix/var/nix/profiles/barectl/wp-cli)" = "$wp_path" ] || exit 2
[ "$(readlink -f /nix/var/nix/profiles/barectl/haproxy)" = "$haproxy_path" ] || exit 2
stage Caddy
if [ "$caddy_mode" = install ]; then
groupadd --system caddy
useradd --system --gid caddy --home-dir /var/lib/caddy --shell /usr/sbin/nologin caddy
install -d -m 700 -o caddy -g caddy /var/lib/caddy
install -d -m 755 /etc/caddy /etc/caddy/sites
fi
if [ "$caddy_mode" != keep ]; then
cat > /etc/caddy/Caddyfile <<'CONFIG'
{
	admin unix//run/caddy/admin.sock|0600
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
fi
"$caddy_path/bin/caddy" validate --config /etc/caddy/Caddyfile --adapter caddyfile
if [ "$caddy_mode" = refresh ]; then systemctl restart caddy.service; fi
# SITE_SERVICE_UNITS
systemctl daemon-reload
systemctl enable --now caddy.service
stage journald
install -d -m 755 /etc/systemd/journald.conf.d
if [ ! -e "$journal" ]; then printf '[Journal]\nStorage=persistent\n' > "$journal"; fi
systemctl restart systemd-journald.service
journalctl --flush
stage verify
systemctl is-active --quiet nix-daemon.service
systemctl is-active --quiet caddy.service
[ "$(stat -c '%a' /run/caddy/admin.sock)" = 600 ]
[ "$(stat -c '%a' /run/caddy)" = 700 ]
[ -z "$(ss -Hlnpt '( sport = :2019 )')" ]
for address in $(ss -Hlnptu | awk '{print $5}'); do
  case "$address" in 127.*|\[::1\]:*|\[::ffff:127.*) continue ;; esac
  case "${address##*:}" in 22|80|443) ;; *) refused foreign_stack ;; esac
done
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' -H 'Host: barectl-unknown.invalid' http://127.0.0.1/)" = 404 ]
"$caddy_path/bin/caddy" validate --config /etc/caddy/Caddyfile --adapter caddyfile
result '{"class":"succeeded"}'
