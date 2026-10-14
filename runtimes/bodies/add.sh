#!/bin/sh
set -eu
export HOME=/root USER=root
reported=0
result() { reported=1; printf 'barectl-result %s\n' "$1"; }
finish() {
    status=$?
    if [ "$reported" -eq 0 ] && [ "$status" -ne 0 ]; then
        result '{"class":"partial","reason":"runtime_config"}'
    fi
    rm -f -- "$0"
}
trap finish EXIT
trap 'result "{\"class\":\"timed_out\"}"; exit 3' TERM
entry=$1
path=$2
fcgi=$3
digest=$4
read_source=$5
probe=$6
ini=$7
master=$8
pool=$9
shift 9
unit=$1
fail() { result "{\"class\":\"$1\",\"reason\":\"$2\"}"; exit 1; }
[ "$(python3 -c "$read_source" "$entry" "$fcgi" "$probe" "$unit" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data["digest"] if data.get("admissible") is True else "unsafe")')" = "$digest" ] || fail refused evidence
printf 'barectl-stage preflight\n'
nixbin=/nix/var/nix/profiles/default/bin
# Query the signed cache before store, profile, account, configuration or unit changes.
case "$entry" in nodejs_22|nodejs_24) paths="$path";; *) paths="$path $fcgi";; esac
# Reviewed paths contain no whitespace or shell metacharacters.
# shellcheck disable=SC2086
"$nixbin/nix" --extra-experimental-features nix-command path-info --store https://cache.nixos.org --recursive $paths >/dev/null || fail refused runtime_cache
printf 'barectl-stage realise\n'
# shellcheck disable=SC2086
"$nixbin/nix-store" --realise $paths --option max-jobs 0 --option fallback false >/dev/null || fail partial runtime_realise
profile=/nix/var/nix/profiles/barectl/$entry
[ ! -e "$profile" ] && [ ! -L "$profile" ] || fail refused evidence
"$nixbin/nix-env" --profile "$profile" --set "$path"
case "$entry" in nodejs_22|nodejs_24) printf 'barectl-stage verify\n'; result '{"class":"succeeded"}'; exit 0;; esac
if [ ! -e /nix/var/nix/profiles/barectl/fcgi ]; then
    "$nixbin/nix-env" --profile /nix/var/nix/profiles/barectl/fcgi --set "$fcgi"
fi
printf 'barectl-stage configure\n'
if ! getent passwd php-probe >/dev/null; then
    groupadd --system php-probe
    useradd --system --gid php-probe --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin php-probe
fi
install -d -o root -g root -m 755 /etc/php-fpm /etc/php-fpm/"$entry" /etc/php-fpm/"$entry"/pools
install -d -o root -g php-probe -m 750 /etc/php-fpm/diagnostics
printf '%s' "$probe" | base64 -d > /etc/php-fpm/diagnostics/probe.php
chown root:php-probe /etc/php-fpm/diagnostics/probe.php
chmod 640 /etc/php-fpm/diagnostics/probe.php
for directory in session upload tmp; do
    install -d -o php-probe -g php-probe -m 700 /var/lib/php-fpm/"$entry"/diagnostic/"$directory"
done
printf '%s' "$ini" | base64 -d > /etc/php-fpm/"$entry"/php.ini
printf '%s' "$master" | base64 -d > /etc/php-fpm/"$entry"/php-fpm.conf
printf '%s' "$pool" | base64 -d > /etc/php-fpm/"$entry"/pools/diagnostic.conf
printf '%s' "$unit" | base64 -d > /etc/systemd/system/php-fpm@.service
chmod 644 /etc/php-fpm/"$entry"/php.ini /etc/php-fpm/"$entry"/php-fpm.conf /etc/php-fpm/"$entry"/pools/diagnostic.conf /etc/systemd/system/php-fpm@.service
printf 'barectl-stage validate\n'
"$path/bin/php-fpm" -t -y /etc/php-fpm/"$entry"/php-fpm.conf -c /etc/php-fpm/"$entry"/php.ini || fail partial runtime_config
systemctl daemon-reload
systemctl enable --now "php-fpm@$entry.service" || fail partial runtime_start
printf 'barectl-stage verify\n'
result '{"class":"succeeded"}'
