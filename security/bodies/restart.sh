#!/bin/sh
# shellcheck shell=sh
# docs/security.md#restart
set -eu
reported=0
result() { reported=1; printf 'barectl-result %s\n' "$1"; }
refused() { result "{\"class\":\"refused\",\"reason\":\"$1\"}"; exit 1; }
finish() {
  status=$?
  if [ "$reported" -eq 0 ] && [ "$status" -ne 0 ]; then
    result '{"class":"partial","reason":"restart_apply"}'
  fi
  rm -f -- "$0"
}
trap finish EXIT
trap 'result "{\"class\":\"timed_out\"}"; exit 3' TERM
stage() { printf 'barectl-stage %s\n' "$1"; }

boot_id=${1:?boot identity}
expected=${2:-}
services=${3:-}

[ "$boot_id" = "$(cat /proc/sys/kernel/random/boot_id)" ] || refused evidence
printf '%s\n' "$services" \
  | grep -Eq '^[a-z][a-z0-9@_.:-]{0,119}\.service(,[a-z][a-z0-9@_.:-]{0,119}\.service)*$' \
  || refused evidence
[ "$(id -u)" = 0 ] || refused privilege
os_id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
os_version=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
[ "$os_id" = ubuntu ] && [ "$os_version" = 26.04 ] || refused platform
apt --version | grep -Eq '^apt 3\.2\.' || refused platform
dpkg --version | grep -Eq "version 1\.23\." || refused platform
systemctl --version | grep -Eq '^systemd 259([ .(]|$)' || refused platform
case $(uname -m) in x86_64|aarch64) ;; *) refused platform ;; esac
[ "$(df -B1 --output=avail / | tail -1)" -ge 536870912 ] || refused headroom

stage preflight
actual=$(sed -e 's/[[:space:]]*$//' -e '/^$/d' /run/reboot-required.pkgs 2>/dev/null \
  | LC_ALL=C sort || true)
[ "$actual" = "$expected" ] || refused restart_evidence

busy() {
  unit=$1
  control=$(systemctl show -p ControlGroup --value "$unit" 2>/dev/null || true)
  [ -n "$control" ] || return 1
  events="/sys/fs/cgroup$control/cgroup.events"
  [ -r "$events" ] && grep -qx 'populated 1' "$events"
}

for role in backup copy cleanup cleanupoffsite check checkoffsite; do
  for unit in $(systemctl list-units --all --plain --no-legend --type=service \
      "barectl-site-*-${role}.service" 2>/dev/null | cut -d' ' -f1); do
    if busy "$unit"; then refused restart_work; fi
  done
done

for unit in apt-daily.service apt-daily-upgrade.service; do
  state=$(systemctl is-active "$unit" 2>/dev/null || true)
  case "$state" in active|activating|deactivating) refused restart_work ;; esac
done

stage restart
sync
result '{"class":"succeeded"}'
systemctl reboot || { result '{"class":"partial","reason":"restart_apply"}'; exit 2; }
