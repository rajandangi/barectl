#!/bin/sh
# shellcheck shell=sh
# docs/security-native-design.md#pending-updates-and-install-updates
# Refresh Ubuntu's own package lists with its own tool under the shared mutation lock.
# Nothing is installed and no package file is changed.
set -eu
reported=0
result() { reported=1; printf 'barectl-result %s\n' "$1"; }
refused() { result "{\"class\":\"refused\",\"reason\":\"$1\"}"; exit 1; }
finish() {
  status=$?
  if [ "$reported" -eq 0 ] && [ "$status" -ne 0 ]; then
    result '{"class":"partial","reason":"updates_refresh_failed"}'
  fi
  rm -f -- "$0"
}
trap finish EXIT
trap 'result "{\"class\":\"timed_out\"}"; exit 3' TERM
stage() { printf 'barectl-stage %s\n' "$1"; }

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
available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
[ "$available" -ge 262144 ] || refused headroom

stage refresh
status=0
output=$(DEBIAN_FRONTEND=noninteractive apt-get -q update 2>&1 </dev/null) || status=$?
printf '%s\n' "$output" | tail -c 120000
if [ "$status" -ne 0 ]; then
  case "$output" in
    *'Could not get lock'*|*'Unable to acquire the dpkg frontend lock'*|*'Could not open lock file'*)
      refused apt_active
      ;;
  esac
  refused updates_refresh
fi

stage verify
find /var/lib/apt/lists -maxdepth 1 -name '*InRelease' -print -quit | grep -q . \
  || refused updates_refresh
result '{"class":"succeeded"}'
