#!/bin/sh
# shellcheck shell=sh
# docs/adr/0024-admit-exact-reviewed-upgrade-transactions.md
# Install exactly the reviewed Ubuntu upgrades and new dependencies. The reviewed
# preconditions are read again under the mutation lock, and the inline guard admits only
# the reviewed dpkg actions.
set -eu
reported=0
result() { reported=1; printf 'barectl-result %s\n' "$1"; }
refused() { result "{\"class\":\"refused\",\"reason\":\"$1\"}"; exit 1; }
finish() {
  status=$?
  if [ "$reported" -eq 0 ] && [ "$status" -ne 0 ]; then
    result '{"class":"partial","reason":"updates_failed"}'
  fi
  rm -f -- "$0"
}
trap finish EXIT
trap 'result "{\"class\":\"timed_out\"}"; exit 3' TERM
stage() { printf 'barectl-stage %s\n' "$1"; }

selection=${1:?selection}
expected=${2:?precondition digest}
roots=${3:?requested packages}
guard=${4:?package guard}
packages=${5:?reviewed packages}

# UPDATES_DIGEST_FUNCTIONS

[ "$(id -u)" = 0 ] || refused privilege
os_id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
os_version=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
[ "$os_id" = ubuntu ] && [ "$os_version" = 26.04 ] || refused platform
apt --version | grep -Eq '^apt 3\.2\.' || refused platform
dpkg --version | grep -Eq "version 1\.23\." || refused platform
systemctl --version | grep -Eq '^systemd 259([ .(]|$)' || refused platform
case $(uname -m) in x86_64|aarch64) ;; *) refused platform ;; esac
[ "$(df -B1 --output=avail / | tail -1)" -ge 536870912 ] || refused headroom
available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
[ "$available" -ge 262144 ] || refused headroom
case "$selection" in security|all) ;; *) refused evidence ;; esac

stage preflight
[ -n "$guard" ] || refused evidence
modified=$(modified_conffiles)
if [ -n "$modified" ]; then
  for name in $packages; do
    printf '%s\n' "$modified" \
      | awk -F '	' -v name="$name" '$1 == name {found = 1} END {exit !found}' \
      && refused updates_conffile
  done
fi
[ -z "$(dpkg --audit 2>&1)" ] || refused updates_pending
held=$(apt-mark showhold)
for name in $packages; do
  printf '%s\n' "$held" | grep -qx "$name" && refused updates_hold
done
[ "$(precondition_digest)" = "$expected" ] || refused evidence

stage install
before=$(sha256sum /var/lib/dpkg/status | cut -d' ' -f1)
status=0
# shellcheck disable=SC2086
output=$(BARECTL_DPKG_STATUS="$before" DEBIAN_FRONTEND=noninteractive apt-get -q -y \
  --no-remove -o APT::Install-Recommends=0 -o APT::Install-Suggests=0 \
  -o APT::Get::Fix-Missing=0 -o DPkg::Lock::Timeout=0 \
  -o "DPkg::Pre-Install-Pkgs::=$guard" \
  -o "DPkg::Tools::Options::barectl_package_guard()::Version=3" \
  --only-upgrade install $roots 2>&1 </dev/null) || status=$?
printf '%s\n' "$output" | tail -c 120000
after=$(sha256sum /var/lib/dpkg/status | cut -d' ' -f1)
if [ "$after" = "$before" ]; then
  printf '%s\n' "$output" | grep -q '^barectl-guard: refused ' \
    && refused updates_transaction
  case "$output" in
    *'Could not get lock'*|*'Unable to acquire the dpkg frontend lock'*|*'Could not open lock file'*)
      refused apt_active
      ;;
  esac
  refused updates_transaction
fi
admitted=$(printf '%s\n' "$output" | grep -cx 'barectl-guard: admitted')
[ "$status" -eq 0 ] && [ "$admitted" -eq 1 ] || refused updates_transaction

stage verify
for entry in $roots; do
  name=${entry%%=*}
  version=${entry#*=}
  [ "$(dpkg-query -W -f='${db:Status-Status}' "$name" 2>/dev/null || true)" = installed ] \
    || refused updates_verify
  [ "$(dpkg-query -W -f='${Version}' "$name" 2>/dev/null || true)" = "$version" ] \
    || refused updates_verify
done
[ -z "$(dpkg --audit 2>&1)" ] || refused updates_verify
result '{"class":"succeeded"}'
