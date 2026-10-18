#!/bin/sh
# shellcheck shell=sh
# docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md
# One reviewed database engine, installed by exactly one APT transaction whose resolved
# actions the inline guard admits, then hardened to the phase specification's shape.
set -eu
reported=0
result() { reported=1; printf 'barectl-result %s\n' "$1"; }
refused() { result "{\"class\":\"refused\",\"reason\":\"$1\"}"; exit 1; }
finish() {
  status=$?
  if [ "$reported" -eq 0 ] && [ "$status" -ne 0 ]; then
    result '{"class":"partial","reason":"database_engine"}'
  fi
  rm -f -- "$0"
}
trap finish EXIT
trap 'result "{\"class\":\"timed_out\"}"; exit 3' TERM
stage() { printf 'barectl-stage %s\n' "$1"; }

engine=${1:?engine}
expected=${2:?precondition digest}
roots=${3:?root packages}
guard=${4:?package guard}
versioned=${5:?versioned package}
version=${6:?version}

# ENGINE_DIGESTS
# ENGINE_HARDENING
# ENGINE_VERIFY

[ "$(id -u)" = 0 ] || refused privilege
[ -n "$guard" ] || refused evidence
os_id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
os_version=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
[ "$os_id" = ubuntu ] && [ "$os_version" = 26.04 ] || refused platform
apt --version | grep -Eq '^apt 3\.2\.' || refused platform
dpkg --version | grep -Eq "version 1\.23\." || refused platform
systemctl --version | grep -Eq '^systemd 259([ .(]|$)' || refused platform
case $(uname -m) in x86_64|aarch64) ;; *) refused platform ;; esac
[ "$(df -B1 --output=avail / | tail -1)" -ge 2147483648 ] || refused headroom
available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
[ "$available" -ge 460800 ] || refused headroom
stage preflight
[ "$(engine_digest "$engine" | cut -d' ' -f1)" = "$expected" ] || refused evidence

stage install
before=$(sha256sum /var/lib/dpkg/status | cut -d' ' -f1)
status=0
# shellcheck disable=SC2086
output=$(BARECTL_DPKG_STATUS="$before" DEBIAN_FRONTEND=noninteractive apt-get -q -y \
  --no-remove -o APT::Install-Recommends=0 -o APT::Install-Suggests=0 \
  -o APT::Get::Fix-Missing=0 -o DPkg::Lock::Timeout=0 \
  -o "DPkg::Pre-Install-Pkgs::=$guard" \
  -o "DPkg::Tools::Options::barectl_package_guard()::Version=3" \
  install $roots 2>&1 </dev/null) || status=$?
printf '%s\n' "$output" | tail -c 120000
after=$(sha256sum /var/lib/dpkg/status | cut -d' ' -f1)
if [ "$after" = "$before" ]; then
  printf '%s\n' "$output" | grep -q '^barectl-guard: refused ' && refused database_engine
  case "$output" in *'Could not get lock'*) refused apt_active ;; esac
  refused database_engine
fi
admitted=$(printf '%s\n' "$output" | grep -cx 'barectl-guard: admitted')
[ "$status" -eq 0 ] && [ "$admitted" -eq 1 ] || exit 2

stage start
engine_start "$engine" || exit 2

stage harden
engine_harden "$engine"

stage verify
systemctl is-active --quiet "$(engine_main_unit "$engine")"
[ "$(dpkg-query -W -f='${Version}' "$versioned")" = "$version" ] || exit 2
engine_verify "$engine" || exit 2
result '{"class":"succeeded"}'
