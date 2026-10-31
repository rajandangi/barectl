#!/bin/sh
# shellcheck shell=sh
# Ubuntu's own automatic security updates, set through the package's debconf answer and
# its dpkg-reconfigure. Barectl installs only the exact reviewed package transaction and
# never writes a second scheduler or edits APT's configuration files by hand.
set -eu
reported=0
result() { reported=1; printf 'barectl-result %s\n' "$1"; }
refused() { result "{\"class\":\"refused\",\"reason\":\"$1\"}"; exit 1; }
finish() {
  status=$?
  if [ "$reported" -eq 0 ] && [ "$status" -ne 0 ]; then
    result '{"class":"partial","reason":"automatic_updates_configure"}'
  fi
  rm -f -- "$0"
}
trap finish EXIT
trap 'result "{\"class\":\"timed_out\"}"; exit 3' TERM
stage() { printf 'barectl-stage %s\n' "$1"; }

state=${1:?state}
expected=${2:?precondition digest}
roots=${3:-}
guard=${4:-}
versioned=${5:?versioned package}
version=${6:?version}
settings=${7:-}

# SECURITY_DIGEST_FUNCTIONS

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
[ "$(precondition_digest)" = "$expected" ] || refused evidence

if [ -n "$roots" ]; then
  [ -n "$guard" ] || refused evidence
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
    printf '%s\n' "$output" | grep -q '^barectl-guard: refused ' \
      && refused automatic_updates_package
    case "$output" in *'Could not get lock'*) refused apt_active ;; esac
    refused automatic_updates_package
  fi
  admitted=$(printf '%s\n' "$output" | grep -cx 'barectl-guard: admitted')
  [ "$status" -eq 0 ] && [ "$admitted" -eq 1 ] || refused automatic_updates_package
else
  [ -z "$guard" ] || refused evidence
fi

stage configure
enabled=false
source=/usr/share/unattended-upgrades/20auto-upgrades
if [ "$state" = off ]; then
  enabled=false
  source=/usr/share/unattended-upgrades/20auto-upgrades-disabled
elif [ "$state" = on ]; then
  enabled=true
else
  refused evidence
fi
[ -f "$source" ] || { result '{"class":"partial","reason":"automatic_updates_configure"}'; exit 2; }
# The package's config script reads the current file before asking its question, so use the
# package's own shipped file first; otherwise a noninteractive reconfigure cannot change it.
ucf --three-way --debconf-ok "$source" /etc/apt/apt.conf.d/20auto-upgrades >/dev/null 2>&1 \
  || { result '{"class":"partial","reason":"automatic_updates_configure"}'; exit 2; }
printf '%s\n' \
  "unattended-upgrades unattended-upgrades/enable_auto_updates boolean $enabled" \
  | debconf-set-selections
DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true \
  dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 \
  || { result '{"class":"partial","reason":"automatic_updates_configure"}'; exit 2; }

stage verify
[ "$(dpkg-query -W -f='${db:Status-Status}' "$versioned" 2>/dev/null || true)" = installed ] \
  || { result '{"class":"partial","reason":"automatic_updates_package"}'; exit 2; }
[ "$(dpkg-query -W -f='${Version}' "$versioned" 2>/dev/null || true)" = "$version" ] \
  || { result '{"class":"partial","reason":"automatic_updates_package"}'; exit 2; }
periodic_lists=$(apt-config dump \
  | sed -n 's/^APT::Periodic::Update-Package-Lists "\(.*\)";$/\1/p' | tail -n 1)
periodic_upgrade=$(apt-config dump \
  | sed -n 's/^APT::Periodic::Unattended-Upgrade "\(.*\)";$/\1/p' | tail -n 1)
if [ "$state" = on ]; then
  [ "$periodic_lists" = 1 ] && [ "$periodic_upgrade" = 1 ] \
    || { result '{"class":"partial","reason":"automatic_updates_verify"}'; exit 2; }
  timer_state=$(systemctl show apt-daily.timer apt-daily-upgrade.timer -p UnitFileState)
  [ "$(printf '%s\n' "$timer_state" | grep -c '^UnitFileState=enabled$')" -eq 2 ] \
    || { result '{"class":"partial","reason":"automatic_updates_verify"}'; exit 2; }
else
  [ "$periodic_lists" = 0 ] && [ "$periodic_upgrade" = 0 ] \
    || { result '{"class":"partial","reason":"automatic_updates_verify"}'; exit 2; }
fi
if [ -z "$roots" ] && [ -n "$settings" ]; then
  [ "$(settings_digest)" = "$settings" ] \
    || { result '{"class":"partial","reason":"automatic_updates_settings"}'; exit 2; }
fi
result '{"class":"succeeded"}'
