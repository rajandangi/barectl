#!/bin/sh
# shellcheck shell=sh
# docs/adr/0010-use-local-site-identities-for-database-access.md
# Remove exactly the reviewed engine packages, keeping every database and data directory.
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
packages=${3:?packages}

# ENGINE_DIGESTS
# ENGINE_VERIFY

[ "$(id -u)" = 0 ] || refused privilege
[ -n "$packages" ] || refused evidence
os_id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
os_version=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
[ "$os_id" = ubuntu ] && [ "$os_version" = 26.04 ] || refused platform
stage preflight
[ "$(engine_digest "$engine" | cut -d' ' -f1)" = "$expected" ] || refused evidence

stage remove
systemctl stop "$(engine_main_unit "$engine")" 2>/dev/null || true
status=0
# shellcheck disable=SC2086
output=$(DEBIAN_FRONTEND=noninteractive apt-get -q -y remove $packages 2>&1 </dev/null) || status=$?
printf '%s\n' "$output" | tail -c 120000
[ "$status" -eq 0 ] || exit 2

stage verify
absent=1
for package in $packages; do
  state=$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || echo not-installed)
  [ "$state" != installed ] || absent=0
done
[ "$absent" -eq 1 ] || exit 2
result '{"class":"succeeded"}'
