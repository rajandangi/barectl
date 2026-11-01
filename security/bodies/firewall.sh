#!/bin/sh
# shellcheck shell=sh
# The standard UFW firewall and one operator port, changed only through ufw's own
# commands. A root-only preimage and a five-minute transient timer let the server put the
# previous firewall back unless the controller confirms access over a new connection
# (docs/adr/0023, docs/security.md#firewall).
set -eu
reported=0
armed=0
result() { reported=1; printf 'barectl-result %s\n' "$1"; }
refused() { result "{\"class\":\"refused\",\"reason\":\"$1\"}"; exit 1; }
finish() {
  status=$?
  if [ "$reported" -eq 0 ] && [ "$status" -ne 0 ]; then
    result '{"class":"partial","reason":"firewall_apply"}'
  fi
  if [ "$armed" -eq 1 ] && [ "$status" -ne 0 ]; then
    systemctl start -- "$service" >/dev/null 2>&1 || true
  fi
  rm -f -- "$0"
}
trap finish EXIT
trap 'result "{\"class\":\"timed_out\"}"; exit 3' TERM
stage() { printf 'barectl-stage %s\n' "$1"; }

action=${1:?action}
expected=${2:?precondition digest}
roots=${3:-}
guard=${4:-}
versioned=${5:-ufw}
version=${6:-}
ssh_ports=${7:-}
standard_rules=${8:-}
port=${9:-}
protocol=${10:-}
network=${11:-}
connection_port=${12:-}
id=${13:-}

case "$action" in on|add|remove) ;; *) refused evidence ;; esac
[ ${#id} -eq 32 ] || refused evidence
case "$id" in *[!0-9a-f]*) refused evidence ;; esac
case "$ssh_ports" in ''|*[!0-9,]*) refused evidence ;; esac
printf '%s\n' "$standard_rules" \
  | grep -Eq '^(tcp|udp):[0-9]{1,5}(,(tcp|udp):[0-9]{1,5})*$' || refused evidence
[ -n "$connection_port" ] || refused evidence

revert=/run/barectl/revert-$id
timer=barectl-revert-$id.timer
service=barectl-revert-$id.service

ufw_run() {
  status=0
  output=$(ufw "$@" 2>&1) || status=$?
  printf '%s\n' "$output"
  [ "$status" -eq 0 ] || case "$output" in
    *'ERROR: problem running'*) return 0 ;;
    *) return 1 ;;
  esac
}

ssh_ok() {
  configured=$(sshd -T 2>/dev/null | sed -n 's/^port //p' | LC_ALL=C sort -nu | paste -sd, -)
  [ "$configured" = "$ssh_ports" ] || return 1
  listeners=$(ss -Hlnptu 2>/dev/null \
    | awk '$1=="tcp" && index($0,"sshd")>0 {n=split($5,a,":"); print a[n]}' \
    | LC_ALL=C sort -nu | paste -sd, -)
  [ "$listeners" = "$ssh_ports" ] || return 1
  socket=$(systemctl show ssh.socket -p ListenStream --value 2>/dev/null || true)
  if [ -n "$socket" ]; then
    socket_ports=$(printf '%s\n' "$socket" | tr ' ' '\n' \
      | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p' | LC_ALL=C sort -nu | paste -sd, -)
    [ "$socket_ports" = "$ssh_ports" ] || return 1
  fi
  printf '%s\n' ",$ssh_ports," | grep -q ",$connection_port," || return 1
}

outside_ok() {
  [ "$(systemctl is-active firewalld 2>/dev/null || true)" != active ] || return 1
  for package in docker.io docker-ce docker-ce-cli containerd.io; do
    state=$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || true)
    [ "$state" != installed ] || return 1
  done
  if [ "$(ufw status 2>/dev/null | head -n 1)" != "Status: active" ]; then
    nft_out=$(nft list ruleset 2>/dev/null || true)
    if [ -n "$nft_out" ]; then
      printf '%s\n' "$nft_out" | awk '
        /^[ \t]*chain [^ ]+ \{/ {chain=$2; next}
        /^[ \t]*[^ \t}]/ {if (chain != "" && chain !~ /^ufw/) found=1}
        END {exit !found}' && return 1
    fi
    if iptables-save 2>/dev/null | awk '
      /^\*/ {table=substr($0,2); next}
      table == "filter" && /^-(A|I) / {
        chain=$2
        if (chain !~ /^ufw/ && $0 !~ /-j ufw/) print}' | grep -q .; then
      return 1
    fi
  fi
  return 0
}

standard_ok() {
  st=$(ufw status verbose 2>&1 || true)
  case "$st" in "Status: active"*) ;; *) return 1 ;; esac
  printf '%s\n' "$st" | grep -q 'Logging: on (low)' || return 1
  printf '%s\n' "$st" \
    | grep -q 'Default: deny (incoming), allow (outgoing), deny (routed)' || return 1
  grep -qx 'IPV6=yes' /etc/default/ufw || return 1
  grep -qx 'ENABLED=yes' /etc/ufw/ufw.conf || return 1
  added=$(ufw show added 2>/dev/null || true)
  for entry in $(printf '%s' "$standard_rules" | tr ',' ' '); do
    rule_protocol=${entry%%:*}
    rule_port=${entry#*:}
    printf '%s\n' "$added" | grep -Fxq "ufw allow $rule_port/$rule_protocol" || return 1
  done
  return 0
}

rule_line() {
  if [ -n "$network" ]; then
    printf 'ufw allow from %s to any port %s proto %s' "$network" "$port" "$protocol"
  else
    printf 'ufw allow %s/%s' "$port" "$protocol"
  fi
}

# FIREWALL_DIGEST_FUNCTIONS

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
[ "$(firewall_prestate)" = "$expected" ] || refused evidence
ssh_ok || refused firewall_ports
outside_ok || refused firewall_outside

if [ "$action" = remove ] && [ -z "$network" ]; then
  case ",$standard_rules," in
    *",$protocol:$port,"*) refused firewall_standard ;;
  esac
fi
if [ "$action" = remove ]; then
  want=$(rule_line)
  printf '%s\n' "$(ufw show added 2>/dev/null || true)" \
    | grep -Fxq "$want" || refused firewall_standard
fi

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
    printf '%s\n' "$output" | grep -q '^barectl-guard: refused ' && refused firewall_package
    case "$output" in *'Could not get lock'*) refused apt_active ;; esac
    refused firewall_package
  fi
  admitted=$(printf '%s\n' "$output" | grep -cx 'barectl-guard: admitted')
  [ "$status" -eq 0 ] && [ "$admitted" -eq 1 ] || refused firewall_package
  [ "$(dpkg-query -W -f='${Version}' "$versioned" 2>/dev/null || true)" = "$version" ] \
    || refused firewall_package
else
  [ -z "$guard" ] || refused evidence
fi

stage preimage
# FIREWALL_SAVE

# FIREWALL_ARM
[ "$(systemctl show -p ActiveState --value "$timer" 2>/dev/null || true)" = active ] \
  || { rm -rf -- "$revert"; refused revert_arm; }
armed=1

stage apply
if [ "$action" = on ]; then
  ufw_run default deny incoming || { result '{"class":"partial","reason":"firewall_apply"}'; exit 2; }
  ufw_run default allow outgoing || { result '{"class":"partial","reason":"firewall_apply"}'; exit 2; }
  ufw_run default deny routed || { result '{"class":"partial","reason":"firewall_apply"}'; exit 2; }
  ufw_run logging low || { result '{"class":"partial","reason":"firewall_apply"}'; exit 2; }
  for entry in $(printf '%s' "$standard_rules" | tr ',' ' '); do
    rule_protocol=${entry%%:*}
    rule_port=${entry#*:}
    ufw_run allow "$rule_port/$rule_protocol" \
      || { result '{"class":"partial","reason":"firewall_apply"}'; exit 2; }
  done
  ufw_run --force enable || { result '{"class":"partial","reason":"firewall_apply"}'; exit 2; }
elif [ "$action" = add ]; then
  if [ -n "$network" ]; then
    ufw_run allow from "$network" to any port "$port" proto "$protocol" \
      || { result '{"class":"partial","reason":"firewall_apply"}'; exit 2; }
  else
    ufw_run allow "$port/$protocol" \
      || { result '{"class":"partial","reason":"firewall_apply"}'; exit 2; }
  fi
else
  if [ -n "$network" ]; then
    ufw_run delete allow from "$network" to any port "$port" proto "$protocol" \
      || { result '{"class":"partial","reason":"firewall_apply"}'; exit 2; }
  else
    ufw_run delete allow "$port/$protocol" \
      || { result '{"class":"partial","reason":"firewall_apply"}'; exit 2; }
  fi
fi

stage verify
standard_ok || { result '{"class":"partial","reason":"firewall_verify"}'; exit 2; }
added=$(ufw show added 2>/dev/null || true)
want=$(rule_line)
if [ "$action" = add ]; then
  printf '%s\n' "$added" | grep -Fxq "$want" \
    || { result '{"class":"partial","reason":"firewall_verify"}'; exit 2; }
elif [ "$action" = remove ]; then
  if printf '%s\n' "$added" | grep -Fxq "$want"; then
    result '{"class":"partial","reason":"firewall_verify"}'
    exit 2
  fi
fi
result '{"class":"succeeded"}'
