#!/bin/sh
# shellcheck shell=sh
# shellcheck disable=SC2034
set -eu
reported=0
armed=0
result() { reported=1; printf 'barectl-result %s\n' "$1"; }
refused() { result "{\"class\":\"refused\",\"reason\":\"$1\"}"; exit 1; }
finish() {
  status=$?
  if [ "$reported" -eq 0 ] && [ "$status" -ne 0 ]; then
    result '{"class":"partial","reason":"sign_in_apply"}'
  fi
  if [ "$armed" -eq 1 ] && [ "$status" -ne 0 ]; then
    systemctl start -- "$service" >/dev/null 2>&1 || true
  fi
  rm -f -- "$0"
}
trap finish EXIT
trap 'result "{\"class\":\"timed_out\"}"; exit 3' TERM
stage() { printf 'barectl-stage %s\n' "$1"; }

expected=${1:?precondition digest}
root_policy=${2:?root policy}
client=${3:?client address}
local_address=${4:?local address}
local_port=${5:?local port}
accounts=${6:-}
id=${7:?run identifier}
case "$root_policy" in no|prohibit-password) ;; *) refused evidence ;; esac
case "$id" in *[!0-9a-f]*) refused evidence ;; esac
[ ${#id} -eq 32 ] || refused evidence
case "$client$local_address" in *[!0-9a-fA-F:.]*) refused evidence ;; esac
case "$local_port" in *[!0-9]*) refused evidence ;; esac
case "$accounts" in *[!a-z0-9_,$-]*) refused evidence ;; esac
revert=/run/barectl/revert-$id
timer=barectl-revert-$id.timer
service=barectl-revert-$id.service

# SIGN_IN_PRESTATE

policy_ok() {
  effective=$(sshd -T 2>/dev/null) || return 1
  printf '%s\n' "$effective" | grep -qx 'passwordauthentication no' || return 1
  printf '%s\n' "$effective" | grep -qx 'kbdinteractiveauthentication no' || return 1
  printf '%s\n' "$effective" | grep -qx "permitrootlogin $root_policy" || return 1
  old_ifs=$IFS
  IFS=,
  for name in $accounts; do
    IFS=$old_ifs
    case "$name" in *[!a-z0-9_$-]*|'') return 1 ;; esac
    effective=$(sshd -T -C "user=$name,host=$client,addr=$client,laddr=$local_address,lport=$local_port" 2>/dev/null) || return 1
    printf '%s\n' "$effective" | grep -qx 'passwordauthentication no' || return 1
    printf '%s\n' "$effective" | grep -qx 'kbdinteractiveauthentication no' || return 1
    if [ "$name" = root ]; then
      printf '%s\n' "$effective" | grep -qx "permitrootlogin $root_policy" || return 1
    fi
    IFS=,
  done
  IFS=$old_ifs
}

[ "$(id -u)" = 0 ] || refused privilege
os_id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
os_version=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
[ "$os_id" = ubuntu ] && [ "$os_version" = 26.04 ] || refused platform

stage preflight
[ "$(sign_in_prestate)" = "$expected" ] || refused evidence
[ ! -L /etc/ssh/sshd_config.d/00-barectl-sign-in.conf ] || refused evidence
sshd -t || refused sign_in_syntax

stage preimage
# SIGN_IN_SAVE
# SIGN_IN_ARM || refused revert_arm
armed=1

stage apply
umask 077
temporary=$(mktemp /etc/ssh/sshd_config.d/.barectl-sign-in.XXXXXXXX) || refused sign_in_apply
printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin %s\n' "$root_policy" > "$temporary" || refused sign_in_apply
install -o root -g root -m 0644 -- "$temporary" /etc/ssh/sshd_config.d/00-barectl-sign-in.conf || refused sign_in_apply
rm -f -- "$temporary"
sshd -t || refused sign_in_syntax
if [ "$(systemctl is-active ssh.service 2>/dev/null || true)" = active ]; then
  systemctl reload ssh.service || refused sign_in_reload
fi

stage verify
policy_ok || refused sign_in_verify
result '{"class":"succeeded"}'
