# shellcheck shell=sh
# docs/bootstrap.md#host-foundation
foundation_digest() {
  {
    cat /etc/os-release
    uname -m
    dpkg-query -W -f='${Package} ${db:Status-Status}\n' | LC_ALL=C sort
    getent passwd | awk -F: '$3>=30001 && $3<=30032 || $1=="caddy" {print}'
    getent group | awk -F: '$1=="nixbld" || $1=="caddy" {print}'
    for path in /etc/nix/nix.conf /etc/caddy/Caddyfile /etc/systemd/system/caddy.service \
      /etc/systemd/journald.conf.d/50-barectl.conf; do
      if [ -f "$path" ] && [ ! -L "$path" ]; then sha256sum "$path"; else printf 'missing %s\n' "$path"; fi
    done
    for entry in caddy composer wp-cli; do
      readlink -f "/nix/var/nix/profiles/barectl/$entry" || printf 'missing %s\n' "$entry"
    done
    ss -Hlnpt '( sport = :80 or sport = :443 )' | LC_ALL=C sort
  } | sha256sum | cut -d' ' -f1
}
foundation_read() {
  printf 'digest\t%s\n' "$(foundation_digest)"
  printf 'boot\t%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
  printf 'uptime\t%s\n' "$(cut -d' ' -f1 /proc/uptime | tr -d .)"
  printf 'architecture\t%s\n' "$(uname -m)"
  for entry in caddy composer wp-cli; do
    printf '%s\t%s\n' "$entry" "$(readlink -f "/nix/var/nix/profiles/barectl/$entry" || true)"
  done
  printf 'daemon\t%s\n' "$(systemctl is-active nix-daemon.service || true)"
  nixstore=/nix/var/nix/profiles/default/bin/nix-store
  if [ -x "$nixstore" ] && getent passwd nixbld1 >/dev/null; then
    if runuser -u nixbld1 -- "$nixstore" --store daemon -q --references \
      /nix/var/nix/profiles/barectl/caddy >/dev/null 2>&1; then
      printf 'daemon_restricted\tno\n'
    elif "$nixstore" --store daemon -q --references \
      /nix/var/nix/profiles/barectl/caddy >/dev/null 2>&1 && \
      journalctl -u nix-daemon.service -n 20 --no-pager -o cat \
      --grep="user 'nixbld1' is not allowed to connect to the Nix daemon" \
      | grep -q "user 'nixbld1' is not allowed to connect to the Nix daemon"; then
      printf 'daemon_restricted\tyes\n'
    else printf 'daemon_restricted\tunknown\n'; fi
  fi
  printf 'caddy_state\t%s\n' "$(systemctl is-active caddy.service || true)"
  printf 'socket\t%s\n' "$(stat -c '%a' /run/caddy/admin.sock 2>/dev/null || true)"
  printf 'runtime\t%s\n' "$(stat -c '%a' /run/caddy 2>/dev/null || true)"
  printf 'journal\t%s\n' "$(systemd-analyze cat-config systemd/journald.conf | sed -n 's/^Storage=//p' | tail -1)"
  caddy=/nix/var/nix/profiles/barectl/caddy/bin/caddy
  if [ -x "$caddy" ] && [ -f /etc/caddy/Caddyfile ]; then
    if "$caddy" validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
      printf 'caddy_valid\tyes\n'
      printf 'caddy_json\t%s\n' "$("$caddy" adapt --config /etc/caddy/Caddyfile --adapter caddyfile 2>/dev/null)"
    else printf 'caddy_valid\tno\n'; fi
    printf 'caddy_running_json\t%s\n' "$(curl --silent --fail \
      --unix-socket /run/caddy/admin.sock http://localhost/config/ || true)"
    printf 'caddy_version\t%s\n' "$("$caddy" version)"
    main=$(systemctl show --value -p MainPID caddy.service)
    if [ "$main" -gt 0 ] 2>/dev/null; then
      printf 'caddy_executable\t%s\n' "$(readlink -f "/proc/$main/exe")"
      printf 'caddy_pid\t%s\n' "$main"
    fi
  fi
}
