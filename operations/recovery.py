"""Restart the units a package transaction's daemon-reload unbinds (#428).

docs/databases.md#restarting-units-after-the-package-transaction-428.
"""

from typing import Final

UNIT_PATTERNS: Final = (
    "php-fpm@*.service",
    "php-fpm-site-*@*.service",
    "haproxy-site@*.service",
)
DETAIL: Final = (
    "The running units a package transaction's daemon-reload unbinds ("
    + ", ".join(UNIT_PATTERNS)
    + "), so discovery still verifies their loaded state."
)
POSTCONDITION: Final = (
    "Every running PHP master and site proxy was restarted after the package database "
    "changed, so discovery still verifies them."
)


def shell() -> str:
    """The fixed shell the package bodies run before they verify their state."""
    patterns = " | ".join(UNIT_PATTERNS)
    return f"""restart_affected_units() {{
  units=$(systemctl list-units --type=service --state=running --no-legend --plain) || return 1
  while read -r unit _; do
    case "$unit" in
      {patterns}) ;;
      *) continue ;;
    esac
    systemctl restart -- "$unit" || return 1
    printf 'barectl-restarted %s\\n' "$unit"
  done <<EOF
$units
EOF
}}
"""


def runtime_masters_shell() -> str:
    """The shell form of ``runtimes/bodies/masters.py`` for the shell bodies that reload.

    docs/runtimes.md#restarting-the-runtime-masters-after-a-systemd-reload. Only the
    runtime masters restart; a failed restart leaves the master as systemd reports it.
    """
    return """restart_runtime_masters() {
  masters=$(systemctl list-units --type=service --state=running --no-legend --plain \\
    'php-fpm@*.service') || return 0
  while read -r unit _; do
    case "$unit" in
      php-fpm@php[0-9][0-9].service) ;;
      *) continue ;;
    esac
    if systemctl restart -- "$unit"; then printf 'barectl-restarted %s\\n' "$unit"; fi
  done <<EOF
$masters
EOF
}
"""
