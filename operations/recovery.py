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
