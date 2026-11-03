"""Restart the running units a package transaction's ``daemon-reload`` unbinds (#428).

A package transaction clears the loaded-execution metadata of every running unit, so the
foundation's diagnostic PHP masters and each site's PHP master and proxy read as
unverifiable on the next discovery even though they serve traffic. Both package-install
bodies embed the one fixed shell below; it discovers the running units from systemd itself,
restarts exactly the affected ones, and prints each restarted unit to the run's journal.
The server's running units stay authoritative: Barectl writes no marker.
"""

from typing import Final

# The templates a package transaction's daemon-reload affects: the foundation's diagnostic
# PHP masters, each site's PHP master and each site's proxy.
UNIT_PATTERNS: Final = (
    "php-fpm@*.service",
    "php-fpm-site-*@*.service",
    "haproxy-site@*.service",
)
DETAIL: Final = (
    "The running PHP masters (php-fpm@*.service), each site's PHP master "
    "(php-fpm-site-*@*.service) and each site's proxy (haproxy-site@*.service), so discovery "
    "still verifies their loaded state."
)
POSTCONDITION: Final = (
    "Every running PHP master and site proxy was restarted after the package database "
    "changed, so discovery still verifies them."
)


def shell() -> str:
    """The fixed shell both package-install bodies run before they verify their state."""
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
