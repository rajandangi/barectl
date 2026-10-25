"""Valkey recognition, the reviewed precondition and the native steps of the install.

docs/target-architecture.md#valkey and
docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md. Passive
discovery reads the package and the distribution's unit from the same dpkg query and
``systemctl show`` a fresh controller reconstructs; the reviewed transaction, its digest
and the body's mask and verification steps are generated from the constants here, so the
review's wording and the body cannot drift.
"""

from dataclasses import dataclass
from typing import Final

from discovery.models import WebStackComponent
from discovery.snapshot import (
    CollectedSnapshot,
    Package,
    ServiceUnit,
    WebStackComponentObservation,
)

VALKEY: Final = "valkey"
LABEL: Final = "Valkey"
PACKAGE: Final = "valkey-server"
UNIT: Final = "valkey-server.service"
PORT: Final = 6379
CONFIG_ROOT: Final = "/etc/valkey"
DATA_ROOT: Final = "/var/lib/valkey"
MASK_PATH: Final = "/etc/systemd/system/valkey-server.service"


@dataclass(frozen=True)
class ValkeyObservation:
    """The reconstructed package set and distribution unit of one server."""

    version: str
    packages: tuple[Package, ...]
    units: tuple[ServiceUnit, ...]
    managed: bool
    deviations: tuple[str, ...]

    @property
    def present(self) -> bool:
        return bool(self.packages)

    @property
    def unit(self) -> ServiceUnit | None:
        return next((unit for unit in self.units if unit.name == UNIT), None)

    @property
    def masked(self) -> bool:
        unit = self.unit
        return unit is not None and unit.load_state == "masked" and unit.unit_file_state == "masked"

    @property
    def inactive(self) -> bool:
        unit = self.unit
        return unit is not None and unit.active_state == "inactive"


def _component(collected: CollectedSnapshot) -> WebStackComponentObservation | None:
    return next(
        (item for item in collected.components if item.component == WebStackComponent.VALKEY),
        None,
    )


def observation_of(collected: CollectedSnapshot) -> ValkeyObservation | None:
    """The server's Valkey observation, or ``None`` when no Valkey package is installed."""
    observed = _component(collected)
    if observed is None or not observed.package.value:
        return None
    version = next(
        (package.version for package in observed.package.value if package.name == PACKAGE),
        "",
    )
    return ValkeyObservation(
        version,
        observed.package.value,
        observed.service.value,
        observed.managed,
        observed.deviations,
    )


def installed(collected: CollectedSnapshot) -> ValkeyObservation | None:
    """The reusable "Valkey is installed" read for a site screen (#392/#393)."""
    observed = observation_of(collected)
    return observed if observed is not None and observed.present else None


def outside_supported(collected: CollectedSnapshot) -> tuple[str, ...]:
    """Why the server's Valkey packages are outside supported settings for a change."""
    observed = _component(collected)
    return () if observed is None else observed.deviations


def digest_command() -> str:
    """The precondition digest the review records and the native body recomputes.

    It covers dpkg's status and automatic marks, APT's Release files and downloaded index
    names, sizes and modification times, the distribution's unit, the package's
    configuration tree, its data directory and any TCP listener on the package's port.
    """
    parts = [
        "sha256sum /var/lib/dpkg/status /var/lib/apt/extended_states",
        (
            "find /var/lib/apt/lists -maxdepth 1 -type f -name '*_InRelease' "
            "-exec sha256sum -- {} + | LC_ALL=C sort"
        ),
        (
            "find /var/lib/apt/lists -maxdepth 1 -type f ! -name lock "
            "-printf '%f %s %T@\\n' | LC_ALL=C sort"
        ),
        f"systemctl show -p Id -p LoadState -p ActiveState -p UnitFileState {UNIT}",
        f"find {CONFIG_ROOT} -xdev -printf '%y %p %l\\n' | LC_ALL=C sort",
        f"find {CONFIG_ROOT} -xdev -type f -exec sha256sum -- {{}} + | LC_ALL=C sort",
        f"ss -Hltn 'sport = :{PORT}' | awk '{{print $4}}' | LC_ALL=C sort",
        f"stat -c '%F %U %n' {CONFIG_ROOT} {DATA_ROOT}",
    ]
    return "{ " + "; ".join(parts) + "; } 2>/dev/null | sha256sum"


def body_functions() -> str:
    """The fixed shell functions the install body runs, generated from the constants above."""
    return f"""valkey_digest() {{
  {digest_command()}
}}
valkey_mask() {{
  [ ! -L {MASK_PATH} ] || [ "$(readlink {MASK_PATH})" = /dev/null ] || return 1
  systemctl mask --now {UNIT} || return 1
  systemctl daemon-reload || return 1
  [ "$(systemctl show -p LoadState --value {UNIT})" = masked ] || return 1
  [ "$(systemctl show -p UnitFileState --value {UNIT})" = masked ] || return 1
  [ "$(systemctl show -p ActiveState --value {UNIT})" = inactive ] || return 1
  [ -z "$(ss -Hltn 'sport = :{PORT}')" ] || return 1
}}
valkey_restart() {{
  systemctl is-active --quiet -- "$1" || return 0
  systemctl restart -- "$1" || return 1
  printf 'barectl-restarted %s\\n' "$1"
}}
valkey_recover() {{
  for unit in php-fpm@php84.service php-fpm@php85.service; do
    valkey_restart "$unit" || return 1
  done
  for cfg in /etc/haproxy/sites/*.cfg; do
    [ -e "$cfg" ] || continue
    identifier=${{cfg##*/}}
    identifier=${{identifier%.cfg}}
    case "$identifier" in
      [a-z][a-z0-9][a-z0-9]*) ;;
      *) continue ;;
    esac
    valkey_restart "haproxy-site@$identifier.service" || return 1
    for entry in php84 php85; do
      valkey_restart "php-fpm-site-$entry@$identifier.service" || return 1
    done
  done
}}
valkey_verify() {{
  expected=$1
  [ "$(systemctl show -p LoadState --value {UNIT})" = masked ] || return 1
  [ "$(systemctl show -p UnitFileState --value {UNIT})" = masked ] || return 1
  [ "$(systemctl show -p ActiveState --value {UNIT})" = inactive ] || return 1
  [ -z "$(ss -Hltn 'sport = :{PORT}')" ] || return 1
  [ "$(dpkg-query -W -f='${{Version}}' {PACKAGE})" = "$expected" ] || return 1
}}
"""


def verification_command(version: str) -> str:
    """The fixed root read that proves the reviewed state still holds on the server."""
    if not version.isascii() or not version:
        raise ValueError("Not a reviewed Valkey version.")
    return body_functions() + f"\nvalkey_verify '{version}'"
