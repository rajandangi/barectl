"""The supported Ubuntu releases' identity and default PHP and MariaDB versions (CONTEXT.md,
Supported release).

Discovery reads them to locate a site's pool; ``bootstrap/releases.py`` builds each
release's review policy on them.
"""

from typing import NamedTuple


class SupportedRelease(NamedTuple):
    # /etc/os-release's VERSION_ID, such as "24.04".
    version: str
    codename: str
    # The PHP version the release's php-defaults package selects, such as "8.3".
    php: str
    # The MariaDB series the release's mariadb-server package installs, such as "10.11",
    # and the data directory that package initializes.
    mariadb: str
    mariadb_data: str

    @property
    def name(self) -> str:
        return f"Ubuntu {self.version}"


NOBLE = SupportedRelease("24.04", "noble", "8.3", "10.11", "/var/lib/mysql")
RESOLUTE = SupportedRelease("26.04", "resolute", "8.5", "11.8", "/var/lib/mariadb")
SUPPORTED = {release.version: release for release in (NOBLE, RESOLUTE)}


def supported(os_id: str, version_id: str) -> SupportedRelease | None:
    return SUPPORTED.get(version_id) if os_id == "ubuntu" else None
