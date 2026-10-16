"""The supported Ubuntu release's identity and default PHP, MariaDB and PostgreSQL versions
(GLOSSARY.md, Supported release).

Discovery names the release's distribution packages when it reports another web stack.
"""

from typing import NamedTuple


class SupportedRelease(NamedTuple):
    # /etc/os-release's VERSION_ID, such as "26.04".
    version: str
    codename: str
    # The PHP version the release's php-defaults package selects, such as "8.5".
    php: str
    # The MariaDB series the release's mariadb-server package installs, such as "11.8".
    mariadb: str
    # The PostgreSQL major the release's postgresql package selects, such as "18".
    postgresql: str

    @property
    def name(self) -> str:
        return f"Ubuntu {self.version}"


RESOLUTE = SupportedRelease("26.04", "resolute", "8.5", "11.8", "18")
SUPPORTED = {release.version: release for release in (RESOLUTE,)}
# The APT PHP branches discovery names when it reports a foreign PHP installation
# (docs/bootstrap.md#host-standing).
ELIGIBLE_BRANCHES = ("8.3", "8.4", "8.5")


def supported(os_id: str, version_id: str) -> SupportedRelease | None:
    return SUPPORTED.get(version_id) if os_id == "ubuntu" else None
