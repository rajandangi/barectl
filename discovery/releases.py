"""The supported Ubuntu releases' identity and default PHP version (CONTEXT.md, Supported release).

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

    @property
    def name(self) -> str:
        return f"Ubuntu {self.version}"


NOBLE = SupportedRelease("24.04", "noble", "8.3")
RESOLUTE = SupportedRelease("26.04", "resolute", "8.5")
SUPPORTED = {release.version: release for release in (NOBLE, RESOLUTE)}


def supported(os_id: str, version_id: str) -> SupportedRelease | None:
    return SUPPORTED.get(version_id) if os_id == "ubuntu" else None
