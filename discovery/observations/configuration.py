"""The Debian configuration directories site recognition reads.

docs/adr/0015-recognize-only-the-convention.md
"""

from dataclasses import dataclass

from ..ssh import RemoteShell
from .probes import _Failed, _list_directory, _outside_layout

SITES_ENABLED_DIR = "/etc/nginx/sites-enabled"
SITES_AVAILABLE_DIR = "/etc/nginx/sites-available"
PHP_BASE_DIR = "/etc/php"
POOL_SUBPATH = "fpm/pool.d"


@dataclass(frozen=True)
class ListedDirectory:
    """One configuration directory, its entries, or why it could not be listed."""

    path: str
    names: tuple[str, ...] = ()
    failure: _Failed | None = None

    @property
    def listed(self) -> bool:
        return self.failure is None


def _list(shell: RemoteShell, path: str) -> ListedDirectory:
    entries = _list_directory(shell, path)
    if isinstance(entries, _Failed):
        return ListedDirectory(path, (), _outside_layout(entries))
    return ListedDirectory(path, tuple(entries))


def _collect_nginx_sites(shell: RemoteShell) -> tuple[ListedDirectory, ListedDirectory]:
    return _list(shell, SITES_ENABLED_DIR), _list(shell, SITES_AVAILABLE_DIR)


def _collect_php_pools(shell: RemoteShell, version: str) -> ListedDirectory:
    return _list(shell, f"{PHP_BASE_DIR}/{version}/{POOL_SUBPATH}")
