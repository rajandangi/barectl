"""The Debian directories site recognition reads, through ``collect``."""

from typing import override

from .fakes import (
    AVAILABLE_DIR,
    PHP_DIR,
    SITE_DIR,
    ObservationTestCase,
    SitePoolFixtures,
    add_site,
)
from .observations.configuration import POOL_SUBPATH

POOL_DIRS = tuple(f"{PHP_DIR}/{branch}/{POOL_SUBPATH}" for branch in ("8.3", "8.4", "8.5"))


class ConfigurationTests(SitePoolFixtures, ObservationTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        add_site(self.remote)

    def test_recognition_names_only_nginx_and_eligible_branch_directories(self) -> None:
        self.collect()
        self.assertEqual(self.collected.sites.source, (SITE_DIR, AVAILABLE_DIR, *POOL_DIRS))

    def test_an_ineligible_branch_pool_directory_is_not_read(self) -> None:
        self.install_php_fpm("8.1", "8.5")
        self.enable_pools("8.1", {"other.conf": "[other]\nlisten = /run/php/other.sock\n"})
        self.remote.commands.clear()
        site = self.collected.sites.value[0] if self.collect().sites.value else None
        self.assertIsNotNone(site)
        self.assertFalse([c for c in self.remote.commands if f"{PHP_DIR}/8.1" in c])

    def test_an_empty_server_lists_its_directories(self) -> None:
        self.remote = type(self.remote)()
        sites = self.collect().sites
        self.assertEqual((sites.outcome, sites.value), ("observed", ()))
        self.assertIn("is named like a site", sites.warning)

    def test_an_unreadable_sites_enabled_is_inaccessible(self) -> None:
        self.remote.unreadable.add(SITE_DIR)
        sites = self.collect().sites
        self.assertEqual((sites.outcome, sites.value), ("inaccessible", ()))
        self.assertIn(SITE_DIR, sites.warning)

    def test_an_installed_server_without_the_debian_layout_is_unsupported(self) -> None:
        self.remote.directories.clear()
        self.remote.links.clear()
        self.remote.sockets.clear()
        for path in [path for path in self.remote.files if path.startswith("/etc/nginx")]:
            del self.remote.files[path]
        sites = self.collect().sites
        self.assertEqual((sites.outcome, sites.value), ("unsupported", ()))
        self.assertIn(f"The server has no {SITE_DIR}", sites.warning)
