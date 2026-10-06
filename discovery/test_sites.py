"""Site recognition rules (docs/ssh-connections.md#site-observations), through ``collect``.

Each test starts from a site that meets docs/site-conventions.md, as an administrator made
it by hand, and changes the server the way the documented case describes.
"""

from typing import override

from sites.convention import Stage, render_pool, render_site

from . import ssh
from .fakes import (
    AVAILABLE_DIR,
    PACKAGE_QUERY,
    PHP_DIR,
    SITE_DIR,
    ObservationTestCase,
    SitePoolFixtures,
    add_site,
    pool_config,
    site_config,
)
from .snapshot import ObservedSite

NAMES = ("alpha.test", "www.alpha.test")
ALPHA = f"{AVAILABLE_DIR}/alpha.conf"
ALPHA_POOL = f"{PHP_DIR}/8.3/fpm/pool.d/alpha.conf"
SOCKET = "/run/php/salpha.sock"


class SiteTests(SitePoolFixtures, ObservationTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        add_site(self.remote)

    def site(self, identifier: str = "alpha") -> ObservedSite:
        sites = self.collect().sites
        (found,) = (site for site in sites.value if site.identifier == identifier)
        return found

    def sites(self) -> dict[str, ObservedSite]:
        return {site.identifier: site for site in self.collect().sites.value}

    def add_enabled(self, name: str, content: str) -> None:
        self.remote.files[f"{SITE_DIR}/{name}"] = content
        listing = self.remote.directories.setdefault(SITE_DIR, [])
        if name not in listing:
            listing.append(name)

    def add_pool(self, name: str, content: str) -> None:
        pool_dir = f"{PHP_DIR}/8.3/fpm/pool.d"
        self.remote.files[f"{pool_dir}/{name}"] = content
        listing = self.remote.directories.setdefault(pool_dir, [])
        if name not in listing:
            listing.append(name)

    def test_a_hand_made_site_meeting_the_convention_is_managed(self) -> None:
        site = self.site()
        self.assertEqual(site.state, "managed", (site.file, site.expected, site.missing))
        self.assertEqual(site.outcome, "observed")
        self.assertEqual(site.server_names, NAMES)
        self.assertEqual(site.php_version, "8.3")
        self.assertEqual(site.account and site.account.home, "/var/www/alpha")
        self.assertEqual(site.file, "")
        self.assertEqual(site.expected, "")
        self.assertEqual(site.missing, ())
        self.assertEqual(self.collected.sites.outcome, "observed")
        # Nothing a pool file holds beyond the convention is kept.
        self.assert_not_kept("hunter2", "env[", "autoindex on")

    def test_a_site_with_every_existing_resource_exact_is_partly_applied(self) -> None:
        del self.remote.files[ALPHA_POOL]
        site = self.site()
        self.assertEqual(site.state, "partly_applied")
        self.assertEqual(site.outcome, "observed")
        self.assertEqual(site.missing, (ALPHA_POOL,))
        self.assertEqual(site.file, "")

    def test_a_missing_socket_is_partly_applied(self) -> None:
        self.remote.sockets.clear()
        self.assertEqual(self.site().state, "partly_applied")
        self.assertIn(SOCKET, self.site().missing)

    def test_a_changed_site_file_names_the_file_and_offers_the_expected_content(self) -> None:
        self.remote.files[ALPHA] = self.remote.files[ALPHA].replace(
            "\troot /var/www/alpha/public;", "\troot /var/www/other/public;"
        )
        site = self.site()
        self.assertEqual(site.state, "changed")
        self.assertEqual(site.file, ALPHA)
        self.assertEqual(site.expected, render_site("alpha", NAMES, ipv6=True))
        self.assertEqual(site.missing, ())

    def test_a_changed_pool_file_names_the_pool(self) -> None:
        self.remote.files[ALPHA_POOL] = pool_config("alpha").replace("0600", "0660")
        site = self.site()
        self.assertEqual(site.state, "changed")
        self.assertEqual(site.file, ALPHA_POOL)
        self.assertEqual(site.expected, render_pool("alpha"))

    def test_a_changed_account_names_the_account(self) -> None:
        self.remote.results["getent passwd salpha"] = ssh.CommandResult(
            0, "salpha:x:1001:1001::/home/salpha:/usr/sbin/nologin\n"
        )
        site = self.site()
        self.assertEqual(site.state, "changed")
        self.assertEqual(site.file, "salpha")
        self.assertEqual(site.account and site.account.home, "/home/salpha")

    def test_ssh_keys_in_the_home_are_changed(self) -> None:
        self.remote.directories["/var/www/alpha/.ssh"] = []
        site = self.site()
        self.assertEqual(site.state, "changed")
        self.assertEqual(site.file, "/var/www/alpha/.ssh")

    def test_an_inaccessible_resource_keeps_its_outcome_and_is_not_changed(self) -> None:
        self.remote.unreadable.add(ALPHA_POOL)
        site = self.site()
        self.assertEqual(site.outcome, "inaccessible")
        self.assertNotEqual(site.state, "changed")
        self.assertEqual(site.file, "")

    def test_an_unreadable_password_lock_is_inaccessible_and_not_drift(self) -> None:
        self.remote.unreadable.add("/etc/shadow")
        site = self.site()
        self.assertEqual(site.outcome, "inaccessible")
        self.assertNotEqual(site.state, "changed")
        self.assertIsNotNone(site.account)

    def test_a_foreign_enabled_file_is_one_blocked_item_with_its_names(self) -> None:
        self.add_enabled("legacy", "server {\n  listen 80;\n  server_name legacy.test;\n}\n")
        sites = self.sites()
        blocked = sites[""]
        self.assertEqual(blocked.state, "not_following")
        self.assertEqual(blocked.outcome, "observed")
        self.assertEqual(blocked.file, f"{SITE_DIR}/legacy")
        self.assertEqual(blocked.server_names, ("legacy.test",))
        # A managed Barectl site stays managed beside the foreign item.
        self.assertEqual(sites["alpha"].state, "managed")

    def test_a_foreign_file_declaring_a_managed_site_name_is_only_blocked(self) -> None:
        self.add_enabled("legacy", "server {\n  listen 80;\n  server_name alpha.test;\n}\n")
        sites = self.sites()
        self.assertEqual(sites[""].server_names, ("alpha.test",))
        self.assertEqual(sites["alpha"].state, "managed")

    def test_a_foreign_pool_file_is_one_blocked_item(self) -> None:
        self.add_pool("custom.conf", "[custom]\nlisten = /run/php/php8.3-fpm.sock\n")
        blocked = self.sites()[""]
        self.assertEqual(blocked.state, "not_following")
        self.assertEqual(blocked.file, f"{PHP_DIR}/8.3/fpm/pool.d/custom.conf")
        self.assertEqual(blocked.server_names, ())

    def test_the_distribution_pool_is_never_reported(self) -> None:
        self.add_pool("www.conf", "[www]\nlisten = /run/php/php8.3-fpm.sock\n")
        self.assertEqual([site for site in self.sites() if site], ["alpha"])

    def test_fixing_a_foreign_file_into_the_convention_recognizes_it(self) -> None:
        self.add_enabled("legacy", "server {\n  listen 80;\n  server_name legacy.test;\n}\n")
        self.assertEqual(self.sites()[""].file, f"{SITE_DIR}/legacy")
        # The operator replaces it with the convention's source, link and pool.
        del self.remote.files[f"{SITE_DIR}/legacy"]
        self.remote.directories[SITE_DIR].remove("legacy")
        add_site(self.remote, "legacy", ("legacy.test",))
        sites = self.sites()
        self.assertNotIn("", sites)
        self.assertEqual(sites["legacy"].state, "managed", sites["legacy"].expected)

    def test_main_configuration_and_foreign_values_are_never_read(self) -> None:
        self.remote.files["/etc/nginx/nginx.conf"] = "include /srv/other/*.conf;\n"
        self.remote.files["/etc/php/8.3/fpm/php-fpm.conf"] = "include=/srv/pools/*.conf\n"
        self.remote.files["/etc/nginx/conf.d/extra.conf"] = "server_tokens off;\n"
        self.remote.commands.clear()
        site = self.site()
        self.assertEqual(site.state, "managed", site.expected)
        for command in ("/etc/nginx/nginx.conf", "/etc/php/8.3/fpm/php-fpm.conf", "conf.d"):
            self.assertFalse([c for c in self.remote.commands if command in c])

    def test_an_available_candidate_that_differs_is_changed_not_foreign(self) -> None:
        add_site(self.remote, "beta", ("beta.test",))
        self.remote.files[f"{AVAILABLE_DIR}/beta.conf"] = site_config(
            "beta", ("beta.test",)
        ).replace("\troot /var/www/beta/public;", "\troot /var/www/other/public;")
        sites = self.sites()
        self.assertEqual(sites["beta"].state, "changed")
        self.assertEqual(sites["beta"].file, f"{AVAILABLE_DIR}/beta.conf")
        self.assertNotIn("", sites)

    def test_reserved_names_are_never_candidates(self) -> None:
        for name in ("www", "html"):
            self.remote.files[f"{AVAILABLE_DIR}/{name}.conf"] = "server {}\n"
            self.remote.directories[AVAILABLE_DIR].append(f"{name}.conf")
        self.assertEqual([site for site in self.sites() if site], ["alpha"])

    def test_names_that_are_not_site_identifiers_are_foreign(self) -> None:
        for name in ("ab.conf", "Alpha2.conf", "1site.conf", "a-b.conf"):
            self.add_enabled(name, "server {}\n")
        self.assertEqual([site for site in self.sites() if site], ["alpha"])

    def test_a_server_without_sites_is_observed_empty(self) -> None:
        self.remote = type(self.remote)()
        sites = self.collect().sites
        self.assertEqual((sites.outcome, sites.value), ("observed", ()))
        self.assertIn("is named like a site", sites.warning)

    def test_unlisted_sites_enabled_leaves_sites_uninspected(self) -> None:
        self.remote.unreadable.add(SITE_DIR)
        sites = self.collect().sites
        self.assertEqual((sites.outcome, sites.value), ("inaccessible", ()))

    def test_the_dpkg_database_decides_whether_sites_are_read(self) -> None:
        cases = {
            "nginx not installed": (ssh.CommandResult(0, "php8.3-fpm 8.3.6 ii \n"), "absent"),
            "dpkg unreadable": (ssh.CommandResult(126, ""), "inaccessible"),
        }
        for case, (packages, outcome) in cases.items():
            with self.subTest(case):
                self.remote.commands.clear()
                self.remote.results[PACKAGE_QUERY] = packages
                sites = self.collect().sites
                self.assertEqual((sites.outcome, sites.value), (outcome, ()))

    def test_an_unsupported_release_has_no_site_convention(self) -> None:
        self.remote.files["/etc/os-release"] = 'ID=debian\nVERSION_ID="12"\nNAME="Debian"\n'
        sites = self.collect().sites
        self.assertEqual((sites.outcome, sites.value), ("unsupported", ()))

    def test_candidates_beyond_the_cap_are_not_inspected(self) -> None:
        names = [f"site{index:03d}.conf" for index in range(51)]
        self.remote.directories[AVAILABLE_DIR] = names
        for name in names:
            self.remote.files[f"{AVAILABLE_DIR}/{name}"] = "server {}\n"
        sites = self.collect().sites
        self.assertIn("Only the first 50 were inspected.", sites.warning)

    def test_every_released_site_file_form_is_managed(self) -> None:
        for stage in Stage:
            with self.subTest(stage=stage.value):
                self.activate_site("alpha", NAMES, stage=stage)
                site = self.site()
                self.assertEqual(site.stage.value, stage.value)
                self.assertEqual(site.state, "managed", (site.file, site.expected))

    def test_an_activated_site_records_its_lineage_references(self) -> None:
        self.activate_site("alpha", NAMES)
        site = self.site()
        self.assertEqual(site.certificate_reference, "/etc/letsencrypt/live/alpha/fullchain.pem")
        self.assertEqual(site.certificate_key_reference, "/etc/letsencrypt/live/alpha/privkey.pem")
        self.assertFalse([command for command in self.remote.commands if "privkey" in command])
        self.activate_site("alpha", NAMES, stage=Stage.HTTP)
        self.assertIsNone(self.site().certificate)
