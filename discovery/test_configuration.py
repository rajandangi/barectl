"""Nginx site file and PHP-FPM pool observations, tested through ``collect``."""

from . import ssh
from .fakes import (
    NGINX_CONF,
    NGINX_CONF_TEXT,
    PACKAGE_QUERY,
    PHP_DIR,
    SITE_DIR,
    ObservationTestCase,
    SitePoolFixtures,
    fpm_conf_path,
    kept_text,
    php_fpm_conf,
)


class SitePoolTests(SitePoolFixtures, ObservationTestCase):
    def test_sites_and_pools_are_collected_with_provenance_and_time(self) -> None:
        self.enable_sites({"example.com": self.EXAMPLE_SITE, "default": self.DEFAULT_SITE})
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        collected = self.collect()
        sites, pools = collected.nginx_site_files, collected.php_fpm_pools
        self.assertEqual(sites.outcome, "observed")
        self.assertEqual(sites.source, (SITE_DIR,))
        self.assertEqual([site.name for site in sites.value], ["example.com", "default"])
        example = sites.value[0]
        self.assertEqual(example.outcome, "observed")
        self.assertEqual(example.server_names, ("example.com",))
        self.assertEqual(example.listens, ("443",))
        self.assertEqual(example.source, f"{SITE_DIR}/example.com")
        self.assertEqual(sites.value[1].listens, ("80",))
        self.assertEqual([(pool.version, pool.name) for pool in pools.value], [("8.3", "www")])
        (pool,) = pools.value
        self.assertEqual((pool.outcome, pool.listen), ("observed", "/run/php/php8.3-fpm.sock"))
        self.assertEqual(pool.source, f"{PHP_DIR}/8.3/fpm/pool.d/www.conf")
        self.assertEqual(pools.outcome, "observed")
        # The pool directory Barectl listed, not /etc/php, which it does not read.
        self.assertEqual(pools.source, (f"{PHP_DIR}/8.3/fpm/pool.d",))
        # Safe fields only: the TLS certificate path, pool user and secret environment
        # values are never kept.
        self.assert_not_kept(
            "ssl_certificate", "/etc/ssl/example.pem", "hunter2", "www-data", "soap"
        )

    def assert_nothing_read_under(self, *paths: str) -> None:
        self.assertFalse([c for c in self.remote.commands if any(p in c for p in paths)])

    def test_uninstalled_components_have_absent_sites_and_pools_without_reads(self) -> None:
        # Nginx was removed without purging (dpkg state rc), leaving its site files behind.
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(
            1, "nginx 1.24.0-2ubuntu7.18 rc \nphp8.3-fpm 8.3.6-0ubuntu0.24.04.11 rc \n"
        )
        self.enable_sites({"example.com": self.EXAMPLE_SITE})
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        collected = self.collect()
        sites, pools = collected.nginx_site_files, collected.php_fpm_pools
        self.assertEqual((sites.outcome, pools.outcome), ("absent", "absent"))
        self.assertEqual((sites.source, pools.source), ((PACKAGE_QUERY,), (PACKAGE_QUERY,)))
        self.assertEqual(
            (sites.warning, pools.warning),
            (
                "The dpkg database lists no installed Nginx packages.",
                "The dpkg database lists no installed PHP-FPM packages.",
            ),
        )
        self.assertFalse(sites.value)
        self.assertFalse(pools.value)
        self.assert_nothing_read_under(SITE_DIR, PHP_DIR)

    def test_uninspectable_packages_leave_sites_and_pools_uninspected(self) -> None:
        for exit_status, outcome in ((127, "unsupported"), (126, "inaccessible")):
            with self.subTest(exit_status=exit_status):
                self.remote.commands.clear()
                self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(exit_status, "")
                self.enable_sites({"example.com": self.EXAMPLE_SITE})
                collected = self.collect()
                sites, pools = collected.nginx_site_files, collected.php_fpm_pools
                self.assertEqual((sites.outcome, pools.outcome), (outcome, outcome))
                self.assertEqual(
                    (self.component("nginx").service.source, sites.source, pools.source),
                    ((PACKAGE_QUERY,), (PACKAGE_QUERY,), (PACKAGE_QUERY,)),
                )
                self.assertFalse(sites.value)
                self.assert_nothing_read_under(SITE_DIR, PHP_DIR)

    def test_installed_components_without_the_debian_layout_are_unsupported(self) -> None:
        # Nginx and PHP-FPM are installed, but keep their configuration elsewhere.
        self.remote.directories.clear()
        collected = self.collect()
        sites, pools = collected.nginx_site_files, collected.php_fpm_pools
        self.assertEqual((sites.outcome, pools.outcome), ("unsupported", "unsupported"))
        self.assertFalse(sites.value)
        self.assertFalse(pools.value)
        self.assertEqual(
            sites.warning, f"The server has no {SITE_DIR}. Barectl reads only the Debian layout."
        )
        self.assertIn(
            f"The server has no {PHP_DIR}/8.3/fpm/pool.d. Barectl reads only the Debian layout.",
            pools.warning,
        )
        self.assert_nothing_absent()

    def test_sites_are_read_only_when_nginx_conf_includes_the_directory(self) -> None:
        self.enable_sites({"example.com": self.EXAMPLE_SITE})
        cases = {
            # The include was commented out, so Nginx does not load sites-enabled.
            "commented": NGINX_CONF_TEXT.replace(
                "\tinclude /etc/nginx/sites-enabled/*;", "\t# include /etc/nginx/sites-enabled/*;"
            ),
            # Loaded from another directory instead.
            "elsewhere": NGINX_CONF_TEXT.replace("sites-enabled/*", "vhosts/*"),
            # Outside the http block, where it does not load server blocks.
            "outside http": NGINX_CONF_TEXT.replace("\tinclude /etc/nginx/sites-enabled/*;\n", "")
            + "include /etc/nginx/sites-enabled/*;\n",
        }
        for case, text in cases.items():
            with self.subTest(case):
                self.remote.commands.clear()
                self.remote.files[NGINX_CONF] = text
                sites = self.collect().nginx_site_files
                self.assertEqual((sites.outcome, sites.source), ("unsupported", (NGINX_CONF,)))
                self.assertFalse(sites.value)
                self.assert_nothing_read_under(SITE_DIR)
                self.assertEqual(
                    sites.warning,
                    "/etc/nginx/nginx.conf does not include /etc/nginx/sites-enabled/*, so "
                    "Barectl cannot confirm which files it loads. Barectl reads only the "
                    "Debian layout.",
                )

    def test_an_uninspectable_nginx_conf_leaves_sites_unread(self) -> None:
        self.enable_sites({"example.com": self.EXAMPLE_SITE})
        # Per case: the file's contents (None when there is none), whether the SSH user is
        # refused it, the outcome and the warning.
        cases = {
            "missing": (None, False, "unsupported", f"The server has no {NGINX_CONF}."),
            "unreadable": (None, True, "inaccessible", f"The SSH user cannot read {NGINX_CONF}."),
            "unparseable": (
                "http {\n  include x\n",
                False,
                "unsupported",
                f"{NGINX_CONF} is not in a supported",
            ),
        }
        for case, (text, refused, outcome, warning) in cases.items():
            with self.subTest(case):
                self.remote.commands.clear()
                self.remote.files.pop(NGINX_CONF, None)
                if text is not None:
                    self.remote.files[NGINX_CONF] = text
                self.remote.unreadable = {NGINX_CONF} if refused else set()
                sites = self.collect().nginx_site_files
                self.assertEqual(sites.outcome, outcome)
                self.assert_nothing_read_under(SITE_DIR)
                self.assertIn(warning, sites.warning)
                self.assert_not_kept("include x")

    def test_pools_are_read_only_when_php_fpm_conf_includes_the_directory(self) -> None:
        self.install_php_fpm("8.1", "8.3")
        self.enable_pools("8.1", {"www.conf": "[www]\nlisten = 9000\n"})
        self.enable_pools("8.3", {"admin.conf": "[admin]\nlisten = 9100\n"})
        # PHP-FPM 8.3 loads its pools from somewhere else.
        self.remote.files[fpm_conf_path("8.3")] = php_fpm_conf("8.3").replace(
            "/etc/php/8.3/fpm/pool.d/*.conf", "/srv/pools/*.conf"
        )
        pools = self.collect().php_fpm_pools
        self.assertEqual([(pool.version, pool.name) for pool in pools.value], [("8.1", "www")])
        self.assertEqual(pools.outcome, "observed")
        # Each read that decided the outcome, in order: 8.1's directory, then 8.3's main file.
        self.assertEqual(pools.source, (f"{PHP_DIR}/8.1/fpm/pool.d", fpm_conf_path("8.3")))
        self.assert_nothing_read_under(f"{PHP_DIR}/8.3/fpm/pool.d")
        self.assertIn(
            "/etc/php/8.3/fpm/php-fpm.conf does not include /etc/php/8.3/fpm/pool.d/*.conf",
            pools.warning,
        )
        self.assertNotIn("/srv/pools", pools.warning)

    def test_every_main_file_that_stopped_pools_being_read_is_the_source(self) -> None:
        self.install_php_fpm("8.1", "8.3")
        del self.remote.files[fpm_conf_path("8.3")]
        pools = self.collect().php_fpm_pools
        self.assertEqual(pools.outcome, "unsupported")
        # Neither version's php-fpm.conf exists; both are named, never /etc/php.
        self.assertEqual(pools.source, (fpm_conf_path("8.1"), fpm_conf_path("8.3")))

    def test_a_pool_directory_that_cannot_be_listed_is_the_source(self) -> None:
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        pool_dir = f"{PHP_DIR}/8.3/fpm/pool.d"
        del self.remote.directories[pool_dir]
        del self.remote.files[f"{pool_dir}/www.conf"]
        self.remote.unreadable.add(pool_dir)
        pools = self.collect().php_fpm_pools
        self.assertEqual(pools.outcome, "inaccessible")
        self.assertEqual(pools.source, (pool_dir,))

    def test_a_missing_php_fpm_conf_leaves_that_version_unread(self) -> None:
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        del self.remote.files[fpm_conf_path("8.3")]
        pools = self.collect().php_fpm_pools
        self.assertEqual(pools.outcome, "unsupported")
        self.assertEqual(pools.source, (fpm_conf_path("8.3"),))
        self.assertFalse(pools.value)
        self.assert_nothing_read_under(f"{PHP_DIR}/8.3/fpm/pool.d")
        self.assertIn("The server has no /etc/php/8.3/fpm/php-fpm.conf.", pools.warning)

    def test_empty_configuration_directories_are_observed_empty(self) -> None:
        collected = self.collect()
        sites, pools = collected.nginx_site_files, collected.php_fpm_pools
        self.assertEqual((sites.outcome, pools.outcome), ("observed", "observed"))
        self.assertEqual(
            sites.warning, "No site configuration files are listed in /etc/nginx/sites-enabled."
        )
        self.assertEqual(pools.warning, "No PHP-FPM pools are configured under /etc/php.")

    def test_permission_denied_directories_are_inaccessible(self) -> None:
        self.remote.unreadable.update({SITE_DIR, f"{PHP_DIR}/8.3/fpm/pool.d"})
        del self.remote.directories[SITE_DIR]
        del self.remote.directories[f"{PHP_DIR}/8.3/fpm/pool.d"]
        collected = self.collect()
        sites, pools = collected.nginx_site_files, collected.php_fpm_pools
        self.assertEqual(sites.outcome, "inaccessible")
        self.assertFalse(sites.value)
        self.assertIn("cannot read /etc/nginx/sites-enabled.", sites.warning)
        self.assertEqual(pools.outcome, "inaccessible")
        self.assertFalse(pools.value)
        self.assertIn("cannot read /etc/php/8.3/fpm/pool.d.", pools.warning)

    def test_total_file_denial_is_inaccessible_not_observed(self) -> None:
        self.list_dir(SITE_DIR, ["secret", "other"])
        self.remote.unreadable.update({f"{SITE_DIR}/secret", f"{SITE_DIR}/other"})
        sites = self.collect().nginx_site_files
        self.assertEqual(sites.outcome, "inaccessible")
        self.assertEqual(
            [(site.name, site.outcome) for site in sites.value],
            [("secret", "inaccessible"), ("other", "inaccessible")],
        )
        self.assertEqual(
            sites.warning,
            "The SSH user cannot read the site configuration files. Barectl does not use sudo.",
        )

    def test_a_broken_site_symlink_is_absent_for_that_entry(self) -> None:
        self.enable_sites({"good": self.EXAMPLE_SITE})
        self.remote.directories[SITE_DIR].append("gone")
        sites = self.collect().nginx_site_files
        self.assertEqual(
            [(site.name, site.outcome) for site in sites.value],
            [("good", "observed"), ("gone", "absent")],
        )
        self.assertEqual(sites.outcome, "observed")
        self.assertEqual(sites.value[1].warning, "The server has no /etc/nginx/sites-enabled/gone.")

    def test_an_observed_site_file_notes_includes_it_skips_once(self) -> None:
        self.enable_sites({"example.com": "include snippets/ssl.conf;\n" + self.EXAMPLE_SITE})
        sites = self.collect().nginx_site_files
        warning = (
            f"{SITE_DIR}/example.com includes other configuration files. Barectl does not "
            "read them, so server names and listen addresses they declare are not shown."
        )
        self.assertEqual(sites.value[0].warning, warning)
        self.assertEqual(kept_text(self.collected).count(warning), 1)
        # The note is a finding, not a warning.
        self.assertEqual(self.warned(), [])

    def test_restricted_files_keep_partial_results(self) -> None:
        self.enable_sites({"example.com": self.EXAMPLE_SITE})
        self.remote.directories[SITE_DIR].append("private")
        self.remote.unreadable.add(f"{SITE_DIR}/private")
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        self.remote.directories[f"{PHP_DIR}/8.3/fpm/pool.d"].append("stale.conf.bak")
        self.remote.unreadable.add(f"{PHP_DIR}/8.3/fpm/pool.d/stale.conf.bak")
        sites = self.collect().nginx_site_files
        self.assertEqual(
            [(site.name, site.outcome) for site in sites.value],
            [("example.com", "observed"), ("private", "inaccessible")],
        )
        self.assertEqual(sites.value[0].server_names, ("example.com",))
        self.assertIn("cannot read /etc/nginx/sites-enabled/private.", sites.value[1].warning)
        # PHP-FPM would not load the .bak file, so it is skipped without a read.
        self.assert_not_kept("stale.conf.bak")
        self.assertFalse([c for c in self.remote.commands if "stale.conf.bak" in c])

    def test_parser_failures_are_unsupported_without_dumps(self) -> None:
        self.enable_sites(
            {
                "broken.conf": "server {\n  listen 80\n  server_name broken.example;\n",
                "upstream-only": "upstream backend {\n  server 10.0.0.1:8000;\n}\n",
                "good": self.EXAMPLE_SITE,
            }
        )
        self.enable_pools("8.3", {"bad.conf": "listen without a section\n"})
        collected = self.collect()
        sites = collected.nginx_site_files
        self.assertEqual(
            [(site.name, site.outcome) for site in sites.value],
            [
                ("broken.conf", "unsupported"),
                ("upstream-only", "unsupported"),
                ("good", "observed"),
            ],
        )
        self.assertEqual(
            [
                "does not define a supported Nginx site configuration" in site.warning
                for site in sites.value
            ],
            [True, True, False],
        )
        pools = collected.php_fpm_pools
        self.assertEqual(pools.outcome, "unsupported")
        self.assertFalse(pools.value)
        self.assertNotIn("No PHP-FPM pools are configured", pools.warning)
        self.assertIn("does not define a supported PHP-FPM pool configuration", pools.warning)
        pool_dir = f"{PHP_DIR}/8.3/fpm/pool.d"
        self.assertEqual(pools.source, (pool_dir, f"{pool_dir}/bad.conf"))
        self.assert_not_kept("broken.example", "10.0.0.1:8000", "listen without a section")

    def test_pools_are_read_only_for_installed_php_fpm_versions(self) -> None:
        self.install_php_fpm("8.1", "8.3")
        self.enable_pools("8.1", {"www.conf": "[www]\nlisten = 9000\n"})
        # PHP 8.2's CLI left a version directory without PHP-FPM, and PHP-FPM 8.3 keeps
        # its pools outside the Debian layout.
        self.list_dir(f"{PHP_DIR}/8.2/fpm/pool.d", ["www.conf"])
        del self.remote.directories[f"{PHP_DIR}/8.3/fpm/pool.d"]
        pools = self.collect().php_fpm_pools
        self.assertEqual([(pool.version, pool.name) for pool in pools.value], [("8.1", "www")])
        self.assertEqual(pools.outcome, "observed")
        self.assert_nothing_read_under(f"{PHP_DIR}/8.2")
        self.assertNotIn(f"ls -1b {PHP_DIR}", self.remote.commands)
        self.assertIn(
            "The server has no /etc/php/8.3/fpm/pool.d. Barectl reads only the Debian layout.",
            pools.warning,
        )

    def test_php_fpm_without_a_versioned_package_is_unsupported(self) -> None:
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(1, "php-fpm 2:8.3+93ubuntu2 ii \n")
        pools = self.collect().php_fpm_pools
        self.assertEqual(pools.outcome, "unsupported")
        self.assert_nothing_read_under(PHP_DIR)
        self.assertIn("lists no PHP-FPM package for a specific PHP version", pools.warning)

    def test_unreadable_pool_files_are_inaccessible_not_empty(self) -> None:
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        pool_file = f"{PHP_DIR}/8.3/fpm/pool.d/www.conf"
        del self.remote.files[pool_file]
        self.remote.unreadable.add(pool_file)
        pools = self.collect().php_fpm_pools
        self.assertEqual(pools.outcome, "inaccessible")
        # The file that could not be read decided the outcome, after its directory.
        self.assertEqual(pools.source, (f"{PHP_DIR}/8.3/fpm/pool.d", pool_file))
        self.assertIn(f"cannot read {pool_file}.", pools.warning)
        self.assertNotIn("No PHP-FPM pools are configured", pools.warning)

    def test_pools_whose_listed_files_are_all_gone_are_absent(self) -> None:
        pool_dir = f"{PHP_DIR}/8.3/fpm/pool.d"
        # The directory lists a pool file that does not exist, such as a broken symlink.
        self.list_dir(pool_dir, ["gone.conf"])
        pools = self.collect().php_fpm_pools
        self.assertEqual(pools.outcome, "absent")
        self.assertEqual(pools.value, ())
        self.assertTrue(
            pools.warning.startswith("None of the PHP-FPM pool files listed under /etc/php exist."),
            pools.warning,
        )
        self.assertNotIn("No PHP-FPM pools are configured", pools.warning)

    def test_an_empty_pool_directory_beside_missing_pool_files_is_absent(self) -> None:
        self.install_php_fpm("8.2", "8.3")
        self.enable_pools("8.2", {})
        self.enable_pools("8.3", {"gone.conf": ""})
        del self.remote.files[f"{PHP_DIR}/8.3/fpm/pool.d/gone.conf"]
        pools = self.collect().php_fpm_pools
        # No pool exists; the one pool file Barectl found listed does not exist.
        self.assertEqual(pools.outcome, "absent")

    def test_pool_directories_that_list_no_pool_files_are_observed_empty(self) -> None:
        self.enable_pools("8.3", {})
        self.list_dir(f"{PHP_DIR}/8.3/fpm/pool.d", ["README"])
        pools = self.collect().php_fpm_pools
        self.assertEqual(pools.outcome, "observed")
        self.assertIn("No PHP-FPM pools are configured under /etc/php.", pools.warning)

    def test_a_pool_declared_in_two_files_is_unsupported_without_failing(self) -> None:
        self.enable_pools(
            "8.3",
            {
                "a.conf": "[www]\nlisten = 9000\n",
                "b.conf": "[WWW]\nlisten = 9001\n",
                "c.conf": "[admin]\nlisten = 9100\n",
            },
        )
        pools = self.collect().php_fpm_pools
        self.assertEqual(
            [(pool.name, pool.outcome, pool.listen) for pool in pools.value],
            [("www", "unsupported", ""), ("admin", "observed", "9100")],
        )
        self.assertEqual(pools.outcome, "observed")
        self.assertIn("Pool www is declared more than once", pools.value[0].warning)

    def test_sites_with_nothing_observed_are_not_observed(self) -> None:
        self.list_dir(SITE_DIR, ["private", "broken"])
        self.remote.unreadable.add(f"{SITE_DIR}/private")
        self.remote.files[f"{SITE_DIR}/broken"] = "server {\n  listen 80\n"
        sites = self.collect().nginx_site_files
        self.assertEqual(sites.outcome, "unsupported")
        self.assertEqual(
            sites.warning,
            "No file in /etc/nginx/sites-enabled could be read as a supported Nginx site "
            "configuration.",
        )

    def test_sites_whose_entries_are_all_gone_are_absent(self) -> None:
        self.list_dir(SITE_DIR, ["gone"])
        sites = self.collect().nginx_site_files
        self.assertEqual(sites.outcome, "absent")
        self.assertEqual([(site.name, site.outcome) for site in sites.value], [("gone", "absent")])
        self.assertEqual(
            sites.warning, "None of the entries listed in /etc/nginx/sites-enabled exist."
        )

    def test_entries_of_an_unsearchable_directory_are_inaccessible_not_absent(self) -> None:
        # The SSH user may list the directory but not open the files inside it.
        self.enable_sites({"default": self.DEFAULT_SITE})
        self.remote.unsearchable.add(SITE_DIR)
        sites = self.collect().nginx_site_files
        self.assertEqual(
            [(site.name, site.outcome) for site in sites.value],
            [("default", "inaccessible")],
        )
        self.assertEqual(sites.outcome, "inaccessible")

    def test_escaped_entry_names_are_skipped_not_split(self) -> None:
        # ls -b prints a name holding a newline as one escaped line, so it cannot repeat
        # another entry's name.
        self.enable_sites({"default": self.DEFAULT_SITE})
        self.remote.directories[SITE_DIR].append("x\\ndefault")
        sites = self.collect().nginx_site_files
        self.assertEqual([site.name for site in sites.value], ["default"])
        self.assertIn("1 entries whose names Barectl does not interpret", sites.warning)
        self.assertIn(f"ls -1b {SITE_DIR}", self.remote.commands)

    def test_the_pool_cap_is_exact(self) -> None:
        def pool_file(start: int) -> str:
            return "".join(f"[p{i}]\nlisten = {9000 + i}\n" for i in range(start, start + 50))

        pools = {f"{n}.conf": pool_file(n * 50) for n in range(4)}
        self.enable_pools("8.3", pools)
        observed_pools = self.collect().php_fpm_pools
        self.assertEqual(len(observed_pools.value), 200)
        self.assertNotIn("More than 200", observed_pools.warning)

        self.enable_pools("8.3", {**pools, "4.conf": "[extra]\nlisten = 9999\n"})
        capped = self.collect().php_fpm_pools
        self.assertEqual(len(capped.value), 200)
        self.assertNotIn("extra", [pool.name for pool in capped.value])
        self.assertIn("More than 200 PHP-FPM pools were found.", capped.warning)

    def test_the_site_file_cap_is_exact(self) -> None:
        sites = {f"s{n:03}": self.DEFAULT_SITE for n in range(200)}
        self.enable_sites(sites)
        observed_sites = self.collect().nginx_site_files
        self.assertEqual(len(observed_sites.value), 200)
        self.assertNotIn("more site entries", observed_sites.warning)

        self.enable_sites({**sites, "s200": self.DEFAULT_SITE, "s201": self.DEFAULT_SITE})
        self.remote.commands.clear()
        capped = self.collect().nginx_site_files
        self.assertEqual(capped.outcome, "observed")
        self.assertEqual(len(capped.value), 200)
        self.assertNotIn("s200", [site.name for site in capped.value])
        self.assertIn("Only the first 200 are shown.", capped.warning)
        self.assert_nothing_read_under(f"{SITE_DIR}/s201")

    def test_included_files_are_named_in_warnings(self) -> None:
        self.enable_sites(
            {"example.com": "server {\n  listen 80;\n  include snippets/names.conf;\n}\n"}
        )
        self.enable_pools("8.3", {"www.conf": "[www]\nlisten = 9000\ninclude = /srv/*.conf\n"})
        collected = self.collect()
        sites, pools = collected.nginx_site_files, collected.php_fpm_pools
        self.assertEqual((sites.outcome, pools.outcome), ("observed", "observed"))
        self.assertIn(
            f"{SITE_DIR}/example.com includes other configuration files. Barectl does not "
            "read them",
            sites.value[0].warning,
        )
        self.assertIn(
            f"{PHP_DIR}/8.3/fpm/pool.d/www.conf includes other configuration files.",
            pools.warning,
        )
        self.assert_not_kept("/srv/")

    def test_entries_with_unsupported_names_are_skipped(self) -> None:
        self.enable_sites({"good": self.EXAMPLE_SITE})
        self.remote.directories[SITE_DIR].append("weird name")
        sites = self.collect().nginx_site_files
        self.assertEqual([site.name for site in sites.value], ["good"])
        self.assertIn("1 entries whose names Barectl does not interpret", sites.warning)
        self.assertFalse([c for c in self.remote.commands if "weird name" in c])
