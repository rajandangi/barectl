"""Site reconstruction rules (docs/ssh-connections.md#site-observations), through ``collect``.

Each test starts from a site that meets docs/site-conventions.md, as an administrator made
it by hand, and changes the server the way the documented case describes.
"""

from typing import override

from . import ssh
from .fakes import (
    AVAILABLE_DIR,
    CONFFILES_QUERY,
    FASTCGI_DIGEST,
    NGINX_CONF,
    NGINX_CONF_TEXT,
    PACKAGE_QUERY,
    PHP_DIR,
    SITE_DIR,
    STOCK_DEFAULT_SITE,
    ObservationTestCase,
    SitePoolFixtures,
    add_site,
    fpm_conf_path,
    php_fpm_conf,
    pool_config,
    site_config,
)
from .models import SiteResource
from .snapshot import ObservedSite, ObservedSiteResource

ALPHA = f"{AVAILABLE_DIR}/alpha.conf"
ALPHA_POOL = f"{PHP_DIR}/8.3/fpm/pool.d/alpha.conf"
SOCKET = "/run/php/salpha.sock"
Resource = SiteResource


class SiteTests(SitePoolFixtures, ObservationTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        add_site(self.remote)

    def site(self, identifier: str = "alpha") -> ObservedSite:
        sites = self.collect().sites
        (found,) = (site for site in sites.value if site.identifier == identifier)
        return found

    @staticmethod
    def resource(site: ObservedSite, kind: SiteResource) -> ObservedSiteResource:
        (found,) = (resource for resource in site.resources if resource.resource == kind)
        return found

    def departures(self, site: ObservedSite) -> dict[str, str]:
        """Every resource that is not as the convention requires, with its outcome."""
        return {
            resource.resource.value: resource.outcome.value
            for resource in site.resources
            if not resource.conforms
        }

    def test_a_site_meeting_the_convention_is_complete(self) -> None:
        site = self.site()
        self.assertTrue(site.complete, self.departures(site))
        self.assertEqual(site.server_names, ("alpha.test", "www.alpha.test"))
        self.assertEqual(
            (site.document_root, site.fastcgi_socket, site.php_version),
            ("/var/www/alpha/public", SOCKET, "8.3"),
        )
        self.assertEqual((site.pool_user, site.pool_group), ("salpha", "salpha"))
        self.assertEqual(site.account and site.account.home, "/var/www/alpha")
        expected = [
            resource for resource in SiteResource if resource != SiteResource.CHALLENGE_WEBROOT
        ]
        self.assertEqual([resource.resource for resource in site.resources], expected)
        enabled = self.resource(site, Resource.NGINX_ENABLED)
        self.assertEqual(enabled.metadata and enabled.metadata.link_target, ALPHA)
        self.assertEqual(self.resource(site, Resource.POOL).source[-1], ALPHA_POOL)
        self.assertEqual(self.collected.sites.outcome, "observed")
        # The stock pool is not a site, and nothing in a pool file but its compared
        # settings is kept.
        self.assertEqual([found.identifier for found in self.collected.sites.value], ["alpha"])

    def test_a_site_serving_http01_challenges_is_complete_with_its_webroot(self) -> None:
        http = self.remote.files[ALPHA]
        webroot = "/var/lib/letsencrypt/alpha"

        def challenge(root: str = webroot) -> str:
            return (
                "\tlocation ^~ /.well-known/acme-challenge/ {\n"
                f"\t\troot {root};\n"
                "\t\ttry_files $uri =404;\n"
                "\t}\n"
                "\n"
            )

        self.remote.files[ALPHA] = http.replace("\tlocation / {", challenge() + "\tlocation / {")
        self.remote.directories.setdefault(webroot, [])
        self.remote.ownership[webroot] = ("root", "www-data", 0o750)
        site = self.site()
        self.assertTrue(site.complete, self.departures(site))
        self.assertEqual(self.resource(site, Resource.CHALLENGE_WEBROOT).location, webroot)
        self.remote.ownership[webroot] = ("root", "www-data", 0o755)
        self.assertEqual(self.departures(self.site()), {"challenge_webroot": "observed"})
        self.remote.ownership[webroot] = ("root", "www-data", 0o750)
        # Another directory, or the location anywhere but first, is not the convention's.
        variants = {
            "other root": http.replace(
                "\tlocation / {", challenge("/var/lib/letsencrypt/beta") + "\tlocation / {"
            ),
            "not first": http.replace("\tlocation ~ /\\. {", challenge() + "\tlocation ~ /\\. {"),
        }
        for variant, text in variants.items():
            with self.subTest(variant=variant):
                self.assertNotEqual(text, http)
                self.remote.files[ALPHA] = text
                self.assertIn("nginx_source", self.departures(self.site()))

    def test_secrets_in_the_pool_are_never_kept(self) -> None:
        self.remote.files[ALPHA_POOL] += "env[DB_PASSWORD] = hunter2\n"
        site = self.site()
        self.assertFalse(site.complete)
        self.assertIn("1 other setting", self.resource(site, Resource.POOL).warning)
        self.assert_not_kept("hunter2", "DB_PASSWORD")

    def test_a_server_without_sites_has_an_observed_empty_collection(self) -> None:
        self.remote = type(self.remote)()
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        sites = self.collect().sites
        self.assertEqual((sites.outcome, sites.value), ("observed", ()))
        self.assertIn("is named like a site", sites.warning)
        self.assertFalse([c for c in self.remote.commands if "getent" in c or "stat " in c])

    def test_a_missing_socket_is_a_broken_link_not_a_site(self) -> None:
        self.remote.sockets.clear()
        site = self.site()
        self.assertEqual(self.departures(site), {"socket": "absent"})
        self.assertIn("no running PHP-FPM pool", self.resource(site, Resource.SOCKET).warning)

    def test_a_missing_account_is_absent(self) -> None:
        self.remote.results["getent passwd salpha"] = ssh.CommandResult(2, "")
        site = self.site()
        self.assertEqual(self.departures(site), {"user": "absent"})
        self.assertIsNone(site.account)

    def test_an_account_outside_the_convention_differs(self) -> None:
        cases = {
            "system uid": "salpha:x:998:998::/var/www/alpha:/usr/sbin/nologin\n",
            "other home": "salpha:x:1001:1001::/home/salpha:/usr/sbin/nologin\n",
            "login shell": "salpha:x:1001:1001::/var/www/alpha:/bin/bash\n",
        }
        for case, record in cases.items():
            with self.subTest(case):
                self.remote.results["getent passwd salpha"] = ssh.CommandResult(0, record)
                self.assertEqual(self.departures(self.site()), {"user": "observed"})
        self.remote.results["getent passwd salpha"] = ssh.CommandResult(
            0, "salpha:x:1001:1001::/var/www/alpha:/usr/sbin/nologin\n"
        )
        self.remote.results["id -G salpha"] = ssh.CommandResult(0, "1001 27\n")
        self.assertIn("no group but its own", self.resource(self.site(), Resource.USER).warning)

    def test_names_and_comments_never_establish_the_relationship(self) -> None:
        # The file is named like the site and mentions its socket in a comment, but passes
        # PHP to the distribution's pool.
        self.remote.files[ALPHA] = site_config("alpha", ("alpha.test",)).replace(
            "fastcgi_pass unix:/run/php/salpha.sock;",
            "# fastcgi_pass unix:/run/php/salpha.sock;\n\t\tfastcgi_pass "
            "unix:/run/php/php8.3-fpm.sock;",
        )
        site = self.site()
        self.assertFalse(site.complete)
        self.assertEqual(site.fastcgi_socket, "/run/php/php8.3-fpm.sock")
        self.assertEqual(self.departures(site), {"nginx_source": "observed"})

    def test_a_shared_document_root_is_a_conflict(self) -> None:
        self.enable_sites(
            {"default": "server {\n  listen 8080;\n  root /var/www/alpha/public;\n}\n"}
        )
        self.remote.directories[SITE_DIR].append("alpha.conf")
        site = self.site()
        self.assertEqual(self.departures(site), {"exclusive": "observed"})
        self.assertIn(
            "/etc/nginx/sites-enabled/default also uses paths in /var/www/alpha.",
            self.resource(site, Resource.EXCLUSIVE).warning,
        )

    def test_duplicate_domains_are_a_conflict_whatever_their_case(self) -> None:
        self.enable_sites({"legacy": "server {\n  listen 80;\n  server_name WWW.Alpha.Test.;\n}\n"})
        self.remote.directories[SITE_DIR].append("alpha.conf")
        site = self.site()
        self.assertEqual(self.departures(site), {"exclusive": "observed"})
        self.assertIn(
            "sites-enabled/legacy also declares www.alpha.test.",
            self.resource(site, Resource.EXCLUSIVE).warning,
        )

    def test_two_sites_declaring_one_name_are_both_incomplete(self) -> None:
        add_site(self.remote, "beta", ("beta.test", "alpha.test"))
        sites = {site.identifier: site for site in self.collect().sites.value}
        for identifier in ("alpha", "beta"):
            with self.subTest(identifier):
                self.assertEqual(self.departures(sites[identifier]), {"exclusive": "observed"})

    def test_another_pool_on_the_site_socket_is_a_conflict(self) -> None:
        self.remote.files[f"{PHP_DIR}/8.3/fpm/pool.d/www.conf"] = (
            f"[www]\nuser = www-data\nlisten = {SOCKET}\n"
        )
        self.remote.directories[f"{PHP_DIR}/8.3/fpm/pool.d"].append("www.conf")
        site = self.site()
        self.assertEqual(self.departures(site), {"exclusive": "observed"})
        self.assertIn(
            f"PHP 8.3 pool www in {PHP_DIR}/8.3/fpm/pool.d/www.conf also listens on {SOCKET}.",
            self.resource(site, Resource.EXCLUSIVE).warning,
        )

    def test_unknown_includes_leave_the_relationship_unsupported(self) -> None:
        self.remote.files[ALPHA] = self.remote.files[ALPHA].replace(
            "\tautoindex off;", "\tautoindex off;\n\tinclude snippets/extra.conf;"
        )
        site = self.site()
        source = self.resource(site, Resource.NGINX_SOURCE)
        self.assertEqual(source.outcome, "unsupported")
        self.assertIn("includes snippets/extra.conf", source.warning)
        self.assertEqual((site.document_root, site.fastcgi_socket), ("", ""))

    def test_the_path_info_snippet_is_not_the_supported_fastcgi_include(self) -> None:
        self.remote.files[ALPHA] = self.remote.files[ALPHA].replace(
            "include fastcgi.conf;", "include snippets/fastcgi-php.conf;"
        )
        source = self.resource(self.site(), Resource.NGINX_SOURCE)
        self.assertEqual(source.outcome, "unsupported")
        self.assertIn("snippets/fastcgi-php.conf", source.warning)

    def test_another_site_file_with_includes_leaves_exclusivity_unconfirmed(self) -> None:
        self.enable_sites({"legacy": "server {\n  listen 80;\n  include snippets/app.conf;\n}\n"})
        self.remote.directories[SITE_DIR].append("alpha.conf")
        exclusive = self.resource(self.site(), Resource.EXCLUSIVE)
        self.assertEqual((exclusive.outcome, exclusive.conforms), ("unsupported", False))

    def test_directives_outside_the_convention_differ(self) -> None:
        additions = {
            "path info": "\tfastcgi_split_path_info ^(.+\\.php)(/.+)$;",
            "extra listener": "\tlisten 8080;",
            "wildcard name": "\tserver_name *.alpha.test;",
            "listing": "\tautoindex on;",
        }
        original = self.remote.files[ALPHA]
        for case, line in additions.items():
            with self.subTest(case):
                self.remote.files[ALPHA] = original.replace("\tindex ", f"{line}\n\tindex ")
                self.assertEqual(self.departures(self.site()).get("nginx_source"), "observed")

    def test_dotfiles_must_be_refused_before_php_runs(self) -> None:
        text = self.remote.files[ALPHA]
        dotfiles = "\tlocation ~ /\\. {\n\t\tdeny all;\n\t}\n\n"
        php_start = text.index("\tlocation ~ \\.php$")
        reordered = text.replace(dotfiles, "")
        php_end = reordered.index("\t}\n", reordered.index("\tlocation ~ \\.php$")) + 3
        self.remote.files[ALPHA] = f"{reordered[:php_end]}\n{dotfiles}{reordered[php_end:]}"
        self.assertLess(php_start, len(text))
        source = self.resource(self.site(), Resource.NGINX_SOURCE)
        self.assertIn("dotfiles refused before PHP scripts", source.warning)

    def test_metadata_outside_the_convention_differs(self) -> None:
        cases = {
            "socket readable by its group": (SOCKET, ("www-data", "www-data", 0o660), "socket"),
            "public writable by the web server": (
                "/var/www/alpha/public",
                ("www-data", "www-data", 0o750),
                "document_root",
            ),
            "boundary owned by the site user": (
                "/var/www/alpha",
                ("salpha", "salpha", 0o755),
                "boundary",
            ),
            "pool writable by others": (ALPHA_POOL, ("root", "root", 0o666), "pool"),
        }
        for case, (path, ownership, kind) in cases.items():
            with self.subTest(case):
                previous = self.remote.ownership.get(path)
                self.remote.ownership[path] = ownership
                self.assertEqual(self.departures(self.site()), {kind: "observed"})
                if previous is None:
                    del self.remote.ownership[path]
                else:
                    self.remote.ownership[path] = previous

    def test_enablement_needs_one_link_to_the_source(self) -> None:
        enabled = f"{SITE_DIR}/alpha.conf"
        self.remote.links[enabled] = "/etc/nginx/sites-available/other.conf"
        self.remote.files["/etc/nginx/sites-available/other.conf"] = site_config(
            "alpha", ("a.test",)
        )
        self.assertIn(
            f"must link to {ALPHA}",
            self.resource(self.site(), Resource.NGINX_ENABLED).warning,
        )
        # A relative link resolves to the same source.
        self.remote.links[enabled] = "../sites-available/alpha.conf"
        self.assertTrue(self.site().complete)

    def test_an_available_site_that_is_not_enabled_is_incomplete(self) -> None:
        del self.remote.links[f"{SITE_DIR}/alpha.conf"]
        self.remote.directories[SITE_DIR].remove("alpha.conf")
        site = self.site()
        self.assertEqual(self.departures(site), {"nginx_enabled": "absent"})
        self.assertIn(
            "The site is not enabled", self.resource(site, Resource.NGINX_ENABLED).warning
        )

    def test_a_link_whose_source_is_gone_leaves_the_site_file_absent(self) -> None:
        del self.remote.files[ALPHA]
        self.remote.directories[AVAILABLE_DIR].remove("alpha.conf")
        site = self.site()
        self.assertEqual(self.resource(site, Resource.NGINX_SOURCE).outcome, "absent")
        self.assertEqual(site.server_names, ())

    def test_unreadable_configuration_is_inaccessible_not_absent(self) -> None:
        self.remote.unreadable.add(ALPHA_POOL)
        self.enable_sites({"private": "server {}\n"})
        self.remote.unreadable.add(f"{SITE_DIR}/private")
        self.remote.directories[SITE_DIR].append("alpha.conf")
        site = self.site()
        self.assertEqual(
            self.departures(site), {"pool": "inaccessible", "exclusive": "inaccessible"}
        )
        self.assertIn(
            "cannot read /etc/nginx/sites-enabled/private",
            self.resource(site, Resource.EXCLUSIVE).warning,
        )

    def test_paths_the_ssh_user_cannot_search_are_inaccessible(self) -> None:
        self.remote.unsearchable.add("/var/www/alpha")
        site = self.site()
        self.assertEqual(
            self.departures(site),
            {"document_root": "inaccessible", "private": "inaccessible", "user": "inaccessible"},
        )

    def test_truncated_reads_are_unsupported(self) -> None:
        self.remote.answers.append(
            lambda command: (
                ssh.CommandResult(0, "server {", truncated=True)
                if command == f"cat {SITE_DIR}/alpha.conf"
                else None
            )
        )
        source = self.resource(self.site(), Resource.NGINX_SOURCE)
        self.assertEqual(source.outcome, "unsupported")
        self.assertIn("larger than expected", source.warning)

    def test_a_changed_fastcgi_file_differs_from_the_package(self) -> None:
        self.remote.results[FASTCGI_DIGEST] = ssh.CommandResult(
            0, "0123456789abcdef0123456789abcdef  /etc/nginx/fastcgi.conf\n"
        )
        site = self.site()
        self.assertEqual(self.departures(site), {"fastcgi": "observed"})
        self.remote.results[CONFFILES_QUERY] = ssh.CommandResult(126, "")
        self.assertEqual(self.departures(self.site()), {"fastcgi": "inaccessible"})

    def test_the_pool_must_be_in_the_release_default_php_version(self) -> None:
        self.install_php_fpm("8.1")
        self.enable_pools("8.1", {"alpha.conf": pool_config("alpha")})
        pool = self.resource(self.site(), Resource.POOL)
        self.assertEqual(pool.outcome, "absent")
        self.assertIn("PHP 8.3-FPM, the default PHP version of Ubuntu 24.04", pool.warning)

    def test_a_pool_declaring_other_values_differs(self) -> None:
        self.remote.files[ALPHA_POOL] = pool_config("alpha").replace("0600", "0660")
        self.remote.files[ALPHA_POOL] += "[extra]\nlisten = /run/php/extra.sock\n"
        warning = self.resource(self.site(), Resource.POOL).warning
        self.assertIn("The pool sets listen.mode = 0660, not 0600.", warning)
        self.assertIn("must declare the pool alpha and no other", warning)

    def test_sites_are_read_only_where_their_configuration_is(self) -> None:
        cases = {
            "nginx not installed": (
                ssh.CommandResult(0, "php8.3-fpm 8.3.6 ii \n"),
                "absent",
            ),
            "dpkg unreadable": (ssh.CommandResult(126, ""), "inaccessible"),
        }
        for case, (packages, outcome) in cases.items():
            with self.subTest(case):
                self.remote.commands.clear()
                self.remote.results[PACKAGE_QUERY] = packages
                sites = self.collect().sites
                self.assertEqual((sites.outcome, sites.value), (outcome, ()))
                self.assertFalse(
                    [c for c in self.remote.commands if "salpha" in c or "/var/www" in c]
                )

    def test_an_unsupported_release_has_no_site_convention(self) -> None:
        self.remote.files["/etc/os-release"] = 'ID=debian\nVERSION_ID="12"\nNAME="Debian"\n'
        sites = self.collect().sites
        self.assertEqual((sites.outcome, sites.value), ("unsupported", ()))
        self.assertIn("not a supported release", sites.warning)

    def test_unlisted_sites_enabled_leaves_sites_uninspected(self) -> None:
        self.remote.unreadable.add(SITE_DIR)
        sites = self.collect().sites
        self.assertEqual((sites.outcome, sites.value), ("inaccessible", ()))

    def test_only_names_of_the_identifier_grammar_are_candidates(self) -> None:
        for name in ("ab.conf", "Alpha2.conf", "1site.conf", "a-b.conf", f"{'a' * 25}.conf"):
            self.remote.files[f"{AVAILABLE_DIR}/{name}"] = "server {}\n"
            self.remote.directories[AVAILABLE_DIR].append(name)
        self.assertEqual([site.identifier for site in self.collect().sites.value], ["alpha"])

    def test_candidates_beyond_the_cap_are_not_inspected(self) -> None:
        names = [f"site{index:03d}.conf" for index in range(51)]
        self.remote.directories[AVAILABLE_DIR] = names
        for name in names:
            self.remote.files[f"{AVAILABLE_DIR}/{name}"] = "server {}\n"
        sites = self.collect().sites
        self.assertEqual(len(sites.value), 50)
        self.assertIn("Only the first 50 were inspected.", sites.warning)

    def exclusive(self) -> ObservedSiteResource:
        return self.resource(self.site(), Resource.EXCLUSIVE)

    def test_nginx_conf_beyond_its_packaged_includes_leaves_exclusivity_unknown(self) -> None:
        cases = {
            "extra include": "\tinclude /etc/nginx/vhosts/*.conf;\n",
            "inline server": "\tserver {\n\t\tlisten 80;\n\t\tserver_name alpha.test;\n\t}\n",
        }
        for case, addition in cases.items():
            with self.subTest(case):
                self.remote.files[NGINX_CONF] = NGINX_CONF_TEXT.replace(
                    "\tinclude /etc/nginx/sites-enabled/*;\n",
                    f"\tinclude /etc/nginx/sites-enabled/*;\n{addition}",
                )
                exclusive = self.exclusive()
                self.assertEqual((exclusive.outcome, exclusive.conforms), ("unsupported", False))
                self.assertIn("/etc/nginx/nginx.conf declares", exclusive.warning)
        self.remote.files[NGINX_CONF] = NGINX_CONF_TEXT
        self.assertTrue(self.site().complete)

    def test_php_fpm_conf_beyond_its_pool_include_leaves_exclusivity_unknown(self) -> None:
        cases = {
            "extra include": "include=/etc/php/extra/*.conf\n",
            "inline pool": "[inline]\nlisten = /run/php/salpha.sock\n",
        }
        for case, addition in cases.items():
            with self.subTest(case):
                self.remote.files[fpm_conf_path("8.3")] = php_fpm_conf("8.3") + addition
                exclusive = self.exclusive()
                self.assertEqual((exclusive.outcome, exclusive.conforms), ("unsupported", False))
                self.assertIn("php-fpm.conf declares", exclusive.warning)

    def test_the_site_never_becomes_the_default_server(self) -> None:
        # Without the stock default site, alpha would answer unknown names on both.
        del self.remote.files[f"{SITE_DIR}/default"]
        self.remote.directories[SITE_DIR].remove("default")
        exclusive = self.exclusive()
        self.assertEqual((exclusive.outcome, exclusive.conforms), ("observed", False))
        self.assertIn("default server for 80,", exclusive.warning)
        self.assertIn("default server for [::]:80,", exclusive.warning)
        # A default server only for IPv4 leaves alpha the default on [::]:80.
        self.enable_sites({"default": "server {\n  listen 80 default_server;\n}\n"})
        self.remote.directories[SITE_DIR].append("alpha.conf")
        self.assertIn("default server for [::]:80,", self.exclusive().warning)
        # Listening on IPv4 alone then follows the convention.
        self.remote.files[ALPHA] = self.remote.files[ALPHA].replace("\tlisten [::]:80;\n", "")
        self.assertTrue(self.site().complete, self.departures(self.site()))

    def test_the_site_listens_on_ipv6_where_the_default_server_does(self) -> None:
        self.remote.files[ALPHA] = self.remote.files[ALPHA].replace("\tlisten [::]:80;\n", "")
        self.assertIn("listens on [::]:80, so the site must too", self.exclusive().warning)

    def test_parent_directories_must_be_owned_and_written_only_by_their_owner(self) -> None:
        cases = {
            "group-writable sites-enabled": (SITE_DIR, ("root", "root", 0o775)),
            "web root owned by another user": ("/var/www", ("www-data", "www-data", 0o755)),
            "socket directory owned by root": ("/run/php", ("root", "root", 0o755)),
        }
        for case, (path, ownership) in cases.items():
            with self.subTest(case):
                previous = self.remote.ownership.get(path)
                self.remote.ownership[path] = ownership
                site = self.site()
                self.assertEqual(self.departures(site), {"ancestors": "observed"})
                self.assertIn(path, self.resource(site, Resource.ANCESTORS).warning)
                if previous is None:
                    del self.remote.ownership[path]
                else:
                    self.remote.ownership[path] = previous

    def test_a_symbolic_link_among_the_parents_differs(self) -> None:
        self.remote.links["/var/www"] = "/srv/www"
        self.assertEqual(self.departures(self.site()).get("ancestors"), "observed")

    def test_other_pools_sharing_the_name_identity_or_socket_are_conflicts(self) -> None:
        pool_dir = f"{PHP_DIR}/8.3/fpm/pool.d"
        cases = {
            "the site's user": "[other]\nuser = salpha\nlisten = /run/php/other.sock\n",
            "the site's socket spelled apart": (
                "[other]\nuser = www-data\nlisten = /var/run/php//salpha.sock\n"
            ),
        }
        self.remote.directories[pool_dir].append("other.conf")
        for case, text in cases.items():
            with self.subTest(case):
                self.remote.files[f"{pool_dir}/other.conf"] = text
                exclusive = self.exclusive()
                self.assertEqual((exclusive.outcome, exclusive.conforms), ("observed", False))
                self.assertIn(f"{pool_dir}/other.conf", exclusive.warning)

    def test_a_pool_of_another_version_with_the_site_name_conflicts(self) -> None:
        # Within one version PHP-FPM merges the two; across versions they are two pools.
        self.install_php_fpm("8.1", "8.3")
        self.enable_pools("8.1", {"other.conf": "[ALPHA]\nuser = www-data\nlisten = 9001\n"})
        exclusive = self.exclusive()
        self.assertEqual((exclusive.outcome, exclusive.conforms), ("observed", False))
        self.assertIn("PHP 8.1 pool ALPHA", exclusive.warning)
        self.assertIn("has the site's name", exclusive.warning)

    def test_another_site_passing_to_the_socket_by_another_spelling_conflicts(self) -> None:
        self.enable_sites(
            {
                "default": STOCK_DEFAULT_SITE,
                "legacy": "server {\n  listen 8080;\n  location / {\n"
                "    fastcgi_pass unix:/var/run/php/salpha.sock/;\n  }\n}\n",
            }
        )
        self.remote.directories[SITE_DIR].append("alpha.conf")
        self.assertIn(
            "legacy also passes requests to /run/php/salpha.sock", self.exclusive().warning
        )

    def test_reserved_names_are_never_candidates(self) -> None:
        for name in ("www", "html"):
            self.remote.files[f"{AVAILABLE_DIR}/{name}.conf"] = "server {}\n"
            self.remote.directories[AVAILABLE_DIR].append(f"{name}.conf")
        self.assertEqual([site.identifier for site in self.collect().sites.value], ["alpha"])

    def test_an_unreadable_group_list_is_not_a_difference(self) -> None:
        self.remote.results["id -G salpha"] = ssh.CommandResult(126, "")
        self.assertEqual(self.departures(self.site()), {"user": "inaccessible"})

    def test_facts_come_only_from_the_file_nginx_loads_through_the_link(self) -> None:
        other = f"{AVAILABLE_DIR}/other.conf"
        self.remote.files[other] = site_config("alpha", ("other.test",))
        self.remote.links[f"{SITE_DIR}/alpha.conf"] = other
        site = self.site()
        self.assertEqual((site.server_names, site.document_root, site.fastcgi_socket), ((), "", ""))
        self.assertEqual(self.departures(site).get("nginx_enabled"), "observed")

    def test_ssh_keys_in_the_home_differ(self) -> None:
        self.remote.directories["/var/www/alpha/.ssh"] = []
        self.assertIn(".ssh must not exist", self.resource(self.site(), Resource.USER).warning)

    def test_the_password_lock_is_read_only_where_shadow_is_readable(self) -> None:
        command = "getent shadow salpha | cut -d: -f2 | cut -c1"
        self.remote.results[command] = ssh.CommandResult(0, "$\n")
        self.assertEqual(self.departures(self.site()), {"password": "observed"})
        self.remote.unreadable.add("/etc/shadow")
        self.remote.commands.clear()
        password = self.resource(self.site(), Resource.PASSWORD)
        self.assertEqual(password.outcome, "inaccessible")
        self.assertNotIn(command, self.remote.commands)

    def test_normal_accounts_follow_login_defs(self) -> None:
        self.remote.files["/etc/login.defs"] = "UID_MIN 2000\nUID_MAX 60000\n"
        warning = self.resource(self.site(), Resource.USER).warning
        self.assertIn("outside the normal accounts' 2000 to 60000", warning)

    def test_autoindex_must_be_declared_off(self) -> None:
        self.remote.files[ALPHA] = self.remote.files[ALPHA].replace("\tautoindex off;\n", "")
        self.assertIn(
            "must set autoindex off", self.resource(self.site(), Resource.NGINX_SOURCE).warning
        )
