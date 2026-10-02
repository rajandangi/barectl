"""docs/ssh-connections.md#nginx-site-file-and-php-fpm-pool-observations"""

from django.test import SimpleTestCase

from .observations.parsers import (
    MAX_BLOCK_DEPTH,
    MAX_POOL_LINES,
    MAX_STATEMENTS,
    MAX_TOKEN,
    NginxBlock,
    NginxReferences,
    NginxSite,
    PoolFile,
    PoolSection,
    fpm_main_extras,
    nginx_main_extras,
    nginx_references,
    parse_nginx_site,
    parse_nginx_tree,
    parse_pool_file,
    parse_pool_sections,
)

NGINX_SITE = """\
server {
    listen 80;
    listen [::]:80;
    server_name example.com;
    root /var/www/example;
}

server {
    listen 443 ssl http2;
    server_name example.com www.example.net "weird.example.org";
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
"""

PHP_POOL = """\
; Start a new pool named www.
[www]
user = www-data
group = www-data
listen = /run/php/php8.3-fpm.sock
listen.owner = www-data
pm = dynamic
pm.max_children = 10
env[PATH] = /usr/local/bin:/usr/bin:/bin
php_value[session.save_path] = /var/lib/php/sessions
"""


class NginxSiteParserTests(SimpleTestCase):
    def test_server_blocks_yield_names_and_listens(self) -> None:
        parsed = parse_nginx_site(NGINX_SITE)
        self.assertEqual(
            parsed,
            NginxSite(
                ("example.com", "www.example.net", "weird.example.org"),
                ("80", "[::]:80", "443"),
                includes=False,
                certificates=("/etc/letsencrypt/live/example.com/fullchain.pem",),
            ),
        )

    def test_listen_flags_and_unix_sockets_are_supported(self) -> None:
        parsed = parse_nginx_site(
            "server {\n  listen unix:/run/nginx.sock;\n  listen 127.0.0.1:8080 default_server;\n}\n"
        )
        self.assertEqual(
            parsed, NginxSite((), ("unix:/run/nginx.sock", "127.0.0.1:8080"), includes=False)
        )

    def test_comments_and_empty_statements_are_ignored(self) -> None:
        parsed = parse_nginx_site(
            "# a comment\nserver {\n  # another\n  ;\n  listen 80; # trailing\n"
            "  server_name a.example;\n}\n"
        )
        self.assertEqual(parsed, NginxSite(("a.example",), ("80",), includes=False))

    def test_server_nameless_block_is_a_supported_catch_all(self) -> None:
        parsed = parse_nginx_site("server {\n  listen 80 default_server;\n}\n")
        self.assertEqual(parsed, NginxSite((), ("80",), includes=False))

    def test_regex_server_names_are_unsupported(self) -> None:
        self.assertIsNone(parse_nginx_site("server {\n  server_name ~^www\\d+\\.example;\n}\n"))

    def test_names_outside_the_supported_charset_are_unsupported(self) -> None:
        self.assertIsNone(parse_nginx_site("server {\n  server_name a b$(touch /tmp/x);\n}\n"))

    def test_listen_addresses_outside_the_supported_charset_are_unsupported(self) -> None:
        self.assertIsNone(parse_nginx_site("server {\n  listen $(touch /tmp/x);\n}\n"))

    def test_unknown_directives_outside_server_blocks_are_ignored(self) -> None:
        self.assertEqual(
            parse_nginx_site("$(touch /tmp/x);\nserver {\n  listen 80;\n}\n"),
            NginxSite((), ("80",), includes=False),
        )

    def test_a_file_without_a_server_block_is_unsupported(self) -> None:
        self.assertIsNone(parse_nginx_site("upstream backend {\n  server 10.0.0.1:8000;\n}\n"))

    def test_unclosed_blocks_are_unsupported(self) -> None:
        self.assertIsNone(parse_nginx_site("server {\n  listen 80;\n"))

    def test_unterminated_quotes_are_unsupported(self) -> None:
        self.assertIsNone(parse_nginx_site('server {\n  server_name "oops;\n}\n'))

    def test_directives_without_a_semicolon_are_unsupported(self) -> None:
        self.assertIsNone(parse_nginx_site("server {\n  listen 80\n}\n"))

    def test_unexpected_close_brace_is_unsupported(self) -> None:
        self.assertIsNone(parse_nginx_site("}\n"))

    def test_server_level_includes_are_reported_but_not_followed(self) -> None:
        parsed = parse_nginx_site(
            "server {\n  listen 80;\n  include snippets/ssl.conf;\n"
            "  location / {\n    include fastcgi_params;\n  }\n}\n"
        )
        self.assertEqual(parsed, NginxSite((), ("80",), includes=True))

    def test_location_includes_cannot_declare_listens(self) -> None:
        # listen and server_name are only valid in a server block, so location includes
        # hide nothing Barectl shows.
        parsed = parse_nginx_site(
            "server {\n  listen 80;\n  location / {\n    include fastcgi_params;\n  }\n}\n"
        )
        self.assertEqual(parsed, NginxSite((), ("80",), includes=False))

    def test_top_level_includes_are_reported(self) -> None:
        parsed = parse_nginx_site("include /etc/nginx/extra/*.conf;\nserver {\n  listen 80;\n}\n")
        self.assertEqual(parsed, NginxSite((), ("80",), includes=True))


class PhpPoolParserTests(SimpleTestCase):
    def test_pool_yields_its_name_and_listen(self) -> None:
        self.assertEqual(
            parse_pool_file(PHP_POOL),
            PoolFile((("www", "/run/php/php8.3-fpm.sock"),), includes=False),
        )

    def test_environment_and_php_values_are_discarded(self) -> None:
        parsed = parse_pool_file(PHP_POOL)
        self.assertEqual(parsed, PoolFile((("www", "/run/php/php8.3-fpm.sock"),), includes=False))

    def test_several_pools_in_one_file_are_kept_in_order(self) -> None:
        parsed = parse_pool_file(
            "[www]\nlisten = /run/php/www.sock\n\n[admin]\nlisten = 127.0.0.1:9100\n"
        )
        self.assertEqual(
            parsed,
            PoolFile((("www", "/run/php/www.sock"), ("admin", "127.0.0.1:9100")), includes=False),
        )

    def test_a_pool_without_a_listen_is_reported_without_one(self) -> None:
        self.assertEqual(
            parse_pool_file("[stale]\npm = static\n"), PoolFile((("stale", ""),), includes=False)
        )

    def test_the_global_section_is_not_a_pool(self) -> None:
        self.assertEqual(
            parse_pool_file("[GLOBAL]\nlisten = 9000\n[web]\nlisten = 9001\n"),
            PoolFile((("web", "9001"),), includes=False),
        )

    def test_tcp_addresses_are_supported(self) -> None:
        parsed = parse_pool_file("[web]\nlisten = 127.0.0.1:9000\n")
        self.assertEqual(parsed, PoolFile((("web", "127.0.0.1:9000"),), includes=False))

    def test_quoted_listen_values_are_unquoted(self) -> None:
        parsed = parse_pool_file("[web]\nlisten = \"/run/php/web.sock\"\n[api]\nlisten = '9001'\n")
        self.assertEqual(
            parsed, PoolFile((("web", "/run/php/web.sock"), ("api", "9001")), includes=False)
        )

    def test_pool_name_in_listen_values_is_expanded(self) -> None:
        parsed = parse_pool_file("[shop]\nlisten = /run/php/php8.3-fpm-$pool.sock\n")
        self.assertEqual(
            parsed, PoolFile((("shop", "/run/php/php8.3-fpm-shop.sock"),), includes=False)
        )

    def test_includes_are_reported_but_not_followed(self) -> None:
        parsed = parse_pool_file("[web]\nlisten = 9000\ninclude = /etc/php/extra/*.conf\n")
        self.assertEqual(parsed, PoolFile((("web", "9000"),), includes=True))

    def test_listen_values_outside_the_supported_charset_are_unsupported(self) -> None:
        self.assertIsNone(parse_pool_file("[web]\nlisten = /run/x $(touch /tmp/y)\n"))

    def test_duplicate_listen_directives_are_unsupported(self) -> None:
        self.assertIsNone(parse_pool_file("[web]\nlisten = 9000\nlisten = 9001\n"))

    def test_duplicate_pools_are_unsupported(self) -> None:
        self.assertIsNone(parse_pool_file("[web]\nlisten = 9000\n[web]\nlisten = 9000\n"))

    def test_pool_names_are_compared_case_insensitively(self) -> None:
        # PHP-FPM treats [Web] and [web] as one pool and merges them.
        self.assertIsNone(parse_pool_file("[web]\nlisten = 9000\n[Web]\nlisten = 9001\n"))

    def test_unclosed_section_headers_are_unsupported(self) -> None:
        self.assertIsNone(parse_pool_file("[web\nlisten = 9000\n"))

    def test_section_names_outside_the_supported_charset_are_unsupported(self) -> None:
        self.assertIsNone(parse_pool_file("[we b]\nlisten = 9000\n"))

    def test_lines_that_are_neither_sections_nor_directives_are_unsupported(self) -> None:
        self.assertIsNone(parse_pool_file("[web]\nlisten = 9000\ngarbage\n"))


class NginxTreeParserTests(SimpleTestCase):
    def test_directives_belong_to_the_block_that_encloses_them(self) -> None:
        tree = parse_nginx_tree(
            "server {\n  listen 80;\n  location / {\n    try_files $uri =404;\n  }\n"
            "  location ~ \\.php$ {\n    fastcgi_pass unix:/run/php/a.sock;\n  }\n"
            "  root /var/www/a/public;\n}\n"
        )
        if tree is None:
            self.fail("The file has a tree.")
        (server,) = tree.blocks
        self.assertEqual(server.header, ("server",))
        self.assertEqual(server.directives, (("listen", "80"), ("root", "/var/www/a/public")))
        first, second = server.blocks
        self.assertEqual(first, NginxBlock(("location", "/"), (("try_files", "$uri", "=404"),), ()))
        self.assertEqual(second.header, ("location", "~", "\\.php$"))
        self.assertEqual(second.directives, (("fastcgi_pass", "unix:/run/php/a.sock"),))

    def test_quoted_empty_values_are_kept_as_tokens(self) -> None:
        tree = parse_nginx_tree('location / {\n  fastcgi_param HTTP_PROXY "";\n}\n')
        if tree is None:
            self.fail("The file has a tree.")
        self.assertEqual(tree.blocks[0].directives, (("fastcgi_param", "HTTP_PROXY", ""),))

    def test_malformed_text_has_no_tree(self) -> None:
        for text in (
            "server {\n  listen 80;\n",
            'server {\n  server_name "oops;\n}\n',
            "server {\n  listen 80\n}\n",
            "}\n",
            "{\n}\n",
        ):
            with self.subTest(text=text):
                self.assertIsNone(parse_nginx_tree(text))

    def test_hostile_nesting_and_length_are_refused(self) -> None:
        depth = MAX_BLOCK_DEPTH + 1
        self.assertIsNone(parse_nginx_tree("a {" * depth + "}" * depth))
        self.assertIsNone(parse_nginx_tree("x;\n" * (MAX_STATEMENTS + 1)))
        self.assertIsNone(parse_nginx_tree(f"root {'a' * (MAX_TOKEN + 1)};\n"))

    def test_references_are_the_paths_and_fastcgi_endpoints(self) -> None:
        references = nginx_references(
            "server {\n  root /var/www/html;\n  location /files/ {\n    alias /srv/files/;\n  }\n"
            "  location ~ \\.php$ {\n    fastcgi_pass unix:/run/php/php8.3-fpm.sock;\n  }\n}\n"
        )
        self.assertEqual(
            references,
            NginxReferences(
                ("/var/www/html", "/srv/files/"),
                ("unix:/run/php/php8.3-fpm.sock",),
                dynamic=False,
            ),
        )

    def test_certificate_references_are_captured(self) -> None:
        references = nginx_references(
            "server {\n  ssl_certificate /etc/letsencrypt/live/a/fullchain.pem;\n"
            "  ssl_certificate_key /etc/letsencrypt/live/a/privkey.pem;\n}\n"
        )
        self.assertEqual(
            references,
            NginxReferences(
                (),
                (),
                dynamic=False,
                certificates=("/etc/letsencrypt/live/a/fullchain.pem",),
                certificate_keys=("/etc/letsencrypt/live/a/privkey.pem",),
            ),
        )
        dynamic = nginx_references(
            "server {\n  ssl_certificate /etc/letsencrypt/live/$id/fullchain.pem;\n}\n"
        )
        self.assertTrue(dynamic is not None and dynamic.dynamic)

    def test_includes_and_variables_leave_references_unknown(self) -> None:
        for text in (
            "server {\n  root /var/www/html;\n  include snippets/site.conf;\n}\n",
            "server {\n  root /var/www/$host;\n}\n",
            "server {\n  location / {\n    fastcgi_pass $backend;\n  }\n}\n",
        ):
            with self.subTest(text=text):
                references = nginx_references(text)
                self.assertTrue(references is not None and references.dynamic)

    def test_known_includes_leave_references_known(self) -> None:
        text = "server {\n  location / {\n    include fastcgi.conf;\n  }\n}\n"
        self.assertEqual(
            nginx_references(text, frozenset({"fastcgi.conf"})),
            NginxReferences((), (), dynamic=False),
        )
        references = nginx_references(text.replace("fastcgi.conf", "fastcgi_params"))
        self.assertTrue(references is not None and references.dynamic)

    def test_block_headers_do_not_change_site_file_observations(self) -> None:
        # The tree keeps location arguments; the site file observation still reads only
        # server-level names, listens and TLS references.
        self.assertEqual(
            parse_nginx_site(NGINX_SITE),
            NginxSite(
                ("example.com", "www.example.net", "weird.example.org"),
                ("80", "[::]:80", "443"),
                includes=False,
                certificates=("/etc/letsencrypt/live/example.com/fullchain.pem",),
            ),
        )

    def test_site_parser_captures_certificate_references(self) -> None:
        text = (
            "server {\n  listen 443 ssl;\n  server_name a.example;\n"
            "  ssl_certificate /etc/letsencrypt/live/a/fullchain.pem;\n"
            "  ssl_certificate_key /etc/letsencrypt/live/a/privkey.pem;\n}\n"
        )
        parsed = parse_nginx_site(text)
        self.assertEqual(
            parsed,
            NginxSite(
                ("a.example",),
                ("443",),
                includes=False,
                certificates=("/etc/letsencrypt/live/a/fullchain.pem",),
                certificate_keys=("/etc/letsencrypt/live/a/privkey.pem",),
            ),
        )


SITE_POOL = """\
; A site's pool.
[shop]
user = sshop
group = sshop
listen = /run/php/s$pool.sock
listen.mode = '0600'
pm = ondemand
env[DATABASE_PASSWORD] = hunter2
php_admin_value[memory_limit] = 64M
"""


class PoolSectionParserTests(SimpleTestCase):
    def test_supported_settings_are_kept_and_others_counted(self) -> None:
        self.assertEqual(
            parse_pool_sections(SITE_POOL),
            (
                PoolSection(
                    "shop",
                    (
                        ("user", "sshop"),
                        ("group", "sshop"),
                        ("listen", "/run/php/sshop.sock"),
                        ("listen.mode", "0600"),
                        ("pm", "ondemand"),
                    ),
                    others=2,
                    includes=False,
                ),
            ),
        )

    def test_secret_names_and_values_are_never_kept(self) -> None:
        kept = repr(parse_pool_sections(SITE_POOL))
        for secret in ("hunter2", "DATABASE_PASSWORD", "memory_limit"):
            self.assertNotIn(secret, kept)

    def test_each_section_is_kept_with_its_includes(self) -> None:
        sections = parse_pool_sections(
            "[www]\nuser = www-data\n[shop]\ninclude = /etc/php/extra.conf\n"
        )
        if sections is None:
            self.fail("The file has sections.")
        self.assertEqual([(s.name, s.includes) for s in sections], [("www", False), ("shop", True)])

    def test_unsupported_pool_files_have_no_sections(self) -> None:
        for text in (
            "user = sshop\n[shop]\n",
            "[shop]\nuser = sshop\nuser = other\n",
            "[shop]\nlisten = /run/php/x.sock; $(touch /tmp/x)\n",
            "[shop]\ngarbage\n",
            "[shop\nuser = sshop\n",
            "[shop]\n" + "; comment\n" * MAX_POOL_LINES,
        ):
            with self.subTest(text=text[:40]):
                self.assertIsNone(parse_pool_sections(text))


PACKAGED = frozenset({("", "/etc/nginx/modules-enabled/*.conf"), ("http", "/etc/nginx/mime.types")})


class MainConfigurationParserTests(SimpleTestCase):
    def test_packaged_includes_are_not_extras(self) -> None:
        text = (
            "include /etc/nginx/modules-enabled/*.conf;\n"
            "http {\n  include /etc/nginx/mime.types;\n}\n"
        )
        self.assertEqual(nginx_main_extras(text, PACKAGED), ())

    def test_other_includes_and_server_blocks_are_extras(self) -> None:
        text = (
            "include /etc/nginx/mime.types;\n"
            "http {\n  include /etc/nginx/vhosts/*.conf;\n  server {\n    listen 80;\n  }\n}\n"
        )
        self.assertEqual(
            nginx_main_extras(text, PACKAGED),
            (
                "include /etc/nginx/mime.types",
                "include /etc/nginx/vhosts/*.conf",
                "1 server block",
            ),
        )
        self.assertIsNone(nginx_main_extras("http {\n", PACKAGED))

    def test_php_fpm_conf_extras_are_other_includes_and_pools(self) -> None:
        pool_include = "/etc/php/8.3/fpm/pool.d/*.conf"
        stock = f"[global]\npid = /run/php/php8.3-fpm.pid\ninclude={pool_include}\n"
        self.assertEqual(fpm_main_extras(stock, pool_include), ())
        self.assertEqual(
            fpm_main_extras(
                f"{stock}include=/etc/php/x/*.conf\n[web]\nlisten = 9000\n", pool_include
            ),
            ("include=/etc/php/x/*.conf", "the pool section [web]"),
        )
        self.assertIsNone(fpm_main_extras("[global]\ngarbage\n", pool_include))

    def test_default_listeners_are_referenced(self) -> None:
        references = nginx_references(
            "server {\n  listen 80 default_server;\n  listen [::]:80 default;\n  listen 443;\n}\n"
        )
        self.assertEqual(references and references.defaults, ("80", "[::]:80"))
