"""Focused fixtures for the Nginx site and PHP-FPM pool configuration parsers.

The parsers turn configuration text into the only fields Barectl keeps: server names and
listen addresses for Nginx sites, pool names and listen addresses for PHP-FPM pools.
Everything else in a file, including environment values and credentials, is discarded
here, before any persistence.
"""

from django.test import SimpleTestCase

from .observations.parsers import NginxSite, PoolFile, parse_nginx_site, parse_pool_file

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
