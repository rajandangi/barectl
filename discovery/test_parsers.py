"""Focused fixtures for the Nginx site and PHP-FPM pool configuration parsers.

The parsers turn configuration text into the only fields Barectl keeps: server names and
listen addresses for Nginx sites, pool names and listen addresses for PHP-FPM pools.
Everything else in a file, including environment values and credentials, is discarded
here, before any persistence.
"""

from django.test import SimpleTestCase

from .observations import parse_nginx_site, parse_pool_file

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
            (
                ("example.com", "www.example.net", "weird.example.org"),
                ("80", "[::]:80", "443"),
            ),
        )

    def test_listen_flags_and_unix_sockets_are_supported(self) -> None:
        parsed = parse_nginx_site(
            "server {\n  listen unix:/run/nginx.sock;\n  listen 127.0.0.1:8080 default_server;\n}\n"
        )
        self.assertEqual(parsed, ((), ("unix:/run/nginx.sock", "127.0.0.1:8080")))

    def test_comments_and_empty_statements_are_ignored(self) -> None:
        parsed = parse_nginx_site(
            "# a comment\nserver {\n  # another\n  ;\n  listen 80; # trailing\n"
            "  server_name a.example;\n}\n"
        )
        self.assertEqual(parsed, (("a.example",), ("80",)))

    def test_server_nameless_block_is_a_supported_catch_all(self) -> None:
        parsed = parse_nginx_site("server {\n  listen 80 default_server;\n}\n")
        self.assertEqual(parsed, ((), ("80",)))

    def test_regex_server_names_are_unsupported(self) -> None:
        self.assertIsNone(parse_nginx_site("server {\n  server_name ~^www\\d+\\.example;\n}\n"))

    def test_names_outside_the_supported_charset_are_unsupported(self) -> None:
        self.assertIsNone(parse_nginx_site("server {\n  server_name a b$(touch /tmp/x);\n}\n"))

    def test_listen_addresses_outside_the_supported_charset_are_unsupported(self) -> None:
        self.assertIsNone(parse_nginx_site("server {\n  listen $(touch /tmp/x);\n}\n"))

    def test_unknown_directives_outside_server_blocks_are_ignored(self) -> None:
        self.assertEqual(
            parse_nginx_site("$(touch /tmp/x);\nserver {\n  listen 80;\n}\n"), ((), ("80",))
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


class PhpPoolParserTests(SimpleTestCase):
    def test_pool_yields_its_name_and_listen(self) -> None:
        self.assertEqual(parse_pool_file(PHP_POOL), (("www", "/run/php/php8.3-fpm.sock"),))

    def test_environment_and_php_values_are_discarded(self) -> None:
        parsed = parse_pool_file(PHP_POOL)
        self.assertEqual(parsed, (("www", "/run/php/php8.3-fpm.sock"),))

    def test_several_pools_in_one_file_are_kept_in_order(self) -> None:
        parsed = parse_pool_file(
            "[www]\nlisten = /run/php/www.sock\n\n[admin]\nlisten = 127.0.0.1:9100\n"
        )
        self.assertEqual(parsed, (("www", "/run/php/www.sock"), ("admin", "127.0.0.1:9100")))

    def test_a_pool_without_a_listen_is_reported_without_one(self) -> None:
        self.assertEqual(parse_pool_file("[stale]\npm = static\n"), (("stale", ""),))

    def test_the_global_section_is_not_a_pool(self) -> None:
        self.assertEqual(
            parse_pool_file("[global]\nlisten = 9000\n[web]\nlisten = 9001\n"), (("web", "9001"),)
        )

    def test_tcp_addresses_are_supported(self) -> None:
        parsed = parse_pool_file("[web]\nlisten = 127.0.0.1:9000\n")
        self.assertEqual(parsed, (("web", "127.0.0.1:9000"),))

    def test_listen_values_outside_the_supported_charset_are_unsupported(self) -> None:
        self.assertIsNone(parse_pool_file("[web]\nlisten = /run/x $(touch /tmp/y)\n"))

    def test_duplicate_listen_directives_are_unsupported(self) -> None:
        self.assertIsNone(parse_pool_file("[web]\nlisten = 9000\nlisten = 9001\n"))

    def test_duplicate_pools_are_unsupported(self) -> None:
        self.assertIsNone(parse_pool_file("[web]\nlisten = 9000\n[web]\nlisten = 9000\n"))

    def test_unclosed_section_headers_are_unsupported(self) -> None:
        self.assertIsNone(parse_pool_file("[web\nlisten = 9000\n"))

    def test_section_names_outside_the_supported_charset_are_unsupported(self) -> None:
        self.assertIsNone(parse_pool_file("[we b]\nlisten = 9000\n"))

    def test_lines_that_are_neither_sections_nor_directives_are_unsupported(self) -> None:
        self.assertIsNone(parse_pool_file("[web]\nlisten = 9000\ngarbage\n"))
