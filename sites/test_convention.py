"""The generated files, and that discovery reads them as a complete convention site."""

from django.test import SimpleTestCase

from discovery.fakes import pool_config, site_config

from .convention import (
    SitePaths,
    probe_marker,
    recognize_pool,
    recognize_site,
    render_placeholder,
    render_pool,
    render_probe,
    render_site,
)

NAMES = ("shop.example.com", "www.shop.example.com")
PROBE = "0123456789abcdef0123456789abcdef"


class TemplateTests(SimpleTestCase):
    def test_the_site_file_is_the_documented_template(self) -> None:
        """docs/site-conventions.md#supported-configuration-grammar"""
        self.assertEqual(render_site("shop", NAMES, ipv6=True), site_config("shop", NAMES))
        without = render_site("shop", NAMES, ipv6=False)
        self.assertEqual(without, site_config("shop", NAMES).replace("\tlisten [::]:80;\n", ""))
        self.assertTrue(without.isascii())
        self.assertNotIn("default_server", without)

    def test_the_pool_is_the_documented_template(self) -> None:
        self.assertEqual(render_pool("shop"), pool_config("shop"))
        self.assertEqual(len(render_pool("a" * 24).encode()), 323)

    def test_the_placeholder_and_probe_are_exact(self) -> None:
        self.assertEqual(
            render_placeholder("shop"),
            '<!DOCTYPE html>\n<html lang="en">\n'
            '<head><meta charset="utf-8"><title>shop</title></head>\n'
            "<body><p>Site shop is ready.</p></body>\n</html>\n",
        )
        probe = render_probe(PROBE)
        self.assertEqual(
            probe,
            f'<?php\necho "barectl-probe {PROBE} " . posix_geteuid() . " " . '
            'posix_getegid() . "\\n";\n',
        )
        self.assertNotIn("phpinfo", probe)
        self.assertEqual(probe_marker(PROBE), f"barectl-probe {PROBE} ")
        with self.assertRaises(ValueError):
            render_probe("../etc")

    def test_paths_follow_the_convention(self) -> None:
        paths = SitePaths("shop", "8.5")
        self.assertEqual(
            (paths.user, paths.source, paths.link, paths.pool, paths.socket, paths.public),
            (
                "sshop",
                "/etc/nginx/sites-available/shop.conf",
                "/etc/nginx/sites-enabled/shop.conf",
                "/etc/php/8.5/fpm/pool.d/shop.conf",
                "/run/php/sshop.sock",
                "/var/www/shop/public",
            ),
        )
        with self.assertRaises(ValueError):
            SitePaths("../x", "8.5")


class RecognitionTests(SimpleTestCase):
    def test_both_variants_are_recognized_with_their_names(self) -> None:
        for ipv6 in (True, False):
            recognized = recognize_site("shop", render_site("shop", NAMES, ipv6=ipv6))
            if recognized is None:
                self.fail(ipv6)
            self.assertEqual((recognized.names, recognized.ipv6), (NAMES, ipv6))
        self.assertTrue(recognize_pool("shop", render_pool("shop")))

    def test_any_byte_deviation_is_not_recognized(self) -> None:
        text = render_site("shop", NAMES, ipv6=True)
        for changed in (
            text.replace("\t", "    "),
            text + "\n",
            text.replace("autoindex off;", "autoindex on;"),
            text.replace("listen 80;", "listen 80 default_server;"),
            text.replace("shop.example.com ", "Shop.example.com "),
            text.replace("include fastcgi.conf;", "include snippets/fastcgi-php.conf;"),
            "# comment\n" + text,
        ):
            self.assertIsNone(recognize_site("shop", changed))
        self.assertIsNone(recognize_site("other", text))
        doubled = text.replace("shop.example.com www", "shop.example.com  www")
        self.assertNotEqual(doubled, text)
        self.assertIsNone(recognize_site("shop", doubled))
        self.assertFalse(recognize_pool("shop", render_pool("shop").replace("5", "50")))
        self.assertFalse(recognize_pool("other", render_pool("shop")))
