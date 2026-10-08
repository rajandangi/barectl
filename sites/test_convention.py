"""The generated files, and that discovery reads them as a complete convention site."""

from django.test import SimpleTestCase

from discovery.fakes import pool_config, site_config

from .convention import (
    Application,
    SitePaths,
    Stage,
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
    def test_selected_branch_is_encoded_and_recognized_in_every_stage(self) -> None:
        for version in ("8.3", "8.4", "8.5"):
            for stage in Stage:
                with self.subTest(version=version, stage=stage):
                    paths = SitePaths("shop", version, revision=4)
                    text = render_site("shop", NAMES, ipv6=True, stage=stage, php_version=version)
                    self.assertIn(f"fastcgi_pass unix:{paths.socket};", text)
                    self.assertEqual(paths.socket, f"/run/php/sshop-php{version}.sock")
                    recognized = recognize_site("shop", text)
                    self.assertIsNotNone(recognized)
                    if recognized is None:
                        self.fail("The selected-branch site was not recognized.")
                    self.assertEqual((recognized.php_version, recognized.revision), (version, 4))
                    pool = render_pool("shop", php_version=version)
                    self.assertIn(f"listen = {paths.socket}\n", pool)
                    self.assertTrue(recognize_pool("shop", pool, php_version=version))
                    self.assertFalse(recognize_pool("shop", pool))

    def test_an_unreviewed_branch_or_inconsistent_stage_is_not_recognized(self) -> None:
        text = render_site("shop", NAMES, ipv6=True, stage=Stage.HTTPS, php_version="8.4")
        self.assertIsNone(recognize_site("shop", text.replace("php8.4", "php8.2")))
        self.assertIsNone(recognize_site("shop", text.replace("php8.4", "php8.3", 1)))

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


READY_REDIRECT = """server {
\tlisten 80;
\tlisten [::]:80;
\tserver_name shop.example.com www.shop.example.com;

\tlocation ^~ /.well-known/acme-challenge/ {
\t\troot /var/lib/letsencrypt/shop;
\t\ttry_files $uri =404;
\t}

\tlocation / {
\t\treturn 301 https://shop.example.com$request_uri;
\t}
}

server {
\tlisten 443 ssl;
\tlisten [::]:443 ssl;
\tserver_name shop.example.com;
\troot /var/www/shop/public;
\tindex index.php index.html;
\tautoindex off;
\tssl_certificate /etc/letsencrypt/live/shop/fullchain.pem;
\tssl_certificate_key /etc/letsencrypt/live/shop/privkey.pem;

\tlocation = /wp-config.php {
\t\tdeny all;
\t}

\tlocation ~* ^/wp-content/uploads/.*\\.(?:php[0-9]?|phtml|phar|pht|phps)(?:$|/) {
\t\tdeny all;
\t}

\tlocation / {
\t\ttry_files $uri $uri/ /index.php?$args;
\t}

\tlocation ~ /\\. {
\t\tdeny all;
\t}

\tlocation ~ \\.php$ {
\t\ttry_files $uri =404;
\t\tinclude fastcgi.conf;
\t\tfastcgi_param HTTP_PROXY "";
\t\tfastcgi_pass unix:/run/php/sshop-php8.4.sock;
\t}
}

server {
\tlisten 443 ssl;
\tlisten [::]:443 ssl;
\tserver_name www.shop.example.com;
\tssl_certificate /etc/letsencrypt/live/shop/fullchain.pem;
\tssl_certificate_key /etc/letsencrypt/live/shop/privkey.pem;

\tlocation / {
\t\treturn 301 https://shop.example.com$request_uri;
\t}
}
"""


class WordPressFormTests(SimpleTestCase):
    def test_the_ready_form_is_the_documented_template(self) -> None:
        """docs/site-conventions.md#wordpress-forms"""
        text = render_site(
            "shop",
            NAMES,
            ipv6=True,
            stage=Stage.REDIRECT,
            php_version="8.4",
            application=Application.WORDPRESS,
        )
        self.assertEqual(text, READY_REDIRECT)

    def test_the_gate_serves_503_for_the_application_and_keeps_the_challenge_route(self) -> None:
        text = render_site(
            "shop",
            NAMES,
            ipv6=False,
            stage=Stage.HTTPS,
            application=Application.WORDPRESS_GATE,
        )
        http, _, https = text.partition("\n\nserver {\n\tlisten 443")
        self.assertIn("location ^~ /.well-known/acme-challenge/", http)
        for block in (http, https):
            self.assertIn("location = /wp-admin/install.php {\n\t\treturn 503;\n\t}", block)
            self.assertIn(
                "location ~ \\.php$ {\n\t\tfastcgi_pass unix:/run/php/sshop.sock;"
                "\n\t\treturn 503;\n\t}",
                block,
            )
            self.assertIn("location / {\n\t\treturn 503;\n\t}", block)
            self.assertNotIn("include fastcgi.conf", block)
            self.assertNotIn("try_files $uri $uri/ /index.php", block)

    def test_every_form_is_recognized_with_its_application_branch_and_canonical(self) -> None:
        for application in (Application.WORDPRESS, Application.WORDPRESS_GATE):
            for stage in (Stage.HTTPS, Stage.REDIRECT):
                for version in ("", "8.3", "8.5"):
                    for canonical in NAMES:
                        if stage == Stage.HTTPS and canonical != NAMES[0]:
                            continue
                        for ipv6 in (True, False):
                            with self.subTest(
                                application=application,
                                stage=stage,
                                version=version,
                                canonical=canonical,
                                ipv6=ipv6,
                            ):
                                text = render_site(
                                    "shop",
                                    NAMES,
                                    ipv6=ipv6,
                                    stage=stage,
                                    php_version=version,
                                    application=application,
                                    canonical=canonical,
                                )
                                recognized = recognize_site("shop", text)
                                if recognized is None:
                                    self.fail("Not recognized.")
                                self.assertEqual(
                                    (
                                        recognized.application,
                                        recognized.stage,
                                        recognized.php_version,
                                        recognized.canonical,
                                        recognized.names,
                                        recognized.ipv6,
                                    ),
                                    (application, stage, version, canonical, NAMES, ipv6),
                                )

    def test_generic_forms_keep_their_bytes_and_application(self) -> None:
        text = render_site("shop", NAMES, ipv6=True, stage=Stage.REDIRECT)
        self.assertIn("return 301 https://shop.example.com$request_uri;", text)
        self.assertNotIn("wp-", text)
        recognized = recognize_site("shop", text)
        if recognized is None:
            self.fail("Not recognized.")
        self.assertEqual(recognized.application, Application.PHP)
        self.assertEqual(recognized.canonical_name, NAMES[0])

    def test_unreviewed_deviations_and_canonical_names_are_not_recognized(self) -> None:
        text = render_site(
            "shop", NAMES, ipv6=True, stage=Stage.REDIRECT, application=Application.WORDPRESS
        )
        for changed in (
            text.replace("deny all;", "allow all;", 1),
            text.replace("(?:$|/)", "$"),
            text.replace("https://shop.example.com$", "https://evil.example.net$", 1),
            text.replace("/index.php?$args", "=404"),
            text + "\n",
        ):
            self.assertIsNone(recognize_site("shop", changed))
        with self.assertRaises(ValueError):
            render_site(
                "shop",
                NAMES,
                ipv6=True,
                stage=Stage.REDIRECT,
                application=Application.WORDPRESS,
                canonical="evil.example.net",
            )
        with self.assertRaises(ValueError):
            render_site("shop", NAMES, ipv6=True, application=Application.WORDPRESS)
        with self.assertRaises(ValueError):
            render_site("shop", NAMES, ipv6=True, stage=Stage.REDIRECT, canonical=NAMES[1])
