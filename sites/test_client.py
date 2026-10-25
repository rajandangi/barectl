"""The per-site object-cache PHP client: rendering and native recognition (#390)."""

import pathlib
from types import SimpleNamespace
from typing import ClassVar
from unittest import mock

from django.test import SimpleTestCase

from runtimes.catalog import Architecture
from runtimes.extensions import path as redis_path
from sites.bodies.common import php_wrapper_variant, pool_file, site_fpm_files, wrapper
from sites.bodies.pool import (
    SitePool,
    pool_extension,
    render_pool_settings,
    supported_pool,
    without_extension,
)
from sites.configuration import SiteSettings, render_pool
from sites.serving import diagnostic_pool

SHOP = SiteSettings("shop", ("shop.example.com",), "php84")
EXTENSION = redis_path(Architecture.AARCH64, "php84")


class Ceiling:
    """The offline body markers normal bodies replace with the app's own render sources."""

    saved_pool: ClassVar[str] = ""
    saved_master: ClassVar[dict[str, dict[str, str]]] = {}

    @classmethod
    def setUpClass(cls) -> None:
        import sites.bodies.common as common
        from runtimes.configuration import render

        cls.saved_pool = common.POOL_TEMPLATE
        cls.saved_master = common.NATIVE_MASTER_FILES
        common.POOL_TEMPLATE = render_pool(SiteSettings("shop", ("shop.example.com",), "php84"))
        common.NATIVE_MASTER_FILES = {
            entry: {"php.ini": render(entry).ini, "php-fpm.conf": render(entry).master}
            for entry in ("php84", "php85")
        }

    @classmethod
    def tearDownClass(cls) -> None:
        import sites.bodies.common as common

        common.POOL_TEMPLATE = cls.saved_pool
        common.NATIVE_MASTER_FILES = cls.saved_master


class ClientRenderingTests(Ceiling, SimpleTestCase):
    def test_the_enabled_pool_and_diagnostic_pool_name_the_locked_shared_object(self) -> None:
        self.assertTrue(EXTENSION.endswith("/lib/php/extensions/redis.so"))
        pool = pool_file(SHOP, EXTENSION)
        self.assertIn(f"php_admin_value[extension] = {EXTENSION}\n", pool)
        diagnostic = diagnostic_pool(SHOP, EXTENSION)
        self.assertIn(f"php_admin_value[extension] = {EXTENSION}\n", diagnostic)
        self.assertNotIn("php_admin_value[extension]", pool_file(SHOP))
        self.assertNotIn("php_admin_value[extension]", diagnostic_pool(SHOP))
        files = site_fpm_files(SHOP, EXTENSION)
        self.assertIn(EXTENSION, files["/etc/php-fpm/sites/shop/php84/pools/shop.conf"])
        self.assertIn(EXTENSION, files["/etc/php-fpm/sites/shop/php84/pools/diagnostic.conf"])

    def test_the_cli_wrapper_names_the_extension_on_the_command_line(self) -> None:
        php = wrapper(SHOP, "php", EXTENSION)
        self.assertIn(f"-dextension={EXTENSION}", php)
        self.assertTrue(php.startswith("#!/bin/sh\nexec "))
        self.assertIn(
            f'"/nix/var/nix/profiles/barectl/php84/bin/php" -dextension={EXTENSION} "$@"', php
        )
        composer = wrapper(SHOP, "composer", EXTENSION)
        self.assertIn(
            f'"/nix/var/nix/profiles/barectl/php84/bin/php" -dextension={EXTENSION} '
            '"/nix/var/nix/profiles/barectl/composer/share/php/composer/bin/composer" "$@"',
            composer,
        )
        self.assertNotIn("-dextension=", wrapper(SHOP, "php"))

    def test_a_pool_with_the_client_is_supported_only_with_that_exact_store_path(self) -> None:
        plain = render_pool(SHOP)
        enabled = pool_file(SHOP, EXTENSION)
        self.assertTrue(supported_pool("shop", "php84", plain))
        self.assertTrue(supported_pool("shop", "php84", enabled, EXTENSION))
        self.assertFalse(supported_pool("shop", "php84", enabled))
        self.assertFalse(
            supported_pool("shop", "php84", pool_file(SHOP, "not-a-store-path"), "not-a-store-path")
        )
        self.assertFalse(
            supported_pool("shop", "php84", enabled.replace("redis.so", "evil.so"), EXTENSION)
        )
        self.assertTrue(
            supported_pool("shop", "php84", render_pool_settings(enabled, _pool()), EXTENSION)
        )

    def test_only_the_client_line_is_added_or_removed(self) -> None:
        enabled = pool_file(SHOP, EXTENSION)
        self.assertEqual(pool_extension(enabled, "shop"), EXTENSION)
        self.assertEqual(pool_extension(without_extension(enabled), "shop"), "")
        self.assertEqual(without_extension(enabled), render_pool(SHOP))


def _pool() -> SitePool:
    return SitePool()


class WrapperRecognitionTests(SimpleTestCase):
    def site_settings(self) -> SimpleNamespace:
        return SimpleNamespace(
            identifier="shop",
            names=["shop.example.com"],
            runtime="php84",
            directory="/var/www/shop",
            account="sshop",
            proxy="pshop",
        )

    def test_all_three_commands_agreeing_on_the_client_are_recognized(self) -> None:
        settings = self.site_settings()
        contents = {name: wrapper(settings, name, EXTENSION) for name in ("php", "composer", "wp")}
        with (
            mock.patch.object(
                pathlib.Path,
                "read_text",
                autospec=True,
                side_effect=lambda path: contents[path.name],
            ),
            mock.patch("sites.bodies.common.safe", return_value=True),
            mock.patch("sites.bodies.common.metadata_matches", return_value=True),
            mock.patch("sites.bodies.common.known_redis", return_value=EXTENSION),
        ):
            self.assertEqual(php_wrapper_variant(settings), ("php84", EXTENSION))

    def test_one_command_without_the_client_is_not_recognized(self) -> None:
        settings = self.site_settings()
        contents = {name: wrapper(settings, name, EXTENSION) for name in ("php", "composer", "wp")}
        contents["wp"] = wrapper(settings, "wp")
        with (
            mock.patch.object(
                pathlib.Path,
                "read_text",
                autospec=True,
                side_effect=lambda path: contents[path.name],
            ),
            mock.patch("sites.bodies.common.safe", return_value=True),
            mock.patch("sites.bodies.common.metadata_matches", return_value=True),
            mock.patch("sites.bodies.common.known_redis", return_value=EXTENSION),
        ):
            self.assertIsNone(php_wrapper_variant(settings))
