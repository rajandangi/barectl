"""The per-site Valkey convention #392 and #393 build on (docs/adr/0030)."""

from django.test import SimpleTestCase

from . import convention


class ValkeyInstanceConventionTests(SimpleTestCase):
    def test_one_site_gets_one_instance_with_private_paths(self) -> None:
        self.assertEqual(convention.UNIT, "valkey-server.service")
        self.assertEqual(convention.INSTANCE_TEMPLATE, "valkey-server@.service")
        paths = convention.instance_paths("shop")
        self.assertEqual(paths.unit, "valkey-server@shop.service")
        self.assertEqual(paths.config, "/etc/valkey/shop.conf")
        self.assertEqual(paths.socket, "/run/valkey/shop/valkey.sock")
        self.assertEqual(paths.run_directory, "/run/valkey/shop")
        self.assertEqual(paths.data_directory, "/var/lib/valkey/shop")

    def test_the_configuration_is_private_socket_only_and_bounded(self) -> None:
        rendered = convention.render_config("shop")
        self.assertEqual(
            rendered,
            "\n".join(
                (
                    "port 0",
                    "bind 127.0.0.1",
                    "protected-mode yes",
                    "daemonize no",
                    "supervised no",
                    "dir /var/lib/valkey/shop",
                    "unixsocket /run/valkey/shop/valkey.sock",
                    "unixsocketperm 600",
                    'save ""',
                    "appendonly no",
                    "maxmemory 67108864",
                    "maxmemory-policy allkeys-lru",
                    "user default on nopass ~* &* +@all -@admin -debug -module",
                )
            ),
        )

    def test_only_the_reviewed_memory_sizes_are_offered(self) -> None:
        self.assertEqual(convention.MAXMEMORY_MIB, (32, 64, 128, 256))
        for size in convention.MAXMEMORY_MIB:
            with self.subTest(size=size):
                self.assertIn(f"maxmemory {size * 1024**2}", convention.render_config("shop", size))
        for size in (0, 48, 512):
            with self.subTest(size=size), self.assertRaises(ValueError):
                convention.render_config("shop", size)

    def test_a_name_outside_the_site_grammar_is_refused(self) -> None:
        for identifier in ("", "ab", "Shop", "shop;reboot", "shop/other"):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                convention.instance_paths(identifier)
