"""The per-site Valkey convention #392 and #393 build on (docs/adr/0030)."""

import hashlib

from django.test import SimpleTestCase

from wordpress import convention as wordpress_convention

from . import convention
from . import laravel as laravel_convention


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
        self.assertEqual(
            paths.drop_in_directory, "/etc/systemd/system/valkey-server@shop.service.d"
        )
        self.assertEqual(
            paths.drop_in,
            "/etc/systemd/system/valkey-server@shop.service.d/barectl.conf",
        )
        # The WordPress wiring and the instance must name the same private connection.
        self.assertEqual(paths.socket, wordpress_convention.cache_socket("shop"))

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
                    'logfile ""',
                    "pidfile /run/valkey/shop/valkey-server.pid",
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
        self.assertNotIn("requirepass", rendered)
        self.assertNotIn("appendonly yes", rendered)
        self.assertNotIn("save 900", rendered)

    def test_the_drop_in_runs_the_packaged_instance_as_the_site(self) -> None:
        rendered = convention.render_drop_in("shop")
        self.assertIn("User=sshop\n", rendered)
        self.assertIn("Group=sshop\n", rendered)
        self.assertIn("ExecStart=\n", rendered)
        self.assertIn(
            "ExecStart=/usr/bin/valkey-server /etc/valkey/shop.conf "
            "--supervised systemd --daemonize no",
            rendered,
        )
        self.assertIn("RuntimeDirectory=valkey/shop", rendered)
        self.assertIn("RuntimeDirectoryMode=0700", rendered)
        self.assertIn("PIDFile=/run/valkey/shop/valkey-server.pid", rendered)

    def test_a_reviewed_limit_is_supported_and_another_size_is_outside(self) -> None:
        for size in convention.MAXMEMORY_MIB:
            with self.subTest(size=size):
                shape = convention.config_shape("shop", convention.render_config("shop", size))
                self.assertEqual(shape.memory_mib, size)
                self.assertEqual(shape.problem, "")
                self.assertEqual(shape.outside, "")
        outside = convention.config_shape(
            "shop",
            convention.render_config("shop").replace("maxmemory 67108864", "maxmemory 100663296"),
        )
        self.assertEqual(outside.memory_mib, 96)
        self.assertNotEqual(outside.problem, "")
        self.assertNotEqual(outside.outside, "")

    def test_another_change_to_the_instance_is_outside_supported_settings(self) -> None:
        changed = convention.render_config("shop").replace(
            "protected-mode yes", "protected-mode no"
        )
        shape = convention.config_shape("shop", changed)
        self.assertNotEqual(shape.problem, "")
        self.assertEqual(shape.outside, "")

    def test_the_laravel_wiring_is_the_same_private_connection(self) -> None:
        values = laravel_convention.laravel_values("shop")
        self.assertEqual(
            values,
            {
                "CACHE_STORE": "redis",
                "REDIS_HOST": "/run/valkey/shop/valkey.sock",
                "REDIS_PORT": "0",
            },
        )
        self.assertEqual(laravel_convention.laravel_wiring("shop", values), "complete")
        self.assertEqual(
            laravel_convention.laravel_managed("shop", values),
            frozenset(laravel_convention.LARAVEL_KEYS),
        )
        self.assertEqual(laravel_convention.laravel_wiring("shop", {}), "")
        other = {**values, "REDIS_HOST": "/run/valkey/other/valkey.sock"}
        self.assertEqual(laravel_convention.laravel_wiring("shop", other), "partial")
        self.assertEqual(laravel_convention.laravel_managed("shop", other), frozenset())

    def test_a_hand_chosen_store_keeps_its_value_but_not_the_cache_keys(self) -> None:
        values = {**laravel_convention.laravel_values("shop"), "CACHE_STORE": "file"}
        self.assertEqual(
            laravel_convention.laravel_managed("shop", values),
            frozenset({"REDIS_HOST", "REDIS_PORT"}),
        )
        digests = {key: hashlib.sha256(value.encode()).hexdigest() for key, value in values.items()}
        self.assertEqual(
            laravel_convention.laravel_managed_digests("shop", digests),
            frozenset({"REDIS_HOST", "REDIS_PORT"}),
        )
        self.assertEqual(
            laravel_convention.laravel_managed_digests(
                "shop",
                {
                    key: hashlib.sha256(value.encode()).hexdigest()
                    for key, value in laravel_convention.laravel_values("shop").items()
                },
            ),
            frozenset(laravel_convention.LARAVEL_KEYS),
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
