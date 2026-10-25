"""The WordPress convention: the pinned archive, salts and private configuration."""

from django.test import SimpleTestCase

from . import convention


class CoreVersionTests(SimpleTestCase):
    def test_reads_one_version_literal(self) -> None:
        text = "<?php\n$wp_version = '7.1.3';\n"
        self.assertEqual(convention.version_of(text), "7.1.3")

    def test_refuses_no_or_repeated_version_literals(self) -> None:
        for text in ("", "<?php\n", "$wp_version = '7.1.3';\n$wp_version = '7.2';\n"):
            with self.subTest(text=text):
                self.assertEqual(convention.version_of(text), "")


class PrivateConfigurationTests(SimpleTestCase):
    def test_renders_supported_configuration_with_eight_salts(self) -> None:
        salts = convention.new_salts()
        text = convention.render_private_configuration("shop", salts)
        self.assertEqual(convention.private_configuration_problem(text, "shop"), "")
        self.assertIn("define( 'DB_HOST', 'localhost:/run/mysqld/mysqld.sock' );", text)
        self.assertIn("$table_prefix = 'wp_';", text)
        self.assertIn("$_SERVER['REQUEST_URI'] = $_SERVER['HTTP_X_FORWARDED_URI'];", text)
        for salt in salts:
            self.assertIn(salt, text)

    def test_refuses_a_changed_database_or_salt(self) -> None:
        text = convention.render_private_configuration("shop", convention.new_salts())
        for changed in (
            text.replace("define( 'DB_NAME', 'sshop' );", "define( 'DB_NAME', 'other' );"),
            text.replace("AUTH_KEY", "AUTH_KEY_EXTRA"),
            text.replace("$table_prefix = 'wp_';", "$table_prefix = 'x_';"),
        ):
            with self.subTest(changed=changed[:40]):
                self.assertNotEqual(convention.private_configuration_problem(changed, "shop"), "")

    def test_loader_is_exact(self) -> None:
        loader = convention.render_loader("shop")
        self.assertEqual(convention.loader_problem(loader, "shop"), "")
        self.assertNotEqual(convention.loader_problem(loader + "\n", "shop"), "")

    def test_salts_are_generated_on_the_server(self) -> None:
        first, second = convention.new_salts(), convention.new_salts()
        self.assertEqual(len(first), len(convention.SALTS))
        self.assertTrue(all(convention.SALT_VALUE.fullmatch(salt) for salt in first))
        self.assertNotEqual(first, second)


SOCKET = convention.cache_socket("shop")


class CacheConstantTests(SimpleTestCase):
    """The Barectl-owned cache constants #380 reserved and #392 writes (Phase C)."""

    def test_turning_the_cache_on_adds_the_three_reserved_lines(self) -> None:
        text = convention.render_private_configuration("shop", convention.new_salts())
        wired = convention.set_cache_constants(text, "shop", enabled=True)
        self.assertEqual(convention.private_configuration_problem(wired, "shop"), "")
        self.assertEqual(
            wired[len(text) :],
            "define( 'WP_REDIS_SCHEME', 'unix' );\n"
            f"define( 'WP_REDIS_PATH', '{SOCKET}' );\n"
            "define( 'WP_REDIS_PREFIX', 'sshop:' );\n",
        )
        self.assertEqual(
            convention.cache_wiring(wired, "shop"),
            "complete",
        )
        self.assertEqual(convention.extra_constants(wired, "shop"), [])

    def test_turning_it_off_removes_exactly_those_lines(self) -> None:
        text = convention.render_private_configuration("shop", convention.new_salts())
        wired = convention.set_cache_constants(text, "shop", enabled=True)
        operators = convention.apply_constants(
            wired,
            [{"key": "MY_KEY", "action": "set", "value": "kept"}],
            "shop",
        )
        off = convention.set_cache_constants(operators, "shop", enabled=False)
        self.assertEqual(off, text + "define( 'MY_KEY', 'kept' );\n")
        self.assertEqual(convention.cache_wiring(off, "shop"), "")

    def test_operator_settings_cannot_write_a_reserved_cache_name(self) -> None:
        text = convention.render_private_configuration("shop", convention.new_salts())
        for key in convention.CACHE_CONSTANTS:
            with self.subTest(key=key):
                self.assertTrue(convention.reserved_constant(key))
                self.assertFalse(convention.valid_constant_key(key))
                with self.assertRaises(ValueError):
                    convention.apply_constants(
                        text, [{"key": key, "action": "set", "value": "x"}], "shop"
                    )

    def test_a_hand_edited_cache_line_is_outside_the_grammar(self) -> None:
        text = convention.render_private_configuration("shop", convention.new_salts())
        wired = convention.set_cache_constants(text, "shop", enabled=True)
        for changed in (
            wired.replace("'unix'", "'tcp'"),
            wired.replace(SOCKET, "/run/valkey/other/valkey.sock"),
            wired.replace("'sshop:'", "'shared:'"),
        ):
            with self.subTest(changed=changed[-60:]):
                self.assertNotEqual(convention.private_configuration_problem(changed, "shop"), "")
        partial = wired.replace("define( 'WP_REDIS_PREFIX', 'sshop:' );\n", "")
        self.assertEqual(convention.private_configuration_problem(partial, "shop"), "")
        self.assertEqual(convention.cache_wiring(partial, "shop"), "partial")
