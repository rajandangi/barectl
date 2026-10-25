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


class OwnedConstantTests(SimpleTestCase):
    """The Phase C lines (#357) the supported grammar accepts and the settings never edit."""

    def test_a_barectl_owned_constant_is_accepted_with_its_fixed_value_grammar(self) -> None:
        text = convention.render_private_configuration("shop", convention.new_salts())
        with_cron = convention.apply_owned_constant(text, "DISABLE_WP_CRON", "true", "shop")
        self.assertEqual(convention.private_configuration_problem(with_cron, "shop"), "")
        self.assertEqual(convention.cron_disabled(with_cron, "shop"), "true")
        self.assertEqual(convention.extra_constants(with_cron, "shop"), [])

    def test_clearing_the_constant_removes_only_that_line(self) -> None:
        text = convention.render_private_configuration("shop", convention.new_salts())
        with_cron = convention.apply_owned_constant(text, "DISABLE_WP_CRON", "true", "shop")
        cleared = convention.apply_owned_constant(with_cron, "DISABLE_WP_CRON", "", "shop")
        self.assertEqual(cleared, text)
        self.assertEqual(convention.cron_disabled(cleared, "shop"), "")

    def test_a_set_owned_constant_keeps_the_operator_constants(self) -> None:
        text = convention.render_private_configuration(
            "shop", convention.new_salts(), (("MAIL_HOST", "smtp.example.com"),)
        )
        updated = convention.apply_owned_constant(text, "DISABLE_WP_CRON", "true", "shop")
        self.assertEqual(
            convention.extra_constants(updated, "shop"), [("MAIL_HOST", "smtp.example.com")]
        )

    def test_an_owned_constant_outside_its_grammar_is_not_supported(self) -> None:
        text = convention.render_private_configuration("shop", convention.new_salts())
        for key, value in (
            ("DISABLE_WP_CRON", "yes"),
            ("WP_REDIS_SCHEME", "tcp"),
            ("WP_REDIS_PATH", "/etc/valkey.sock"),
            ("WP_REDIS_PREFIX", "has space"),
        ):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    convention.apply_owned_constant(text, key, value, "shop")
                written = text + f"define( '{key}', '{value}' );\n"
                self.assertNotEqual(convention.private_configuration_problem(written, "shop"), "")

    def test_the_reserved_object_cache_names_stay_closed_to_operator_edits(self) -> None:
        for key in ("WP_REDIS_SCHEME", "WP_REDIS_PATH", "WP_REDIS_PREFIX", "WP_REDIS_PORT"):
            with self.subTest(key=key):
                self.assertTrue(convention.reserved_constant(key))
                self.assertFalse(convention.valid_constant_key(key))
