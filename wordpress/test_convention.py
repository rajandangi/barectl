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
