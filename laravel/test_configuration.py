"""The reviewed Laravel environment and repository trust grammar (Phase B #382)."""

from django.test import SimpleTestCase

from . import configuration


class RepositoryLocatorTests(SimpleTestCase):
    def test_accepts_credential_free_https_and_fixed_ssh_locators(self) -> None:
        for value in (
            "https://github.com/acme/shop.git",
            "https://git.example.com:8443/acme/shop",
            "git@github.com:acme/shop.git",
            "deploy@git.example.com:acme/shop.git",
        ):
            with self.subTest(value=value):
                self.assertEqual(configuration.repository_locator(value), value)

    def test_refuses_credentials_transports_and_git_options(self) -> None:
        for value in (
            "https://user:token@github.com/acme/shop.git",
            "https://token@github.com/acme/shop.git",
            "ext::sh -c whoami",
            "file:///srv/repo",
            "ssh://git@github.com/acme/shop.git",
            "git://github.com/acme/shop.git",
            "--upload-pack=/bin/sh",
            "-u",
            "git@github.com:acme/shop.git --config core.sshCommand=x",
            "",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                configuration.repository_locator(value)


class RepositoryRefTests(SimpleTestCase):
    def test_accepts_ordinary_branches_and_tags(self) -> None:
        for value in ("main", "release/13.x", "v13.17.0", "feature-1.2"):
            with self.subTest(value=value):
                self.assertEqual(configuration.repository_ref(value), value)

    def test_refuses_refs_git_would_treat_as_options_or_bad_names(self) -> None:
        for value in (
            "-u",
            "@",
            "main..other",
            "main@{1}",
            "a b",
            "a~1",
            "a^",
            "a:b",
            "a?",
            "a*",
            "/main",
            "main/",
            "main//x",
            ".hidden",
            "a.lock",
            "main.",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                configuration.repository_ref(value)


class FingerprintTests(SimpleTestCase):
    def test_accepts_openssh_sha256_fingerprints_only(self) -> None:
        self.assertTrue(
            configuration.valid_fingerprint("SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s")
        )
        self.assertFalse(configuration.valid_fingerprint("MD5:aa:bb"))
        self.assertFalse(configuration.valid_fingerprint("SHA256:short"))


class EnvironmentTests(SimpleTestCase):
    def test_renders_laravel_production_defaults_with_the_socket_connection(self) -> None:
        environment = configuration.render_environment(
            app_url="https://shop.example.com",
            app_key="base64:" + "A" * 43 + "=",
            connection="mariadb",
            host="localhost",
            port="3306",
            database="sshop",
            username="sshop",
            socket="/run/mysqld/mysqld.sock",
        )
        lines = environment.splitlines()
        self.assertEqual(lines[0], "APP_NAME=Laravel")
        self.assertIn("APP_ENV=production", lines)
        self.assertIn("APP_DEBUG=false", lines)
        self.assertIn("APP_URL=https://shop.example.com", lines)
        self.assertIn("LOG_CHANNEL=daily", lines)
        self.assertIn("LOG_DAILY_DAYS=14", lines)
        self.assertIn("DB_CONNECTION=mariadb", lines)
        self.assertIn("DB_DATABASE=sshop", lines)
        self.assertIn("DB_USERNAME=sshop", lines)
        self.assertIn("DB_PASSWORD=", lines)
        self.assertIn("DB_SOCKET=/run/mysqld/mysqld.sock", lines)
        self.assertTrue(environment.endswith("\n"))

    def test_postgresql_uses_the_socket_directory_and_needs_no_socket_key(self) -> None:
        environment = configuration.render_environment(
            app_url="https://shop.example.com",
            app_key="base64:" + "A" * 43 + "=",
            connection="pgsql",
            host="/var/run/postgresql",
            port="5432",
            database="sshop",
            username="sshop",
        )
        self.assertIn("DB_CONNECTION=pgsql", environment)
        self.assertIn("DB_HOST=/var/run/postgresql", environment)
        self.assertNotIn("DB_SOCKET", environment)

    def test_refuses_an_application_url_without_a_scheme(self) -> None:
        with self.assertRaises(ValueError):
            configuration.render_environment(
                app_url="shop.example.com",
                app_key="base64:" + "A" * 43 + "=",
                connection="mariadb",
                host="localhost",
                port="3306",
                database="sshop",
                username="sshop",
            )
