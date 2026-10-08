"""Passive WordPress application discovery against a disposable server
(docs/wordpress.md#passive-application-discovery).

The server's administrator creates sites, MariaDB databases and WordPress files by hand
through ``docker exec``; Barectl reads them through the dashboard request, the worker and its
SSH connection only, as root and as a lesser identity. A fresh controller database rebuilds the
same evidence, and no PHP or WP-CLI ever runs, which `php` and `wp` stand-ins on the server's
PATH would record.
"""

import os
import secrets
import shlex
import tempfile
from pathlib import Path
from typing import ClassVar, override
from unittest import mock, skipUnless

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, User
from django.test import TestCase, override_settings, tag
from django_tasks_db.models import DBTaskResult

from bootstrap.test_mariadb_remote import INSTALL_MARIADB, REMOVE_MARIADB
from dashboard.testing import TEST_MANIFEST
from discovery.fakes import current, run_worker
from discovery.models import (
    ApplicationState,
    ConfigurationState,
    CoreQualification,
    DiscoveryAttempt,
    LoaderState,
    SchemaState,
    SiteApplicationObservation,
    SiteRouting,
)
from discovery.releases import SUPPORTED
from discovery.snapshot import ObservedSite
from discovery.test_databases_remote import docker, mariadb, mariadb_binding
from discovery.test_remote import CONFIGURED, STATE_COMMAND, NativeShell, setting
from discovery.test_sites_remote import FIXTURES, create_site, remove_site
from servers.models import Server
from servers.registration import remove_server
from sites.convention import Application, Stage, render_site

from . import convention

IDENTIFIER = "shop"
DATABASE = "sshop"
NAMES = ("shop.test", "www.shop.test")
PUBLIC = f"/var/www/{IDENTIFIER}/public"
PRIVATE = f"/var/www/{IDENTIFIER}/private"
PERMISSIONS = (
    "view_server",
    "add_server",
    "add_discoveryattempt",
    "view_siteobservation",
    "view_siteapplicationobservation",
)
PHP_STAND_IN = "#!/bin/sh\ntouch /tmp/barectl-application-code-ran\n"
MARKER = "/tmp/barectl-application-code-ran"  # noqa: S108 - inside the disposable server
RELEASE_FILES = ("index.php", "wp-load.php", "wp-settings.php")
TABLE_STATEMENT = "CREATE TABLE `{database}`.`wp_{table}` ({columns}) ENGINE=InnoDB"


def put(path: str, text: str, owner: str, group: str, mode: str) -> str:
    return (
        f"printf %s {shlex.quote(text)} >{path} && chown {owner}:{group} {path} && "
        f"chmod {mode} {path}"
    )


def salts() -> tuple[str, ...]:
    return tuple(secrets.token_urlsafe(48)[:64] for _ in convention.SALTS)


def core_tables(*, omit: str = "", only: tuple[str, ...] = ()) -> tuple[str, ...]:
    """The administrator's CREATE TABLE statements for the core schema, all columns text."""
    statements = []
    for table, columns in convention.CORE_TABLES.items():
        if only and table not in only:
            continue
        listed = ", ".join(f"`{column}` TEXT" for column in columns if f"{table}.{column}" != omit)
        statements.append(
            mariadb(TABLE_STATEMENT.format(database=DATABASE, table=table, columns=listed))
        )
    return tuple(statements)


def options(url: str) -> str:
    return mariadb(
        f"INSERT INTO `{DATABASE}`.`wp_options` (option_id, option_name, option_value, autoload) "  # noqa: S608 - the tests' own fixture statements
        f"VALUES (1, 'siteurl', '{url}', 'yes'), (2, 'home', '{url}', 'yes')"
    )


def tree(version: str = convention.CORE_VERSION) -> tuple[str, ...]:
    """The release files, as the administrator extracted them."""
    files = [
        put(f"{PUBLIC}/{name}", "<?php\n", f"s{IDENTIFIER}", "www-data", "640")
        for name in RELEASE_FILES
    ]
    return (
        (
            f"install -d -o s{IDENTIFIER} -g www-data -m 750 "
            f"{PUBLIC}/wp-admin {PUBLIC}/wp-includes {PUBLIC}/wp-content"
        ),
        *files,
        put(
            f"{PUBLIC}/wp-includes/version.php",
            f"<?php\n$wp_version = '{version}';\n",
            f"s{IDENTIFIER}",
            "www-data",
            "640",
        ),
    )


def configuration() -> tuple[str, ...]:
    user = f"s{IDENTIFIER}"
    return (
        put(
            f"{PUBLIC}/wp-config.php", convention.render_loader(IDENTIFIER), user, "www-data", "640"
        ),
        put(
            f"{PRIVATE}/wp-config.php",
            convention.render_private_configuration(IDENTIFIER, salts()),
            user,
            user,
            "600",
        ),
    )


def routing(application: Application, canonical: str = "") -> str:
    text = render_site(
        IDENTIFIER, NAMES, ipv6=True, stage=Stage.REDIRECT, application=application,
        canonical=canonical,
    )  # fmt: skip
    # The activated forms keep the challenge webroot, which makes the site's own state complete.
    return f"install -d -o root -g www-data -m 750 /var/lib/letsencrypt/{IDENTIFIER} && " + put(
        f"/etc/nginx/sites-available/{IDENTIFIER}.conf", text, "root", "root", "644"
    )


def reset() -> str:
    return "; ".join(
        (
            f"rm -rf {PUBLIC}/* {PUBLIC}/.[!.]* {PRIVATE}/* {MARKER}",
            mariadb(f"DROP DATABASE IF EXISTS `{DATABASE}`"),
            mariadb(
                f"CREATE DATABASE `{DATABASE}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            ),
            "true",
        )
    )


@tag("ssh")
@skipUnless(FIXTURES and CONFIGURED, "Set BARECTL_SSH_TEST_* and the server's container")
class ApplicationReconstructionTests(TestCase):
    user: ClassVar[User]
    php: ClassVar[str]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        release = docker(". /etc/os-release; echo $VERSION_ID").strip()
        cls.php = SUPPORTED[release].php
        cls.addClassCleanup(docker, REMOVE_MARIADB)
        docker(INSTALL_MARIADB)

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.user = get_user_model().objects.create_user("operator")
        for codename in PERMISSIONS:
            cls.user.user_permissions.add(Permission.objects.get(codename=codename))

    @override
    def setUp(self) -> None:
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir="/tmp")))
        self.config = directory / "config"
        self.native = NativeShell(directory)
        self.addCleanup(self.native.close)
        self.enterContext(
            override_settings(SSH_CONFIG_PATH=str(self.config), VITE_MANIFEST_PATH=TEST_MANIFEST)
        )
        self.enterContext(mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": ""}))
        self.client.force_login(self.user)
        self.addCleanup(self.administer, remove_site(self.php, IDENTIFIER))
        self.addCleanup(self.administer, f"rm -rf /var/lib/letsencrypt/{IDENTIFIER}")
        self.addCleanup(self.administer, "rm -f /usr/local/bin/php /usr/local/bin/wp " + MARKER)
        self.addCleanup(self.administer, mariadb(f"DROP DATABASE IF EXISTS `{DATABASE}`"))
        self.addCleanup(self.administer, mariadb(f"DROP USER IF EXISTS `{DATABASE}`@`localhost`"))
        self.administer(create_site(self.php, IDENTIFIER), *mariadb_binding(DATABASE))
        # Any PHP or WP-CLI started on the server would leave this marker.
        for name in ("php", "wp"):
            self.administer(put(f"/usr/local/bin/{name}", PHP_STAND_IN, "root", "root", "755"))
        self.addCleanup(self.assert_unchanged)

    def administer(self, *scripts: str) -> str:
        """Change the server as its administrator would, outside Barectl and its SSH user."""
        output = docker(" && ".join(scripts))
        self.baseline = self.state()
        return output

    def state(self) -> tuple[str, str]:
        files = docker(f"find /var/www/{IDENTIFIER} -printf '%p %s %T@ %m %u\\n' | sort")
        return self.native.run(STATE_COMMAND).stdout, files + self.rows()

    def rows(self) -> str:
        query = (
            "SELECT TABLE_NAME, TABLE_ROWS FROM information_schema.TABLES "  # noqa: S608 - the tests' own fixture statements
            f"WHERE TABLE_SCHEMA='{DATABASE}' ORDER BY 1"
        )
        return docker(mariadb(query))

    def assert_unchanged(self) -> None:
        self.assertEqual(self.state(), self.baseline)

    def write_config(self, user: str) -> None:
        self.config.write_text(
            f"Host disposable\n  HostName {setting('HOST')}\n  Port {setting('PORT')}\n"
            f"  User {user}\n  IdentityFile {setting('KEY')}\n"
            f"  UserKnownHostsFile {setting('KNOWN_HOSTS')}\n",
            encoding="utf-8",
        )

    def discover(self, user: str = "root") -> ObservedSite:
        self.write_config(user)
        server = Server.objects.filter(name="Disposable").first()
        if server is None:
            self.client.post("/servers/add/", {"name": "Disposable", "ssh_alias": "disposable"})
            server = Server.objects.get(name="Disposable")
        else:
            self.client.post(f"/servers/{server.pk}/verify/")
        run_worker()
        attempt = DiscoveryAttempt.objects.filter(server=server).latest("queued_at", "pk")
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
        sites = {site.identifier: site for site in current(server).collected.sites.value}
        return sites[IDENTIFIER]

    def expect(self, state: ApplicationState, user: str = "root") -> None:
        site = self.discover(user)
        application = site.application
        assert application is not None  # noqa: S101 - every current discovery observes it
        self.assertEqual(application.state, state, site)

    def assert_no_application_code_ran(self) -> None:
        self.assertEqual(self.administer(f"ls {MARKER} 2>/dev/null || true").strip(), "")

    def install(
        self, version: str = convention.CORE_VERSION, url: str = f"https://{NAMES[0]}"
    ) -> None:
        self.administer(
            *tree(version),
            *configuration(),
            *core_tables(),
            options(url),
            # A plugin's table in the same database, and a user row Barectl must never read.
            mariadb(f"CREATE TABLE `{DATABASE}`.`wp_plugin_data` (note TEXT)"),
            mariadb(f"INSERT INTO `{DATABASE}`.`wp_plugin_data` VALUES ('PLUGIN-ROW-MARKER')"),  # noqa: S608 - the tests' own fixture statements
            mariadb(
                f"INSERT INTO `{DATABASE}`.`wp_users` (ID, user_login, user_pass) "  # noqa: S608 - the tests' own fixture statements
                "VALUES (1, 'admin', 'PASSWORD-HASH-MARKER')"
            ),
        )

    def test_a_fresh_controller_reconstructs_an_administrator_created_application(self) -> None:
        self.install(url=f"https://{NAMES[1]}")
        self.administer(routing(Application.WORDPRESS, NAMES[1]))
        site = self.discover()
        application = site.application
        assert application is not None  # noqa: S101 - every current discovery observes it
        self.assertEqual(application.state, ApplicationState.INSTALLED, application)
        self.assertEqual(
            (application.core_version, application.qualification),
            (convention.CORE_VERSION, CoreQualification.QUALIFIED),
        )
        self.assertEqual(
            (application.loader, application.configuration, application.schema),
            (LoaderState.EXACT, ConfigurationState.SUPPORTED, SchemaState.COMPLETE),
        )
        self.assertEqual(application.site_url, f"https://{NAMES[1]}")
        self.assertEqual((site.routing, site.canonical_name), (SiteRouting.WORDPRESS, NAMES[1]))
        digest = docker(f"sha256sum <{PRIVATE}/wp-config.php | cut -d' ' -f1").strip()
        self.assertEqual(application.configuration_digest, digest)

        server = Server.objects.get()
        page = self.client.get(f"/servers/{server.pk}/sites/{IDENTIFIER}/wordpress/")
        self.assertContains(page, "<strong>Installed.</strong>")
        self.assertContains(page, "Collected <time")

        # Nothing private was kept: no secret, user row or plugin row reached the controller.
        stored = " ".join(
            str(value)
            for row in SiteApplicationObservation.objects.values()
            for value in row.values()
        )
        configuration_text = docker(f"cat {PRIVATE}/wp-config.php")
        for line in configuration_text.splitlines():
            if "_KEY'" in line or "_SALT'" in line:
                self.assertNotIn(line.split("'")[3], stored + page.content.decode())
        for secret in ("PASSWORD-HASH-MARKER", "PLUGIN-ROW-MARKER", "DB_PASSWORD"):
            self.assertNotIn(secret, stored + page.content.decode())

        # A lesser identity cannot read the private configuration or the catalog: the
        # application is unreadable, never absent or installed, and discovery does not escalate.
        for lesser in (setting("USER"), setting("UNPRIVILEGED_USER")):
            self.expect(ApplicationState.UNREADABLE, lesser)

        # Nothing Barectl recorded survives; a fresh controller reads the same evidence.
        remove_server(Server.objects.get())
        DBTaskResult.objects.all().delete()
        self.assertFalse(SiteApplicationObservation.objects.exists())
        rebuilt = self.discover()
        self.assertEqual(rebuilt.application, application)
        self.assertEqual((rebuilt.routing, rebuilt.canonical_name), (site.routing, NAMES[1]))
        self.assert_no_application_code_ran()

    def test_partial_core_plugin_tables_and_external_changes_are_reported_as_found(self) -> None:
        self.administer(reset())
        self.expect(ApplicationState.ABSENT)
        self.administer(*tree())
        self.expect(ApplicationState.CANDIDATE)
        self.administer(*configuration())
        self.expect(ApplicationState.PARTIAL)
        self.administer(*core_tables(only=("options", "users")))
        self.expect(ApplicationState.PARTIAL)
        self.administer(reset())
        self.install()
        self.expect(ApplicationState.INSTALLED)
        self.administer(routing(Application.WORDPRESS_GATE))
        self.assertEqual(self.discover().routing, SiteRouting.WORDPRESS_GATE)
        self.expect(ApplicationState.INSTALLED)

        # An external core update is reported with its qualification, never downgraded.
        self.administer(*tree("8.0.1"))
        application = self.discover().application
        assert application is not None  # noqa: S101 - every current discovery observes it
        self.assertEqual(application.state, ApplicationState.INSTALLED)
        self.assertEqual(application.core_version, "8.0.1")
        self.assertEqual(application.qualification, CoreQualification.NEWER)
        self.assertIn("newer than the qualified", application.warning)
        self.administer(*tree())

        # Edited resources block dependent actions without touching the site's infrastructure.
        site_state = self.discover().state
        self.administer(
            put(
                f"{PUBLIC}/wp-config.php",
                "<?php\nphpinfo();\n",
                f"s{IDENTIFIER}",
                "www-data",
                "640",
            )
        )
        self.expect(ApplicationState.BLOCKED)
        self.assertEqual(self.discover().state, site_state)
        self.administer(*configuration())
        self.expect(ApplicationState.INSTALLED)
        self.administer(mariadb(f"ALTER TABLE `{DATABASE}`.`wp_posts` DROP COLUMN `guid`"))
        self.expect(ApplicationState.BLOCKED)
        self.administer(mariadb(f"ALTER TABLE `{DATABASE}`.`wp_posts` ADD COLUMN `guid` TEXT"))
        self.expect(ApplicationState.INSTALLED)
        self.administer(
            mariadb(f"CREATE TABLE `{DATABASE}`.`wp2_users` (ID INT)"),
            mariadb(f"CREATE TABLE `{DATABASE}`.`wp2_options` (option_id INT)"),
        )
        self.expect(ApplicationState.BLOCKED)
        self.assert_no_application_code_ran()

    def test_hostile_configuration_is_read_as_data_and_never_executed(self) -> None:
        self.administer(reset())
        # The stand-ins record any PHP or WP-CLI started through an SSH session's PATH.
        self.native.run("php -v; wp --info")
        self.assertEqual(self.administer(f"ls {MARKER}").strip(), MARKER)
        self.administer(f"rm -f {MARKER}")
        user = f"s{IDENTIFIER}"
        payload = f"<?php touch('{MARKER}'); system('touch {MARKER}'); exit; ?>\n"
        self.administer(
            *tree(),
            put(f"{PUBLIC}/wp-includes/version.php", payload, user, "www-data", "640"),
            put(f"{PUBLIC}/wp-load.php", payload, user, "www-data", "640"),
            put(f"{PUBLIC}/wp-config.php", payload, user, "www-data", "640"),
            put(f"{PRIVATE}/wp-config.php", payload, user, user, "600"),
        )
        self.expect(ApplicationState.UNREADABLE, setting("USER"))
        self.expect(ApplicationState.BLOCKED)
        application = self.discover().application
        assert application is not None  # noqa: S101 - every current discovery observes it
        self.assertEqual(application.configuration_digest, "")
        self.assertEqual(application.core_version, "")
        self.assert_no_application_code_ran()
        # A configuration with the grammar plus an include is just as unsupported.
        text = convention.render_private_configuration(IDENTIFIER, salts())
        self.administer(
            put(
                f"{PRIVATE}/wp-config.php",
                text + f"require '/var/www/{IDENTIFIER}/public/wp-load.php';\n",
                user,
                user,
                "600",
            ),
            put(
                f"{PUBLIC}/wp-config.php",
                convention.render_loader(IDENTIFIER),
                user,
                "www-data",
                "640",
            ),
        )
        self.expect(ApplicationState.BLOCKED)
        self.assert_no_application_code_ran()
