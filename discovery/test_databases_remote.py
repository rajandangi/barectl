"""Site database bindings against a disposable server
(docs/ssh-connections.md#site-database-observations).

The server's administrator creates sites and database bindings by hand through
``docker exec``; Barectl reads them through the dashboard request, the worker and its SSH
connection only, as root and as a lesser identity.
"""

import os
import shlex
import subprocess
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
from servers.models import Server
from servers.registration import remove_server

from .fakes import current, run_worker
from .models import DatabaseEngine, DiscoveryAttempt, ObservationOutcome
from .observations.databases import mariadb_command, postgresql_command
from .releases import SUPPORTED
from .snapshot import ObservedDatabase
from .test_remote import CONFIGURED, STATE_COMMAND, NativeShell, setting
from .test_sites_remote import FIXTURES, PERMISSIONS, create_site, remove_site

MARIADB = "mariadb --no-defaults -N -B -e"
PSQL = "runuser -u postgres -- psql -X -q -v ON_ERROR_STOP=1"
PRIVILEGES = (
    "SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES, "
    "CREATE TEMPORARY TABLES, LOCK TABLES"
)


def mariadb(statement: str) -> str:
    return f"{MARIADB} {shlex.quote(statement)}"


def psql(statement: str, database: str = "postgres") -> str:
    return f"{PSQL} -d {database} -c {shlex.quote(statement)}"


# The convention's statements (docs/site-conventions.md#database-convention), as an
# administrator runs them by hand.
def mariadb_binding(name: str) -> tuple[str, ...]:
    return (
        mariadb(f"CREATE USER `{name}`@`localhost` IDENTIFIED VIA unix_socket"),
        mariadb(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"),
        mariadb(f"GRANT {PRIVILEGES} ON `{name}`.* TO `{name}`@`localhost`"),
    )


def postgresql_binding(name: str) -> tuple[str, ...]:
    return (
        psql(f'CREATE ROLE "{name}" LOGIN'),
        psql(
            f'CREATE DATABASE "{name}" WITH OWNER "{name}" TEMPLATE template0 '
            "ENCODING 'UTF8' LOCALE_PROVIDER libc LC_COLLATE 'C.UTF-8' LC_CTYPE 'C.UTF-8'"
        ),
        psql(f'REVOKE CONNECT, TEMPORARY ON DATABASE "{name}" FROM PUBLIC'),
        psql("REVOKE ALL ON SCHEMA public FROM PUBLIC", name),
    )


def drop(name: str) -> str:
    return "; ".join(
        (
            mariadb(f"DROP DATABASE IF EXISTS `{name}`"),
            mariadb(f"DROP USER IF EXISTS `{name}`@`localhost`"),
            psql(f'DROP DATABASE IF EXISTS "{name}"'),
            psql(f'DROP ROLE IF EXISTS "{name}"'),
            "true",
        )
    )


def docker(script: str) -> str:
    return subprocess.run(  # noqa: S603 - the tests' own fixture scripts
        ["docker", "exec", setting("CONTAINER"), "sh", "-c", script],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
        timeout=600,
    ).stdout


@tag("ssh")
@skipUnless(FIXTURES and CONFIGURED, "Set BARECTL_SSH_TEST_* and the server's container")
class DatabaseReconstructionTests(TestCase):
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
        for identifier in ("shop", "blog"):
            self.addCleanup(self.administer, remove_site(self.php, identifier))
            self.addCleanup(self.administer, drop(f"s{identifier}"))
            self.administer(create_site(self.php, identifier))
        self.addCleanup(self.assert_unchanged)

    def administer(self, *scripts: str) -> str:
        """Change the server as its administrator would, outside Barectl and its SSH user."""
        output = docker(" && ".join(scripts))
        self.baseline = self.native.run(STATE_COMMAND).stdout, self.catalogs()
        return output

    def catalogs(self) -> tuple[str, str]:
        names = ("sshop", "sblog")
        return docker(mariadb_command(names)), docker(postgresql_command(names))

    def assert_unchanged(self) -> None:
        self.assertEqual((self.native.run(STATE_COMMAND).stdout, self.catalogs()), self.baseline)

    def write_config(self, user: str) -> None:
        self.config.write_text(
            f"Host disposable\n  HostName {setting('HOST')}\n  Port {setting('PORT')}\n"
            f"  User {user}\n  IdentityFile {setting('KEY')}\n"
            f"  UserKnownHostsFile {setting('KNOWN_HOSTS')}\n",
            encoding="utf-8",
        )

    def discover(self, user: str = "root") -> dict[str, ObservedDatabase | None]:
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
        sites = current(server).collected.sites
        return {site.identifier: site.database for site in sites.value}

    def binding(self, identifier: str, user: str = "root") -> ObservedDatabase:
        database = self.discover(user)[identifier]
        assert database is not None  # noqa: S101 - every current discovery observes it
        return database

    def test_root_reconstructs_bindings_and_a_lesser_identity_sees_inaccessible(self) -> None:
        self.administer(*mariadb_binding("sshop"), *postgresql_binding("sblog"))
        databases = self.discover()
        shop, blog = databases["shop"], databases["blog"]
        self.assertEqual(
            shop and (shop.engine, shop.conforms, shop.principal, shop.authentication),
            (DatabaseEngine.MARIADB, True, "sshop@localhost", "unix_socket"),
            shop and shop.warning,
        )
        self.assertEqual(
            blog and (blog.engine, blog.conforms, blog.owner, blog.character_set),
            (DatabaseEngine.POSTGRESQL, True, "sblog", "UTF8"),
            blog and blog.warning,
        )
        page = self.client.get(f"/servers/{Server.objects.get().pk}/")
        self.assertContains(page, "MariaDB binding, as the convention requires")
        self.assertContains(page, "PostgreSQL binding, as the convention requires")

        # The SSH user with sudo is still not root: discovery never escalates.
        for database in self.discover(setting("USER")).values():
            self.assertEqual(database and database.outcome, ObservationOutcome.INACCESSIBLE)

        # Nothing Barectl recorded survives; a fresh controller reads the same bindings.
        remove_server(Server.objects.get())
        DBTaskResult.objects.all().delete()
        self.assertEqual(self.discover(), databases)

    def test_partial_custom_and_conflicting_bindings_are_named(self) -> None:
        self.administer(mariadb_binding("sshop")[0], *postgresql_binding("sblog")[:2])
        databases = self.discover()
        shop, blog = databases["shop"], databases["blog"]
        self.assertEqual(shop and (shop.outcome, shop.conforms), ("observed", False))
        self.assertIn("database, privileges are missing", shop.warning if shop else "")
        self.assertIn("privileges, schema are missing", blog.warning if blog else "")

        # A password fallback is the administrator's own authentication, not the convention's.
        self.administer(
            mariadb(
                "ALTER USER `sshop`@`localhost` IDENTIFIED VIA unix_socket "
                "OR mysql_native_password USING PASSWORD('not-a-secret')"
            )
        )
        self.assertIn("does not authenticate by unix_socket alone", self.binding("shop").warning)
        self.assertNotIn("not-a-secret", str(self.discover()))

        # A data directory entry is a database MariaDB lists under the site's name.
        data = SUPPORTED[docker(". /etc/os-release; echo $VERSION_ID").strip()].mariadb_data
        self.administer(
            drop("sshop"),
            f"install -d -o mysql -g mysql {data}/sshop",
        )
        self.addCleanup(self.administer, f"rm -rf {data}/sshop")
        shop = self.binding("shop")
        self.assertEqual((shop.engine, shop.conforms), (DatabaseEngine.MARIADB, False))
        self.assertIn("Database sshop uses", shop.warning)

        # One site's name held in both engines is no supported binding.
        self.administer(
            f"rm -rf {data}/sshop", *mariadb_binding("sshop"), psql('CREATE ROLE "sshop" LOGIN')
        )
        self.assertEqual(self.binding("shop").outcome, ObservationOutcome.UNSUPPORTED)
