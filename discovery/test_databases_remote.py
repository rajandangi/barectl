"""Site database bindings against a disposable server
(docs/ssh-connections.md#site-database-observations).

The server's administrator creates sites and database bindings by hand through
``docker exec``; Barectl reads them through the dashboard request, the worker and its SSH
connection only, as root and as a lesser identity.
"""

import os
import re
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
from databases.native_testing import (
    PSQL,
    docker,
    drop,
    mariadb,
    mariadb_binding,
    postgresql_binding,
    psql,
)
from servers.models import Server
from servers.registration import remove_server

from .fakes import current, run_worker
from .models import (
    DatabaseEngine,
    DiscoveryAttempt,
    ObservationOutcome,
    SiteDatabaseObservation,
)
from .observations.databases import mariadb_command, postgresql_command
from .releases import SUPPORTED
from .snapshot import ObservedDatabase
from .test_remote import CONFIGURED, STATE_COMMAND, NativeShell, setting
from .test_sites_remote import FIXTURES, PERMISSIONS, create_site, remove_site


@tag("ssh")
@skipUnless(FIXTURES and CONFIGURED, "Set BARECTL_SSH_TEST_* and the server's container")
class DatabaseReconstructionTests(TestCase):
    user: ClassVar[User]
    release: ClassVar[str]
    php: ClassVar[str]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.release = docker(". /etc/os-release; echo $VERSION_ID").strip()
        cls.php = SUPPORTED[cls.release].php
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
        page = self.client.get(f"/servers/{Server.objects.get().pk}/advanced/")
        self.assertContains(page, "MariaDB binding, as the convention requires")
        self.assertContains(page, "PostgreSQL binding, as the convention requires")

        # The SSH user with sudo is still not root: discovery never escalates. Blocked
        # foreign items carry no database binding, so only named sites are compared.
        for identifier, database in self.discover(setting("USER")).items():
            if not identifier:
                continue
            self.assertEqual(
                database and database.outcome,
                ObservationOutcome.INACCESSIBLE,
                identifier,
            )

        # Nothing Barectl recorded survives; a fresh controller reads the same bindings.
        remove_server(Server.objects.get())
        DBTaskResult.objects.all().delete()
        self.assertEqual(self.discover(), databases)

    def test_no_password_or_secret_is_read_or_kept(self) -> None:
        self.administer(*mariadb_binding("sshop"), *postgresql_binding("sblog"))
        # A password fallback and a role password are the administrator's own
        # authentication, not the convention's.
        self.administer(
            mariadb(
                "ALTER USER `sshop`@`localhost` IDENTIFIED VIA unix_socket "
                "OR mysql_native_password USING PASSWORD('not-a-secret')"
            ),
            psql("ALTER ROLE \"sblog\" PASSWORD 'not-a-secret'"),
        )
        created = docker(mariadb("SHOW CREATE USER `sshop`@`localhost`"))
        hashes = re.findall(r"\*[0-9A-F]{40}", created)
        query = "SELECT rolpassword FROM pg_authid WHERE rolname='sblog'"
        hashes.append(docker(f"{PSQL} -A -t -d postgres -c {shlex.quote(query)}").strip())
        self.assertEqual(len(hashes), 2, created)
        self.assertTrue(hashes[1].startswith("SCRAM-SHA-256$"))
        # An LDAP rule whose options hold a bind password, from an included file.
        cluster = f"/etc/postgresql/{SUPPORTED[self.release].postgresql}/main"
        self.administer(
            f"cp -p {cluster}/pg_hba.conf /root/pg_hba.conf.orig",
            f"echo 'local all sblog ldap ldapserver=localhost ldapbinddn=x "
            f"ldapbindpasswd=not-a-secret ldapbasedn=y ldapsearchattribute=uid' "
            f"> {cluster}/extra.conf",
            f"{{ echo 'include {cluster}/extra.conf'; cat /root/pg_hba.conf.orig; }} "
            f"> {cluster}/pg_hba.conf",
            f"systemctl reload postgresql@{SUPPORTED[self.release].postgresql}-main",
        )
        self.addCleanup(
            self.administer,
            f"mv /root/pg_hba.conf.orig {cluster}/pg_hba.conf; rm -f {cluster}/extra.conf; "
            f"systemctl reload postgresql@{SUPPORTED[self.release].postgresql}-main",
        )
        databases = self.discover()
        shop, blog = databases["shop"], databases["blog"]
        self.assertFalse(shop and shop.conforms)
        self.assertIn("do not follow the database convention", shop.warning if shop else "")
        self.assertFalse(blog and blog.conforms)
        self.assertIn("do not follow the database convention", blog.warning if blog else "")
        raw = "".join(self.catalogs())
        stored = [
            str(value) for row in SiteDatabaseObservation.objects.values() for value in row.values()
        ]
        for secret in (*hashes, "not-a-secret"):
            with self.subTest(secret=secret[:16]):
                self.assertNotIn(secret, raw)
                self.assertFalse([value for value in stored if secret in value])

    def test_partial_custom_and_conflicting_bindings_are_named(self) -> None:
        self.administer(mariadb_binding("sshop")[0], *postgresql_binding("sblog")[:2])
        databases = self.discover()
        shop, blog = databases["shop"], databases["blog"]
        self.assertEqual(shop and (shop.outcome, shop.conforms), ("observed", False))
        self.assertIn("database, privileges are missing", shop.warning if shop else "")
        self.assertIn("privileges, schema are missing", blog.warning if blog else "")

        # Another account's pattern grant reaches the name without being its binding.
        self.administer(
            mariadb("CREATE USER `other`@`localhost` IDENTIFIED VIA unix_socket"),
            mariadb("GRANT SELECT ON `s%`.* TO `other`@`localhost`"),
        )
        self.addCleanup(self.administer, mariadb("DROP USER IF EXISTS `other`@`localhost`"))
        blog = self.binding("blog")
        self.assertEqual(blog.engine, DatabaseEngine.POSTGRESQL)
        self.assertIn(
            "Database resources named sblog do not follow the database convention.", blog.warning
        )
        self.administer(mariadb("DROP USER `other`@`localhost`"))

        # A data directory entry is a database MariaDB lists under the site's name.
        data = SUPPORTED[self.release].mariadb_data
        self.administer(
            drop("sshop"),
            f"install -d -o mysql -g mysql {data}/sshop",
        )
        self.addCleanup(self.administer, f"rm -rf {data}/sshop")
        shop = self.binding("shop")
        self.assertEqual((shop.engine, shop.conforms), (DatabaseEngine.MARIADB, False))
        self.assertIn("do not follow the database convention", shop.warning)

        self.administer(
            f"rm -rf {data}/sshop", *mariadb_binding("sshop"), psql('CREATE ROLE "sshop" LOGIN')
        )
        self.assertEqual(self.binding("shop").outcome, ObservationOutcome.UNSUPPORTED)
