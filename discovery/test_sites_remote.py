"""Site reconstruction against a disposable server (docs/ssh-connections.md#site-observations).

The server's administrator, through ``docker exec``, creates a site that meets
docs/site-conventions.md by hand and a broken one, then edits and removes them. Barectl
reads them through the dashboard request, the worker and its SSH connection only.
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

from dashboard.testing import TEST_MANIFEST
from servers.models import Server
from servers.registration import remove_server

from .fakes import current, pool_config, run_worker, site_config
from .models import DiscoveryAttempt, SiteObservation
from .releases import SUPPORTED
from .snapshot import ObservedSite as Site
from .test_remote import CONFIGURED, STATE_COMMAND, NativeShell, setting

FIXTURES = CONFIGURED and all(
    os.environ.get(f"BARECTL_SSH_TEST_{name}") for name in ("CONTAINER", "UNPRIVILEGED_USER")
)
PERMISSIONS = ("view_server", "add_server", "add_discoveryattempt", "view_siteobservation")
PRIVATE_LINK = "/etc/nginx/sites-enabled/private"
# The site file only root can read, moved aside while a test needs every file readable.
PRIVATE_ASIDE = "/root/private.link"


def _write(path: str, content: str, mode: str) -> str:
    return f"printf %s {shlex.quote(content)} >{path} && chmod {mode} {path}"


def create_site(php: str, identifier: str = "alpha") -> str:
    """The administrator's own commands for a site that meets the convention."""
    user, boundary = f"s{identifier}", f"/var/www/{identifier}"
    source = f"/etc/nginx/sites-available/{identifier}.conf"
    names = (f"{identifier}.test", f"www.{identifier}.test")
    return " && ".join(
        (
            (
                f"useradd --home-dir {boundary} --no-create-home "
                f"--shell /usr/sbin/nologin --user-group {user}"
            ),
            f"install -d -o root -g root -m 755 {boundary}",
            f"install -d -o {user} -g www-data -m 750 {boundary}/public",
            f"install -d -o {user} -g {user} -m 700 {boundary}/private",
            _write(source, site_config(identifier, names), "644"),
            f"ln -s {source} /etc/nginx/sites-enabled/{identifier}.conf",
            _write(f"/etc/php/{php}/fpm/pool.d/{identifier}.conf", pool_config(identifier), "644"),
            "nginx -t -q",
            f"php-fpm{php} -t",
            f"systemctl reload php{php}-fpm",
            f"for _ in $(seq 50); do test -S /run/php/{user}.sock && break; sleep 0.2; done",
            f"test -S /run/php/{user}.sock",
        )
    )


def remove_site(php: str, identifier: str) -> str:
    return "; ".join(
        (
            f"rm -f /etc/nginx/sites-enabled/{identifier}.conf",
            f"rm -f /etc/nginx/sites-available/{identifier}.conf",
            f"rm -f /etc/php/{php}/fpm/pool.d/{identifier}.conf",
            f"systemctl reload php{php}-fpm",
            f"rm -rf /var/www/{identifier}",
            f"id s{identifier} >/dev/null 2>&1 && userdel s{identifier}",
            "true",
        )
    )


def _create_beta() -> str:
    """An enabled site file whose account, directories, pool and socket were never made."""
    return " && ".join(
        (
            _write(
                "/etc/nginx/sites-available/beta.conf", site_config("beta", ("beta.test",)), "644"
            ),
            "ln -s /etc/nginx/sites-available/beta.conf /etc/nginx/sites-enabled/beta.conf",
        )
    )


def _remove_sites(php: str) -> str:
    return "; ".join(
        (
            "rm -f /etc/nginx/sites-enabled/alpha.conf /etc/nginx/sites-enabled/beta.conf",
            "rm -f /etc/nginx/sites-available/alpha.conf /etc/nginx/sites-available/beta.conf",
            f"rm -f /etc/php/{php}/fpm/pool.d/alpha.conf",
            f"systemctl reload php{php}-fpm",
            "rm -rf /var/www/alpha",
            "id salpha >/dev/null 2>&1 && userdel salpha",
            f"test -e {PRIVATE_LINK} || mv {PRIVATE_ASIDE} {PRIVATE_LINK}",
            "true",
        )
    )


@tag("ssh")
@skipUnless(FIXTURES, "Set BARECTL_SSH_TEST_* and the server's container to change sites")
class SiteReconstructionTests(TestCase):
    user: ClassVar[User]

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
        release = self.administer(". /etc/os-release; echo $VERSION_ID").strip()
        self.php = SUPPORTED[release].php
        self.addCleanup(self.administer, _remove_sites(self.php))
        # The SSH user reads the shadow database as a member of its group, so the password
        # lock can be observed; the account without sudo stays outside it.
        self.addCleanup(self.administer, f"gpasswd -d {setting('USER')} shadow >/dev/null")
        self.administer(f"usermod -aG shadow {setting('USER')}")
        self.administer(create_site(self.php))
        self.administer(_create_beta())
        # Whatever discovery does, the server stays as its administrator left it.
        self.addCleanup(self.assert_unchanged)

    def administer(self, script: str) -> str:
        """Change the server as its administrator would, outside Barectl and its SSH user."""
        result = subprocess.run(  # noqa: S603 - the tests' own fixture scripts
            ["docker", "exec", setting("CONTAINER"), "sh", "-c", script],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.baseline = self.native.run(STATE_COMMAND).stdout
        return result.stdout

    def assert_unchanged(self) -> None:
        self.assertEqual(self.native.run(STATE_COMMAND).stdout, self.baseline)

    def write_config(self, user: str, key: str) -> None:
        self.config.write_text(
            f"Host disposable\n  HostName {setting('HOST')}\n  Port {setting('PORT')}\n"
            f"  User {user}\n  IdentityFile {key}\n"
            f"  UserKnownHostsFile {setting('KNOWN_HOSTS')}\n",
            encoding="utf-8",
        )

    def discover(self) -> dict[str, Site]:
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
        self.assertEqual(sites.outcome, "observed", sites.warning)
        return {site.identifier: site for site in sites.value}

    @staticmethod
    def departures(site: Site) -> dict[str, str]:
        return {
            resource.resource.value: resource.outcome.value
            for resource in site.resources
            if not resource.conforms
        }

    def test_a_manually_created_site_is_reconstructed_by_a_fresh_controller(self) -> None:
        self.write_config(setting("USER"), setting("KEY"))
        # Root's unreadable site file might declare the same names, so alpha is not
        # complete while it is enabled; it is inaccessible, never absent.
        sites = self.discover()
        self.assertEqual(self.departures(sites["alpha"]), {"exclusive": "inaccessible"})
        self.assertEqual(
            self.departures(sites["beta"]),
            {
                "boundary": "absent",
                "document_root": "absent",
                "private": "absent",
                "pool": "absent",
                "socket": "absent",
                "user": "absent",
                "password": "absent",
                "exclusive": "inaccessible",
            },
        )

        self.administer(f"mv {PRIVATE_LINK} {PRIVATE_ASIDE}")
        alpha = self.discover()["alpha"]
        self.assertTrue(alpha.complete, self.departures(alpha))
        self.assertEqual(alpha.server_names, ("alpha.test", "www.alpha.test"))
        self.assertEqual(
            (alpha.document_root, alpha.fastcgi_socket, alpha.php_version),
            ("/var/www/alpha/public", "/run/php/salpha.sock", self.php),
        )
        uid = int(self.administer("id -u salpha"))
        self.assertEqual(
            alpha.account and (alpha.account.uid, alpha.account.home), (uid, "/var/www/alpha")
        )
        page = self.client.get(f"/servers/{Server.objects.get().pk}/")
        self.assertContains(page, "<code>alpha</code>: Matches the supported site convention")
        self.assertContains(page, "<code>beta</code>: Does not match the supported site convention")

        # Nothing Barectl recorded survives; another account and key rebuild the same sites.
        remove_server(Server.objects.get())
        DBTaskResult.objects.all().delete()
        self.assertFalse(SiteObservation.objects.exists())
        self.write_config(
            setting("UNPRIVILEGED_USER"),
            os.environ.get("BARECTL_SSH_TEST_SECOND_KEY") or setting("KEY"),
        )
        rebuilt = self.discover()
        # Without the shadow group, the password lock is inaccessible, never absent.
        self.assertEqual(self.departures(rebuilt["alpha"]), {"password": "inaccessible"})
        self.assertEqual(
            [r for r in rebuilt["alpha"].resources if r.resource != "password"],
            [r for r in alpha.resources if r.resource != "password"],
        )
        self.assertEqual(rebuilt["alpha"].account, alpha.account)
        self.assertEqual(set(rebuilt), {"alpha", "beta"})

    def test_external_edits_and_removal_change_the_next_discovery(self) -> None:
        self.administer(f"mv {PRIVATE_LINK} {PRIVATE_ASIDE}")
        self.write_config(setting("USER"), setting("KEY"))
        self.assertTrue(self.discover()["alpha"].complete)

        # alpha now also answers for beta's name: neither can be a complete site.
        self.administer(
            "sed -i 's/www.alpha.test/beta.test/' /etc/nginx/sites-available/alpha.conf"
        )
        sites = self.discover()
        self.assertEqual(sites["alpha"].server_names, ("alpha.test", "beta.test"))
        for identifier in ("alpha", "beta"):
            exclusive = next(r for r in sites[identifier].resources if r.resource == "exclusive")
            self.assertEqual((exclusive.outcome, exclusive.conforms), ("observed", False))
            self.assertIn("also declares beta.test", exclusive.warning)

        # The pool's configuration and its running socket each lose their protection.
        # PHP-FPM keeps its listening socket across a reload, so they are changed apart.
        self.administer(
            "sed -i 's/listen.mode = 0600/listen.mode = 0666/' "
            f"/etc/php/{self.php}/fpm/pool.d/alpha.conf && chmod 666 /run/php/salpha.sock"
        )
        departures = self.departures(self.discover()["alpha"])
        self.assertEqual(departures.get("pool"), "observed")
        self.assertEqual(departures.get("socket"), "observed")

        self.administer("rm /etc/nginx/sites-enabled/alpha.conf")
        self.assertEqual(self.discover()["alpha"].resources[0].outcome, "absent")

        self.administer(_remove_sites(self.php))
        self.assertEqual(set(self.discover()), set())
