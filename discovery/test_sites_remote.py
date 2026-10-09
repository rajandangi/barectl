"""Site reconstruction against a disposable server (docs/ssh-connections.md#site-observations).

The server's administrator, through ``docker exec``, creates a site that meets
docs/site-conventions.md by hand and a broken one, then edits and removes them. Barectl
reads them through the dashboard request, the worker and its SSH connection only.
"""

import os
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

from .fakes import current, run_worker, site_config
from .models import DiscoveryAttempt, SiteObservation
from .native_testing import FIXTURES as FIXTURES
from .native_testing import create_site as create_site
from .native_testing import remove_site as remove_site
from .native_testing import write_file
from .releases import SUPPORTED
from .snapshot import ObservedSite as Site
from .test_remote import STATE_COMMAND, NativeShell, setting

PERMISSIONS = ("view_server", "add_server", "add_discoveryattempt", "view_siteobservation")
PRIVATE_LINK = "/etc/nginx/sites-enabled/private"
# The site file only root can read, moved aside while a test needs every file readable.
PRIVATE_ASIDE = "/root/private.link"


def _create_beta() -> str:
    """An enabled site file whose account, directories, pool and socket were never made."""
    return " && ".join(
        (
            write_file(
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
    def blocked(sites: dict[str, Site]) -> list[Site]:
        return [site for site in sites.values() if site.state == "not_following"]

    def test_a_manually_created_site_is_reconstructed_by_a_fresh_controller(self) -> None:
        self.write_config(setting("USER"), setting("KEY"))
        # A foreign enabled file is one blocked item; the hand-made site stays managed, and
        # the enabled-but-unfinished beta site is partly applied.
        sites = self.discover()
        self.assertEqual(sites["alpha"].state, "managed", sites["alpha"].expected)
        self.assertEqual(sites["beta"].state, "partly_applied")
        # The root-only enabled file is one blocked item, unreadable but never drift.
        blocked = {site.file: site.outcome for site in self.blocked(sites)}
        self.assertEqual(blocked, {PRIVATE_LINK: "inaccessible"})

        self.administer(f"mv {PRIVATE_LINK} {PRIVATE_ASIDE}")
        alpha = self.discover()["alpha"]
        self.assertEqual(alpha.state, "managed", alpha.expected)
        self.assertEqual(alpha.server_names, ("alpha.test", "www.alpha.test"))
        self.assertEqual(alpha.php_version, self.php)
        uid = int(self.administer("id -u salpha"))
        self.assertEqual(
            alpha.account and (alpha.account.uid, alpha.account.home), (uid, "/var/www/alpha")
        )
        server = Server.objects.get()
        page = self.client.get(f"/servers/{server.pk}/advanced/")
        self.assertContains(page, f"/servers/{server.pk}/sites/alpha/overview/")
        self.assertContains(page, "alpha.test, www.alpha.test")
        self.assertContains(page, "Matches the supported site convention")
        self.assertContains(page, "beta.test")
        self.assertContains(page, "Partly applied")

        # Nothing Barectl recorded survives; another account and key rebuild the same sites.
        remove_server(Server.objects.get())
        DBTaskResult.objects.all().delete()
        self.assertFalse(SiteObservation.objects.exists())
        self.write_config(
            setting("UNPRIVILEGED_USER"),
            os.environ.get("BARECTL_SSH_TEST_SECOND_KEY") or setting("KEY"),
        )
        rebuilt = self.discover()
        # Without the shadow group, the password lock is inaccessible, never drift.
        self.assertEqual(rebuilt["alpha"].outcome, "inaccessible")
        self.assertEqual(rebuilt["alpha"].account, alpha.account)
        self.assertEqual({name for name in rebuilt if name}, {"alpha", "beta"})

    def test_external_edits_and_removal_change_the_next_discovery(self) -> None:
        self.administer(f"mv {PRIVATE_LINK} {PRIVATE_ASIDE}")
        self.write_config(setting("USER"), setting("KEY"))
        self.assertEqual(self.discover()["alpha"].state, "managed")

        # The hand-edited site file is one changed resource: the file and what Barectl
        # expects there, with no per-difference wording. A valid new server_name would
        # still be the convention, so only a broken fixed value is drift.
        self.administer(
            "sed -i 's|root /var/www/alpha/public;|root /var/www/elsewhere/public;|' "
            "/etc/nginx/sites-available/alpha.conf"
        )
        alpha = self.discover()["alpha"]
        self.assertEqual(alpha.state, "changed")
        self.assertEqual(alpha.file, "/etc/nginx/sites-available/alpha.conf")
        self.assertIn("root /var/www/alpha/public;", alpha.expected)
        self.assertEqual(alpha.server_names, ("alpha.test", "www.alpha.test"))

        self.administer("rm /etc/nginx/sites-enabled/alpha.conf")
        self.assertEqual(self.discover()["alpha"].state, "changed")

        self.administer(_remove_sites(self.php))
        remaining = self.discover()
        self.assertEqual({site.identifier for site in remaining.values() if site.identifier}, set())
