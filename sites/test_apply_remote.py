"""Applying reviewed site plans on a real, disposable Ubuntu server (docs/sites.md).

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. Every run goes through the dashboard request,
the worker, Barectl's SSH connection and actual systemd, useradd, Nginx and PHP-FPM on the
server. Ground truth is read as root through ``docker exec``, independently of Barectl.
"""

import shlex
from typing import ClassVar, override

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission

from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, PlanPreparation, Verification
from bootstrap.test_apply_remote import ApplyAcceptanceTestCase
from discovery.fakes import current, run_worker
from discovery.models import DiscoveryAttempt
from discovery.releases import SUPPORTED
from discovery.services import request_discovery
from discovery.test_remote import setting
from operations.models import RemoteOperation

from . import native
from .convention import render_placeholder, render_pool, render_site
from .models import RunFileChange, SiteRunResult
from .test_review_remote import PUT_BACK, SET_ASIDE, remove_site

Status = RemoteOperation.Status
PERMISSIONS = ("view_server", "view_siteplan", "prepare_siteplan", "apply_siteplan")
SITES = ("shop", "blog")
IDENTITY = "<?php echo posix_geteuid(), ' ', posix_getegid(), \"\\n\";\n"


class SiteApplyTestCase(ApplyAcceptanceTestCase):
    """A disposable server with the provisioned root-only site set aside; every site the
    tests create is removed again by the administrator."""

    php: ClassVar[str]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.user = get_user_model().objects.create_user("operator")
        for codename in PERMISSIONS:
            cls.user.user_permissions.add(Permission.objects.get(codename=codename))

    @override
    def setUp(self) -> None:
        super().setUp()
        release = self.administer(". /etc/os-release; echo $VERSION_ID").strip()
        type(self).php = SUPPORTED[release].php
        # Cleanups run last first: shop, which a fault may have left broken, goes first.
        for identifier in reversed(SITES):
            self.addCleanup(self.administer, remove_site(identifier, self.php))
        self.addCleanup(self.administer, PUT_BACK)
        self.administer(SET_ASIDE)

    def site_plan(
        self, identifier: str = "shop", names: str = "shop.test www.shop.test"
    ) -> ConfigurationPlan:
        self.client.post(
            f"/servers/{self.server.pk}/sites/prepare/",
            {"identifier": identifier, "names": names},
        )
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        refusals = list(plan.refusals.values_list("text", flat=True))
        self.assertTrue(plan.eligible, refusals)
        return plan

    def apply_site(self, plan: ConfigurationPlan) -> ApplyRun:
        run = self.request(plan)
        run_worker()
        run.refresh_from_db()
        return run

    def get(self, host: str, path: str = "/", address: str = "127.0.0.1") -> str:
        """The body of an HTTP GET answered with 200 on the server, else nothing."""
        client = native.http_client(self.php)
        return self.administer(
            f"{client}; k {shlex.quote(address)} {shlex.quote(host)} {shlex.quote(path)}; true"
        )

    def state(self, identifier: str) -> str:
        """The site's native resources, as its administrator lists them."""
        base = f"/var/www/{identifier}"
        return self.administer(
            f"getent passwd s{identifier}; getent group s{identifier}; "
            f"stat -c '%n %F %U %G %a' {base} {base}/public {base}/private "
            f"{base}/public/index.html /etc/nginx/sites-available/{identifier}.conf "
            f"/etc/nginx/sites-enabled/{identifier}.conf "
            f"/etc/php/{self.php}/fpm/pool.d/{identifier}.conf /run/php/s{identifier}.sock "
            "2>&1; true"
        )


class SiteApplyAcceptanceTests(SiteApplyTestCase):
    def test_a_reviewed_site_is_created_verified_and_reconstructed(self) -> None:
        plan = self.site_plan()
        run = self.apply_site(plan)
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        user = self.administer("getent passwd sshop").strip().split(":")
        uid, gid = int(user[2]), int(user[3])
        self.assertEqual(user[5:], ["/var/www/shop", "/usr/sbin/nologin"])
        self.assertEqual(self.administer("getent shadow sshop | cut -d: -f2 | cut -c1"), "!\n")
        self.assertEqual(self.administer("id -G sshop").strip(), str(gid))
        result = SiteRunResult.objects.get(run=run)
        self.assertEqual((result.uid, result.gid, result.probe_absent), (uid, gid, True))
        self.assertEqual(
            self.administer(
                "stat -c '%n %U %G %a' /var/www/shop /var/www/shop/public /var/www/shop/private "
                "/var/www/shop/public/index.html"
            ).splitlines(),
            [
                "/var/www/shop root root 755",
                "/var/www/shop/public sshop www-data 750",
                "/var/www/shop/private sshop sshop 700",
                "/var/www/shop/public/index.html sshop www-data 640",
            ],
        )
        names = ("shop.test", "www.shop.test")
        self.assertEqual(
            self.administer("cat /etc/nginx/sites-available/shop.conf"),
            render_site("shop", names, ipv6=True),
        )
        self.assertEqual(
            self.administer(f"cat /etc/php/{self.php}/fpm/pool.d/shop.conf"), render_pool("shop")
        )
        self.assertEqual(
            self.administer("readlink /etc/nginx/sites-enabled/shop.conf"),
            "/etc/nginx/sites-available/shop.conf\n",
        )
        self.assertEqual(
            self.administer("ls -A /var/www/shop/public /etc/nginx/sites-available"),
            "/etc/nginx/sites-available:\ndefault\nshop.conf\n\n/var/www/shop/public:\n"
            "index.html\n",
        )
        # Static and PHP content by Host, as the site user.
        for name in names:
            for address in ("127.0.0.1", "[::1]"):
                self.assertEqual(self.get(name, "/", address), render_placeholder("shop"))
        self.assertNotIn("is ready", self.get("unknown.test"))
        self.administer(
            f"printf %s {shlex.quote(IDENTITY)} >/var/www/shop/public/who.php && "
            "chown sshop:www-data /var/www/shop/public/who.php && "
            "chmod 640 /var/www/shop/public/who.php"
        )
        self.assertEqual(self.get("shop.test", "/who.php"), f"{uid} {gid}\n")
        # The run's audit keeps the reviewed files.
        self.assertEqual(RunFileChange.objects.filter(run=run).count(), 5)
        self.assertEqual(
            RunFileChange.objects.get(run=run, role="nginx_source").content,
            render_site("shop", names, ipv6=True),
        )

        # Discovery was queued after the run; with the password lock readable it finds the
        # site complete, and a repeated review changes nothing.
        self.addCleanup(self.administer, f"gpasswd -d {setting('USER')} shadow >/dev/null")
        self.assertEqual(DiscoveryAttempt.objects.filter(server=self.server).count(), 1)
        self.administer(f"usermod -aG shadow {setting('USER')}")
        request_discovery(self.server)
        run_worker()
        sites = {site.identifier: site for site in current(self.server).collected.sites.value}
        self.assertTrue(
            sites["shop"].complete,
            [r.warning for r in sites["shop"].resources if not r.conforms],
        )
        again = self.site_plan()
        self.assertTrue(again.no_changes)
