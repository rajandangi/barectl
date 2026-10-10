"""One ordinary WordPress form on a fresh disposable server and encrypted first access."""

import subprocess
import sys
import time
from typing import override

from django.contrib.auth.models import Permission
from django.test import override_settings, tag
from playwright.sync_api import expect

from bootstrap.models import ApplyRun
from bootstrap.php_source_testing import trust_fixture
from dashboard.hosting_testing import HostingJourneyTestCase
from discovery.native_testing import setting
from discovery.releases import SUPPORTED
from disposable import acme
from tls.native_testing import SHORT_AUTHORITY
from wordpress import qualification_testing

from .creation import CreationInput, permissions
from .models import HostingCreation


@tag("ssh", "native-browser")
@override_settings(
    ACME_AUTHORITIES=[SHORT_AUTHORITY], ACME_PRODUCTION_DIRECTORY=acme.SHORT_DIRECTORY
)
class FreshWordpressBrowserTests(HostingJourneyTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        trust_fixture(self, self.administer)
        release = self.administer(". /etc/os-release; echo $VERSION_ID").strip()
        architecture = self.administer("dpkg --print-architecture").strip()
        self.enterContext(
            qualification_testing.source_candidate_qualified(
                release, architecture, SUPPORTED[release].php
            )
        )
        self.administer(
            "set -e; p=$(dpkg-query -W -f='${Package} ${db:Status-Abbrev}\\n' 'php*' "
            "2>/dev/null | awk '$2 != \"un\" {print $1}'); "
            'if [ -n "$p" ]; then DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq $p '
            ">/dev/null; fi; DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "
            "nginx nginx-common gpg gpg-agent curl libsodium23 libgd3 certbot "
            ">/dev/null; rm -rf /etc/nginx"
        )
        addresses = acme.server_addresses()
        self.point(("browser-wordpress.test",), addresses.ipv4, addresses.ipv6)
        wanted = CreationInput(
            ("browser-wordpress.test",),
            application="wordpress",
            database_engine="mariadb",
            https=True,
        )
        for permission in permissions(wanted):
            app, codename = permission.split(".")
            self.user.user_permissions.add(
                Permission.objects.get(content_type__app_label=app, codename=codename)
            )

    def test_fresh_wordpress_one_form_under_two_minutes_and_browser_first_access(self) -> None:
        started = time.monotonic()
        server = self.register()
        page = self.page
        page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/new/?application=wordpress")
        expect(page.get_by_role("heading", name="Create WordPress site")).to_be_visible()
        page.get_by_label("Domain", exact=True).fill("browser-wordpress.test")
        page.get_by_label("Site title").fill("Browser site")
        page.get_by_label("Administrator username").fill("owner")
        page.get_by_label("Administrator email").fill("owner@example.com")
        page.get_by_label("Accept the certificate authority agreement").check()
        self.assert_no_overflow()
        with page.expect_navigation():
            page.get_by_role("button", name="Create WordPress site").click()
        operator_seconds = time.monotonic() - started
        self.assertLess(operator_seconds, 120)
        self.assertEqual(HostingCreation.objects.count(), 1)
        self.drain_worker()
        creation = HostingCreation.objects.get()
        failure = creation.failure
        if creation.status != HostingCreation.Status.SUCCEEDED:
            last = ApplyRun.objects.order_by("-pk").first()
            if last is not None:
                failure += "\n" + self.administer(
                    f"journalctl --no-pager -n 45 -u {last.unit_name}; true"
                )
        self.assertEqual(creation.status, HostingCreation.Status.SUCCEEDED, failure)
        page.reload()
        expect(page.get_by_role("link", name="Open WordPress login")).to_be_visible()
        page.get_by_role("button", name="Show administrator password").click()
        output = page.locator("[data-first-access-password]")
        expect(output).to_be_visible()
        password = output.inner_text()
        self.assertRegex(password, r"\A[A-Za-z0-9]{32}\Z")
        self.assertFalse(any(password in (request.post_data or "") for request in self.requests))
        response = subprocess.run(  # noqa: S603 - disposable native HTTPS ground truth
            [  # noqa: S607 - the configured disposable-container tool
                "docker",
                "exec",
                "-i",
                setting("CONTAINER"),
                "curl",
                "--silent",
                "--show-error",
                "--max-time",
                "20",
                "--resolve",
                "browser-wordpress.test:443:127.0.0.1",
                "--cookie",
                "wordpress_test_cookie=WP%20Cookie%20check",
                "--data-urlencode",
                "log=owner",
                "--data-urlencode",
                "pwd@-",
                "--data-urlencode",
                "redirect_to=https://browser-wordpress.test/wp-admin/",
                "--data",
                "testcookie=1",
                "--dump-header",
                "-",
                "--output",
                "/dev/null",
                "https://browser-wordpress.test/wp-login.php",
            ],
            input=password,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(response.returncode, 0)
        headers = response.stdout.replace("\r", "").splitlines()
        self.assertTrue(
            any(line.startswith("Set-Cookie: wordpress_logged_in_") for line in headers)
        )
        self.assertTrue(
            any(line == "Location: https://browser-wordpress.test/wp-admin/" for line in headers)
        )
        expect(page.get_by_role("button", name="Show administrator password")).to_be_disabled()
        self.assertEqual(HostingCreation.objects.count(), 1)
        self.assert_no_overflow()
        sys.stdout.write(
            f"WordPress operator input: {operator_seconds:.3f}s; "
            f"total through authenticated first access: {time.monotonic() - started:.3f}s\n"
        )
