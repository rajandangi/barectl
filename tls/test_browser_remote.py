"""Renewal setup reviewed, applied and inspected in Chromium against a real server.

Tagged ``ssh`` and ``browser``; see dashboard/test_browser_remote.py for the pattern.
"""

import logging
import re
import subprocess
import tempfile
from pathlib import Path
from typing import override
from unittest import skipUnless
from urllib.parse import urlsplit

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from playwright.sync_api import Response, expect

from bootstrap.models import ApplyRun
from bootstrap.test_remote import FIXTURES
from dashboard.test_browser import PASSWORD, BrowserTestCase
from dashboard.testing import RecordedErrors
from discovery.fakes import run_worker
from discovery.test_remote import setting
from servers.models import Server

from . import renewal
from .test_setup_remote import PURGE

TLS_PERMISSIONS = ("view_server", "view_tlsplan", "prepare_tlsplan", "apply_tlsplan")


@tag("ssh", "native-browser")
@skipUnless(FIXTURES, "Set BARECTL_SSH_TEST_* to run against a disposable server")
class DisposableServerRenewalBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    @override
    def setUp(self) -> None:
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir="/tmp")))
        config = directory / "config"
        config.write_text(
            f"Host disposable\n  HostName {setting('HOST')}\n  Port {setting('PORT')}\n"
            f"  User {setting('USER')}\n  UserKnownHostsFile {setting('KNOWN_HOSTS')}\n"
            f"  IdentityFile {setting('KEY')}\n",
            encoding="utf-8",
        )
        self.enterContext(override_settings(SSH_CONFIG_PATH=str(config)))
        self.user = get_user_model().objects.create_user("operator", password=PASSWORD)
        for codename in TLS_PERMISSIONS:
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.server = Server.objects.create(name="Production", ssh_alias="disposable")
        self.administer(PURGE)
        self.addCleanup(self.administer, PURGE)
        self.addCleanup(
            self.administer,
            "systemctl stop 'barectl-apply-*' 2>/dev/null; "
            "systemctl reset-failed 'barectl-apply-*' 2>/dev/null; true",
        )
        self.open_context(width=1280, height=900)
        self.page.on("response", self.record_server_error)
        errors = RecordedErrors(self.console_errors)
        logger = logging.getLogger("django.request")
        logger.addHandler(errors)
        self.addCleanup(logger.removeHandler, errors)

    def record_server_error(self, response: Response) -> None:
        if response.status >= 500:
            self.console_errors.append(f"{response.status} {response.url}")

    def administer(self, script: str) -> str:
        result = subprocess.run(  # noqa: S603 - the tests' own fixture scripts
            ["docker", "exec", setting("CONTAINER"), "sh", "-c", script],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
            timeout=600,
        )
        return result.stdout

    def work(self, *paths: str) -> None:
        page = self.page
        for path in paths:
            page.route(f"**{path}**", lambda route: route.fulfill(status=204))
        run_worker()
        for path in paths:
            page.unroute(f"**{path}**")

    def prepare(self) -> None:
        page = self.page
        section = page.locator("#tls-plans")
        if section.locator("details").first.get_attribute("open") is None:
            section.get_by_text("Advanced TLS plans and diagnostics", exact=True).focus()
            page.keyboard.press("Enter")
        page.route("**/tls/?shown=**", lambda route: route.fulfill(status=204))
        prepare = section.get_by_role("button", name="Prepare renewal setup plan")
        prepare.focus()
        with page.expect_response(lambda response: response.url.endswith("/certbot/prepare/")):
            page.keyboard.press("Enter")
        self.work("/tls/?shown=")
        page.unroute("**/tls/?shown=**")

    def test_renewal_setup_is_reviewed_applied_and_inspected_through_the_browser(self) -> None:
        page = self.page
        self.sign_in()
        page.get_by_role("link", name="Production").click()
        page.get_by_role("navigation", name="Server sections").get_by_role(
            "link", name="Advanced", exact=True
        ).click()
        section = page.locator("#tls-plans")
        self.prepare()
        expect(section).to_contain_text("Ready for review", timeout=60_000)
        expect(section).to_contain_text("certbot.timer is not installed.")
        expect(section).to_contain_text(renewal.WRAPPER)
        expect(section).to_contain_text("masked at runtime")
        expect(page.get_by_role("button", name=re.compile("Apply"))).to_have_count(0)
        section.get_by_role("link", name=re.compile("Open this plan")).click()
        plan_path = urlsplit(page.url).path
        expect(page.locator("#apply-confirmation")).to_contain_text(
            re.compile(r"Certbot renewal setup, revision \d+, to Production")
        )
        apply = page.get_by_role("button", name=re.compile(r"^Apply plan \d+$"))
        apply.focus()
        page.route("**/status/**", lambda route: route.fulfill(status=204))
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Apply queued", level=2)).to_be_visible()
        self.work("/status/")
        page.unroute("**/status/**")
        page.reload()
        expect(page.get_by_role("heading", name="Applied and verified", level=2)).to_be_visible(
            timeout=120_000
        )
        expect(page.locator("#apply-audit")).to_contain_text(f"Publish {renewal.WRAPPER}")
        run = ApplyRun.objects.get()
        timer = self.administer(
            "systemctl is-enabled certbot.timer; systemctl is-active certbot.timer"
        )
        self.assertEqual(timer, "enabled\nactive\n")

        # Renewal runs, and a new preparation inspects it read-only.
        self.administer("systemctl start certbot.service")
        page.goto(f"{self.live_server_url}/servers/{self.server.pk}/advanced/")
        self.prepare()
        expect(section).to_contain_text("No changes", timeout=60_000)
        expect(section).to_contain_text("certbot.timer is enabled and active")
        expect(section).to_contain_text("completed: nothing was due")

        # Site and bootstrap permissions grant no TLS plan, run or inspection.
        observer = get_user_model().objects.create_user("observer", password=PASSWORD)
        for codename in ("view_server", "view_siteplan", "view_configurationplan"):
            observer.user_permissions.add(Permission.objects.get(codename=codename))
        self.client.force_login(observer)
        self.assertEqual(self.client.get(plan_path).status_code, 403)
        self.assertEqual(self.client.get(f"/applies/{run.pk}/").status_code, 403)
        self.assertNotContains(self.client.get(f"/servers/{self.server.pk}/advanced/"), "TLS plans")
        response = self.client.post(f"/servers/{self.server.pk}/tls/certbot/prepare/")
        self.assertEqual(response.status_code, 403)
