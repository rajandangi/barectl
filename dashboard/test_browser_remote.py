"""docs/ssh-connections.md#acceptance-against-a-real-server"""

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
from playwright.sync_api import expect

from bootstrap.models import ApplyRun
from bootstrap.test_package_remote import RESTORE as RESTORE_NGINX
from bootstrap.test_remote import FIXTURES, REMOVE_NGINX
from discovery.fakes import run_worker
from discovery.releases import SUPPORTED
from discovery.services import request_discovery
from discovery.test_remote import setting
from servers.models import Server
from sites.native import http_client
from sites.test_review_remote import PUT_BACK, SET_ASIDE, remove_site, snapshot

from .test_browser import PASSWORD, BrowserTestCase

REVIEWER_PERMISSIONS = (
    "view_server",
    "delete_server",
    "view_configurationplan",
    "prepare_configurationplan",
    "apply_configurationplan",
)


@tag("ssh")
@skipUnless(FIXTURES, "Set BARECTL_SSH_TEST_* to run against a disposable server")
class DisposableServerBrowserTests(BrowserTestCase):
    """An operator's browser, the production build, and the disposable server without Nginx."""

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
        for codename in REVIEWER_PERMISSIONS:
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.server = Server.objects.create(name="Production", ssh_alias="disposable")
        self.administer(REMOVE_NGINX)
        self.addCleanup(self.administer, RESTORE_NGINX)
        self.clear_units()
        self.addCleanup(self.clear_units)
        request_discovery(self.server)
        run_worker()
        self.open_context(width=1280, height=900)

    def administer(self, script: str) -> str:
        """Run ``script`` as the server's administrator, outside Barectl."""
        result = subprocess.run(  # noqa: S603 - the tests' own fixture scripts
            ["docker", "exec", setting("CONTAINER"), "sh", "-c", script],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return result.stdout

    def clear_units(self) -> None:
        self.administer(
            "systemctl stop 'barectl-apply-*' 2>/dev/null; "
            "systemctl reset-failed 'barectl-apply-*' 2>/dev/null; true"
        )

    def work(self, *paths: str) -> None:
        """Run the worker while the page's polls of ``paths`` are held back."""
        page = self.page
        for path in paths:
            page.route(f"**{path}**", lambda route: route.fulfill(status=204))
        run_worker()
        for path in paths:
            page.unroute(f"**{path}**")

    def test_nginx_is_reviewed_applied_audited_and_removed_through_the_browser(self) -> None:
        page = self.page
        self.sign_in()
        page.get_by_role("link", name="Production").click()
        plans = page.locator("#plans")
        nginx = page.get_by_role("radio", name=re.compile(r"^Nginx profile"))
        nginx.focus()
        page.keyboard.press("Space")
        page.keyboard.press("Tab")
        expect(page.get_by_role("button", name="Prepare plan")).to_be_focused()
        with page.expect_response(lambda response: response.url.endswith("/prepare/")):
            page.keyboard.press("Enter")
        self.work("/plans/?shown=")
        expect(plans).to_contain_text("Ready for review", timeout=30_000)
        plans.get_by_role("link", name=re.compile("Open this plan")).click()
        expect(page.get_by_role("heading", name="Nginx profile plan", level=1)).to_be_visible()
        # The review shows the server's actual transaction and its exposure.
        main = page.locator("main")
        expect(main.get_by_role("table").first).to_contain_text("nginx-common")
        expect(main).to_contain_text("Transaction guard.")
        expect(main).to_contain_text("serves HTTP on port 80")
        confirmation = page.locator("#apply-confirmation")
        expect(confirmation).to_contain_text("to Production with SSH alias disposable")

        apply = page.get_by_role("button", name=re.compile(r"^Apply plan \d+$"))
        apply.focus()
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Apply queued", level=2)).to_be_visible()
        self.work("/status/")
        expect(page.get_by_role("heading", name="Applied and verified", level=2)).to_be_visible(
            timeout=30_000
        )
        expect(page.locator("#apply-status")).to_contain_text("Postconditions hold")
        run = ApplyRun.objects.get()
        # Native truth, read outside Barectl.
        self.assertEqual(
            self.administer("systemctl is-active nginx; systemctl is-active " + run.unit_name),
            "active\nactive\n",
        )

        # Activity lists the run for a reviewer.
        page.get_by_role("link", name="Activity").click()
        expect(page.locator("main")).to_contain_text("Apply: Nginx profile")

        # An account with inventory access alone sees no plans, runs or their audit.
        observer = get_user_model().objects.create_user("observer", password=PASSWORD)
        observer.user_permissions.add(Permission.objects.get(codename="view_server"))
        self.context.close()
        self.open_context(width=1280, height=900)
        page = self.page
        page.goto(f"{self.live_server_url}/accounts/login/?next=/")
        page.get_by_label("Username").fill("observer")
        page.get_by_label("Password").fill(PASSWORD)
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Servers", level=1)).to_be_visible()
        page.get_by_role("link", name="Production").click()
        expect(page.locator("#plans")).to_have_count(0)
        page.goto(f"{self.live_server_url}/activity/")
        expect(page.locator("main")).not_to_contain_text("Apply:")
        self.client.force_login(observer)
        self.assertEqual(self.client.get(f"/applies/{run.pk}/").status_code, 403)

        # The reviewer removes the registration; the apply audit stays, detached.
        self.context.close()
        self.open_context(width=1280, height=900)
        page = self.page
        self.sign_in()
        page.get_by_role("link", name="Production").click()
        page.get_by_role("link", name="Remove Production").focus()
        page.keyboard.press("Enter")
        confirm = page.get_by_role("button", name="Remove server")
        confirm.focus()
        page.keyboard.press("Enter")
        expect(page.locator(".barectl-messages")).to_contain_text("Removed Production")
        page.goto(f"{self.live_server_url}/activity/")
        expect(page.locator("main")).to_contain_text("Production (removed)")
        page.goto(f"{self.live_server_url}/applies/{run.pk}/")
        expect(page.locator("main")).to_contain_text("Production (registration removed)")
        expect(page.get_by_role("heading", name="Applied and verified", level=2)).to_be_visible()
        # Removal changed nothing on the server.
        self.assertEqual(self.administer("systemctl is-active nginx"), "active\n")


SITE_PERMISSIONS = (
    "view_server",
    "delete_server",
    "view_siteplan",
    "prepare_siteplan",
    "apply_siteplan",
)


@tag("ssh")
@skipUnless(FIXTURES, "Set BARECTL_SSH_TEST_* to run against a disposable server")
class DisposableServerSiteBrowserTests(BrowserTestCase):
    """A site plan prepared with the keyboard through the real worker and SSH; nothing changes."""

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
        for codename in SITE_PERMISSIONS:
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.server = Server.objects.create(name="Production", ssh_alias="disposable")
        self.administer(SET_ASIDE)
        self.addCleanup(self.administer, PUT_BACK)
        self.addCleanup(
            self.administer,
            "systemctl stop 'barectl-apply-*' 2>/dev/null; "
            "systemctl reset-failed 'barectl-apply-*' 2>/dev/null; true",
        )
        release = self.administer(". /etc/os-release; echo $VERSION_ID").strip()
        self.php = SUPPORTED[release].php
        self.addCleanup(self.administer, remove_site("shop", self.php))
        self.open_context(width=1280, height=900)

    def administer(self, script: str) -> str:
        """Run ``script`` as the server's administrator, outside Barectl."""
        result = subprocess.run(  # noqa: S603 - the tests' own fixture scripts
            ["docker", "exec", setting("CONTAINER"), "sh", "-c", script],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return result.stdout

    def test_a_site_is_reviewed_applied_audited_and_removed_through_the_browser(self) -> None:
        before = self.administer(snapshot(self.php))
        page = self.page
        self.sign_in()
        page.get_by_role("link", name="Production").click()
        section = page.locator("#site-plans")
        section.get_by_label("Site identifier").focus()
        page.keyboard.type("html")
        page.keyboard.press("Tab")
        page.keyboard.type("shop.test")
        page.keyboard.press("Tab")
        page.keyboard.press("Enter")
        expect(section).to_contain_text("html is reserved")
        self.assertEqual(len(self.console_errors), 1)
        self.assertIn("status of 422", self.console_errors.pop())

        section.get_by_label("Site identifier").focus()
        page.keyboard.press("ControlOrMeta+a")
        page.keyboard.type("shop")
        page.keyboard.press("Tab")
        page.keyboard.press("Tab")
        page.route("**/sites/?shown=**", lambda route: route.fulfill(status=204))
        with page.expect_response(lambda response: response.url.endswith("/sites/prepare/")):
            page.keyboard.press("Enter")
        self.work("/sites/?shown=")
        expect(section).to_contain_text("Ready for review", timeout=30_000)
        expect(section).to_contain_text(f"/etc/php/{self.php}/fpm/pool.d/shop.conf")
        expect(section).to_contain_text("Required authority")
        # Applying starts only from the plan's own page.
        expect(page.get_by_role("button", name=re.compile("Apply"))).to_have_count(0)
        section.get_by_role("link", name=re.compile("Open this plan")).click()
        expect(page.get_by_role("heading", name="HTTP PHP site plan", level=1)).to_be_visible()
        # Native truth, read as root outside Barectl: preparation changed nothing.
        self.assertEqual(self.administer(snapshot(self.php)), before)
        plan_path = urlsplit(page.url).path
        confirmation = page.locator("#apply-confirmation")
        expect(confirmation).to_contain_text("HTTP PHP site, revision 1, to Production")
        apply = page.get_by_role("button", name=re.compile(r"^Apply plan \d+$"))
        apply.focus()
        # The run page's polls are held from its first load until the worker is done, so
        # none reaches the database while the worker writes to it.
        page.route("**/status/**", lambda route: route.fulfill(status=204))
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Apply queued", level=2)).to_be_visible()
        self.work("/status/")
        expect(page.get_by_role("heading", name="Applied and verified", level=2)).to_be_visible(
            timeout=60_000
        )
        run = ApplyRun.objects.get()
        # Native truth: the site serves its placeholder by Host.
        served = self.administer(f"{http_client(self.php)}; k 127.0.0.1 shop.test /")
        self.assertIn("Site shop is ready.", served)

        observer = get_user_model().objects.create_user("observer", password=PASSWORD)
        observer.user_permissions.add(Permission.objects.get(codename="view_server"))
        self.client.force_login(observer)
        self.assertEqual(self.client.get(plan_path).status_code, 403)
        self.assertEqual(self.client.get(f"/applies/{run.pk}/").status_code, 403)

        # Removing the registration keeps the run's audit; the site keeps serving.
        page.goto(f"{self.live_server_url}/servers/{self.server.pk}/remove/")
        confirm = page.get_by_role("button", name="Remove server")
        confirm.focus()
        page.keyboard.press("Enter")
        expect(page.locator(".barectl-messages")).to_contain_text("Removed Production")
        page.goto(f"{self.live_server_url}/applies/{run.pk}/")
        expect(page.locator("main")).to_contain_text("Production (registration removed)")
        expect(page.locator("#apply-audit")).to_contain_text(
            "Publish /etc/nginx/sites-available/shop.conf"
        )
        served = self.administer(f"{http_client(self.php)}; k 127.0.0.1 shop.test /")
        self.assertIn("Site shop is ready.", served)

    def work(self, *paths: str) -> None:
        page = self.page
        for path in paths:
            page.route(f"**{path}**", lambda route: route.fulfill(status=204))
        run_worker()
        for path in paths:
            page.unroute(f"**{path}**")
