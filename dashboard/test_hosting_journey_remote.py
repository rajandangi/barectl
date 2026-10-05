"""The integrated hosting workflow in Chromium against a disposable server.

docs/dashboard-qualification.md records what these journeys qualify. Tagged ``ssh`` and
``native-browser``; they need the ACME and DNS fixtures ``run-tests.sh`` starts
(docs/ssh-connections.md#acme-and-dns-fixtures). Ground truth is read with ``docker exec``.
"""

import json
import logging
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from html import unescape
from pathlib import Path
from typing import ClassVar, override
from unittest import skipUnless

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from playwright.sync_api import Locator, Response, expect

from bootstrap.models import Action, ApplyRun, Verification
from bootstrap.test_mariadb_remote import REMOVE_MARIADB
from bootstrap.test_remote import FIXTURES, REMOVE_NGINX, RESTORE_NGINX
from dashboard.testing import TEST_MANIFEST, RecordedErrors
from discovery.fakes import run_worker
from discovery.releases import SUPPORTED
from discovery.test_remote import setting
from disposable import acme
from operations.models import RemoteOperation
from servers.models import Server
from sites.test_review_remote import PUT_BACK, SET_ASIDE, remove_site
from tls import native as tls_native
from tls import progress
from tls.models import CertificateInstallation
from tls.test_setup_remote import PURGE

from .test_browser import PASSWORD, BrowserTestCase

AUTHORITY = {"directory": acme.DIRECTORY, "caa": "pebble", "name": "Pebble"}
OPERATOR_PERMISSIONS = (
    "view_server",
    "add_server",
    "add_discoveryattempt",
    "view_siteobservation",
    "view_configurationplan",
    "prepare_configurationplan",
    "apply_configurationplan",
    "view_siteplan",
    "prepare_siteplan",
    "apply_siteplan",
    "view_databaseplan",
    "prepare_databaseplan",
    "apply_databaseplan",
    "view_tlsplan",
    "prepare_tlsplan",
    "apply_tlsplan",
    "issue_certificate",
)
UNITS = (
    "systemctl stop 'barectl-apply-*' 2>/dev/null; "
    "systemctl reset-failed 'barectl-apply-*' 2>/dev/null; true"
)
WRONG_IPV4 = "192.0.2.10"
WRONG_IPV6 = "2001:db8::10"
OVERFLOW = "document.documentElement.scrollWidth - document.documentElement.clientWidth"

# A separate process, as the native suites run other controllers
# (bootstrap/test_journey_remote.py SECOND_DEVICE).
FRESH_CONTROLLER = """
import json
import os
import sys
from pathlib import Path

os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
from config import settings as configured

database, ssh_config, manifest, identifier = sys.argv[1:]
configured.DATABASES["default"]["NAME"] = database
configured.SSH_CONFIG_PATH = ssh_config
configured.VITE_MANIFEST_PATH = Path(manifest)
configured.VITE_DEV_SERVER_URL = ""
configured.ALLOWED_HOSTS = ["testserver"]

import django

django.setup()

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import Client

from bootstrap.models import ApplyRun, PlanPreparation
from discovery.fakes import run_worker
from discovery.models import DiscoveryAttempt
from discovery.services import request_discovery
from servers.models import Server
from tls.models import CertificateInstallation

call_command("migrate", verbosity=0)
user = get_user_model().objects.create_user("fresh-controller")
for codename in (
    "view_server",
    "view_siteobservation",
    "view_configurationplan",
    "view_siteplan",
    "view_databaseplan",
    "view_tlsplan",
):
    user.user_permissions.add(Permission.objects.get(codename=codename))
server = Server.objects.create(name="Reconstructed", ssh_alias="disposable-fresh")
request_discovery(server)
run_worker()
client = Client()
client.force_login(user)
pages = {}
for section in ("overview", "database", "https", "activity"):
    response = client.get(f"/servers/{server.pk}/sites/{identifier}/{section}/", secure=True)
    pages[section] = {"status": response.status_code, "html": response.content.decode()}
print(json.dumps({
    "discovery": DiscoveryAttempt.objects.get().status,
    "pages": pages,
    "runs": ApplyRun.objects.count(),
    "preparations": PlanPreparation.objects.count(),
    "installations": CertificateInstallation.objects.count(),
}))
"""


@dataclass(frozen=True)
class FreshController:
    discovery: str
    pages: dict[str, dict[str, object]]
    runs: int
    preparations: int
    installations: int

    def html(self, section: str) -> str:
        page = self.pages[section]
        if page["status"] != 200:
            raise AssertionError(f"{section}: {page['status']}")
        return str(page["html"])


def evidence(html: str) -> str:
    """A site section's observed evidence as text, without its times.

    It is the section's first fact list; reviews and installation records below it are this
    controller's own records.
    """
    main = html[html.index("<main") :]
    found = re.search(r'<dl class="barectl-facts[^"]*">(.*?)</dl>', main, re.DOTALL)
    if found is None:
        raise AssertionError("The page shows no observed evidence.")
    untimed = re.sub(r"<time\b.*?</time>", "", found.group(1), flags=re.DOTALL)
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", untimed)).split())


@tag("ssh", "native-browser")
@skipUnless(FIXTURES and acme.CONFIGURED, "Set BARECTL_SSH_TEST_* and BARECTL_ACME_TEST_*")
@override_settings(ACME_AUTHORITIES=[AUTHORITY], ACME_PRODUCTION_DIRECTORY=acme.DIRECTORY)
class HostingJourneyTestCase(BrowserTestCase):
    """One operator's browser, the production build, the worker and the disposable server."""

    php: ClassVar[str]

    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        acme.install_trust_and_resolver(cls)
        release = cls.administer(". /etc/os-release; echo $VERSION_ID").strip()
        cls.php = SUPPORTED[release].php
        cls.establish(PURGE, PURGE)
        cls.addClassCleanup(cls.administer, UNITS)

    @classmethod
    def establish(cls, state: str, restore: str) -> None:
        """Bring the server to ``state`` for this class and ``restore`` it afterwards."""
        cls.addClassCleanup(cls.administer, restore)
        cls.administer(state)

    @classmethod
    def administer(cls, script: str) -> str:
        """Run ``script`` as the server's administrator, outside Barectl."""
        result = subprocess.run(  # noqa: S603 - the tests' own fixture scripts
            ["docker", "exec", setting("CONTAINER"), "sh", "-c", script],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
            timeout=600,
        )
        return result.stdout

    @override
    def setUp(self) -> None:
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        config = self.directory / "config"
        config.write_text(self.ssh_entry("disposable", "KEY"), encoding="utf-8")
        self.enterContext(override_settings(SSH_CONFIG_PATH=str(config)))
        self.user = get_user_model().objects.create_user("operator", password=PASSWORD)
        for codename in OPERATOR_PERMISSIONS:
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.open_context(width=1280, height=900)
        self.page.on("response", self.record_server_error)
        errors = RecordedErrors(self.console_errors)
        logger = logging.getLogger("django.request")
        logger.addHandler(errors)
        self.addCleanup(logger.removeHandler, errors)

    def ssh_entry(self, alias: str, key: str) -> str:
        return (
            f"Host {alias}\n  HostName {setting('HOST')}\n  Port {setting('PORT')}\n"
            f"  User {setting('USER')}\n  UserKnownHostsFile {setting('KNOWN_HOSTS')}\n"
            f"  IdentityFile {setting(key)}\n"
        )

    def record_server_error(self, response: Response) -> None:
        if response.status >= 500:
            self.console_errors.append(f"{response.status} {response.url}")

    def drain_worker(self) -> None:
        """Run the worker until its queue is empty while the page's polls are held back.

        Held polls cannot race the worker for the database; the next poll shows its result.
        """
        page = self.page

        def held(url: str) -> bool:
            return "shown=" in url or url.endswith(("/status/", "/discovery/"))

        page.route(held, lambda route: route.fulfill(status=204))
        run_worker()
        page.unroute(held)

    def submit(self, button: Locator, endpoint: str) -> None:
        """Press ``button`` with the keyboard and run the work its request queued."""
        page = self.page
        button.focus()
        with page.expect_response(lambda response: response.url.endswith(endpoint)):
            page.keyboard.press("Enter")
        self.drain_worker()

    def open_review(self, section: Locator) -> None:
        expect(section).to_contain_text("Ready for review", timeout=60_000)
        section.get_by_role("link", name=re.compile("Open this plan")).click()

    def navigate(self, navigation: str, name: str) -> None:
        nav = self.page.get_by_role("navigation", name=navigation)
        nav.get_by_role("link", name=name, exact=True).focus()
        self.page.keyboard.press("Enter")
        expect(nav.get_by_role("link", name=name, exact=True)).to_have_attribute(
            "aria-current", "page"
        )

    def point(self, names: tuple[str, ...], ipv4: str, ipv6: str) -> None:
        """Answer the names with these addresses only, replacing earlier answers."""
        base = f"http://{acme.published(acme.setting('CHALLTESTSRV'), 8055)}"
        for name in names:
            for clear in ("clear-a", "clear-aaaa"):
                body = json.dumps({"host": acme.fqdn(name)}).encode()
                acme.fetch(f"{base}/{clear}", method="POST", body=body)
            acme.add_a(self, name, [ipv4])
            if not acme.IPV6_UNAVAILABLE:
                acme.add_aaaa(self, name, [ipv6])

    def assert_no_overflow(self) -> None:
        page = self.page
        page.set_viewport_size({"width": 320, "height": 740})
        self.assertEqual(page.evaluate(OVERFLOW), 0, page.url)
        page.set_viewport_size({"width": 1280, "height": 900})

    def register(self) -> Server:
        """Add the server by its controller SSH alias and follow its connection check."""
        page = self.page
        self.sign_in()
        expect(page.get_by_role("heading", name="No servers yet")).to_be_visible()
        page.get_by_role("link", name="Add server").click()
        page.get_by_role("textbox", name="Name").focus()
        page.keyboard.type("Production")
        page.keyboard.press("Tab")
        page.get_by_role("combobox", name="SSH alias").select_option("disposable")
        page.get_by_role("button", name="Register server").focus()
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Production", level=1)).to_be_visible()
        expect(page.locator("#discovery")).to_contain_text("Connection check queued")
        self.drain_worker()
        expect(page.locator("#connection-status")).to_have_text("Verified", timeout=30_000)
        expect(page.locator("#discovery-announcement")).to_contain_text("Connection verified.")
        return Server.objects.get()

    def apply_reviewed(self, heading: str, timeout: int = 300_000) -> ApplyRun:
        """Apply the plan this page shows and follow its run to its verified outcome."""
        page = self.page
        expect(page.get_by_role("heading", name=heading, level=1)).to_be_visible()
        page.get_by_role("button", name=re.compile(r"^Apply plan \d+$")).focus()
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Apply queued", level=2)).to_be_visible()
        self.drain_worker()
        run = ApplyRun.objects.latest("pk")
        failure = run.failure
        if run.status != RemoteOperation.Status.SUCCEEDED:
            failure += "\n" + self.administer(
                f"journalctl --no-pager -n 60 -u {run.unit_name}; true"
            )
        self.assertEqual(
            (run.status, run.verification),
            (RemoteOperation.Status.SUCCEEDED, Verification.PASSED),
            failure,
        )
        expect(page.get_by_role("heading", name="Applied and verified", level=2)).to_be_visible(
            timeout=timeout
        )
        return run

    def prepare_profile(self, label: str) -> None:
        """Choose a Setup profile with the keyboard, prepare it and open its review."""
        page = self.page
        plans = page.locator("#plans")
        page.get_by_role("radio", name=re.compile(f"^{re.escape(label)}")).focus()
        page.keyboard.press("Space")
        page.keyboard.press("Tab")
        button = plans.get_by_role("button", name="Prepare plan")
        expect(button).to_be_focused()
        self.submit(button, "/plans/prepare/")
        self.open_review(plans)

    def create_site(self, identifier: str, names: tuple[str, ...]) -> ApplyRun:
        """From Sites: prepare, review and apply a site plan, then open its handoff."""
        page = self.page
        self.navigate("Server sections", "Sites")
        section = page.locator("#site-plans")
        expect(section).to_contain_text("application deployment is not included")
        section.get_by_label("Site identifier").focus()
        page.keyboard.type(identifier)
        page.keyboard.press("Tab")
        page.keyboard.type(" ".join(names))
        page.keyboard.press("Tab")
        button = section.get_by_role("button", name="Prepare site plan")
        expect(button).to_be_focused()
        self.submit(button, "/sites/prepare/")
        expect(section).to_contain_text("Ready for review", timeout=60_000)
        expect(section).to_contain_text(f"/etc/php/{self.php}/fpm/pool.d/{identifier}.conf")
        expect(page.get_by_role("button", name=re.compile("Apply"))).to_have_count(0)
        self.open_review(section)
        run = self.apply_reviewed("HTTP PHP site plan")
        page.reload()
        completion = page.locator("#run-completion")
        expect(completion).to_contain_text("Observed as a current site")
        completion.get_by_role("link", name=re.compile("^Open site")).click()
        expect(page.get_by_role("heading", name=", ".join(names), level=1)).to_be_visible()
        expect(page.locator("main")).to_contain_text(f"Site {identifier} on Production")
        served = self.administer(f"{tls_native.status_client(self.php)}; s 127.0.0.1 {names[-1]} /")
        self.assertTrue(served.startswith("200"), served)
        self.assertIn(f"Site {identifier} is ready.", served)
        return run

    def enable_https(self, email: str) -> None:
        """Submit the site's one Enable HTTPS action with the keyboard."""
        page = self.page
        section = page.locator("#site-installation")
        expect(section.get_by_role("checkbox")).to_have_count(0)
        section.get_by_label("Contact email", exact=True).focus()
        page.keyboard.type(email)
        page.keyboard.press("Tab")
        expect(section.get_by_role("button", name="Enable HTTPS", exact=True)).to_be_focused()
        with page.expect_response(lambda response: response.url.endswith("/https/install/")):
            page.keyboard.press("Enter")
        expect(page.locator("#site-installation-heading")).to_be_focused()
        expect(page.locator("#site-installation-announcement")).to_contain_text("Installing HTTPS")
        expect(section.get_by_role("button", name="Enable HTTPS")).to_have_count(0)
        self.drain_worker()

    def assert_activated_site_observed(self, server: Server, identifier: str) -> None:
        """After activation, discovery observes the site's names, root and socket as its own.

        The SSH identity cannot read /etc/shadow, so the locked password is inaccessible and
        the site is reported with that one resource unconfirmed
        (docs/ssh-connections.md#completeness).
        """
        page = self.page
        page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/{identifier}/advanced/")
        resources = page.get_by_role("region", name="Native resources and evidence")

        def verdict(label: str) -> Locator:
            return resources.locator("dl > div").filter(
                has=page.locator("dt", has_text=re.compile(f"^\\s*{label}"))
            )

        expect(verdict("Names, root and socket not shared").locator("dd")).to_contain_text(
            "Observed, as the convention requires"
        )
        expect(verdict("Locked password").locator("dd")).to_contain_text("Inaccessible")
        self.navigate("Site sections", "Overview")
        expect(page.get_by_role("region", name="Observed site")).to_contain_text(
            re.compile(r"Does not match the supported site convention: 1 of \d+ resources")
        )

    def check_readiness(self) -> None:
        readiness = self.page.locator("#site-readiness")
        self.submit(readiness.get_by_role("button", name="Check readiness"), "/readiness/prepare/")

    def assert_served_over_https(self, identifier: str, names: tuple[str, ...]) -> None:
        """Each name is served the issued certificate, trusted for that name, and HTTP redirects."""
        live = f"/etc/letsencrypt/live/{identifier}"
        on_disk = self.administer(
            f"openssl x509 -outform DER -in {live}/cert.pem | sha256sum | cut -d' ' -f1"
        ).strip()
        self.assertEqual(len(on_disk), 64)
        for name in names:
            quoted = shlex.quote(name)
            served = self.administer(
                "timeout 10 openssl s_client -connect 127.0.0.1:443 "
                f"-servername {quoted} </dev/null 2>/dev/null | openssl x509 -outform DER "
                "| sha256sum | cut -d' ' -f1"
            ).strip()
            self.assertEqual(served, on_disk, name)
            body = self.administer(
                f"printf 'GET / HTTP/1.0\\r\\nHost: %s\\r\\n\\r\\n' {quoted} | timeout 10 "
                "openssl s_client -quiet -verify_return_error -verify_hostname "
                f"{quoted} -connect 127.0.0.1:443 -servername {quoted} 2>/dev/null; true"
            )
            self.assertIn(f"Site {identifier} is ready.", body, name)
            redirect = self.administer(
                f"{tls_native.status_client(self.php)}; s 127.0.0.1 {quoted} / | head -c 3"
            )
            self.assertEqual(redirect, "301", name)


class FirstSiteJourneyTests(HostingJourneyTestCase):
    """A server without Nginx or MariaDB: connect, Setup, create, database, HTTPS, Activity."""

    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        no_database = (
            f"{REMOVE_MARIADB}; DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "
            f"php{cls.php}-mysql >/dev/null 2>&1; systemctl reload php{cls.php}-fpm; true"
        )
        cls.establish(no_database, no_database)
        cls.establish(REMOVE_NGINX, RESTORE_NGINX)
        cls.addClassCleanup(cls.administer, remove_site("shop", cls.php))

    def test_connect_setup_create_database_and_https(self) -> None:
        names = ("shop.test", "www.shop.test")
        addresses = acme.server_addresses()
        self.point(names, addresses.ipv4, addresses.ipv6)
        page = self.page
        server = self.register()
        self.assert_no_overflow()
        page.get_by_role("region", name="Observed hosting").get_by_role(
            "link", name="Prepare web hosting"
        ).click()
        expect(
            page.get_by_role("navigation", name="Server sections").get_by_role(
                "link", name="Setup", exact=True
            )
        ).to_have_attribute("aria-current", "page")
        summary = page.get_by_role("region", name="Observed hosting")
        expect(summary.get_by_role("row", name=re.compile("^Nginx"))).to_contain_text(
            "Observed absent"
        )
        self.prepare_profile("Nginx profile")
        expect(page.locator("main")).to_contain_text("serves HTTP on port 80")
        self.apply_reviewed("Nginx profile plan")
        self.assertEqual(self.administer("systemctl is-active nginx"), "active\n")

        page.goto(f"{self.live_server_url}/servers/{server.pk}/")
        overview = page.get_by_role("region", name="Observed hosting")
        expect(overview).to_contain_text("Nginx and PHP-FPM packages were observed")
        overview.get_by_role("link", name="Open Sites").click()
        creation = self.create_site("shop", names)
        self.assert_no_overflow()

        self.navigate("Site sections", "Database")
        database = page.locator("#site-database-plans")
        expect(database).to_contain_text("No database plans for this site yet.")
        prepare = database.get_by_role("button", name="Prepare MariaDB database plan")
        self.submit(prepare, "/database/prepare/")
        expect(database).to_contain_text(
            "The PHP MariaDB driver is not installed and enabled for PHP-FPM", timeout=60_000
        )
        expect(database).to_contain_text("Prepare and apply the MariaDB profile first")
        site_database = page.url
        self.assertFalse(ApplyRun.objects.filter(action=Action.DATABASE_MARIADB).exists())
        page.get_by_role(
            "link", name="review the PHP database drivers and profiles in Setup"
        ).click()
        setup = page.url
        self.assertTrue(
            setup.endswith(f"/servers/{server.pk}/setup/?from=shop&origin=database#driver-plans")
        )
        expect(page.get_by_role("link", name="Return to site shop")).to_be_visible()
        expect(
            page.get_by_role("region", name="Observed hosting").get_by_role(
                "row", name=re.compile("^MariaDB")
            )
        ).to_contain_text("Observed absent")
        self.prepare_profile("MariaDB profile")
        self.apply_reviewed("MariaDB profile plan", timeout=600_000)
        page.goto(setup)
        drivers = page.locator("#driver-plans")
        self.submit(
            drivers.get_by_role("button", name="Prepare PHP MariaDB driver plan"),
            "/databases/prepare/",
        )
        self.open_review(drivers)
        self.apply_reviewed("PHP MariaDB driver plan")
        page.goto(setup)
        page.get_by_role("link", name="Return to site shop").click()
        expect(page).to_have_url(site_database)
        expect(
            page.get_by_role("navigation", name="Site sections").get_by_role(
                "link", name="Database", exact=True
            )
        ).to_have_attribute("aria-current", "page")
        self.submit(prepare, "/database/prepare/")
        expect(database).to_contain_text(
            "CREATE USER `sshop`@`localhost` IDENTIFIED VIA unix_socket", timeout=60_000
        )
        self.open_review(database)
        binding = self.apply_reviewed("MariaDB site database plan")
        self.assertEqual(
            self.administer(
                'mariadb --no-defaults -N -B -e "SELECT SCHEMA_NAME FROM '
                "information_schema.SCHEMATA WHERE SCHEMA_NAME = 'sshop'\""
            ),
            "sshop\n",
        )

        page.goto(site_database)
        self.navigate("Site sections", "HTTPS")
        installation = page.locator("#site-installation")
        for name in names:
            expect(installation).to_contain_text(name)
        self.enable_https("ops@example.com")
        page.reload()
        expect(installation).to_contain_text("Installation recorded as verified", timeout=30_000)
        for stage in progress.LABELS:
            expect(installation).to_contain_text(f"{stage}: Completed")
        recorded = CertificateInstallation.objects.get()
        self.assertEqual(
            recorded.status, CertificateInstallation.Status.SUCCEEDED, recorded.failure
        )
        self.assertEqual(recorded.names.splitlines(), list(names))
        self.assert_served_over_https("shop", names)
        self.assert_no_overflow()
        self.assert_activated_site_observed(server, "shop")

        self.navigate("Site sections", "Activity")
        activity = page.get_by_role("region", name="Activity for shop")
        expect(activity).to_contain_text("Apply: HTTP PHP site")
        expect(activity).to_contain_text("Apply: MariaDB site database")
        expect(activity).to_contain_text("Certificate installations")
        expect(activity).to_contain_text(f"Installation {recorded.pk}")
        for server_wide in ("Nginx profile", "MariaDB profile", "PHP MariaDB driver"):
            expect(activity).not_to_contain_text(server_wide)
        expect(page.locator("main").get_by_role("button")).to_have_count(0)
        expect(activity.get_by_role("link", name=f"Open apply run {binding.pk}")).to_be_visible()
        activity.get_by_role("link", name=f"Open apply run {creation.pk}").focus()
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Applied and verified", level=2)).to_be_visible()
        page.go_back()
        expect(activity).to_be_visible()
        self.assert_no_overflow()
        page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/")
        self.assert_no_overflow()


class PreparedServerJourneyTests(HostingJourneyTestCase):
    """A prepared server: create, wrong DNS, HTTPS without a database, another controller."""

    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.establish(SET_ASIDE, PUT_BACK)
        without_tls = (
            "rm -f /etc/nginx/conf.d/tls-default-reject.conf; nginx -t -q && "
            "systemctl reload nginx; true"
        )
        cls.establish(without_tls, without_tls)
        cls.addClassCleanup(cls.administer, remove_site("blog", cls.php))

    def fresh_controller(self, identifier: str) -> FreshController:
        directory = self.directory / "fresh-controller"
        directory.mkdir()
        config = directory / "config"
        config.write_text(self.ssh_entry("disposable-fresh", "SECOND_KEY"), encoding="utf-8")
        completed = subprocess.run(  # noqa: S603 - the test's own script
            [
                sys.executable,
                "-c",
                FRESH_CONTROLLER,
                str(directory / "db.sqlite3"),
                str(config),
                str(TEST_MANIFEST),
                identifier,
            ],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr[-3000:])
        return FreshController(**json.loads(completed.stdout.strip().splitlines()[-1]))

    def test_https_without_a_database_after_wrong_dns_and_another_controller(self) -> None:
        names = ("blog.test",)
        page = self.page
        server = self.register()
        page.get_by_role("region", name="Observed hosting").get_by_role(
            "link", name="Open Sites"
        ).click()
        self.create_site("blog", names)
        https = f"{self.live_server_url}/servers/{server.pk}/sites/blog/https/"

        addresses = acme.server_addresses()
        self.point(names, WRONG_IPV4, WRONG_IPV6)
        self.navigate("Site sections", "HTTPS")
        readiness = page.locator("#site-readiness")
        installation = page.locator("#site-installation")
        expect(readiness).to_contain_text("No readiness review for this site yet.")
        self.check_readiness()
        expect(readiness).to_contain_text(
            "Apply the site's challenge route plan first", timeout=60_000
        )

        page.reload()
        self.enable_https("ops@example.com")
        page.reload()
        expect(installation).to_contain_text("Stopped at certificate order", timeout=30_000)
        expect(installation).to_contain_text("Certificate order: Failed")
        expect(installation).to_contain_text("HTTPS activation: Not started")
        expect(installation).to_contain_text(f"blog.test resolves to {WRONG_IPV4}")
        expect(installation).to_contain_text("not this server's own addresses")
        expect(installation.get_by_role("link", name="HTTPS readiness")).to_have_attribute(
            "href", "#site-readiness"
        )
        stopped = CertificateInstallation.objects.get()
        self.assertEqual(stopped.status, CertificateInstallation.Status.FAILED)
        order = stopped.steps.get(position=2)
        self.assertIsNotNone(order.preparation)
        self.assertIsNone(order.run)
        self.assertFalse(ApplyRun.objects.filter(action=Action.TLS_ISSUANCE).exists())
        self.assertEqual(
            self.administer("test -e /etc/letsencrypt/live/blog && echo issued; true"), ""
        )
        self.check_readiness()
        expect(readiness).to_contain_text(WRONG_IPV4, timeout=60_000)
        expect(readiness).to_contain_text("blog.test")
        expect(readiness).to_contain_text("Expected destination")
        expect(readiness).to_contain_text(addresses.ipv4)
        expect(readiness).to_contain_text("not this server's own addresses")
        if not acme.IPV6_UNAVAILABLE:
            expect(readiness).to_contain_text(WRONG_IPV6)

        self.point(names, addresses.ipv4, addresses.ipv6)
        page.goto(https)
        self.check_readiness()
        expect(readiness).to_contain_text("Ready for review", timeout=60_000)
        self.enable_https("ops@example.com")
        page.reload()
        expect(installation).to_contain_text("Installation recorded as verified", timeout=30_000)
        expect(installation).to_contain_text("HTTPS activation: Completed")
        self.assertEqual(
            CertificateInstallation.objects.filter(
                status=CertificateInstallation.Status.SUCCEEDED
            ).count(),
            1,
        )
        self.assertEqual(ApplyRun.objects.filter(action=Action.TLS_ISSUANCE).count(), 1)
        self.assertFalse(ApplyRun.objects.filter(action__startswith="database_").exists())
        self.assert_served_over_https("blog", names)
        self.assert_activated_site_observed(server, "blog")
        page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/blog/activity/")
        activity = page.get_by_role("region", name="Activity for blog")
        expect(activity).to_contain_text("Installation stopped")
        expect(activity).to_contain_text("Apply: HTTP PHP site")
        page.reload()
        expect(activity).to_contain_text("Certificate installations")
        page.go_back()
        expect(page.get_by_role("region", name="Observed site")).to_be_visible()
        page.go_forward()
        expect(activity).to_contain_text("Certificate installations")

        self.client.force_login(self.user)
        first = {
            section: evidence(
                self.client.get(
                    f"/servers/{server.pk}/sites/blog/{section}/", secure=True
                ).content.decode()
            )
            for section in ("overview", "database", "https")
        }
        self.assertIn("blog.test", first["overview"])
        self.assertIn("/etc/letsencrypt/live/blog", first["https"], first["https"])
        fresh = self.fresh_controller("blog")
        self.assertEqual(fresh.discovery, "succeeded")
        for section, shown in first.items():
            self.assertEqual(evidence(fresh.html(section)), shown, section)
        self.assertIn("<h1>blog.test</h1>", fresh.html("overview"))
        self.assertIn(
            "No certificate installation for this site on this controller yet.",
            fresh.html("https"),
        )
        reconstructed = fresh.html("activity")
        self.assertIn(
            "No plan preparations or apply runs your account may view are recorded", reconstructed
        )
        self.assertNotIn("Certificate installations", reconstructed)
        self.assertEqual((fresh.runs, fresh.preparations, fresh.installations), (0, 0, 0))
