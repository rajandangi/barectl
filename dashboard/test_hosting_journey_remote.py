"""The integrated hosting workflow in Chromium against a disposable server.

docs/dashboard-qualification.md records what these journeys qualify. Tagged ``ssh`` and
``native-browser``; they need the ACME and DNS fixtures ``run-tests.sh`` starts
(docs/ssh-connections.md#acme-and-dns-fixtures). Ground truth is read with ``docker exec``.
"""

import json
import re
import subprocess
import sys
from typing import override

from playwright.sync_api import expect

from bootstrap.models import Action, ApplyRun
from bootstrap.native_testing import REMOVE_MARIADB, REMOVE_NGINX, RESTORE_NGINX
from dashboard.testing import TEST_MANIFEST
from disposable import acme
from sites.native_testing import PUT_BACK, SET_ASIDE, remove_site
from tls import progress
from tls.models import CertificateInstallation

from .hosting_testing import FRESH_CONTROLLER, WRONG_IPV4, WRONG_IPV6, FreshController, evidence
from .hosting_testing import HostingJourneyTestCase as HostingJourneyTestCase


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
        self.navigate("Server sections", "Advanced")
        expect(
            page.get_by_role("navigation", name="Server sections").get_by_role(
                "link", name="Advanced", exact=True
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
            "link", name="review the PHP database drivers and profiles in Advanced"
        ).click()
        setup = page.url
        self.assertTrue(
            setup.endswith(f"/servers/{server.pk}/advanced/?from=shop&origin=database#driver-plans")
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
