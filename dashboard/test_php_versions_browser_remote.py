"""Approved PHP source and branch selection through production Chromium forms.

Only the public qualification gate is opened by this fixture. Source authentication,
APT acquisition, worker SSH execution and native runtime verification remain real.
"""

import re
import shlex
from typing import ClassVar, override
from unittest.mock import patch
from urllib.parse import parse_qs

from django.contrib.staticfiles.handlers import StaticFilesHandler
from django.test import tag
from playwright.sync_api import expect

from bootstrap import php_supply, releases
from bootstrap.models import Action, ApplyRun, ConfigurationPlan, Execution
from bootstrap.native_testing import REMOVE_MARIADB
from bootstrap.php_source_testing import trust_fixture
from dashboard.testing import TEST_MANIFEST
from databases.models import RunDatabaseBinding
from discovery.models import SiteObservation
from discovery.native_testing import reconstruct
from disposable import acme
from sites import native as site_native
from sites.models import RunSite
from tls.models import CertificateInstallation

from .browser_testing import serve_development_assets
from .hosting_testing import HostingJourneyTestCase


@tag("ssh", "native-browser")
class PhpSourceBrowserJourneyTests(HostingJourneyTestCase):
    def assert_asset_delivery(self) -> None:
        self.assertFalse(
            [request.url for request in self.requests if "@vite/client" in request.url]
        )

    @override
    def assert_no_overflow(self) -> None:
        page = self.page
        page.set_viewport_size({"width": 320, "height": 740})
        overflow = page.evaluate(
            "document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        if overflow:
            outside = page.evaluate("""() => [...document.querySelectorAll('main *')]
                .filter(element => element.getBoundingClientRect().right > innerWidth)
                .slice(0, 8).map(element => ({
                    tag: element.tagName, id: element.id, classes: element.className,
                    right: element.getBoundingClientRect().right,
                    text: element.textContent.trim().slice(0, 80)
                }))""")
            self.fail(f"{page.url}: {overflow}px horizontal overflow: {outside}")
        page.set_viewport_size({"width": 1280, "height": 900})

    @override
    def setUp(self) -> None:
        super().setUp()
        self.enterContext(patch("bootstrap.php_supply.qualified", return_value=True))
        trust_fixture(self, self.administer)
        self.administer(
            "set -e; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
            "--no-install-recommends gpg >/dev/null; "
            "p=$(dpkg-query -W -f='${Package} ${db:Status-Abbrev}\\n' 'php*' 2>/dev/null "
            "| awk '$2 != \"un\" {print $1}'); "
            'if [ -n "$p" ]; then DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq $p '
            ">/dev/null; fi; "
            f"rm -f {php_supply.SOURCE_FILE} {php_supply.KEY_FILE} "
            f"{php_supply.PREFERENCE_FILE}; "
            "rm -f /etc/nginx/sites-enabled/private /etc/nginx/sites-available/private; "
            "nginx -t -q; systemctl reload nginx"
        )
        self.administer(REMOVE_MARIADB)
        release = releases.RELEASES[self.administer(". /etc/os-release; echo $VERSION_ID").strip()]
        self.administer(
            f"pg_dropcluster --stop {release.postgresql.major} archive; "
            f"pg_dropcluster --stop {release.postgresql.major} reports"
        )

    def package_state(self) -> str:
        return self.administer(
            "sha256sum /var/lib/dpkg/status; "
            "find /var/lib/apt/lists -maxdepth 1 -type f -exec sha256sum {} + | sort"
        )

    def prepare_selected(self, action: Action, branch: str = "") -> ConfigurationPlan:
        page = self.page
        page.goto(f"{self.live_server_url}/servers/{self.server.pk}/setup/")
        plans = page.locator("#plans")
        radio = plans.get_by_role("radio", name=re.compile(f"^{re.escape(action.label)}"))
        radio.focus()
        page.keyboard.press("Space")
        expect(radio).to_be_checked()
        page.keyboard.press("Tab")
        selection = plans.get_by_label("PHP branch (PHP profile only)", exact=True)
        expect(selection).to_be_focused()
        selection.select_option(branch)
        expect(selection).to_have_value(branch)
        page.keyboard.press("Tab")
        supply = plans.get_by_label("PHP supply (PHP profile only)", exact=True)
        expect(supply).to_be_focused()
        supply.select_option("sury" if branch else "ubuntu")
        expect(supply).to_have_value("sury" if branch else "ubuntu")
        page.keyboard.press("Tab")
        button = plans.get_by_role("button", name="Prepare plan", exact=True)
        expect(button).to_be_focused()
        expect(button).to_have_class("usa-button")
        before = self.package_state()
        endpoint = f"/servers/{self.server.pk}/plans/prepare/"
        with page.expect_response(lambda response: response.url.endswith(endpoint)) as submitted:
            page.keyboard.press("Enter")
        response = submitted.value
        self.assertEqual(response.status, 200)
        self.assertEqual(response.request.headers["hx-request-type"], "partial")
        values = parse_qs(response.request.post_data or "", keep_blank_values=True)
        self.assertEqual(values["action"], [action.value])
        self.assertEqual(values["php_version"], [branch])
        self.assertEqual(values["php_supply"], ["sury" if branch else "ubuntu"])
        self.drain_worker()
        plan = ConfigurationPlan.objects.latest("pk")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        self.assertEqual(self.package_state(), before)
        expect(plans).to_contain_text(
            "Already satisfied" if plan.no_changes else "Ready for review", timeout=60_000
        )
        self.assert_theme_and_components_initialized()
        link = plans.get_by_role("link", name=re.compile("Open this plan"))
        link.focus()
        page.keyboard.press("Enter")
        expect(page).to_have_url(f"{self.live_server_url}/plans/{plan.pk}/")
        expect(page.get_by_role("heading", name=f"{action.label} plan", level=1)).to_be_visible()
        return plan

    def assert_site_runtime(self, identifier: str, branch: str) -> None:
        probe = f"/var/www/{identifier}/public/version.php"
        code = '<?php echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION,"|",posix_geteuid();'
        self.administer(f"printf %s {shlex.quote(code)} >{probe}")
        self.addCleanup(self.administer, f"rm -f {probe}")
        uid = self.administer(f"id -u s{identifier}").strip()
        self.assertEqual(
            self.administer(
                f"{site_native.http_client(branch)}; k 127.0.0.1 {identifier}.test /version.php"
            ),
            f"{branch}|{uid}",
        )

    def prepare_database(self) -> ApplyRun:
        page = self.page
        page.goto(f"{self.live_server_url}/servers/{self.server.pk}/sites/shop/database/")
        database = page.locator("#site-database-plans")
        self.submit(
            database.get_by_role("button", name="Prepare MariaDB database plan"),
            "/database/prepare/",
        )
        expect(database).to_contain_text("The PHP MariaDB driver is not installed", timeout=60_000)
        page.get_by_role(
            "link", name="review the PHP database drivers and profiles in Setup"
        ).click()
        setup = page.url
        drivers = page.locator("#driver-plans")
        self.submit(
            drivers.get_by_role("button", name="Prepare PHP MariaDB driver plan"),
            "/databases/prepare/",
        )
        self.open_review(drivers)
        driver = self.apply_reviewed("PHP MariaDB driver plan")
        self.assertEqual((driver.php_version, driver.php_supply), ("8.3", "sury"))
        self.assertEqual(
            self.administer("php8.4 -r 'echo (int)extension_loaded(\"pdo_mysql\");'"), "0"
        )
        page.goto(setup)
        page.get_by_role("link", name="Return to site shop").click()
        self.submit(
            database.get_by_role("button", name="Prepare MariaDB database plan"),
            "/database/prepare/",
        )
        self.open_review(database)
        applied = self.apply_reviewed("MariaDB site database plan")
        audit = RunDatabaseBinding.objects.get(run=applied)
        self.assertEqual(
            (audit.php_version, audit.php_supply, audit.site_revision), ("8.3", "sury", 4)
        )
        self.assertEqual(
            self.administer(
                "runuser -u sshop -- mariadb --no-defaults -N -B sshop -e 'SELECT CURRENT_USER()'"
            ),
            "sshop@localhost\n",
        )
        return applied

    def finish_and_reconstruct(self) -> None:
        page = self.page
        source = self.administer("cat /etc/nginx/sites-available/blog.conf")
        self.administer("rm /etc/php/8.4/fpm/pool.d/blog.conf; systemctl reload php8.4-fpm")
        self.administer(
            "timeout 20 sh -c 'while [ -e /run/php/sblog-php8.4.sock ] "
            '|| [ -L /run/php/sblog-php8.4.sock ] || [ -n "$(ss -Hlx '
            "src /run/php/sblog-php8.4.sock)\" ]; do sleep 0.1; done' && "
            "systemctl is-active --quiet php8.4-fpm"
        )
        page.goto(f"{self.live_server_url}/servers/{self.server.pk}/")
        self.submit(
            page.get_by_role("button", name="Refresh observations"),
            "/verify/?section=overview",
        )
        type(self).php = "8.4"
        finish = self.create_site("blog", ("blog.test",))
        self.assertIn("Finish", finish.intent)
        self.assertEqual(self.administer("cat /etc/nginx/sites-available/blog.conf"), source)
        self.assertEqual((finish.site.php_version, finish.site.convention_revision), ("8.4", 4))
        self.assert_site_runtime("blog", "8.4")
        config = self.directory / "second-config"
        config.write_text(self.ssh_entry("disposable", "SECOND_KEY"), encoding="utf-8")
        fresh = reconstruct(self.directory / "fresh-controller", config, TEST_MANIFEST)
        self.assertEqual(
            (fresh["status"], fresh["runs"], fresh["preparations"]), ("succeeded", 0, 0)
        )
        sites = fresh["sites"]
        if not isinstance(sites, list):
            raise AssertionError("Fresh controller did not return site observations.")
        observed = {site["identifier"]: site for site in sites if isinstance(site, dict)}
        self.assertEqual(
            (observed["shop"]["php_version"], observed["blog"]["php_version"]),
            ("8.3", "8.4"),
        )
        for identifier in ("shop", "blog"):
            self.assertEqual(observed[identifier]["state"], "managed")
            self.assertEqual(observed[identifier]["convention_revision"], 4)
        self.assertEqual(observed["shop"]["stage"], "redirect")
        self.assertEqual(observed["blog"]["stage"], "http")
        binding = observed["shop"]["database"]
        if not isinstance(binding, dict):
            raise AssertionError("Fresh controller did not return the native database binding.")
        self.assertEqual(binding["outcome"], "inaccessible", binding)
        self.assertFalse(binding["conforms"])
        self.assertEqual((binding["principal"], binding["database"]), ("", ""))
        self.assertIn("ordinary discovery never escalates", binding["warning"])
        self.assertEqual(fresh["page_status"], 200)
        self.assertIn("shop.test", str(fresh["page"]))
        self.assertIn("blog.test", str(fresh["page"]))

    def test_source_two_branches_bindings_https_finish_and_fresh_discovery(self) -> None:
        addresses = acme.server_addresses()
        self.point(("shop.test", "blog.test"), addresses.ipv4, addresses.ipv6)
        self.server = self.register()
        self.assert_asset_delivery()
        self.navigate("Server sections", "Setup")
        self.assert_theme_and_components_initialized()
        self.assert_no_overflow()

        before = self.package_state()
        source = self.prepare_selected(Action.PHP_SOURCE)
        main = self.page.locator("main")
        expect(main).to_contain_text("without refreshing metadata or installing PHP")
        for path in (php_supply.KEY_FILE, php_supply.SOURCE_FILE, php_supply.PREFERENCE_FILE):
            expect(main).to_contain_text(path)
        published = self.apply_reviewed(f"{Action.PHP_SOURCE.label} plan")
        self.assertEqual(published.execution, Execution.SUCCEEDED)
        self.assertEqual(published.plan_id, source.pk)
        self.assertEqual(self.package_state(), before)
        release = releases.RELEASES[source.release]
        self.assertEqual(
            self.administer(f"cat {php_supply.SOURCE_FILE}"),
            php_supply.source_content(release, source.architecture),
        )
        self.assertEqual(
            self.administer(f"cat {php_supply.PREFERENCE_FILE}"),
            php_supply.preference_content(release),
        )
        self.assertEqual(
            self.administer(f"sha256sum {php_supply.KEY_FILE}").split()[0],
            php_supply.KEY_SHA256,
        )

        refreshed = self.prepare_selected(Action.METADATA_REFRESH)
        refresh_run = self.apply_reviewed(f"{Action.METADATA_REFRESH.label} plan")
        self.assertEqual(refresh_run.plan_id, refreshed.pk)
        self.assertNotEqual(self.package_state(), before)
        self.assertEqual(
            self.administer(
                "dpkg-query -W -f='${db:Status-Abbrev}' 'php*-fpm' 2>/dev/null || true"
            ).strip(),
            "",
        )

        installed: list[ApplyRun] = []
        for branch in ("8.3", "8.4"):
            plan = self.prepare_selected(Action.PHP, branch)
            self.assertEqual((plan.php_version, plan.php_supply), (branch, "sury"))
            self.assertEqual(
                (plan.preparation.php_version, plan.preparation.php_supply), (branch, "sury")
            )
            expect(self.page.locator("main")).to_contain_text(
                f"Install PHP {branch} FPM and CLI from the approved unified PHP source."
            )
            roots = set(plan.roots.values_list("name", flat=True))
            self.assertLessEqual({f"php{branch}-fpm", f"php{branch}-cli"}, roots)
            run = self.apply_reviewed(f"{Action.PHP.label} plan")
            self.assertEqual((run.php_version, run.php_supply), (branch, "sury"))
            self.assertEqual(run.execution, Execution.SUCCEEDED)
            expect(self.page.locator("#apply-audit")).to_contain_text(plan.intent)
            self.assertIn(f"php{branch}-fpm", run.reviewed_changes)
            self.assertEqual(
                self.administer(
                    f"php{branch} -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;'"
                ),
                branch,
            )
            self.assertEqual(
                self.administer(f"systemctl is-active php{branch}-fpm.service"), "active\n"
            )
            installed.append(run)

        for identifier, branch in (("shop", "8.3"), ("blog", "8.4")):
            type(self).php = branch
            self.page.goto(f"{self.live_server_url}/servers/{self.server.pk}/setup/")
            site = self.create_site(identifier, (f"{identifier}.test",))
            retained = RunSite.objects.get(run=site)
            self.assertEqual((retained.php_version, retained.convention_revision), (branch, 4))
            self.assertEqual(
                SiteObservation.objects.filter(identifier=identifier).latest("pk").php_version,
                branch,
            )
            self.assert_site_runtime(identifier, branch)
        self.assert_no_overflow()
        self.prepare_selected(Action.MARIADB)
        self.apply_reviewed(f"{Action.MARIADB.label} plan")
        binding = self.prepare_database()
        type(self).php = "8.3"
        self.page.goto(f"{self.live_server_url}/servers/{self.server.pk}/sites/shop/https/")
        self.enable_https("ops@example.com")
        self.page.reload()
        expect(self.page.locator("#site-installation")).to_contain_text(
            "Installation recorded as verified", timeout=30_000
        )
        installation = CertificateInstallation.objects.get()
        self.assertEqual(installation.status, CertificateInstallation.Status.SUCCEEDED)
        self.assert_served_over_https("shop", ("shop.test",))
        self.page.goto(f"{self.live_server_url}/servers/{self.server.pk}/sites/shop/activity/")
        activity = self.page.get_by_role("region", name="Activity for shop")
        expect(activity).to_contain_text("Certificate installations")
        expect(activity).not_to_contain_text("PHP MariaDB driver")
        expect(activity.get_by_role("link", name=f"Open apply run {binding.pk}")).to_be_visible()
        self.finish_and_reconstruct()
        for run in installed:
            self.page.goto(f"{self.live_server_url}/applies/{run.pk}/")
            expect(self.page.locator("#apply-audit")).to_contain_text(run.intent)
            run.refresh_from_db()
            self.assertEqual(run.php_supply, "sury")
        self.assertEqual(self.console_errors, [])


@tag("ssh", "native-browser")
class DevelopmentPhpSourceBrowserJourneyTests(PhpSourceBrowserJourneyTests):
    static_handler = StaticFilesHandler
    vite_origin: ClassVar[str]

    @classmethod
    @override
    def serve_assets(cls) -> None:
        serve_development_assets(cls)

    @override
    def assert_asset_delivery(self) -> None:
        self.assertTrue([request.url for request in self.requests if "@vite/client" in request.url])
        self.assertFalse(
            [request.url for request in self.requests if "/static/dist/" in request.url]
        )
