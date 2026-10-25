import tempfile
from typing import override

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from playwright.sync_api import expect

from dashboard.browser_testing import BrowserTestCase
from servers.models import Server
from sites.ui_testing import (
    record_http_sites,
    record_laravel_releases,
    record_shaped_sites,
    record_site_settings,
    record_wordpress_sites,
)


@tag("browser")
class HttpSiteBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    def assert_phone_layout(self) -> None:
        """The journey's final page fits a 320-pixel screen with production assets."""
        self.page.set_viewport_size({"width": 320, "height": 800})
        # Fonts change the measurement; wait for them before checking for overflow.
        self.assert_theme_and_components_initialized()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )
        self.assertEqual(self.console_errors, [])

    def test_keyboard_creation_keeps_the_edited_identifier_and_validation_focus(self) -> None:
        server = Server.objects.get(name="Production")
        record_http_sites(server)
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/sites/")
        link = self.page.get_by_role("link", name="Create a site on Production", exact=True)
        link.focus()
        self.page.keyboard.press("Enter")
        form = self.page.locator("#http-site-create")
        names = form.get_by_label("DNS names", exact=True)
        names.fill("shop.example.com")
        identifier = form.get_by_label("Site identifier", exact=True)
        expect(identifier).to_have_value("shop")
        identifier.fill("myshop")
        names.fill("second.example.com")
        expect(identifier).to_have_value("myshop")
        identifier.fill("apply")
        php = form.get_by_label("PHP runtime", exact=True)
        php.select_option("php85")
        expect(
            form.get_by_role("button", name="Step 1: install PHP 8.5", exact=True)
        ).to_be_visible()
        php.select_option("php84")
        button = form.get_by_role("button", name="Prepare HTTP site review", exact=True)
        button.focus()
        self.page.keyboard.press("Enter")
        expect(
            self.page.get_by_text("apply is reserved; choose another identifier.")
        ).to_be_visible()
        expect(
            self.page.get_by_role("heading", name="Create HTTP site", exact=True)
        ).to_be_focused()
        expect(form.get_by_label("Site identifier", exact=True)).to_have_value("apply")
        self.assertEqual(len(self.console_errors), 1)
        self.assertIn("status of 422", self.console_errors.pop())
        self.page.set_viewport_size({"width": 375, "height": 812})
        self.assert_theme_and_components_initialized()
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )

    def test_operator_prepares_the_laravel_site_change_without_ssh(self) -> None:
        from unittest import mock

        from operations.services import read_changes

        server = Server.objects.get(name="Production")
        record_http_sites(server, engine="mariadb")
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/")
            form = self.page.locator("#laravel-site-create")
            form.get_by_label("Primary domain", exact=True).fill("shop.example.com")
            form.get_by_label("Repository", exact=True).fill("https://github.com/acme/shop.git")
            expect(form.get_by_label("Branch or tag", exact=True)).to_have_value("main")
            form.get_by_label("PHP runtime", exact=True).select_option("php84")
            button = form.get_by_role("button", name="Prepare Laravel site review", exact=True)
            button.focus()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role("heading", name="Create Laravel site: review", exact=True)
            ).to_be_visible()
        rows = read_changes(server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0].preparation.inputs,
            {
                "version": 1,
                "identifier": "shop",
                "names": ["shop.example.com"],
                "selection": "php84",
                "https": True,
                "repository": "https://github.com/acme/shop.git",
                "branch": "main",
            },
        )

    def test_operator_prepares_the_wordpress_site_change_in_five_fields(self) -> None:
        from unittest import mock

        from operations.services import read_changes

        server = Server.objects.get(name="Production")
        record_wordpress_sites(server)
        for codename in ("view_siteobservation", "view_changes", "change_site", "manage_secrets"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/")
            form = self.page.locator("#wordpress-site-create")
            form.get_by_label("Primary domain", exact=True).fill("shop.example.com")
            form.get_by_label("Site title", exact=True).fill("Shop")
            form.get_by_label("Administrator username", exact=True).fill("shopadmin")
            form.get_by_label("Administrator email", exact=True).fill("admin@example.com")
            form.get_by_label("PHP runtime", exact=True).select_option("php84")
            button = form.get_by_role("button", name="Prepare WordPress site review", exact=True)
            button.focus()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role("heading", name="Create WordPress site: review", exact=True)
            ).to_be_visible()
        rows = read_changes(server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0].preparation.inputs,
            {
                "version": 1,
                "identifier": "shop",
                "names": ["shop.example.com"],
                "selection": "php84",
                "https": True,
                "title": "Shop",
                "admin_username": "shopadmin",
                "admin_email": "admin@example.com",
            },
        )

    def test_operator_installs_a_missing_engine_first_and_keeps_the_create_answers(
        self,
    ) -> None:
        from unittest import mock

        from operations.services import read_changes
        from sites.ui_testing import record_step_run

        server = Server.objects.get(name="Production")
        record_wordpress_sites(server, engine="")
        for codename in ("view_siteobservation", "view_changes", "change_site", "manage_secrets"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        self.page.set_viewport_size({"width": 320, "height": 740})
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/")
            form = self.page.locator("#wordpress-site-create")
            expect(form.get_by_text("Step 1: install MariaDB on this server")).to_be_visible()
            form.get_by_label("Primary domain", exact=True).fill("shop.example.com")
            form.get_by_label("Site title", exact=True).fill("Shop")
            form.get_by_label("Administrator username", exact=True).fill("shopadmin")
            form.get_by_label("Administrator email", exact=True).fill("admin@example.com")
            form.get_by_label("PHP runtime", exact=True).select_option("php84")
            self.assertEqual(
                self.page.evaluate(
                    "document.documentElement.scrollWidth - document.documentElement.clientWidth"
                ),
                0,
            )
            step = form.get_by_role("button", name="Step 1: install MariaDB", exact=True)
            step.focus()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role("heading", name="Install database engine: review", exact=True)
            ).to_be_visible()
        rows = read_changes(server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].preparation.inputs, {"version": 1, "selection": "mariadb"})
        run = record_step_run(rows[0].preparation)
        # The worker's refresh observes MariaDB before the operator continues.
        record_wordpress_sites(server)
        self.page.goto(f"{self.live_server_url}/runs/{run.pk}/")
        expect(self.page.get_by_text("Step 1 is complete.")).to_be_visible()
        link = self.page.get_by_role("link", name="Continue creating the WordPress site")
        link.focus()
        self.page.keyboard.press("Enter")
        form = self.page.locator("#wordpress-site-create")
        expect(form.get_by_label("Primary domain", exact=True)).to_have_value("shop.example.com")
        expect(form.get_by_label("Site title", exact=True)).to_have_value("Shop")
        expect(form.get_by_label("Administrator email", exact=True)).to_have_value(
            "admin@example.com"
        )
        expect(form.get_by_label("PHP runtime", exact=True)).to_have_value("php84")
        self.assertEqual(
            self.page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            ),
            0,
        )
        button = form.get_by_role("button", name="Prepare WordPress site review", exact=True)
        button.focus()
        self.page.keyboard.press("Enter")
        expect(
            self.page.get_by_role("heading", name="Create WordPress site: review", exact=True)
        ).to_be_visible()
        rows = read_changes(server).rows
        self.assertEqual(rows[0].preparation.kind_slug, "create_wordpress_site")
        self.assertEqual(rows[0].preparation.inputs["title"], "Shop")
        self.assertEqual(rows[0].preparation.inputs["admin_email"], "admin@example.com")

    def test_operator_changes_domains_and_https_from_settings_with_a_keyboard(self) -> None:
        from unittest import mock

        from operations.services import read_changes

        server = Server.objects.get(name="Production")
        record_http_sites(server)
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/alpha/settings/")
            expect(
                self.page.get_by_role("heading", name="Domains and HTTPS", exact=True)
            ).to_be_visible()
            names = self.page.get_by_label("DNS names", exact=True)
            names.fill("alpha.example.com www.example.com")
            https = self.page.get_by_label("Serve over HTTPS", exact=True)
            expect(https).not_to_be_checked()
            https.check()
            expect(https).to_be_checked()
            button = self.page.get_by_role(
                "button", name="Prepare domains and HTTPS review", exact=True
            )
            button.focus()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role(
                    "heading", name="Change domains and HTTPS: review", exact=True
                )
            ).to_be_visible()
        rows = read_changes(server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0].preparation.inputs,
            {
                "version": 1,
                "identifier": "alpha",
                "names": ["alpha.example.com", "www.example.com"],
                "https": True,
            },
        )
        self.assert_theme_and_components_initialized()
        self.page.set_viewport_size({"width": 320, "height": 812})
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )
        self.assertEqual(self.console_errors, [])

    def test_overview_links_the_site_address_without_ssh(self) -> None:
        from unittest import mock

        server = Server.objects.get(name="Production")
        record_http_sites(server)
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/alpha/overview/")
            address = self.page.get_by_role("link", name="http://alpha.example.com")
            expect(address).to_be_visible()
            expect(address).to_have_attribute("href", "http://alpha.example.com")
        self.assert_theme_and_components_initialized()
        self.assertEqual(self.console_errors, [])

    def test_operator_resets_a_wordpress_password_through_the_confidential_channel(
        self,
    ) -> None:
        from unittest import mock

        from operations.services import read_changes

        server = Server.objects.get(name="Production")
        record_wordpress_sites(server)
        for codename in (
            "view_siteobservation",
            "view_changes",
            "change_site",
            "manage_secrets",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/shop/overview/")
            self.page.get_by_role("link", name="WordPress", exact=True).click()
            expect(
                self.page.get_by_role("heading", name="Reset administrator password", exact=True)
            ).to_be_visible()
            self.page.get_by_label("Administrator username", exact=True).fill("shopadmin")
            button = self.page.get_by_role("button", name="Review password reset", exact=True)
            button.focus()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role(
                    "heading", name="Reset WordPress administrator password: review", exact=True
                )
            ).to_be_visible()
        rows = read_changes(server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0].preparation.inputs,
            {"version": 1, "identifier": "shop", "admin_username": "shopadmin"},
        )
        self.assert_phone_layout()

    def test_attention_and_recognition_read_at_phone_width(self) -> None:
        server = Server.objects.get(name="Production")
        record_shaped_sites(server)
        self.user.user_permissions.add(Permission.objects.get(codename="view_siteobservation"))
        self.sign_in()
        self.page.set_viewport_size({"width": 375, "height": 812})
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/")
        attention = self.page.get_by_role("region", name="Needs attention")
        expect(attention.get_by_role("listitem")).to_have_count(5)
        self.assertEqual(
            self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
        )
        link = attention.get_by_role("link", name="Finish the runtime change", exact=True)
        link.focus()
        self.page.keyboard.press("Enter")
        expect(self.page).to_have_url(
            f"{self.live_server_url}/servers/{server.pk}/sites/delta/runtime/"
        )
        for tab, table in (("web", "Caddy site files"), ("php", "PHP-FPM site pools")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/stack/?tab={tab}")
            expect(self.page.get_by_role("table", name=table)).to_be_visible()
            self.assertEqual(
                self.page.evaluate("document.documentElement.scrollWidth - window.innerWidth"), 0
            )
        self.assert_theme_and_components_initialized()
        self.assertEqual(self.console_errors, [])

    def test_discovery_poll_leaves_the_creation_field_focused(self) -> None:
        from django.utils import timezone

        from discovery.fakes import record_attempt
        from discovery.models import DiscoveryAttempt

        server = Server.objects.get(name="Production")
        record_http_sites(server)
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        attempt = record_attempt(server, DiscoveryAttempt.Status.QUEUED)
        self.sign_in()
        self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/")
        field = self.page.locator("#http-site-create").get_by_label("DNS names", exact=True)
        field.focus()
        with self.page.expect_response(lambda response: "/discovery/?" in response.url):
            attempt.status = DiscoveryAttempt.Status.FAILED
            attempt.finished_at = timezone.now()
            attempt.save(update_fields=("status", "finished_at"))
        expect(self.page.locator("#discovery")).not_to_have_attribute("hx-trigger", "every 2s")
        expect(field).to_be_focused()

    def test_operator_prepares_the_real_registered_site_change_without_ssh(self) -> None:
        from unittest import mock

        from operations.services import read_changes

        server = Server.objects.get(name="Production")
        record_http_sites(server)
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/")
            form = self.page.locator("#http-site-create")
            form.get_by_label("DNS names", exact=True).fill("shop.example.com www.shop.example.com")
            form.get_by_label("PHP runtime", exact=True).select_option("php84")
            expect(form.get_by_label("Serve over HTTP only", exact=True)).not_to_be_checked()
            button = form.get_by_role("button", name="Prepare HTTP site review", exact=True)
            button.focus()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role("heading", name="Create PHP site: review", exact=True)
            ).to_be_visible()
        rows = read_changes(server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0].preparation.inputs,
            {
                "version": 1,
                "identifier": "shop",
                "names": ["shop.example.com", "www.shop.example.com"],
                "selection": "php84",
                "https": True,
            },
        )
        expect(
            self.page.get_by_role("heading", name="Preparation queued", exact=True)
        ).to_be_visible()

    def test_operator_reviews_a_deploy_with_its_migration_acknowledgement(self) -> None:
        from unittest import mock

        from laravel.change import MIGRATION_ACKNOWLEDGEMENT
        from operations.models import ChangePreparation
        from sites.ui_testing import record_deploy_review

        server = Server.objects.get(name="Production")
        record_laravel_releases(server)
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/alpha/deployments/")
            expect(
                self.page.get_by_role("table", name="Retained releases for alpha")
            ).to_be_visible()
            deploy = self.page.get_by_role("button", name="Deploy", exact=True)
            deploy.focus()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role("heading", name="Deploy Laravel site: review", level=1)
            ).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "deploy_laravel_site")
        self.assertEqual(preparation.inputs, {"version": 1, "identifier": "alpha"})
        record_deploy_review(preparation)
        self.page.reload()
        expect(
            self.page.get_by_role("heading", name="Deploy Laravel site: review", level=1)
        ).to_be_visible()
        expect(self.page.get_by_text("Run pending migrations", exact=True)).to_be_visible()
        acknowledgement = self.page.get_by_label(MIGRATION_ACKNOWLEDGEMENT)
        acknowledgement.focus()
        expect(acknowledgement).to_be_focused()
        expect(acknowledgement).to_have_attribute("required", "")
        self.page.keyboard.press("Space")
        expect(acknowledgement).to_be_checked()
        self.assert_phone_layout()

    def test_operator_rolls_back_to_a_release_chosen_from_the_list(self) -> None:
        from unittest import mock

        from laravel.configuration import ROLLBACK_ACKNOWLEDGEMENT
        from operations.models import ChangePreparation
        from sites.ui_testing import record_rollback_review

        server = Server.objects.get(name="Production")
        record_laravel_releases(server)
        target = f"{1:040x}-{'a' * 16}"
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/alpha/deployments/")
            release = self.page.get_by_label("Release")
            release.focus()
            release.select_option(target)
            rollback = self.page.get_by_role("button", name="Roll back", exact=True)
            rollback.focus()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role("heading", name="Roll back Laravel site: review", level=1)
            ).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "rollback_laravel_site")
        self.assertEqual(
            preparation.inputs,
            {"version": 1, "identifier": "alpha", "release": target},
        )
        record_rollback_review(preparation)
        self.page.reload()
        expect(
            self.page.get_by_role("heading", name="Roll back Laravel site: review", level=1)
        ).to_be_visible()
        expect(self.page.get_by_text(ROLLBACK_ACKNOWLEDGEMENT, exact=True)).to_be_visible()
        acknowledgement = self.page.get_by_label(ROLLBACK_ACKNOWLEDGEMENT)
        acknowledgement.focus()
        expect(acknowledgement).to_be_focused()
        expect(acknowledgement).to_have_attribute("required", "")
        self.page.keyboard.press("Space")
        expect(acknowledgement).to_be_checked()
        self.assert_phone_layout()

    def test_operator_adds_an_environment_key_with_a_keyboard(self) -> None:
        from unittest import mock

        from discovery.snapshot import ObservedSetting
        from operations.models import ChangePreparation

        server = Server.objects.get(name="Production")
        record_site_settings(
            server,
            application="laravel",
            settings=(
                ObservedSetting("alpha", "laravel", "APP_ENV", "a" * 64, "production"),
                ObservedSetting("alpha", "laravel", "MAIL_PASSWORD", "b" * 64),
            ),
        )
        for codename in (
            "view_siteobservation",
            "view_changes",
            "change_site",
            "manage_secrets",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/alpha/environment/")
            expect(self.page.get_by_text("Hidden, write-only")).to_be_visible()
            key = self.page.get_by_label("Key", exact=True)
            key.focus()
            self.page.keyboard.type("MAIL_FROM_ADDRESS")
            button = self.page.get_by_role("button", name="Review adding the key", exact=True)
            button.focus()
            expect(button).to_be_focused()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role("heading", name="Edit Laravel environment: review", level=1)
            ).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "edit_laravel_environment")
        self.assertEqual(
            preparation.inputs,
            {
                "version": 1,
                "identifier": "alpha",
                "changes": [{"key": "MAIL_FROM_ADDRESS", "action": "set"}],
            },
        )
        self.assert_phone_layout()

    def test_operator_adds_a_wordpress_constant_with_a_keyboard(self) -> None:
        from unittest import mock

        from discovery.snapshot import ObservedSetting
        from operations.models import ChangePreparation

        server = Server.objects.get(name="Production")
        record_site_settings(
            server,
            application="wordpress",
            settings=(ObservedSetting("alpha", "wordpress", "MAIL_HOST", "b" * 64),),
        )
        for codename in (
            "view_siteobservation",
            "view_changes",
            "change_site",
            "manage_secrets",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/alpha/wordpress/")
            expect(self.page.get_by_text("write-only")).to_be_visible()
            constant = self.page.get_by_label("Constant", exact=True)
            constant.focus()
            self.page.keyboard.type("ACME_MODE")
            button = self.page.get_by_role("button", name="Review adding the constant", exact=True)
            button.focus()
            expect(button).to_be_focused()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role("heading", name="Edit WordPress settings: review", level=1)
            ).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "edit_wordpress_settings")
        self.assertEqual(
            preparation.inputs,
            {
                "version": 1,
                "identifier": "alpha",
                "changes": [{"key": "ACME_MODE", "action": "set"}],
            },
        )
        self.assert_phone_layout()

    def test_operator_changes_php_settings_with_a_keyboard(self) -> None:
        from unittest import mock

        from operations.models import ChangePreparation
        from sites.bodies.pool import SitePool

        server = Server.objects.get(name="Production")
        record_http_sites(server)
        for codename in ("view_siteobservation", "view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/alpha/runtime/")
            self.page.get_by_label("Process manager", exact=True).select_option("static")
            self.page.get_by_label("Maximum child processes", exact=True).fill("8")
            self.page.get_by_label("Slow request log threshold (seconds)", exact=True).fill("10")
            self.page.get_by_label("Request time limit (seconds)", exact=True).fill("120")
            self.page.get_by_label("Memory limit (MB)", exact=True).fill("256")
            self.page.get_by_label("Maximum upload size (MB)", exact=True).fill("64")
            self.page.get_by_label("Maximum post size (MB)", exact=True).fill("64")
            button = self.page.get_by_role("button", name="Review PHP settings", exact=True)
            button.focus()
            expect(button).to_be_focused()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role("heading", name="Change site PHP settings: review", level=1)
            ).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "set_site_pool")
        self.assertEqual(
            preparation.inputs,
            {
                "version": 1,
                "identifier": "alpha",
                "pool": SitePool(
                    process_manager="static",
                    max_children=8,
                    slowlog_timeout=10,
                    terminate_timeout=120,
                    memory_limit=256,
                    upload_max_filesize=64,
                    post_max_size=64,
                ).document(),
            },
        )
        self.assert_phone_layout()

    def test_operator_installs_a_database_engine_from_server_settings(self) -> None:
        from unittest import mock

        from operations.models import ChangePreparation

        server = Server.objects.get(name="Production")
        record_http_sites(server, engine="")
        for codename in ("view_changes", "change_site"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/settings/")
            expect(self.page.get_by_text("No database engine is installed.")).to_be_visible()
            button = self.page.get_by_role("button", name="Install MariaDB", exact=True)
            button.focus()
            expect(button).to_be_focused()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role("heading", name="Install database engine: review", level=1)
            ).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "install_database_engine")
        self.assertEqual(preparation.inputs, {"version": 1, "selection": "mariadb"})
        self.assert_phone_layout()

    def test_operator_prepares_a_removal_and_types_the_domain_to_confirm(self) -> None:
        from unittest import mock

        from operations.models import ChangePreparation
        from sites.ui_testing import record_removal_review

        server = Server.objects.get(name="Production")
        record_http_sites(server)
        for codename in (
            "view_siteobservation",
            "view_changes",
            "change_site",
            "change_destructive",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/alpha/settings/")
            expect(self.page.get_by_text("No backup exists", exact=True)).to_be_visible()
            button = self.page.get_by_role("button", name="Prepare removal review", exact=True)
            button.focus()
            expect(button).to_be_focused()
            self.page.keyboard.press("Enter")
            expect(
                self.page.get_by_role("heading", name="Remove site: review", level=1)
            ).to_be_visible()
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, "remove_site")
        self.assertEqual(
            preparation.inputs,
            {"version": 1, "identifier": "alpha", "primary": "alpha.example.com"},
        )
        record_removal_review(preparation)
        self.page.reload()
        expect(
            self.page.get_by_role("heading", name="Remove site: review", level=1)
        ).to_be_visible()
        label = "Type alpha.example.com to confirm this removal."
        expect(self.page.get_by_text(label, exact=True)).to_be_visible()
        confirmation = self.page.get_by_label(label, exact=True)
        confirmation.focus()
        expect(confirmation).to_be_focused()
        expect(confirmation).to_have_attribute("required", "")
        self.page.keyboard.type("alpha.example.com")
        expect(confirmation).to_have_value("alpha.example.com")
        expect(confirmation).to_be_focused()
        self.assert_phone_layout()

    def test_operator_reads_the_https_and_certificate_states_at_phone_width(self) -> None:
        from unittest import mock

        from discovery.snapshot import SiteCertificate

        server = Server.objects.get(name="Production")
        record_site_settings(
            server,
            certificate=SiteCertificate("issued", "CN=Pebble", 1_800_000_000),
            https=True,
        )
        self.user.user_permissions.add(Permission.objects.get(codename="view_siteobservation"))
        self.sign_in()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/alpha/overview/")
            expect(self.page.get_by_role("heading", name="Observed site", level=2)).to_be_visible()
            expect(self.page.get_by_text("Certificate", exact=True)).to_be_visible()
            expect(self.page.get_by_text("over HTTPS")).to_be_visible()
            expect(
                self.page.get_by_text(
                    "Issued by CN=Pebble, expires 2027-01-15 08:00 UTC", exact=True
                )
            ).to_be_visible()
            self.assert_phone_layout()
            record_site_settings(server, certificate=SiteCertificate("http"), https=False)
            self.page.reload()
            expect(self.page.get_by_text("over HTTP only")).to_be_visible()
            expect(self.page.get_by_text("Not used (HTTP only)", exact=True)).to_be_visible()
        self.assert_phone_layout()
