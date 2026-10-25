"""The Environment and WordPress settings pages and their permission gate (Phase B #383)."""

from typing import override
from unittest import mock

from discovery.snapshot import ObservedSetting
from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.ui_testing import record_site_settings

DIGEST = "a" * 64


class SettingsPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def laravel(self) -> None:
        record_site_settings(
            self.server,
            application="laravel",
            settings=(
                ObservedSetting("alpha", "laravel", "APP_URL", DIGEST, "https://alpha.example.com"),
                ObservedSetting("alpha", "laravel", "MAIL_PASSWORD", "b" * 64),
            ),
        )

    def wordpress(self) -> None:
        record_site_settings(
            self.server,
            application="wordpress",
            settings=(ObservedSetting("alpha", "wordpress", "MAIL_HOST", "c" * 64),),
        )

    def test_the_environment_page_shows_non_secret_values_and_hides_secrets(self) -> None:
        self.laravel()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/environment/")
        self.assertContains(response, "Environment")
        self.assertContains(response, "APP_URL")
        self.assertContains(response, "https://alpha.example.com")
        self.assertContains(response, "MAIL_PASSWORD")
        self.assertContains(response, "Hidden, write-only")
        self.assertContains(response, "manage-secrets permission")

    def test_the_wordpress_page_lists_extra_constants_without_values(self) -> None:
        self.wordpress()
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/wordpress/")
        self.assertContains(response, "WordPress settings")
        self.assertContains(response, "MAIL_HOST")
        self.assertContains(response, "write-only")

    def test_the_environment_review_needs_manage_secrets(self) -> None:
        self.laravel()
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/environment/prepare/",
            {"key": "APP_URL", "action": "set"},
        )
        self.assertEqual(response.status_code, 403)

    def test_the_wordpress_settings_review_needs_manage_secrets(self) -> None:
        self.wordpress()
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/wordpress/settings/prepare/",
            {"key": "MAIL_HOST", "action": "set"},
        )
        self.assertEqual(response.status_code, 403)

    def test_a_permitted_environment_review_keeps_values_out_of_the_inputs(self) -> None:
        from operations.services import read_changes

        self.grant("manage_secrets")
        self.laravel()
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/environment/prepare/",
            {"key": "APP_URL", "action": "set", "value": "should not persist"},
        )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0].preparation.inputs,
            {
                "version": 1,
                "identifier": "alpha",
                "changes": [{"key": "APP_URL", "action": "set"}],
            },
        )
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")

    def test_a_non_target_site_has_no_environment_page(self) -> None:
        self.wordpress()
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/environment/")
        self.assertEqual(response.status_code, 404)

    def test_a_viewer_reads_the_certificate_releases_and_settings_keys(self) -> None:
        from discovery.snapshot import SiteCertificate

        from .ui_testing import record_laravel_releases

        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        record_site_settings(
            self.server,
            application="laravel",
            certificate=SiteCertificate("issued", "CN=Pebble", 1_800_000_000),
            settings=(ObservedSetting("alpha", "laravel", "APP_ENV", DIGEST, "production"),),
        )
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            logs = self.client.get(f"/servers/{self.server.pk}/sites/alpha/logs/")
            environment = self.client.get(f"/servers/{self.server.pk}/sites/alpha/environment/")
        self.assertContains(logs, "Issued by CN=Pebble")
        self.assertContains(environment, "APP_ENV")
        self.assertContains(environment, "production")
        record_laravel_releases(self.server)
        deployments = self.client.get(f"/servers/{self.server.pk}/sites/alpha/deployments/")
        self.assertContains(deployments, f"{0:040x}")
