"""The Create Laravel site tile, its form and its reviewed inputs (Phase B #382)."""

from typing import override
from unittest import mock

from django.test import SimpleTestCase

from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.forms import LaravelSiteForm
from sites.ui_testing import record_http_sites

FINGERPRINT = "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s"


class LaravelSiteFormTests(SimpleTestCase):
    def test_derives_the_identifier_from_the_primary_domain(self) -> None:
        form = LaravelSiteForm(
            {
                "names": "shop.example.com",
                "repository": "https://github.com/acme/shop.git",
                "branch": "main",
                "php_version": "php84",
            },
            php_versions=("php84",),
        )
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["identifier"], "shop")
        self.assertEqual(form.cleaned_data["branch"], "main")

    def test_an_ssh_repository_requires_the_pasted_fingerprint(self) -> None:
        form = LaravelSiteForm(
            {
                "names": "shop.example.com",
                "repository": "git@github.com:acme/shop.git",
                "branch": "main",
                "php_version": "php84",
            },
            php_versions=("php84",),
        )
        self.assertFalse(form.is_valid())
        self.assertIn("fingerprint", form.errors)

    def test_an_https_repository_refuses_a_stray_fingerprint(self) -> None:
        form = LaravelSiteForm(
            {
                "names": "shop.example.com",
                "repository": "https://github.com/acme/shop.git",
                "branch": "main",
                "php_version": "php84",
                "fingerprint": FINGERPRINT,
            },
            php_versions=("php84",),
        )
        self.assertFalse(form.is_valid())
        self.assertIn("fingerprint", form.errors)

    def test_refuses_credentials_in_a_url_and_git_options_as_a_branch(self) -> None:
        form = LaravelSiteForm(
            {
                "names": "shop.example.com",
                "repository": "https://user:token@github.com/acme/shop.git",
                "branch": "-u",
                "php_version": "php84",
            },
            php_versions=("php84",),
        )
        self.assertFalse(form.is_valid())
        self.assertIn("repository", form.errors)
        self.assertIn("branch", form.errors)


class LaravelSiteTileTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        record_http_sites(self.server, engine="mariadb")

    def test_the_tile_asks_domain_repository_and_branch_with_the_identifier_under_more(
        self,
    ) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/create/laravel/")
        self.assertContains(response, "Create Laravel site")
        self.assertContains(response, 'name="repository"')
        self.assertContains(response, 'name="branch"')
        self.assertContains(response, 'value="main"')
        self.assertContains(response, "More options")
        self.assertContains(response, "Prepare Laravel site review")

    def test_a_viewer_without_prepare_permission_still_reads_the_tile(self) -> None:
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.get(f"/servers/{self.server.pk}/sites/create/laravel/")
        self.assertRegex(
            response.content.decode(),
            r"<button[^>]*disabled[^>]*>Prepare Laravel site review",
        )
        self.assertNotContains(response, "Step 1: install MariaDB")
