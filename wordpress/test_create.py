"""The Create WordPress site tile, its form and its reviewed inputs (Phase B #380)."""

from typing import override
from unittest import mock

from django.test import SimpleTestCase

from bootstrap.standing import Standing
from operations import services
from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.forms import WordPressSiteForm
from sites.ui_testing import record_wordpress_sites


class WordPressSiteFormTests(SimpleTestCase):
    def test_derives_the_identifier_from_the_primary_domain(self) -> None:
        form = WordPressSiteForm(
            {
                "names": "shop.example.com",
                "title": "Shop",
                "admin_username": "shopadmin",
                "admin_email": "admin@example.com",
                "php_version": "php84",
            },
            php_versions=("php84",),
        )
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["identifier"], "shop")

    def test_refuses_an_unsupported_administrator_username(self) -> None:
        form = WordPressSiteForm(
            {
                "names": "shop.example.com",
                "title": "Shop",
                "admin_username": "shop admin!",
                "admin_email": "admin@example.com",
                "php_version": "php84",
            },
            php_versions=("php84",),
        )
        self.assertFalse(form.is_valid())
        self.assertIn("admin_username", form.errors)


class WordPressReviewTests(SimpleTestCase):
    def test_postgresql_refuses_the_review_with_the_reason(self) -> None:
        from databases import provision
        from operations.inputs import PreparationInputs
        from sites.change import SiteEvidence
        from wordpress import create

        evidence = create.WordPressEvidence(
            SiteEvidence(None, Standing.TARGET_STACK, None, None),
            provision.DatabaseEvidence("postgresql", "PostgreSQL", True, (), None, "", "", "", ""),
        )
        inputs = PreparationInputs(
            "php84",
            "shop",
            ("shop.example.com",),
            title="Shop",
            admin_username="shopadmin",
            admin_email="admin@example.com",
        )
        draft = create.review(evidence, inputs)
        self.assertFalse(draft.eligible)
        self.assertIn("WordPress needs MariaDB. This server runs PostgreSQL.", draft.refusals)


class WordPressSiteTileTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant(
            "view_server",
            "view_siteobservation",
            "view_changes",
            "change_site",
            "manage_secrets",
        )
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def test_the_tile_asks_for_the_wordpress_fields_without_ssh(self) -> None:
        record_wordpress_sites(self.server)
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/")
        self.assertContains(response, "Create WordPress site")
        self.assertContains(response, 'name="title"')
        self.assertContains(response, 'name="admin_username"')
        self.assertContains(response, 'name="admin_email"')
        self.assertContains(response, "Prepare WordPress site review")

    def test_a_missing_engine_is_offered_as_step_one(self) -> None:
        record_wordpress_sites(self.server, engine="")
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/")
        self.assertContains(response, "Step 1: install MariaDB on this server")
        self.assertContains(response, "Step 1: install MariaDB")
        self.assertNotContains(response, "Install a database engine from Server Settings first.")

    def test_postgresql_disables_the_tile_with_the_reason(self) -> None:
        record_wordpress_sites(self.server, engine="postgresql")
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/")
        self.assertContains(response, "WordPress needs MariaDB. This server runs PostgreSQL.")

    def test_preparing_the_tile_queues_the_reviewed_inputs(self) -> None:
        record_wordpress_sites(self.server)
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/wordpress/prepare/",
            {
                "names": "shop.example.com",
                "title": "Shop",
                "admin_username": "shopadmin",
                "admin_email": "admin@example.com",
                "php_version": "php84",
            },
        )
        self.assertEqual(response.status_code, 302)
        rows = services.read_changes(self.server).rows
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

    def test_a_viewer_without_prepare_permission_cannot_prepare_the_review(self) -> None:
        record_wordpress_sites(self.server)
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.get(f"/servers/{self.server.pk}/sites/")
        self.assertNotContains(response, "Prepare WordPress site review")
