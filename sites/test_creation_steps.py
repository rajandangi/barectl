"""Create site's Step 1: a missing runtime or database engine is installed first
(docs/sites.md#step-1-a-missing-runtime-or-database-engine)."""

from typing import override
from unittest import mock

from django.test import SimpleTestCase

from operations.models import ChangeRun, RemoteOperation, Result, Verification
from operations.services import read_changes
from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.forms import HttpSiteForm, LaravelSiteForm, WordPressSiteForm
from sites.ui_testing import record_http_sites, record_step_run, record_wordpress_sites


class InstallFirstFormTests(SimpleTestCase):
    def test_a_catalog_runtime_is_offered_as_installs_first(self) -> None:
        for form_class in (HttpSiteForm, LaravelSiteForm, WordPressSiteForm):
            with self.subTest(form=form_class.__name__):
                data = {
                    "identifier": "shop",
                    "names": "shop.example.com",
                    "php_version": "php85",
                    "title": "Shop",
                    "admin_username": "shopadmin",
                    "admin_email": "admin@example.com",
                    "repository": "https://github.com/acme/shop.git",
                }
                form = form_class(
                    data, php_versions=("php84",), installable=(("php85", 120_000_000),)
                )
                self.assertTrue(form.is_valid(), form.errors)
                self.assertEqual(form.cleaned_data["php_version"], "php85")
                self.assertIn("PHP 8.5 (installs first, about 120 MB)", str(form["php_version"]))

    def test_a_runtime_outside_the_observation_and_catalog_is_refused(self) -> None:
        form = HttpSiteForm(
            {"identifier": "shop", "names": "shop.example.com", "php_version": "php86"},
            php_versions=("php84",),
        )
        self.assertFalse(form.is_valid())
        self.assertIn("php_version", form.errors)


class CreateStepPageTests(ControllerConfigTestCase):
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

    def wordpress(self, **overrides: str) -> dict[str, str]:
        values = {
            "names": "shop.example.com",
            "title": "Shop",
            "admin_username": "shopadmin",
            "admin_email": "admin@example.com",
            "php_version": "php84",
        }
        values.update(overrides)
        return values

    def test_wordpress_without_an_engine_queues_the_engine_install_first(self) -> None:
        record_wordpress_sites(self.server, engine="")
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.post(
                f"/servers/{self.server.pk}/sites/wordpress/prepare/", self.wordpress()
            )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(rows[0].preparation.kind_slug, "install_database_engine")
        self.assertEqual(rows[0].preparation.inputs, {"version": 1, "selection": "mariadb"})

    def test_the_engine_review_names_step_one_and_keeps_the_answers(self) -> None:
        record_wordpress_sites(self.server, engine="")
        self.client.post(f"/servers/{self.server.pk}/sites/wordpress/prepare/", self.wordpress())
        preparation = read_changes(self.server).rows[0].preparation
        response = self.client.get(f"/changes/{preparation.pk}/")
        self.assertContains(response, "Step 1: install MariaDB on this server")
        self.assertContains(response, "This is the first step for the WordPress site")
        response = self.client.get(f"/servers/{self.server.pk}/sites/?create={preparation.pk}")
        self.assertContains(response, "Your answers are kept.")
        self.assertContains(response, 'value="shop.example.com"')
        self.assertContains(response, 'value="Shop"')
        self.assertContains(response, 'value="shopadmin"')
        self.assertContains(response, 'value="admin@example.com"')

    def test_the_step_run_continues_into_the_same_site_review(self) -> None:
        record_wordpress_sites(self.server, engine="")
        self.client.post(f"/servers/{self.server.pk}/sites/wordpress/prepare/", self.wordpress())
        preparation = read_changes(self.server).rows[0].preparation
        run = record_step_run(preparation)
        response = self.client.get(f"/runs/{run.pk}/")
        self.assertContains(response, "Step 1 is complete.")
        self.assertContains(response, "Continue creating the WordPress site")
        self.assertContains(
            response,
            f'href="/servers/{self.server.pk}/sites/?create={preparation.pk}#wordpress-site-create"',
        )
        # The worker's refresh observes MariaDB; the create form still holds the answers.
        record_wordpress_sites(self.server)
        response = self.client.get(f"/servers/{self.server.pk}/sites/?create={preparation.pk}")
        self.assertContains(response, "Prepare WordPress site review")
        self.assertContains(response, 'value="shop.example.com"')
        self.assertContains(response, 'value="Shop"')
        self.assertContains(response, 'value="admin@example.com"')
        self.assertContains(response, '<option value="php84" selected>')
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/wordpress/prepare/", self.wordpress()
        )
        rows = read_changes(self.server).rows
        self.assertEqual(rows[0].preparation.kind_slug, "create_wordpress_site")
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")
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

    def test_a_finished_step_links_back_when_it_did_not_complete(self) -> None:
        record_wordpress_sites(self.server, engine="")
        self.client.post(f"/servers/{self.server.pk}/sites/wordpress/prepare/", self.wordpress())
        preparation = read_changes(self.server).rows[0].preparation
        run = record_step_run(preparation)
        ChangeRun.objects.filter(pk=run.pk).update(
            status=RemoteOperation.Status.FAILED,
            execution=Result.FAILED,
            verification=Verification.FAILED,
        )
        response = self.client.get(f"/runs/{run.pk}/")
        self.assertContains(response, "Step 1 did not complete.")
        self.assertContains(response, "Return to Create site")

    def test_a_missing_php_runtime_is_installed_first(self) -> None:
        record_http_sites(self.server)
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/http/prepare/",
            {"identifier": "shop", "names": "shop.example.com", "php_version": "php85"},
        )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(rows[0].preparation.kind_slug, "add_runtime")
        self.assertEqual(rows[0].preparation.inputs, {"version": 1, "selection": "php85"})
        response = self.client.get(f"/changes/{rows[0].preparation.pk}/")
        self.assertContains(response, "Step 1: install PHP 8.5 on this server")

    def test_laravel_without_an_engine_installs_the_engine_the_operator_chose(self) -> None:
        record_http_sites(self.server)
        page = self.client.get(f"/servers/{self.server.pk}/sites/")
        self.assertContains(page, "Step 1: install a database engine on this server")
        self.assertContains(page, "Step 1: install MariaDB")
        self.assertContains(page, "Step 1: install PostgreSQL")
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/laravel/prepare/",
            {
                "names": "shop.example.com",
                "repository": "https://github.com/acme/shop.git",
                "branch": "main",
                "php_version": "php84",
                "step": "engine:postgresql",
            },
        )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(rows[0].preparation.kind_slug, "install_database_engine")
        self.assertEqual(rows[0].preparation.inputs, {"version": 1, "selection": "postgresql"})
        page = self.client.get(f"/servers/{self.server.pk}/sites/?create={rows[0].preparation.pk}")
        self.assertContains(page, 'value="https://github.com/acme/shop.git"')
        self.assertContains(page, 'value="main"')

    def test_a_host_with_no_runtime_installs_the_engine_then_php(self) -> None:
        record_wordpress_sites(self.server, engine="", installed_php=False)
        response = self.client.get(f"/servers/{self.server.pk}/sites/")
        self.assertContains(response, "PHP 8.4 (installs first")
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/wordpress/prepare/", self.wordpress()
        )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(rows[0].preparation.kind_slug, "install_database_engine")
        # The engine applies and discovery observes it; PHP is still missing.
        RemoteOperation.objects.filter(pk=rows[0].preparation.pk).update(
            status=RemoteOperation.Status.SUCCEEDED
        )
        record_wordpress_sites(self.server, installed_php=False)
        step_one = rows[0].preparation.pk
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/wordpress/prepare/", self.wordpress()
        )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0].preparation.kind_slug, "add_runtime")
        self.assertEqual(rows[0].preparation.inputs, {"version": 1, "selection": "php84"})
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")
        # Its answers are the same ones the first step kept.
        page = self.client.get(f"/servers/{self.server.pk}/sites/?create={rows[0].preparation.pk}")
        self.assertContains(page, 'value="shop.example.com"')
        self.assertContains(page, 'value="Shop"')
        self.assertContains(page, 'id="wordpress-site-continuation"')
        self.assertNotEqual(rows[0].preparation.pk, step_one)

    def test_wordpress_refuses_postgresql_as_a_step(self) -> None:
        record_wordpress_sites(self.server, engine="")
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/wordpress/prepare/",
            {**self.wordpress(), "step": "engine:postgresql"},
            follow=True,
        )
        self.assertContains(
            response, "That database engine is not offered for the site you are creating."
        )
        self.assertEqual(read_changes(self.server).rows, [])

    def test_a_present_runtime_that_is_not_verified_is_not_offered_as_installs_first(
        self,
    ) -> None:
        record_http_sites(self.server, problem="Master failed")
        response = self.client.get(f"/servers/{self.server.pk}/sites/")
        self.assertNotContains(response, "PHP 8.4 (installs first")
        self.assertContains(response, "PHP 8.5 (installs first")

    def test_the_kept_answers_stay_in_the_session_that_queued_the_step(self) -> None:
        from django.test import Client

        record_wordpress_sites(self.server, engine="")
        self.client.post(f"/servers/{self.server.pk}/sites/wordpress/prepare/", self.wordpress())
        preparation = read_changes(self.server).rows[0].preparation
        run = record_step_run(preparation)
        other = Client()
        other.force_login(self.user)
        response = other.get(f"/runs/{run.pk}/")
        self.assertNotContains(response, "Step 1 is complete.")
        self.assertNotContains(response, "Continue creating the WordPress site")

    def test_postgresql_still_disables_the_wordpress_tile(self) -> None:
        record_wordpress_sites(self.server, engine="postgresql")
        response = self.client.get(f"/servers/{self.server.pk}/sites/")
        self.assertContains(response, "WordPress needs MariaDB. This server runs PostgreSQL.")
        self.assertNotContains(response, "Step 1: install MariaDB")
