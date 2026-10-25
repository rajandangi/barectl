"""Journey 3: create a site from one page, with Add runtime first when PHP is missing
(docs/dashboard-workflows.md, docs/sites.md#creating-a-site)."""

import re
from dataclasses import replace
from typing import override
from unittest import mock

from django.test import Client
from django.utils import timezone

from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt
from discovery.snapshot import current_snapshot, save_snapshot
from operations.models import ChangePreparation, RemoteOperation
from operations.services import read_changes
from servers.models import Server
from servers.testing import HTMX_FRAGMENT, ControllerConfigTestCase
from sites.ui_testing import record_http_sites, record_step_run

BANNED = (
    "master",
    "pool",
    "fpm",
    "haproxy",
    "admission",
    "caddy",
    "nix",
    "store path",
    "catalog",
    "socket",
    "opcache",
    "systemd",
    "unit",
    "invocation",
    "journal",
    "stage",
    "standing",
    "foundation",
    "evidence",
    "consent level",
    "review",
    "plan",
    "digest",
    "known_hosts",
)


class CreateSitePageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant(
            "view_server",
            "view_siteobservation",
            "view_changes",
            "change_site",
            "add_server",
        )
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        record_http_sites(self.server)

    def test_global_page_lists_only_ready_servers_and_preselects_the_only_one(self) -> None:
        Server.objects.create(name="Cold", ssh_alias="stage.example.net")
        response = self.client.get("/sites/create/")
        self.assertContains(response, "Which server?")
        self.assertContains(response, f'id="create-server-{self.server.pk}"')
        self.assertRegex(
            response.content.decode(),
            rf'id="create-server-{self.server.pk}"\s+value="{self.server.pk}"\s+checked',
        )
        self.assertNotContains(response, "Cold")

    def test_server_page_offers_the_three_platforms_and_php_versions(self) -> None:
        response = self.client.get(f"/servers/{self.server.pk}/sites/create/")
        self.assertContains(response, "Platform")
        self.assertContains(response, 'id="create-platform-php"')
        self.assertContains(response, 'id="create-platform-wordpress"')
        self.assertContains(response, 'id="create-platform-laravel"')
        self.assertRegex(
            response.content.decode(),
            r'id="create-platform-php"\s+value="php"\s+checked',
        )
        self.assertContains(response, "PHP 8.4")
        self.assertContains(response, "PHP 8.5")
        self.assertContains(response, "Installed first, adds about")
        self.assertContains(response, "Domain")
        self.assertContains(response, "Add another domain")
        self.assertContains(response, "More options")
        self.assertContains(response, "Short name")
        self.assertContains(response, "Node.js version")
        self.assertNotContains(response, "Serve over HTTP only")

    def test_create_page_avoids_native_terms(self) -> None:
        response = self.client.get(f"/servers/{self.server.pk}/sites/create/")
        text = re.sub(r"<[^>]+>", " ", response.content.decode()).lower()
        for word in BANNED:
            with self.subTest(word=word):
                self.assertNotRegex(text, rf"\b{re.escape(word)}\b")

    def test_opening_the_page_makes_no_ssh_connection(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            self.assertEqual(
                self.client.get(f"/servers/{self.server.pk}/sites/create/").status_code, 200
            )
            self.assertEqual(self.client.get("/sites/create/").status_code, 200)

    def test_an_installed_php_version_queues_the_site_review(self) -> None:
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/http/prepare/",
            {
                "platform": "php",
                "names": ["SHOP.example.com", "www.shop.example.com"],
                "php_version": "php84",
            },
        )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")
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

    def test_a_missing_php_version_is_step_one_and_keeps_the_answers(self) -> None:
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/http/prepare/",
            {
                "platform": "php",
                "names": ["shop.example.com", "www.shop.example.com"],
                "php_version": "php85",
            },
        )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        preparation = rows[0].preparation
        self.assertEqual(preparation.kind_slug, "add_runtime")
        self.assertEqual(preparation.inputs, {"version": 1, "selection": "php85"})
        self.assertRedirects(response, f"/changes/{preparation.pk}/")
        page = self.client.get(f"/changes/{preparation.pk}/")
        self.assertContains(page, "Step 1 of 2: add PHP 8.5 to this server")
        run = record_step_run(preparation)
        run_page = self.client.get(f"/runs/{run.pk}/")
        self.assertContains(run_page, "Continue to create the site")
        self.assertContains(
            run_page,
            f'action="/servers/{self.server.pk}/sites/create/continue/"',
        )
        page = self.client.get(f"/servers/{self.server.pk}/sites/create/?create={preparation.pk}")
        self.assertContains(page, "Your answers are kept.")
        self.assertContains(page, 'value="shop.example.com"')
        self.assertContains(page, 'value="www.shop.example.com"')
        self.assertRegex(
            page.content.decode(),
            r'id="create-php-php85"\s+value="php85"\s+checked',
        )
        # The same answers prepare the site once the runtime is installed.
        record_php85_installed(self.server)
        response = self.client.post(f"/servers/{self.server.pk}/sites/create/continue/")
        rows = read_changes(self.server).rows
        self.assertEqual(rows[0].preparation.kind_slug, "create_http_site")
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")

    def test_wordpress_and_laravel_tiles_lead_to_their_forms(self) -> None:
        for platform in ("wordpress", "laravel"):
            with self.subTest(platform=platform):
                response = self.client.post(
                    f"/servers/{self.server.pk}/sites/http/prepare/", {"platform": platform}
                )
                self.assertRedirects(
                    response, f"/servers/{self.server.pk}/sites/create/{platform}/"
                )
        self.assertEqual(read_changes(self.server).rows, [])

    def test_a_platform_outside_the_three_is_refused(self) -> None:
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/http/prepare/", {"platform": "rails"}
        )
        self.assertContains(response, "Choose PHP, WordPress or Laravel.", status_code=422)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_a_php_version_outside_the_catalog_is_refused(self) -> None:
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/http/prepare/",
            {"platform": "php", "names": "shop.example.com", "php_version": "php86"},
        )
        self.assertContains(
            response, "unavailable in the current recorded observation", status_code=422
        )
        self.assertEqual(read_changes(self.server).rows, [])

    def test_more_than_ten_domains_is_refused(self) -> None:
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/http/prepare/",
            {
                "platform": "php",
                "names": [f"site{index}.example.com" for index in range(11)],
                "php_version": "php84",
            },
        )
        self.assertContains(response, "Enter at most 10 names.", status_code=422)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_a_viewer_cannot_prepare_and_csrf_is_required(self) -> None:
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        self.assertEqual(self.client.get("/sites/create/").status_code, 403)
        self.assertEqual(
            self.client.post(f"/servers/{self.server.pk}/sites/http/prepare/", {}).status_code,
            403,
        )
        self.grant("change_site")
        csrf = Client(enforce_csrf_checks=True)
        csrf.force_login(self.user)
        self.assertEqual(
            csrf.post(f"/servers/{self.server.pk}/sites/http/prepare/", {}).status_code, 403
        )

    def test_a_changed_connection_keeps_the_answers(self) -> None:
        from django.db.models.signals import post_init

        def correct_connection(sender: object, instance: Server, **kwargs: object) -> None:
            del sender
            post_init.disconnect(correct_connection, sender=Server)
            Server.objects.filter(pk=self.server.pk).update(connection_revision=1)

        for headers in ({}, HTMX_FRAGMENT):
            with self.subTest(fragment=bool(headers)):
                Server.objects.filter(pk=self.server.pk).update(connection_revision=0)
                post_init.connect(correct_connection, sender=Server)
                try:
                    response = self.client.post(
                        f"/servers/{self.server.pk}/sites/http/prepare/",
                        {
                            "platform": "php",
                            "names": ["shop.example.com", "www.shop.example.com"],
                            "php_version": "php84",
                        },
                        headers=headers,
                    )
                finally:
                    post_init.disconnect(correct_connection, sender=Server)
                self.assertContains(response, "The server connection changed", status_code=409)
                self.assertContains(response, 'value="shop.example.com"', status_code=409)
                self.assertContains(response, 'value="www.shop.example.com"', status_code=409)
                self.assertRegex(
                    response.content.decode(),
                    r'id="create-php-php84"\s+value="php84"\s+checked',
                )
                self.assertEqual(read_changes(self.server).rows, [])

    def test_the_site_page_says_the_site_is_ready_and_where_to_point_dns(self) -> None:
        server = Server.objects.create(
            name="Addressed",
            ssh_alias="addressed.example.com",
            connection_mode="agent",
            address="203.0.113.10",
        )
        record_http_sites(server)
        response = self.client.get(f"/servers/{server.pk}/sites/alpha/")
        self.assertContains(
            response,
            'Your site is ready at <a href="http://alpha.example.com">http://alpha.example.com</a>.',
        )
        self.assertContains(response, "Point your domain's DNS at <code>203.0.113.10</code>")

    def test_a_successful_setup_run_offers_create_site(self) -> None:
        preparation = ChangePreparation.objects.create(
            server=self.server,
            ssh_alias=self.server.ssh_alias,
            kind_slug="host_foundation",
            inputs={"version": 1},
            status=RemoteOperation.Status.SUCCEEDED,
        )
        run = record_step_run(preparation)
        response = self.client.get(f"/runs/{run.pk}/")
        self.assertContains(response, f'href="/servers/{self.server.pk}/sites/create/"')
        self.assertContains(response, "Create site")


def record_php85_installed(server: Server) -> None:
    """A host where Step 1 installed PHP 8.5 and discovery verified its master."""
    record_http_sites(server)
    snapshot = current_snapshot(server)
    if snapshot is None:
        raise AssertionError("No snapshot.")
    runtimes = tuple(
        replace(row, path="/nix/store/observed-php85", master_state="active", problem="")
        if row.entry == "php85"
        else row
        for row in snapshot.collected.runtimes
    )
    collected = replace(snapshot.collected, runtimes=runtimes)
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    save_snapshot(attempt, collected, timezone.now())


class NoReadyServerTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant(
            "view_server", "view_siteobservation", "view_changes", "change_site", "add_server"
        )
        self.client.force_login(self.user)
        Server.objects.create(name="Cold", ssh_alias="stage.example.net")

    def test_global_page_with_no_ready_server_says_what_to_do_first(self) -> None:
        response = self.client.get("/sites/create/")
        self.assertContains(response, "No server is ready yet.")
        self.assertContains(response, "Add server")


class CreateSiteFormTests(ControllerConfigTestCase):
    def test_platform_must_be_one_of_the_three(self) -> None:
        from sites.forms import CreateSiteForm

        form = CreateSiteForm(
            {"platform": "rails", "names": "shop.example.com", "php_version": "php84"},
            php_versions=("php84",),
        )
        self.assertFalse(form.is_valid())
        self.assertIn("platform", form.errors)

    def test_the_short_name_is_derived_when_left_empty(self) -> None:
        from sites.forms import CreateSiteForm

        form = CreateSiteForm(
            {"platform": "php", "names": "www.shop.example.com", "php_version": "php84"},
            php_versions=("php84",),
        )
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["identifier"], "shop")
