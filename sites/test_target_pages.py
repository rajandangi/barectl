from typing import override
from unittest import mock

from django.test import SimpleTestCase

from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.forms import HttpSiteForm
from sites.ui_testing import record_http_sites, record_site_settings


class HttpSiteFormTests(SimpleTestCase):
    def test_accepts_long_dns_names(self) -> None:
        form = HttpSiteForm(
            {"identifier": "example", "names": "a" * 60 + ".example.com", "php_version": "php84"},
            php_versions=("php84",),
        )
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["names"], ("a" * 60 + ".example.com",))


class HttpSitePageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        record_http_sites(self.server)

    def test_runtime_page_uses_the_observed_master_without_ssh(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/logs/")
        self.assertContains(response, "Diagnostic master state")
        self.assertContains(response, "Verified in this observation")
        # Each site has its own master, so another runtime's master failure is not this
        # site's problem.
        self.assertNotContains(response, "Shared by")
        self.assertNotContains(response, "Master failed")
        self.assertContains(response, "opcache.validate_permission")
        self.assertContains(response, "8.4.26")
        self.assertNotContains(response, "Apply review")
        # The Database section is its own page; the runtime page links to it without
        # rendering its card.
        self.assertContains(response, ">Database</a>")
        self.assertNotContains(response, 'id="site-database-heading"')

    def test_overview_links_the_https_address_and_the_readiness_path(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/")
        self.assertContains(response, 'href="http://alpha.example.com"')
        self.assertContains(response, "Barectl checks <code>/</code>")

    def test_a_wordpress_overview_links_the_sign_in_page(self) -> None:
        record_site_settings(self.server, identifier="alpha", application="wordpress", https=True)
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/")
        self.assertContains(response, 'href="https://alpha.example.com"')
        self.assertContains(response, 'href="https://alpha.example.com/wp-admin/"')
        self.assertContains(response, "Sign in to WordPress")

    def test_a_laravel_overview_offers_the_current_release_and_deploy(self) -> None:
        from discovery.models import SiteState
        from discovery.snapshot import ObservedRelease, ObservedSetting

        record_site_settings(
            self.server,
            identifier="alpha",
            application="laravel",
            https=True,
            releases=(
                ObservedRelease(
                    "alpha",
                    "abc123def456-0123456789abcdef",
                    "abc123def456",
                    1_700_000_000,
                    SiteState.MANAGED,
                    True,
                ),
            ),
            settings=(ObservedSetting("alpha", "laravel", "APP_ENV", "a" * 64, "production"),),
        )
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/")
        self.assertContains(response, "Current release")
        self.assertContains(response, "abc123def456")
        self.assertContains(response, "Deploy")

    def test_overview_summary_ends_with_one_period(self) -> None:
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/")
        self.assertContains(response, "Matches the supported site convention. This describes")
        self.assertNotContains(response, "..")

    def test_server_sites_offers_the_create_page_and_its_php_versions(self) -> None:
        response = self.client.get(f"/servers/{self.server.pk}/sites/")
        self.assertContains(response, "Create site")
        self.assertNotContains(response, "Create HTTP site")
        response = self.client.get(f"/servers/{self.server.pk}/sites/create/")
        self.assertContains(response, 'id="create-php-php84"')
        self.assertContains(response, 'id="create-php-php85"')
        self.assertContains(response, "Installed first, adds about")
        self.assertNotContains(response, "Prepare site plan")

    def test_global_sites_reads_observations_and_links_to_creation_without_ssh(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get("/sites/")
        self.assertContains(response, "alpha.example.com")
        self.assertContains(response, f"/servers/{self.server.pk}/sites/create/")
        self.assertContains(response, "Create a site on Web")

    def test_preparation_queues_only_canonical_operator_inputs_and_opens_review(self) -> None:
        from operations.services import read_changes

        response = self.client.post(
            f"/servers/{self.server.pk}/sites/http/prepare/",
            {
                "identifier": "shop",
                "names": "SHOP.example.com. www.shop.example.com",
                "php_version": "php84",
                "path": "/untrusted/path",
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

    def test_a_runtime_the_catalog_does_not_offer_is_refused_before_preparation(self) -> None:
        from operations.services import read_changes

        response = self.client.post(
            f"/servers/{self.server.pk}/sites/http/prepare/",
            {"identifier": "shop", "names": "shop.example.com", "php_version": "php86"},
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_viewer_can_read_sites_but_cannot_prepare_a_change(self) -> None:
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        self.assertEqual(self.client.get("/sites/").status_code, 200)
        response = self.client.post(f"/servers/{self.server.pk}/sites/http/prepare/", {})
        self.assertEqual(response.status_code, 403)
        self.assertNotContains(
            self.client.get(f"/servers/{self.server.pk}/sites/"), ">Create site</a>"
        )

    def test_activity_shows_this_devices_target_site_changes_only(self) -> None:
        from operations.models import ChangePreparation, RemoteOperation

        wanted = ChangePreparation.objects.create(
            server=self.server,
            ssh_alias=self.server.ssh_alias,
            kind_slug="create_http_site",
            inputs={
                "version": 1,
                "identifier": "alpha",
                "names": ["alpha.example.com"],
                "selection": "php84",
            },
            status=RemoteOperation.Status.SUCCEEDED,
        )
        other = ChangePreparation.objects.create(
            server=self.server,
            ssh_alias=self.server.ssh_alias,
            kind_slug="create_http_site",
            inputs={
                "version": 1,
                "identifier": "beta",
                "names": ["beta.example.com"],
                "selection": "php84",
            },
            status=RemoteOperation.Status.SUCCEEDED,
        )
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/activity/")
        self.assertContains(response, f"/changes/{wanted.pk}/")
        self.assertNotContains(response, f"/changes/{other.pk}/")

    def test_current_master_failure_is_shown_without_claiming_verification(self) -> None:
        record_http_sites(self.server, problem="Loaded master evidence is unavailable")
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/logs/")
        self.assertContains(response, "Not manageable: Loaded master evidence is unavailable")
        self.assertNotContains(response, "Verified in this observation")

    def test_stale_observations_are_visible_but_offer_no_runtime_for_creation(self) -> None:
        from discovery.fakes import record_attempt
        from discovery.models import DiscoveryAttempt

        record_attempt(self.server, DiscoveryAttempt.Status.FAILED)
        response = self.client.get(f"/servers/{self.server.pk}/sites/")
        self.assertContains(response, "observations may be out of date")
        for section in ("", "settings/", "logs/", "activity/"):
            with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
                self.assertEqual(
                    self.client.get(f"/servers/{self.server.pk}/sites/alpha/{section}").status_code,
                    200,
                )

    def test_connection_corrected_during_request_refuses_queue_and_retains_input(self) -> None:
        from django.db.models.signals import post_init

        from operations.services import read_changes

        def correct_connection(sender: object, instance: Server, **kwargs: object) -> None:
            del sender
            post_init.disconnect(correct_connection, sender=Server)
            Server.objects.filter(pk=self.server.pk).update(connection_revision=1)

        from servers.testing import HTMX_FRAGMENT

        for headers in ({}, HTMX_FRAGMENT):
            with self.subTest(fragment=bool(headers)):
                Server.objects.filter(pk=self.server.pk).update(connection_revision=0)
                post_init.connect(correct_connection, sender=Server)
                try:
                    response = self.client.post(
                        f"/servers/{self.server.pk}/sites/http/prepare/",
                        {
                            "identifier": "shop",
                            "names": "SHOP.example.com. www.shop.example.com",
                            "php_version": "php84",
                        },
                        headers=headers,
                    )
                finally:
                    post_init.disconnect(correct_connection, sender=Server)
                self.assertContains(response, "The server connection changed", status_code=409)
                self.assertContains(response, 'value="shop.example.com"', status_code=409)
                self.assertContains(response, 'value="www.shop.example.com"', status_code=409)
                self.assertContains(response, 'value="shop"', status_code=409)
                self.assertRegex(
                    response.content.decode(), r'id="create-php-php84"\s+value="php84"\s+checked'
                )
                self.assertContains(response, "disabled", status_code=409)
                self.assertEqual(read_changes(self.server).rows, [])
