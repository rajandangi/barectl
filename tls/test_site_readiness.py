"""The selected site's HTTPS readiness section (docs/tls.md#readiness)."""

from unittest import mock

from django.test import Client

from discovery.fakes import DiscoveryTestCase, add_site
from servers.models import Server
from servers.testing import HTMX_FRAGMENT

VIEW = ("view_server", "add_server", "add_discoveryattempt")
SITES = "view_siteobservation"
TLS = ("view_tlsplan", "prepare_tlsplan")


class SiteReadinessTests(DiscoveryTestCase):
    def discover_site(self, *codenames: str) -> Server:
        add_site(self.remote, "shop", ("shop.example.com",))
        self.grant(*VIEW, SITES, *codenames)
        server = self.register()
        self.run_worker()
        return server

    def test_prepare_binds_the_url_site(self) -> None:
        server = self.discover_site(*TLS)
        with mock.patch("tls.views.request_readiness_preparation", return_value=object()) as queue:
            response = self.client.post(
                f"/servers/{server.pk}/sites/shop/https/readiness/prepare/",
                headers=HTMX_FRAGMENT,
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(queue.call_args.args[2], "shop")
        self.assertContains(response, 'id="site-readiness"')

    def test_prepare_requires_the_prepare_permission(self) -> None:
        server = self.discover_site("view_tlsplan")
        self.assertEqual(
            self.client.post(
                f"/servers/{server.pk}/sites/shop/https/readiness/prepare/"
            ).status_code,
            403,
        )

    def test_prepare_rejects_a_site_not_in_the_current_observation(self) -> None:
        server = self.discover_site(*TLS)
        self.assertEqual(
            self.client.post(
                f"/servers/{server.pk}/sites/absent1/https/readiness/prepare/"
            ).status_code,
            404,
        )

    def test_prepare_rejects_a_missing_csrf_token(self) -> None:
        server = self.discover_site(*TLS)
        csrf = Client(enforce_csrf_checks=True)
        csrf.force_login(self.user)
        self.assertEqual(
            csrf.post(f"/servers/{server.pk}/sites/shop/https/readiness/prepare/").status_code,
            403,
        )

    def test_the_section_requires_the_observation_permission(self) -> None:
        add_site(self.remote, "shop", ("shop.example.com",))
        self.grant(*VIEW, *TLS)
        server = self.register()
        self.run_worker()
        self.assertEqual(
            self.client.get(f"/servers/{server.pk}/sites/shop/https/").status_code, 403
        )

    def test_the_section_offers_the_readiness_review(self) -> None:
        server = self.discover_site(*TLS)
        page = self.client.get(f"/servers/{server.pk}/sites/shop/https/")
        self.assertContains(page, "HTTPS readiness")
        self.assertContains(page, "Check readiness")
