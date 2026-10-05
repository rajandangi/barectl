"""The selected site's database section and binding preparation (docs/databases.md)."""

from unittest import mock

from django.test import Client

from discovery.fakes import DiscoveryTestCase, add_site
from servers.models import Server
from servers.testing import HTMX_FRAGMENT

VIEW = ("view_server", "add_server", "add_discoveryattempt")
SITES = "view_siteobservation"
DATABASE = ("view_databaseplan", "prepare_databaseplan")


class SiteBindingTests(DiscoveryTestCase):
    def discover_site(self, *codenames: str) -> Server:
        add_site(self.remote, "shop", ("shop.example.com",))
        self.grant(*VIEW, SITES, *codenames)
        server = self.register()
        self.run_worker()
        return server

    def test_prepare_binds_the_url_site_and_ignores_a_form_value(self) -> None:
        server = self.discover_site(*DATABASE)
        with mock.patch(
            "databases.views.request_binding_preparation", return_value=object()
        ) as queue:
            response = self.client.post(
                f"/servers/{server.pk}/sites/shop/database/prepare/",
                {"action": "database_mariadb", "identifier": "other"},
                headers=HTMX_FRAGMENT,
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(queue.call_args.args[2], "shop")
        self.assertContains(response, 'id="site-database-plans"')

    def test_prepare_requires_the_prepare_permission(self) -> None:
        server = self.discover_site("view_databaseplan")
        self.assertEqual(
            self.client.post(
                f"/servers/{server.pk}/sites/shop/database/prepare/",
                {"action": "database_mariadb"},
            ).status_code,
            403,
        )

    def test_the_section_requires_the_observation_permission(self) -> None:
        add_site(self.remote, "shop", ("shop.example.com",))
        self.grant(*VIEW, *DATABASE)
        server = self.register()
        self.run_worker()
        self.assertEqual(
            self.client.get(f"/servers/{server.pk}/sites/shop/database/").status_code, 403
        )

    def test_prepare_refuses_the_identifier_from_another_server(self) -> None:
        self.discover_site(*DATABASE)
        other = self.register(name="Other", alias="stage.example.net")
        self.assertEqual(
            self.client.post(
                f"/servers/{other.pk}/sites/shop/database/prepare/",
                {"action": "database_mariadb"},
            ).status_code,
            404,
        )

    def test_prepare_rejects_a_site_not_in_the_current_observation(self) -> None:
        server = self.discover_site(*DATABASE)
        self.assertEqual(
            self.client.post(
                f"/servers/{server.pk}/sites/absent1/database/prepare/",
                {"action": "database_mariadb"},
            ).status_code,
            404,
        )

    def test_prepare_rejects_a_missing_csrf_token(self) -> None:
        server = self.discover_site(*DATABASE)
        csrf = Client(enforce_csrf_checks=True)
        csrf.force_login(self.user)
        self.assertEqual(
            csrf.post(
                f"/servers/{server.pk}/sites/shop/database/prepare/",
                {"action": "database_mariadb"},
            ).status_code,
            403,
        )

    def test_the_section_offers_the_reviewed_prerequisite_and_both_engines(self) -> None:
        server = self.discover_site(*DATABASE)
        page = self.client.get(f"/servers/{server.pk}/sites/shop/database/")
        self.assertContains(page, "Site database plans")
        self.assertContains(page, f"/servers/{server.pk}/setup/?from=shop#driver-plans")
        self.assertContains(page, "Prepare MariaDB database plan")
        self.assertContains(page, "Prepare PostgreSQL database plan")
        self.assertContains(page, "at most one database binding")
