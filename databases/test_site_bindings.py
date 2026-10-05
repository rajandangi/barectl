"""The selected site's database section and binding preparation (docs/databases.md)."""

from unittest import mock

from django.test import Client
from django.utils.html import escape

from discovery import ssh
from discovery.fakes import DiscoveryTestCase, add_site, mariadb_rows, postgresql_rows
from discovery.models import DatabaseEngine
from discovery.observations.databases import MARIADB_STEPS, ROOT_QUERY
from servers.models import Server
from servers.testing import HTMX_FRAGMENT

from .binding import connection_text

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
        self.assertContains(
            page, f"/servers/{server.pk}/setup/?from=shop&amp;origin=database#driver-plans"
        )
        self.assertContains(page, "Prepare MariaDB database plan")
        self.assertContains(page, "Prepare PostgreSQL database plan")
        self.assertContains(page, "at most one database binding")

    def discover_as_root(self) -> Server:
        add_site(self.remote, "shop", ("shop.example.com",))
        add_site(self.remote, "blog", ("blog.example.com",))
        self.remote.results[ROOT_QUERY] = ssh.CommandResult(0, "0\n")
        # Viewing the observation is enough; no database plan permission is needed.
        self.grant(*VIEW, SITES)
        server = self.register()
        self.run_worker()
        return server

    def test_an_observed_binding_shows_its_socket_connection_without_a_password(self) -> None:
        self.remote.catalogs.mariadb["sshop"] = mariadb_rows("sshop")
        self.remote.catalogs.postgresql["sblog"] = postgresql_rows("sblog")
        server = self.discover_as_root()
        for identifier, engine, dsn in (
            ("shop", DatabaseEngine.MARIADB, "unix_socket=/run/mysqld/mysqld.sock;dbname=sshop"),
            ("blog", DatabaseEngine.POSTGRESQL, "host=/var/run/postgresql;port=5432;dbname=sblog"),
        ):
            with self.subTest(engine=engine):
                page = self.client.get(f"/servers/{server.pk}/sites/{identifier}/database/")
                self.assertContains(page, "<dt>Connection</dt>")
                self.assertContains(page, escape(connection_text(engine, identifier)))
                self.assertContains(page, dsn)
                self.assertContains(page, f"as the user s{identifier} with no password")
                self.assertContains(page, "TCP connections are refused.")
                self.assertContains(page, "Barectl offers no remote access to it.")

    def test_no_connection_guidance_without_a_conforming_binding(self) -> None:
        # shop's binding is partial; blog has none.
        self.remote.catalogs.mariadb["sshop"] = mariadb_rows("sshop", MARIADB_STEPS[:1])
        server = self.discover_as_root()
        for identifier in ("shop", "blog"):
            with self.subTest(identifier=identifier):
                page = self.client.get(f"/servers/{server.pk}/sites/{identifier}/database/")
                self.assertContains(page, 'id="site-database-heading"')
                self.assertNotContains(page, "<dt>Connection</dt>")
                self.assertNotContains(page, "with no password")
