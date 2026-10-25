from unittest import mock

from discovery.fakes import FakeServer, record_attempt, run_worker
from discovery.services import request_discovery
from operations.models import RemoteOperation

from .models import Server
from .testing import ControllerConfigTestCase


class ServerSectionTests(ControllerConfigTestCase):
    def test_sections_are_local_reads_and_history_restores_are_full_pages(self) -> None:
        self.grant("view_server", "view_siteobservation")
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        with mock.patch("discovery.ssh.connect_alias") as connect:
            for suffix, title in (
                ("", "Sites"),
                ("sites/", "Sites"),
                ("activity/", "Activity"),
                ("settings/", "Settings"),
                ("advanced/", "Advanced"),
            ):
                with self.subTest(section=title):
                    response = self.client.get(
                        f"/servers/{server.pk}/{suffix}",
                        headers={"HX-Request": "true", "HX-History-Restore-Request": "true"},
                    )
                    self.assertContains(response, "<html")
                    self.assertContains(response, 'aria-label="Server sections"')
                    self.assertContains(response, f'aria-current="page">{title}</a>')
            connect.assert_not_called()
        self.assertFalse(RemoteOperation.objects.exists())

    def test_removed_sections_redirect_to_their_new_homes(self) -> None:
        self.grant("view_server", "view_siteobservation")
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        stack = self.client.get(f"/servers/{server.pk}/stack/?tab=php")
        self.assertRedirects(
            stack, f"/servers/{server.pk}/advanced/?tab=php", fetch_redirect_response=False
        )
        runtime = self.client.get(f"/servers/{server.pk}/sites/example/runtime/")
        self.assertRedirects(
            runtime,
            f"/servers/{server.pk}/sites/example/settings/",
            fetch_redirect_response=False,
        )
        advanced = self.client.get(f"/servers/{server.pk}/sites/example/advanced/")
        self.assertRedirects(
            advanced,
            f"/servers/{server.pk}/sites/example/logs/",
            fetch_redirect_response=False,
        )

    def test_site_page_requires_observation_permission_and_omits_restricted_tasks(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        # The server page opens on Sites and says the account may not view them.
        page = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(page, "may manage this server but not view its sites")
        self.assertEqual(self.client.get(f"/servers/{server.pk}/sites/").status_code, 200)
        response = self.client.get(f"/servers/{server.pk}/advanced/")
        self.assertNotContains(response, 'id="site-plans"')
        self.assertNotContains(response, 'id="tls-plans"')
        self.assertNotContains(response, 'id="database-plans"')
        self.assertEqual(self.client.get("/servers/999/setup/").status_code, 404)

    def test_failed_refresh_preserves_truthful_status_and_advanced_evidence(self) -> None:
        self.grant("view_server", "add_discoveryattempt", "view_siteobservation")
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        remote = FakeServer()
        with remote.substituted():
            request_discovery(server)
            run_worker()
            sites = self.client.get(f"/servers/{server.pk}/")
            self.assertContains(sites, 'id="connection-status"')
            remote.failure = "The SSH service could not be reached."
            request_discovery(server)
            run_worker()
        response = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(response, "Connection failed")
        self.assertContains(response, "The latest connection check failed")
        advanced = self.client.get(f"/servers/{server.pk}/advanced/")
        self.assertContains(advanced, "Ubuntu 26.04.1 LTS")
        self.assertContains(advanced, 'id="foundation-stack-heading"')

    def test_unavailable_alias_has_remediation_and_no_check_control(self) -> None:
        self.grant("view_server", "add_discoveryattempt", "view_siteobservation")
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="missing")
        response = self.client.get(f"/servers/{server.pk}/settings/")
        self.assertContains(response, "no longer a usable Host entry")
        self.assertContains(response, "Edit connection")
        self.assertNotContains(response, f"/servers/{server.pk}/verify/")

    def test_activity_excludes_other_registrations_and_handles_empty_history(self) -> None:
        self.grant("view_server")
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        response = self.client.get(f"/servers/{server.pk}/activity/")
        self.assertContains(response, "No activity yet")
        record_attempt(server, RemoteOperation.Status.FAILED, failure="The connection failed.")
        response = self.client.get(f"/servers/{server.pk}/activity/")
        self.assertContains(response, "The connection failed.")

    def test_advanced_holds_the_stack_and_the_discovery_history(self) -> None:
        self.grant("view_server", "view_siteobservation")
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        response = self.client.get(f"/servers/{server.pk}/advanced/")
        self.assertContains(response, "Web stack and services")
        self.assertContains(response, "Discovery history")
        sites = self.client.get(f"/servers/{server.pk}/")
        self.assertNotContains(sites, "Web stack and services")
        self.assertNotContains(sites, "Discovery history")
