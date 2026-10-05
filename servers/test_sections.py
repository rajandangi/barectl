from unittest import mock

from django.test import Client

from discovery.fakes import FakeServer, record_attempt, run_worker
from discovery.models import DiscoveryAttempt
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
                ("", "Overview"),
                ("sites/", "Sites"),
                ("setup/", "Setup"),
                ("activity/", "Activity"),
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

    def test_site_page_requires_observation_permission_and_omits_restricted_tasks(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        self.assertEqual(self.client.get(f"/servers/{server.pk}/sites/").status_code, 403)
        response = self.client.get(f"/servers/{server.pk}/advanced/")
        self.assertNotContains(response, 'id="site-plans"')
        self.assertNotContains(response, 'id="tls-plans"')
        self.assertNotContains(response, 'id="database-plans"')
        self.assertEqual(self.client.get("/servers/999/setup/").status_code, 404)

    def test_failed_refresh_preserves_truthful_overview_and_advanced_evidence(self) -> None:
        self.grant("view_server", "add_discoveryattempt")
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        remote = FakeServer()
        with remote.substituted():
            request_discovery(server)
            run_worker()
            overview = self.client.get(f"/servers/{server.pk}/")
            self.assertContains(overview, "Ubuntu 24.04.3 LTS")
            self.assertNotContains(overview, 'id="nginx-site-files-heading"')
            remote.failure = "The SSH service could not be reached."
            request_discovery(server)
            run_worker()
        response = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(response, "The latest connection check failed")
        self.assertContains(response, "Ubuntu 24.04.3 LTS")
        self.assertContains(response, "Retry connection check")
        advanced = self.client.get(f"/servers/{server.pk}/advanced/")
        self.assertContains(advanced, 'id="nginx-site-files-heading"')
        self.assertContains(advanced, "The latest connection check failed")

    def test_unavailable_alias_has_remediation_and_no_check_control(self) -> None:
        self.grant("view_server", "add_discoveryattempt")
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="missing")
        response = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(response, "SSH alias unavailable")
        self.assertContains(response, "Restore it on the controller host")
        self.assertNotContains(response, f"/servers/{server.pk}/verify/")

    def test_activity_excludes_other_registrations_and_handles_empty_history(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        other = Server.objects.create(name="Other", ssh_alias="stage.example.net")
        record_attempt(other, DiscoveryAttempt.Status.FAILED, failure="Other registration only")
        response = self.client.get(f"/servers/{server.pk}/activity/")
        self.assertContains(response, "No local activity yet")
        self.assertNotContains(response, "Other registration only")
        record_attempt(server, DiscoveryAttempt.Status.FAILED, failure="Selected registration")
        response = self.client.get(f"/servers/{server.pk}/activity/")
        self.assertContains(response, "Selected registration")
        self.assertNotContains(response, "Other registration only")
        self.assertNotContains(response, "across all servers")

    def test_legacy_task_anchors_offer_permission_appropriate_destinations(self) -> None:
        self.grant(
            "view_server",
            "view_configurationplan",
            "view_siteplan",
            "view_databaseplan",
            "view_tlsplan",
        )
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        response = self.client.get(f"/servers/{server.pk}/")
        for anchor in ("plans", "site-plans", "database-plans", "tls-plans"):
            with self.subTest(anchor=anchor):
                self.assertContains(response, f'id="{anchor}"')
                self.assertContains(response, f'#{anchor}">')
        self.assertContains(response, f"/servers/{server.pk}/setup/#plans")
        self.assertContains(response, f"/servers/{server.pk}/advanced/#tls-plans")
        # Without site observations, the Sites section is closed, so creation stays in Advanced.
        self.assertContains(
            response, f'href="/servers/{server.pk}/advanced/#site-plans">Reviewed site creation'
        )
        self.grant("view_siteobservation")
        response = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(
            response, f'href="/servers/{server.pk}/sites/#site-plans">Reviewed site creation'
        )

    def test_navigation_permissions_do_not_authorize_post_or_bypass_csrf(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        self.assertEqual(self.client.post(f"/servers/{server.pk}/verify/").status_code, 403)
        csrf = Client(enforce_csrf_checks=True)
        csrf.force_login(self.user)
        self.assertEqual(csrf.post(f"/servers/{server.pk}/verify/").status_code, 403)
        self.assertFalse(RemoteOperation.objects.exists())
