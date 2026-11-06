from dataclasses import replace
from typing import override
from unittest import mock

from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, FakeServer, record_attempt, run_worker
from discovery.models import DiscoveryAttempt
from discovery.services import request_discovery
from discovery.snapshot import save_snapshot
from operations import preparation
from operations.activity_testing import record_change
from operations.models import ChangePreparation, RemoteOperation
from servers.views import SECTIONS

from .discovery_state import server_state
from .models import Server
from .preparation import decide_for_server
from .testing import ControllerConfigTestCase


class ServerSectionTests(ControllerConfigTestCase):
    def test_sections_are_local_reads_and_history_restores_are_full_pages(self) -> None:
        self.grant("view_server", "view_siteobservation")
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        with mock.patch("discovery.ssh.connect_alias") as connect:
            for key, title in SECTIONS.items():
                suffix = "" if key == "sites" else f"{key}/"
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

    def test_navigation_lists_the_exported_sections_in_order(self) -> None:
        self.grant("view_server")
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        body = self.client.get(f"/servers/{server.pk}/").content.decode()
        positions = [body.index(f">{title}</a>") for title in SECTIONS.values()]
        self.assertEqual(positions, sorted(positions))

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
        self.assertEqual(self.client.get("/servers/999/setup/").status_code, 302)

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

    def test_security_section_is_a_stored_read_with_no_score_or_native_terms(self) -> None:
        self.grant("view_server", "view_siteobservation", "add_discoveryattempt")
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        empty = self.client.get(f"/servers/{server.pk}/security/")
        self.assertContains(empty, "No security checks have been read yet")
        self.assertNotContains(empty, "Security score")
        remote = FakeServer()
        with remote.substituted():
            request_discovery(server)
            run_worker()
        with mock.patch("discovery.ssh.connect_alias") as connect:
            response = self.client.get(f"/servers/{server.pk}/security/")
            connect.assert_not_called()
        self.assertContains(response, "There is no score")
        for name in (
            "Firewall",
            "SSH sign-in",
            "Automatic security updates",
            "Ubuntu updates",
            "Restart needed",
            "Web runtimes",
        ):
            self.assertContains(response, name)
        self.assertContains(response, "Could not check")

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


class SetupCardTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def store(self, standing: Standing, foundation: tuple[tuple[str, str], ...] = ()) -> None:
        attempt = record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED)
        collected = replace(COLLECTED, standing=HostJudgment(standing, (), (), foundation))
        save_snapshot(attempt, collected, timezone.now())

    def test_a_fresh_server_offers_setup_in_the_banner(self) -> None:
        self.grant("view_server", "view_changes", "change_site")
        self.store(Standing.FRESH)
        response = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(response, "Ready to set up")
        self.assertContains(response, "Set up server")

    def test_a_fresh_server_without_permission_shows_the_gate_sentence(self) -> None:
        self.grant("view_server")
        self.store(Standing.FRESH)
        response = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(response, "Your account does not have permission to prepare changes.")
        self.assertNotContains(response, "Set up server")

    def test_needs_attention_offers_setup_and_names_the_gate_sentence(self) -> None:
        self.grant("view_server", "view_changes", "change_site")
        self.store(
            Standing.INCOMPLETE_FOUNDATION,
            (("Web server", "present"), ("PHP", "absent")),
        )
        response = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertContains(response, "Needs attention")
        self.assertContains(response, "Set up server")

    def test_needs_attention_without_permission_shows_the_gate_sentence(self) -> None:
        self.grant("view_server")
        self.store(
            Standing.INCOMPLETE_FOUNDATION,
            (("Web server", "present"), ("PHP", "absent")),
        )
        response = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertContains(response, "Needs attention")
        self.assertContains(response, "Your account does not have permission to prepare changes.")
        self.assertNotContains(response, "Set up server")

    def test_a_server_with_no_observation_still_passes_the_setup_gate(self) -> None:
        self.grant("view_server", "view_changes", "change_site")
        decision = decide_for_server(server_state(self.server), self.user, preparation.SERVER)
        self.assertTrue(decision.allowed)
        response = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(response, "Check the connection")

    def test_a_running_change_withholds_setup_and_refuses_the_post_with_the_sentence(
        self,
    ) -> None:
        self.grant("view_server", "view_changes", "change_site")
        self.store(Standing.FRESH)
        record_change(self.server, status=RemoteOperation.Status.RUNNING)
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertNotContains(page, "Set up server")
        self.assertContains(
            page,
            "Another change is running for this server; wait for it to finish before "
            "preparing a change.",
        )
        refused = self.client.post(
            f"/servers/{self.server.pk}/changes/prepare/",
            {"kind": "host_foundation"},
            follow=True,
        )
        self.assertContains(
            refused,
            "Another change is running for this server; wait for it to finish before "
            "preparing a change.",
        )
        self.assertEqual(ChangePreparation.objects.count(), 1)
