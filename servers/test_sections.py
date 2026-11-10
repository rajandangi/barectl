from dataclasses import replace
from typing import override
from unittest import mock

from django.urls import reverse
from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, FakeServer, record_attempt, run_worker
from discovery.models import DiscoveryAttempt
from discovery.services import request_discovery
from discovery.snapshot import save_snapshot
from operations import preparation
from operations.activity_testing import record_change
from operations.models import ChangePreparation, RemoteOperation
from servers.advanced import STACK_TABS
from servers.views import SECTIONS
from sites.ui_testing import record_http_sites, record_older_snapshots

from .discovery_state import server_state
from .models import Server
from .preparation import decide_for_server
from .testing import (
    HTMX_FRAGMENT,
    ControllerConfigTestCase,
    assert_query_count_flat_as_history_grows,
)


class ServerSectionTests(ControllerConfigTestCase):
    def test_sections_are_local_reads_and_history_restores_are_full_pages(self) -> None:
        self.grant("view_server", "view_siteobservation")
        self.client.force_login(self.user)
        server = Server.objects.create(
            name="Web", ssh_alias="web.example.com", address="203.0.113.10"
        )
        with mock.patch("discovery.ssh.connect_alias") as connect:
            for key, title in SECTIONS.items():
                suffix = "" if key == "sites" else f"{key}/"
                with self.subTest(section=title):
                    response = self.client.get(
                        f"/servers/{server.pk}/{suffix}",
                        headers={"HX-Request": "true", "HX-History-Restore-Request": "true"},
                    )
                    self.assertContains(response, "<html")
                    self.assertContains(response, 'id="server-summary"', count=1)
                    self.assertContains(response, "No observations yet")
                    self.assertContains(
                        response, '<code id="server-address">203.0.113.10</code>', html=True
                    )
                    self.assertContains(response, 'aria-label="Server sections"')
                    self.assertContains(response, f'aria-current="page">{title}</a>')
                    if key == "settings":
                        body = response.content.decode()
                        self.assertNotIn('id="connection-heading"', body)
                        self.assertNotIn("<dt>SSH user</dt>", body)
                        self.assertNotIn("settings-connection-heading", body)
            for tab_key, label in STACK_TABS:
                response = self.client.get(
                    f"/servers/{server.pk}/advanced/?tab={tab_key}",
                    headers={**HTMX_FRAGMENT, "HX-Target": "section#server-stack"},
                )
                self.assertContains(response, 'id="server-stack"')
                self.assertNotContains(response, "<html")
                self.assertNotContains(response, "Server details")
                self.assertContains(response, f">{label}</a>")
                self.assertIn("HX-Target", response.headers["Vary"])
            connect.assert_not_called()
        self.assertFalse(RemoteOperation.objects.exists())

    def test_navigation_lists_the_exported_sections_in_order(self) -> None:
        self.grant("view_server")
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        body = self.client.get(f"/servers/{server.pk}/").content.decode()
        self.assertIn("Server address unavailable", body)
        self.assertNotIn("data-copy-address", body)
        self.assertNotIn(f'href="/servers/{server.pk}/activity/"', body)
        self.assertIn('href="/activity/"', body)
        positions = [body.index(f">{title}</a>") for title in SECTIONS.values()]
        self.assertEqual(positions, sorted(positions))
        listing = self.client.get("/")
        self.assertNotContains(listing, "Edit connection for Web")
        self.grant("change_server")
        listing = self.client.get("/")
        self.assertContains(
            listing,
            '<th scope="col" role="columnheader" class="barectl-server-list__action">Actions</th>',
            html=True,
        )
        self.assertContains(listing, f"/servers/{server.pk}/edit/")

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
        self.assertContains(response, "Ubuntu 26.04.1 LTS")
        self.assertContains(response, "Memory")
        self.assertContains(response, "Storage")
        advanced = self.client.get(f"/servers/{server.pk}/advanced/")
        self.assertContains(advanced, "Ubuntu 26.04.1 LTS")
        self.assertContains(advanced, 'aria-label="Selected stack details"')

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
        response = self.client.get("/activity/", {"server": server.pk})
        self.assertContains(response, "No activity yet")
        record_attempt(server, RemoteOperation.Status.FAILED, failure="The connection failed.")
        response = self.client.get("/activity/", {"server": server.pk})
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


class ServerPageReadCostTests(ControllerConfigTestCase):
    """Every server page and the site Activity page costs the same as history grows."""

    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        record_http_sites(self.server)

    def assert_flat(self, url: str) -> None:
        assert_query_count_flat_as_history_grows(
            self.client, url, lambda: record_older_snapshots(self.server, 3)
        )

    def test_the_server_overview_query_count_does_not_grow_with_recorded_attempts(self) -> None:
        self.assert_flat(f"/servers/{self.server.pk}/")

    def test_the_server_settings_query_count_does_not_grow_with_recorded_attempts(self) -> None:
        self.assert_flat(f"/servers/{self.server.pk}/settings/")

    def test_the_server_security_query_count_does_not_grow_with_recorded_attempts(self) -> None:
        self.assert_flat(f"/servers/{self.server.pk}/security/")

    def test_the_server_advanced_query_count_does_not_grow_with_recorded_attempts(self) -> None:
        self.assert_flat(f"/servers/{self.server.pk}/advanced/")

    def test_the_server_jobs_query_count_does_not_grow_with_recorded_attempts(self) -> None:
        self.assert_flat(f"/servers/{self.server.pk}/jobs/")

    def test_filtered_activity_query_count_does_not_grow_with_recorded_attempts(self) -> None:
        self.assert_flat(f"/activity/?server={self.server.pk}")

    def test_the_site_activity_query_count_does_not_grow_with_recorded_attempts(self) -> None:
        self.assert_flat(f"/servers/{self.server.pk}/sites/alpha/activity/")


class ServerVerifyFragmentTests(ControllerConfigTestCase):
    def test_the_fragment_after_queueing_shows_the_queued_check(self) -> None:
        self.grant("view_server", "add_discoveryattempt")
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        response = self.client.post(
            reverse("server_verify", args=[server.pk]), headers=HTMX_FRAGMENT
        )
        self.assertEqual(response.status_code, 200)
        # The fragment is rendered from a read built after the queue, not the one the
        # request started with.
        self.assertContains(response, "Checking the connection")
        self.assertContains(response, "Connection check queued.")
        self.assertTrue(
            DiscoveryAttempt.objects.filter(
                server=server, status=DiscoveryAttempt.Status.QUEUED
            ).exists()
        )


class ReadIsolationTests(ControllerConfigTestCase):
    def test_a_check_queued_between_two_requests_appears_in_the_second(self) -> None:
        self.grant("view_server")
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        url = f"/servers/{server.pk}/"
        first = self.client.get(url)
        self.assertContains(first, "Not checked yet")
        record_attempt(server, DiscoveryAttempt.Status.QUEUED)
        second = self.client.get(url)
        # Every request builds its own read; nothing is cached across requests.
        self.assertContains(second, "Checking…")


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
