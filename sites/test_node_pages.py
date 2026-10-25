"""Journey 5: a site's Node.js version is changed from Settings (docs/dashboard-workflows.md)."""

from dataclasses import replace
from typing import override
from unittest import mock

from django.test import Client
from django.utils import timezone

from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt
from discovery.snapshot import current_snapshot, save_snapshot
from operations.services import read_changes
from runtimes.observation import RuntimeObservation
from servers.models import Server
from servers.testing import ControllerConfigTestCase

from .node_change import SLUG
from .ui_testing import record_http_sites, record_step_run


def record_node_sites(
    server: Server, *, current: str = "", installed: tuple[str, ...] = ()
) -> None:
    """A target host with the given Node.js versions installed and the site's selection."""
    record_http_sites(server)
    snapshot = current_snapshot(server)
    if snapshot is None:
        raise AssertionError("No snapshot.")
    rows = [
        RuntimeObservation(
            entry,
            f"/nix/store/observed-{entry}",
            "1",
            "22.23.3" if entry == "nodejs_22" else "24.21.0",
            (),
            "",
            (),
            "",
        )
        for entry in installed
    ]
    sites = tuple(
        replace(site, node_runtime=current) if site.identifier == "alpha" else site
        for site in snapshot.collected.sites.value
    )
    collected = replace(
        snapshot.collected,
        runtimes=(*snapshot.collected.runtimes, *rows),
        sites=replace(snapshot.collected.sites, value=sites),
    )
    save_snapshot(
        record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED),
        collected,
        timezone.now(),
    )


class SiteNodeSettingsTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Node", ssh_alias="node.example.com")
        record_node_sites(self.server, current="nodejs_22", installed=("nodejs_22", "nodejs_24"))
        self.settings_url = f"/servers/{self.server.pk}/sites/alpha/settings/"
        self.url = f"/servers/{self.server.pk}/sites/alpha/runtime/node/prepare/"

    def test_settings_shows_the_current_node_version_without_ssh(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(self.settings_url)
        self.assertContains(response, "Node.js version:")
        self.assertContains(response, "<strong>22</strong>")
        self.assertContains(response, "Change Node.js version")
        self.assertContains(response, "?change=node#change-node")

    def test_the_choice_offers_only_the_other_installed_versions(self) -> None:
        response = self.client.get(f"{self.settings_url}?change=node")
        self.assertContains(response, 'id="site-node-nodejs_24"')
        self.assertContains(response, "Node.js 24")
        self.assertNotContains(response, 'id="site-node-nodejs_22"')

    def test_an_installed_version_queues_the_site_switch(self) -> None:
        response = self.client.post(
            self.url, {"selection": "nodejs_24", "path": "/untrusted/program"}
        )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].preparation.kind_slug, SLUG)
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(
            rows[0].preparation.inputs,
            {"version": 1, "identifier": "alpha", "selection": "nodejs_24"},
        )

    def test_a_forged_prepare_for_the_current_version_is_refused(self) -> None:
        response = self.client.post(self.url, {"selection": "nodejs_22"})
        self.assertRedirects(response, self.settings_url)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_a_forged_prepare_outside_the_catalog_is_refused(self) -> None:
        response = self.client.post(self.url, {"selection": "nodejs_99"})
        self.assertRedirects(response, self.settings_url)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_a_missing_version_is_step_one_and_keeps_the_choice(self) -> None:
        record_node_sites(self.server, current="nodejs_22", installed=("nodejs_22",))
        response = self.client.post(self.url, {"selection": "nodejs_24"})
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        preparation = rows[0].preparation
        self.assertEqual(preparation.kind_slug, "add_runtime")
        self.assertEqual(preparation.inputs, {"version": 1, "selection": "nodejs_24"})
        self.assertRedirects(response, f"/changes/{preparation.pk}/")
        page = self.client.get(f"/changes/{preparation.pk}/")
        self.assertContains(page, "Step 1 of 2: add Node.js 24 to this server")
        run = record_step_run(preparation)
        run_page = self.client.get(f"/runs/{run.pk}/")
        self.assertContains(run_page, "Continue to switch the site")
        self.assertContains(
            run_page,
            f'href="/servers/{self.server.pk}/sites/alpha/settings/'
            "?change=node&amp;selection=nodejs_24#change-node",
        )
        record_node_sites(self.server, current="nodejs_22", installed=("nodejs_22", "nodejs_24"))
        response = self.client.post(self.url, {"selection": "nodejs_24"})
        rows = read_changes(self.server).rows
        self.assertEqual(rows[0].preparation.kind_slug, SLUG)
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")

    def test_viewer_cannot_submit_a_node_change(self) -> None:
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(self.url, {"selection": "nodejs_24"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_csrf_is_required(self) -> None:
        csrf = Client(enforce_csrf_checks=True)
        csrf.force_login(self.user)
        self.assertEqual(csrf.post(self.url, {"selection": "nodejs_24"}).status_code, 403)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_a_failed_refresh_cannot_reuse_old_choices(self) -> None:
        record_attempt(self.server, DiscoveryAttempt.Status.FAILED)
        response = self.client.post(self.url, {"selection": "nodejs_24"})
        self.assertRedirects(response, self.settings_url)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_busy_server_does_not_queue_another_preparation(self) -> None:
        self.client.post(self.url, {"selection": "nodejs_24"})
        response = self.client.post(self.url, {"selection": "nodejs_24"})
        self.assertRedirects(response, self.settings_url)
        self.assertEqual(len(read_changes(self.server).rows), 1)
