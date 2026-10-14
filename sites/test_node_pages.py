"""Site Node selection reads cached choices and queues immutable site-only intent."""

from dataclasses import replace
from typing import override
from unittest import mock

from django.utils import timezone

from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt
from discovery.snapshot import current_snapshot, save_snapshot
from operations.services import read_changes
from runtimes.observation import RuntimeObservation
from servers.models import Server
from servers.testing import ControllerConfigTestCase

from .ui_testing import record_http_sites


class SiteNodePageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Node", ssh_alias="node.example.com")
        record_http_sites(self.server)
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("No setup snapshot.")
        node = RuntimeObservation(
            "nodejs_24", "/nix/store/observed-node", "1", "24.14.0", (), "Profile only", (), ""
        )
        collected = replace(snapshot.collected, runtimes=(*snapshot.collected.runtimes, node))
        save_snapshot(
            record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED),
            collected,
            timezone.now(),
        )

    def test_runtime_page_offers_only_installed_node_without_opening_ssh(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/runtime/")
        self.assertContains(response, "Select site Node runtime")
        self.assertContains(response, 'value="nodejs_24"')
        self.assertNotContains(response, 'value="nodejs_22"')

    def test_post_queues_only_the_versioned_site_selection(self) -> None:
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/runtime/node/prepare/",
            {"selection": "nodejs_24", "path": "/untrusted/program"},
        )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(
            rows[0].preparation.inputs,
            {"version": 1, "identifier": "alpha", "selection": "nodejs_24"},
        )

    def test_viewer_cannot_submit_node_selection(self) -> None:
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/runtime/node/prepare/",
            {"selection": "nodejs_24"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(read_changes(self.server).rows, [])
