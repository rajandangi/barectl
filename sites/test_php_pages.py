from dataclasses import replace
from typing import override
from unittest import mock

from django.test import override_settings
from django.urls import path
from django.utils import timezone

from config.urls import urlpatterns as existing_patterns
from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt, SiteState
from discovery.snapshot import current_snapshot, save_snapshot
from operations.services import read_changes
from servers.models import Server
from servers.testing import ControllerConfigTestCase

from .php_views import prepare_php
from .ui_testing import record_http_sites

urlpatterns = [
    path(
        "servers/<int:pk>/sites/<str:identifier>/runtime/php/prepare/",
        prepare_php,
        name="site_php_prepare",
    ),
    *existing_patterns,
]


@override_settings(ROOT_URLCONF=__name__)
class SitePhpPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="PHP", ssh_alias="php.example.com")
        record_http_sites(self.server)
        self.url = f"/servers/{self.server.pk}/sites/alpha/runtime/php/prepare/"

    def test_post_queues_only_versioned_site_selection_without_ssh(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            response = self.client.post(
                self.url, {"selection": "php84", "path": "/untrusted/program"}
            )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(
            rows[0].preparation.inputs,
            {"version": 1, "identifier": "alpha", "selection": "php84"},
        )

    def test_unverified_target_cannot_be_queued(self) -> None:
        response = self.client.post(self.url, {"selection": "php85"})
        self.assertRedirects(response, f"/servers/{self.server.pk}/sites/alpha/runtime/")
        self.assertEqual(read_changes(self.server).rows, [])

    def test_failed_refresh_cannot_reuse_old_runtime_choices(self) -> None:
        record_attempt(self.server, DiscoveryAttempt.Status.FAILED)
        response = self.client.post(self.url, {"selection": "php84"})
        self.assertRedirects(response, f"/servers/{self.server.pk}/sites/alpha/runtime/")
        self.assertEqual(read_changes(self.server).rows, [])

    def test_viewer_cannot_submit_php_selection(self) -> None:
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(self.url, {"selection": "php84"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_busy_server_does_not_queue_another_preparation(self) -> None:
        self.client.post(self.url, {"selection": "php84"})
        response = self.client.post(self.url, {"selection": "php84"})
        self.assertRedirects(response, f"/servers/{self.server.pk}/sites/alpha/runtime/")
        self.assertEqual(len(read_changes(self.server).rows), 1)

    def test_unmanaged_site_cannot_queue_a_php_switch(self) -> None:
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("No setup snapshot.")
        observed = snapshot.collected.sites
        sites = tuple(replace(site, state=SiteState.CHANGED) for site in observed.value)
        save_snapshot(
            record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED),
            replace(snapshot.collected, sites=replace(observed, value=sites)),
            timezone.now(),
        )
        response = self.client.post(self.url, {"selection": "php84"})
        self.assertRedirects(response, f"/servers/{self.server.pk}/sites/alpha/runtime/")
        self.assertEqual(read_changes(self.server).rows, [])
