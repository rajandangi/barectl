from dataclasses import replace
from typing import override
from unittest import mock

from django.utils import timezone

from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt
from discovery.snapshot import current_snapshot, save_snapshot
from operations.models import ChangePreparation
from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.ui_testing import record_http_sites

from .defaults import DefaultsObservation


class DefaultCommandPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Defaults", ssh_alias="defaults.example.com")
        record_http_sites(self.server)
        self.record_defaults(
            DefaultsObservation(
                "php84", php_choices=("php84", "php85"), node_choices=("nodejs_24",)
            )
        )

    def record_defaults(self, defaults: DefaultsObservation) -> None:
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("No current snapshot.")
        attempt = record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED)
        save_snapshot(
            attempt, replace(snapshot.collected, runtime_defaults=defaults), timezone.now()
        )

    def test_stack_reads_recorded_defaults_and_queues_the_exact_installed_selection(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            page = self.client.get(f"/servers/{self.server.pk}/stack/?tab=defaults")
            self.assertContains(page, 'value="php84" selected')
            self.assertContains(page, "Review PHP default")
            response = self.client.post(
                f"/servers/{self.server.pk}/stack/defaults/php/prepare/",
                {"selection": "php85", "path": "/untrusted"},
            )
        preparation = ChangePreparation.objects.get()
        self.assertEqual(preparation.kind_slug, "set_default_php")
        self.assertEqual(preparation.inputs, {"version": 1, "selection": "php85"})
        self.assertRedirects(response, f"/changes/{preparation.pk}/")

    def test_an_uninstalled_runtime_and_cross_language_selection_never_queue(self) -> None:
        for selection in ("nodejs_22", "php85", "nodejs_99"):
            response = self.client.post(
                f"/servers/{self.server.pk}/stack/defaults/node/prepare/",
                {"selection": selection},
            )
            self.assertEqual(response.status_code, 302)
        self.assertFalse(ChangePreparation.objects.exists())

    def test_an_administrator_command_is_reported_and_direct_post_is_refused(self) -> None:
        self.record_defaults(
            DefaultsObservation(
                php_problem="The PHP commands are set by the administrator.", php_choices=("php84",)
            )
        )
        page = self.client.get(f"/servers/{self.server.pk}/stack/?tab=defaults")
        self.assertContains(page, "set by the administrator")
        self.assertNotContains(page, "Review PHP default")
        self.client.post(
            f"/servers/{self.server.pk}/stack/defaults/php/prepare/", {"selection": "php84"}
        )
        self.assertFalse(ChangePreparation.objects.exists())

    def test_failed_refresh_does_not_authorize_the_previous_default_choices(self) -> None:
        record_attempt(self.server, DiscoveryAttempt.Status.FAILED)
        self.client.post(
            f"/servers/{self.server.pk}/stack/defaults/php/prepare/", {"selection": "php85"}
        )
        self.assertFalse(ChangePreparation.objects.exists())

    def test_viewer_cannot_prepare_a_shared_default_review(self) -> None:
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(
            f"/servers/{self.server.pk}/stack/defaults/php/prepare/", {"selection": "php85"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangePreparation.objects.exists())
