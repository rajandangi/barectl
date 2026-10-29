from typing import override
from unittest import mock

from django.test import Client

from operations.models import ChangePreparation
from servers.models import Server
from servers.testing import ControllerConfigTestCase

from .deploy_views import DEPLOY_SLUG, ROLLBACK_SLUG
from .ui_testing import record_laravel_releases


class SiteDeployPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Laravel", ssh_alias="laravel.example.com")
        record_laravel_releases(self.server)
        self.deploy_url = f"/servers/{self.server.pk}/sites/alpha/deployments/deploy/prepare/"
        self.rollback_url = f"/servers/{self.server.pk}/sites/alpha/deployments/rollback/prepare/"

    def test_the_deployments_section_lists_releases_without_ssh(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/deployments/")
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertIn("Deployments", body)
        self.assertIn("Current", body)
        self.assertIn(f"{0:040x}", body)
        # Each release's commit, creation time, state and whether it is serving.
        for heading in ("Release", "Commit", "Created", "Status", "Serving"):
            self.assertIn(heading, body)
        self.assertIn("Managed", body)
        self.assertIn("Retained", body)
        self.assertIn("2023-11-14 22:13 UTC", body)

    def test_deploy_prepare_queues_only_the_versioned_identifier(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            response = self.client.post(self.deploy_url, {"repository": "/untrusted"})
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].kind_slug, DEPLOY_SLUG)
        self.assertRedirects(response, f"/changes/{rows[0].pk}/")
        self.assertEqual(rows[0].inputs, {"version": 1, "identifier": "alpha"})

    def test_rollback_prepare_queues_the_chosen_release(self) -> None:
        release = f"{3:040x}-{'a' * 16}"
        self.client.post(self.rollback_url, {"release": release})
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].kind_slug, ROLLBACK_SLUG)
        self.assertEqual(rows[0].inputs, {"version": 1, "identifier": "alpha", "release": release})

    def test_a_release_outside_the_observation_is_refused(self) -> None:
        response = self.client.post(self.rollback_url, {"release": f"{9:040x}-{'f' * 16}"})
        self.assertRedirects(response, f"/servers/{self.server.pk}/sites/alpha/deployments/")
        self.assertEqual(self._rows(), [])

    def test_the_deploy_migrations_switch_defaults_on_and_saves_off(self) -> None:
        settings_url = f"/servers/{self.server.pk}/sites/alpha/deployments/settings/"
        self.client.post(settings_url, {})
        self.client.post(self.deploy_url, {})
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].inputs, {"version": 1, "identifier": "alpha", "migrations": False})

    def test_the_switch_can_be_turned_back_on(self) -> None:
        settings_url = f"/servers/{self.server.pk}/sites/alpha/deployments/settings/"
        self.client.post(settings_url, {})
        self.client.post(settings_url, {"run_migrations": "on"})
        self.client.post(self.deploy_url, {})
        self.assertEqual(self._rows()[0].inputs, {"version": 1, "identifier": "alpha"})

    def test_a_viewer_cannot_save_deploy_settings(self) -> None:
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/deployments/settings/", {}
        )
        self.assertEqual(response.status_code, 403)

    def test_a_viewer_cannot_prepare_a_deploy(self) -> None:
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(self.deploy_url)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self._rows(), [])

    def _rows(self) -> list[ChangePreparation]:
        from operations.services import read_changes

        return [row.preparation for row in read_changes(self.server).rows]


class DeployBackUpFirstRequestTests(ControllerConfigTestCase):
    """The Deploy confirm screen's Back up first is one guarded preparation (#407)."""

    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Laravel", ssh_alias="laravel.example.com")
        record_laravel_releases(self.server)
        self.url = f"/servers/{self.server.pk}/sites/alpha/backups/back-up-first/prepare/"

    def enable_backups(self) -> None:
        from backups.testing import record_backups

        record_backups(self.server, identifier="alpha", enabled=True)

    def test_a_post_prepares_a_full_capture_that_returns_to_deploy(self) -> None:
        self.enable_backups()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            response = self.client.post(self.url)
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].kind_slug, "back_up_full_site")
        self.assertEqual(rows[0].inputs, {"version": 1, "identifier": "alpha", "from_deploy": True})
        self.assertRedirects(response, f"/changes/{rows[0].pk}/")

    def test_without_backups_nothing_is_queued(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            response = self.client.post(self.url)
        self.assertRedirects(response, f"/servers/{self.server.pk}/sites/alpha/deployments/")
        self.assertEqual(self._rows(), [])

    def test_a_get_is_refused_and_uses_no_ssh(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)

    def test_a_viewer_cannot_prepare_a_backup(self) -> None:
        self.enable_backups()
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self._rows(), [])

    def test_a_post_without_its_csrf_token_is_refused(self) -> None:
        self.enable_backups()
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(self.url)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self._rows(), [])

    def _rows(self) -> list[ChangePreparation]:
        from operations.services import read_changes

        return [row.preparation for row in read_changes(self.server).rows]
