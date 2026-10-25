"""The four-place header and installation Settings (docs/dashboard-workflows.md, #362)."""

import tempfile
from pathlib import Path
from unittest import mock

from django.test import override_settings
from paramiko import ECDSAKey

from servers.testing import ControllerConfigTestCase


class HeaderTests(ControllerConfigTestCase):
    def test_each_place_requires_sign_in(self) -> None:
        for path in ("/", "/sites/", "/activity/", "/settings/"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 302)
                self.assertIn("/accounts/login/", response["Location"])

    def test_the_current_place_is_announced_on_every_top_level_page(self) -> None:
        self.grant("view_server", "view_siteobservation")
        self.client.force_login(self.user)
        for path, label in (
            ("/", "Servers"),
            ("/sites/", "Sites"),
            ("/activity/", "Activity"),
            ("/settings/", "Settings"),
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, 'aria-current="page"')
                self.assertContains(response, f"<span>{label}</span>")

    def test_opening_the_top_level_pages_makes_no_ssh_connection(self) -> None:
        self.grant("view_server", "view_siteobservation")
        self.client.force_login(self.user)
        with mock.patch("discovery.ssh.connect_alias") as connect:
            for path in ("/", "/sites/", "/activity/", "/settings/"):
                self.client.get(path)
        connect.assert_not_called()


class InstallationSettingsTests(ControllerConfigTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.key_file = directory / "id_ed25519"
        cls.key = ECDSAKey.generate()
        cls.key.write_private_key_file(str(cls.key_file))
        cls.enterClassContext(override_settings(SSH_APPROVED_KEYS={"deploy": str(cls.key_file)}))

    def test_settings_show_the_account_keys_worker_and_version(self) -> None:
        self.grant("view_server")
        self.client.force_login(self.user)
        response = self.client.get("/settings/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Signed in as operator")
        self.assertContains(response, "python manage.py changepassword operator")
        self.assertContains(response, "deploy")
        self.assertContains(response, f"{self.key.get_name()} {self.key.get_base64()}")
        self.assertNotContains(response, str(self.key_file))
        self.assertContains(response, "python manage.py db_worker")
        self.assertContains(response, "Barectl")
        self.assertContains(response, "PHP")

    def test_settings_need_only_sign_in(self) -> None:
        self.client.force_login(self.user)
        response = self.client.get("/settings/")
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Add server")

    def test_settings_without_approved_keys_explain_the_choice(self) -> None:
        self.client.force_login(self.user)
        with override_settings(SSH_APPROVED_KEYS={}):
            response = self.client.get("/settings/")
        self.assertContains(response, "No approved key files are configured")


class EmptyStateTests(ControllerConfigTestCase):
    def test_empty_servers_and_sites_offer_add_server(self) -> None:
        self.grant("view_server", "view_siteobservation", "add_server")
        self.client.force_login(self.user)
        for path in ("/", "/sites/"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertContains(response, "Add your first server")
                self.assertContains(response, "fresh Ubuntu 26.04")
                self.assertContains(response, ">Add server</a>")

    def test_empty_activity_lists_nothing(self) -> None:
        self.grant("view_server")
        self.client.force_login(self.user)
        response = self.client.get("/activity/")
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Add server")

    def test_a_viewer_without_add_permission_sees_no_control(self) -> None:
        self.grant("view_server")
        self.client.force_login(self.user)
        response = self.client.get("/")
        self.assertContains(response, "Add your first server")
        self.assertNotContains(response, 'class="usa-button" href="/servers/add/"')

    def test_sites_need_the_observation_permission(self) -> None:
        self.grant("view_server")
        self.client.force_login(self.user)
        self.assertEqual(self.client.get("/sites/").status_code, 403)
        self.assertEqual(self.client.get("/settings/").status_code, 200)


class SearchThresholdTests(ControllerConfigTestCase):
    def test_search_appears_only_above_ten_servers(self) -> None:
        from servers.models import Server

        self.grant("view_server")
        self.client.force_login(self.user)
        Server.objects.bulk_create(
            Server(name=f"Web {index}", ssh_alias=f"web-{index}.example.com") for index in range(10)
        )
        self.assertNotContains(self.client.get("/"), "Search servers")
        Server.objects.create(name="Web ten", ssh_alias="web-ten.example.com")
        self.assertContains(self.client.get("/"), "Search servers")
