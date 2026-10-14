import tempfile
from pathlib import Path
from typing import override

from django.test import override_settings
from paramiko import ECDSAKey

from .testing import ControllerConfigTestCase


class ApprovedKeyJourneyTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.key = ECDSAKey.generate()
        self.path = self.directory / "private-key"
        self.key.write_private_key_file(str(self.path))
        self.enterContext(override_settings(SSH_APPROVED_KEYS={"production": str(self.path)}))
        self.grant("view_server", "add_server", "add_discoveryattempt")
        self.client.force_login(self.user)

    def test_editor_sees_public_key_without_private_contents_or_path(self) -> None:
        response = self.client.get("/servers/add/")
        self.assertContains(response, self.key.get_base64())
        self.assertContains(response, "authorized_keys")
        self.assertNotContains(response, str(self.path))
        self.assertNotContains(response, "PRIVATE KEY")

    def test_editor_saves_an_approved_reference_with_captured_public_identity(self) -> None:
        response = self.client.post(
            "/servers/add/",
            {"name": "Cloud", "address": "cloud.example", "credential_reference": "production"},
        )
        self.assertEqual(response.status_code, 302)
        from discovery.models import DiscoveryAttempt

        definition = DiscoveryAttempt.objects.get().connection
        self.assertIsNotNone(definition)
        if definition is None:
            self.fail("The selected credential was not captured.")
        self.assertEqual(definition.mode, "keyfile")
        self.assertEqual(definition.credential_reference, "production")
        self.assertEqual(
            definition.credential_public_key, f"{self.key.get_name()} {self.key.get_base64()}"
        )

    def test_unlisted_reference_is_refused_without_path_disclosure(self) -> None:
        response = self.client.post(
            "/servers/add/",
            {"name": "Cloud", "address": "cloud.example", "credential_reference": str(self.path)},
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, str(self.path))
        self.assertContains(response, "Choose a currently approved key")

    def test_catalogue_is_unavailable_to_server_viewers(self) -> None:
        self.user.user_permissions.clear()
        self.grant("view_server")
        response = self.client.get("/servers/add/")
        self.assertEqual(response.status_code, 403)
        self.assertNotContains(response, self.key.get_base64(), status_code=403)

    def test_missing_and_protected_files_have_clear_sanitized_states(self) -> None:
        self.key.write_private_key_file(str(self.path), password="fixture-password")  # noqa: S106
        protected = self.client.get("/servers/add/")
        self.assertContains(protected, "passphrase-protected")
        self.assertContains(protected, "choose agent mode")
        self.assertNotContains(protected, str(self.path))
        self.path.unlink()
        missing = self.client.get("/servers/add/")
        self.assertContains(missing, "credential is unavailable")
        self.assertNotContains(missing, str(self.path))
        with override_settings(SSH_APPROVED_KEYS={}):
            self.assertContains(self.client.get("/servers/add/"), "No approved key files")
