import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, override

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, User
from django.test import TestCase, override_settings

from dashboard.testing import TEST_MANIFEST

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse

HTMX_FRAGMENT = {"HX-Request": "true", "HX-Request-Type": "partial"}
SSH_CONFIG = """\
Host web.example.com
  HostName 203.0.113.10
  User deploy
Host stage.example.net db-1
  User deploy
Host *.internal
  User ops
"""


class ControllerConfigTestCase(TestCase):
    """Runs against a temporary controller SSH configuration, never the real one."""

    user: ClassVar[User]
    ssh_config: ClassVar[Path]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.ssh_config = directory / "config"
        cls.enterClassContext(
            override_settings(
                SSH_CONFIG_PATH=str(cls.ssh_config),
                VITE_MANIFEST_PATH=TEST_MANIFEST,
                VITE_DEV_SERVER_URL="",
            )
        )
        super().setUpClass()

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.user = get_user_model().objects.create_user("operator")

    @override
    def setUp(self) -> None:
        self.write_config(SSH_CONFIG)

    def write_config(self, text: str) -> None:
        self.ssh_config.write_text(text, encoding="utf-8")

    def grant(self, *codenames: str) -> None:
        for codename in codenames:
            self.user.user_permissions.add(Permission.objects.get(codename=codename))

    def grant_view(self) -> None:
        self.grant("view_server")

    def history_of(self, page: _MonkeyPatchedWSGIResponse) -> str:
        content = page.content.decode()
        return content[content.index('id="discovery-history"') :]
