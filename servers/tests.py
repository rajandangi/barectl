import re
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, override
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, User
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from dashboard.tests import TEST_MANIFEST
from discovery.models import DiscoveryAttempt
from discovery.services import INTERRUPTED_FAILURE, STALE_AFTER

from .forms import ServerForm
from .models import Server

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
        """The rendered Discovery history section of a server page."""
        content = page.content.decode()
        return content[content.index('id="discovery-history"') :]


class InventoryTests(ControllerConfigTestCase):
    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Production", ssh_alias="web.example.com")
        Server.objects.create(name="Staging", ssh_alias="stage.example.net")

    def test_anonymous_user_must_log_in(self) -> None:
        self.assertRedirects(self.client.get("/"), "/accounts/login/?next=/")

    def test_anonymous_htmx_request_reloads_through_sign_in(self) -> None:
        response = self.client.get("/?q=web", headers=HTMX_FRAGMENT)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.headers["HX-Redirect"], "/accounts/login/?next=/%3Fq%3Dweb")
        self.assertNotContains(response, "web.example.com", status_code=204)

    def test_inventory_requires_permission(self) -> None:
        self.client.force_login(self.user)
        response = self.client.get("/")
        self.assertContains(response, "Access denied", status_code=403)
        self.assertNotContains(response, "web.example.com", status_code=403)
        # The page offers sign-out, but no navigation the account cannot use.
        self.assertContains(response, "Sign out", status_code=403)
        self.assertNotContains(response, "usa-nav__primary", status_code=403)

    def test_unauthorized_htmx_request_reloads_the_page(self) -> None:
        self.client.force_login(self.user)
        response = self.client.get("/?q=web", headers=HTMX_FRAGMENT)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.headers["HX-Refresh"], "true")
        self.assertNotContains(response, "web.example.com", status_code=403)

    def test_authorized_user_sees_inventory(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        response = self.client.get("/")
        self.assertContains(response, "web.example.com")
        self.assertContains(response, "stage.example.net")
        # Registration alone never claims connectivity.
        self.assertContains(response, "<td>Not verified</td>", count=2, html=True)
        self.assertNotContains(response, "Connected")
        self.assertContains(response, "2 servers.")
        # The banner states what discovery covers and that Barectl does not change servers.
        self.assertContains(response, "runs read-only discovery of the operating system")
        self.assertContains(response, "It does not change servers yet.")
        self.assertContains(response, 'aria-current="page"')
        self.assertContains(response, "data-uswds-fragment")
        # View-only accounts get no registration or edit actions.
        self.assertNotContains(response, "Add server")
        self.assertNotContains(response, "/edit/")
        self.assertIn("no-store", response.headers["Cache-Control"])

    def test_permitted_operators_see_registration_actions(self) -> None:
        self.grant("view_server", "add_server", "change_server")
        self.client.force_login(self.user)
        response = self.client.get("/")
        self.assertContains(response, '<a class="usa-button" href="/servers/add/">Add server</a>')
        self.assertContains(response, f'href="/servers/{self.server.pk}/edit/"')
        self.assertContains(response, '<span class="usa-sr-only"> Production</span>')
        self.assertNotContains(response, "/admin/")

    def test_aliases_removed_from_the_controller_are_flagged(self) -> None:
        self.write_config("Host stage.example.net\n  User deploy\n")
        self.grant_view()
        self.client.force_login(self.user)
        response = self.client.get("/")
        self.assertContains(response, "<td>SSH alias unavailable</td>", html=True)
        self.assertContains(response, "<td>Not verified</td>", html=True)

    def test_empty_inventory_explains_the_next_step(self) -> None:
        Server.objects.all().delete()
        self.grant_view()
        self.client.force_login(self.user)
        response = self.client.get("/")
        self.assertContains(response, "No servers yet")
        self.assertContains(response, "An operator with inventory permissions")
        self.assertNotContains(response, 'role="search"')

    def test_search_filters_the_full_page(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        response = self.client.get("/", {"q": "stage"})
        self.assertContains(response, "stage.example.net")
        self.assertNotContains(response, "web.example.com")
        self.assertContains(response, "1 of 2 servers match “stage”.")
        self.assertContains(response, 'value="stage"')

    def test_search_without_matches_offers_all_servers(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        response = self.client.get("/", {"q": "missing"})
        self.assertContains(response, "No matching servers")
        self.assertContains(response, 'href="/">Show all servers</a>', html=False)

    def test_invalid_search_is_reported_on_the_field(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        response = self.client.get("/", {"q": "x" * 101})
        self.assertContains(response, 'id="id_q_error"')
        self.assertContains(response, 'aria-invalid="true"')
        self.assertContains(response, "web.example.com")

    def test_htmx_search_returns_the_results_fragment(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        response = self.client.get("/", {"q": "web"}, headers=HTMX_FRAGMENT)
        content = response.content.decode()
        self.assertNotIn("<html", content)
        self.assertRegex(content, r'<div id="server-results"[^>]*data-uswds-fragment')
        self.assertIn("web.example.com", content)
        self.assertNotIn("stage.example.net", content)
        self.assertIn('<hx-partial hx-target="#server-results-status"', content)
        self.assertIn("1 of 2 servers match “web”.", content)
        vary = response.headers["Vary"]
        self.assertIn("HX-Request", vary)
        self.assertIn("HX-Request-Type", vary)

    def test_full_htmx_requests_receive_the_page(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        for headers in (
            {"HX-Request": "true", "HX-Request-Type": "full"},
            {"HX-Request": "true", "HX-History-Restore-Request": "true"},
        ):
            with self.subTest(headers=headers):
                response = self.client.get("/", headers=headers)
                self.assertContains(response, "<html")

    def test_htmx_requests_inherit_a_valid_csrf_header(self) -> None:
        self.grant_view()
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        page = client.get("/").content.decode()
        match = re.search(r"hx-headers:inherited='\{\"X-CSRFToken\": \"([^\"]+)\"\}'", page)
        self.assertIsNotNone(match, "The body must pass the CSRF token to HTMX requests.")
        token = match.group(1) if match else ""
        response = client.post("/accounts/logout/", headers={"X-CSRFToken": token})
        self.assertRedirects(response, "/accounts/login/", fetch_redirect_response=False)

    def test_aliases_that_are_patterns_or_commands_are_rejected(self) -> None:
        for value in ("-oProxyCommand=bad", "host;whoami", "web-*", "two words", "!web"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                Server(name="Test", ssh_alias=value).full_clean()

    def test_persistence_requires_a_unique_alias(self) -> None:
        for fields in ({"name": "No alias"}, {"name": "Duplicate", "ssh_alias": "web.example.com"}):
            with (
                self.subTest(fields=fields),
                self.assertRaises(IntegrityError),
                transaction.atomic(),
            ):
                Server.objects.create(**fields)

    def test_logout_requires_post_and_csrf(self) -> None:
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        self.assertEqual(client.get("/accounts/logout/").status_code, 405)
        self.assertEqual(client.post("/accounts/logout/").status_code, 403)

    def test_logout_ends_inventory_access(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        self.assertRedirects(
            self.client.post("/accounts/logout/"),
            "/accounts/login/",
            fetch_redirect_response=False,
        )
        self.assertRedirects(self.client.get("/?q=web"), "/accounts/login/?next=/%3Fq%3Dweb")


class RegistrationTests(ControllerConfigTestCase):
    def sign_in_with(self, *codenames: str) -> None:
        self.grant(*codenames)
        self.client.force_login(self.user)

    def test_anonymous_operators_must_sign_in(self) -> None:
        self.assertRedirects(
            self.client.get("/servers/add/"), "/accounts/login/?next=/servers/add/"
        )
        response = self.client.post(
            "/servers/add/", {"name": "Web", "ssh_alias": "web.example.com"}
        )
        self.assertRedirects(response, "/accounts/login/?next=/servers/add/")
        self.assertFalse(Server.objects.exists())

    def test_registration_requires_add_and_view_permissions(self) -> None:
        for codenames in ((), ("view_server",), ("add_server",)):
            with self.subTest(codenames=codenames):
                self.user.user_permissions.clear()
                self.sign_in_with(*codenames)
                self.assertEqual(self.client.get("/servers/add/").status_code, 403)
                response = self.client.post(
                    "/servers/add/", {"name": "Web", "ssh_alias": "web.example.com"}
                )
                self.assertContains(response, "Access denied", status_code=403)
                self.assertNotContains(response, "db-1", status_code=403)
        self.assertFalse(Server.objects.exists())

    def test_registration_requires_csrf(self) -> None:
        self.grant("view_server", "add_server")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post("/servers/add/", {"name": "Web", "ssh_alias": "web.example.com"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Server.objects.exists())

    def test_form_offers_only_configured_concrete_aliases(self) -> None:
        self.sign_in_with("view_server", "add_server")
        response = self.client.get("/servers/add/")
        self.assertContains(response, "<h1>Add server</h1>", html=True)
        self.assertContains(
            response, '<label class="usa-label" for="id_name">Name</label>', html=True
        )
        self.assertContains(
            response, '<label class="usa-label" for="id_ssh_alias">SSH alias</label>', html=True
        )
        options = re.findall(r'<option value="([^"]*)"', response.content.decode())
        self.assertEqual(options, ["", "db-1", "stage.example.net", "web.example.com"])
        # Patterns are explained, not offered.
        self.assertContains(response, "<code>*.internal</code>: A pattern, not a single server.")
        # Only a display name and an alias are accepted from the browser.
        controls = r'<(?:input|select|textarea|button)\b[^>]*?\sname="([^"]+)"'
        fields = set(re.findall(controls, response.content.decode()))
        self.assertEqual(fields, {"csrfmiddlewaretoken", "name", "ssh_alias"})
        self.assertNotContains(response, 'type="file"')
        self.assertContains(response, "Saving a new alias queues a connection check.")

    def test_valid_registration_persists_only_the_name_and_alias(self) -> None:
        self.sign_in_with("view_server", "add_server")
        config_before = self.ssh_config.read_bytes()
        response = self.client.post(
            "/servers/add/",
            {
                "name": "Web",
                "ssh_alias": "web.example.com",
                # Connection settings are not form fields and must be ignored.
                "hostname": "198.51.100.9",
                "ssh_user": "root",
                "ssh_port": "2222",
                "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----",
                "command": "id",
            },
        )
        server = Server.objects.get()
        self.assertRedirects(response, f"/servers/{server.pk}/", fetch_redirect_response=False)
        self.assertEqual((server.name, server.ssh_alias), ("Web", "web.example.com"))
        self.assertEqual(self.ssh_config.read_bytes(), config_before)
        page = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(
            page,
            "Registered Web with SSH alias web.example.com. Barectl queued a connection check.",
        )
        # Registration queues a check; it does not claim the server is reachable.
        self.assertContains(page, "Connection check queued")
        self.assertNotContains(page, "Verified")

    def test_invalid_selections_are_rejected_with_field_errors(self) -> None:
        self.sign_in_with("view_server", "add_server")
        cases = {
            "": "Choose the SSH alias for this server.",
            "*.internal": "Choose an alias that is currently configured on the controller host.",
            "missing": "Choose an alias that is currently configured on the controller host.",
            "web.example.com;id": (
                "Choose an alias that is currently configured on the controller host."
            ),
        }
        for alias, message in cases.items():
            with self.subTest(alias=alias):
                response = self.client.post("/servers/add/", {"name": "Web", "ssh_alias": alias})
                self.assertContains(response, message, count=2)
                self.assertContains(response, 'id="id_ssh_alias_error"')
                self.assertContains(
                    response, 'aria-describedby="id_ssh_alias_helptext id_ssh_alias_error"'
                )
                self.assertContains(response, 'aria-invalid="true"', count=1)
                self.assertContains(response, 'id="server-form-errors"')
        response = self.client.post("/servers/add/", {"name": "", "ssh_alias": "web.example.com"})
        self.assertContains(response, "Enter a name for this server.", count=2)
        self.assertFalse(Server.objects.exists())

    def test_alias_removed_after_the_form_was_shown_is_revalidated(self) -> None:
        self.sign_in_with("view_server", "add_server")
        self.assertContains(self.client.get("/servers/add/"), '<option value="db-1"')
        self.write_config("Host web.example.com\n")
        response = self.client.post("/servers/add/", {"name": "Database", "ssh_alias": "db-1"})
        self.assertContains(response, "currently configured on the controller host", count=2)
        self.assertFalse(Server.objects.exists())

    def test_an_alias_can_register_only_one_server(self) -> None:
        Server.objects.create(name="Web", ssh_alias="web.example.com")
        self.sign_in_with("view_server", "add_server")
        response = self.client.post(
            "/servers/add/", {"name": "Other", "ssh_alias": "web.example.com"}
        )
        self.assertContains(response, "Another server is already registered with this alias.")
        response = self.client.post("/servers/add/", {"name": "Web", "ssh_alias": "db-1"})
        self.assertContains(response, "Another server already uses this name.")
        self.assertEqual(Server.objects.count(), 1)

    def test_alias_taken_after_validation_is_reported_not_a_server_error(self) -> None:
        self.sign_in_with("view_server", "add_server")
        form_valid = ServerForm.is_valid

        def race(form: ServerForm) -> bool:
            valid = form_valid(form)
            # Another request registers the same alias between validation and saving.
            Server.objects.create(name="Concurrent", ssh_alias="db-1")
            return valid

        with mock.patch.object(ServerForm, "is_valid", race):
            response = self.client.post("/servers/add/", {"name": "Web", "ssh_alias": "db-1"})
        self.assertContains(response, "Another server was saved with this name or alias.")
        self.assertEqual(list(Server.objects.values_list("name", flat=True)), ["Concurrent"])

    def test_configuration_without_usable_aliases_explains_the_fix(self) -> None:
        self.sign_in_with("view_server", "add_server")
        self.write_config("Host *.internal web-*\n  User ops\n")
        response = self.client.get("/servers/add/")
        self.assertContains(response, "No usable SSH aliases")
        self.assertContains(response, f"{self.ssh_config} has no Host entry that names a single")
        self.assertContains(response, "<code>web-*</code>: A pattern, not a single server.")
        self.assertEqual(re.findall(r'<option value="([^"]*)"', response.content.decode()), [""])

    def test_unusable_configuration_is_reported_without_its_content(self) -> None:
        self.sign_in_with("view_server", "add_server")
        cases = {
            "Host web\n  IdentityFile secret-key-path extra\n  broken-line\n": "cannot parse",
            'Host web\nMatch exec "id"\n  User x\n': "uses Match blocks",
        }
        for text, message in cases.items():
            with self.subTest(message=message):
                self.write_config(text)
                response = self.client.get("/servers/add/")
                self.assertContains(response, "SSH configuration unavailable")
                self.assertContains(response, message)
                self.assertNotContains(response, "secret-key-path")
                self.assertNotContains(response, "broken-line")
        self.ssh_config.unlink()
        response = self.client.get("/servers/add/")
        self.assertContains(response, f"No SSH configuration file exists at {self.ssh_config}.")
        response = self.client.post("/servers/add/", {"name": "Web", "ssh_alias": "web"})
        self.assertContains(response, "currently configured on the controller host", count=2)
        self.assertFalse(Server.objects.exists())


class EditTests(ControllerConfigTestCase):
    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def edit_url(self, server: Server | None = None) -> str:
        return f"/servers/{(server or self.server).pk}/edit/"

    def test_editing_requires_change_and_view_permissions(self) -> None:
        self.assertRedirects(
            self.client.get(self.edit_url()), f"/accounts/login/?next={self.edit_url()}"
        )
        for codenames in (("view_server",), ("view_server", "add_server"), ("change_server",)):
            with self.subTest(codenames=codenames):
                self.user.user_permissions.clear()
                self.grant(*codenames)
                self.client.force_login(self.user)
                response = self.client.post(self.edit_url(), {"name": "X", "ssh_alias": "db-1"})
                self.assertEqual(response.status_code, 403)
        self.server.refresh_from_db()
        self.assertEqual((self.server.name, self.server.ssh_alias), ("Web", "web.example.com"))

    def test_editing_requires_csrf(self) -> None:
        self.grant("view_server", "change_server")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(self.edit_url(), {"name": "X", "ssh_alias": "db-1"})
        self.assertEqual(response.status_code, 403)

    def test_operator_can_rename_and_change_the_alias(self) -> None:
        self.grant("view_server", "change_server")
        self.client.force_login(self.user)
        page = self.client.get(self.edit_url())
        self.assertContains(page, "<h1>Edit Web</h1>", html=True)
        self.assertContains(
            page, '<option value="web.example.com" selected>web.example.com</option>', html=True
        )
        self.assertContains(page, 'value="Web"')
        response = self.client.post(self.edit_url(), {"name": "Primary", "ssh_alias": "db-1"})
        self.assertRedirects(response, f"/servers/{self.server.pk}/", fetch_redirect_response=False)
        self.server.refresh_from_db()
        self.assertEqual((self.server.name, self.server.ssh_alias), ("Primary", "db-1"))
        self.assertContains(
            self.client.get(self.edit_url()), "Saved Primary with SSH alias db-1. Barectl queued"
        )

    def test_removed_alias_must_be_restored_or_replaced(self) -> None:
        self.grant("view_server", "change_server")
        self.client.force_login(self.user)
        self.write_config("Host db-1\n")
        page = self.client.get(self.edit_url())
        self.assertContains(page, "SSH alias unavailable")
        self.assertContains(page, "The alias <code>web.example.com</code> is no longer")
        self.assertNotRegex(page.content.decode(), r'<option value="[^"]+" selected')
        # Renaming alone would keep an alias that no longer exists.
        response = self.client.post(
            self.edit_url(), {"name": "Renamed", "ssh_alias": "web.example.com"}
        )
        self.assertContains(response, "currently configured on the controller host", count=2)
        self.assertContains(response, "<h1>Edit Web</h1>", html=True)
        self.server.refresh_from_db()
        self.assertEqual(self.server.name, "Web")

    def test_unknown_servers_are_not_found(self) -> None:
        self.grant("view_server", "change_server")
        self.client.force_login(self.user)
        self.assertEqual(self.client.get("/servers/999/edit/").status_code, 404)

    def test_edit_of_a_concurrently_removed_server_does_not_recreate_it(self) -> None:
        self.grant("view_server", "change_server")
        self.client.force_login(self.user)
        form_valid = ServerForm.is_valid

        def race(form: ServerForm) -> bool:
            valid = form_valid(form)
            # Another request removes the server between loading and saving it.
            Server.objects.filter(pk=self.server.pk).delete()
            return valid

        for alias in ("web.example.com", "db-1"):
            with self.subTest(alias=alias), mock.patch.object(ServerForm, "is_valid", race):
                response = self.client.post(
                    self.edit_url(), {"name": "Renamed", "ssh_alias": alias}
                )
                self.assertEqual(response.status_code, 404)
                self.assertFalse(Server.objects.exists())
            self.server.save(force_insert=True)


class ActivityTests(ControllerConfigTestCase):
    """The cross-server Activity view and each server's history, through requests."""

    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Production", ssh_alias="web.example.com")

    def record_attempt(
        self,
        *,
        status: DiscoveryAttempt.Status = DiscoveryAttempt.Status.QUEUED,
        failure: str = "",
        minutes_ago: float = 0.0,
    ) -> DiscoveryAttempt:
        """Create an attempt recorded minutes ago; finished unless it is still active."""
        attempt = DiscoveryAttempt.objects.create(
            server=self.server, ssh_alias=self.server.ssh_alias
        )
        recorded = timezone.now() - timedelta(minutes=minutes_ago)
        started = recorded if status == DiscoveryAttempt.Status.RUNNING else None
        finished = (
            recorded
            if status in (DiscoveryAttempt.Status.SUCCEEDED, DiscoveryAttempt.Status.FAILED)
            else None
        )
        # queued_at is auto_now_add; explicit values make the recorded order definite.
        DiscoveryAttempt.objects.filter(pk=attempt.pk).update(
            status=status,
            queued_at=recorded,
            started_at=started,
            finished_at=finished,
            failure=failure,
        )
        attempt.refresh_from_db()
        return attempt

    def test_anonymous_operators_must_sign_in(self) -> None:
        self.assertRedirects(self.client.get("/activity/"), "/accounts/login/?next=/activity/")

    def test_activity_requires_view_permission(self) -> None:
        self.client.force_login(self.user)
        response = self.client.get("/activity/")
        self.assertContains(response, "Access denied", status_code=403)
        self.assertNotContains(response, "web.example.com", status_code=403)
        # The page offers sign-out, but no navigation the account cannot use.
        self.assertNotContains(response, "usa-nav__primary", status_code=403)

    def test_htmx_activity_requests_follow_the_authorized_flow(self) -> None:
        response = self.client.get("/activity/", headers=HTMX_FRAGMENT)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.headers["HX-Redirect"], "/accounts/login/?next=/activity/")
        self.client.force_login(self.user)
        response = self.client.get("/activity/", headers=HTMX_FRAGMENT)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.headers["HX-Refresh"], "true")
        self.assertNotContains(response, "web.example.com", status_code=403)

    def test_navigation_offers_servers_and_activity(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        inventory = self.client.get("/")
        self.assertContains(
            inventory,
            '<a href="/activity/" class="usa-nav-link"> <span>Activity</span> </a>',
            html=True,
        )
        page = self.client.get("/activity/")
        self.assertContains(page, "<h1>Activity</h1>", html=True)
        self.assertContains(
            page,
            '<a href="/activity/" class="usa-nav-link usa-current" aria-current="page">'
            " <span>Activity</span> </a>",
            html=True,
        )
        self.assertNotContains(
            page,
            '<a href="/" class="usa-nav-link usa-current" aria-current="page">'
            " <span>Servers</span> </a>",
            html=True,
        )

    def test_attempts_are_shown_newest_first_with_their_outcomes(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        self.record_attempt(status=DiscoveryAttempt.Status.SUCCEEDED, minutes_ago=120)
        self.record_attempt(
            status=DiscoveryAttempt.Status.FAILED,
            minutes_ago=1,
            failure="The controller host does not trust the host key presented.",
        )
        response = self.client.get("/activity/")
        content = response.content.decode()
        self.assertContains(response, "The controller host does not trust the host key presented.")
        self.assertLess(content.index("Failed"), content.index("Succeeded"))
        self.assertContains(response, "Snapshot collected")

    def test_queued_and_running_attempts_are_visible(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        other = Server.objects.create(name="Staging", ssh_alias="stage.example.net")
        self.record_attempt(status=DiscoveryAttempt.Status.RUNNING, minutes_ago=2)
        # One active attempt per server, so the queued one runs on another server.
        DiscoveryAttempt.objects.create(server=other, ssh_alias=other.ssh_alias)
        response = self.client.get("/activity/")
        content = response.content.decode()
        self.assertLess(content.index("Queued"), content.index("Running"))
        # Activity reports attempt outcomes, not each server's derived status.
        self.assertEqual(content.count("Connection check"), 0)

    def test_activity_claims_no_live_status(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        self.record_attempt(status=DiscoveryAttempt.Status.SUCCEEDED, minutes_ago=60)
        response = self.client.get("/activity/")
        self.assertContains(response, "not live status")

    def test_snapshot_collection_time_is_shown_only_where_one_exists(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        self.record_attempt(
            status=DiscoveryAttempt.Status.FAILED, minutes_ago=5, failure=INTERRUPTED_FAILURE
        )
        response = self.client.get("/activity/")
        self.assertContains(response, "stopped before finishing")
        # A failed attempt publishes no snapshot, so only its recorded and finished
        # times are shown and no collection time is claimed.
        self.assertEqual(response.content.decode().count("<time"), 2)

    def test_visiting_activity_recovers_interrupted_attempts(self) -> None:
        attempt = self.record_attempt(
            status=DiscoveryAttempt.Status.RUNNING,
            minutes_ago=(STALE_AFTER + timedelta(minutes=2)).total_seconds() / 60,
        )
        self.grant_view()
        self.client.force_login(self.user)
        response = self.client.get("/activity/")
        self.assertContains(response, "stopped before finishing")
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertEqual(attempt.failure, INTERRUPTED_FAILURE)

    def test_server_history_lists_attempts_newest_first(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        self.record_attempt(status=DiscoveryAttempt.Status.SUCCEEDED, minutes_ago=60)
        self.record_attempt(
            status=DiscoveryAttempt.Status.FAILED,
            minutes_ago=1,
            failure="The controller host does not trust the host key presented.",
        )
        page = self.client.get(f"/servers/{self.server.pk}/")
        history = self.history_of(page)
        self.assertIn("Discovery history", history)
        self.assertIn("The controller host does not trust the host key presented.", history)
        self.assertLess(history.index("Failed"), history.index("Succeeded"))

    def test_server_history_without_attempts_says_so(self) -> None:
        self.grant_view()
        self.client.force_login(self.user)
        history = self.history_of(self.client.get(f"/servers/{self.server.pk}/"))
        self.assertIn("No discovery attempts yet.", history)
        self.assertNotIn("<table", history)
