import re
import tempfile
from pathlib import Path
from typing import ClassVar, override
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, User
from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, models, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import Client, TestCase, TransactionTestCase, override_settings

from dashboard.tests import TEST_MANIFEST

from .forms import ServerForm
from .models import Server

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

    def test_persistence_requires_a_unique_alias_or_migrated_details(self) -> None:
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
        self.assertEqual(server.legacy_connection, "")
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


class ReconciliationTests(ControllerConfigTestCase):
    """Records migrated from explicit connection details before alias registration."""

    legacy: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.legacy = Server.objects.create(
            name="Legacy", legacy_connection="deploy@web.example.com:22"
        )

    def test_unmatched_records_stay_visible_and_cannot_connect(self) -> None:
        self.grant("view_server", "change_server")
        self.client.force_login(self.user)
        response = self.client.get("/")
        self.assertContains(
            response,
            f"<th scope='row'><a href='/servers/{self.legacy.pk}/'>Legacy</a></th>",
            html=True,
        )
        self.assertContains(response, "<td>Needs SSH alias</td>", html=True)
        self.assertContains(response, "1 server needs an SSH alias.")
        self.assertTrue(Server.objects.get().needs_alias)

    def test_matching_hostname_is_not_selected_as_the_alias(self) -> None:
        self.grant("view_server", "change_server")
        self.client.force_login(self.user)
        page = self.client.get(f"/servers/{self.legacy.pk}/edit/")
        self.assertContains(page, "Choose an SSH alias")
        self.assertContains(page, "<code>deploy@web.example.com:22</code>")
        # A Host entry named like the old hostname is offered, never preselected.
        self.assertContains(page, '<option value="web.example.com"')
        self.assertNotRegex(page.content.decode(), r'<option value="[^"]+" selected')

    def test_choosing_an_alias_reconciles_the_record(self) -> None:
        self.grant("view_server", "change_server")
        self.client.force_login(self.user)
        response = self.client.post(
            f"/servers/{self.legacy.pk}/edit/", {"name": "Legacy", "ssh_alias": "web.example.com"}
        )
        self.assertRedirects(response, f"/servers/{self.legacy.pk}/")
        server = Server.objects.get()
        self.assertEqual((server.ssh_alias, server.legacy_connection), ("web.example.com", ""))
        self.assertFalse(server.needs_alias)
        self.assertNotContains(self.client.get("/"), "needs an SSH alias")


class ConnectionMetadataMigrationTests(TransactionTestCase):
    before: ClassVar[list[tuple[str, str]]] = [("servers", "0001_initial")]
    after: ClassVar[list[tuple[str, str]]] = [("servers", "0002_ssh_alias")]

    @override
    def tearDown(self) -> None:
        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes())
        super().tearDown()

    def historical_servers(self, target: list[tuple[str, str]]) -> models.Manager[models.Model]:
        executor = MigrationExecutor(connection)
        executor.migrate(target)
        model: type[models.Model] = executor.loader.project_state(target).apps.get_model(
            "servers", "Server"
        )
        return model._default_manager

    def test_explicit_details_are_kept_for_reconciliation_not_used_as_aliases(self) -> None:
        old = self.historical_servers(self.before)
        old.create(name="Web", hostname="web.example.com", ssh_user="deploy", ssh_port=2222)
        old.create(name="Alias", hostname="web", ssh_user="deploy", ssh_port=22)
        new = self.historical_servers(self.after)
        rows = set(new.values_list("name", "ssh_alias", "legacy_connection"))
        self.assertEqual(
            rows,
            {
                ("Web", "", "deploy@web.example.com:2222"),
                # Even a value that looks like an alias waits for the operator.
                ("Alias", "", "deploy@web:22"),
            },
        )

    def test_reversing_restores_explicit_details(self) -> None:
        self.historical_servers(self.before).create(
            name="Web", hostname="web.example.com", ssh_user="deploy", ssh_port=2222
        )
        new = self.historical_servers(self.after)
        new.create(name="Reconciled", ssh_alias="db-1")
        old = self.historical_servers(self.before)
        rows = set(old.values_list("name", "ssh_user", "hostname", "ssh_port"))
        self.assertEqual(
            rows, {("Web", "deploy", "web.example.com", 2222), ("Reconciled", "", "db-1", 22)}
        )
