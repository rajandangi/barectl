import re
from typing import ClassVar, override

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, User
from django.core.exceptions import ValidationError
from django.test import Client, TestCase, override_settings

from dashboard.tests import TEST_MANIFEST

from .models import Server

HTMX_FRAGMENT = {"HX-Request": "true", "HX-Request-Type": "partial"}


@override_settings(VITE_MANIFEST_PATH=TEST_MANIFEST, VITE_DEV_SERVER_URL="")
class InventoryTests(TestCase):
    user: ClassVar[User]
    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.user = get_user_model().objects.create_user("operator")
        cls.server = Server.objects.create(
            name="Production", hostname="web.example.com", ssh_user="deploy"
        )
        Server.objects.create(name="Staging", hostname="stage.example.net", ssh_user="deploy")

    def grant_view(self) -> None:
        self.user.user_permissions.add(Permission.objects.get(codename="view_server"))

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
        self.assertContains(response, "Not connected")
        self.assertContains(response, "2 servers.")
        self.assertContains(response, 'aria-current="page"')
        self.assertContains(response, "data-uswds-fragment")
        # Admin forms remain the add workflow for staff until the dashboard replaces them.
        self.assertNotContains(response, "Add server")
        self.assertIn("no-store", response.headers["Cache-Control"])

    def test_staff_with_add_permission_can_reach_the_admin_form(self) -> None:
        self.grant_view()
        self.user.user_permissions.add(Permission.objects.get(codename="add_server"))
        self.user.is_staff = True
        self.user.save()
        self.client.force_login(self.user)
        self.assertContains(self.client.get("/"), 'href="/admin/servers/server/add/"')

    def test_empty_inventory_explains_the_next_step(self) -> None:
        Server.objects.all().delete()
        self.grant_view()
        self.client.force_login(self.user)
        response = self.client.get("/")
        self.assertContains(response, "No servers yet")
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

    def test_invalid_connection_metadata_is_rejected(self) -> None:
        for field, value in [
            ("ssh_port", 0),
            ("ssh_port", 65536),
            ("hostname", "-oProxyCommand=bad"),
            ("hostname", "host;whoami"),
            ("ssh_user", "root;id"),
        ]:
            with self.subTest(field=field, value=value):
                server = Server(name="Test", hostname="web.example.com", ssh_user="deploy")
                setattr(server, field, value)
                with self.assertRaises(ValidationError):
                    server.full_clean()

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
