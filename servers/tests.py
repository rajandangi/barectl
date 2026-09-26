from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.test import Client, TestCase

from .models import Server


class InventoryTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user("operator")
        cls.server = Server.objects.create(
            name="Production", hostname="web.example.com", ssh_user="deploy"
        )

    def test_anonymous_user_must_log_in(self):
        self.assertRedirects(self.client.get("/"), "/accounts/login/?next=/")

    def test_inventory_requires_permission(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get("/").status_code, 403)

    def test_authorized_user_sees_inventory(self):
        self.user.user_permissions.add(Permission.objects.get(codename="view_server"))
        self.client.force_login(self.user)
        response = self.client.get("/")
        self.assertContains(response, "web.example.com")
        self.assertContains(response, "Not connected")

    def test_invalid_connection_metadata_is_rejected(self):
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

    def test_logout_requires_post_and_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        self.assertEqual(client.get("/accounts/logout/").status_code, 405)
        self.assertEqual(client.post("/accounts/logout/").status_code, 403)
