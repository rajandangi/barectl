from django.http import QueryDict
from django.test import TestCase

from discovery.models import DiscoveryAttempt

from .forms import ServerForm
from .models import Server
from .ssh_config import AliasCatalog
from .testing import ControllerConfigTestCase


class SavedConnectionFormTests(TestCase):
    def test_operator_enters_address_without_an_ssh_alias(self) -> None:
        data = QueryDict("name=Cloud&address=2001:db8::1&username=root&port=2222")
        form = ServerForm(
            data,
            catalog=AliasCatalog(source="fixture"),
        )
        self.assertTrue(form.is_valid(), form.errors)
        server = form.save(commit=False)
        self.assertEqual(
            (server.address, server.username, server.port), ("2001:db8::1", "root", 2222)
        )

    def test_documented_user_address_and_port_bounds(self) -> None:
        valid = (
            {"address": "cloud.example", "username": ".deploy", "port": "65535"},
            {"address": "127.0.0.1", "username": "u" * 64, "port": "1"},
            {"address": ".".join(("a" * 63, "a" * 63, "a" * 63, "a" * 61))},
        )
        invalid = (
            {"address": "a" * 64 + ".example"},
            {"address": ".".join(("a" * 63,) * 4)},
            {"address": "999.2.3.4"},
            {"username": "-root"},
            {"username": "u" * 65},
            {"username": "root;id"},
            {"port": "0"},
            {"port": "65536"},
        )
        for fields, accepted in ((valid, True), (invalid, False)):
            for values in fields:
                with self.subTest(values=values):
                    data = QueryDict("", mutable=True)
                    data.update({"name": "Cloud", "address": "cloud.example", **values})
                    form = ServerForm(data, catalog=AliasCatalog(source="fixture"))
                    self.assertEqual(form.is_valid(), accepted, form.errors)


class SavedConnectionJourneyTests(ControllerConfigTestCase):
    def test_save_and_check_captures_an_immutable_target(self) -> None:
        self.grant("view_server", "add_server", "add_discoveryattempt")
        self.client.force_login(self.user)
        response = self.client.post(
            "/servers/add/",
            {
                "name": "Cloud",
                "address": "cloud.example",
                "username": "root",
                "port": "2222",
            },
        )
        self.assertEqual(response.status_code, 302)
        attempt = DiscoveryAttempt.objects.get()
        if attempt.connection is None:
            self.fail("The queued check did not capture its connection definition.")
        self.assertEqual(attempt.connection.address, "cloud.example")
        self.assertEqual(attempt.connection.revision, 1)
        self.assertContains(self.client.get(response.headers["Location"]), "cloud.example")

    def test_address_errors_keep_the_other_valid_values(self) -> None:
        self.grant("view_server", "add_server", "add_discoveryattempt")
        self.client.force_login(self.user)
        for address in (
            "https://example.com",
            "root@example.com",
            "example.com:22",
            "fe80::1%eth0",
            "é.example",
        ):
            with self.subTest(address=address):
                response = self.client.post(
                    "/servers/add/",
                    {
                        "name": "Cloud",
                        "address": address,
                        "username": "operator",
                        "port": "2222",
                    },
                )
                self.assertContains(response, 'id="id_address_error"')
                self.assertContains(response, 'value="operator"')
                self.assertContains(response, 'value="2222"')
        self.assertEqual(DiscoveryAttempt.objects.count(), 0)

    def test_render_and_validation_never_resolve_dns(self) -> None:
        from unittest import mock

        self.grant("view_server", "add_server", "add_discoveryattempt")
        self.client.force_login(self.user)
        self.write_config(
            "Host cloud\n  CanonicalizeHostname yes\n  CanonicalDomains example.com\n"
        )
        with (
            mock.patch("socket.getaddrinfo", side_effect=AssertionError("DNS during form request")),
            mock.patch(
                "socket.gethostbyname", side_effect=AssertionError("DNS during form request")
            ),
            mock.patch("socket.getfqdn", side_effect=AssertionError("DNS during form request")),
        ):
            self.assertEqual(self.client.get("/servers/add/").status_code, 200)
            self.assertEqual(
                self.client.post(
                    "/servers/add/",
                    {
                        "name": "Cloud",
                        "address": "cloud.example",
                    },
                ).status_code,
                302,
            )

    def test_repeated_save_and_check_shares_the_active_check(self) -> None:
        self.grant("view_server", "add_server", "add_discoveryattempt")
        self.client.force_login(self.user)
        data = {"name": "Cloud", "address": "cloud.example"}
        first = self.client.post("/servers/add/", data)
        second = self.client.post("/servers/add/", data)
        self.assertEqual(second.status_code, 302)
        self.assertEqual(first.headers["Location"], second.headers["Location"])
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)

    def test_registration_permission_is_rechecked_before_worker_dispatch(self) -> None:
        from discovery.fakes import run_worker

        self.grant("view_server", "add_server", "add_discoveryattempt")
        self.client.force_login(self.user)
        self.client.post("/servers/add/", {"name": "Cloud", "address": "cloud.example"})
        self.user.user_permissions.clear()
        run_worker()
        attempt = DiscoveryAttempt.objects.get()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("Permission", attempt.failure)

    def test_status_poll_updates_the_banner_and_announces_a_change(self) -> None:
        from servers.testing import HTMX_FRAGMENT

        self.grant("view_server", "add_server", "add_discoveryattempt")
        self.client.force_login(self.user)
        self.client.post("/servers/add/", {"name": "Cloud", "address": "cloud.example"})
        server = Server.objects.get()
        page = self.client.get(
            f"/servers/{server.pk}/status/", {"shown": "RUNNING"}, headers=HTMX_FRAGMENT
        )
        self.assertContains(page, 'id="connection-status"')
        self.assertContains(page, "Checking…")
        self.assertContains(page, "Checking the connection…")
        self.assertContains(page, 'hx-target="#next-action-region"')
        self.assertContains(page, "Connection check queued.")
        # A poll that shows the same state does not repeat the announcement.
        page = self.client.get(
            f"/servers/{server.pk}/status/", {"shown": "QUEUED"}, headers=HTMX_FRAGMENT
        )
        self.assertNotContains(page, "Connection check queued.")
        # Opening the poll URL as a page queues nothing and redirects to the server page.
        self.assertRedirects(
            self.client.get(f"/servers/{server.pk}/status/"), f"/servers/{server.pk}/"
        )
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)

    def test_viewing_the_registered_pages_does_not_request_remote_work(self) -> None:
        self.grant("view_server", "add_server", "add_discoveryattempt")
        self.client.force_login(self.user)
        response = self.client.post("/servers/add/", {"name": "Cloud", "address": "cloud.example"})
        for _ in range(2):
            self.client.get(response.headers["Location"])
            self.client.get("/")
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)

    def test_permission_revocation_during_read_prevents_publication(self) -> None:
        from django.contrib.auth.models import Permission

        from discovery.fakes import FakeServer, run_worker
        from discovery.ssh import CommandResult

        self.grant("view_server", "add_server", "add_discoveryattempt")
        self.client.force_login(self.user)
        response = self.client.post("/servers/add/", {"name": "Cloud", "address": "cloud.example"})
        revoked = False

        def revoke_during_read(command: str) -> CommandResult | None:
            nonlocal revoked
            if not revoked:
                self.user.user_permissions.remove(Permission.objects.get(codename="add_server"))
                revoked = True
            return None

        with FakeServer(answers=[revoke_during_read]).substituted():
            run_worker()
        attempt = DiscoveryAttempt.objects.get()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        page = self.client.get(response.headers["Location"])
        self.assertContains(page, "Permission to check this server is no longer available")
        self.assertNotContains(page, "Discovery evidence")

    def test_old_captured_revision_is_refused_before_dispatch(self) -> None:
        from discovery.fakes import run_worker

        from .models import Server

        self.grant("view_server", "add_server", "add_discoveryattempt")
        self.client.force_login(self.user)
        self.client.post("/servers/add/", {"name": "Cloud", "address": "cloud.example"})
        Server.objects.update(connection_revision=2)
        run_worker()
        self.assertIn("connection changed", DiscoveryAttempt.objects.get().failure)

    def test_alias_change_cannot_redirect_an_already_queued_check(self) -> None:
        from discovery.fakes import FakeServer, run_worker

        self.grant("view_server", "add_server", "add_discoveryattempt")
        self.client.force_login(self.user)
        self.client.post("/servers/add/", {"name": "Cloud", "ssh_alias": "web.example.com"})
        self.write_config("Host web.example.com\n  HostName other.example\n  User deploy\n")
        remote = FakeServer()
        with remote.substituted():
            run_worker()
        self.assertEqual(DiscoveryAttempt.objects.get().status, DiscoveryAttempt.Status.FAILED)
        self.assertEqual(remote.targets, [])

    def test_deleted_requesting_account_cannot_dispatch_an_alias_check(self) -> None:
        from discovery.fakes import FakeServer, run_worker

        self.grant("view_server", "add_server", "add_discoveryattempt")
        self.client.force_login(self.user)
        self.client.post("/servers/add/", {"name": "Cloud", "ssh_alias": "web.example.com"})
        self.user.delete()
        remote = FakeServer()
        with remote.substituted():
            run_worker()
        self.assertEqual(DiscoveryAttempt.objects.get().status, DiscoveryAttempt.Status.FAILED)
        self.assertEqual(remote.targets, [])

    def test_delayed_queued_check_reports_worker_unavailability(self) -> None:
        from datetime import timedelta

        from django.utils import timezone

        self.grant("view_server", "add_server", "add_discoveryattempt")
        self.client.force_login(self.user)
        response = self.client.post("/servers/add/", {"name": "Cloud", "address": "cloud.example"})
        DiscoveryAttempt.objects.update(queued_at=timezone.now() - timedelta(minutes=11))
        page = self.client.get(response.headers["Location"])
        self.assertContains(page, "Checking the connection…")
        self.assertContains(page, "Worker unavailable for this check")
        self.assertContains(page, "Queued at")

    def test_queue_time_and_worker_command_wait_one_minute(self) -> None:
        from datetime import timedelta

        from django.utils import timezone

        self.grant("view_server", "add_server", "add_discoveryattempt")
        self.client.force_login(self.user)
        response = self.client.post("/servers/add/", {"name": "Cloud", "address": "cloud.example"})
        DiscoveryAttempt.objects.update(queued_at=timezone.now() - timedelta(seconds=30))
        page = self.client.get(response.headers["Location"])
        self.assertContains(page, "Checking the connection…")
        self.assertNotContains(page, "Queued at")
        self.assertNotContains(page, "db_worker")
        DiscoveryAttempt.objects.update(queued_at=timezone.now() - timedelta(minutes=2))
        page = self.client.get(response.headers["Location"])
        self.assertContains(page, "Queued at")
        self.assertContains(page, "python manage.py db_worker")
        self.assertNotContains(page, "Worker unavailable for this check")
