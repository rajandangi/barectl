from typing import ClassVar, override

from django.urls import reverse

from discovery.fakes import FakeServer, run_worker
from discovery.services import request_discovery
from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.models import SiteRequest


class PhpSelectionWorkflowTests(ControllerConfigTestCase):
    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def observe_php(self) -> None:
        with FakeServer().substituted():
            request_discovery(self.server)
            run_worker()

    def authorize_sites(self) -> None:
        self.grant("view_server", "view_siteplan", "prepare_siteplan")
        self.client.force_login(self.user)

    def test_unavailable_observation_cannot_queue_an_implicit_or_submitted_branch(self) -> None:
        self.authorize_sites()
        remote = FakeServer()
        with remote.substituted():
            for branch in ("", "8.5"):
                with self.subTest(branch=branch):
                    response = self.client.post(
                        reverse("server_site_prepare", args=[self.server.pk]),
                        {"identifier": "shop", "names": "shop.example.com", "php_version": branch},
                    )
                    self.assertEqual(response.status_code, 422)
        self.assertFalse(SiteRequest.objects.exists())
        self.assertEqual(remote.targets, [])

    def test_observed_branch_is_explicit_and_unobserved_selection_never_queues(self) -> None:
        self.authorize_sites()
        self.observe_php()
        path = reverse("server_site_prepare", args=[self.server.pk])
        for branch in ("", "8.4", "8.5; id"):
            with self.subTest(branch=branch):
                response = self.client.post(
                    path,
                    {"identifier": "shop", "names": "shop.example.com", "php_version": branch},
                )
                self.assertEqual(response.status_code, 422)
        self.assertFalse(SiteRequest.objects.exists())
        response = self.client.post(
            path,
            {"identifier": "shop", "names": "shop.example.com", "php_version": "8.5"},
        )
        self.assertEqual(response.status_code, 302)
        request = SiteRequest.objects.get()
        self.assertEqual(request.php_version, "8.5")
        self.assertEqual(request.convention_revision, 4)

    def test_inventory_permission_does_not_authorize_php_site_preparation(self) -> None:
        self.grant("view_server")
        self.client.force_login(self.user)
        self.observe_php()
        response = self.client.post(
            reverse("server_site_prepare", args=[self.server.pk]),
            {"identifier": "shop", "names": "shop.example.com", "php_version": "8.5"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(SiteRequest.objects.exists())
