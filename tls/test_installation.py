"""Create and Install requests at the dashboard and worker boundaries."""

from typing import override

from django.test import Client

from bootstrap.models import ApplyRun, PlanPreparation
from discovery.models import SiteObservation
from discovery.services import request_discovery
from servers.registration import RemovalBlocked, remove_server
from servers.testing import HTMX_FRAGMENT

from .fakes import NAMES, TlsTestCase
from .installation import available_sites
from .models import CertificateInstallation


class CertificateInstallationTests(TlsTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        request_discovery(self.server)
        self.run_worker()
        SiteObservation.objects.create(
            snapshot=self.server.snapshots.get(),
            identifier="shop",
            server_names="\n".join(NAMES),
            php_version="8.3",
            state="managed",
            outcome="observed",
        )
        self.site.add_site("shop", NAMES)
        self.site.answer(self.remote)
        self.sign_in_with(
            "view_server",
            "view_siteobservation",
            "view_tlsplan",
            "prepare_tlsplan",
            "apply_tlsplan",
            "issue_certificate",
        )

    def install(self) -> None:
        response = self.client.post(
            f"/servers/{self.server.pk}/tls/install/",
            {
                "installation-identifier": "shop",
                "installation-email": "ops@example.com",
                "installation-snapshot": str(self.server.snapshots.latest("pk").pk),
            },
            headers=HTMX_FRAGMENT,
        )
        self.assertEqual(response.status_code, 200)

    def test_the_site_and_domains_are_prefilled_without_a_terms_checkbox(self) -> None:
        response = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertContains(response, "Create and Install")
        for name in NAMES:
            self.assertContains(response, name)
        self.assertNotContains(response, "I accept the authority's terms")

    def test_duplicate_clicks_queue_one_installation_and_no_server_work_in_the_request(
        self,
    ) -> None:
        before = list(self.remote.commands)
        self.install()
        self.install()
        self.assertEqual(CertificateInstallation.objects.count(), 1)
        self.assertEqual(
            CertificateInstallation.objects.get().discovery_revision,
            self.server.snapshots.latest("pk").pk,
        )
        self.assertEqual(self.remote.commands, before)
        self.assertFalse(ApplyRun.objects.exists())

    def test_domain_drift_stops_before_any_mutation(self) -> None:
        self.install()
        self.site.sites["shop"] = (("changed.example.com",), True, True)
        self.run_worker()
        installation = CertificateInstallation.objects.get()
        self.assertEqual(installation.status, CertificateInstallation.Status.FAILED)
        self.assertIn("domains changed", installation.failure)
        self.assertFalse(ApplyRun.objects.exists())

    def test_a_stale_discovery_form_cannot_authorize_new_domains(self) -> None:
        response = self.client.post(
            f"/servers/{self.server.pk}/tls/install/",
            {
                "installation-identifier": "shop",
                "installation-email": "ops@example.com",
                "installation-snapshot": "0",
            },
            headers=HTMX_FRAGMENT,
        )
        self.assertContains(response, "Installation cannot start")
        self.assertLess(
            response.content.index(b"Installation cannot start"),
            response.content.index(b"<details"),
        )
        self.assertFalse(CertificateInstallation.objects.exists())

    def test_revoked_permission_stops_before_the_worker_connects(self) -> None:
        self.install()
        self.user.user_permissions.clear()
        before = list(self.remote.commands)
        self.run_worker()
        installation = CertificateInstallation.objects.get()
        self.assertEqual(installation.status, CertificateInstallation.Status.FAILED)
        self.assertEqual(self.remote.commands, before)
        self.assertFalse(PlanPreparation.objects.exists())

    def test_csrf_and_certificate_permission_are_required(self) -> None:
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        self.assertEqual(
            csrf_client.post(f"/servers/{self.server.pk}/tls/install/").status_code, 403
        )
        self.user.user_permissions.clear()
        self.assertEqual(
            self.client.post(f"/servers/{self.server.pk}/tls/install/").status_code, 403
        )
        self.assertFalse(CertificateInstallation.objects.exists())

    def test_an_active_installation_blocks_server_removal_between_steps(self) -> None:
        self.install()
        with self.assertRaises(RemovalBlocked):
            remove_server(self.server)

    def test_an_unknown_site_is_refused(self) -> None:
        response = self.client.post(
            f"/servers/{self.server.pk}/tls/install/",
            {"installation-identifier": "unknown", "installation-email": "ops@example.com"},
            headers=HTMX_FRAGMENT,
        )
        self.assertEqual(response.status_code, 422)
        self.assertFalse(CertificateInstallation.objects.exists())

    def test_an_incomplete_site_is_not_offered_or_requested(self) -> None:
        SiteObservation.objects.filter(identifier="shop").update(state="partly_applied")
        self.assertEqual(available_sites(self.server).sites, ())
        response = self.client.post(
            f"/servers/{self.server.pk}/tls/install/",
            {
                "installation-identifier": "shop",
                "installation-email": "ops@example.com",
                "installation-snapshot": str(self.server.snapshots.latest("pk").pk),
            },
            headers=HTMX_FRAGMENT,
        )
        self.assertEqual(response.status_code, 422)
        self.assertFalse(CertificateInstallation.objects.exists())
