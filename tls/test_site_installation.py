"""Enable HTTPS from a site's page (docs/tls.md#create-and-install)."""

from typing import TYPE_CHECKING, override

from django.contrib.auth.models import Permission
from django.test import Client
from django.utils import timezone

from bootstrap.models import ApplyRun, Execution, PlanPreparation, Verification
from discovery.models import SiteObservation
from discovery.services import request_discovery
from operations.models import RemoteOperation
from servers.testing import HTMX_FRAGMENT

from .fakes import NAMES, TlsTestCase, record_step
from .installation import advance_installation
from .models import CertificateInstallation

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse

INSTALL = (
    "view_server",
    "view_siteobservation",
    "view_tlsplan",
    "prepare_tlsplan",
    "apply_tlsplan",
    "issue_certificate",
)
Status = RemoteOperation.Status


class SiteInstallationTests(TlsTestCase):
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
        )
        self.site.add_site("shop", NAMES)
        self.site.answer(self.remote)
        self.sign_in_with(*INSTALL)

    @property
    def revision(self) -> str:
        return str(self.server.snapshots.latest("pk").pk)

    @property
    def https_page(self) -> str:
        return f"/servers/{self.server.pk}/sites/shop/https/"

    def install(self, identifier: str = "shop", **data: str) -> _MonkeyPatchedWSGIResponse:
        return self.client.post(
            f"/servers/{self.server.pk}/sites/{identifier}/https/install/",
            {"installation-email": "ops@example.com", "installation-snapshot": self.revision}
            | data,
            headers=HTMX_FRAGMENT,
        )

    def record(
        self,
        status: str = CertificateInstallation.Status.ACTIVE,
        identifier: str = "shop",
        failure: str = "",
    ) -> CertificateInstallation:
        return CertificateInstallation.objects.create(
            server=self.server,
            requested_by=self.user,
            identifier=identifier,
            names="\n".join(NAMES),
            discovery_revision=int(self.revision),
            email="ops@example.com",
            authority="https://acme.example/directory",
            ssh_alias=self.server.ssh_alias,
            status=status,
            failure=failure,
            finished_at=None if status == CertificateInstallation.Status.ACTIVE else timezone.now(),
        )

    def test_the_section_names_the_exact_domains_and_asks_only_for_an_email(self) -> None:
        response = self.client.get(self.https_page)
        section = response.content.decode()
        self.assertContains(response, "Enable HTTPS")
        for name in NAMES:
            self.assertContains(response, f"<code>{name}</code>", html=True)
        self.assertContains(response, 'name="installation-email"')
        self.assertContains(response, f'name="installation-snapshot" value="{self.revision}"')
        self.assertNotIn('type="checkbox"', section)
        self.assertNotContains(response, 'name="installation-identifier"')
        self.assertContains(response, "the server's Advanced TLS plans")

    def test_a_site_without_a_database_installs_for_the_url_site_and_observed_domains(
        self,
    ) -> None:
        before = list(self.remote.commands)
        response = self.install()
        self.assertEqual(response.status_code, 200)
        installation = CertificateInstallation.objects.get()
        self.assertEqual(installation.identifier, "shop")
        self.assertEqual(installation.names.splitlines(), list(NAMES))
        self.assertEqual(installation.discovery_revision, int(self.revision))
        self.assertContains(response, 'id="site-installation-heading"')
        self.assertContains(response, "autofocus")
        self.assertContains(response, "<strong>Route preparation</strong>: Current", html=False)
        self.assertContains(response, "manage.py db_worker")
        self.assertContains(response, "hx-partial")
        self.assertEqual(self.remote.commands, before)
        self.assertFalse(ApplyRun.objects.exists())

    def test_duplicate_submissions_and_reloads_converge_on_one_installation(self) -> None:
        self.install()
        self.install()
        self.client.get(self.https_page)
        self.assertEqual(CertificateInstallation.objects.count(), 1)
        self.assertFalse(PlanPreparation.objects.exists())

    def test_a_stale_revision_is_refused_before_anything_is_recorded(self) -> None:
        response = self.install(**{"installation-snapshot": "0"})
        self.assertContains(response, "Installation cannot start")
        self.assertFalse(CertificateInstallation.objects.exists())

    def test_an_invalid_email_is_explained_without_recording(self) -> None:
        response = self.install(**{"installation-email": "not an address"})
        self.assertEqual(response.status_code, 422)
        self.assertContains(response, "usa-error-message", status_code=422)
        self.assertFalse(CertificateInstallation.objects.exists())

    def test_a_site_outside_the_current_observation_is_not_found(self) -> None:
        self.assertEqual(self.install("absent1").status_code, 404)
        self.assertEqual(
            self.client.get(
                f"/servers/{self.server.pk}/sites/absent1/https/installation/",
                headers=HTMX_FRAGMENT,
            ).status_code,
            404,
        )
        self.assertFalse(CertificateInstallation.objects.exists())

    def test_site_viewing_and_certificate_permissions_are_both_required(self) -> None:
        self.user.user_permissions.remove(Permission.objects.get(codename="issue_certificate"))
        self.assertEqual(self.install().status_code, 403)
        page = self.client.get(self.https_page)
        self.assertNotContains(page, 'name="installation-email"')
        self.assertContains(page, "<code>tls.issue_certificate</code>")
        self.user.user_permissions.add(Permission.objects.get(codename="issue_certificate"))
        self.user.user_permissions.remove(Permission.objects.get(codename="view_siteobservation"))
        self.assertEqual(self.install().status_code, 403)
        self.assertFalse(CertificateInstallation.objects.exists())

    def test_database_permissions_are_irrelevant(self) -> None:
        self.assertFalse(self.user.user_permissions.filter(content_type__app_label="databases"))
        self.install()
        self.assertTrue(CertificateInstallation.objects.exists())

    def test_csrf_is_enforced(self) -> None:
        csrf = Client(enforce_csrf_checks=True)
        csrf.force_login(self.user)
        self.assertEqual(
            csrf.post(
                f"/servers/{self.server.pk}/sites/shop/https/install/",
                {"installation-email": "ops@example.com", "installation-snapshot": self.revision},
            ).status_code,
            403,
        )
        self.assertFalse(CertificateInstallation.objects.exists())

    def test_navigation_and_polling_queue_no_remote_work(self) -> None:
        installation = self.record()
        before = (list(self.remote.commands), RemoteOperation.objects.count())
        self.client.get(self.https_page)
        poll = self.client.get(
            f"/servers/{self.server.pk}/sites/shop/https/installation/?shown=x",
            headers=HTMX_FRAGMENT,
        )
        self.assertContains(poll, 'id="site-installation"')
        self.assertContains(poll, 'hx-trigger="every 2s"')
        self.assertContains(poll, "Installing HTTPS")
        full = self.client.get(f"/servers/{self.server.pk}/sites/shop/https/installation/")
        self.assertRedirects(full, self.https_page)
        self.assertEqual((list(self.remote.commands), RemoteOperation.objects.count()), before)
        installation.refresh_from_db()
        self.assertEqual(installation.status, CertificateInstallation.Status.ACTIVE)

    def test_an_uncertain_step_pauses_and_links_its_original_run(self) -> None:
        installation = self.record()
        record_step(installation, 0)
        run = record_step(
            installation, 1, Status.RECONCILING, Verification.PENDING, Execution.SUBMITTED
        )
        response = self.client.get(self.https_page)
        self.assertContains(response, "Continuation is paused")
        self.assertContains(response, f'<a href="/applies/{run.pk}/">Check outcome</a>', html=True)
        self.assertContains(response, "<strong>Route preparation</strong>: Completed")
        self.assertContains(response, "<strong>Renewal setup</strong>: Current")
        self.assertContains(response, "<strong>Certificate order</strong>: Not started")
        self.assertNotContains(response, 'name="installation-email"')
        self.assertNotContains(response, "Retry")

    def test_a_failed_activation_after_issuance_names_both_results(self) -> None:
        installation = self.record(
            CertificateInstallation.Status.FAILED,
            failure="A reviewed name is not served the reviewed certificate.",
        )
        for position in range(3):
            record_step(installation, position)
        run = record_step(installation, 3, Status.FAILED, Verification.FAILED)
        response = self.client.get(self.https_page)
        self.assertContains(response, "The certificate was issued")
        self.assertContains(response, "HTTPS activation failed after changing the server")
        self.assertNotContains(response, "HTTPS was not activated")
        self.assertContains(response, "A reviewed name is not served the reviewed certificate.")
        self.assertContains(response, "<strong>Certificate order</strong>: Completed")
        self.assertContains(response, "<strong>HTTPS activation</strong>: Failed")
        self.assertContains(response, f'href="/applies/{run.pk}/"')
        self.assertContains(response, "docs/recovery.md")
        self.assertNotContains(response, "Every stage verified")
        self.assertNotContains(response, "rolled back.")
        # A new installation needs a fresh explicit submission.
        self.assertContains(response, 'name="installation-email"')
        self.assertEqual(CertificateInstallation.objects.count(), 1)

    def test_an_activation_refused_before_changes_was_not_activated(self) -> None:
        installation = self.record(
            CertificateInstallation.Status.FAILED, failure="The server refused the activation."
        )
        for position in range(3):
            record_step(installation, position)
        record_step(
            installation, 3, Status.FAILED, Verification.NOT_APPLICABLE, Execution.NOT_SUBMITTED
        )
        response = self.client.get(self.https_page)
        self.assertContains(response, "The certificate was issued")
        self.assertContains(response, "HTTPS was not activated")
        self.assertNotContains(response, "after changing the server")

    def test_another_sites_active_installation_blocks_without_naming_it(self) -> None:
        self.record(identifier="blog")
        response = self.client.get(self.https_page)
        self.assertContains(response, "Another site's certificate installation is active")
        self.assertNotContains(response, "blog")
        self.assertNotContains(response, 'name="installation-email"')
        self.assertContains(response, 'hx-trigger="every 2s"')
        self.assertIsNone(CertificateInstallation.objects.filter(identifier="shop").first())

    def test_unverified_activation_is_unconfirmed_not_a_failure(self) -> None:
        installation = self.record(
            CertificateInstallation.Status.FAILED, failure="Verification could not be checked."
        )
        for position in range(3):
            record_step(installation, position)
        run = record_step(installation, 3, Status.FAILED, Verification.UNAVAILABLE)
        response = self.client.get(self.https_page)
        self.assertContains(response, "<strong>HTTPS activation</strong>: Outcome not established")
        self.assertContains(response, "Whether HTTPS was activated is not established")
        self.assertContains(response, f'<a href="/applies/{run.pk}/">Check outcome</a>', html=True)
        self.assertNotContains(response, "HTTPS was not activated")
        self.assertNotContains(response, "submit a new installation")

    def test_an_unconfirmed_order_asks_for_its_run_before_any_new_order(self) -> None:
        installation = self.record(CertificateInstallation.Status.FAILED, failure="Unknown.")
        for position in range(2):
            record_step(installation, position)
        run = record_step(installation, 2, Status.FAILED, Verification.UNAVAILABLE)
        response = self.client.get(self.https_page)
        self.assertContains(response, "A certificate may have been issued")
        self.assertContains(response, f'<a href="/applies/{run.pk}/">Check outcome</a>', html=True)
        self.assertNotContains(response, "submit a new installation")

    def test_a_reconciling_run_after_the_installation_stopped_still_offers_check_outcome(
        self,
    ) -> None:
        installation = self.record(
            CertificateInstallation.Status.FAILED,
            failure="The requesting account can no longer install certificates.",
        )
        record_step(installation, 0)
        run = record_step(
            installation, 1, Status.RECONCILING, Verification.PENDING, Execution.SUBMITTED
        )
        response = self.client.get(self.https_page)
        self.assertContains(response, f'<a href="/applies/{run.pk}/">Check outcome</a>', html=True)
        self.assertContains(response, "The installation stopped while the outcome")
        self.assertNotContains(response, "Continuation is paused")

    def test_an_installation_stopped_between_stages_names_the_stage_that_never_started(
        self,
    ) -> None:
        installation = self.record(
            CertificateInstallation.Status.FAILED,
            failure="Another operation is active. No later step was started.",
        )
        record_step(installation, 0)
        response = self.client.get(self.https_page)
        self.assertContains(response, "Stopped before renewal setup started")
        self.assertContains(response, "<strong>Route preparation</strong>: Completed")
        self.assertContains(response, '<a href="#site-readiness">HTTPS readiness</a>', html=True)
        self.assertContains(response, f"The installation covered {', '.join(NAMES)}.")

    def test_an_earlier_installation_for_other_domains_is_not_the_current_site(self) -> None:
        installation = self.record(CertificateInstallation.Status.SUCCEEDED)
        CertificateInstallation.objects.filter(pk=installation.pk).update(names="old.example.com")
        response = self.client.get(self.https_page)
        self.assertContains(response, "This is an earlier installation")
        self.assertContains(response, "Recorded domains: old.example.com.")
        self.assertContains(response, "Installation recorded as verified at")
        self.assertNotContains(response, "Every stage verified")

    def test_domains_changing_after_the_page_loaded_are_refused(self) -> None:
        shown = self.revision
        self.assertContains(self.client.get(self.https_page), f'value="{shown}"')
        request_discovery(self.server)
        self.run_worker()
        SiteObservation.objects.create(
            snapshot=self.server.snapshots.latest("pk"),
            identifier="shop",
            server_names="changed.example.com",
            php_version="8.3",
        )
        self.assertNotEqual(self.revision, shown)
        response = self.install(**{"installation-snapshot": shown})
        self.assertContains(response, "Installation cannot start")
        self.assertFalse(CertificateInstallation.objects.exists())

    def test_the_worker_starts_route_preparation_and_the_page_links_its_record(self) -> None:
        self.install()
        installation = CertificateInstallation.objects.get()
        advance_installation.call(installation.pk)
        preparation = installation.steps.get(position=0).preparation
        if preparation is None:
            self.fail("The worker recorded no route preparation.")
        response = self.client.get(self.https_page)
        self.assertContains(response, "<strong>Route preparation</strong>: Current")
        self.assertContains(response, f'href="/plans/{preparation.pk}/"')

    def test_drift_found_by_the_worker_stops_at_route_preparation(self) -> None:
        self.install()
        self.site.sites["shop"] = (("changed.example.com",), True, True)
        self.run_worker()
        response = self.client.get(self.https_page)
        self.assertContains(response, "Stopped at route preparation")
        self.assertContains(response, "domains changed")
        self.assertContains(response, '<a href="#site-readiness">HTTPS readiness</a>', html=True)
        self.assertFalse(ApplyRun.objects.exists())
