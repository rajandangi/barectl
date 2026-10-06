"""A site's Activity: local operations recorded for its identifier on one registration.

docs/dashboard-workflows.md#site-pages
"""

from typing import override

from django.utils import timezone

from bootstrap.models import Action, ApplyRun, Execution, Verification
from discovery.fakes import AVAILABLE_DIR, PHP_DIR, SITE_DIR, DiscoveryTestCase, add_site
from discovery.models import DiscoveryAttempt
from operations.models import RemoteOperation
from tls.models import CertificateInstallation, CertificateInstallationStep

from .activity import UNKNOWN_STEP
from .models import Server
from .registration import remove_server
from .testing import record_preparation, record_run

Status = RemoteOperation.Status
SITES = ("view_server", "add_server", "add_discoveryattempt", "view_siteobservation")
PLANS = ("view_configurationplan", "view_siteplan", "view_databaseplan", "view_tlsplan")


class SiteActivityTests(DiscoveryTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        add_site(self.remote)

    def discovered(self, name: str = "Web", alias: str = "web.example.com") -> Server:
        self.grant(*SITES, *PLANS)
        server = self.register(name, alias)
        self.run_worker()
        return server

    def activity(self, server: Server, identifier: str = "alpha") -> str:
        response = self.client.get(f"/servers/{server.pk}/sites/{identifier}/activity/")
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        start = content.index('id="site-activity"')
        return content[start : content.index("</section>", start)]

    def test_rows_come_from_typed_requests_and_retained_runs_of_this_registration(self) -> None:
        server = self.discovered()
        other = self.discovered("Stage", "stage.example.net")
        site = record_preparation(server, Action.SITE_HTTP, "alpha")
        applied = record_run(server, Action.SITE_HTTP, preparation=site)
        retained = record_run(server, Action.SITE_HTTP, site="alpha")
        record_preparation(server, Action.DATABASE_MARIADB, "alpha")
        record_preparation(server, Action.TLS_READINESS, "alpha")
        elsewhere = record_run(other, Action.SITE_HTTP, site="alpha")
        another_site = record_run(server, Action.SITE_HTTP, site="beta")
        section = self.activity(server)
        self.assertIn("Activity for <code>alpha</code>", section)
        self.assertIn("does not establish the current site's identity", section)
        self.assertIn(f'href="/servers/{server.pk}/sites/alpha/overview/"', section)
        for run in (applied, retained):
            self.assertIn(f'href="/applies/{run.pk}/"', section)
        self.assertIn(f'href="/plans/{site.pk}/"', section)
        self.assertIn("Plan preparation: MariaDB site database", section)
        self.assertIn("Plan preparation: TLS readiness review", section)
        # The same identifier on another registration, or another site, never joins.
        for run in (elsewhere, another_site):
            self.assertNotIn(f'href="/applies/{run.pk}/"', section)
        self.assertIn(f'href="/applies/{elsewhere.pk}/"', self.activity(other))

    def test_server_wide_work_stays_on_the_server_activity(self) -> None:
        server = self.discovered()
        # Intent prose that names the site never associates server-wide work with it.
        nginx = record_run(server, Action.NGINX, intent="Serve alpha with Nginx")
        driver = record_preparation(server, Action.PHP_MYSQL)
        inspection = record_preparation(server, Action.DATABASE_INSPECTION)
        renewal = record_preparation(server, Action.CERTBOT)
        refresh = record_preparation(server, Action.METADATA_REFRESH)
        record_run(server, Action.SITE_HTTP, site="alpha")
        section = self.activity(server)
        server_page = self.client.get(f"/servers/{server.pk}/activity/").content.decode()
        self.assertNotIn(f'href="/applies/{nginx.pk}/"', section)
        self.assertIn(f'href="/applies/{nginx.pk}/"', server_page)
        for preparation in (driver, inspection, renewal, refresh):
            self.assertNotIn(f"/plans/{preparation.pk}/", section)

    def test_installation_steps_join_through_their_relation(self) -> None:
        server = self.discovered()
        installation = CertificateInstallation.objects.create(
            server=server,
            requested_by=self.user,
            identifier="alpha",
            names="alpha.test",
            email="admin@example.com",
            authority="https://acme.example.com/directory",
            ssh_alias=server.ssh_alias,
            status=CertificateInstallation.Status.FAILED,
            failure="Another operation is active. No later step was started.",
        )
        challenge = record_preparation(server, Action.TLS_CHALLENGE, "alpha")
        route = record_run(server, Action.TLS_CHALLENGE, preparation=challenge)
        renewal = record_preparation(server, Action.CERTBOT)
        CertificateInstallationStep.objects.create(
            installation=installation, position=0, preparation=challenge, run=route
        )
        CertificateInstallationStep.objects.create(
            installation=installation, position=1, preparation=renewal
        )
        unrelated = record_preparation(server, Action.CERTBOT)
        section = self.activity(server)
        self.assertIn("Certificate installations", section)
        self.assertIn("Installation stopped", section)
        self.assertIn("No later step was started.", section)
        self.assertIn(f'href="/plans/{renewal.pk}/"', section)
        self.assertIn(f'href="/applies/{route.pk}/"', section)
        self.assertNotIn(f'href="/plans/{unrelated.pk}/"', section)
        # The installation's own renewal setup is listed; a standalone one is not.
        self.assertEqual(section.count("Plan preparation: Certbot renewal setup"), 1)
        # Without TLS view permission neither the installation nor its steps are shown.
        self.user.user_permissions.remove(
            *self.user.user_permissions.filter(codename="view_tlsplan")
        )
        section = self.activity(server)
        self.assertNotIn("Certificate installations", section)
        self.assertNotIn(f"/plans/{renewal.pk}/", section)
        self.assertNotIn(f"/applies/{route.pk}/", section)

    def install(self, server: Server, identifier: str = "alpha") -> CertificateInstallation:
        return CertificateInstallation.objects.create(
            server=server,
            requested_by=self.user,
            identifier=identifier,
            names=f"{identifier}.test",
            email="admin@example.com",
            authority="https://acme.example.com/directory",
            ssh_alias=server.ssh_alias,
            status=CertificateInstallation.Status.SUCCEEDED,
        )

    def test_other_and_detached_installations_never_join(self) -> None:
        server = self.discovered()
        other = self.discovered("Stage", "stage.example.net")
        elsewhere = self.install(other)
        detached = self.install(server)
        CertificateInstallationStep.objects.create(
            installation=detached, position=0, preparation=None, run=None
        )
        self.assertNotIn(f"Installation {elsewhere.pk},", self.activity(server))
        self.assertIn(f"Installation {detached.pk},", self.activity(server))
        DiscoveryAttempt.objects.all().delete()
        remove_server(server)
        self.assertIsNone(CertificateInstallation.objects.get(pk=detached.pk).server_id)
        renewed = self.discovered()
        section = self.activity(renewed)
        self.assertNotIn("Certificate installations", section)
        self.assertNotIn(f"Installation {detached.pk},", section)

    def test_an_unrecognized_step_position_is_labelled_without_failing(self) -> None:
        server = self.discovered()
        installation = self.install(server)
        CertificateInstallationStep.objects.create(installation=installation, position=9)
        self.assertIn(f"{UNKNOWN_STEP}:", self.activity(server))

    def test_retained_run_copies_and_typed_requests_join_each_action(self) -> None:
        server = self.discovered()
        for action in (
            Action.DATABASE_MARIADB,
            Action.TLS_CHALLENGE,
            Action.TLS_STAGING,
            Action.TLS_ISSUANCE,
            Action.TLS_ACTIVATION,
        ):
            with self.subTest(action=action):
                retained = record_run(server, action, site="alpha")
                planned = record_run(
                    server, action, preparation=record_preparation(server, action, "alpha")
                )
                elsewhere = record_run(server, action, site="beta")
                section = self.activity(server)
                self.assertIn(f'href="/applies/{retained.pk}/"', section)
                self.assertIn(f'href="/applies/{planned.pk}/"', section)
                self.assertNotIn(f'href="/applies/{elsewhere.pk}/"', section)

    def test_a_reused_identifier_keeps_old_runs_historical(self) -> None:
        server = self.discovered()
        old = record_run(server, Action.SITE_HTTP, site="alpha")
        # An administrator removes the site, then recreates the identifier with other names.
        del self.remote.links[f"{SITE_DIR}/alpha.conf"]
        del self.remote.files[f"{AVAILABLE_DIR}/alpha.conf"]
        self.remote.directories[SITE_DIR].remove("alpha.conf")
        self.remote.directories[AVAILABLE_DIR].remove("alpha.conf")
        del self.remote.files[f"{PHP_DIR}/8.3/fpm/pool.d/alpha.conf"]
        self.remote.directories[f"{PHP_DIR}/8.3/fpm/pool.d"].remove("alpha.conf")
        self.client.post(f"/servers/{server.pk}/verify/")
        self.run_worker()
        absent = self.client.get(f"/servers/{server.pk}/sites/alpha/activity/")
        self.assertContains(absent, "Site not found in the latest observation")
        self.assertContains(absent, f'href="/applies/{old.pk}/"')
        add_site(self.remote, "alpha", ("recreated.test",))
        self.client.post(f"/servers/{server.pk}/verify/")
        self.run_worker()
        section = self.activity(server)
        self.assertIn(f'href="/applies/{old.pk}/"', section)
        self.assertIn("Applied and verified", section)
        self.assertIn("a site recreated outside Barectl does not establish", section)
        overview = self.client.get(f"/servers/{server.pk}/sites/alpha/overview/")
        self.assertContains(overview, "recreated.test")
        self.assertNotContains(overview, "alpha.test")
        self.assertNotContains(overview, f"/applies/{old.pk}/")

    def test_restricted_actions_are_hidden_with_their_links(self) -> None:
        server = self.discovered()
        site = record_run(server, Action.SITE_HTTP, site="alpha")
        binding = record_preparation(server, Action.DATABASE_MARIADB, "alpha")
        self.user.user_permissions.remove(
            *self.user.user_permissions.filter(codename="view_databaseplan")
        )
        section = self.activity(server)
        self.assertIn(f'href="/applies/{site.pk}/"', section)
        self.assertNotIn(f"/plans/{binding.pk}/", section)
        self.assertNotIn("MariaDB site database", section)
        self.assertEqual(self.client.get(f"/plans/{binding.pk}/").status_code, 403)
        self.user.user_permissions.remove(*self.user.user_permissions.filter(codename__in=PLANS))
        section = self.activity(server)
        self.assertIn("Your account may not view plan preparations or apply runs.", section)
        self.assertNotIn(f"/applies/{site.pk}/", section)

    def test_an_uncertain_run_links_to_its_original_check_without_resubmitting(self) -> None:
        server = self.discovered()
        uncertain = record_run(
            server,
            Action.SITE_HTTP,
            site="alpha",
            status=Status.RECONCILING,
            execution=Execution.SUBMITTED,
            verification=Verification.PENDING,
            failure="The server did not acknowledge the submission.",
        )
        operations = RemoteOperation.objects.count()
        self.remote.commands.clear()
        section = self.activity(server)
        self.assertIn("Outcome being reconciled", section)
        self.assertIn(
            f'<a href="/applies/{uncertain.pk}/">Check outcome<span class="usa-sr-only"> '
            f"of apply run {uncertain.pk}</span></a>",
            section,
        )
        self.assertIn("Execution: Submitted; not yet confirmed on the server.", section)
        self.assertIn("Verification: Not checked yet.", section)
        self.assertIn("submits nothing new", section)
        self.assertNotIn("<form", section)
        self.assertNotIn("<button", section)
        # Navigation reads local records only.
        self.assertEqual(RemoteOperation.objects.count(), operations)
        self.assertEqual(self.remote.commands, [])
        run = self.client.get(f"/applies/{uncertain.pk}/")
        self.assertContains(run, f'action="/applies/{uncertain.pk}/check/"')

    def test_a_partial_run_shows_its_boundary_and_recovery(self) -> None:
        server = self.discovered()
        partial = record_run(
            server,
            Action.SITE_HTTP,
            site="alpha",
            status=Status.FAILED,
            execution=Execution.PARTIAL,
            verification=Verification.NOT_APPLICABLE,
            failure="Stopped at exit status 21: the site's directories exist.",
        )
        section = self.activity(server)
        self.assertIn("Apply failed", section)
        self.assertIn("Stopped after changing the server: partly applied", section)
        self.assertIn("Verification: Not applicable: the execution did not succeed.", section)
        self.assertIn("Stopped at exit status 21: the site&#x27;s directories exist.", section)
        self.assertIn("does not resume, undo or resubmit", section)
        self.assertIn(
            f'<a href="/applies/{partial.pk}/">Open the original run for its recovery guidance',
            section,
        )
        self.assertNotIn("docs/recovery.md", section)

    def test_acknowledgement_states_never_read_as_success(self) -> None:
        server = self.discovered()
        now = timezone.now()
        pending = record_run(
            server,
            Action.SITE_HTTP,
            site="alpha",
            status=Status.RECONCILING,
            execution=Execution.NOT_FOUND,
            verification=Verification.PENDING,
        )
        ApplyRun.objects.filter(pk=pending.pk).update(
            check_requested_at=now, closure_requested_at=now
        )
        section = self.activity(server)
        self.assertIn("A check of the original run is queued", section)
        self.assertIn("waits for that check", section)
        self.assertIn("never records success, rollback or no changes", section)
        ApplyRun.objects.filter(pk=pending.pk).update(
            check_requested_at=None,
            closure_requested_at=None,
            closure_blocked="The admission deadline has not passed on the server.",
        )
        section = self.activity(server)
        self.assertIn("Not closed: The admission deadline has not passed", section)
        self.assertNotIn("A check of the original run is queued", section)
        ApplyRun.objects.filter(pk=pending.pk).update(
            status=Status.FAILED,
            execution=Execution.OUTCOME_UNKNOWN,
            finished_at=now,
            unknown_acknowledged_by_name="operator",
            unknown_acknowledged_at=now,
        )
        section = self.activity(server)
        self.assertIn("Outcome unknown", section)
        self.assertIn("may have changed the server", section)
        self.assertIn("Closed as outcome unknown by operator", section)
        self.assertNotIn("Applied and verified", section)

    def test_an_absent_site_keeps_its_history_without_change_controls(self) -> None:
        server = self.discovered()
        gone = record_run(server, Action.SITE_HTTP, site="gone1")
        response = self.client.get(f"/servers/{server.pk}/sites/gone1/activity/")
        self.assertContains(response, "Site not found in the latest observation")
        self.assertContains(response, f'href="/applies/{gone.pk}/"')
        self.assertNotContains(response, 'aria-label="Site sections"')
        self.assertNotContains(response, "site's Overview")
        main = response.content.decode().split('id="main-content"', 1)[1]
        self.assertNotIn("<button", main)
        self.assertNotIn("<form", main)

    def test_detached_audit_never_joins_a_new_registration(self) -> None:
        server = self.discovered()
        old = record_run(server, Action.SITE_HTTP, site="alpha")
        DiscoveryAttempt.objects.all().delete()
        remove_server(server)
        renewed = self.discovered()
        self.assertEqual((renewed.name, renewed.ssh_alias), ("Web", "web.example.com"))
        self.assertNotIn(f"/applies/{old.pk}/", self.activity(renewed))
        server_page = self.client.get(f"/servers/{renewed.pk}/activity/")
        self.assertNotContains(server_page, f"/applies/{old.pk}/")
        # The detached run stays reachable through its own authorized views.
        self.assertContains(self.client.get(f"/applies/{old.pk}/"), "Web (registration removed)")
        self.assertContains(self.client.get("/activity/"), "Web (removed)")

    def test_site_activity_requires_authentication_and_site_permission(self) -> None:
        server = self.discovered()
        url = f"/servers/{server.pk}/sites/alpha/activity/"
        self.assertEqual(self.client.get("/servers/999/sites/alpha/activity/").status_code, 404)
        self.user.user_permissions.remove(
            *self.user.user_permissions.filter(codename="view_siteobservation")
        )
        self.assertEqual(self.client.get(url).status_code, 403)
        self.client.logout()
        self.assertRedirects(self.client.get(url), f"/accounts/login/?next={url}")
