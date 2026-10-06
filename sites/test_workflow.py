"""The site plan workflow: request, worker, plan, rendered review and permissions.

Real views, services, the lifecycle, the worker, persistence and rendering run; only remote
execution is substituted, with ``SiteServer`` answering at ``discovery.ssh.connect``.
"""

from datetime import timedelta
from typing import override
from unittest import mock

from django.db.models import Model
from django.test import Client

from bootstrap.fakes import BOOT_ID, PLAN_PERMISSIONS
from bootstrap.models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    PlanEffect,
    PlanEvidence,
    PlanPreparation,
    Privilege,
)
from bootstrap.services import read_plans, request_preparation
from operations.models import RemoteOperation
from servers.testing import HTMX_FRAGMENT

from .fakes import SITE_PERMISSIONS, SiteTestCase
from .handler import INVALID_REQUEST, MISSING_REQUEST
from .models import PlanFileChange, SiteRequest

Effect = PlanEffect.Kind
Status = RemoteOperation.Status
SITE_VIEWER = ("view_server", "view_siteplan")
FOREIGN = "server { listen 81; server_name private.internal; }\n"


def kept_text(plan: ConfigurationPlan) -> str:
    """Every value stored for a plan, as text: what could ever be shown."""
    rows: list[Model] = [
        plan,
        *plan.effects.all(),
        *plan.postconditions.all(),
        *plan.refusals.all(),
        *plan.evidence.all(),
        *plan.site_names.all(),
        *plan.site_files.all(),
        *plan.site_directories.all(),
    ]
    return "\n".join(
        str(getattr(row, field.attname)) for row in rows for field in row._meta.concrete_fields
    )


class SitePreparationTests(SiteTestCase):
    def site_plan(self) -> ConfigurationPlan:
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        found = ConfigurationPlan.objects.filter(preparation=preparation).first()
        if found is None:
            raise AssertionError(f"No plan: {preparation.status} {preparation.failure}")
        return found

    def test_a_request_is_prepared_into_a_complete_review_without_writing(self) -> None:
        response = self.prepare_site(perms=(*SITE_PERMISSIONS, "view_siteobservation"))
        # Creation begins from Sites, and an ordinary submission returns there.
        self.assertRedirects(response, f"/servers/{self.server.pk}/sites/#site-plans")
        request = SiteRequest.objects.get()
        self.assertEqual(
            (request.identifier, request.names), ("shop", "shop.example.com\nwww.shop.example.com")
        )
        plan = self.site_plan()
        self.assertEqual(list(plan.refusals.values_list("reason", "text")), [])
        self.assertTrue(plan.eligible)
        self.assertFalse(plan.no_changes)
        self.assertEqual(
            (plan.action, plan.profile_revision, plan.boot_id, plan.privilege),
            (Action.SITE_HTTP, 3, BOOT_ID, Privilege.SUDO),
        )
        self.assertEqual(
            list(plan.effects.values_list("kind", flat=True)),
            [
                Effect.SITE_ACCOUNT,
                Effect.SITE_DIRECTORIES,
                Effect.SITE_FILES,
                Effect.SERVICE_RELOAD,
                Effect.HTTP_ROUTING,
                Effect.ACCEPTANCE_PROBE,
                Effect.ISOLATION_LIMITS,
                Effect.NO_ROLLBACK,
            ],
        )
        self.assertEqual(
            list(plan.site_files.values_list("role", "path")),
            [
                ("nginx_source", "/etc/nginx/sites-available/shop.conf"),
                ("nginx_link", "/etc/nginx/sites-enabled/shop.conf"),
                ("pool", "/etc/php/8.3/fpm/pool.d/shop.conf"),
                ("placeholder", "/var/www/shop/public/index.html"),
                ("probe", f"/var/www/shop/public/probe-{plan.site.probe_token}.php"),
            ],
        )
        self.assertTrue(plan.site.ipv6)
        self.assertLessEqual(plan.site.payload_bytes or 0, 16 * 1024 - 2048)
        account = plan.site_account
        self.assertEqual(
            (account.uid_min, account.uid_max, account.predicted_uid, account.subordinate_ids),
            (1000, 60000, 1003, True),
        )
        kinds = set(plan.evidence.values_list("kind", flat=True))
        self.assertLessEqual(
            {
                PlanEvidence.Kind.SITE_REVALIDATION,
                PlanEvidence.Kind.NGINX_CLOSURE,
                PlanEvidence.Kind.FPM_CLOSURE,
                PlanEvidence.Kind.ACCOUNTS,
                PlanEvidence.Kind.ALLOCATION,
                PlanEvidence.Kind.SITE_PATHS,
                PlanEvidence.Kind.LISTENERS,
            },
            kinds,
        )
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, "HTTP PHP site plan")
        self.assertContains(page, "convention revision 3")
        self.assertContains(page, "fastcgi_pass unix:/run/php/sshop.sock;")
        self.assertContains(page, "/usr/sbin/useradd --user-group")
        self.assertContains(page, "Required authority")
        self.assertContains(page, "Admission expires")
        # Applying needs its own permission.
        self.assertNotContains(page, "Apply plan")
        self.assertEqual(ApplyRun.objects.count(), 0)
        self.assertEqual(PlanFileChange.objects.filter(temporary=True).count(), 1)
        server_page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertContains(server_page, "Site plans")
        self.assertContains(server_page, "Latest plan: HTTP PHP site")

    def test_foreign_configuration_bytes_are_never_kept(self) -> None:
        self.site.files["/etc/nginx/sites-available/private"] = FOREIGN
        self.prepare_site()
        plan = self.site_plan()
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        kept = kept_text(plan)
        self.assertNotIn("private.internal", kept)
        self.assertNotIn("listen 81", kept)

    def test_refusals_are_explained_and_nothing_is_offered(self) -> None:
        self.site.add_site("blog", ("blog.example.com", "shop.example.com"))
        self.prepare_site()
        plan = self.site_plan()
        self.assertFalse(plan.eligible)
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, "Not following the convention.")
        self.assertContains(page, "The site blog already declares shop.example.com")
        self.assertContains(page, "Barectl changed nothing on the server.")

    def test_invalid_input_is_refused_by_the_form_without_connecting(self) -> None:
        self.sign_in_with(*SITE_PERMISSIONS)
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/prepare/",
            {"identifier": "WWW", "names": "*.example.com 192.0.2.1"},
            headers=HTMX_FRAGMENT,
        )
        self.assertEqual(response.status_code, 422)
        self.assertContains(response, "usa-error-message", status_code=422)
        self.assertContains(response, "wildcards are not supported", status_code=422)
        self.assertContains(response, "IP addresses are not supported", status_code=422)
        self.assertContains(response, 'aria-invalid="true"', status_code=422)
        self.assertEqual(PlanPreparation.objects.count(), 0)
        self.assertEqual(self.remote.targets, [])

    def test_an_ordinary_invalid_submission_keeps_its_input_on_the_sites_page(self) -> None:
        self.sign_in_with(*SITE_PERMISSIONS, "view_siteobservation")
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/prepare/",
            {"identifier": "www", "names": "shop.example.com\n*.example.com"},
        )
        self.assertEqual(response.status_code, 422)
        page = response.content.decode()
        self.assertIn('aria-current="page">Sites</a>', page)
        self.assertIn('id="site-plans"', page)
        self.assertIn("Correct the site identifier or names.", page)
        self.assertIn('id="id_site_identifier_error"', page)
        self.assertIn('id="id_site_names_error"', page)
        self.assertIn("wildcards are not supported", page)
        self.assertIn(
            'aria-describedby="id_site_identifier_helptext id_site_identifier_error"', page
        )
        self.assertIn('aria-describedby="id_site_names_helptext id_site_names_error"', page)
        self.assertIn('aria-invalid="true"', page)
        # Entered values survive.
        self.assertIn('value="www"', page)
        self.assertIn("shop.example.com\n*.example.com</textarea>", page)
        self.assertEqual(PlanPreparation.objects.count(), 0)
        self.assertEqual(self.remote.targets, [])

    def test_the_invalid_page_needs_server_viewing_permission(self) -> None:
        # The re-rendered page shows the server, so preparing must keep requiring its view.
        self.sign_in_with("view_siteplan", "prepare_siteplan", "view_siteobservation")
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/prepare/", {"identifier": "www", "names": "a.example"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertNotIn(b"site-plans", response.content)

    def test_an_account_without_site_observations_keeps_the_advanced_form(self) -> None:
        self.sign_in_with(*SITE_PERMISSIONS)
        url = f"/servers/{self.server.pk}/sites/prepare/"
        invalid = self.client.post(url, {"identifier": "www", "names": "a.example"})
        self.assertEqual(invalid.status_code, 422)
        self.assertContains(invalid, 'aria-current="page">Advanced</a>', status_code=422)
        self.assertContains(invalid, 'value="www"', status_code=422)
        self.site.answer(self.remote)
        queued = self.client.post(url, {"identifier": "shop", "names": "shop.example.com"})
        self.assertRedirects(queued, f"/servers/{self.server.pk}/advanced/#site-plans")

    def test_a_second_request_while_one_is_active_is_busy(self) -> None:
        self.sign_in_with(*SITE_PERMISSIONS)
        url = f"/servers/{self.server.pk}/sites/prepare/"
        form = {"identifier": "shop", "names": "shop.example.com"}
        self.client.post(url, form, headers=HTMX_FRAGMENT)
        response = self.client.post(url, form, headers=HTMX_FRAGMENT)
        self.assertContains(response, "Barectl is running another remote operation")
        self.assertEqual(PlanPreparation.objects.count(), 1)
        self.assertEqual(SiteRequest.objects.count(), 1)
        polled = self.client.get(f"/servers/{self.server.pk}/sites/?shown=x", headers=HTMX_FRAGMENT)
        self.assertContains(polled, 'hx-trigger="every 2s"')
        bootstrap = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertNotContains(bootstrap, "Prepare site plan")

    def test_preparation_requires_csrf_and_post(self) -> None:
        self.sign_in_with(*SITE_PERMISSIONS)
        url = f"/servers/{self.server.pk}/sites/prepare/"
        self.assertEqual(self.client.get(url).status_code, 405)
        checked = Client(enforce_csrf_checks=True)
        checked.force_login(self.user)
        response = checked.post(url, {"identifier": "shop", "names": "shop.example.com"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(PlanPreparation.objects.count(), 0)

    def test_an_expired_review_asks_for_a_new_preparation(self) -> None:
        self.prepare_site()
        plan = self.site_plan()
        later = plan.admission_expires_at + timedelta(seconds=1)
        with mock.patch("bootstrap.presentation.timezone.now", return_value=later):
            page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, "admission deadline has passed")
        self.assertContains(page, "(expired)")

    def test_the_worker_rechecks_the_requesters_permission(self) -> None:
        self.sign_in_with(*SITE_PERMISSIONS)
        self.site.answer(self.remote)
        self.client.post(
            f"/servers/{self.server.pk}/sites/prepare/",
            {"identifier": "shop", "names": "shop.example.com"},
        )
        self.user.user_permissions.clear()
        self.run_worker()
        preparation = PlanPreparation.objects.get()
        self.assertEqual(preparation.status, Status.FAILED)
        self.assertEqual(self.remote.targets, [])

    def test_an_invalid_stored_request_reads_nothing(self) -> None:
        self.grant(*SITE_PERMISSIONS)
        self.site.answer(self.remote)
        preparation = request_preparation(self.server, self.user, Action.SITE_HTTP)
        assert preparation is not None  # noqa: S101 - queued on an idle server
        SiteRequest.objects.create(preparation=preparation, identifier="www", names="*.example.com")
        self.run_worker()
        preparation.refresh_from_db()
        self.assertEqual(
            (preparation.status, preparation.failure), (Status.FAILED, INVALID_REQUEST)
        )
        self.assertEqual(self.remote.commands, [])

    def test_a_preparation_without_its_request_reads_nothing(self) -> None:
        self.grant(*SITE_PERMISSIONS)
        self.site.answer(self.remote)
        request_preparation(self.server, self.user, Action.SITE_HTTP)
        self.run_worker()
        preparation = PlanPreparation.objects.get()
        self.assertEqual(
            (preparation.status, preparation.failure), (Status.FAILED, MISSING_REQUEST)
        )
        self.assertFalse(ConfigurationPlan.objects.exists())
        self.assertEqual(self.remote.commands, [])


class PermissionTests(SiteTestCase):
    """docs/sites.md#permissions: each family's plans are visible only to its viewers."""

    @override
    def setUp(self) -> None:
        super().setUp()
        self.prepare_site()
        self.site_plan_id = ConfigurationPlan.objects.get(action=Action.SITE_HTTP).pk
        self.user.user_permissions.clear()

    def as_user(self, *codenames: str) -> None:
        self.user.user_permissions.clear()
        for cache in ("_perm_cache", "_user_perm_cache", "_group_perm_cache"):
            self.user.__dict__.pop(cache, None)
        self.sign_in_with(*codenames)

    def test_an_inventory_only_account_sees_no_plans(self) -> None:
        self.as_user("view_server", "delete_server")
        self.assertEqual(self.client.get(f"/plans/{self.site_plan_id}/").status_code, 403)
        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertNotContains(page, "Site plans")
        self.assertNotContains(page, "Bootstrap plans")
        self.assertNotContains(self.client.get("/activity/"), "HTTP PHP site")
        removal = self.client.get(f"/servers/{self.server.pk}/remove/")
        self.assertNotContains(removal, "plan preparation")
        self.assertEqual(
            self.client.get(f"/servers/{self.server.pk}/sites/", headers=HTMX_FRAGMENT).status_code,
            403,
        )

    def test_a_bootstrap_account_sees_no_site_plans(self) -> None:
        self.as_user(*PLAN_PERMISSIONS, "delete_server")
        self.assertEqual(self.client.get(f"/plans/{self.site_plan_id}/").status_code, 403)
        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertContains(page, "Bootstrap plans")
        self.assertNotContains(page, "Site plans")
        self.assertNotContains(page, "HTTP PHP site")
        self.assertNotContains(self.client.get("/activity/"), "HTTP PHP site")
        removal = self.client.get(f"/servers/{self.server.pk}/remove/")
        self.assertContains(removal, "including kinds of plans you cannot view")
        self.assertContains(removal, "0 plan preparations of the kinds you can view")
        self.assertEqual(read_plans(self.server).history, [])
        response = self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/", {"action": "site_http"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(PlanPreparation.objects.count(), 1)

    def test_a_site_viewer_sees_site_plans_but_cannot_prepare(self) -> None:
        self.as_user(*SITE_VIEWER, "delete_server")
        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertContains(page, "Site plans")
        self.assertNotContains(page, "Prepare site plan")
        self.assertNotContains(page, "Bootstrap plans")
        self.assertEqual(self.client.get(f"/plans/{self.site_plan_id}/").status_code, 200)
        self.assertContains(self.client.get("/activity/"), "HTTP PHP site")
        removal = self.client.get(f"/servers/{self.server.pk}/remove/")
        self.assertContains(removal, "1 plan preparation of the kinds you can view")
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/prepare/",
            {"identifier": "blog", "names": "blog.example.com"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(PlanPreparation.objects.count(), 1)

    def test_bootstrap_plans_stay_hidden_from_site_viewers(self) -> None:
        self.as_user(*PLAN_PERMISSIONS)
        self.ubuntu.answer(self.remote)
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": "nginx"})
        self.run_worker()
        bootstrap_plan = ConfigurationPlan.objects.get(action=Action.NGINX)
        self.as_user(*SITE_VIEWER)
        self.assertEqual(self.client.get(f"/plans/{bootstrap_plan.pk}/").status_code, 403)
        self.assertNotContains(self.client.get("/activity/"), "Nginx profile")
