"""Who may request, see and poll an installation review, and what the form accepts.

docs/wordpress.md#review-permissions. Site, database, TLS and bootstrap access alone grant none of
it, and every request, poll and dispatch checks the account again.
"""

from django.contrib.auth.models import Permission

from bootstrap.fakes import PLAN_PERMISSIONS
from bootstrap.models import ApplyRun, ConfigurationPlan, PlanPreparation
from bootstrap.services import REVOKED_FAILURE
from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt
from operations.models import RemoteOperation
from servers.testing import HTMX_FRAGMENT

from .install_testing import ADDRESS, FORM, POLL, PREPARE, VIEW, InstallTestCase
from .models import InstallationRequest, PlanWordpressInstall

Status = RemoteOperation.Status
OTHER_PERMISSIONS = (
    *PLAN_PERMISSIONS,
    "apply_configurationplan",
    "view_siteobservation",
    "view_siteplan",
    "prepare_siteplan",
    "view_databaseplan",
    "prepare_databaseplan",
    "view_tlsplan",
    "prepare_tlsplan",
    "apply_tlsplan",
    "issue_certificate",
    "view_siteapplicationobservation",
)


class PermissionTests(InstallTestCase):
    def post(self, form: dict[str, str] | None = None, *, fragment: bool = True) -> int:
        return self.client.post(
            ADDRESS.format(pk=self.server.pk),
            form or FORM,
            headers=HTMX_FRAGMENT if fragment else {},
        ).status_code

    def test_every_other_workflows_permissions_grant_nothing(self) -> None:
        self.sign_in_as(*OTHER_PERMISSIONS)
        self.answer_all()
        self.assertEqual(self.post(), 403)
        self.assertEqual(
            self.client.get(POLL.format(pk=self.server.pk), headers=HTMX_FRAGMENT).status_code, 403
        )
        self.assertEqual(PlanPreparation.objects.count(), 0)
        self.assertEqual(self.remote.commands, [])

    def test_viewing_plans_does_not_prepare_them(self) -> None:
        self.sign_in_as(*VIEW)
        self.assertEqual(self.post(), 403)
        self.assertEqual(self.post(fragment=False), 403)
        self.assertEqual(PlanPreparation.objects.count(), 0)

    def test_preparing_also_needs_the_sites_observation(self) -> None:
        self.sign_in_as("view_server", "view_wordpressplan", "prepare_wordpressplan")
        self.assertEqual(self.post(), 403)
        self.assertEqual(PlanPreparation.objects.count(), 0)

    def test_an_anonymous_request_is_sent_to_sign_in(self) -> None:
        response = self.client.post(ADDRESS.format(pk=self.server.pk), FORM)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(PlanPreparation.objects.count(), 0)

    def test_the_poll_needs_the_plan_view_and_the_site_observation(self) -> None:
        self.sign_in_as("view_server", "view_siteobservation")
        url = POLL.format(pk=self.server.pk)
        self.assertEqual(self.client.get(url, headers=HTMX_FRAGMENT).status_code, 403)
        self.sign_in_as(*VIEW)
        self.assertEqual(self.client.get(url, headers=HTMX_FRAGMENT).status_code, 200)

    def test_the_plan_page_and_polls_hide_a_review_from_other_plan_viewers(self) -> None:
        plan = self.reviewed()
        self.sign_in_as(*OTHER_PERMISSIONS)
        self.assertEqual(self.client.get(f"/plans/{plan.pk}/").status_code, 403)
        self.sign_in_as(*VIEW)
        self.assertEqual(self.client.get(f"/plans/{plan.pk}/").status_code, 200)

    def test_the_site_page_shows_each_card_only_to_accounts_that_may_see_it(self) -> None:
        self.reviewed()
        page = f"/servers/{self.server.pk}/sites/shop/wordpress/"
        self.sign_in_as(*VIEW)
        viewer = self.client.get(page)
        self.assertNotContains(viewer, "Prepare WordPress installation review")
        self.assertContains(viewer, "owner@example.com")
        self.sign_in_as(*PREPARE)
        card = self.client.get(page)
        self.assertContains(card, "Prepare WordPress installation review")
        self.assertNotContains(card, 'id="site-wordpress-runtime"')
        self.assertContains(card, "owner@example.com")
        self.sign_in_as("view_server", "view_siteobservation", "view_configurationplan")
        other = self.client.get(page)
        self.assertNotContains(other, "owner@example.com")
        self.assertNotContains(other, "Prepare WordPress installation review")
        self.assertContains(other, "may view WordPress plans can review the installation")

    def test_the_activity_lists_reviews_only_to_accounts_that_may_view_them(self) -> None:
        self.reviewed()
        activity = f"/servers/{self.server.pk}/sites/shop/activity/"
        self.sign_in_as("view_server", "view_siteobservation", "view_wordpressplan")
        self.assertContains(self.client.get(activity), "WordPress installation review")
        self.sign_in_as("view_server", "view_siteobservation", "view_configurationplan")
        self.assertNotContains(self.client.get(activity), "WordPress installation review")

    def test_the_account_is_revalidated_before_the_worker_connects(self) -> None:
        user = type(self.user)

        def remove_permission() -> None:
            self.user.user_permissions.remove(
                Permission.objects.get(codename="prepare_wordpressplan")
            )

        def remove_site_observation() -> None:
            self.user.user_permissions.remove(
                Permission.objects.get(codename="view_siteobservation")
            )

        def deactivate() -> None:
            user.objects.filter(pk=self.user.pk).update(is_active=False)

        for name, revoke in {
            "permission": remove_permission,
            "site observation": remove_site_observation,
            "deactivation": deactivate,
        }.items():
            with self.subTest(revocation=name):
                PlanPreparation.objects.all().delete()
                user.objects.filter(pk=self.user.pk).update(is_active=True)
                self.sign_in_as(*PREPARE)
                self.answer_all()
                self.assertEqual(self.post(), 200)
                revoke()
                self.remote.targets.clear()
                self.run_worker()
                preparation = PlanPreparation.objects.get()
                self.assertEqual(preparation.status, Status.FAILED)
                self.assertEqual(preparation.failure, REVOKED_FAILURE)
                self.assertEqual(self.remote.targets, [])

    def test_installing_is_not_offered_even_to_an_account_that_may_install(self) -> None:
        plan = self.reviewed()
        self.sign_in_as(*VIEW, "install_wordpress")
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertNotContains(page, f"/plans/{plan.pk}/apply/")
        response = self.client.post(f"/plans/{plan.pk}/apply/")
        self.assertEqual(ApplyRun.objects.count(), 0)
        self.assertRedirects(response, f"/plans/{plan.pk}/")
        self.assertEqual(ConfigurationPlan.objects.get().pk, plan.pk)


class FormTests(InstallTestCase):
    def submit(self, **changes: str) -> tuple[int, str]:
        self.sign_in_as(*PREPARE)
        form = {**FORM, **{f"wordpress-{name}": value for name, value in changes.items()}}
        response = self.client.post(ADDRESS.format(pk=self.server.pk), form, headers=HTMX_FRAGMENT)
        return response.status_code, response.content.decode()

    def test_a_valid_request_queues_a_review_of_the_sites_own_identifier(self) -> None:
        status, _ = self.submit()
        self.assertEqual(status, 200)
        request = InstallationRequest.objects.get()
        self.assertEqual(request.identifier, "shop")
        self.assertEqual(request.preparation.action, "wordpress_install")

    def test_invalid_input_names_its_field_and_queues_nothing(self) -> None:
        cases = {
            "canonical_name": (
                ("https://user:pw@www.shop.example.com", "credentials"),
                ("https://www.shop.example.com:8443", "port"),
                ("https://www.shop.example.com/blog", "remove the path"),
                ("https://www.shop.example.com/?a=1", "query"),
                ("https://www.shop.example.com/#x", "fragment"),
                ("http://www.shop.example.com", "HTTPS"),
                ("other.example.com", "not one of the names this site serves"),
                ("192.0.2.1", "IP addresses"),
            ),
            "title": (
                ("", "Enter a site title"),
                ("<b>x</b>", "must not contain"),
                ("x" * 101, "at most"),
            ),
            "admin_login": (("A B", "Enter 3 to 60"), ("", "Enter the administrator login")),
            "admin_email": (("not-an-email", "plain email"), ("", "Enter the administrator email")),
        }
        for field, examples in cases.items():
            for value, message in examples:
                with self.subTest(field=field, value=value):
                    status, content = self.submit(**{field: value})
                    self.assertEqual(status, 422)
                    self.assertIn(message, content)
                    self.assertIn("usa-form-group--error", content)
                    self.assertEqual(PlanPreparation.objects.count(), 0)

    def test_an_invalid_request_without_htmx_renders_the_whole_page_with_the_input_kept(
        self,
    ) -> None:
        self.sign_in_as(*PREPARE)
        response = self.client.post(
            ADDRESS.format(pk=self.server.pk), {**FORM, "wordpress-admin_login": "A B"}
        )
        self.assertEqual(response.status_code, 422)
        self.assertContains(response, "Enter 3 to 60", status_code=422)
        self.assertContains(response, 'value="Shop &amp; Sons"', status_code=422)
        self.assertEqual(PlanPreparation.objects.count(), 0)

    def test_no_password_version_or_command_can_be_supplied(self) -> None:
        self.sign_in_as(*PREPARE)
        page = self.client.get(f"/servers/{self.server.pk}/sites/shop/wordpress/").content.decode()
        for word in ("password", "version", "command", "latest"):
            self.assertNotIn(f'name="wordpress-{word}', page)
        status, _ = self.submit()
        self.assertEqual(status, 200)
        request = InstallationRequest.objects.get()
        self.assertFalse(hasattr(request, "version"))

    def test_a_second_request_while_one_is_active_is_busy(self) -> None:
        self.submit()
        status, content = self.submit()
        self.assertEqual(status, 200)
        self.assertIn("Barectl is running another remote operation", content)
        self.assertEqual(PlanPreparation.objects.count(), 1)

    def test_a_later_connection_check_makes_the_site_stale_and_queues_nothing(self) -> None:
        record_attempt(self.server, DiscoveryAttempt.Status.FAILED, failure="No answer.")
        status, content = self.submit()
        self.assertEqual(status, 409)
        self.assertIn("Refresh observations before changing this site", content)
        self.assertEqual(PlanPreparation.objects.count(), 0)

    def test_a_site_the_observation_does_not_show_is_not_found(self) -> None:
        self.sign_in_as(*PREPARE)
        url = f"/servers/{self.server.pk}/sites/nothere/wordpress/install/prepare/"
        self.assertEqual(self.client.post(url, FORM, headers=HTMX_FRAGMENT).status_code, 404)
        self.assertEqual(PlanPreparation.objects.count(), 0)


class PollTests(InstallTestCase):
    def test_the_card_polls_while_a_review_is_active_and_stops_when_it_is_done(self) -> None:
        self.sign_in_as(*PREPARE)
        self.answer_all()
        self.client.post(ADDRESS.format(pk=self.server.pk), FORM, headers=HTMX_FRAGMENT)
        poll = POLL.format(pk=self.server.pk)
        active = self.client.get(poll + "?shown=x", headers=HTMX_FRAGMENT)
        self.assertContains(active, 'hx-trigger="every 2s"')
        self.assertContains(active, "queued")
        self.run_worker()
        done = self.client.get(poll + "?shown=x", headers=HTMX_FRAGMENT)
        self.assertNotContains(done, 'hx-trigger="every 2s"')
        self.assertContains(done, "Ready for review")
        self.assertContains(done, "https://www.shop.example.com/")
        self.assertEqual(PlanWordpressInstall.objects.count(), 1)

    def test_a_poll_without_htmx_returns_to_the_page(self) -> None:
        self.sign_in_as(*VIEW)
        response = self.client.get(POLL.format(pk=self.server.pk))
        self.assertRedirects(
            response,
            f"/servers/{self.server.pk}/sites/shop/wordpress/",
            fetch_redirect_response=False,
        )


class ImmutabilityTests(InstallTestCase):
    def test_the_review_and_its_request_cannot_change(self) -> None:
        plan = self.reviewed()
        review = PlanWordpressInstall.objects.get(plan=plan)
        review.title = "Changed"
        with self.assertRaises(ValueError):
            review.save()
        request = InstallationRequest.objects.get()
        request.admin_email = "other@example.com"
        with self.assertRaises(ValueError):
            request.save()

    def test_changed_evidence_makes_a_new_review_and_keeps_the_earlier_one(self) -> None:
        first = self.reviewed()
        self.state.public = {"index.html": "f", "wp-config.php": "f"}
        self.sign_in_as(*PREPARE)
        self.client.post(ADDRESS.format(pk=self.server.pk), FORM, headers=HTMX_FRAGMENT)
        self.run_worker()
        second = ConfigurationPlan.objects.exclude(pk=first.pk).get()
        self.assertTrue(first.eligible)
        self.assertFalse(second.eligible)
        self.assertTrue(PlanWordpressInstall.objects.filter(plan=first).exists())
        self.assertFalse(PlanWordpressInstall.objects.filter(plan=second).exists())
