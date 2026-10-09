"""Who may request, see and poll a Finish review, and what the form accepts.

docs/wordpress.md#review-permissions. Site, database, TLS, bootstrap and installation-review
access alone grant none of it where it does not belong, and every request, poll and dispatch
checks the account again.
"""

from django.contrib.auth.models import Permission

from bootstrap.models import ApplyRun, ConfigurationPlan, PlanPreparation
from bootstrap.services import REVOKED_FAILURE
from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt
from operations.models import RemoteOperation
from servers.testing import HTMX_FRAGMENT

from .finish_testing import ADDRESS, FORM, POLL, FinishTestCase
from .install_testing import OTHER_PERMISSIONS, PREPARE, VIEW
from .models import FinishRequest, PlanWordpressFinish

Status = RemoteOperation.Status


class PermissionTests(FinishTestCase):
    def post(self, form: dict[str, str] | None = None, *, fragment: bool = True) -> int:
        return self.client.post(
            ADDRESS.format(pk=self.server.pk),
            FORM if form is None else form,
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

    def test_the_plan_page_hides_a_review_from_other_plan_viewers(self) -> None:
        plan = self.reviewed()
        self.sign_in_as(*OTHER_PERMISSIONS)
        self.assertEqual(self.client.get(f"/plans/{plan.pk}/").status_code, 403)
        self.sign_in_as(*VIEW)
        self.assertEqual(self.client.get(f"/plans/{plan.pk}/").status_code, 200)

    def test_the_site_page_shows_the_card_only_to_accounts_that_may_see_it(self) -> None:
        self.reviewed()
        page = f"/servers/{self.server.pk}/sites/shop/wordpress/"
        self.sign_in_as(*VIEW)
        viewer = self.client.get(page)
        self.assertNotContains(viewer, "Prepare Finish review")
        self.assertContains(viewer, "Finish a partial WordPress installation")
        self.sign_in_as(*PREPARE)
        card = self.client.get(page)
        self.assertContains(card, "Prepare Finish review")
        self.sign_in_as("view_server", "view_siteobservation", "view_configurationplan")
        other = self.client.get(page)
        self.assertNotContains(other, "Prepare Finish review")
        self.assertContains(other, "may view WordPress plans can review the completion")

    def test_the_activity_lists_reviews_only_to_accounts_that_may_view_them(self) -> None:
        self.reviewed()
        activity = f"/servers/{self.server.pk}/sites/shop/activity/"
        self.sign_in_as("view_server", "view_siteobservation", "view_wordpressplan")
        self.assertContains(self.client.get(activity), "WordPress installation Finish")
        self.sign_in_as("view_server", "view_siteobservation", "view_configurationplan")
        self.assertNotContains(self.client.get(activity), "WordPress installation Finish")

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

    def test_finishing_is_offered_only_to_an_account_that_may_install(self) -> None:
        plan = self.reviewed()
        self.sign_in_as(*VIEW)
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertNotContains(page, f"/plans/{plan.pk}/apply/")
        response = self.client.post(f"/plans/{plan.pk}/apply/")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(ApplyRun.objects.count(), 0)
        self.sign_in_as(*VIEW, "install_wordpress")
        self.assertContains(self.client.get(f"/plans/{plan.pk}/"), f"/plans/{plan.pk}/apply/")
        self.assertEqual(ConfigurationPlan.objects.get().pk, plan.pk)


class FormTests(FinishTestCase):
    def submit(self, **changes: str) -> tuple[int, str]:
        self.sign_in_as(*PREPARE)
        form = {**FORM, **{f"finish-{name}": value for name, value in changes.items()}}
        response = self.client.post(ADDRESS.format(pk=self.server.pk), form, headers=HTMX_FRAGMENT)
        return response.status_code, response.content.decode()

    def test_a_valid_request_queues_a_review_of_the_sites_own_identifier(self) -> None:
        status, _ = self.submit()
        self.assertEqual(status, 200)
        request = FinishRequest.objects.get()
        self.assertEqual(request.identifier, "shop")
        self.assertEqual(request.preparation.action, "wordpress_finish")

    def test_the_metadata_is_optional_but_all_or_nothing(self) -> None:
        self.sign_in_as(*PREPARE)
        response = self.client.post(ADDRESS.format(pk=self.server.pk), {}, headers=HTMX_FRAGMENT)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(FinishRequest.objects.get().title, "")
        PlanPreparation.objects.all().delete()
        status, content = self.submit(title="", admin_login="", admin_email="owner@example.com")
        self.assertEqual(status, 422)
        self.assertIn("Enter a site title", content)
        self.assertEqual(PlanPreparation.objects.count(), 0)

    def test_invalid_input_names_its_field_and_queues_nothing(self) -> None:
        cases = {
            "title": (("<b>x</b>", "must not contain"), ("x" * 101, "at most")),
            "admin_login": (("A B", "Enter 3 to 60"),),
            "admin_email": (("not-an-email", "plain email"),),
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
            ADDRESS.format(pk=self.server.pk), {**FORM, "finish-admin_login": "A B"}
        )
        self.assertEqual(response.status_code, 422)
        self.assertContains(response, "Enter 3 to 60", status_code=422)
        self.assertContains(response, 'value="Shop &amp; Sons"', status_code=422)
        self.assertEqual(PlanPreparation.objects.count(), 0)

    def test_no_address_password_version_or_command_can_be_supplied(self) -> None:
        self.sign_in_as(*PREPARE)
        page = self.client.get(f"/servers/{self.server.pk}/sites/shop/wordpress/").content.decode()
        for word in ("canonical_name", "password", "version", "command", "latest", "url"):
            self.assertNotIn(f'name="finish-{word}', page)
        self.submit()
        self.assertFalse(hasattr(FinishRequest.objects.get(), "canonical_name"))

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
        url = f"/servers/{self.server.pk}/sites/nothere/wordpress/finish/prepare/"
        self.assertEqual(self.client.post(url, FORM, headers=HTMX_FRAGMENT).status_code, 404)
        self.assertEqual(PlanPreparation.objects.count(), 0)


class PollTests(FinishTestCase):
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
        self.assertEqual(PlanWordpressFinish.objects.count(), 1)

    def test_the_install_card_and_the_finish_card_keep_their_own_reviews(self) -> None:
        self.reviewed()
        self.sign_in_as(*VIEW)
        install = self.client.get(
            f"/servers/{self.server.pk}/sites/shop/wordpress/install/", headers=HTMX_FRAGMENT
        )
        self.assertContains(install, "No installation review for this site yet")
        finish = self.client.get(POLL.format(pk=self.server.pk), headers=HTMX_FRAGMENT)
        self.assertNotContains(finish, "No Finish review for this site yet")

    def test_a_poll_without_htmx_returns_to_the_page(self) -> None:
        self.sign_in_as(*VIEW)
        response = self.client.get(POLL.format(pk=self.server.pk))
        self.assertRedirects(
            response,
            f"/servers/{self.server.pk}/sites/shop/wordpress/",
            fetch_redirect_response=False,
        )


class ImmutabilityTests(FinishTestCase):
    def test_the_review_and_its_request_cannot_change(self) -> None:
        plan = self.reviewed()
        review = PlanWordpressFinish.objects.get(plan=plan)
        review.absent_names = "wp-admin"
        with self.assertRaises(ValueError):
            review.save()
        request = FinishRequest.objects.get()
        request.admin_email = "other@example.com"
        with self.assertRaises(ValueError):
            request.save()

    def test_changed_evidence_makes_a_new_review_and_keeps_the_earlier_one(self) -> None:
        first = self.reviewed()
        self.stranded.leave("configuration")
        self.sign_in_as(*PREPARE)
        self.client.post(ADDRESS.format(pk=self.server.pk), FORM, headers=HTMX_FRAGMENT)
        self.run_worker()
        second = ConfigurationPlan.objects.exclude(pk=first.pk).get()
        old = PlanWordpressFinish.objects.get(plan=first)
        new = PlanWordpressFinish.objects.get(plan=second)
        self.assertTrue(old.creates_configuration)
        self.assertFalse(new.creates_configuration)
        self.assertNotEqual(old.body_sha256, new.body_sha256)
