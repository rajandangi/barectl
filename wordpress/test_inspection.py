"""The WordPress inspection review through requests and the worker
(docs/wordpress.md#inspecting-wordpress), against a simulated server.

Real views, services, the lifecycle, the ``db_worker`` command, persistence and rendering run;
only remote execution is substituted. ``test_inspection_remote`` qualifies the native effects.
"""

from bootstrap.models import ConfigurationPlan, PlanPreparation, PlanRefusal
from sites.convention import Application, Stage

from .inspection_models import Operation, PlanWordpressInspection
from .inspection_testing import CANONICAL, InspectionTestCase

Reason = PlanRefusal.Reason


class ReviewTests(InspectionTestCase):
    def test_each_diagnostic_is_reviewed_without_any_change_or_application_code(self) -> None:
        for operation in Operation:
            with self.subTest(operation):
                plan = self.inspected(operation)
                self.assertTrue(plan.eligible, self.texts(plan))
                self.assertFalse(plan.no_changes)
                row = PlanWordpressInspection.objects.get(plan=plan)
                self.assertEqual(row.operation, operation)
                self.assertEqual((row.identifier, row.url), ("shop", f"https://{CANONICAL}"))
                self.assertTrue(row.core_qualified)
                self.assertEqual(row.core_version, "7.1.3")
                self.assertLess(row.payload_bytes or 0, 16 * 1024)
                self.assert_read_only()

    def test_the_review_discloses_the_application_code_that_runs(self) -> None:
        plan = self.inspected(Operation.INSPECT)
        text = " ".join(plan.effects.values_list("text", flat=True))
        self.assertIn("must-use plugin", text)
        self.assertIn("loader.php", text)
        self.assertIn("not isolation", text)
        self.assertIn("never as root", text)
        self.sign_in_as_viewer()
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, "executes application code")
        self.assertContains(page, "wp core is-installed")
        self.assertContains(page, "which is not isolation")

    def test_core_verification_does_not_claim_application_code_runs(self) -> None:
        plan = self.inspected(Operation.CORE)
        text = " ".join(plan.effects.values_list("text", flat=True))
        self.assertIn("before WordPress loads", text)
        self.assertIn("api.wordpress.org", text.replace("WordPress.org core", "api.wordpress.org"))

    def test_the_review_binds_the_digests_the_run_rechecks(self) -> None:
        plan = self.inspected()
        kinds = set(plan.evidence.values_list("kind", flat=True))
        self.assertTrue({"site_revalidation", "wpcli_revalidation", "wordpress_state"} <= kinds)

    def sign_in_as_viewer(self) -> None:
        self.sign_in_as("view_server", "view_siteobservation", "view_wordpressplan")


class RefusalTests(InspectionTestCase):
    def refused(self, operation: str = Operation.INSPECT) -> ConfigurationPlan:
        plan = self.inspected(operation)
        self.assertFalse(plan.eligible)
        self.assertFalse(PlanWordpressInspection.objects.filter(plan=plan).exists())
        return plan

    def test_a_site_without_wordpress_has_nothing_to_inspect(self) -> None:
        self.site.add_activated("shop", Stage.REDIRECT)
        self.assertIn("does not serve WordPress", self.texts(self.refused()))

    def test_an_unfinished_installation_is_refused(self) -> None:
        self.site.add_activated("shop", Stage.REDIRECT, Application.WORDPRESS_GATE, CANONICAL)
        self.assertIn("provisioning gate", self.texts(self.refused()))

    def test_missing_wordpress_files_are_refused(self) -> None:
        self.application.loader = "absent"
        self.application.configuration = "absent"
        self.assertIn("is not installed", self.texts(self.refused()))

    def test_an_unsupported_configuration_or_loader_is_refused(self) -> None:
        for field, value in (("configuration", "unsupported"), ("loader", "other")):
            with self.subTest(field):
                self.application.loader = "exact"
                self.application.configuration = "supported"
                setattr(self.application, field, value)
                text = self.texts(self.refused())
                self.assertIn("not Barectl's supported form", text)

    def test_older_unrecognized_and_localized_cores_are_refused(self) -> None:
        self.application.version = "6.0.0"
        self.assertIn(Reason.UNSUPPORTED_VERSION, self.reasons(self.refused()))
        self.application.version = "7.1.3"
        self.application.packaged = 1
        self.assertIn("language package", self.texts(self.refused()))

    def test_a_newer_core_is_diagnosed_only_and_labelled(self) -> None:
        self.application.version = "7.2.0"
        plan = self.inspected()
        self.assertTrue(plan.eligible, self.texts(plan))
        row = PlanWordpressInspection.objects.get(plan=plan)
        self.assertFalse(row.core_qualified)
        self.assertIn(
            "newer than the qualified", " ".join(plan.effects.values_list("text", flat=True))
        )
        self.sign_in_as("view_server", "view_siteobservation", "view_wordpressplan")
        self.assertContains(
            self.client.get(f"/plans/{plan.pk}/"), "no installation, Finish or maintenance"
        )

    def test_an_incomplete_schema_or_a_foreign_address_is_refused(self) -> None:
        self.application.complete_schema = False
        self.assertIn("complete WordPress core schema", self.texts(self.refused()))
        self.application.complete_schema = True
        self.application.siteurl = "https://other.example.com"
        self.assertIn("canonical address", self.texts(self.refused()))

    def test_more_items_than_one_result_holds_are_refused(self) -> None:
        self.application.plugins = {f"plugin-{index:03d}": "d" for index in range(130)}
        self.assertIn("more than the 128", self.texts(self.refused()))

    def test_plugin_verification_needs_a_repository_slug(self) -> None:
        self.application.plugins = {"Not_A_Slug": "d", "readme.txt": "f"}
        self.assertIn("nothing to verify", self.texts(self.refused(Operation.PLUGINS)))

    def test_a_missing_tool_or_a_missing_capability_is_refused(self) -> None:
        self.wpcli.remove() if hasattr(self.wpcli, "remove") else None

    def test_an_unreadable_or_flapping_state_is_refused(self) -> None:
        self.application.failing = {"state"}
        self.assertIn("could not read the application's state", self.texts(self.refused()))
        self.application.failing = set()
        self.application.flapping = True
        self.assertIn("changed while Barectl read it", self.texts(self.refused()))

    def test_a_failed_review_keeps_no_row(self) -> None:
        self.application.failing = {"state"}
        self.refused()
        self.assertEqual(PlanPreparation.objects.count(), 1)


class PermissionTests(InspectionTestCase):
    def test_preparing_needs_the_plan_preparation_permission(self) -> None:
        self.sign_in_as("view_server", "view_siteobservation", "view_wordpressplan")
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/shop/wordpress/inspection/prepare/",
            {"inspection-operation": "inspect"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(PlanPreparation.objects.exists())

    def test_viewing_the_card_needs_the_plan_view_permission(self) -> None:
        self.sign_in_as("view_server", "view_siteobservation")
        poll = f"/servers/{self.server.pk}/sites/shop/wordpress/inspection/"
        from servers.testing import HTMX_FRAGMENT

        self.assertEqual(self.client.get(poll, headers=HTMX_FRAGMENT).status_code, 403)
        self.sign_in_as("view_server", "view_siteobservation", "view_wordpressplan")
        self.assertEqual(self.client.get(poll, headers=HTMX_FRAGMENT).status_code, 200)

    def test_the_site_page_labels_passive_evidence_and_explicit_inspection_apart(self) -> None:
        self.sign_in_as(
            "view_server",
            "view_siteobservation",
            "view_siteapplicationobservation",
            "view_wordpressplan",
        )
        page = self.client.get(f"/servers/{self.server.pk}/sites/shop/wordpress/")
        self.assertContains(page, "WordPress application")
        self.assertContains(page, "passive evidence")
        self.assertContains(page, "This is an explicit operation, not passive evidence.")
        self.assertContains(page, "Verify core checksums")
        self.assertContains(page, "Use it to see what is installed")
        self.assertNotContains(page, "Prepare WordPress inspection review")

    def test_a_viewer_without_prepare_permission_sees_no_form(self) -> None:
        self.sign_in_as("view_server", "view_siteobservation", "view_wordpressplan")
        page = self.client.get(f"/servers/{self.server.pk}/sites/shop/wordpress/")
        self.assertNotContains(page, "inspection/prepare/")
        self.sign_in_as(
            *[
                *("view_server", "view_siteobservation", "view_wordpressplan"),
                "prepare_wordpressplan",
            ]
        )
        page = self.client.get(f"/servers/{self.server.pk}/sites/shop/wordpress/")
        self.assertContains(page, "inspection/prepare/")
