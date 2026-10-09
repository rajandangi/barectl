"""The WordPress maintenance review through requests and the worker
(docs/wordpress.md#maintaining-wordpress), against a simulated server.

Real views, services, the lifecycle, the ``db_worker`` command, persistence and rendering run;
only remote execution is substituted. ``test_maintenance_remote`` qualifies the native effects.
"""

from bootstrap.models import ConfigurationPlan, PlanPreparation, PlanRefusal
from servers.testing import HTMX_FRAGMENT
from sites.convention import Application, Stage

from .inspection_testing import CANONICAL
from .maintenance_models import Operation, PlanWordpressMaintenance
from .maintenance_testing import MAINTAIN_PREPARE, MAINTAIN_VIEW, MaintenanceTestCase

Reason = PlanRefusal.Reason


class ReviewTests(MaintenanceTestCase):
    def test_each_action_is_reviewed_without_any_change_or_application_code(self) -> None:
        for operation in Operation:
            with self.subTest(operation):
                plan = self.maintained(operation)
                self.assertTrue(plan.eligible, self.texts(plan))
                self.assertFalse(plan.no_changes)
                row = PlanWordpressMaintenance.objects.get(plan=plan)
                self.assertEqual(row.operation, operation)
                self.assertEqual(
                    (row.identifier, row.url), ("shop", "https://www.shop.example.com")
                )
                self.assertTrue(row.core_qualified)
                self.assertLess(row.payload_bytes or 0, 16 * 1024)
                self.assert_read_only()

    def test_the_review_binds_the_digests_the_run_rechecks(self) -> None:
        plan = self.maintained()
        kinds = set(plan.evidence.values_list("kind", flat=True))
        self.assertTrue({"site_revalidation", "wpcli_revalidation", "wordpress_state"} <= kinds)

    def test_the_rewrite_review_discloses_hooks_routes_and_load(self) -> None:
        plan = self.maintained(Operation.REWRITE)
        text = " ".join(plan.effects.values_list("text", flat=True))
        for phrase in (
            "`wp rewrite flush`",
            "without --hard",
            "never writes .htaccess, never edits the Nginx site file",
            "loader.php",
            "active plugins",
            "Their hooks run",
            "never as root",
            "one command-line PHP process of CPU, memory",
            "outside the lock",
            "Page caches are not cleared",
        ):
            self.assertIn(phrase, text)
        self.assertNotIn("--skip-plugins", text.replace("with --skip-plugins", ""))
        self.sign_in_as_viewer()
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, "wp rewrite flush")
        self.assertContains(page, "skip flags deliberately left off")
        self.assertNotContains(page, "wp rewrite flush --hard")

    def test_the_cache_review_makes_no_live_site_claim(self) -> None:
        plan = self.maintained(Operation.CACHE)
        text = " ".join(plan.effects.values_list("text", flat=True))
        self.assertIn("`wp cache flush`", text)
        self.assertIn("memory of one request", text)
        self.assertIn("clears the cache of its own command-line process", text)
        self.assertIn("does not present this as a live-site cache repair", text)
        self.assertIn("--skip-plugins and --skip-themes", text)
        self.assertNotIn("page cache is cleared", text)
        self.sign_in_as_viewer()
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, "wp cache flush")
        self.assertContains(page, "is not isolation")

    def sign_in_as_viewer(self) -> None:
        self.sign_in_as(*MAINTAIN_VIEW)


class RefusalTests(MaintenanceTestCase):
    def refused(self, operation: str = Operation.REWRITE) -> ConfigurationPlan:
        plan = self.maintained(operation)
        self.assertFalse(plan.eligible)
        self.assertFalse(PlanWordpressMaintenance.objects.filter(plan=plan).exists())
        return plan

    def test_a_site_without_wordpress_is_refused(self) -> None:
        self.site.add_activated("shop", Stage.REDIRECT)
        self.assertIn("does not serve WordPress", self.texts(self.refused()))

    def test_an_unfinished_installation_is_refused(self) -> None:
        self.site.add_activated("shop", Stage.REDIRECT, Application.WORDPRESS_GATE, CANONICAL)
        self.assertIn("provisioning gate", self.texts(self.refused()))

    def test_an_unsupported_configuration_or_core_is_refused(self) -> None:
        self.application.configuration = "unsupported"
        self.assertIn("not Barectl's supported form", self.texts(self.refused()))
        self.application.configuration = "supported"
        self.application.version = "6.0.0"
        self.assertIn(Reason.UNSUPPORTED_VERSION, self.reasons(self.refused()))

    def test_a_newer_core_is_diagnosable_but_never_maintained(self) -> None:
        self.application.version = "7.2.0"
        for operation in Operation:
            with self.subTest(operation):
                plan = self.refused(operation)
                self.assertIn("exact qualified core", self.texts(plan))
                self.assertIn(Reason.UNSUPPORTED_VERSION, self.reasons(plan))

    def test_a_cache_drop_in_refuses_the_cache_flush_as_unverified_scope(self) -> None:
        for name in ("object-cache.php", "advanced-cache.php", "db.php", "sunrise.php"):
            with self.subTest(name):
                self.application.dropins = {name: "a" * 64}
                text = self.texts(self.refused(Operation.CACHE))
                self.assertIn("scope of an object-cache flush is unverified", text)
                self.assertIn(name, text)

    def test_a_cache_drop_in_does_not_refuse_the_rewrite_flush_but_is_disclosed(self) -> None:
        self.application.dropins = {"object-cache.php": "a" * 64}
        plan = self.maintained(Operation.REWRITE)
        self.assertTrue(plan.eligible, self.texts(plan))
        self.assertIn("object-cache.php", " ".join(plan.effects.values_list("text", flat=True)))

    def test_an_inventory_larger_than_the_state_read_binds_is_refused(self) -> None:
        self.application.plugins = {f"plugin-{index:03d}": "d" for index in range(305)}
        self.assertIn("lists more than 300 entries", self.texts(self.refused()))

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


class PermissionTests(MaintenanceTestCase):
    def test_preparing_needs_the_plan_preparation_permission(self) -> None:
        self.sign_in_as(*MAINTAIN_VIEW)
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/shop/wordpress/maintenance/prepare/",
            {"maintenance-operation": "rewrite"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(PlanPreparation.objects.exists())

    def test_viewing_the_card_needs_the_plan_view_permission(self) -> None:
        self.sign_in_as("view_server", "view_siteobservation")
        poll = f"/servers/{self.server.pk}/sites/shop/wordpress/maintenance/"
        self.assertEqual(self.client.get(poll, headers=HTMX_FRAGMENT).status_code, 403)
        self.sign_in_as(*MAINTAIN_VIEW)
        self.assertEqual(self.client.get(poll, headers=HTMX_FRAGMENT).status_code, 200)

    def test_an_unnamed_action_is_not_queued(self) -> None:
        self.sign_in_as(*MAINTAIN_PREPARE)
        for value in ("hard", "rewrite flush --hard", ""):
            response = self.client.post(
                f"/servers/{self.server.pk}/sites/shop/wordpress/maintenance/prepare/",
                {"maintenance-operation": value},
                headers=HTMX_FRAGMENT,
            )
            self.assertEqual(response.status_code, 422)
        self.assertFalse(PlanPreparation.objects.exists())

    def test_the_site_page_separates_maintenance_from_inspection_and_passive_evidence(self) -> None:
        self.sign_in_as(*MAINTAIN_VIEW, "view_siteapplicationobservation")
        page = self.client.get(f"/servers/{self.server.pk}/sites/shop/wordpress/")
        self.assertContains(page, "Maintain WordPress")
        self.assertContains(page, "Maintenance runs WordPress and changes application state.")
        self.assertContains(page, "does <strong>not</strong> clear the running site")
        self.assertContains(page, "This is an explicit operation, not passive evidence.")
        self.assertNotContains(page, "Prepare WordPress maintenance review")
        self.sign_in_as(*MAINTAIN_PREPARE)
        page = self.client.get(f"/servers/{self.server.pk}/sites/shop/wordpress/")
        self.assertContains(page, "maintenance/prepare/")
