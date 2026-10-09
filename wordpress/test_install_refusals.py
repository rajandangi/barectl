"""The installation review's admission refusals (docs/wordpress.md#installation-review).

Each case changes one fact of the prepared site and expects a named, actionable refusal,
no saved review rows, and no write to the server.
"""

from bootstrap.models import ConfigurationPlan, PlanPreparation, PlanRefusal
from discovery.observations.databases import satisfied_postgresql_rows
from operations.models import RemoteOperation
from sites.convention import Application, Stage

from . import core_native, inputs
from .install_testing import PREPARE, InstallTestCase
from .models import InstallationRequest, PlanWordpressInstall
from .services import request_install_preparation

Reason = PlanRefusal.Reason
Status = RemoteOperation.Status


class RefusalTestCase(InstallTestCase):
    def refused(self, reason: str, *fragments: str) -> ConfigurationPlan:
        plan = self.reviewed()
        self.assertFalse(plan.eligible)
        self.assertIn(reason, self.reasons(plan), self.texts(plan))
        for fragment in fragments:
            self.assertIn(fragment, self.texts(plan))
        self.assertFalse(PlanWordpressInstall.objects.filter(plan=plan).exists())
        return plan


class SiteRefusalTests(RefusalTestCase):
    def test_an_unknown_site_does_not_follow_the_convention(self) -> None:
        self.site.sites.clear()
        self.refused(Reason.NOT_FOLLOWING, "does not follow the convention")

    def test_a_site_without_https_refuses_before_any_conversion(self) -> None:
        self.site.stages["shop"] = Stage.CHALLENGE
        self.refused(Reason.PREREQUISITE, "does not serve HTTPS", "activate the site's HTTPS")

    def test_a_site_serving_https_without_the_redirect_is_not_complete(self) -> None:
        self.site.stages["shop"] = Stage.HTTPS
        self.refused(Reason.PREREQUISITE, "does not serve HTTPS with the HTTP redirect")

    def test_a_name_the_site_does_not_cover_is_refused(self) -> None:
        self.sign_in_with(*PREPARE)
        self.answer_all()
        request_install_preparation(
            self.server,
            self.user,
            "shop",
            inputs.Metadata("other.example.com", "Shop", "owner", "owner@example.com"),
        )
        self.run_worker()
        plan = ConfigurationPlan.objects.get()
        self.assertFalse(plan.eligible)
        self.assertIn(
            "other.example.com is not one of the names the site shop serves", self.texts(plan)
        )

    def test_a_site_already_routing_wordpress_is_refused(self) -> None:
        self.site.applications["shop"] = (Application.WORDPRESS_GATE, "shop.example.com")
        plan = self.reviewed()
        self.assertFalse(plan.eligible)
        self.assertIn(Reason.EXISTING_APPLICATION, self.reasons(plan), self.texts(plan))

    def test_a_missing_certificate_lineage_is_refused(self) -> None:
        self.tls.production = ""
        self.refused(Reason.PREREQUISITE, "certificate lineage")

    def test_a_lineage_for_other_names_is_refused(self) -> None:
        self.tls.production = self.tls.production.replace("www.shop.example.com", "www.other.test")
        self.refused(Reason.COLLISION, "names")


class PrerequisiteRefusalTests(RefusalTestCase):
    def test_postgresql_is_refused_without_conversion(self) -> None:
        self.site.ubuntu.postgresql = "installed"
        self.database.other = satisfied_postgresql_rows("sshop")
        self.refused(
            Reason.UNSUPPORTED_ENGINE,
            "PostgreSQL holds",
            "converts no engine",
            "no PostgreSQL adapter",
        )

    def test_a_site_without_a_binding_names_the_database_workflow(self) -> None:
        self.database.mariadb = ""
        self.refused(Reason.PREREQUISITE, "no satisfied MariaDB binding", "MariaDB database first")

    def test_missing_extensions_are_named_not_installed(self) -> None:
        self.site.drivers = ("mysql", "curl")
        plan = self.refused(Reason.PREREQUISITE, "WordPress baseline", "installs no package")
        self.assertIn("ZIP archives", self.texts(plan))

    def test_a_missing_tool_names_the_setup_workflow(self) -> None:
        self.wpcli.phar = "absent"
        self.refused(Reason.PREREQUISITE, "is not installed", "WP-CLI setup plan first")

    def test_a_foreign_tool_is_not_adopted(self) -> None:
        self.wpcli.phar = "foreign"
        plan = self.reviewed()
        self.assertFalse(plan.eligible)
        self.assertIn("cannot be verified", self.texts(plan))


class ApplicationRefusalTests(RefusalTestCase):
    def test_existing_wordpress_files_are_never_adopted(self) -> None:
        self.state.public = {"index.html": "f", "wp-config.php": "f", "wp-includes": "d"}
        self.refused(
            Reason.EXISTING_APPLICATION,
            "WordPress files (wp-config.php, wp-includes)",
            "never overwrites",
        )

    def test_foreign_content_is_refused_without_deletion(self) -> None:
        self.state.public = {"index.html": "f", "shop.html": "f"}
        self.refused(Reason.EXISTING_APPLICATION, "content other than the site placeholder")

    def test_an_edited_placeholder_is_application_content(self) -> None:
        self.state.placeholder = "<html>my page</html>\n"
        self.refused(Reason.EXISTING_APPLICATION, "not the exact known placeholder")

    def test_a_private_configuration_is_never_adopted(self) -> None:
        self.state.private = {"wp-config.php": "f"}
        self.refused(Reason.EXISTING_APPLICATION, "a private WordPress configuration")

    def test_foreign_entries_beside_the_site_directories_are_refused(self) -> None:
        self.state.beside = {"wpprobe-1.php": "f"}
        self.refused(Reason.COLLISION, "wpprobe-1.php")

    def test_tables_in_the_database_refuse_core_installation(self) -> None:
        self.state.tables = ("wp_options", "wp_users", "wp_posts")
        self.refused(
            Reason.EXISTING_APPLICATION, "not empty", "wp_options, wp_users, wp_posts", "replays"
        )

    def test_routines_events_and_triggers_count_as_content(self) -> None:
        for field in ("routines", "events", "triggers"):
            with self.subTest(field=field):
                setattr(self.state, field, 1)
                self.refused(Reason.EXISTING_APPLICATION, "not empty")
                setattr(self.state, field, 0)

    def test_a_missing_database_refuses(self) -> None:
        self.state.exists = False
        self.refused(Reason.PREREQUISITE, "does not exist")


class SupplyRefusalTests(RefusalTestCase):
    def test_missing_native_tools_are_named(self) -> None:
        self.state.tools = ("curl", "sha256sum")
        self.refused(Reason.PREREQUISITE, "/usr/bin/tar")

    def test_too_little_space_is_refused_with_the_figures(self) -> None:
        self.state.free_bytes = 10 * 2**20
        self.refused(
            Reason.PREREQUISITE, f"{10 * 2**20} bytes free", str(core_native.REQUIRED_FREE_BYTES)
        )

    def test_an_unreachable_archive_is_refused(self) -> None:
        self.state.archive_status = 000
        self.state.archive_bytes = 0
        self.refused(Reason.PREREQUISITE, "trusted HTTPS", core_native.ARCHIVE_URL)

    def test_a_different_archive_size_is_refused(self) -> None:
        self.state.archive_bytes = core_native.ARCHIVE_BYTES + 1
        self.refused(Reason.INCOMPLETE, "not the reviewed 35368461", "different archive is refused")


class EvidenceRefusalTests(RefusalTestCase):
    def test_a_failing_read_is_incomplete_evidence_not_an_empty_one(self) -> None:
        for name in ("files", "database", "supply"):
            with self.subTest(read=name):
                self.state.failing = {name}
                self.refused(Reason.INCOMPLETE, "could not read")
                self.state.failing = set()

    def test_a_tree_that_changes_while_it_is_read_refuses(self) -> None:
        self.state.flapping = {"files"}
        self.refused(Reason.INCOMPLETE, "changed while Barectl read it")

    def test_a_lesser_ssh_identity_cannot_read_the_trees(self) -> None:
        self.site.privilege = "none"
        plan = self.reviewed()
        self.assertFalse(plan.eligible)
        self.assertIn(Reason.PRIVILEGE, self.reasons(plan), self.texts(plan))
        self.assertFalse(PlanWordpressInstall.objects.exists())

    def test_a_stored_request_that_is_not_valid_fails_before_any_read(self) -> None:
        self.sign_in_with(*PREPARE)
        self.answer_all()
        preparation = request_install_preparation(
            self.server,
            self.user,
            "shop",
            inputs.Metadata("www.shop.example.com", "Shop", "owner", "owner@example.com"),
        )
        assert preparation is not None  # noqa: S101 - queued on an idle server
        InstallationRequest.objects.filter(preparation=preparation).update(
            canonical_name="https://user:pw@shop.example.com:8443/blog"
        )
        self.remote.commands.clear()
        self.run_worker()
        preparation = PlanPreparation.objects.get(pk=preparation.pk)
        self.assertEqual(preparation.status, Status.FAILED)
        self.assertIn("not valid", preparation.failure)
        self.assertEqual(self.remote.commands, [])
