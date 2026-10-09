"""The WordPress Finish review (docs/wordpress.md#finishing-a-partial-installation), against a
simulated server.

Real views, services, the lifecycle, the ``db_worker`` command, persistence and rendering run;
only remote execution is substituted. Each case describes the state an interrupted
installation can leave and expects an immutable review of exactly the missing, verified work, or
a named refusal that saves no review and writes nothing to the server. The reads' native
behavior is qualified by ``test_finish_remote``.
"""

from bootstrap.models import ConfigurationPlan, PlanEffect, PlanPreparation, PlanRefusal
from operations.models import RemoteOperation
from sites.convention import Application, Stage

from . import core_native
from .finish_testing import FinishTestCase
from .models import FinishRequest, PlanWordpressFinish, PlanWordpressInstall

Reason = PlanRefusal.Reason
Status = RemoteOperation.Status
Effect = PlanEffect.Kind


class ReviewTestCase(FinishTestCase):
    def finished(self, boundary: str, form: dict[str, str] | None = None) -> PlanWordpressFinish:
        self.stranded.leave(boundary)
        plan = self.reviewed(form)
        self.assertTrue(plan.eligible, self.texts(plan))
        return PlanWordpressFinish.objects.get(plan=plan)

    def refused(self, reason: str, *fragments: str) -> ConfigurationPlan:
        plan = self.reviewed()
        self.assertFalse(plan.eligible)
        self.assertIn(reason, self.reasons(plan), self.texts(plan))
        for fragment in fragments:
            self.assertIn(fragment, self.texts(plan))
        self.assertFalse(PlanWordpressFinish.objects.filter(plan=plan).exists())
        return plan


class EligibleStateTests(ReviewTestCase):
    """What an installation that stopped after each step leaves, and what Finish proposes."""

    def test_a_site_behind_the_gate_with_nothing_published_gets_the_whole_release(self) -> None:
        row = self.finished("gate")
        self.assertEqual((row.compares, row.strict_content), (False, True))
        self.assertEqual(row.absent_names.split(), sorted(core_native.RELEASE_ENTRIES))
        self.assertEqual(
            (row.creates_loader, row.creates_configuration, row.runs_install), (True, True, True)
        )
        self.assertTrue(row.placeholder_present)
        self.assertEqual((row.title, row.admin_login), ("Shop & Sons", "owner"))
        self.assertEqual(row.preimage_sha256, row.gate_sha256)
        self.assertEqual(row.canonical_name, "www.shop.example.com")
        self.assertIsNotNone(row.payload_bytes)

    def test_published_release_files_are_compared_and_kept(self) -> None:
        row = self.finished("publish")
        self.assertTrue(row.compares)
        self.assertEqual(row.absent_names, "")
        self.assertTrue(row.placeholder_present)
        self.assertTrue(row.runs_install)

    def test_only_the_missing_release_entries_are_published(self) -> None:
        self.stranded.leave("publish")
        self.stranded.release = {"index.php", "wp-admin"}
        plan = self.reviewed()
        row = PlanWordpressFinish.objects.get(plan=plan)
        absent = sorted(set(core_native.RELEASE_ENTRIES) - {"index.php", "wp-admin"})
        self.assertEqual(row.absent_names.split(), absent)
        text = " ".join(plan.effects.values_list("text", flat=True))
        self.assertIn(" ".join(absent), text)
        self.assertIn("index.php, wp-admin", text)
        self.assertIn("compares every release entry that exists", text)

    def test_a_replaced_placeholder_is_not_replaced_again(self) -> None:
        row = self.finished("placeholder")
        self.assertFalse(row.placeholder_present)

    def test_a_missing_private_configuration_is_created_beside_the_existing_loader(self) -> None:
        row = self.finished("loader")
        self.assertEqual((row.creates_loader, row.creates_configuration), (False, True))
        self.assertEqual(row.configuration_sha256, "")

    def test_an_existing_supported_configuration_is_kept_and_its_digest_recorded(self) -> None:
        row = self.finished("configuration")
        self.assertEqual((row.creates_loader, row.creates_configuration), (False, False))
        self.assertEqual(row.configuration_sha256, self.stranded.configuration_digest)
        self.assertTrue(row.runs_install)

    def test_an_exact_installed_database_runs_no_installation_and_needs_no_metadata(self) -> None:
        row = self.finished("install", {})
        self.assertFalse(row.runs_install)
        self.assertFalse(row.strict_content)
        self.assertEqual((row.title, row.admin_login, row.admin_email), ("", "", ""))
        plan = row.plan
        text = " ".join(plan.effects.values_list("text", flat=True))
        self.assertIn("Core installation is not run", text)
        self.assertIn("Creates, resets and changes no account", text)
        self.assertNotIn(
            "password setup required", text.replace("Administrator password setup", "")
        )

    def test_metadata_given_for_an_installed_database_is_not_used(self) -> None:
        row = self.finished("install")
        self.assertEqual((row.title, row.admin_login, row.admin_email), ("", "", ""))
        self.assertEqual(FinishRequest.objects.get().title, "Shop & Sons")

    def test_plugin_tables_beside_the_core_schema_do_not_make_it_ambiguous(self) -> None:
        self.stranded.plugin_tables = 3
        row = self.finished("install")
        self.assertFalse(row.runs_install)

    def test_wp_content_is_the_operators_content_once_installed(self) -> None:
        row = self.finished("install")
        self.assertFalse(row.strict_content)
        self.assertEqual(row.absent_names, "")

    def test_the_review_reads_everything_it_proposes_from_the_server_alone(self) -> None:
        self.assertFalse(PlanPreparation.objects.exists())
        self.finished("configuration")
        self.assertFalse(PlanWordpressInstall.objects.exists())
        self.assertEqual(PlanPreparation.objects.count(), 1)
        self.assert_read_only()
        self.assertEqual(set(self.stranded.reads) - {"supply"}, {"layout", "state_database"})

    def test_the_review_lists_the_effects_the_run_will_have(self) -> None:
        row = self.finished("loader")
        kinds = set(row.plan.effects.values_list("kind", flat=True))
        self.assertEqual(
            kinds,
            {
                Effect.APP_ARTIFACTS,
                Effect.APP_FILES,
                Effect.APP_SCHEMA,
                Effect.APP_NETWORK,
                Effect.APP_EXPOSURE,
                Effect.APP_ACCOUNT,
                Effect.APP_LIMITS,
                Effect.NO_ROLLBACK,
            },
        )
        files = row.plan.effects.get(kind=Effect.APP_FILES).text
        self.assertIn("keeps the existing exact loader", files)
        self.assertIn("eight new salts", files)
        self.assertIn("never replaced", files)

    def test_the_review_page_shows_the_work_and_the_password_step_only_when_it_applies(
        self,
    ) -> None:
        gate = self.finished("gate")
        page = self.client.get(f"/plans/{gate.plan.pk}/")
        self.assertContains(page, "Administrator password setup required")
        self.assertContains(page, "whole release is published")
        installed = self.finished("install")
        page = self.client.get(f"/plans/{installed.plan.pk}/")
        self.assertNotContains(page, "Administrator password setup required")
        self.assertContains(page, "Core installation is not run")


class SiteRefusalTests(ReviewTestCase):
    def test_a_site_whose_file_is_not_the_gate_has_nothing_to_finish(self) -> None:
        self.site.applications["shop"] = (Application.PHP, "")
        self.refused(Reason.EXISTING_APPLICATION, "no installation stopped behind a gate")

    def test_a_site_already_routing_wordpress_live_is_refused(self) -> None:
        self.site.applications["shop"] = (Application.WORDPRESS, "www.shop.example.com")
        self.refused(Reason.EXISTING_APPLICATION, "ready WordPress routing")

    def test_a_gate_without_the_http_redirect_stage_is_not_finished(self) -> None:
        self.site.stages["shop"] = Stage.HTTPS
        plan = self.reviewed()
        self.assertFalse(plan.eligible)
        self.assertIn(Reason.EXISTING_APPLICATION, self.reasons(plan), self.texts(plan))

    def test_an_unknown_site_does_not_follow_the_convention(self) -> None:
        self.site.sites.clear()
        self.refused(Reason.NOT_FOLLOWING, "does not follow the convention")

    def test_an_entry_the_convention_does_not_create_is_refused_by_name(self) -> None:
        self.stranded.beside = {"backup.sql": "f"}
        self.refused(Reason.COLLISION, "backup.sql", "ordinary administration")

    def test_a_staging_directory_left_by_a_killed_run_is_named(self) -> None:
        self.stranded.beside = {".wp-0123456789abcdef0123456789abcdef": "d"}
        self.refused(Reason.COLLISION, ".wp-0123456789abcdef0123456789abcdef", "staging area")

    def test_a_public_directory_that_is_not_one_is_refused(self) -> None:
        self.stranded.beside = {"public": "f"}
        plan = self.reviewed()
        self.assertFalse(plan.eligible)
        self.assertIn(Reason.UNSUPPORTED_LAYOUT, self.reasons(plan))


class FileRefusalTests(ReviewTestCase):
    def test_a_release_entry_of_the_wrong_kind_refuses(self) -> None:
        self.stranded.leave("publish")
        self.stranded.extras = {"wp-admin": "l", "index.php": "d"}
        self.refused(Reason.EXISTING_APPLICATION, "index.php, wp-admin", "not the kind of entry")

    def test_a_foreign_file_in_the_public_root_refuses(self) -> None:
        self.stranded.leave("publish")
        self.stranded.extras = {"robots.txt": "f"}
        self.refused(Reason.EXISTING_APPLICATION, "robots.txt", "neither a WordPress release file")

    def test_foreign_content_in_an_otherwise_empty_public_root_refuses(self) -> None:
        self.stranded.extras = {"uploads": "d"}
        self.refused(Reason.EXISTING_APPLICATION, "uploads")

    def test_a_public_root_with_far_more_entries_than_a_release_refuses(self) -> None:
        self.stranded.extras = {f"entry{n:03d}": "f" for n in range(60)}
        self.refused(Reason.EXISTING_APPLICATION, "more than")

    def test_a_changed_placeholder_may_be_application_content(self) -> None:
        self.stranded.placeholder = "<html>mine</html>"
        self.refused(Reason.EXISTING_APPLICATION, "not the exact known placeholder")

    def test_a_loader_that_is_not_the_fixed_one_refuses(self) -> None:
        self.stranded.leave("loader")
        self.stranded.loader = "other"
        self.refused(Reason.EXISTING_APPLICATION, "not the fixed loader")

    def test_an_unreadable_loader_is_incomplete_not_absent(self) -> None:
        self.stranded.leave("loader")
        self.stranded.loader = "denied"
        self.refused(Reason.INCOMPLETE, "could not read the public wp-config.php")

    def test_a_configuration_outside_the_supported_grammar_refuses_without_replacement(
        self,
    ) -> None:
        self.stranded.leave("configuration")
        self.stranded.configuration = "unsupported"
        self.refused(Reason.EXISTING_APPLICATION, "first refused line is 4", "rotates no salt")

    def test_an_unreadable_configuration_is_incomplete_not_absent(self) -> None:
        self.stranded.leave("configuration")
        self.stranded.configuration = "denied"
        self.refused(Reason.INCOMPLETE, "could not read the private configuration")

    def test_private_files_other_than_the_configuration_refuse(self) -> None:
        self.stranded.leave("configuration")
        self.stranded.private_extras = {"dump.sql": "f"}
        self.refused(Reason.EXISTING_APPLICATION, "dump.sql", "private directory")

    def test_a_loader_with_other_ownership_is_not_adopted(self) -> None:
        self.stranded.leave("loader")
        self.stranded.loader_attributes = "640 0 33"
        self.refused(Reason.UNSUPPORTED_LAYOUT, "must be a regular file owned by")

    def test_a_configuration_with_other_modes_is_not_adopted(self) -> None:
        self.stranded.leave("configuration")
        self.stranded.configuration_attributes = "644 1003 1003"
        self.refused(Reason.UNSUPPORTED_LAYOUT, "with mode 0600")

    def test_a_missing_wp_content_of_an_installed_database_is_not_recreated(self) -> None:
        self.stranded.leave("install")
        self.stranded.release.discard("wp-content")
        self.refused(Reason.EXISTING_APPLICATION, "wp-content directory is missing")


class DatabaseRefusalTests(ReviewTestCase):
    def test_partial_tables_refuse_core_installation_replay(self) -> None:
        self.stranded.leave("configuration")
        self.stranded.database_state = "partial"
        self.refused(Reason.EXISTING_APPLICATION, "never replays core installation", "3 table(s)")

    def test_a_core_table_without_a_required_column_is_altered(self) -> None:
        self.stranded.leave("configuration")
        self.stranded.database_state = "altered"
        self.refused(Reason.EXISTING_APPLICATION, "not exactly the complete WordPress core schema")

    def test_another_table_prefix_with_its_own_users_makes_the_prefix_ambiguous(self) -> None:
        self.stranded.leave("install")
        self.stranded.database_state = "ambiguous"
        self.refused(Reason.EXISTING_APPLICATION, "not exactly the complete WordPress core schema")

    def test_a_complete_schema_with_other_site_addresses_refuses(self) -> None:
        self.stranded.leave("install")
        self.stranded.options = "home\thttps://other.test\nsiteurl\thttps://other.test\n"
        self.refused(Reason.EXISTING_APPLICATION, "siteurl and home options are not")

    def test_a_complete_schema_without_the_options_is_not_installed(self) -> None:
        self.stranded.leave("install")
        self.stranded.options = ""
        self.refused(Reason.EXISTING_APPLICATION, "canonical options")

    def test_an_empty_database_that_holds_a_routine_is_not_empty(self) -> None:
        self.stranded.leave("configuration")
        self.stranded.routines = 1
        self.refused(Reason.EXISTING_APPLICATION, "1 routine(s)")

    def test_a_missing_database_is_a_missing_binding(self) -> None:
        self.stranded.exists = False
        plan = self.reviewed()
        self.assertFalse(plan.eligible)

    def test_an_empty_database_needs_the_installation_metadata(self) -> None:
        self.stranded.leave("configuration")
        plan = self.reviewed({})
        self.assertFalse(plan.eligible)
        self.assertIn(Reason.PREREQUISITE, self.reasons(plan))
        self.assertIn("wholly empty", self.texts(plan))
        self.assertIn("Prepare a new review with them", self.texts(plan))
        self.assertFalse(PlanWordpressFinish.objects.exists())


class PrerequisiteRefusalTests(ReviewTestCase):
    def test_a_missing_certificate_lineage_is_refused(self) -> None:
        self.tls.production = ""
        self.refused(Reason.PREREQUISITE, "certificate lineage")

    def test_a_missing_tool_is_named_not_installed(self) -> None:
        self.wpcli.phar = "absent"
        self.refused(Reason.PREREQUISITE, "is not installed")

    def test_an_incomplete_php_baseline_is_named(self) -> None:
        self.site.drivers = ()
        plan = self.reviewed()
        self.assertFalse(plan.eligible)

    def test_a_server_without_the_archive_tools_is_refused(self) -> None:
        self.stranded.tools = ("curl",)
        self.refused(Reason.PREREQUISITE, "/usr/bin/sha256sum")

    def test_an_archive_that_is_not_the_pinned_size_is_refused(self) -> None:
        self.stranded.archive_bytes = core_native.ARCHIVE_BYTES + 1
        self.refused(Reason.INCOMPLETE, "announces")


class ReadRefusalTests(ReviewTestCase):
    def test_each_failed_read_refuses_instead_of_assuming(self) -> None:
        for read, fragment in {
            "layout": "could not read the site's trees",
            "state_database": "could not read the site database's catalog",
        }.items():
            with self.subTest(read=read):
                PlanPreparation.objects.all().delete()
                self.stranded.leave("publish")
                self.stranded.failing = {read}
                plan = self.reviewed()
                self.assertFalse(plan.eligible)
                self.assertIn(Reason.INCOMPLETE, self.reasons(plan))
                self.assertIn(fragment, self.texts(plan))

    def test_a_tree_that_changes_while_it_is_read_is_refused(self) -> None:
        self.stranded.flapping = {"layout"}
        self.refused(Reason.INCOMPLETE, "changed while Barectl read it")

    def test_a_payload_that_cannot_fit_one_run_is_refused_not_split(self) -> None:
        from unittest import mock

        from bootstrap import native

        with mock.patch.object(native, "MAX_PAYLOAD", 1000):
            plan = self.reviewed()
        self.assertFalse(plan.eligible)
        self.assertIn(Reason.PAYLOAD_TOO_LARGE, self.reasons(plan))
        self.assertIn("never splits a reviewed action", self.texts(plan))
