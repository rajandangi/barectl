"""Finishing a partial WordPress installation on a real, disposable Ubuntu server
(docs/wordpress.md#finishing-a-partial-installation).

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. The administrator prepares the site, HTTPS lineage,
MariaDB binding, PHP baseline and authenticated WP-CLI by hand (see ``test_install_remote``).
Barectl then installs through the dashboard's request, the worker and a real unit, stopped after
a named fragment of its production body by one inserted ``exit``, which leaves exactly the state
an interrupted run leaves. A Finish is reviewed and applied the same way, against the real
systemd, curl, tar, WP-CLI, MariaDB, PHP-FPM, Nginx and WordPress. Ground truth is read as root
through ``docker exec``, independently of Barectl: what existed before is still there, bit for
bit, and no installation was replayed.
"""

import re
import time
from unittest import mock

from django.db.models import F

from bootstrap import native as bootstrap_native
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, PlanRefusal, Verification
from discovery.fakes import run_worker
from operations import native as operations_native
from operations.models import RemoteOperation

from . import finish_native
from .finish_remote_testing import (
    INTERRUPTED,
    FinishCase,
    injected_finish,
)
from .install_apply_remote_testing import BASE, SITE_FILE, USER
from .install_remote_testing import DATABASE, PRIVATE, PUBLIC
from .models import InstallRunResult, PlanWordpressFinish, RunWordpressFinish

Status = RemoteOperation.Status
Exit = finish_native.Exit
Reason = PlanRefusal.Reason


class FinishFixture(FinishCase):
    """The shared steps of the boundary suites."""

    def finishes(self, after: str, *, installed: bool) -> ApplyRun:
        self.interrupted(after)
        self.assert_gated()
        before = self.deep()
        plan = self.eligible_finish()
        row = PlanWordpressFinish.objects.get(plan=plan)
        self.assertEqual(row.runs_install, not installed)
        self.assertEqual(self.deep(), before, "the review changed the server")
        run = self.apply_finish(plan)
        self.assert_finished(run, before, installed=installed)
        return run


class FinishEarlyBoundaryTests(FinishFixture):
    """Boundaries before the database exists: Finish runs core installation once."""

    def test_nothing_published_yet_finishes_the_whole_installation(self) -> None:
        self.finishes("gate", installed=False)
        self.assertEqual(self.tables(), "12")

    def test_release_files_without_a_loader_a_configuration_or_tables(self) -> None:
        run = self.finishes("publish", installed=False)
        row = RunWordpressFinish.objects.get(run=run)
        self.assertTrue(row.compares)
        self.assertTrue(row.creates_loader and row.creates_configuration and row.runs_install)

    def test_a_replaced_placeholder_and_nothing_more(self) -> None:
        self.finishes("placeholder", installed=False)


class FinishMiddleBoundaryTests(FinishFixture):
    def test_a_loader_without_a_configuration(self) -> None:
        run = self.finishes("loader", installed=False)
        row = RunWordpressFinish.objects.get(run=run)
        self.assertFalse(row.creates_loader)
        self.assertTrue(row.creates_configuration)

    def test_a_configuration_and_an_empty_database_run_core_installation_once(self) -> None:
        run = self.finishes("configuration", installed=False)
        row = RunWordpressFinish.objects.get(run=run)
        self.assertFalse(row.creates_loader or row.creates_configuration)
        self.assertEqual(self.count("wp_users"), "1")


class FinishLateBoundaryTests(FinishFixture):
    """Boundaries after the schema exists: Finish never runs core installation again."""

    def test_an_installed_database_gets_only_the_ready_routing_and_no_installation(self) -> None:
        run = self.finishes("install", installed=True)
        row = RunWordpressFinish.objects.get(run=run)
        self.assertFalse(row.runs_install or row.compares is False)
        self.assertEqual((row.title, row.admin_login, row.admin_email), ("", "", ""))
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertNotContains(page, "Administrator password setup required")

    def test_everything_verified_while_gated_needs_only_the_ready_routing(self) -> None:
        run = self.finishes("access", installed=True)
        self.assertEqual(self.count("wp_users"), "1")
        self.assertIn(
            "barectl-wordpress: schema, integrity and access", self.journal(run.unit_name)
        )


class FinishMissingEntryTests(FinishFixture):
    def test_release_entries_removed_after_publication_are_published_again(self) -> None:
        self.interrupted("publish")
        self.administer(f"rm -rf {PUBLIC}/wp-includes {PUBLIC}/wp-login.php")
        before = self.deep()
        plan = self.eligible_finish()
        row = PlanWordpressFinish.objects.get(plan=plan)
        self.assertEqual(row.absent_names, "wp-includes wp-login.php")
        run = self.apply_finish(plan)
        self.assert_finished(run, before, installed=False)
        self.assertEqual(
            self.administer(f"stat -c '%U:%G %a' {PUBLIC}/wp-includes {PUBLIC}/wp-login.php")
            .strip()
            .splitlines(),
            [f"{USER}:{USER} 755", f"{USER}:{USER} 644"],
        )


class RefusalFixture(FinishCase):
    """A review that stands on ambiguous or edited state refuses and changes nothing."""

    def refuses(
        self,
        after: str | None,
        change: str,
        *fragments: str,
        reason: str = Reason.EXISTING_APPLICATION,
        undo: str = "true",
    ) -> ConfigurationPlan:
        """Stop an installation after ``after`` (or install fully when ``None``), change the
        server as ``change`` says and expect a named refusal that leaves everything as it is."""
        if after is None:
            installed = self.apply_install(self.eligible())
            self.assertEqual(installed.execution, Execution.SUCCEEDED, installed.failure)
            units = [installed.unit_name]
        else:
            units = [self.interrupted(after).unit_name]
        self.addCleanup(self.administer, undo)
        self.administer(change)
        before = self.deep()
        plan = self.finish_review()
        self.assertFalse(plan.eligible, "a Finish review was offered")
        self.assertIn(
            reason, list(plan.refusals.values_list("reason", flat=True)), self.texts(plan)
        )
        for fragment in fragments:
            self.assertIn(fragment, self.texts(plan))
        self.assertFalse(PlanWordpressFinish.objects.filter(plan=plan).exists())
        self.assertEqual(self.deep(), before, "the refused review changed the server")
        self.assertEqual(self.units(), units, "a refused review submitted a unit")
        return plan


class FinishFileRefusalTests(RefusalFixture):
    def test_a_release_entry_of_the_wrong_kind_is_refused_and_never_followed(self) -> None:
        self.refuses(
            "publish",
            f"rm -rf {PUBLIC}/wp-admin && ln -s /etc {PUBLIC}/wp-admin",
            "wp-admin",
            "not the kind of entry",
        )

    def test_a_foreign_file_in_the_public_root_is_refused(self) -> None:
        self.refuses(
            "install", f"printf x >{PUBLIC}/robots.txt", "robots.txt", "neither a WordPress"
        )

    def test_a_changed_placeholder_is_application_content(self) -> None:
        self.refuses(
            "gate", f"printf changed >>{PUBLIC}/index.html", "not the exact known placeholder"
        )

    def test_a_missing_wp_content_of_an_installed_site_is_not_recreated(self) -> None:
        self.refuses("install", f"rm -rf {PUBLIC}/wp-content", "wp-content directory is missing")

    def test_foreign_content_beside_the_site_directorys_trees_is_refused(self) -> None:
        self.refuses(
            "gate",
            f"printf x >{BASE}/backup.sql",
            "backup.sql",
            reason=Reason.COLLISION,
            undo=f"rm -f {BASE}/backup.sql",
        )

    def test_a_staging_directory_left_by_a_killed_run_is_named(self) -> None:
        residue = f".wp-{'0123456789abcdef' * 2}"
        self.refuses(
            "gate",
            f"mkdir -m 0700 {BASE}/{residue}",
            residue,
            "staging area",
            reason=Reason.COLLISION,
            undo=f"rm -rf {BASE}/{residue}",
        )


class FinishConfigurationRefusalTests(RefusalFixture):
    def test_an_edited_loader_is_never_replaced(self) -> None:
        self.refuses(
            "loader", f"printf '<?php // mine\\n' >{PUBLIC}/wp-config.php", "not the fixed loader"
        )

    def test_a_loader_with_other_ownership_is_refused(self) -> None:
        self.refuses(
            "loader",
            f"chown root:root {PUBLIC}/wp-config.php",
            "must be a regular file owned by",
            reason=Reason.UNSUPPORTED_LAYOUT,
        )

    def test_a_private_configuration_outside_the_grammar_is_refused_and_keeps_its_salts(
        self,
    ) -> None:
        self.refuses(
            "configuration",
            f"printf \"define( 'WP_DEBUG', true );\\n\" >>{PRIVATE}/wp-config.php",
            "rotates no salt",
        )

    def test_a_private_configuration_with_other_modes_is_refused(self) -> None:
        self.refuses(
            "configuration",
            f"chmod 644 {PRIVATE}/wp-config.php",
            "with mode 0600",
            reason=Reason.UNSUPPORTED_LAYOUT,
        )

    def test_other_private_files_are_refused(self) -> None:
        self.refuses("configuration", f"touch {PRIVATE}/dump.sql", "dump.sql", "private directory")

    def test_an_unreadable_configuration_is_incomplete_evidence_not_absence(self) -> None:
        # The grammar is read by the SSH user; a directory entry that is not a regular file
        # is "not a plain regular file", never "absent".
        self.refuses(
            "loader",
            f"mkdir {PRIVATE}/wp-config.php",
            "not a plain regular file",
            undo=f"rmdir {PRIVATE}/wp-config.php 2>/dev/null; true",
        )


class FinishDatabaseRefusalTests(RefusalFixture):
    def mysql(self, sql: str) -> str:
        return f'mariadb --no-defaults --protocol=socket -e "{sql}"'

    def test_partial_core_tables_are_never_replayed_into(self) -> None:
        plan = self.refuses(
            "configuration",
            self.mysql(f"CREATE TABLE {DATABASE}.wp_options (option_id INT)"),
            "never replays core installation",
            "1 table(s)",
        )
        self.assertIn("wp_options", self.texts(plan))
        self.assertEqual(self.tables(), "1")

    def test_a_table_the_installation_does_not_create_makes_the_database_not_empty(self) -> None:
        self.refuses(
            "configuration",
            self.mysql(f"CREATE TABLE {DATABASE}.notes (note TEXT)"),
            "1 table(s)",
        )

    def test_a_routine_makes_the_database_not_empty(self) -> None:
        self.refuses(
            "configuration",
            self.mysql(f"CREATE PROCEDURE {DATABASE}.p() BEGIN END"),
            "1 routine(s)",
        )

    def test_a_dropped_core_table_is_never_recreated(self) -> None:
        self.refuses(
            "install",
            self.mysql(f"DROP TABLE {DATABASE}.wp_commentmeta"),
            "not exactly the complete WordPress core schema",
        )
        self.assertEqual(self.tables(), "11")

    def test_a_core_table_missing_a_required_column_is_never_repaired(self) -> None:
        self.refuses(
            "install",
            self.mysql(f"ALTER TABLE {DATABASE}.wp_commentmeta DROP COLUMN meta_value"),
            "not exactly the complete WordPress core schema",
        )

    def test_another_prefix_with_its_own_users_makes_the_prefix_ambiguous(self) -> None:
        self.refuses(
            "install",
            self.mysql(
                f"CREATE TABLE {DATABASE}.x_users (ID INT); "
                f"CREATE TABLE {DATABASE}.x_options (i INT)"
            ),
            "not exactly the complete WordPress core schema",
        )

    def test_plugin_tables_beside_the_core_schema_are_allowed_and_kept(self) -> None:
        self.interrupted("install")
        self.administer(self.mysql(f"CREATE TABLE {DATABASE}.wp_plugin_data (id INT)"))
        before = self.deep()
        plan = self.eligible_finish()
        run = self.apply_finish(plan)
        self.assert_finished(run, before, installed=True)
        self.assertIn("wp_plugin_data", self.deep()["tables"])

    def test_other_site_addresses_are_refused(self) -> None:
        self.refuses(
            "install",
            self.mysql(
                f"UPDATE {DATABASE}.wp_options SET option_value='https://other.test' "  # noqa: S608 - fixed names
                "WHERE option_name='siteurl'"
            ),
            "siteurl and home options are not",
        )

    def test_an_empty_database_needs_the_metadata(self) -> None:
        self.interrupted("configuration")
        before = self.deep()
        plan = self.finish_review({})
        self.assertFalse(plan.eligible)
        self.assertIn("wholly empty", self.texts(plan))
        self.assertEqual(self.deep(), before)


class FinishSiteRefusalTests(RefusalFixture):
    def test_an_edited_gate_is_not_a_convention_site_file(self) -> None:
        self.refuses(
            "gate",
            f"printf '# edited\\n' >>{SITE_FILE}; nginx -t -q",
            "does not follow the convention",
            reason=Reason.NOT_FOLLOWING,
        )

    def test_a_site_already_routed_live_has_nothing_to_finish(self) -> None:
        self.refuses(
            "ready",
            "true",
            "ready WordPress routing",
        )

    def test_a_complete_installation_has_nothing_to_finish(self) -> None:
        self.refuses(None, "true", "ready WordPress routing")

    def test_a_site_that_was_never_installed_is_pointed_to_the_installation_review(self) -> None:
        plan = self.finish_review()
        self.assertFalse(plan.eligible)
        self.assertIn("no installation stopped behind a gate", self.texts(plan))
        self.assertEqual(self.tables(), "0")


class FaultFixture(FinishCase):
    def reviewed_finish(self, after: str) -> ConfigurationPlan:
        self.interrupted(after)
        return self.eligible_finish()

    def assert_refused(self, run: ApplyRun, execution: Execution, before: dict[str, str]) -> None:
        self.assertEqual((run.status, run.execution), (Status.FAILED, execution), run.failure)
        self.assertEqual(run.verification, Verification.NOT_APPLICABLE)
        self.assertEqual(self.deep(), before, "a refused run changed the server")
        self.assertEqual(self.administer_home_residue(), "")


class FinishEditedFileTests(FaultFixture):
    """The review reads only the top level; the run compares every existing release entry with
    its staged copy of the pinned archive and refuses before it changes anything."""

    def refused_by_the_run(self, after: str, change: str, entry: str) -> ApplyRun:
        self.interrupted(after)
        self.administer(change)
        # The review reads the top level, which an edit inside an entry may leave as it was.
        plan = self.eligible_finish()
        before = self.deep()
        run = self.apply_finish(plan)
        self.assert_refused(run, Execution.EDITED_FILES, before)
        self.assertEqual(run.exit_status, Exit.EDITED)
        self.assertIn("differs from the pinned WordPress archive", run.failure)
        self.assertIn(
            f"barectl-wordpress: {entry} differs from the pinned release",
            self.journal(run.unit_name),
        )
        self.assertEqual(len(self.units()), 2, "the install and the refused Finish only")
        return run

    def test_an_edited_release_file_is_never_finished_on_top_of(self) -> None:
        self.refused_by_the_run(
            "publish", f"printf '// edited\\n' >>{PUBLIC}/wp-admin/admin.php", "wp-admin"
        )

    def test_an_edited_top_level_file_of_an_installed_site_is_refused_too(self) -> None:
        self.refused_by_the_run(
            "install", f"printf '// edited\\n' >>{PUBLIC}/index.php", "index.php"
        )

    def test_a_new_file_inside_a_release_directory_is_refused(self) -> None:
        self.refused_by_the_run("publish", f"touch {PUBLIC}/wp-includes/extra.php", "wp-includes")

    def test_a_link_inside_the_release_is_refused_and_never_followed(self) -> None:
        self.refused_by_the_run(
            "publish", f"ln -s /etc/shadow {PUBLIC}/wp-includes/link.php", "wp-includes"
        )

    def test_a_release_file_with_other_ownership_is_refused(self) -> None:
        self.refused_by_the_run("publish", f"chown root:root {PUBLIC}/wp-login.php", "wp-login.php")

    def test_a_release_file_with_other_modes_is_refused(self) -> None:
        self.refused_by_the_run("publish", f"chmod 666 {PUBLIC}/wp-login.php", "wp-login.php")

    def test_new_supplied_content_of_a_first_installation_is_compared_too(self) -> None:
        self.refused_by_the_run(
            "publish", f"touch {PUBLIC}/wp-content/plugins/extra.php", "wp-content"
        )

    def test_operator_content_of_an_installed_site_is_not_a_difference(self) -> None:
        self.interrupted("install")
        self.administer(
            f"mkdir -p {PUBLIC}/wp-content/uploads && "
            f"printf jpg >{PUBLIC}/wp-content/uploads/a.jpg && "
            f"chown -R {USER}:{USER} {PUBLIC}/wp-content/uploads"
        )
        before = self.deep()
        plan = self.eligible_finish()
        run = self.apply_finish(plan)
        self.assert_finished(run, before, installed=True)
        self.assertEqual(self.administer(f"cat {PUBLIC}/wp-content/uploads/a.jpg"), "jpg")


class FinishDriftTests(FaultFixture):
    """Evidence that changes after review is found under the lock, before any change."""

    def drifts(self, after: str, change: str, execution: Execution = Execution.DRIFT) -> ApplyRun:
        plan = self.reviewed_finish(after)
        self.administer(change)
        before = self.deep()
        run = self.apply_finish(plan)
        self.assert_refused(run, execution, before)
        if execution == Execution.DRIFT:
            self.assertIn("changed after review", run.failure)
        self.assertEqual(len(self.units()), 2, "the install and the refused Finish only")
        return run

    def test_an_existing_release_file_edited_after_review_is_found_by_the_comparison(self) -> None:
        # Nested files are invisible to the top-level evidence: the staged comparison catches it.
        run = self.drifts(
            "publish",
            f"printf '// edited\\n' >>{PUBLIC}/wp-admin/admin.php",
            Execution.EDITED_FILES,
        )
        self.assertEqual(run.exit_status, Exit.EDITED)

    def test_a_new_top_level_file_after_review_is_found_by_the_layout(self) -> None:
        self.drifts("publish", f"touch {PUBLIC}/surprise.txt")

    def test_a_changed_private_configuration_after_review_is_found_by_its_digest(self) -> None:
        self.drifts("configuration", f"printf '// edited\\n' >>{PRIVATE}/wp-config.php")

    def test_a_new_table_after_review_is_found_by_the_catalog(self) -> None:
        self.drifts("install", f"mariadb --no-defaults -e 'CREATE TABLE {DATABASE}.t (i INT)'")

    def test_a_changed_site_file_after_review_is_found(self) -> None:
        self.drifts("gate", f"printf '# changed\\n' >>{SITE_FILE}; nginx -t -q")


class FinishGateTests(FaultFixture):
    def test_a_gate_nginx_no_longer_serves_refuses_before_any_change(self) -> None:
        plan = self.reviewed_finish("publish")
        before = self.deep()
        self.addCleanup(self.administer, "systemctl start nginx; true")
        with injected_finish(plan, "checksums", "systemctl stop nginx"):
            run = self.apply_finish(plan)
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.NOT_GATED))
        self.assertEqual(run.exit_status, Exit.NOT_GATED)
        self.assertIn("not the reviewed provisioning gate", run.failure)
        self.administer("systemctl start nginx")
        self.assertEqual(self.deep(), before)

    def test_a_gate_serving_another_certificate_refuses_before_any_change(self) -> None:
        from .install_apply_remote_testing import REPLACE_CERTIFICATE

        plan = self.reviewed_finish("publish")
        before = self.deep()
        with injected_finish(plan, "checksums", f"{REPLACE_CERTIFICATE}; systemctl reload nginx"):
            run = self.apply_finish(plan)
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.NOT_GATED))
        self.assertEqual(self.deep()["files"], before["files"])
        self.assertEqual(self.deep()["private"], before["private"])

    def test_the_gate_serves_503_throughout_and_nothing_is_public_before_it_is_verified(
        self,
    ) -> None:
        plan = self.reviewed_finish("publish")
        samples = (
            "for i in 1 2 3 4 5 6; do "
            "curl -sk --max-time 5 --resolve www.shop.test:443:127.0.0.1 -o /dev/null "
            "-w 'barectl-test: / %{http_code}\\n' https://www.shop.test/; sleep 0.5; done"
        )
        with injected_finish(plan, "gated", samples):
            run = self.apply_finish(plan)
        self.assertEqual(run.execution, Execution.SUCCEEDED, run.failure)
        codes = re.findall(r"barectl-test: / (\d+)", self.journal(run.unit_name))
        self.assertEqual(codes, ["503"] * 6)


class FinishInterruptedFinishTests(FaultFixture):
    """A Finish is itself not transactional, and a second Finish continues from the server."""

    def test_a_finish_interrupted_after_publication_is_finished_by_the_next_one(self) -> None:
        plan = self.reviewed_finish("gate")
        with injected_finish(plan, "placeholder", f"exit {INTERRUPTED}"):
            run = self.apply_finish(plan)
        self.assertEqual((run.status, run.exit_status), (Status.FAILED, INTERRUPTED))
        self.assertEqual(self.administer(f"ls -A {PUBLIC}").split().count("wp-includes"), 1)
        before = self.deep()
        self.assert_gated()
        again = self.eligible_finish()
        row = PlanWordpressFinish.objects.get(plan=again)
        self.assertTrue(row.compares)
        self.assertTrue(row.creates_loader and row.runs_install)
        second = self.apply_finish(again)
        self.assert_finished(second, before, installed=False)

    def test_a_finish_interrupted_after_core_installation_never_replays_it(self) -> None:
        plan = self.reviewed_finish("gate")
        with injected_finish(plan, "install", f"exit {INTERRUPTED}"):
            run = self.apply_finish(plan)
        self.assertEqual(run.exit_status, INTERRUPTED)
        before = self.deep()
        self.assertEqual(self.count("wp_users"), "1")
        again = self.eligible_finish()
        row = PlanWordpressFinish.objects.get(plan=again)
        self.assertFalse(row.runs_install)
        second = self.apply_finish(again)
        self.assert_finished(second, before, installed=True)

    def test_a_failed_core_installation_keeps_the_gate_and_every_file(self) -> None:
        plan = self.reviewed_finish("configuration")
        grant = f"{DATABASE}.* FROM '{USER}'@'localhost'"
        revoke = f'mariadb --no-defaults -e "REVOKE ALL PRIVILEGES ON {grant}"'
        with injected_finish(plan, "gated", revoke):
            run = self.apply_finish(plan)
        self.assertEqual((run.execution, run.exit_status), (Execution.PARTIAL, Exit.INSTALL))
        self.assertIn("never replayed", run.failure)
        self.assertEqual(self.tables(), "0")
        self.assert_gated()


class FinishServingTests(FaultFixture):
    BREAK = 'chmod 000 "$pub/index.php" "$pub/wp-login.php"'

    def test_a_serving_failure_restores_the_exact_gate_and_a_later_finish_serves(self) -> None:
        plan = self.reviewed_finish("install")
        row = PlanWordpressFinish.objects.get(plan=plan)
        with injected_finish(plan, "ready", self.BREAK):
            run = self.apply_finish(plan)
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.NOT_SERVING))
        self.assertEqual(run.exit_status, Exit.NOT_SERVING)
        self.assertEqual(self.site_sha(), row.gate_sha256)
        self.assert_gated()
        self.assertIn("verified that application paths answer 503", run.failure)
        self.assertEqual(run.verification, Verification.NOT_APPLICABLE)
        # The administrator repairs what the unit's step broke; a new Finish then publishes.
        self.administer(f"chmod 644 {PUBLIC}/index.php {PUBLIC}/wp-login.php")
        before = self.deep()
        again = self.eligible_finish()
        second = self.apply_finish(again)
        self.assert_finished(second, before, installed=True)

    def test_a_gate_that_cannot_be_restored_reports_the_uncertain_exposure(self) -> None:
        plan = self.reviewed_finish("install")
        away = "/etc/letsencrypt/live/shop/fullchain.pem.away"
        self.addCleanup(
            self.administer,
            f"mv {away} /etc/letsencrypt/live/shop/fullchain.pem 2>/dev/null; true",
        )
        with injected_finish(
            plan, "ready", f"{self.BREAK}; mv /etc/letsencrypt/live/shop/fullchain.pem {away}"
        ):
            run = self.apply_finish(plan)
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.EXPOSURE_UNCERTAIN))
        self.assertEqual(run.exit_status, Exit.EXPOSED)
        self.assertIn("could not prove", run.failure)
        self.assertIn("/etc/nginx/sites-available/shop.conf", run.failure)

    def test_changed_ready_bytes_are_never_overwritten_by_the_restoration(self) -> None:
        plan = self.reviewed_finish("install")
        edited = f"printf '# an administrator edit\\n' >>{SITE_FILE}"
        with injected_finish(plan, "ready", f"{self.BREAK}; {edited}"):
            run = self.apply_finish(plan)
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.EXPOSURE_UNCERTAIN))
        self.assertIn("# an administrator edit", self.administer(f"cat {SITE_FILE}"))
        self.assertNotEqual(self.site_sha(), PlanWordpressFinish.objects.get(plan=plan).gate_sha256)
        # Application data is preserved.
        self.assertEqual(self.tables(), "12")

    def test_ready_routing_that_cannot_be_staged_keeps_the_gate(self) -> None:
        plan = self.reviewed_finish("install")
        with injected_finish(plan, "access", ': >"$sn"'):
            run = self.apply_finish(plan)
        self.assertEqual((run.execution, run.exit_status), (Execution.PARTIAL, Exit.READY))
        self.assert_gated()
        self.assertIn("not served", run.failure)


class FinishFenceTests(FaultFixture):
    """The shared lock, boot and deadline fences, checked under the lock before any change."""

    def refused_finish(self, plan: ConfigurationPlan, execution: Execution) -> ApplyRun:
        before = self.deep()
        run = self.apply_finish(plan)
        self.assertEqual((run.status, run.execution), (Status.FAILED, execution), run.failure)
        self.assertEqual(self.deep(), before)
        return run

    def test_a_changed_boot_and_an_expired_deadline_refuse(self) -> None:
        plan = self.reviewed_finish("publish")
        ConfigurationPlan.objects.filter(pk=plan.pk).update(
            boot_id="00000000-0000-4000-8000-000000000000"
        )
        self.refused_finish(plan, Execution.BOOT_CHANGED)
        again = self.eligible_finish()
        ConfigurationPlan.objects.filter(pk=again.pk).update(
            uptime_centiseconds=F("uptime_centiseconds") - 100000,
            admission_deadline_centiseconds=F("admission_deadline_centiseconds") - 100000,
        )
        self.refused_finish(again, Execution.EXPIRED)

    def test_a_lock_held_by_another_controllers_run_refuses_at_once(self) -> None:
        plan = self.reviewed_finish("publish")
        holder = self.submit(
            lambda unit, boot, deadline: "; ".join(
                [*bootstrap_native.admission(unit, boot, deadline), "sleep 120"]
            ),
            alias="disposable-second",
        )
        started = time.monotonic()
        run = self.refused_finish(plan, Execution.LOCK_CONFLICT)
        self.assertLess(time.monotonic() - started, 60)
        self.assertIn("Prepare a new", run.failure)
        self.assertEqual(self.inspect(holder).execution, Execution.RUNNING)

    def test_a_scheduled_renewal_with_processes_refuses(self) -> None:
        plan = self.reviewed_finish("publish")
        self.renewal()
        self.refused_finish(plan, Execution.RENEWAL_ACTIVE)


class FinishTerminationTests(FaultFixture):
    def test_the_runtime_limit_stops_the_run_and_cleans_its_staging(self) -> None:
        plan = self.reviewed_finish("publish")
        before = self.deep()
        with (
            mock.patch.object(operations_native, "RUNTIME_MAX", "20s"),
            injected_finish(plan, "stage", "sleep 120"),
        ):
            run = self.apply_finish(plan)
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.TIMED_OUT))
        self.assertEqual(self.administer_home_residue(), "")
        self.assertEqual(self.deep(), before)
        self.assertTrue(self.lock_is_free())

    def test_a_killed_run_leaves_only_a_removable_staging_directory(self) -> None:
        plan = self.reviewed_finish("publish")
        kill = 'systemctl kill --signal=SIGKILL "barectl-apply-$q.service"; sleep 30'
        with injected_finish(plan, "stage", kill):
            run = self.apply_finish(plan)
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.KILLED))
        residue = self.administer_home_residue()
        self.assertRegex(residue, r"^\.wp-[0-9a-f]{32}$")
        again = self.finish_review()
        self.assertFalse(again.eligible)
        self.assertIn(residue, self.texts(again))
        self.assertIn("staging area", self.texts(again))
        self.administer(f"rm -rf {BASE}/{residue}")
        self.assertTrue(self.finish_review().eligible)


class FinishControllerLossTests(FaultFixture):
    def test_a_lost_acknowledgement_is_reconciled_without_a_second_dispatch(self) -> None:
        plan = self.reviewed_finish("publish")
        request = self.request(plan)
        with self.losing(
            lambda command: command.startswith("sudo -n /usr/bin/systemd-run"), after=True
        ):
            run_worker()
        request.refresh_from_db()
        self.assertEqual(request.status, Status.RECONCILING, request.failure)
        self.wait_terminal(request.unit_name, timeout=300)
        run = self.check(request)
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        self.assertEqual(len(self.units()), 2, "the install and the Finish, each once")
        self.assertEqual(self.tables(), "12")
        self.assertEqual(InstallRunResult.objects.get(run=run).problems, "")

    def test_a_submission_that_never_reached_the_server_is_never_replayed(self) -> None:
        plan = self.reviewed_finish("publish")
        before = self.deep()
        request = self.request(plan)
        with self.losing(
            lambda command: command.startswith("sudo -n /usr/bin/systemd-run"), after=False
        ):
            run_worker()
        request.refresh_from_db()
        self.assertEqual(request.status, Status.RECONCILING, request.failure)
        run = self.check(request)
        self.assertEqual((run.status, run.execution), (Status.RECONCILING, Execution.NOT_FOUND))
        self.assertEqual(len(self.units()), 1, "checking never submits")
        self.assertEqual(self.deep(), before)
