"""WordPress maintenance on a real, disposable Ubuntu server
(docs/wordpress.md#maintaining-wordpress).

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. The administrator prepares the site and Barectl
installs a real WordPress through its own reviewed workflow (``test_install_apply_remote``);
Barectl then reviews and applies maintenance through the dashboard request, the worker, its SSH
connection, actual systemd, journald, WP-CLI, MariaDB, WordPress and Nginx. The administrator
alters the application between steps, by hand through ``docker exec``, to fault each boundary.
Ground truth is read as root, independently of Barectl.
"""

import re

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission

from bootstrap import native
from bootstrap.models import ApplyRun, Execution, Verification
from discovery.fakes import run_worker
from operations.models import RemoteOperation

from . import execution, maintenance_native
from .inspection_remote_testing import (
    CONTENT,
    HOSTILE,
)
from .install_apply_remote_testing import BASE, SITE_FILE, USER
from .install_remote_testing import PRIVATE, PUBLIC
from .maintenance_models import MaintenanceResult, Operation, PlanWordpressMaintenance
from .maintenance_remote_testing import (
    PLUGIN_ROUTE,
    ROUTE,
    MaintenanceServerCase,
)

Status = RemoteOperation.Status
Exit = execution.Exit


class RewriteAcceptanceTests(MaintenanceServerCase):
    def test_a_soft_flush_registers_custom_routes_and_changes_no_nginx_byte(self) -> None:
        self.recorder()
        self.routes()
        self.permalinks()
        self.assertEqual(self.page(f"/{ROUTE}/")[0], "404", "the stale rules route nothing")
        self.assertEqual(self.page(f"/{PLUGIN_ROUTE}/")[0], "404")
        plan = self.eligible_maintenance(Operation.REWRITE)
        row = PlanWordpressMaintenance.objects.get(plan=plan)
        self.assertIn("mu-plugin routes.php", row.targets)
        text = " ".join(plan.effects.values_list("text", flat=True))
        self.assertIn("wp rewrite flush", text)
        before = self.snapshot()
        run = self.run_maintenance(plan=plan)
        result = self.assert_maintained(run)
        self.assertEqual((result.state, result.rules), ("available", "stored"))
        stored = self.stored_rules()
        self.assertIn(ROUTE, stored, "the must-use plugin's route is registered")
        self.assertIn(PLUGIN_ROUTE, stored, "the active plugin's route is registered")
        self.assertNotIn("stale-marker", stored)
        self.assertEqual(self.page(f"/{ROUTE}/"), ("200", "barectl-route-ok"))
        after = self.snapshot()
        self.assert_same(before, after)
        self.assertEqual(self.residue(), "")
        self.assertNotIn(
            "RewriteRule",
            self.administer(f"cat {PUBLIC}/.htaccess 2>/dev/null; true"),
            "a soft flush writes no .htaccess",
        )
        self.assertFalse(int(self.administer(f"test -e {PUBLIC}/.htaccess && echo 1 || echo 0")))
        # WordPress ran as the site user with exactly the controlled environment.
        uid = int(self.administer(f"id -u {USER}").strip())
        marks = self.marked()
        self.assertTrue(marks)
        for mark in marks:
            self.assertEqual(mark["uid"], uid)
            self.assertRegex(str(mark["cwd"]), rf"^{BASE}/\.wp-[0-9a-f]{{32}}/home$")
        page = self.client.get(f"/applies/{run.pk}/").content.decode()
        self.assertIn("The rewrite rules were flushed and stored again.", page)

    def test_plain_permalinks_store_no_rules_and_the_result_says_so(self) -> None:
        self.sql("UPDATE wp_options SET option_value='' WHERE option_name='permalink_structure'")
        run = self.run_maintenance(Operation.REWRITE)
        result = self.assert_maintained(run)
        self.assertEqual((result.state, result.rules), ("available", "empty"))
        self.assertContains(
            self.client.get(f"/applies/{run.pk}/"), "WordPress stores no rewrite rules"
        )

    def test_the_unit_runs_under_the_reviewed_native_limits(self) -> None:
        run = self.run_maintenance(Operation.REWRITE)
        self.assert_maintained(run)
        shown = self.administer(
            "systemctl show -p LimitFSIZE -p MemoryMax -p MemorySwapMax -p RuntimeMaxUSec "
            f"{run.unit_name}"
        )
        values = dict(line.split("=", 1) for line in shown.splitlines())
        self.assertEqual(values["LimitFSIZE"], str(maintenance_native.MAX_FILE_BYTES))
        self.assertEqual(values["MemoryMax"], str(maintenance_native.MEMORY_MAX_BYTES))
        self.assertEqual(values["MemorySwapMax"], "0")
        self.assertEqual(values["RuntimeMaxUSec"], "30min")

    def test_the_journal_holds_exactly_the_one_result_record(self) -> None:
        self.permalinks()
        run = self.run_maintenance(Operation.REWRITE)
        self.assert_maintained(run)
        lines = self.administer(f"journalctl -u {run.unit_name} -o cat --no-pager").splitlines()
        records = [line for line in lines if line.startswith(execution.RECORD_MARKER)]
        self.assertEqual(len(records), 1, lines)
        record = maintenance_native.parse_record(
            records[0].removeprefix(f"{execution.RECORD_MARKER} "), Operation.REWRITE
        )
        self.assertEqual((record.state, record.rules), ("ok", "stored"))
        pam = re.compile(
            r"^(pam_unix\(runuser:session\): session (opened|closed) for user |"
            r"(Starting|Started) barectl-apply-)"
        )
        others = [line for line in lines if not line.startswith(execution.RECORD_MARKER)]
        self.assertEqual([line for line in others if not pam.match(line)], [])

    def test_hostile_output_makes_the_result_unavailable_and_never_reaches_the_journal(
        self,
    ) -> None:
        self.put(f"{CONTENT}/mu-plugins/hostile.php", HOSTILE)
        self.addCleanup(self.remove, f"{CONTENT}/mu-plugins/hostile.php")
        run = self.run_maintenance(Operation.REWRITE)
        result = self.assert_maintained(run)
        self.assertEqual((result.state, result.why), ("unavailable", "output"))
        journal = self.administer("journalctl --no-pager -o cat 2>/dev/null; true")
        self.assertNotIn("hunter2", journal)
        page = self.client.get(f"/applies/{run.pk}/").content.decode()
        self.assertNotIn("hunter2", page)
        self.assertIn("Result unavailable", page)
        self.assertEqual(self.residue(), "")

    def test_a_command_that_fails_ends_the_run_failed_and_is_not_repeated(self) -> None:
        self.put(
            f"{CONTENT}/mu-plugins/exits.php", "<?php\nadd_action('init', fn () => exit(3));\n"
        )
        self.addCleanup(self.remove, f"{CONTENT}/mu-plugins/exits.php")
        run = self.run_maintenance(Operation.REWRITE)
        self.assertEqual(
            (run.status, run.execution, run.exit_status, run.verification),
            (Status.FAILED, Execution.FAILED, maintenance_native.Exit.COMMAND, "not_applicable"),
            f"{run.failure}\n{self.journal_tail(run)}",
        )
        self.assertIn("did not complete", run.failure)
        record = [
            line
            for line in self.administer(f"journalctl -u {run.unit_name} -o cat").splitlines()
            if line.startswith(execution.RECORD_MARKER)
        ]
        self.assertEqual(len(record), 1)
        self.assertIn('"done":false', record[0])
        self.assertEqual(self.residue(), "")


class CacheAcceptanceTests(MaintenanceServerCase):
    def test_the_default_cache_flush_clears_only_its_own_process_and_says_so(self) -> None:
        self.recorder()
        plan = self.eligible_maintenance(Operation.CACHE)
        text = " ".join(plan.effects.values_list("text", flat=True))
        self.assertIn("clears the cache of its own command-line process", text)
        before = self.snapshot()
        run = self.run_maintenance(plan=plan)
        result = self.assert_maintained(run)
        self.assertEqual((result.state, result.rules), ("available", ""))
        after = self.snapshot()
        self.assert_same(before, after)
        page = self.client.get(f"/applies/{run.pk}/").content.decode()
        self.assertIn("cleared only its own command-line process", page)
        self.assertIn("is not a live-site cache repair", page)
        marks = self.marked()
        self.assertTrue(marks)
        self.assertEqual(self.residue(), "")

    def test_unverified_cache_scope_is_refused_and_no_code_runs(self) -> None:
        self.recorder()
        earlier = self.units()
        for name in ("object-cache.php", "advanced-cache.php", "db.php"):
            with self.subTest(name):
                self.put(f"{CONTENT}/{name}", "<?php\n// provider\n")
                try:
                    plan = self.review_maintenance(Operation.CACHE)
                finally:
                    self.remove(f"{CONTENT}/{name}")
                self.assertFalse(plan.eligible)
                self.assertIn("scope of an object-cache flush is unverified", self.texts(plan))
                self.assertFalse(PlanWordpressMaintenance.objects.filter(plan=plan).exists())
                self.assertEqual(self.marked(), [])
        self.assertEqual(self.units(), earlier)

    def test_a_drop_in_added_after_review_refuses_the_run_before_any_code(self) -> None:
        self.recorder()
        plan = self.eligible_maintenance(Operation.CACHE)
        self.put(f"{CONTENT}/object-cache.php", "<?php\n// provider\n")
        try:
            run = self.run_maintenance(plan=plan)
        finally:
            self.remove(f"{CONTENT}/object-cache.php")
        self.assertEqual(
            (run.status, run.execution, run.exit_status),
            (Status.FAILED, Execution.DRIFT, Exit.DRIFT),
            run.failure,
        )
        self.assertEqual(self.marked(), [])


class RefusalAcceptanceTests(MaintenanceServerCase):
    def test_changed_evidence_after_review_refuses_before_any_application_code(self) -> None:
        self.recorder()
        phar = "/usr/local/lib/wp-cli/wp-cli-2.12.0.phar"
        changes = {
            "a plugin appeared": (
                f"mkdir {CONTENT}/plugins/late && chown {USER} {CONTENT}/plugins/late",
                f"rm -rf {CONTENT}/plugins/late",
            ),
            "a plugin was removed": (
                f"mv {CONTENT}/plugins/akismet /tmp/akismet.held",
                f"mv /tmp/akismet.held {CONTENT}/plugins/akismet",
            ),
            "a must-use plugin changed": (
                f"echo '// changed' >>{CONTENT}/mu-plugins/recorder.php",
                f"sed -i '$ d' {CONTENT}/mu-plugins/recorder.php",
            ),
            "the private configuration changed": (
                f"sed -i \"s/'utf8mb4'/'utf8'/\" {PRIVATE}/wp-config.php",
                f"sed -i \"s/'utf8'/'utf8mb4'/\" {PRIVATE}/wp-config.php",
            ),
            "the core release changed": (
                f"sed -i \"s/'7.1.3'/'7.1.4'/\" {PUBLIC}/wp-includes/version.php",
                f"sed -i \"s/'7.1.4'/'7.1.3'/\" {PUBLIC}/wp-includes/version.php",
            ),
            "the site file changed": (
                f"echo '# changed' >>{SITE_FILE}",
                f"sed -i '$ d' {SITE_FILE}",
            ),
            "the tool changed": (f"chmod 0755 {phar}", f"chmod 0644 {phar}"),
        }
        for operation in Operation:
            for label, (change, undo) in changes.items():
                with self.subTest(operation=operation, label=label):
                    plan = self.eligible_maintenance(operation)
                    self.administer(change)
                    try:
                        run = self.run_maintenance(plan=plan)
                    finally:
                        self.administer(undo)
                    self.assertEqual(
                        (run.status, run.execution, run.exit_status, run.verification),
                        (Status.FAILED, Execution.DRIFT, Exit.DRIFT, Verification.NOT_APPLICABLE),
                        f"{label}: {run.failure}\n{self.journal_tail(run)}",
                    )
                    self.assertEqual(self.marked(), [], f"{label}: application code ran")
                    self.assertEqual(self.residue(), "")
                    self.assertFalse(MaintenanceResult.objects.filter(run=run).exists())

    def test_a_newer_core_is_never_maintained(self) -> None:
        version = f"{PUBLIC}/wp-includes/version.php"
        original = self.administer(f"cat {version}")
        self.addCleanup(self.put, version, original)
        self.administer(f"sed -i \"s/'7.1.3'/'7.1.4'/\" {version}")
        earlier = self.units()
        for operation in Operation:
            plan = self.review_maintenance(operation)
            self.assertFalse(plan.eligible)
            self.assertIn("exact qualified core", self.texts(plan))
        self.assertEqual(self.units(), earlier)

    def test_an_unsupported_configuration_is_refused_and_no_code_runs(self) -> None:
        self.recorder()
        private = f"{PRIVATE}/wp-config.php"
        original = self.administer(f"cat {private}")
        self.addCleanup(self.put, private, original, "600")
        self.administer(f"echo \"echo 'hostile';\" >>{private}")
        earlier = self.units()
        plan = self.review_maintenance()
        self.assertFalse(plan.eligible)
        self.assertIn("not Barectl's supported form", self.texts(plan))
        self.assertEqual(self.marked(), [])
        self.assertEqual(self.units(), earlier)

    def test_wp_cli_configuration_files_refuse_the_run(self) -> None:
        self.recorder()
        for directory in (PUBLIC, BASE, "/var"):
            with self.subTest(directory):
                plan = self.eligible_maintenance()
                self.administer(f"printf 'path: /tmp\\n' >{directory}/wp-cli.yml")
                try:
                    run = self.run_maintenance(plan=plan)
                finally:
                    self.administer(f"rm -f {directory}/wp-cli.yml")
                self.assertEqual(
                    (run.execution, run.exit_status),
                    (Execution.MAINTENANCE_REFUSED, Exit.STAGING),
                    run.failure,
                )
                self.assertEqual(self.marked(), [])
                self.assertEqual(self.residue(), "")

    def test_a_missing_tool_refuses_before_any_application_code_runs(self) -> None:
        self.recorder()
        plan = self.eligible_maintenance()
        self.administer("mv /usr/bin/timeout /usr/bin/timeout.held")
        try:
            run = self.run_maintenance(plan=plan)
        finally:
            self.administer("mv /usr/bin/timeout.held /usr/bin/timeout")
        self.assertEqual(
            (run.execution, run.exit_status), (Execution.MAINTENANCE_REFUSED, Exit.TOOLS)
        )
        self.assertEqual(self.marked(), [])

    def test_inspection_authority_alone_cannot_apply_a_maintenance_plan(self) -> None:
        self.recorder()
        plan = self.eligible_maintenance()
        earlier = self.units()
        inspector = get_user_model().objects.create_user("inspector", password="x")  # noqa: S106
        for codename in (
            "view_server",
            "view_siteobservation",
            "view_wordpressplan",
            "prepare_wordpressplan",
            "inspect_wordpress",
            "view_configurationplan",
            "apply_configurationplan",
        ):
            inspector.user_permissions.add(Permission.objects.get(codename=codename))
        self.client.force_login(inspector)
        self.assertEqual(self.client.post(f"/plans/{plan.pk}/apply/").status_code, 403)
        self.assertFalse(ApplyRun.objects.filter(plan_number=plan.pk).exists())
        self.assertEqual(self.units(), earlier)
        self.assertEqual(self.marked(), [])


class ReconciliationAcceptanceTests(MaintenanceServerCase):
    def test_a_lost_response_checks_the_original_run_without_flushing_again(self) -> None:
        self.recorder()
        plan = self.eligible_maintenance(Operation.REWRITE)
        earlier = self.units()
        request = self.request(plan)
        with self.losing(
            lambda command: command.startswith("sudo -n /usr/bin/systemd-run"), after=True
        ):
            run_worker()
        request.refresh_from_db()
        self.assertEqual(request.status, Status.RECONCILING, request.failure)
        self.wait_terminal(request.unit_name, timeout=300)
        ran = len(self.marked())
        self.assertGreater(ran, 0)
        run = self.check(request)
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        self.assertEqual(
            sorted(self.units()),
            sorted([*earlier, run.unit_name]),
            "the unit was submitted exactly once",
        )
        self.assertEqual(len(self.marked()), ran, "checking ran application code again")
        self.assertEqual(MaintenanceResult.objects.get(run=run).state, "available")

    def test_a_rotated_journal_makes_the_result_unavailable_but_keeps_the_outcome(self) -> None:
        from unittest import mock

        from . import maintenance_apply

        plan = self.eligible_maintenance()
        real = maintenance_apply.verify

        def rotated(shell: object, run: ApplyRun) -> Verification:
            self.administer("journalctl --rotate; journalctl --vacuum-time=1s >/dev/null 2>&1")
            return real(shell, run)  # type: ignore[arg-type]

        with mock.patch.object(maintenance_apply, "verify", rotated):
            run = self.run_maintenance(plan=plan)
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        result = MaintenanceResult.objects.get(run=run)
        self.assertEqual((result.state, result.why), ("unavailable", "journal_missing"))
        self.assertEqual(self.unit(run.unit_name)["Result"], "success")

    def test_a_held_lock_refuses_before_any_application_code_and_is_not_replayed(self) -> None:
        self.recorder()
        plan = self.eligible_maintenance()
        other = self.eligible_maintenance(Operation.CACHE)
        first = self.request(plan)
        self.administer("flock -x /run/lock/barectl/mutation.lock sleep 25", detach=True)
        self.addCleanup(self.administer, "pkill -x flock; true")
        run_worker()
        first.refresh_from_db()
        self.assertEqual(
            (first.execution, first.exit_status),
            (Execution.LOCK_CONFLICT, native.Exit.LOCK_CONFLICT),
        )
        self.assertEqual(self.marked(), [])
        self.assertIn("before running any application code", first.failure)
        self.assertEqual(ApplyRun.objects.filter(plan_number=plan.pk).count(), 1)
        self.assertFalse(ApplyRun.objects.filter(plan_number=other.pk).exists())
