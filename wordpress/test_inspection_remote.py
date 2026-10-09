"""Explicit WordPress inspection on a real, disposable Ubuntu server
(docs/wordpress.md#inspecting-wordpress).

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. The administrator prepares the site and Barectl
installs a real WordPress through its own reviewed workflow (``test_install_apply_remote``);
Barectl then reviews and applies inspections through the dashboard request, the worker, its SSH
connection, actual systemd, journald, WP-CLI, MariaDB and WordPress, and the official checksum
catalogs over the real network. The administrator alters the application between steps, by
hand through ``docker exec``, to fault each boundary. Ground truth is read as root,
independently of Barectl.
"""

import base64
import json
import re
import shlex
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission

from bootstrap import native
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, Verification
from discovery.fakes import run_worker
from discovery.services import request_discovery
from operations.models import RemoteOperation

from . import execution, inspection_apply, inspection_fakes, inspection_native
from .inspection_models import (
    InspectionItem,
    InspectionResult,
    Operation,
    PlanWordpressInspection,
)
from .test_install_apply_remote import BASE, SITE_FILE, USER, InstallApplyTestCase
from .test_install_remote import IDENTIFIER, PRIVATE, PUBLIC

Status = RemoteOperation.Status
Exit = execution.Exit
CONTENT = f"{PUBLIC}/wp-content"
MARKER = "/var/tmp/barectl-inspection-marker"  # noqa: S108 - a file in the disposable server
ENVIRONMENT = {
    "HOME",
    "LC_ALL",
    "PATH",
    "PWD",
    "TMPDIR",
    "WP_CLI_CACHE_DIR",
    "WP_CLI_CONFIG_PATH",
    "WP_CLI_DISABLE_AUTO_CHECK_UPDATE",
    "WP_CLI_PACKAGES_DIR",
}
# A must-use plugin that records who ran it and with which environment.
RECORDER = (
    "<?php\n"
    f"file_put_contents('{MARKER}', json_encode(['uid' => posix_geteuid(), "
    "'env' => array_keys(getenv()), 'cwd' => getcwd()]) . \"\\n\", FILE_APPEND);\n"
)
HOSTILE = (
    "<?php\n"
    'echo "debug: secret=hunter2\\n";\n'
    'fwrite(STDERR, "stderr: secret=hunter2\\n");\n'
    "trigger_error('notice: secret=hunter2', E_USER_WARNING);\n"
    "var_dump(['password' => 'hunter2']);\n"
)


def plugin_header(name: str, version: str = "1.0") -> str:
    return f"<?php\n/*\nPlugin Name: {name}\nVersion: {version}\n*/\n"


class InspectionServerCase(InstallApplyTestCase):
    """A disposable server on which Barectl installed WordPress through its own workflow."""

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        for codename in ("inspect_wordpress",):
            cls.user.user_permissions.add(Permission.objects.get(codename=codename))

    @override
    def setUp(self) -> None:
        super().setUp()
        run = self.apply_install(self.eligible())
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            f"{run.failure}\n{self.journal_tail(run)}",
        )
        self.refresh()

    # Steps -------------------------------------------------------------------------------

    def refresh(self) -> None:
        """Observe the server again, as an operator's connection check does."""
        request_discovery(self.server)
        run_worker()

    def put(self, path: str, text: str, mode: str = "644", owner: str = USER) -> None:
        directory = path.rsplit("/", 1)[0]
        self.administer(
            f"install -d -o {owner} -g {owner} -m 755 {directory} && "
            f"printf %s {shlex.quote(text)} >{path} && chown {owner}:{owner} {path} && "
            f"chmod {mode} {path}"
        )

    def remove(self, path: str) -> None:
        self.administer(f"rm -rf {path}")

    def plugin(self, slug: str, version: str = "1.0") -> None:
        self.put(f"{CONTENT}/plugins/{slug}/{slug}.php", plugin_header(slug, version))
        self.addCleanup(self.remove, f"{CONTENT}/plugins/{slug}")

    def recorder(self) -> None:
        self.put(f"{CONTENT}/mu-plugins/recorder.php", RECORDER)
        self.administer(f"rm -f {MARKER}")
        self.addCleanup(self.administer, f"rm -f {MARKER} {CONTENT}/mu-plugins/recorder.php")

    def marked(self) -> list[dict[str, object]]:
        text = self.administer(f"cat {MARKER} 2>/dev/null; true")
        marks = [json.loads(line) for line in text.splitlines()]
        # Web requests the pool served run the recorder too; only inspections are of interest.
        return [mark for mark in marks if str(mark["cwd"]).startswith(f"{BASE}/.wp-")]

    def block(self, host: str) -> None:
        """Make a catalog host unreachable by a local name that serves a certificate WP-CLI
        refuses."""
        self.administer(f"echo '127.0.0.1 {host}' >>/etc/hosts")
        self.addCleanup(
            self.administer,
            f"grep -v ' {host}$' /etc/hosts >/tmp/hosts.new; cat /tmp/hosts.new >/etc/hosts; "
            "rm -f /tmp/hosts.new",
        )

    def review_inspection(self, operation: str = Operation.INSPECT) -> ConfigurationPlan:
        self.refresh()
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/{IDENTIFIER}/wordpress/inspection/prepare/",
            {"inspection-operation": operation},
        )
        self.assertEqual(response.status_code, 302, response.content[:300])
        run_worker()
        from bootstrap.models import PlanPreparation

        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        return ConfigurationPlan.objects.get(preparation=preparation)

    def eligible_inspection(self, operation: str = Operation.INSPECT) -> ConfigurationPlan:
        plan = self.review_inspection(operation)
        self.assertTrue(plan.eligible, self.texts(plan))
        return plan

    def run_inspection(
        self, operation: str = Operation.INSPECT, plan: ConfigurationPlan | None = None
    ) -> ApplyRun:
        run = self.request(plan or self.eligible_inspection(operation))
        run_worker()
        run.refresh_from_db()
        return run

    def assert_inspected(self, run: ApplyRun) -> InspectionResult:
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            f"{run.failure}\n{self.journal_tail(run)}",
        )
        return InspectionResult.objects.get(run=run)

    def names(self, result: InspectionResult, kind: str) -> list[str]:
        return list(
            InspectionItem.objects.filter(result=result, kind=kind).values_list("name", flat=True)
        )

    def residue(self) -> str:
        return self.administer(f"ls -A {BASE} | grep '^[.]wp' || true").strip()

    def options_command(self) -> str:
        return f"mariadb --no-defaults --protocol=socket -N -B -e {shlex.quote(OPTIONS)}"

    def tree(self) -> dict[str, str]:
        """Everything an inspection must leave exactly as it was."""
        reads = {
            "public": f"find {PUBLIC} -xdev -printf '%y %m %U %G %s %T@ %p\\n' | sort | sha256sum",
            "base": f"find {BASE} -maxdepth 1 -printf '%y %m %U %G %p\\n' | sort",
            "private": f"sha256sum {PRIVATE}/wp-config.php",
            "site": f"sha256sum {SITE_FILE}",
            "tables": self.tables_command(),
            "options": self.options_command(),
            "backups": "ls -A /var/backups/nginx",
        }
        return {name: self.administer(command) for name, command in reads.items()}

    def assert_unchanged(self, before: dict[str, str]) -> None:
        after = self.tree()
        self.assertEqual(
            {name: text.splitlines() for name, text in after.items()},
            {name: text.splitlines() for name, text in before.items()},
        )


IDENTIFIER_DB = f"s{IDENTIFIER}"
# WordPress writes its own transients and caches whenever it loads, so they are not Barectl's.
OPTIONS = (
    f"SELECT option_name, MD5(option_value) FROM {IDENTIFIER_DB}.wp_options "  # noqa: S608 - the test's own fixed name
    "WHERE option_name NOT LIKE '%transient%' ORDER BY 1"
)


class InspectionAcceptanceTests(InspectionServerCase):
    def test_an_inspection_reports_the_inventory_as_the_site_user_and_changes_nothing(self) -> None:
        self.recorder()
        self.plugin("custom-tool", "2.3")
        self.put(f"{CONTENT}/object-cache.php", "<?php\n// cache\n")
        self.addCleanup(self.remove, f"{CONTENT}/object-cache.php")
        plan = self.eligible_inspection()
        row = PlanWordpressInspection.objects.get(plan=plan)
        self.assertIn("recorder.php", row.targets)
        self.assertIn("dropin object-cache.php", row.targets)
        before = self.tree()
        run = self.run_inspection(plan=plan)
        result = self.assert_inspected(run)
        self.assertEqual((result.state, result.core_installed), ("available", True))
        self.assertEqual(result.core_version, "7.1.3")
        plugins = self.names(result, "plugin")
        self.assertIn("akismet", plugins)
        self.assertIn("custom-tool", plugins)
        self.assertEqual(self.names(result, "mu-plugin"), ["recorder"])
        self.assertEqual(self.names(result, "dropin"), ["object-cache.php"])
        self.assertTrue(self.names(result, "theme"))
        item = InspectionItem.objects.get(result=result, name="custom-tool")
        self.assertEqual((item.status, item.version), ("inactive", "2.3"))
        self.assert_unchanged(before)
        self.assertEqual(self.residue(), "")
        # WordPress and WP-CLI ran as the site user, from the private working directory, with
        # exactly the controlled environment.
        uid = int(self.administer(f"id -u {USER}").strip())
        marks = self.marked()
        self.assertTrue(marks)
        for mark in marks:
            self.assertEqual(mark["uid"], uid)
            self.assertEqual(set(mark["env"]), ENVIRONMENT)  # type: ignore[call-overload]
            self.assertRegex(str(mark["cwd"]), rf"^{BASE}/\.wp-[0-9a-f]{{32}}/home$")
        # The reported time is the server's clock, and the page shows it with the inventory.
        page = self.client.get(f"/applies/{run.pk}/").content.decode()
        for text in ("custom-tool", "object-cache.php", "Reported by the application", "akismet"):
            self.assertIn(text, page)
        shown = self.client.get(f"/servers/{self.server.pk}/sites/{IDENTIFIER}/wordpress/")
        self.assertContains(shown, "Latest explicit inspection result")

    def test_the_unit_runs_under_the_reviewed_native_limits(self) -> None:
        run = self.run_inspection()
        self.assert_inspected(run)
        shown = self.administer(
            "systemctl show -p LimitFSIZE -p MemoryMax -p MemorySwapMax -p RuntimeMaxUSec "
            f"{run.unit_name}"
        )
        values = dict(line.split("=", 1) for line in shown.splitlines())
        self.assertEqual(values["LimitFSIZE"], str(inspection_native.MAX_FILE_BYTES))
        self.assertEqual(values["MemoryMax"], str(inspection_native.MEMORY_MAX_BYTES))
        self.assertEqual(values["MemorySwapMax"], "0")
        self.assertEqual(values["RuntimeMaxUSec"], "30min")

    def test_the_journal_holds_exactly_the_one_result_record(self) -> None:
        self.recorder()
        run = self.run_inspection()
        result = self.assert_inspected(run)
        lines = self.administer(f"journalctl -u {run.unit_name} -o cat --no-pager").splitlines()
        records = [line for line in lines if line.startswith(execution.RECORD_MARKER)]
        self.assertEqual(len(records), 1, lines)
        self.assertLessEqual(len(records[0]), execution.MAX_RECORD)
        record = inspection_native.parse_record(
            records[0].removeprefix(f"{execution.RECORD_MARKER} "), Operation.INSPECT
        )
        self.assertEqual(
            sorted(item.name for item in record.items),
            sorted(InspectionItem.objects.filter(result=result).values_list("name", flat=True)),
        )
        # Nothing else the commands could print, such as their argument echoes, is journaled.
        # runuser's own PAM session messages are the only other lines the unit logs.
        pam = re.compile(
            r"^(pam_unix\(runuser:session\): session (opened|closed) for user |"
            r"(Starting|Started) barectl-apply-)"
        )
        others = [line for line in lines if not line.startswith(execution.RECORD_MARKER)]
        self.assertEqual([line for line in others if not pam.match(line)], [])

    def test_a_record_the_site_user_writes_to_the_journal_is_never_the_result(self) -> None:
        forged = inspection_fakes.project(
            Operation.INSPECT,
            inspection_fakes.inventory_outputs(
                plugins='[{"name":"forged-plugin","status":"active","version":"9"}]'
            ),
        )
        header = base64.b64encode(f"forged\n\n6\n0\n0\n0\n0\n{forged}\n".encode()).decode()
        forger = (
            "<?php\n"
            f"if (strpos(getcwd(), '{BASE}/.wp-') === 0) {{\n"
            "  $s = stream_socket_client('unix:///run/systemd/journal/stdout');\n"
            f"  fwrite($s, base64_decode('{header}'));\n"
            "  fclose($s);\n}\n"
        )
        self.put(f"{CONTENT}/mu-plugins/forger.php", forger)
        self.addCleanup(self.remove, f"{CONTENT}/mu-plugins/forger.php")
        run = self.run_inspection()
        result = self.assert_inspected(run)
        entries = [
            json.loads(line)
            for line in self.administer(
                f"journalctl -u {run.unit_name} -o json --all --no-pager"
            ).splitlines()
        ]
        marked = [
            entry
            for entry in entries
            if isinstance(entry.get("MESSAGE"), str)
            and entry["MESSAGE"].startswith(execution.RECORD_MARKER)
        ]
        self.assertEqual(sorted(entry["_UID"] for entry in marked), ["0", str(self.uid(USER))])
        self.assertEqual((result.state, result.why), ("available", ""))
        self.assertNotIn("forged-plugin", self.names(result, "plugin"))
        self.assertIn("akismet", self.names(result, "plugin"))

    def uid(self, user: str) -> int:
        return int(self.administer(f"id -u {user}").strip())


class IntegrityAcceptanceTests(InspectionServerCase):
    def verdict(self, operation: str) -> InspectionResult:
        return self.assert_inspected(self.run_inspection(operation))

    def test_core_checksums_match_mismatch_and_unavailable_are_separate(self) -> None:
        matched = self.verdict(Operation.CORE)
        self.assertEqual((matched.integrity, matched.core_version), ("match", "7.1.3"))
        before = self.tree()
        self.administer(f"echo '// edited' >>{PUBLIC}/wp-includes/load.php")
        self.administer(f"rm {PUBLIC}/readme.html")
        self.put(f"{PUBLIC}/wp-admin/evil.php", "<?php\n")
        mismatched = self.verdict(Operation.CORE)
        self.assertEqual(
            (mismatched.integrity, mismatched.modified, mismatched.missing, mismatched.extra),
            ("mismatch", 1, 1, 1),
        )
        self.assertIn("modified wp-includes/load.php", mismatched.files)
        self.assertNotEqual(self.tree(), before)
        self.block("api.wordpress.org")
        unavailable = self.verdict(Operation.CORE)
        self.assertEqual(
            (unavailable.state, unavailable.integrity, unavailable.integrity_why),
            ("available", "unavailable", "catalog"),
        )
        self.assertEqual((unavailable.modified, unavailable.missing, unavailable.extra), (0, 0, 0))
        page = self.client.get(f"/applies/{ApplyRun.objects.latest('pk').pk}/")
        self.assertContains(page, "neither a pass nor a mismatch")
        self.assertEqual(self.residue(), "")

    def test_core_verification_executes_no_application_code(self) -> None:
        self.recorder()
        self.verdict(Operation.CORE)
        self.assertEqual(self.marked(), [], "core verification loaded WordPress")
        plan = self.review_inspection(Operation.CORE)
        text = " ".join(plan.effects.values_list("text", flat=True))
        self.assertIn("before WordPress loads", text)

    def test_plugin_checksums_distinguish_match_mismatch_and_unavailable(self) -> None:
        self.plugin("custom-tool")
        result = self.verdict(Operation.PLUGINS)
        found = {
            item.name: (item.verdict, item.why)
            for item in InspectionItem.objects.filter(result=result)
        }
        self.assertEqual(found["akismet"], ("match", ""), found)
        # A private package is unavailable: neither trusted nor corrupt by inference.
        self.assertEqual(found["custom-tool"], ("unavailable", "catalog"))
        self.administer(f"echo '// edited' >>{CONTENT}/plugins/akismet/akismet.php")
        self.put(f"{CONTENT}/plugins/akismet/extra.php", "<?php\n")
        edited = {
            item.name: (item.verdict, item.modified, item.added)
            for item in InspectionItem.objects.filter(result=self.verdict(Operation.PLUGINS))
        }
        self.assertEqual(edited["akismet"], ("mismatch", 1, 1))
        self.assertEqual(edited["custom-tool"][0], "unavailable")
        self.block("downloads.wordpress.org")
        offline = {
            item.name: (item.verdict, item.why)
            for item in InspectionItem.objects.filter(result=self.verdict(Operation.PLUGINS))
        }
        self.assertEqual(offline["akismet"], ("unavailable", "catalog"))

    def test_a_newer_core_is_diagnosed_with_the_qualified_tool_and_never_enables_mutation(
        self,
    ) -> None:
        version = f"{PUBLIC}/wp-includes/version.php"
        original = self.administer(f"cat {version}")
        self.addCleanup(self.put, version, original)
        self.administer(f"sed -i \"s/'7.1.3'/'7.1.4'/\" {version}")
        plan = self.eligible_inspection()
        row = PlanWordpressInspection.objects.get(plan=plan)
        self.assertEqual((row.core_version, row.core_qualified), ("7.1.4", False))
        result = self.assert_inspected(self.run_inspection(plan=plan))
        self.assertEqual(result.core_version, "7.1.4")
        checksums = self.verdict(Operation.CORE)
        self.assertNotEqual(checksums.integrity, "match")
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, "no installation, Finish or maintenance")


class RefusalAcceptanceTests(InspectionServerCase):
    def test_an_unsupported_configuration_is_refused_and_no_code_runs(self) -> None:
        self.recorder()
        private = f"{PRIVATE}/wp-config.php"
        original = self.administer(f"cat {private}")
        self.addCleanup(self.put, private, original, "600")
        self.administer(f"echo \"echo 'hostile';\" >>{private}")
        before = self.administer("ls -A /var/tmp")
        plan = self.review_inspection()
        self.assertFalse(plan.eligible)
        self.assertIn("not Barectl's supported form", self.texts(plan))
        self.assertFalse(PlanWordpressInspection.objects.filter(plan=plan).exists())
        self.assertEqual(self.marked(), [])
        self.assertEqual(self.units().count(""), 0)
        self.assertEqual(self.administer("ls -A /var/tmp"), before)

    def test_changed_evidence_after_review_refuses_before_any_application_code(self) -> None:
        self.recorder()
        site = f"{SITE_FILE}"
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
            "a drop-in appeared": (
                f"printf '<?php\\n' >{CONTENT}/db.php; chown {USER} {CONTENT}/db.php",
                f"rm -f {CONTENT}/db.php",
            ),
            "the private configuration changed": (
                f"sed -i \"s/'utf8mb4'/'utf8'/\" {PRIVATE}/wp-config.php",
                f"sed -i \"s/'utf8'/'utf8mb4'/\" {PRIVATE}/wp-config.php",
            ),
            "the core release changed": (
                f"sed -i \"s/'7.1.3'/'7.1.4'/\" {PUBLIC}/wp-includes/version.php",
                f"sed -i \"s/'7.1.4'/'7.1.3'/\" {PUBLIC}/wp-includes/version.php",
            ),
            "the site file changed": (f"echo '# changed' >>{site}", f"sed -i '$ d' {site}"),
            "the tool changed": (f"chmod 0755 {phar}", f"chmod 0644 {phar}"),
        }
        for label, (change, undo) in changes.items():
            with self.subTest(label):
                plan = self.eligible_inspection()
                self.administer(change)
                try:
                    run = self.run_inspection(plan=plan)
                finally:
                    self.administer(undo)
                self.assertEqual(
                    (run.status, run.execution, run.exit_status, run.verification),
                    (Status.FAILED, Execution.DRIFT, Exit.DRIFT, Verification.NOT_APPLICABLE),
                    f"{label}: {run.failure}\n{self.journal_tail(run)}",
                )
                self.assertEqual(self.marked(), [], f"{label}: application code ran")
                self.assertEqual(self.residue(), "")
                self.assertFalse(InspectionResult.objects.filter(run=run).exists())

    def test_a_plugin_table_beside_the_core_schema_does_not_stale_the_review(self) -> None:
        plan = self.eligible_inspection()
        create = f"CREATE TABLE {IDENTIFIER_DB}.late_plugin_table (a INT)"
        self.administer(f"mariadb --no-defaults --protocol=socket -e {shlex.quote(create)}")
        drop = f"DROP TABLE {IDENTIFIER_DB}.late_plugin_table"
        self.addCleanup(
            self.administer, f"mariadb --no-defaults --protocol=socket -e {shlex.quote(drop)}"
        )
        self.assert_inspected(self.run_inspection(plan=plan))

    def test_project_and_global_wp_cli_configuration_refuses_the_run(self) -> None:
        self.recorder()
        # /var/www is part of the site evidence, which refuses first as a change.
        refused = {
            PUBLIC: (Execution.INSPECTION_REFUSED, Exit.STAGING),
            BASE: (Execution.INSPECTION_REFUSED, Exit.STAGING),
            "/var": (Execution.INSPECTION_REFUSED, Exit.STAGING),
            "/var/www": (Execution.DRIFT, Exit.DRIFT),
        }
        for directory, (outcome, status) in refused.items():
            with self.subTest(directory):
                plan = self.eligible_inspection()
                self.administer(f"printf 'path: /tmp\\n' >{directory}/wp-cli.yml")
                try:
                    run = self.run_inspection(plan=plan)
                finally:
                    self.administer(f"rm -f {directory}/wp-cli.yml")
                self.assertEqual((run.execution, run.exit_status), (outcome, status), run.failure)
                self.assertEqual(self.marked(), [])
                self.assertEqual(self.residue(), "")

    def test_a_held_lock_refuses_before_any_application_code_runs(self) -> None:
        self.recorder()
        plan = self.eligible_inspection()
        self.administer("flock -x /run/lock/barectl/mutation.lock sleep 40", detach=True)
        self.addCleanup(self.administer, "pkill -x flock; true")
        run = self.run_inspection(plan=plan)
        self.assertEqual(
            (run.execution, run.exit_status), (Execution.LOCK_CONFLICT, native.Exit.LOCK_CONFLICT)
        )
        self.assertEqual(self.marked(), [])
        self.assertIn("before running any application code", run.failure)

    def test_a_missing_tool_refuses_before_any_application_code_runs(self) -> None:
        self.recorder()
        plan = self.eligible_inspection()
        self.administer("mv /usr/bin/timeout /usr/bin/timeout.held")
        try:
            run = self.run_inspection(plan=plan)
        finally:
            self.administer("mv /usr/bin/timeout.held /usr/bin/timeout")
        self.assertEqual(
            (run.execution, run.exit_status), (Execution.INSPECTION_REFUSED, Exit.TOOLS)
        )
        self.assertEqual(self.marked(), [])


class OutputAcceptanceTests(InspectionServerCase):
    def test_hostile_must_use_output_is_unavailable_and_never_reaches_the_journal(self) -> None:
        self.put(f"{CONTENT}/mu-plugins/hostile.php", HOSTILE)
        self.addCleanup(self.remove, f"{CONTENT}/mu-plugins/hostile.php")
        plan = self.eligible_inspection()
        run = self.run_inspection(plan=plan)
        result = self.assert_inspected(run)
        self.assertEqual((result.state, result.why), ("unavailable", "output"))
        self.assertFalse(InspectionItem.objects.filter(result=result).exists())
        journal = self.administer("journalctl --no-pager -o cat 2>/dev/null; true")
        self.assertNotIn("hunter2", journal)
        page = self.client.get(f"/applies/{run.pk}/").content.decode()
        self.assertNotIn("hunter2", page)
        self.assertIn("Result unavailable", page)
        self.assertEqual(self.residue(), "")

    def test_secrets_never_reach_the_journal_the_records_or_the_pages(self) -> None:
        salts = re.findall(
            r"define\( '[A-Z_]*(?:KEY|SALT)', '([^']{32,})' \)",
            self.administer(f"cat {PRIVATE}/wp-config.php"),
        )
        self.assertEqual(len(salts), 8)
        plan = self.eligible_inspection()
        run = self.run_inspection(plan=plan)
        self.assert_inspected(run)
        surfaces = [
            self.administer("journalctl --no-pager -o cat 2>/dev/null; true"),
            self.administer(f"systemctl show {run.unit_name}"),
            self.client.get(f"/applies/{run.pk}/").content.decode(),
            self.client.get(f"/plans/{plan.pk}/").content.decode(),
            self.client.get(
                f"/servers/{self.server.pk}/sites/{IDENTIFIER}/wordpress/"
            ).content.decode(),
        ]
        surfaces += [
            f"{field.attname}={getattr(row, field.attname)}"
            for row in (run, PlanWordpressInspection.objects.get(plan=plan))
            for field in row._meta.concrete_fields
        ]
        text = "\n".join(surfaces)
        for salt in salts:
            self.assertNotIn(salt, text)

    def test_more_inspection_items_than_one_result_holds_are_refused(self) -> None:
        for index in range(125):
            self.administer(f"mkdir -p {CONTENT}/plugins/bulk-{index:03d}")
        self.addCleanup(self.administer, f"rm -rf {CONTENT}/plugins/bulk-*")
        plan = self.review_inspection()
        self.assertFalse(plan.eligible)
        self.assertIn("more than the 128", self.texts(plan))

    def test_a_result_over_16_kib_is_unavailable_never_truncated(self) -> None:
        for index in range(100):
            slug = f"{'p' * 90}{index:02d}"
            self.put(
                f"{CONTENT}/plugins/{slug}/{slug}.php",
                plugin_header(slug, "9." * 19 + "9"),
            )
        self.addCleanup(self.administer, f"rm -rf {CONTENT}/plugins/{'p' * 90}*")
        run = self.run_inspection()
        result = self.assert_inspected(run)
        self.assertEqual((result.state, result.why), ("unavailable", "overflow"))
        self.assertFalse(InspectionItem.objects.filter(result=result).exists())
        lines = self.administer(f"journalctl -u {run.unit_name} -o cat --no-pager").splitlines()
        self.assertTrue(all(len(line) <= execution.MAX_RECORD for line in lines))


class ReconciliationAcceptanceTests(InspectionServerCase):
    def test_a_rotated_journal_makes_the_result_unavailable_but_keeps_the_outcome(self) -> None:
        plan = self.eligible_inspection()
        real = inspection_apply.verify

        def rotated(shell: object, run: ApplyRun) -> Verification:
            self.administer("journalctl --rotate; journalctl --vacuum-time=1s >/dev/null 2>&1")
            return real(shell, run)  # type: ignore[arg-type]

        with mock.patch.object(inspection_apply, "verify", rotated):
            run = self.run_inspection(plan=plan)
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        result = InspectionResult.objects.get(run=run)
        self.assertEqual((result.state, result.why), ("unavailable", "journal_missing"))
        self.assertEqual(self.unit(run.unit_name)["Result"], "success")
        self.assertContains(self.client.get(f"/applies/{run.pk}/"), "Result unavailable")

    def test_a_lost_response_checks_the_original_run_without_inspecting_again(self) -> None:
        self.recorder()
        plan = self.eligible_inspection()
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
        self.assertEqual(InspectionResult.objects.get(run=run).state, "available")

    def test_the_run_records_the_invocation_a_check_retrieves_by(self) -> None:
        run = self.run_inspection()
        self.assert_inspected(run)
        run.refresh_from_db()
        self.assertRegex(run.invocation_id, r"^[0-9a-f]{32}$")
        self.assertEqual(
            self.unit(run.unit_name)["InvocationID"], run.invocation_id, "the recorded invocation"
        )

    def test_another_controller_cannot_dispatch_while_one_inspection_holds_the_lock(self) -> None:
        self.recorder()
        plan = self.eligible_inspection()
        other = self.eligible_inspection()
        first = self.request(plan)
        self.administer("flock -x /run/lock/barectl/mutation.lock sleep 25", detach=True)
        self.addCleanup(self.administer, "pkill -x flock; true")
        run_worker()
        first.refresh_from_db()
        self.assertEqual(first.execution, Execution.LOCK_CONFLICT)
        # Nothing was replayed for the plan that was refused; a new review is needed.
        self.assertEqual(ApplyRun.objects.filter(plan_number=plan.pk).count(), 1)
        self.assertFalse(ApplyRun.objects.filter(plan_number=other.pk).exists())
