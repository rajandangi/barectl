"""The WordPress maintenance body, projection and record grammar
(docs/wordpress.md#maintaining-wordpress).

Pure tests. The projection runs as the production script does, over fixed command outputs.
``wordpress/test_maintenance_remote.py`` establishes the native behaviour on Ubuntu 26.04.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from . import execution, inspection_native, maintenance_native
from .maintenance_fakes import CACHE_OK, REWRITE_EMPTY, REWRITE_OK, project
from .maintenance_models import Operation, PlanWordpressMaintenance

SHELL = shutil.which("dash") or shutil.which("sh") or "sh"
UNIT = f"barectl-apply-{'a' * 32}.service"
BOOT = "6f1c4e1a-3a8e-4b5f-9d2e-7c0b8a9d1e23"
DIGEST = "e" * 64
MARKER = f"{execution.RECORD_MARKER} "


def row(operation: str = Operation.REWRITE, **changes: object) -> PlanWordpressMaintenance:
    base = PlanWordpressMaintenance(
        identifier="shop",
        php_version="8.5",
        php_supply="ubuntu",
        site_revision=4,
        site_user="sshop",
        uid=1003,
        gid=1003,
        canonical_name="www.shop.test",
        url="https://www.shop.test",
        operation=operation,
        tool_version="2.12.0",
        tool_path="/usr/local/lib/wp-cli/wp-cli-2.12.0.phar",
        tool_sha256="d" * 64,
        core_version="7.1.3",
        core_locale="en_US",
        core_qualified=True,
        configuration_sha256="c" * 64,
        targets="plugin akismet\nmu-plugin loader.php\ntheme twentytwentysix",
        max_file_bytes=maintenance_native.MAX_FILE_BYTES,
        memory_max_bytes=maintenance_native.MEMORY_MAX_BYTES,
        runtime_limit_seconds=maintenance_native.RUNTIME_LIMIT_SECONDS,
        command_seconds=maintenance_native.COMMAND_SECONDS,
        budget_seconds=maintenance_native.BUDGET_SECONDS,
    )
    for name, value in changes.items():
        setattr(base, name, value)
    return base


def evidence() -> inspection_native.Evidence:
    return inspection_native.Evidence(DIGEST, DIGEST, DIGEST)


def syntax(text: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "script"
        script.write_text(text)
        return subprocess.run(  # noqa: S603 - a syntax check of the tests' own scripts
            [SHELL, "-n", str(script)], capture_output=True, text=True, check=False
        )


def loaded(line: str) -> dict[str, object]:
    data = json.loads(line.removeprefix(MARKER))
    if not line.startswith(MARKER) or not isinstance(data, dict):
        raise AssertionError(line)
    return data


class BodyTests(SimpleTestCase):
    def test_every_actions_body_and_payload_are_valid_shell(self) -> None:
        for operation in Operation:
            with self.subTest(operation):
                review = row(operation)
                body = maintenance_native.body(review, evidence())
                payload = maintenance_native.staged(UNIT, BOOT, 123456, review, evidence())[0]
                for name, text in (("body", body), ("payload", payload)):
                    result = syntax(text)
                    self.assertEqual(result.returncode, 0, f"{name}: {result.stderr}")
                self.assertLess(len(payload.encode()), 16 * 1024)

    def test_the_steps_are_named_in_order(self) -> None:
        names = [step.name for step in maintenance_native.body_steps(row(), evidence())]
        self.assertEqual(
            names, ["helpers", "tools", "revalidation", "stage", "run", "project", "finish"]
        )

    def test_a_soft_rewrite_flush_loads_plugins_and_never_hard_flushes(self) -> None:
        text = maintenance_native.body(row(Operation.REWRITE), evidence())
        self.assertIn("W flush rewrite flush;", text)
        self.assertNotIn("--hard", text)
        self.assertNotIn("--skip-plugins", text)
        self.assertNotIn("--skip-themes", text)
        self.assertIn("--skip-packages", text)

    def test_the_cache_flush_keeps_the_skip_flags_and_runs_one_command(self) -> None:
        text = maintenance_native.body(row(Operation.CACHE), evidence())
        self.assertIn("W flush cache flush;", text)
        self.assertIn("--skip-packages --skip-plugins --skip-themes", text)
        self.assertNotIn("W flush rewrite", text)

    def test_the_body_revalidates_before_the_application_command_runs(self) -> None:
        text = maintenance_native.body(row(), evidence())
        self.assertLess(text.index(f"= {DIGEST} ] || exit 15"), text.index("W flush"))
        self.assertLess(text.index("mkdir -m 0700"), text.index("W flush"))
        script = inspection_native.state_script("shop")
        self.assertIn(script, text)

    def test_wordpress_runs_only_as_the_site_user_with_no_free_command(self) -> None:
        for operation in Operation:
            text = maintenance_native.body(row(operation), evidence())
            self.assertIn('s(){ runuser -u "$u" -- /usr/bin/env -i ', text)
            for forbidden in ("--allow-root", "--ssh", "set -x", "eval", "db query", "wp-cli.yml;"):
                self.assertNotIn(forbidden, text.replace('"$phar"', ""))
            self.assertEqual(text.count('"/usr/bin/php$php" "$phar"'), 1)

    def test_command_output_never_reaches_the_journal(self) -> None:
        text = maintenance_native.body(row(), evidence())
        self.assertIn('>"$o.out" 2>"$o.err" </dev/null', text)
        self.assertEqual(text.count('printf "%s\\n" "$r"'), 1)

    def test_a_failed_command_ends_the_unit_as_failed_after_publishing_its_record(self) -> None:
        text = maintenance_native.body(row(), evidence())
        self.assertLess(text.index('printf "%s\\n" "$r"'), text.index("exit 64"))

    def test_a_review_that_is_not_the_conventions_is_never_built(self) -> None:
        for changes in (
            {"site_user": "root"},
            {"url": "https://other.test"},
            {"identifier": "Shop"},
            {"php_version": "8;3"},
            {"tool_path": "/opt/wp-cli.phar"},
            {"operation": "plugin install"},
        ):
            with self.subTest(changes), self.assertRaises(ValueError):
                maintenance_native.body(row(**changes), evidence())
        with self.assertRaises(ValueError):
            maintenance_native.body(row(), inspection_native.Evidence("x", DIGEST, DIGEST))


class ProjectionTests(SimpleTestCase):
    def unavailable(self, operation: str, flush: tuple[int, str, str] | None, why: str) -> None:
        record = loaded(project(operation, flush))
        self.assertEqual((record["state"], record["why"]), ("unavailable", why), record)
        self.assertEqual(set(record), {"at", "op", "state", "v", "why"})

    def test_a_rewrite_flush_distinguishes_stored_rules_from_none(self) -> None:
        stored = loaded(project(Operation.REWRITE, REWRITE_OK))
        self.assertEqual((stored["state"], stored["done"], stored["rules"]), ("ok", True, "stored"))
        empty = loaded(project(Operation.REWRITE, REWRITE_EMPTY))
        self.assertEqual((empty["state"], empty["done"], empty["rules"]), ("ok", True, "empty"))

    def test_a_cache_flush_is_exactly_the_success_message(self) -> None:
        record = loaded(project(Operation.CACHE, CACHE_OK))
        self.assertEqual((record["state"], record["done"]), ("ok", True))
        self.assertNotIn("rules", record)

    def test_extra_or_mixed_output_is_unavailable_and_never_copied(self) -> None:
        noise = "debug: secret=hunter2"
        for operation, ok in ((Operation.REWRITE, REWRITE_OK), (Operation.CACHE, CACHE_OK)):
            for flush in (
                (0, ok[1] + noise + "\n", ok[2]),
                (0, noise + "\n" + ok[1], ok[2]),
                (0, ok[1], ok[2] + noise + "\n"),
                (0, "", ""),
                (0, "Success: something else\n", ""),
            ):
                with self.subTest(operation=operation, flush=flush):
                    self.unavailable(operation, flush, "output")
                    self.assertNotIn(noise, project(operation, flush))

    def test_the_sibling_form_is_not_accepted_for_the_other_action(self) -> None:
        self.unavailable(Operation.CACHE, REWRITE_OK, "output")
        self.unavailable(Operation.REWRITE, CACHE_OK, "output")

    def test_a_command_that_failed_or_ran_out_is_recorded_as_not_done(self) -> None:
        cases = {
            (1, "", "Error: The object cache could not be flushed.\n"): "error",
            (255, "", "PHP Fatal error: secret=hunter2\n"): "error",
            (124, "", ""): "timeout",
            (137, "", ""): "timeout",
            (153, "", ""): "overflow",
        }
        for flush, why in cases.items():
            with self.subTest(flush):
                line = project(Operation.CACHE, flush)
                record = loaded(line)
                self.assertEqual(
                    (record["state"], record["done"], record["why"]), ("failed", False, why)
                )
                self.assertNotIn("hunter2", line)

    def test_a_missing_status_is_skipped_and_non_ascii_output_is_unavailable(self) -> None:
        self.unavailable(Operation.CACHE, None, "skipped")
        self.unavailable(Operation.CACHE, (0, "Success: Thé cache was flushed.\n", ""), "output")
        self.unavailable(Operation.CACHE, (0, "x" * 262_145, ""), "overflow")


class RecordTests(SimpleTestCase):
    def parse(
        self, operation: str, flush: tuple[int, str, str] | None
    ) -> maintenance_native.Record:
        return maintenance_native.parse_record(
            project(operation, flush).removeprefix(MARKER), operation
        )

    def test_the_projections_own_records_are_valid(self) -> None:
        self.assertEqual(self.parse(Operation.REWRITE, REWRITE_OK).rules, "stored")
        self.assertEqual(self.parse(Operation.REWRITE, REWRITE_EMPTY).rules, "empty")
        self.assertEqual(self.parse(Operation.CACHE, CACHE_OK).state, "ok")
        self.assertEqual(self.parse(Operation.CACHE, (1, "", "Error: x\n")).state, "failed")
        self.assertEqual(self.parse(Operation.CACHE, None).state, "unavailable")

    def test_anything_outside_the_grammar_is_invalid(self) -> None:
        good = project(Operation.REWRITE, REWRITE_OK).removeprefix(MARKER)
        at = loaded(project(Operation.REWRITE, REWRITE_OK))["at"]

        def built(**fields: object) -> str:
            base = {"v": 1, "op": "rewrite", "at": at}
            return json.dumps({**base, **fields}, separators=(",", ":"), sort_keys=True)

        forged = (
            good.replace('"rules":"stored"', '"rules":"maybe"'),
            good.replace('"done":true', '"done":"yes"'),
            good.replace('"op":"rewrite"', '"op":"cache"'),
            good + " ",
            good.replace('"state":"ok"', '"state":"failed"'),
            built(state="ok", done=True),
            built(state="ok", done=True, rules="stored", x=1),
            built(state="failed", done=True, why="error"),
            built(state="unavailable", why="hunter2"),
        )
        for line in forged:
            with self.subTest(line), self.assertRaises(inspection_native.InvalidRecord):
                maintenance_native.parse_record(line, Operation.REWRITE)
        with self.assertRaises(inspection_native.InvalidRecord):
            maintenance_native.parse_record(good, "inspect")
