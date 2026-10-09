"""The WordPress inspection's native body, projection and record grammar
(docs/wordpress.md#inspecting-wordpress).

Pure tests. The projection runs as the production script does, over fixed command outputs.
``wordpress/test_inspection_remote.py`` establishes the native behaviour on both releases.
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from . import execution, inspection_fakes, inspection_native
from .inspection_fakes import (
    CORE_OK,
    PLUGIN_OK,
    PLUGIN_SKIPPED,
    core_outputs,
    inventory_outputs,
    plugin_outputs,
    project,
)
from .inspection_models import Operation, PlanWordpressInspection

SHELL = shutil.which("dash") or shutil.which("sh") or "sh"
UNIT = f"barectl-apply-{'a' * 32}.service"
BOOT = "6f1c4e1a-3a8e-4b5f-9d2e-7c0b8a9d1e23"
DIGEST = "e" * 64
MARKER = f"{execution.RECORD_MARKER} "


def row(operation: str = Operation.INSPECT, **changes: object) -> PlanWordpressInspection:
    base = PlanWordpressInspection(
        identifier="shop",
        php_version="8.3",
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
        targets="plugin akismet\nplugin jetpack\nmu-plugin loader.php\ntheme twentytwentysix",
        max_file_bytes=inspection_native.MAX_FILE_BYTES,
        memory_max_bytes=inspection_native.MEMORY_MAX_BYTES,
        runtime_limit_seconds=inspection_native.RUNTIME_LIMIT_SECONDS,
        command_seconds=inspection_native.COMMAND_SECONDS,
        budget_seconds=inspection_native.BUDGET_SECONDS,
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
    def test_every_operations_body_and_payload_are_valid_shell(self) -> None:
        for operation in Operation:
            with self.subTest(operation):
                review = row(operation)
                body = inspection_native.body(review, evidence())
                payload = inspection_native.staged(UNIT, BOOT, 123456, review, evidence())[0]
                for name, text in (("body", body), ("payload", payload)):
                    result = syntax(text)
                    self.assertEqual(result.returncode, 0, f"{name}: {result.stderr}")
                self.assertLess(len(payload.encode()), 16 * 1024)

    def test_the_steps_are_named_in_order(self) -> None:
        names = [step.name for step in inspection_native.body_steps(row(), evidence())]
        self.assertEqual(
            names, ["helpers", "tools", "revalidation", "stage", "run", "project", "finish"]
        )

    def test_the_body_revalidates_before_any_application_command_runs(self) -> None:
        text = inspection_native.body(row(), evidence())
        self.assertLess(text.index(f"= {DIGEST} ] || exit 15"), text.index("W installed"))
        self.assertLess(text.index("mkdir -m 0700"), text.index("W installed"))
        for kind in ("site_digest", "dropin", "mufile", "wp-cli.yml"):
            self.assertIn(kind if kind != "site_digest" else "/etc/nginx", text)

    def test_wordpress_runs_only_as_the_site_user(self) -> None:
        text = inspection_native.body(row(), evidence())
        self.assertIn('s(){ runuser -u "$u" -- /usr/bin/env -i ', text)
        self.assertNotIn("--allow-root", text)
        self.assertNotIn("--ssh", text)
        self.assertNotIn("--http", text)
        self.assertNotIn("set -x", text)
        self.assertEqual(text.count('"/usr/bin/php$php" "$phar"'), 1)
        self.assertIn("--skip-packages --skip-plugins --skip-themes", text)
        for command in inspection_native.COMMANDS[Operation.INSPECT]:
            self.assertIn(command, text)

    def test_command_output_never_reaches_the_journal(self) -> None:
        text = inspection_native.body(row(), evidence())
        self.assertIn('>"$o.out" 2>"$o.err" </dev/null', text)
        # The only printing step is the validated record.
        self.assertEqual(text.count('printf "%s\\n" "$r"'), 1)

    def test_a_review_that_is_not_the_conventions_is_never_built(self) -> None:
        for changes in (
            {"site_user": "root"},
            {"url": "https://other.test"},
            {"identifier": "Shop"},
            {"php_version": "8;3"},
            {"tool_path": "/opt/wp-cli.phar"},
        ):
            with self.subTest(changes), self.assertRaises(ValueError):
                inspection_native.body(row(**changes), evidence())
        with self.assertRaises(ValueError):
            inspection_native.body(row(), inspection_native.Evidence("x", DIGEST, DIGEST))
        with self.assertRaises(ValueError):
            inspection_native.body(
                row(Operation.PLUGINS, targets="mu-plugin loader.php"), evidence()
            )
        with self.assertRaises(ValueError):
            inspection_native.body(row(Operation.PLUGINS, targets="plugin x; rm -rf /"), evidence())

    def test_the_state_read_is_the_one_the_run_rechecks(self) -> None:
        script = inspection_native.state_script("shop")
        self.assertIn("-printf 'entry '", script)
        self.assertEqual(syntax(script).returncode, 0)
        self.assertIn(script, inspection_native.body(row(), evidence()))

    def test_the_state_read_parses_and_names_the_extensions(self) -> None:
        server = inspection_fakes.InspectionServer(
            plugins={"akismet": "d", "hello.php": "f", "index.php": "f", "Odd Name": "d"},
            dropins={"object-cache.php": "a" * 64},
        )
        state = inspection_native.parse_state(server.state())
        found = inspection_native.inventory(state)
        self.assertEqual(found.slugs, ["akismet"])
        self.assertEqual(found.plugins, ["Odd Name", "akismet", "hello.php"])
        self.assertEqual(found.dropins, ["object-cache.php"])
        self.assertEqual(found.mu_plugins, ["loader.php"])
        self.assertEqual(
            found.targets().splitlines()[:3],
            ["plugin akismet", "mu-plugin loader.php", "dropin object-cache.php"],
        )
        for text in ("nonsense\n", server.state() + "entry plugins d x\n", "end plugins\n"):
            with self.subTest(text[:20]), self.assertRaises(inspection_native.Unreadable):
                inspection_native.parse_state(text)


class InventoryProjectionTests(SimpleTestCase):
    def test_a_healthy_inventory_is_projected_and_valid(self) -> None:
        line = project(
            Operation.INSPECT,
            inventory_outputs(
                plugins='[{"name":"akismet","status":"active","version":"5.7.2"},'
                '{"name":"loader","status":"must-use","version":""},'
                '{"name":"object-cache.php","status":"dropin","version":""}]'
            ),
        )
        record = inspection_native.parse_record(line.removeprefix(MARKER), Operation.INSPECT)
        self.assertEqual(
            (record.state, record.core_installed, record.core_version), ("ok", True, "7.1.3")
        )
        self.assertEqual(
            [(item.kind, item.name, item.status) for item in record.items],
            [
                ("plugin", "akismet", "active"),
                ("mu-plugin", "loader", "must-use"),
                ("dropin", "object-cache.php", "dropin"),
                ("theme", "twentytwentysix", "active"),
            ],
        )

    def test_an_uninstalled_application_reports_no_items(self) -> None:
        outputs = inventory_outputs(installed=1)
        record = inspection_native.parse_record(
            project(Operation.INSPECT, outputs).removeprefix(MARKER), Operation.INSPECT
        )
        self.assertEqual((record.core_installed, record.items), (False, ()))

    def unavailable(self, outputs: dict[str, inspection_fakes.Output], why: str) -> None:
        record = loaded(project(Operation.INSPECT, outputs))
        self.assertEqual((record["state"], record["why"]), ("unavailable", why), record)
        self.assertEqual(set(record), {"at", "op", "state", "v", "why"})

    def test_raw_debug_text_and_mixed_output_make_the_result_unavailable(self) -> None:
        noise = "debug: secret=hunter2"
        for name in ("installed", "version", "plugins", "themes"):
            for stream in (1, 2):
                with self.subTest(name, stream=stream):
                    outputs = inventory_outputs()
                    status, out, err = outputs[name]
                    outputs[name] = (
                        status,
                        out + (noise if stream == 1 else ""),
                        err + (noise if stream == 2 else ""),
                    )
                    self.unavailable(outputs, "output")
                    self.assertNotIn(noise, project(Operation.INSPECT, outputs))
        mixed = inventory_outputs(plugins=f"{noise}\n" + inventory_outputs()["plugins"][1])
        self.unavailable(mixed, "output")

    def test_malformed_extra_and_unexpected_json_is_unavailable(self) -> None:
        for plugins in (
            "not json",
            "{}",
            '[{"name":"a","status":"active"}]',
            '[{"name":"a","status":"active","version":"1","extra":"x"}]',
            '[{"name":"a","status":"hacked","version":"1"}]',
            '[{"name":"a b","status":"active","version":"1"}]',
            '[{"name":"a","status":"active","version":"1;rm"}]',
            '[{"name":"a","name":"b","status":"active","version":"1"}]',
            '[{"name":1,"status":"active","version":"1"}]',
            '[{"name":"a","status":"active","version":"1"}] trailing',
        ):
            with self.subTest(plugins):
                self.unavailable(inventory_outputs(plugins=plugins), "output")

    def test_a_failed_a_timed_out_and_a_capped_command_are_named(self) -> None:
        for status, why in ((2, "failed"), (124, "timeout"), (137, "timeout"), (153, "overflow")):
            with self.subTest(status):
                outputs = inventory_outputs()
                outputs["plugins"] = (status, "", "")
                self.unavailable(outputs, why)
        outputs = inventory_outputs()
        outputs["themes"] = (0, "x" * 262_145, "")
        self.unavailable(outputs, "overflow")

    def test_more_than_128_items_are_unavailable_not_truncated(self) -> None:
        many = ",".join(
            f'{{"name":"p{index}","status":"inactive","version":"1"}}' for index in range(129)
        )
        self.unavailable(inventory_outputs(plugins=f"[{many}]"), "overflow")
        within = ",".join(
            f'{{"name":"p{index}","status":"inactive","version":"1"}}' for index in range(127)
        )
        record = loaded(project(Operation.INSPECT, inventory_outputs(plugins=f"[{within}]")))
        self.assertEqual(record["state"], "ok")
        self.assertEqual(len(record["items"]), 128)  # type: ignore[arg-type]

    def test_a_record_over_16_kib_is_unavailable(self) -> None:
        names = ",".join(
            f'{{"name":"{"n" * 90}{index:03d}","status":"active-network","version":"{"9" * 40}"}}'
            for index in range(128)
        )
        line = project(Operation.INSPECT, inventory_outputs(plugins=f"[{names}]", themes="[]"))
        self.assertLessEqual(len(line), execution.MAX_RECORD)
        self.assertEqual(loaded(line)["why"], "overflow")

    def test_a_missing_file_is_skipped_and_a_non_ascii_one_is_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run = subprocess.run(  # noqa: S603 - the production projection on an empty directory
                [sys.executable, "-I", "-c", inspection_native.PROJECTION, directory, "inspect"],
                capture_output=True,
                text=True,
                check=True,
            )
        self.assertEqual(loaded(run.stdout.strip())["why"], "skipped")
        outputs = inventory_outputs(plugins='[{"name":"café","status":"active","version":"1"}]')
        self.unavailable(outputs, "output")


class CoreProjectionTests(SimpleTestCase):
    def verdict(self, status: int, out: str, err: str) -> dict[str, object]:
        record = loaded(project(Operation.CORE, core_outputs(status, out, err), "7.1.3"))
        self.assertEqual(record["state"], "ok", record)
        integrity = record["integrity"]
        if not isinstance(integrity, dict):
            raise AssertionError(integrity)
        return integrity

    def test_a_match_is_exactly_the_success_message_and_nothing_else(self) -> None:
        self.assertEqual(self.verdict(0, *CORE_OK)["state"], "match")
        for out, err in (
            (CORE_OK[0] + "extra\n", ""),
            (CORE_OK[0], "Notice: something\n"),
            ("", ""),
            ("Success: other\n", ""),
        ):
            with self.subTest(out=out, err=err):
                self.assertEqual(self.verdict(0, out, err)["state"], "unavailable")

    def test_modified_missing_and_extra_files_are_a_mismatch(self) -> None:
        err = (
            "Warning: File doesn't exist: readme.html\n"
            "Warning: File doesn't verify against checksum: wp-includes/load.php\n"
            "Warning: File should not exist: wp-admin/evil.php\n"
            "Error: WordPress installation doesn't verify against checksums.\n"
        )
        verdict = self.verdict(1, "", err)
        self.assertEqual(
            (verdict["state"], verdict["modified"], verdict["missing"], verdict["extra"]),
            ("mismatch", 1, 1, 1),
        )
        record = loaded(project(Operation.CORE, core_outputs(1, "", err), "7.1.3"))
        self.assertEqual(
            record["files"],
            [
                {"k": "missing", "p": "readme.html"},
                {"k": "modified", "p": "wp-includes/load.php"},
                {"k": "extra", "p": "wp-admin/evil.php"},
            ],
        )

    def test_extra_files_alone_are_a_mismatch_and_the_list_is_capped(self) -> None:
        err = "".join(
            f"Warning: File should not exist: wp-admin/e{index}.php\n" for index in range(30)
        )
        verdict = self.verdict(0, CORE_OK[0], err)
        self.assertEqual((verdict["state"], verdict["extra"]), ("mismatch", 30))
        record = loaded(project(Operation.CORE, core_outputs(0, CORE_OK[0], err), "7.1.3"))
        self.assertEqual(len(record["files"]), 20)  # type: ignore[arg-type]

    def test_an_unavailable_catalog_is_neither_a_pass_nor_a_mismatch(self) -> None:
        err = "Error: RuntimeException: Failed to get url 'https://api.wordpress.org/x'\n"
        verdict = self.verdict(1, "", err)
        self.assertEqual((verdict["state"], verdict["why"]), ("unavailable", "catalog"))
        self.assertEqual((verdict["modified"], verdict["missing"], verdict["extra"]), (0, 0, 0))

    def test_noise_around_a_mismatch_is_unavailable_not_corruption(self) -> None:
        err = (
            "PHP Deprecated: noise\n"
            "Warning: File doesn't verify against checksum: wp-includes/load.php\n"
            "Error: WordPress installation doesn't verify against checksums.\n"
        )
        self.assertEqual(self.verdict(1, "", err)["state"], "unavailable")
        forged = "Warning: File doesn't verify against checksum: ../../etc/passwd;rm\n"
        self.assertEqual(self.verdict(1, "", forged)["state"], "unavailable")

    def test_a_timeout_or_failure_is_unavailable_with_its_reason(self) -> None:
        for status, why in ((124, "timeout"), (153, "overflow")):
            with self.subTest(status):
                self.assertEqual(self.verdict(status, "", "")["why"], why)


class PluginProjectionTests(SimpleTestCase):
    def verdicts(self, **results: inspection_fakes.Output) -> dict[str, dict[str, object]]:
        record = loaded(project(Operation.PLUGINS, plugin_outputs(**results), *results))
        self.assertEqual(record["state"], "ok", record)
        items = record["items"]
        if not isinstance(items, list):
            raise AssertionError(items)
        return {item["n"]: item for item in items}

    def test_match_mismatch_and_unavailable_are_separate(self) -> None:
        found = self.verdicts(
            akismet=(0, PLUGIN_OK, ""),
            jetpack=(
                1,
                (
                    '[{"plugin_name":"jetpack","file":"a.php","message":"Checksum does not match"},'
                    '{"plugin_name":"jetpack","file":"b.php","message":"File was added"},'
                    '{"plugin_name":"jetpack","file":"c.php","message":"File was added"}]'
                ),
                "Error: No plugins verified (1 failed).\n",
            ),
            custom=(
                0,
                PLUGIN_SKIPPED,
                (
                    "Warning: Couldn't fetch response from https://downloads.wordpress.org/"
                    "plugin-checksums/custom/1.0.json (HTTP code 404).\n"
                    "Warning: Could not retrieve the checksums for version 1.0 of plugin "
                    "custom, skipping.\n"
                ),
            ),
        )
        self.assertEqual(found["akismet"]["c"], "match")
        self.assertEqual(
            (found["jetpack"]["c"], found["jetpack"]["m"], found["jetpack"]["a"]),
            ("mismatch", 1, 2),
        )
        self.assertEqual((found["custom"]["c"], found["custom"]["w"]), ("unavailable", "catalog"))

    def test_anything_else_is_unavailable_never_a_pass(self) -> None:
        for out, err in (
            (PLUGIN_OK, "Warning: noise\n"),
            (PLUGIN_SKIPPED, ""),
            (PLUGIN_SKIPPED, "Warning: something else\n"),
            ("[]", "Error: No plugins verified (1 failed).\n"),
            (
                '[{"plugin_name":"other","file":"a.php","message":"Checksum does not match"}]',
                "Error: No plugins verified (1 failed).\n",
            ),
            (
                '[{"plugin_name":"akismet","file":"a.php","message":"File is missing"}]',
                "Error: No plugins verified (1 failed).\n",
            ),
            ("garbage", "Error: No plugins verified (1 failed).\n"),
        ):
            with self.subTest(out=out, err=err):
                status = 1 if "Error" in err else 0
                item = self.verdicts(akismet=(status, out, err))["akismet"]
                self.assertEqual(item["c"], "unavailable")
                self.assertEqual((item["m"], item["a"]), (0, 0))

    def test_a_skipped_slug_is_named_when_the_time_budget_ended_the_loop(self) -> None:
        record = loaded(
            project(
                Operation.PLUGINS, plugin_outputs(akismet=(0, PLUGIN_OK, "")), "akismet", "later"
            )
        )
        items = record["items"]
        if not isinstance(items, list):
            raise AssertionError(items)
        self.assertEqual((items[1]["n"], items[1]["w"]), ("later", "skipped"))

    def test_slugs_that_are_not_repository_slugs_are_refused(self) -> None:
        record = loaded(project(Operation.PLUGINS, {}, "Bad_Slug"))
        self.assertEqual((record["state"], record["why"]), ("unavailable", "output"))


class RecordGrammarTests(SimpleTestCase):
    def accepted(self, operation: str, line: str) -> inspection_native.Record:
        return inspection_native.parse_record(line, operation)

    def rejected(self, operation: str, line: str) -> None:
        with self.assertRaises(inspection_native.InvalidRecord):
            inspection_native.parse_record(line, operation)

    def test_the_projection_output_is_always_accepted(self) -> None:
        for operation in Operation:
            line = inspection_fakes.default_record(operation).removeprefix(MARKER)
            self.assertEqual(self.accepted(operation, line).state, "ok")

    def test_anything_outside_the_grammar_is_rejected(self) -> None:
        good = inspection_fakes.default_record(Operation.INSPECT).removeprefix(MARKER)
        data = json.loads(good)
        cases = [
            "",
            "not json",
            "[]",
            good + " ",
            good.replace('"v":1', '"v":2'),
            good.replace('"op":"inspect"', '"op":"core"'),
            good.replace('"state":"ok"', '"state":"fine"'),
            good.replace('"installed":true', '"installed":"yes"'),
            good[:-1] + ',"extra":1}',
            json.dumps({**data, "at": 1}),
            json.dumps({**data, "at": True}),
            json.dumps({**data, "items": [{"k": "plugin", "n": "a", "s": "active"}]}),
            json.dumps({**data, "items": [{"k": "x", "n": "a", "s": "active", "v": "1"}]}),
            json.dumps({**data, "items": [{"k": "theme", "n": "a", "s": "must-use", "v": "1"}]}),
            json.dumps({**data, "items": [{"k": "plugin", "n": "a;b", "s": "active", "v": "1"}]}),
            json.dumps(
                {**data, "items": [{"k": "plugin", "n": "a", "s": "active", "v": "1"}] * 129}
            ),
            json.dumps(
                {
                    "v": 1,
                    "op": "inspect",
                    "at": data["at"],
                    "state": "unavailable",
                    "why": "secrets",
                }
            ),
            json.dumps(
                {"v": 1, "op": "inspect", "at": data["at"], "state": "unavailable", "why": ""}
            ),
            '{"v":1,"v":1}',
            good.replace('"at":', '"at":9e9,"x":'),
            "x" * (execution.MAX_RECORD + 1),
            good.replace("5.7.2", "5.7.é"),
        ]
        for line in cases:
            with self.subTest(line[:300]):
                self.rejected(Operation.INSPECT, line)

    def test_core_and_plugin_records_reject_inconsistent_counts_and_states(self) -> None:
        core = json.loads(inspection_fakes.default_record(Operation.CORE).removeprefix(MARKER))
        for integrity in (
            {"state": "match", "why": "", "modified": 1, "missing": 0, "extra": 0},
            {"state": "mismatch", "why": "", "modified": 0, "missing": 0, "extra": 0},
            {"state": "unavailable", "why": "", "modified": 0, "missing": 0, "extra": 0},
            {"state": "match", "why": "catalog", "modified": 0, "missing": 0, "extra": 0},
            {"state": "maybe", "why": "", "modified": 0, "missing": 0, "extra": 0},
            {"state": "match", "why": "", "modified": -1, "missing": 0, "extra": 0},
        ):
            with self.subTest(integrity):
                self.rejected(Operation.CORE, json.dumps({**core, "integrity": integrity}))
        self.rejected(Operation.CORE, json.dumps({**core, "files": [{"k": "modified", "p": "x"}]}))
        plugins = json.loads(
            inspection_fakes.default_record(Operation.PLUGINS).removeprefix(MARKER)
        )
        for item in (
            {"k": "plugin", "n": "a", "c": "match", "w": "", "m": 1, "a": 0},
            {"k": "plugin", "n": "A", "c": "match", "w": "", "m": 0, "a": 0},
            {"k": "plugin", "n": "a", "c": "unavailable", "w": "", "m": 0, "a": 0},
            {"k": "theme", "n": "a", "c": "match", "w": "", "m": 0, "a": 0},
        ):
            with self.subTest(item):
                self.rejected(Operation.PLUGINS, json.dumps({**plugins, "items": [item]}))
        self.rejected(Operation.PLUGINS, json.dumps({**plugins, "items": []}))


class RetrievalTests(SimpleTestCase):
    INVOCATION = "1" * 32

    def entry(self, **changes: object) -> str:
        message = (
            f"{MARKER}{inspection_fakes.default_record(Operation.INSPECT).removeprefix(MARKER)}"
        )
        return json.dumps(
            {
                "MESSAGE": message,
                "_SYSTEMD_UNIT": UNIT,
                "_SYSTEMD_INVOCATION_ID": self.INVOCATION,
                "_TRANSPORT": "stdout",
                **changes,
            }
        )

    def read(self, *lines: str, header: str = "residue absent\njournal ok") -> execution.Retrieved:
        text = "\n".join([header, *lines]) + "\n"
        return execution.parse_retrieval(text, unit=UNIT, invocation=self.INVOCATION)

    def test_exactly_one_matching_entry_supplies_the_record(self) -> None:
        found = self.read(self.entry())
        self.assertIsNotNone(found.record)
        self.assertFalse(found.residue)
        self.assertTrue(self.read(self.entry(), header="residue present\njournal ok").residue)

    def test_other_units_invocations_transports_and_messages_are_not_ours(self) -> None:
        for change in (
            {"_SYSTEMD_UNIT": f"barectl-apply-{'b' * 32}.service"},
            {"_SYSTEMD_INVOCATION_ID": "2" * 32},
            {"_TRANSPORT": "syslog"},
            {"MESSAGE": "some other line"},
            {"MESSAGE": [1, 2, 3]},
            {"MESSAGE": None},
        ):
            with self.subTest(change):
                found = self.read(self.entry(**change))
                self.assertEqual((found.record, found.why), (None, "journal_missing"))

    def test_absence_surplus_and_unreadable_journals_are_unavailable(self) -> None:
        self.assertEqual(self.read().why, "journal_missing")
        self.assertEqual(self.read("not json", "[]", "{").why, "journal_missing")
        self.assertEqual(self.read(self.entry(), self.entry()).why, "extra")
        self.assertEqual(
            self.read(header="residue absent\njournal error").why, "journal_unreadable"
        )

    def test_a_read_that_is_not_in_its_form_is_unreadable(self) -> None:
        for text in (
            "",
            "residue maybe\njournal ok\n",
            "residue absent\njournal ok?\n",
            "journal ok\n",
        ):
            with self.subTest(text), self.assertRaises(execution.Unreadable):
                execution.parse_retrieval(text, unit=UNIT, invocation=self.INVOCATION)

    def test_the_retrieval_command_names_the_unit_and_takes_the_invocation_as_data(self) -> None:
        argv = execution.retrieval_argv(UNIT, "shop")
        script = argv[2]
        self.assertIn(f"_SYSTEMD_UNIT={UNIT}", script)
        self.assertNotIn(self.INVOCATION, script)
        self.assertIn('_SYSTEMD_INVOCATION_ID="$i"', script)
        self.assertIn("_TRANSPORT=stdout", script)
        self.assertIn("--all", script)
        self.assertEqual(syntax(script).returncode, 0)
        self.assertEqual(
            execution.retrieval_command(argv, self.INVOCATION, root=False).split(" | ")[0],
            f"printf '%s\\n' {self.INVOCATION}",
        )
        with self.assertRaises(ValueError):
            execution.retrieval_command(argv, "1; rm", root=True)
        with self.assertRaises(ValueError):
            execution.retrieval_argv("barectl-apply-x.service", "shop")
