"""The shared-source manifest covers every resource embedded in a native command."""

import ast
import json
import os
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import override

from django.test import SimpleTestCase

from . import source_manifest

REPOSITORY = Path(__file__).resolve().parent.parent
EXCLUDED = frozenset({".venv", "node_modules", ".git", "migrations", "__pycache__"})


def _package_of(call: ast.Call) -> str | None:
    if (
        call.args
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
        and ast.unparse(call.func).endswith("importlib.resources.files")
    ):
        return call.args[0].value
    return None


def _sentinel_files() -> Iterator[Path]:
    for path in REPOSITORY.rglob("*.py"):
        if EXCLUDED & set(path.parts) or path.name.startswith("test_"):
            continue
        yield path


def _packages(tree: ast.AST) -> dict[str, str]:
    packages: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target, value = node.targets[0], node.value
        if not isinstance(target, ast.Name) or not isinstance(value, ast.Call):
            continue
        package = _package_of(value)
        if package:
            packages[target.id] = package
    return packages


def _joined(tree: ast.AST, packages: dict[str, str]) -> Iterator[str]:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "joinpath":
            continue
        if (
            not node.args
            or not isinstance(node.args[0], ast.Constant)
            or not isinstance(node.args[0].value, str)
        ):
            continue
        base = node.func.value
        package = _package_of(base) if isinstance(base, ast.Call) else None
        if package is None and isinstance(base, ast.Name):
            package = packages.get(base.id)
        if package:
            yield str(Path(package.replace(".", "/")) / node.args[0].value)


def embedded_sources() -> set[str]:
    """Every first-party file read through ``importlib.resources`` by non-test code."""
    found: set[str] = set()
    for path in _sentinel_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError, UnicodeDecodeError:
            continue
        packages = _packages(tree)
        for candidate in _joined(tree, packages):
            if Path(candidate).exists() and "fixtures" not in Path(candidate).parts:
                found.add(candidate)
    return found


class BaselineTests(SimpleTestCase):
    def baseline(self, recorded: dict[str, str], current: dict[str, str]) -> dict[str, object]:
        return source_manifest.baseline_document(
            recorded,
            current,
            current_inputs={"new.py": "input"},
            command_inputs={"a.py": "1"},
            capture_pins={"ubuntu": "pin"},
            capture_states={"state": "hash"},
        )

    def test_an_added_harness_source_refreshes_inputs_and_sources(self) -> None:
        document = self.baseline({"a.py": "1"}, {"a.py": "1", "b.py": "2"})
        self.assertEqual(document["sources"], {"a.py": "1", "b.py": "2"})
        self.assertEqual(document["capture_inputs"], {"new.py": "input"})
        self.assertEqual(document["capture_command_inputs"], {"a.py": "1"})
        self.assertNotIn("audit_digest", document)

    def test_a_changed_or_removed_shared_source_still_needs_the_recording_pass(self) -> None:
        with self.assertRaisesMessage(source_manifest.BaselineRefused, "text changed"):
            self.baseline({"a.py": "1"}, {"a.py": "2"})
        with self.assertRaisesMessage(source_manifest.BaselineRefused, "were removed"):
            self.baseline({"a.py": "1"}, {})

    def test_a_proven_command_neutral_edit_refreshes_without_a_capture_pass(self) -> None:
        document = source_manifest.baseline_document(
            {"a.py": "1"},
            {"a.py": "2"},
            current_inputs={"new.py": "input"},
            command_inputs={"a.py": "1"},
            capture_pins={"ubuntu": "pin"},
            capture_states={"state": "hash"},
            command_neutral=True,
        )
        self.assertEqual(document["sources"], {"a.py": "2"})

    def test_a_command_neutral_refresh_still_refuses_a_removed_shared_source(self) -> None:
        with self.assertRaisesMessage(source_manifest.BaselineRefused, "were removed"):
            source_manifest.baseline_document(
                {"a.py": "1"},
                {},
                current_inputs={"new.py": "input"},
                command_inputs={"a.py": "1"},
                capture_pins={"ubuntu": "pin"},
                capture_states={"state": "hash"},
                command_neutral=True,
            )

    def test_a_removed_mutation_source_refreshes_without_a_capture_pass(self) -> None:
        document = source_manifest.baseline_document(
            {"operations/recovery.py": "1", "a.py": "1"},
            {"a.py": "1"},
            current_inputs={"new.py": "input"},
            command_inputs={"a.py": "1"},
            capture_pins={"ubuntu": "pin"},
            capture_states={"state": "hash"},
        )
        self.assertEqual(document["sources"], {"a.py": "1"})
        self.assertEqual(document["capture_command_inputs"], {"a.py": "1"})


class ManifestMergeTests(SimpleTestCase):
    """Independent source edits merge without an aggregate digest line (spec #507, retro)."""

    @override
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())) / "repo"
        self.root.mkdir()
        environment = {
            key: value for key, value in os.environ.items() if not key.startswith("GIT_")
        }
        environment["GIT_CONFIG_NOSYSTEM"] = "1"
        environment["HOME"] = str(self.root.parent)
        self.environment = environment
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Manifest Test")
        self.git("config", "user.email", "manifest@example.invalid")
        self.write(self.manifest(first="1", last="1"))
        self.git("add", "manifest.json")
        self.git("commit", "-qm", "base")
        self.git("checkout", "-q", "-b", "left")

    def git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - the test owns the fixed argv
            ["git", *arguments],  # noqa: S607 - PATH resolution is the test's own git
            cwd=self.root,
            check=False,
            capture_output=True,
            text=True,
            env=self.environment,
        )

    def write(self, document: dict[str, object]) -> None:
        (self.root / "manifest.json").write_text(
            json.dumps(document, indent=2) + "\n", encoding="utf-8"
        )

    def commit(self, message: str) -> None:
        self.git("add", "manifest.json")
        self.git("commit", "-qm", message)

    def manifest(self, *, first: str, last: str) -> dict[str, object]:
        fillers = {f"m{index}.py": "1" for index in range(10)}
        return {
            "version": 1,
            "sources": {"a.py": first, **fillers, "z.py": last},
            "capture_inputs": {"a.py": "a", **fillers, "z.py": "z"},
            "capture_pins": {"base": "pin"},
            "capture_states": {"state": "hash"},
        }

    def test_independent_source_edits_merge_without_a_summary_conflict(self) -> None:
        self.write(self.manifest(first="left", last="1"))
        self.commit("left")

        self.git("checkout", "-q", "main")
        self.git("checkout", "-q", "-b", "right")
        self.write(self.manifest(first="1", last="right"))
        self.commit("right")

        self.git("checkout", "-q", "left")
        result = self.git("merge", "--no-edit", "right")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        merged = json.loads((self.root / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(merged["sources"]["a.py"], "left")
        self.assertEqual(merged["sources"]["z.py"], "right")
        self.assertNotIn("audit_digest", merged)

    def test_the_recorded_manifest_has_no_aggregate_digest(self) -> None:
        document = json.loads(source_manifest.MANIFEST.read_text(encoding="utf-8"))
        self.assertIn("capture_inputs", document)
        self.assertNotIn("audit_digest", document)


class SourceManifestTests(SimpleTestCase):
    def test_every_embedded_resource_is_a_shared_source(self) -> None:
        missing = sorted(embedded_sources() - set(source_manifest.SOURCES))
        self.assertEqual(
            missing,
            [],
            "embedded native resources are missing from discovery/source_manifest.py "
            "SOURCES; changing one would leave recorded transcripts silently current",
        )

    def test_the_journal_retention_body_and_change_module_are_shared_sources(self) -> None:
        for path in (
            "logs/bodies/journal_retention.py",
            "logs/journal_retention_change.py",
        ):
            with self.subTest(path=path):
                self.assertIn(path, source_manifest.SOURCES)

    def test_every_shared_source_exists(self) -> None:
        missing = [path for path in source_manifest.SOURCES if not (REPOSITORY / path).is_file()]
        self.assertEqual(missing, [])

    def test_every_command_source_is_a_shared_source(self) -> None:
        missing = sorted(
            path for path in source_manifest.COMMAND_SOURCES if path not in source_manifest.SOURCES
        )
        self.assertEqual(
            missing,
            [],
            "a module that builds transcript commands is missing from SOURCES; changing "
            "its command text would leave every replay silently current",
        )

    def test_a_mutation_source_is_not_a_recorded_command_source(self) -> None:
        for path in source_manifest.MUTATION_SOURCES:
            with self.subTest(path=path):
                self.assertTrue((REPOSITORY / path).is_file())
                self.assertNotIn(path, source_manifest.SOURCES)
