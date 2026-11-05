"""The shared-source manifest covers every resource embedded in a native command."""

import ast
from collections.abc import Iterator
from pathlib import Path

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
            audit_digest="a" * 64,
        )

    def test_an_added_harness_source_refreshes_inputs_and_sources(self) -> None:
        document = self.baseline({"a.py": "1"}, {"a.py": "1", "b.py": "2"})
        self.assertEqual(document["sources"], {"a.py": "1", "b.py": "2"})
        self.assertEqual(document["capture_inputs"], {"new.py": "input"})
        self.assertEqual(document["capture_command_inputs"], {"a.py": "1"})
        self.assertEqual(document["audit_digest"], "a" * 64)

    def test_a_changed_or_removed_shared_source_still_needs_the_recording_pass(self) -> None:
        with self.assertRaisesMessage(source_manifest.BaselineRefused, "text changed"):
            self.baseline({"a.py": "1"}, {"a.py": "2"})
        with self.assertRaisesMessage(source_manifest.BaselineRefused, "were removed"):
            self.baseline({"a.py": "1"}, {})

    def test_a_removed_mutation_source_refreshes_without_a_capture_pass(self) -> None:
        document = source_manifest.baseline_document(
            {"operations/recovery.py": "1", "a.py": "1"},
            {"a.py": "1"},
            current_inputs={"new.py": "input"},
            command_inputs={"a.py": "1"},
            capture_pins={"ubuntu": "pin"},
            capture_states={"state": "hash"},
            audit_digest="a" * 64,
        )
        self.assertEqual(document["sources"], {"a.py": "1"})
        self.assertEqual(document["capture_command_inputs"], {"a.py": "1"})


class SourceManifestTests(SimpleTestCase):
    def test_every_embedded_resource_is_a_shared_source(self) -> None:
        missing = sorted(embedded_sources() - set(source_manifest.SOURCES))
        self.assertEqual(
            missing,
            [],
            "embedded native resources are missing from discovery/source_manifest.py "
            "SOURCES; changing one would leave recorded transcripts silently current",
        )

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
