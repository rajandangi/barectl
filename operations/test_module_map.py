"""A diff that adds a module must name it in docs/architecture.md#module-map."""

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import override

from django.test import SimpleTestCase

CHECK = Path(__file__).resolve().parent.parent / "scripts" / "check_module_map.py"


def check_module_map() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_module_map", CHECK)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not load {CHECK}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ModuleMapTests(SimpleTestCase):
    @override
    def setUp(self) -> None:
        self.check = check_module_map()

    def test_an_added_module_must_be_named_in_its_app_row(self) -> None:
        problems = self.check.problems(
            ["logs/retention.py"],
            {"logs": "| `logs/` | `sources.py` |"},
            False,
        )

        self.assertEqual(len(problems), 1)
        self.assertIn("logs/retention.py", problems[0])
        self.assertIn("logs/", problems[0])

    def test_a_named_module_or_a_changed_map_passes(self) -> None:
        rows = {"logs": "| `logs/` | `retention.py` |"}
        self.assertEqual(self.check.problems(["logs/retention.py"], rows, False), [])
        self.assertEqual(
            self.check.problems(["logs/retention.py"], {"logs": "| `logs/` | |"}, True), []
        )

    def test_a_longer_module_that_ends_with_the_name_does_not_count(self) -> None:
        problems = self.check.problems(
            ["logs/change.py"],
            {"logs": "| `logs/` | `journal_retention_change.py` |"},
            False,
        )

        self.assertEqual(len(problems), 1)
        self.assertIn("change.py", problems[0])

    def test_a_module_in_a_nested_directory_is_checked_by_its_basename(self) -> None:
        problems = self.check.problems(
            ["logs/bodies/retention.py"],
            {"logs": "| `logs/` | `bodies/rotation.py` |"},
            False,
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("retention.py", problems[0])

    def test_generated_tests_and_non_app_directories_are_ignored(self) -> None:
        rows = {"logs": "| `logs/` | `sources.py` |"}
        added = [
            "logs/__init__.py",
            "logs/apps.py",
            "logs/conftest.py",
            "logs/test_retention.py",
            "logs/migrations/0002_retention.py",
            "logs/tests/helpers.py",
            "scripts/check_module_map.py",
            "config/urls.py",
        ]
        self.assertEqual(self.check.problems(added, rows, False), [])
