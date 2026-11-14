"""Two assertion shapes that can pass without proving the behavior they claim.

docs/quality.md#required-evidence. ``str()`` or ``repr()`` of a module-level collection
asserts a substring of the collection's display form instead of the value the product
rendered, and two identical adjacent ``assertEqual`` calls repeat one outcome.
"""

import ast
import os
from collections.abc import Iterator, Mapping
from pathlib import Path, PurePosixPath

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parent.parent
SKIPPED_DIRECTORIES = {
    ".agents",
    ".ai",
    ".claude",
    ".git",
    ".opencode",
    ".venv",
    "evals",
    "node_modules",
    "static",
}
COLLECTIONS = (ast.Tuple, ast.List, ast.Dict)
STRING_ASSERTIONS = {"assertIn", "assertNotIn"}
DISPLAY = {"str", "repr"}


def _module_constants(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, COLLECTIONS):
            names.update(target.id for target in node.targets if isinstance(target, ast.Name))
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.value, COLLECTIONS)
            and isinstance(node.target, ast.Name)
        ):
            names.add(node.target.id)
    return names


def _module_name(path: str) -> str:
    return PurePosixPath(path).with_suffix("").as_posix().replace("/", ".")


def _imported(module: str, tree: ast.Module) -> dict[str, str]:
    """Each ``from`` import's local name and the absolute path of the constant it names."""
    package = module.rsplit(".", 1)[0] if "." in module else ""
    imported: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level:
            base = package.split(".") if package else []
            base = base[: len(base) - (node.level - 1)] if node.level > 1 else base
            target = ".".join([*base, node.module]) if node.module else ".".join(base)
        else:
            target = node.module or ""
        for alias in node.names:
            qualified = f"{target}.{alias.name}" if target else alias.name
            imported[alias.asname or alias.name] = qualified
    return imported


def _string_assertions(tree: ast.Module) -> Iterator[tuple[int, str, str]]:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if not isinstance(function, ast.Attribute) or function.attr not in STRING_ASSERTIONS:
            continue
        if len(node.args) < 2:
            continue
        wrapped = node.args[1]
        if not isinstance(wrapped, ast.Call) or len(wrapped.args) != 1:
            continue
        display = wrapped.func
        if not isinstance(display, ast.Name) or display.id not in DISPLAY:
            continue
        argument = wrapped.args[0]
        if isinstance(argument, ast.Name):
            yield node.lineno, argument.id, display.id


def _assert_equal(statement: ast.stmt) -> str | None:
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return None
    function = statement.value.func
    if not isinstance(function, ast.Attribute) or function.attr != "assertEqual":
        return None
    return ast.dump(statement.value)


def _duplicates(path: str, tree: ast.Module) -> list[str]:
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not node.name.startswith("test_"):
            continue
        previous: str | None = None
        for statement in node.body:
            current = _assert_equal(statement)
            if current is not None and current == previous:
                found.append(
                    f"{path}:{statement.lineno}: duplicate assertEqual repeats the previous "
                    "assertion"
                )
            previous = current
    return found


def problems(sources: Mapping[str, str], modules: Mapping[str, str] | None = None) -> list[str]:
    """Every flagged assertion shape in the ``test_*.py`` sources."""
    known = modules if modules is not None else sources
    found: list[str] = []

    def is_constant(qualified: str) -> bool:
        module, _, name = qualified.rpartition(".")
        source = known.get(module.replace(".", "/") + ".py")
        return source is not None and name in _module_constants(ast.parse(source))

    for path, source in sources.items():
        if not PurePosixPath(path).name.startswith("test_"):
            continue
        tree = ast.parse(source)
        local = _module_constants(tree)
        imported = _imported(_module_name(path), tree)
        for line, name, display in _string_assertions(tree):
            qualified = imported.get(name)
            if name in local or (qualified is not None and is_constant(qualified)):
                found.append(
                    f"{path}:{line}: {display}({name}) asserts a display string, not the "
                    "rendered value; assert the real value"
                )
        found.extend(_duplicates(path, tree))
    return found


def repository_sources() -> dict[str, str]:
    sources: dict[str, str] = {}
    for directory, directories, files in os.walk(ROOT):
        directories[:] = [name for name in directories if name not in SKIPPED_DIRECTORIES]
        for name in files:
            if name.endswith(".py"):
                path = Path(directory, name)
                sources[path.relative_to(ROOT).as_posix()] = path.read_text(encoding="utf-8")
    return sources


class TestAssertionShapeTests(SimpleTestCase):
    def test_a_display_of_a_module_constant_and_a_duplicate_are_flagged(self) -> None:
        source = """\
REASONS = ("one", "two")


class Sample:
    def test_it(self):
        self.assertIn("one", str(REASONS))
        self.assertIn("two", repr(REASONS))
        self.assertIn("legitimate", str(self.document["note"]))
        self.assertEqual(len(REASONS), 2)
        self.assertEqual(len(REASONS), 2)
"""
        found = problems({"test_sample.py": source})
        self.assertEqual(len(found), 3, found)
        joined = "\n".join(found)
        self.assertIn("test_sample.py:6:", joined)
        self.assertIn("test_sample.py:7:", joined)
        self.assertIn("test_sample.py:10:", joined)

    def test_an_imported_collection_constant_is_flagged(self) -> None:
        modules = {
            "pkg/reasons.py": 'REASONS = ("one", "two")\n',
            "pkg/test_sample.py": (
                "from .reasons import REASONS\n\n\n"
                "class Sample:\n"
                "    def test_it(self):\n"
                '        self.assertIn("one", str(REASONS))\n'
            ),
        }
        found = problems(modules)
        self.assertEqual(len(found), 1, found)
        self.assertIn("pkg/test_sample.py:6", found[0])

    def test_a_string_constant_is_not_a_collection(self) -> None:
        source = 'NOTE = "the rendered note"\n\n\ndef test_it():\n    assert NOTE\n'
        self.assertEqual(problems({"test_sample.py": source}), [])

    def test_the_real_tree_has_no_flagged_assertions(self) -> None:
        self.assertEqual(problems(repository_sources()), [])
