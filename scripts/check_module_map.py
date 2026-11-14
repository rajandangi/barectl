# ruff: noqa: INP001
"""Fail when a diff adds a first-party module its architecture row does not name.

docs/architecture.md#module-map is the map an agent reads before changing an area. A new
module that the map omits sends the next reader to the wrong document, so this check reads
the added files from a base ref and compares them with the map's app rows.
"""

import argparse
import re
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath

REPOSITORY = Path(__file__).resolve().parent.parent
ARCHITECTURE = REPOSITORY / "docs" / "architecture.md"
SKIPPED_NAMES = {"__init__.py", "apps.py", "conftest.py"}
SKIPPED_DIRECTORIES = {"migrations", "tests"}
APP_PATH = re.compile(r"`([A-Za-z0-9_.-]+)/`")


def rows(markdown: str) -> dict[str, str]:
    """The map's app rows, keyed by the top-level directory each row names."""
    found: dict[str, str] = {}
    for line in markdown.splitlines():
        if not line.startswith("|"):
            continue
        cells = line.split("|")
        if len(cells) < 3:
            continue
        for match in APP_PATH.finditer(cells[1]):
            found[match.group(1)] = line
    return found


def _names(row: str, name: str) -> bool:
    """Whether the row names the module, not a longer module that ends with its name."""
    return re.search(rf"(?<![\w]){re.escape(name)}(?![\w])", row) is not None


def problems(added: Sequence[str], rows: Mapping[str, str], docs_changed: bool) -> list[str]:
    """Every added module whose app row does not name it, unless the map changed too."""
    if docs_changed:
        return []
    found: list[str] = []
    for path in added:
        parts = PurePosixPath(path).parts
        if not parts or len(parts) < 2:
            continue
        name = parts[-1]
        if name in SKIPPED_NAMES or name.startswith("test_"):
            continue
        if any(part in SKIPPED_DIRECTORIES for part in parts[:-1]):
            continue
        row = rows.get(parts[0])
        if row is None or _names(row, name):
            continue
        found.append(
            f"{path}: the added module {name} is not named in the {parts[0]}/ row of "
            "docs/architecture.md"
        )
    return found


def _git(*arguments: str) -> list[str]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is not installed")
    completed = subprocess.run(  # noqa: S603 - refs are arguments, never shell input.
        [git, *arguments],
        cwd=REPOSITORY,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.splitlines()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="origin/main", help="the base ref (default: origin/main)")
    parser.add_argument("--head", default="HEAD", help="the head ref (default: HEAD)")
    arguments = parser.parse_args(argv)
    base: str = arguments.base
    head: str = arguments.head
    try:
        added = _git("diff", "--name-only", "--diff-filter=A", f"{base}...{head}", "--", "*.py")
        changed = _git("diff", "--name-only", f"{base}...{head}", "--", "docs/architecture.md")
    except subprocess.CalledProcessError as error:
        sys.stderr.write(
            f"check_module_map: git diff {base}...{head} failed; fetch the base ref. {error.stderr}"
        )
        return 2
    found = problems(added, rows(ARCHITECTURE.read_text(encoding="utf-8")), bool(changed))
    if found:
        sys.stderr.write("\n".join(found) + "\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
