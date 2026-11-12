"""Prepare native agent layouts from the repository's shared AI sources."""

import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path

PROVIDERS = ("codex", "claude", "opencode")
DIRECTORIES = {"codex": ".codex", "claude": ".claude", "opencode": ".opencode"}


@dataclass(frozen=True)
class Link:
    destination: Path
    source: Path


def links(root: Path, providers: list[str]) -> list[Link]:
    sources = root / ".ai"
    planned = [Link(root / "evals", sources / "evals")]
    for provider in providers:
        directory = root / DIRECTORIES[provider]
        skill_directory = root / ".agents" if provider == "codex" else directory
        planned.append(Link(skill_directory / "skills", sources / "skills"))
        if provider == "claude":
            planned.append(Link(root / "CLAUDE.md", sources / "instructions.md"))
        overrides = sources / "providers" / provider
        if overrides.is_dir():
            planned.extend(
                Link(directory / path.name, path) for path in sorted(overrides.iterdir())
            )
    return planned


def conflict(link: Link, root: Path) -> str | None:
    if not link.source.exists() or not link.source.resolve().is_relative_to(root / ".ai"):
        return f"Missing or external source: {link.source.relative_to(root)}"
    if not link.destination.parent.resolve().is_relative_to(root):
        return f"Destination parent leaves the checkout: {link.destination.relative_to(root)}"
    for parent in link.destination.parents:
        if parent == root:
            break
        if (parent.exists() or parent.is_symlink()) and not parent.is_dir():
            return f"Preserving non-directory parent: {parent.relative_to(root)}"
    if link.destination.is_symlink() and link.destination.resolve() == link.source.resolve():
        return None
    if link.destination.exists() or link.destination.is_symlink():
        return f"Preserving existing path: {link.destination.relative_to(root)}"
    return None


def setup(root: Path, providers: list[str], *, check: bool, dry_run: bool) -> int:
    if not (root / ".ai" / "skills").is_dir() or not any(
        (root / ".ai" / "skills").glob("*/SKILL.md")
    ):
        print("No shared skills found under .ai/skills.", file=sys.stderr)
        return 1
    planned = links(root, providers)
    if len({link.destination for link in planned}) != len(planned):
        print("Provider overrides overlap a shared layout.", file=sys.stderr)
        return 1
    conflicts = [message for link in planned if (message := conflict(link, root))]
    if conflicts:
        print("\n".join(conflicts), file=sys.stderr)
        return 1
    missing = [link for link in planned if not link.destination.is_symlink()]
    if check:
        for link in missing:
            print(f"Missing link: {link.destination.relative_to(root)}")
        return int(bool(missing))
    for link in missing:
        relative = os.path.relpath(link.source, link.destination.parent)
        if not dry_run:
            link.destination.parent.mkdir(parents=True, exist_ok=True)
            link.destination.symlink_to(relative, target_is_directory=link.source.is_dir())
        print(f"{link.destination.relative_to(root)} -> {relative}")
    print("Plan ready." if dry_run else "Agent layouts ready.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    install = commands.add_parser("setup", help="Link shared AI sources into native agent layouts")
    install.add_argument("--provider", action="append", choices=PROVIDERS)
    mode = install.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Check links without changing files")
    mode.add_argument("--dry-run", action="store_true", help="Show planned links without writing")
    arguments = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    providers = list(dict.fromkeys(arguments.provider or PROVIDERS))
    try:
        return setup(root, providers, check=arguments.check, dry_run=arguments.dry_run)
    except OSError as error:
        print(f"Could not prepare agent layouts: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
