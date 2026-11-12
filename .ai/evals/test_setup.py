"""Exercise the installer through its CLI in disposable checkouts."""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import override

SOURCE = Path.cwd() / ".ai"


class AgentSetupTests(unittest.TestCase):
    root: Path

    @override
    def setUp(self) -> None:
        self.assertTrue((SOURCE / "cli.py").is_file(), "The shared AI installer is unavailable.")
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        if SOURCE.is_dir():
            shutil.copytree(SOURCE, self.root / ".ai", ignore=shutil.ignore_patterns("__pycache__"))

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed Python CLI in a disposable checkout
            [sys.executable, str(self.root / ".ai" / "cli.py"), "setup", *arguments],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_all_providers_read_one_shared_source(self) -> None:
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        shared = self.root / ".ai" / "skills"
        for directory in (".agents", ".claude", ".opencode"):
            link = self.root / directory / "skills"
            self.assertTrue(link.is_symlink())
            self.assertFalse(os.path.isabs(os.readlink(link)))
            self.assertEqual(link.resolve(), shared)
        self.assertEqual((self.root / "CLAUDE.md").resolve(), self.root / ".ai/instructions.md")
        self.assertEqual((self.root / "evals").resolve(), self.root / ".ai/evals")
        skill = shared / "barectl-retro" / "SKILL.md"
        skill.write_text(skill.read_text() + "\nA shared edit.\n")
        for directory in (".agents", ".claude", ".opencode"):
            self.assertIn(
                "A shared edit.",
                (self.root / directory / "skills" / skill.relative_to(shared)).read_text(),
            )

    def test_repeated_setup_keeps_existing_links_and_local_settings(self) -> None:
        self.assertEqual(self.run_cli().returncode, 0)
        link = self.root / ".agents" / "skills"
        before = link.lstat().st_mtime_ns
        settings = self.root / ".claude" / "settings.local.json"
        settings.write_text('{"local": true}\n')
        self.assertEqual(self.run_cli().returncode, 0)
        self.assertEqual(link.lstat().st_mtime_ns, before)
        self.assertEqual(settings.read_text(), '{"local": true}\n')
        self.assertEqual(self.run_cli("--check").returncode, 0)

    def test_provider_selection_only_prepares_the_selected_provider(self) -> None:
        result = self.run_cli("--provider", "claude", "--provider", "claude")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / ".claude/skills").is_symlink())
        self.assertFalse((self.root / ".agents").exists())
        self.assertFalse((self.root / ".opencode").exists())
        self.assertEqual(self.run_cli("--provider", "claude", "--check").returncode, 0)
        self.assertEqual(self.run_cli("--check").returncode, 1)

    def test_check_and_dry_run_do_not_write_missing_links(self) -> None:
        for arguments, expected in ((("--check",), 1), (("--dry-run",), 0)):
            with self.subTest(arguments=arguments):
                result = self.run_cli(*arguments)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual({path.name for path in self.root.iterdir()}, {".ai"})
                self.assertIn(".agents/skills", result.stdout)

    def test_conflicts_are_reported_before_any_link_is_created(self) -> None:
        private = self.root / ".opencode/skills/private/SKILL.md"
        private.parent.mkdir(parents=True)
        private.write_text("Keep this local skill.\n")
        for arguments in ((), ("--check",), ("--dry-run",)):
            with self.subTest(arguments=arguments):
                result = self.run_cli(*arguments)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Preserving existing path", result.stderr)
                self.assertEqual(private.read_text(), "Keep this local skill.\n")
                self.assertFalse((self.root / ".agents").exists())
                self.assertFalse((self.root / "evals").exists())

    def test_a_broken_existing_link_is_preserved(self) -> None:
        (self.root / ".agents").mkdir()
        private = self.root / ".agents/skills"
        private.symlink_to("missing-private-skills")
        self.assertEqual(self.run_cli().returncode, 1)
        self.assertEqual(os.readlink(private), "missing-private-skills")
        self.assertFalse((self.root / "evals").exists())

    def test_an_external_destination_parent_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            external = Path(directory).resolve()
            (self.root / ".claude").symlink_to(external, target_is_directory=True)
            self.assertEqual(self.run_cli().returncode, 1)
            self.assertEqual(list(external.iterdir()), [])
            self.assertFalse((self.root / "evals").exists())

    def test_a_file_or_broken_link_in_a_parent_preserves_the_whole_plan(self) -> None:
        parent = self.root / ".claude"
        for broken in (False, True):
            with self.subTest(broken=broken):
                if broken:
                    parent.symlink_to("missing-private-directory")
                else:
                    parent.write_text("Keep this local file.\n")
                result = self.run_cli()
                self.assertEqual(result.returncode, 1)
                self.assertIn("non-directory parent", result.stderr)
                self.assertFalse((self.root / "evals").exists())
                self.assertFalse((self.root / ".agents").exists())
                parent.unlink()

    def test_provider_overrides_cannot_replace_shared_skills(self) -> None:
        overrides = self.root / ".ai/providers/claude/skills"
        overrides.mkdir(parents=True)
        result = self.run_cli()
        self.assertEqual(result.returncode, 1)
        self.assertIn("overlap", result.stderr)
        self.assertFalse((self.root / "evals").exists())

    def test_invalid_provider_is_rejected_without_writing(self) -> None:
        self.assertEqual(self.run_cli("--provider", "unknown").returncode, 2)
        self.assertEqual({path.name for path in self.root.iterdir()}, {".ai"})

    def test_missing_sources_are_rejected_without_writing(self) -> None:
        skills = self.root / ".ai/skills"
        if skills.exists():
            shutil.rmtree(skills)
        self.assertNotEqual(self.run_cli().returncode, 0)
        self.assertFalse((self.root / "evals").exists())

    def test_generated_layouts_are_ignored_and_common_sources_are_not(self) -> None:
        paths = (".agents/skills", ".claude/skills", ".opencode/skills", "CLAUDE.md", "evals")
        result = subprocess.run(  # noqa: S603 - fixed Git probe over generated repository paths
            ["/usr/bin/git", "check-ignore", "--no-index", *paths],
            cwd=SOURCE.parent,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(result.stdout.splitlines()), set(paths))
        result = subprocess.run(
            ["/usr/bin/git", "check-ignore", "--no-index", ".ai/cli.py"],
            cwd=SOURCE.parent,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_shared_instruction_document_paths_remain_valid_after_relocation(self) -> None:
        instructions = (SOURCE / "instructions.md").read_text()
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", instructions):
            if target.startswith(("https://", "http://", "#")):
                continue
            self.assertTrue((SOURCE / target.split("#")[0]).exists(), target)
        for target in re.findall(r"`((?:docs/|README\.md|ROADMAP\.md)[^`]*)`", instructions):
            self.assertTrue((SOURCE.parent / target.split("#")[0]).exists(), target)


if __name__ == "__main__":
    unittest.main()
