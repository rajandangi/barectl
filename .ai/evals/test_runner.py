"""Oracle files remain readable across the shared-source migration."""

import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import override
from unittest import mock

from . import runner


class OracleLocationTests(unittest.TestCase):
    root: Path
    repository: Path
    legacy: str
    shared: str

    @override
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.repository = self.root / "repository"
        self.repository.mkdir()
        isolated = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.enterContext(mock.patch.dict(os.environ, isolated, clear=True))
        self.enterContext(mock.patch.object(runner, "REPOSITORY", self.repository))
        self.git("init", "-q")
        self.git("config", "user.name", "Eval Test")
        self.git("config", "user.email", "eval@example.invalid")
        old = self.repository / "evals/probe.py"
        old.parent.mkdir()
        old.write_text("legacy oracle\n")
        self.git("add", ".")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "Legacy source")
        self.legacy = self.git("rev-parse", "HEAD")
        shared = self.repository / ".ai/evals/probe.py"
        shared.parent.mkdir(parents=True)
        old.rename(shared)
        shared.write_text("shared oracle\n")
        self.git("add", "-A")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "Shared source")
        self.shared = self.git("rev-parse", "HEAD")

    def git(self, *arguments: str) -> str:
        result = subprocess.run(  # noqa: S603 - fixed Git operations in an isolated temporary repository
            ["/usr/bin/git", *arguments],
            cwd=self.repository,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def case(self, ref: str, module: str = "evals.probe") -> runner.Case:
        return runner.Case(
            id="oracle-location",
            title="Oracle location",
            kind="harness",
            base=self.legacy,
            oracle_ref=ref,
            oracle_tests=(module,),
            checks=(),
            budget_minutes=1,
            prompt=self.root / "prompt.md",
            ground_truth=(),
            harness_skills=(),
        )

    def test_both_oracle_locations_copy_into_legacy_and_generated_layouts(self) -> None:
        for generated in (False, True):
            target = self.root / str(generated)
            target.mkdir()
            if generated:
                (target / ".ai/evals").mkdir(parents=True)
                (target / "evals").symlink_to(".ai/evals", target_is_directory=True)
            for ref, expected in (
                (self.legacy, "legacy oracle\n"),
                (self.shared, "shared oracle\n"),
            ):
                with self.subTest(generated=generated, ref=ref):
                    self.assertEqual(runner._copy_oracle(self.case(ref), target), 0)
                    self.assertEqual((target / "evals/probe.py").read_text(), expected)

    def test_missing_oracle_does_not_create_a_replacement(self) -> None:
        target = self.root / "missing"
        target.mkdir()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertNotEqual(
                runner._copy_oracle(self.case(self.shared, "evals.missing"), target), 0
            )
        self.assertEqual(list(target.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
