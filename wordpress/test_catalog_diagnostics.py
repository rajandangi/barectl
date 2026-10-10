"""Bounded, secret-free native catalog failure evidence (docs/wordpress-native-design.md)."""

import json
import os
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from discovery.ssh import CommandResult

from .install_apply_remote_testing import (
    InstallApplyTestCase,
    catalog_failure_receipt,
    catalog_read_diagnostics,
)
from .install_remote_testing import InstallationServerCase


class _Shell:
    host_key = "fixture"

    def __init__(self, result: CommandResult) -> None:
        self.result = result
        self.calls = 0

    def run(self, command: str) -> CommandResult:
        self.calls += 1
        return self.result


class CatalogDiagnosticsTests(SimpleTestCase):
    def test_fixture_stops_a_held_unit_before_removing_its_resources(self) -> None:
        state = {"held": True, "removed": False}
        fixture = InstallApplyTestCase("runTest")

        def clear_units(_case: InstallApplyTestCase) -> None:
            state["held"] = False

        def remove_resource() -> None:
            self.assertFalse(state["held"], "Resource deletion raced a held native unit")
            state["removed"] = True

        def parent_setup(case: InstallApplyTestCase) -> None:
            case.addCleanup(case.clear_units)
            case.addCleanup(remove_resource)

        with (
            mock.patch.object(InstallationServerCase, "setUp", parent_setup),
            mock.patch.object(InstallApplyTestCase, "clear_units", clear_units),
        ):
            fixture.setUp()
            fixture.doCleanups()
            self.assertTrue(state["removed"], "Resource deletion raced a held native unit")
        self.assertFalse(state["held"])

    def test_the_original_failed_read_is_not_replayed_or_rendered(self) -> None:
        reads: list[dict[str, int | bool]] = []
        shell = _Shell(CommandResult(2, "private catalog contents"))
        with catalog_read_diagnostics(reads) as reader_type:
            reader = reader_type(shell)
            reader.read("sudo -n -l mysql.global_priv", "the catalog authorization")
            result = reader.read("mysql.global_priv; runuser -u postgres", "the MariaDB catalog")
        self.assertIsNone(result)
        self.assertEqual(
            reader.gaps,
            [
                "Barectl could not read the catalog authorization.",
                "Barectl could not read the MariaDB catalog.",
            ],
        )
        self.assertEqual(shell.calls, 2)
        self.assertEqual(len(reads), 1)
        self.assertEqual(reads[0]["exit_status"], 2)
        self.assertTrue(reads[0]["other_engine"])
        self.assertNotIn("private catalog contents", json.dumps(reads))

    def test_original_truncation_still_refuses(self) -> None:
        reads: list[dict[str, int | bool]] = []
        with catalog_read_diagnostics(reads) as reader_type:
            reader = reader_type(_Shell(CommandResult(0, "private", truncated=True)))
            self.assertIsNone(reader.read("mysql.global_priv", "the MariaDB catalog"))
        self.assertEqual(reader.gaps, ["the MariaDB catalog was larger than Barectl reads."])
        self.assertTrue(reads[0]["truncated"])

    def test_native_errors_keep_only_codes_and_discard_query_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            scripts = {
                "timeout": 'shift; exec "$@"',
                "systemctl": "printf 'ActiveState=inactive\\n'; printf '%04096d' 0",
                "mariadb": (
                    "printf 'private query output\\n'; "
                    "printf 'ERROR 1698 secret account/password\\nprivate error\\n' >&2; exit 1"
                ),
                "runuser": (
                    "printf 'private query output\\n'; "
                    "printf 'FATAL: 28P01 secret account/password\\nprivate error\\n' >&2; exit 2"
                ),
            }
            for name, script in scripts.items():
                path = folder / name
                path.write_text(f"#!/bin/sh\n{script}\n")
                path.chmod(0o755)

            def administer(command: str) -> str:
                return subprocess.run(  # noqa: S602 - fixed diagnostic commands against fixtures
                    command,
                    shell=True,
                    check=True,
                    text=True,
                    capture_output=True,
                    env={**os.environ, "PATH": f"{folder}:/usr/bin:/bin"},
                    timeout=5,
                ).stdout

            receipt = catalog_failure_receipt([], administer)
        self.assertNotIn("private", receipt)
        self.assertNotIn("secret", receipt)
        self.assertIn("MariaDB error code=1698", receipt)
        self.assertIn("PostgreSQL error code=28P01", receipt)
        self.assertIn("native-read-exit=1", receipt)
        self.assertIn("native-read-exit=2", receipt)
        self.assertEqual(len(json.loads(receipt)["native"]["units"].encode()), 2048)

    def test_an_unavailable_diagnostic_never_discloses_exception_output(self) -> None:
        def administer(command: str) -> str:
            raise subprocess.CalledProcessError(1, command, output="secret", stderr="private")

        receipt = catalog_failure_receipt([], administer)
        self.assertNotIn("secret", receipt)
        self.assertNotIn("private", receipt)
        self.assertIn("CalledProcessError", receipt)
