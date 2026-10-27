"""Real restic 0.18.1 output replayed at the parser and exit-code seams (#396)."""

import importlib.resources
import json

from django.test import SimpleTestCase

from discovery import ssh
from discovery.recorded import Recorded, ReplayShell, Transcript

from . import check
from .bodies import backup as backup_body


def fixture(name: str) -> str:
    return importlib.resources.files("backups.fixtures").joinpath(name).read_text(encoding="utf-8")


class RecordedResticTests(SimpleTestCase):
    def test_a_recorded_snapshot_listing_lists_its_recovery_point(self) -> None:
        parsed = check.parse_listing(fixture("restic-snapshots.txt"))
        if parsed is None:
            self.fail("The recorded listing was refused.")
        points = check.points(parsed)
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0]["scope"], "database")
        self.assertEqual(points[0]["point"], "0123456789abcdef")
        self.assertTrue(points[0]["complete"])
        self.assertTrue(points[0]["live"])

    def test_a_recorded_backup_summary_names_its_snapshot_and_bytes(self) -> None:
        summary = backup_body.summary(fixture("restic-backup-summary.txt"))
        if summary is None:
            self.fail("The recorded summary was not found.")
        self.assertEqual(len(str(summary["snapshot_id"])), 64)
        self.assertGreater(int(str(summary["total_bytes_processed"])), 0)

    def test_a_recorded_failed_dump_names_the_unreadable_source(self) -> None:
        error = fixture("restic-backup-failed-error.txt")
        self.assertIn("command failed: exit status 7", error)
        self.assertEqual(fixture("restic-backup-failed.txt"), "")
        self.assertEqual(backup_body.classify(1, False), ("refused", "backup_dump", 1))

    def test_the_recorded_listing_replays_at_the_remote_shell_seam(self) -> None:
        command = check.listing_command("alpha")
        shell = ReplayShell(
            Transcript(
                "backups",
                {},
                "26.04",
                "x86_64",
                "ssh-ed25519 SHA256:x",
                ((command, Recorded(ssh.CommandResult(0, fixture("restic-snapshots.txt")))),),
            )
        )
        result = shell.run(command)
        self.assertEqual(result.exit_status, 0)
        points = check.points(check.parse_listing(result.stdout) or [])
        self.assertEqual(len(points), 1)

    def test_the_recorded_listing_is_json(self) -> None:
        self.assertIsInstance(json.loads(fixture("restic-snapshots.txt")), list)
