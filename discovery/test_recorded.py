"""Recorded transcripts: replay, recording over a real SSH connection, and the stored files.

docs/quality.md#recorded-transcripts
"""

import json
import tempfile
from pathlib import Path
from typing import override
from unittest import mock

from django.test import SimpleTestCase

from . import recorded, ssh
from .fakes import FakeServer
from .recorded import (
    Recorded,
    RecordingRefused,
    RecordingShell,
    ReplayShell,
    Transcript,
    UnrecordedCommand,
)
from .test_ssh import SshServerTestCase

PINS = {"ubuntu-26.04": "ubuntu:26.04@sha256:" + "0" * 64}


def transcript(*commands: tuple[str, Recorded]) -> Transcript:
    return Transcript("example", PINS, "26.04", "x86_64", "ssh-ed25519 SHA256:x", commands)


class ReplayTests(SimpleTestCase):
    def test_recorded_commands_are_answered_exactly(self) -> None:
        shell = ReplayShell(transcript(("nproc", Recorded(ssh.CommandResult(0, "2\n")))))
        self.assertEqual(shell.run("nproc"), ssh.CommandResult(0, "2\n"))
        self.assertEqual(shell.host_key, "ssh-ed25519 SHA256:x")

    def test_an_unrecorded_command_fails_and_names_the_state(self) -> None:
        shell = ReplayShell(transcript(("nproc", Recorded(ssh.CommandResult(0, "2\n")))))
        for command in ("nproc ", "uname -m"):
            with self.subTest(command=command), self.assertRaises(AssertionError) as raised:
                shell.run(command)
            self.assertEqual(
                str(raised.exception), f"unrecorded command; re-record example: {command}"
            )

    def test_a_repeated_command_replays_in_order_then_keeps_the_last(self) -> None:
        shell = ReplayShell(
            transcript(
                ("systemctl is-active x", Recorded(ssh.CommandResult(3, "activating\n"))),
                ("systemctl is-active x", Recorded(ssh.CommandResult(0, "active\n"))),
            )
        )
        outputs = [shell.run("systemctl is-active x").stdout for _ in range(3)]
        self.assertEqual(outputs, ["activating\n", "active\n", "active\n"])

    def test_standard_input_must_match_the_recording(self) -> None:
        digest = recorded._digest(b"value")
        shell = ReplayShell(transcript(("stage", Recorded(ssh.CommandResult(0, ""), digest))))
        self.assertEqual(shell.run("stage", stdin=b"value").exit_status, 0)
        for stdin in (b"other", None):
            with self.subTest(stdin=stdin), self.assertRaises(AssertionError) as raised:
                shell.run("stage", stdin=stdin)
            self.assertIn("re-record example", str(raised.exception))

    def test_overrides_change_only_recorded_commands(self) -> None:
        recording = transcript(("nproc", Recorded(ssh.CommandResult(0, "2\n"))))
        shell = ReplayShell(recording, overrides={"nproc": ssh.CommandResult(127, "")})
        self.assertEqual(shell.run("nproc").exit_status, 127)
        with self.assertRaises(UnrecordedCommand):
            ReplayShell(recording, overrides={"uname -m": ssh.CommandResult(0, "x86_64\n")})

    def test_a_described_filesystem_answers_the_probes(self) -> None:
        recording = transcript(
            ("cat /etc/os-release", Recorded(ssh.CommandResult(0, "ID=ubuntu\n"))),
            ("nproc", Recorded(ssh.CommandResult(0, "2\n"))),
        )
        filesystem = FakeServer(files={}, directories={}, results={})
        filesystem.unreadable = {"/etc/os-release"}
        shell = ReplayShell(recording, filesystem=filesystem)
        self.assertEqual(shell.run("cat /etc/os-release").exit_status, 1)
        self.assertEqual(shell.run("test -e /etc/os-release").exit_status, 0)
        self.assertEqual(shell.run("nproc").stdout, "2\n")

    def test_a_transcript_survives_writing_and_reading(self) -> None:
        original = transcript(
            ("cat x", Recorded(ssh.CommandResult(0, "é\x00\n", truncated=True))),
            ("stage", Recorded(ssh.CommandResult(1, ""), recorded._digest(b"v"))),
        )
        self.assertEqual(recorded.parse(original.dumps(), "example"), original)

    def test_a_malformed_transcript_is_refused(self) -> None:
        document = json.loads(transcript(("nproc", Recorded(ssh.CommandResult(0, "2")))).dumps())
        for change in (
            {"format": 0},
            {"state": "other"},
            {"pins": {"ubuntu": 1}},
            {"commands": [{"command": "nproc", "exit": 300, "stdout": "", "truncated": False}]},
            {"commands": [{"command": "nproc", "exit": True, "stdout": "", "truncated": False}]},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                recorded.parse(json.dumps(document | change), "example")


class RecordingTests(SshServerTestCase):
    """The recorder over pyinfra and a real SSH server, with a known secret seeded."""

    @override
    def setUp(self) -> None:
        super().setUp()
        self.secret_file = self.directory / "settings"
        self.secret_file.write_text(f"KEY={recorded.SEEDED_SECRET}\n", encoding="utf-8")

    def test_a_seeded_secret_appears_in_no_transcript(self) -> None:
        with ssh.connect(self.target()) as shell:
            recording = RecordingShell(shell, "seeded", secrets=(recorded.SEEDED_SECRET,))
            # The caller still receives the real output.
            read = recording.run(f"cat {self.secret_file}")
            staged = recording.run("cat >/dev/null", stdin=recorded.SEEDED_SECRET.encode())
        self.assertIn(recorded.SEEDED_SECRET, read.stdout)
        text = recording.transcript(pins=PINS, release="26.04", architecture="x86_64").dumps()
        self.assertNotIn(recorded.SEEDED_SECRET, text)
        replay = ReplayShell(recorded.parse(text, "seeded"))
        self.assertEqual(replay.run(f"cat {self.secret_file}").stdout, "KEY=<secret>\n")
        self.assertEqual(
            replay.run("cat >/dev/null", stdin=recorded.SEEDED_SECRET.encode()), staged
        )

    def test_reading_a_secret_location_fails_the_recording(self) -> None:
        for command in (
            "cat /var/www/blog/private/.env",
            "ls -1bA /run/barectl/secrets",
            f"grep KEY {self.secret_file} {recorded.SEEDED_SECRET}",
        ):
            with self.subTest(command=command), ssh.connect(self.target()) as shell:
                sent = len(self.server.commands)
                recording = RecordingShell(shell, "seeded", secrets=(recorded.SEEDED_SECRET,))
                recording.run("true")
                with self.assertRaises(RecordingRefused):
                    recording.run(command)
                # Even when the collector would carry on, nothing can be written.
                with self.assertRaises(RecordingRefused):
                    recording.transcript(pins=PINS, release="26.04", architecture="x86_64")
                self.assertEqual(len(self.server.commands), sent + 1)


def stale_states() -> list[str]:
    """The stored states recorded with pins other than the current ones."""
    current = recorded.current_pins()
    return [state for state in recorded.stored() if dict(recorded.load(state).pins) != current]


class StoredTranscriptTests(SimpleTestCase):
    """Every transcript in the repository, read as tests read it."""

    def test_every_transcript_was_recorded_with_the_current_pins(self) -> None:
        self.assertEqual(stale_states(), [], "re-record these states: their pins changed")

    def test_no_transcript_holds_a_secret(self) -> None:
        for state in recorded.stored():
            with self.subTest(state=state):
                text = (recorded.TRANSCRIPTS / f"{state}.json").read_text(encoding="utf-8")
                self.assertNotIn(recorded.SEEDED_SECRET, text)
                for command, _ in recorded.load(state).commands:
                    self.assertFalse(recorded.names_secret_location(command), command)

    def test_a_pin_change_is_detected(self) -> None:
        stale = transcript(("nproc", Recorded(ssh.CommandResult(0, "2\n"))))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "transcripts"
            path.mkdir()
            (path / "example.json").write_text(stale.dumps(), encoding="utf-8")
            (path.parent / "pins.json").write_text(
                json.dumps({"ubuntu-26.04": "ubuntu:26.04@sha256:" + "1" * 64}), encoding="utf-8"
            )
            with (
                mock.patch.object(recorded, "TRANSCRIPTS", path),
                mock.patch.object(recorded, "PINS", path.parent / "pins.json"),
            ):
                self.assertEqual(stale_states(), ["example"])
