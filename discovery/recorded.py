"""Real command output recorded and replayed at the ``RemoteShell`` seam.

docs/quality.md#recorded-transcripts describes transcripts, how they are recorded and when
they must be recorded again (docs/adr/0033-prove-real-behavior-in-two-test-layers.md).
"""

import hashlib
import json
import re
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .ssh import MAX_EXIT_STATUS, CommandResult, RemoteShell

TRANSCRIPTS = Path(__file__).resolve().parent / "transcripts"
PINS = Path(__file__).resolve().parent.parent / "docker" / "disposable-server" / "pins.json"
FORMAT = 1
REDACTED = "<secret>"
# Seeded on every server a transcript is recorded from; no transcript may contain it.
SEEDED_SECRET = "barectl-seeded-secret-6f1d0c2a9b"  # noqa: S105 - a public canary
# A site's private directory and the root-only confidential staging directory
# (docs/adr/0032-keep-secrets-in-private-native-files.md).
_SECRET_LOCATION = re.compile(r"/var/www/[^/\s]+/private/|/run/barectl/secrets(?![\w.-])")
# The probes the described filesystem answers (docs/adr/0002-keep-the-remote-shell-seam.md).
_FILESYSTEM_PROBES = frozenset({"test", "cat", "ls"})


class UnrecordedCommand(AssertionError):
    """A replayed command the transcript does not hold; it fails the test."""


class RecordingRefused(Exception):
    """A command would have put a secret into a transcript; the recording fails."""


@dataclass(frozen=True)
class Recorded:
    result: CommandResult
    # SHA-256 of the standard input the command received; the input itself is never kept.
    stdin_sha256: str | None = None


@dataclass(frozen=True)
class Transcript:
    """Every command run against one server state, with its results in the order received."""

    state: str
    # The provisioning pins the recorded server was built from.
    pins: Mapping[str, str]
    release: str
    architecture: str
    host_key: str
    commands: tuple[tuple[str, Recorded], ...]

    def dumps(self) -> str:
        document = {
            "format": FORMAT,
            "state": self.state,
            "pins": dict(sorted(self.pins.items())),
            "recorded": {
                "release": self.release,
                "architecture": self.architecture,
                "host_key": self.host_key,
            },
            "commands": [
                {
                    "command": command,
                    "exit": recorded.result.exit_status,
                    "stdout": recorded.result.stdout,
                    "truncated": recorded.result.truncated,
                    "stdin_sha256": recorded.stdin_sha256,
                }
                for command, recorded in self.commands
            ],
        }
        return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def load(state: str) -> Transcript:
    """The recorded transcript of ``state``, validated as it is read."""
    return parse((TRANSCRIPTS / f"{state}.json").read_text(encoding="utf-8"), state)


def stored() -> tuple[str, ...]:
    """Every recorded state, by name."""
    return tuple(sorted(path.stem for path in TRANSCRIPTS.glob("*.json")))


def parse(text: str, state: str) -> Transcript:
    document = json.loads(text)
    problem = f"The transcript of {state} is not in format {FORMAT}"
    if not isinstance(document, dict) or document.get("format") != FORMAT:
        raise ValueError(f"{problem}.")
    recorded = document.get("recorded")
    if document.get("state") != state or not isinstance(recorded, dict):
        raise ValueError(f"{problem}: its state or recording details are missing.")
    commands = document.get("commands")
    if not isinstance(commands, list):
        raise ValueError(f"{problem}: it lists no commands.")
    return Transcript(
        state=state,
        pins=_strings(document.get("pins"), problem),
        release=_string(recorded, "release", problem),
        architecture=_string(recorded, "architecture", problem),
        host_key=_string(recorded, "host_key", problem),
        commands=tuple(_command(entry, problem) for entry in commands),
    )


def current_pins() -> dict[str, str]:
    """The provisioning pins every transcript must have been recorded with."""
    return _strings(json.loads(PINS.read_text(encoding="utf-8")), f"{PINS.name} is not valid")


def names_secret_location(command: str) -> bool:
    return _SECRET_LOCATION.search(command) is not None


class ReplayShell:
    """Answers exactly the commands a transcript recorded, with the results recorded.

    ``overrides`` replaces the result of a recorded command for one test. ``filesystem``,
    when given, answers the ``test``, ``cat`` and ``ls`` probes from a described filesystem
    instead, whose emulation ``test_fake_server.py`` checks against a real one.
    """

    def __init__(
        self,
        transcript: Transcript,
        overrides: Mapping[str, CommandResult] | None = None,
        filesystem: RemoteShell | None = None,
    ) -> None:
        recorded = {command for command, _ in transcript.commands}
        if unknown := sorted(set(overrides or {}) - recorded):
            raise UnrecordedCommand(_unrecorded(transcript.state, unknown[0]))
        self._state = transcript.state
        self._overrides = dict(overrides or {})
        self._filesystem = filesystem
        self._remaining: dict[str, deque[Recorded]] = {}
        for command, result in transcript.commands:
            self._remaining.setdefault(command, deque()).append(result)
        self.host_key = transcript.host_key
        self.commands: list[str] = []

    def run(self, command: str, stdin: bytes | None = None) -> CommandResult:
        self.commands.append(command)
        if command in self._overrides:
            return self._overrides[command]
        if self._filesystem is not None and command.partition(" ")[0] in _FILESYSTEM_PROBES:
            return self._filesystem.run(command, stdin)
        remaining = self._remaining.get(command)
        if not remaining:
            raise UnrecordedCommand(_unrecorded(self._state, command))
        # A repeated command replays its results in order, then keeps the last.
        recorded = remaining.popleft() if len(remaining) > 1 else remaining[0]
        if recorded.stdin_sha256 != _digest(stdin):
            raise AssertionError(
                f"{command!r} received other standard input than in the recording of "
                f"{self._state}; re-record {self._state}"
            )
        return recorded.result


class RecordingShell:
    """Runs commands through ``inner`` and keeps a transcript of what they returned.

    It refuses a command that names a secret location or a known secret, and replaces each
    known secret in recorded output with a placeholder. A refused command is never sent, and
    the recording can no longer produce a transcript.
    """

    def __init__(self, inner: RemoteShell, state: str, *, secrets: Iterable[str] = ()) -> None:
        self._inner = inner
        self._state = state
        self._secrets = tuple(secret for secret in secrets if secret)
        self._commands: list[tuple[str, Recorded]] = []
        self._refused = ""

    @property
    def host_key(self) -> str:
        return self._inner.host_key

    def run(self, command: str, stdin: bytes | None = None) -> CommandResult:
        if names_secret_location(command) or any(s in command for s in self._secrets):
            self._refused = self._refused or (
                f"The recording of {self._state} refused a command that reads a secret."
            )
            raise RecordingRefused(self._refused)
        result = self._inner.run(command, stdin)
        stdout = result.stdout
        for secret in self._secrets:
            stdout = stdout.replace(secret, REDACTED)
        kept = CommandResult(result.exit_status, stdout, result.truncated)
        self._commands.append((command, Recorded(kept, _digest(stdin))))
        return result

    def transcript(self, *, pins: Mapping[str, str], release: str, architecture: str) -> Transcript:
        if self._refused:
            raise RecordingRefused(self._refused)
        return Transcript(
            self._state, dict(pins), release, architecture, self.host_key, tuple(self._commands)
        )


def _unrecorded(state: str, command: str) -> str:
    return f"unrecorded command; re-record {state}: {command}"


def _digest(stdin: bytes | None) -> str | None:
    return None if stdin is None else hashlib.sha256(stdin).hexdigest()


def _strings(value: object, problem: str) -> dict[str, str]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
        raise ValueError(f"{problem}: pins must map names to strings.")
    return {str(key): str(item) for key, item in value.items()}


def _string(document: dict[object, object], name: str, problem: str) -> str:
    value = document.get(name)
    if not isinstance(value, str):
        raise ValueError(f"{problem}: {name} is missing.")
    return value


def _command(entry: object, problem: str) -> tuple[str, Recorded]:
    if not isinstance(entry, dict):
        raise ValueError(f"{problem}: a command entry is not an object.")
    command, status, stdout = entry.get("command"), entry.get("exit"), entry.get("stdout")
    truncated, digest = entry.get("truncated"), entry.get("stdin_sha256")
    if (
        not isinstance(command, str)
        or type(status) is not int
        or not 0 <= status <= MAX_EXIT_STATUS
        or not isinstance(stdout, str)
        or not isinstance(truncated, bool)
        or not (digest is None or isinstance(digest, str))
    ):
        raise ValueError(f"{problem}: a command entry is malformed.")
    return command, Recorded(CommandResult(status, stdout, truncated), digest)
