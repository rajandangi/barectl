"""Base class for the native lifecycle scenarios (docs/quality.md#native-layer).

A scenario is a Django test class tagged ``scenario``. It runs in its own
``manage.py test`` process against a real server the harness boots on a lane, reaching it
only through the lane's forwarder. It declares the snapshot layer it needs, whether it
needs a server to itself, the name prefix it gives every resource it creates, and the
checkpoint states it records a transcript for.

The harness sets the environment below; a scenario reads nothing else from its host.
"""

import os
import shlex
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import override

from django.test import TestCase

from discovery import recorded, ssh
from servers.ssh_config import ConnectionTarget

from .docker import docker
from .scenarios import EGRESS_CANARY

SCENARIO_TAG = "scenario"
_RECORD_ENV = "BARECTL_SCENARIO_RECORD"


def _setting(name: str) -> str:
    return os.environ[f"BARECTL_SSH_TEST_{name}"]


class ScenarioTestCase(TestCase):
    """One native lifecycle scenario; subclasses set the declarations below."""

    layer = "L0"
    exclusive = False
    prefix = "s0"
    records: tuple[str, ...] = ()

    @override
    def setUp(self) -> None:
        self.record_state = os.environ.get(_RECORD_ENV, "")
        if self.record_state:
            self._seed_secret()

    def target(self) -> ConnectionTarget:
        return ConnectionTarget(
            alias="scenario",
            hostname=_setting("HOST"),
            port=int(_setting("PORT")),
            user=_setting("USER"),
            identity_files=(Path(_setting("KEY")),),
            known_hosts_files=(Path(_setting("KNOWN_HOSTS")),),
        )

    @contextmanager
    def shell(self) -> Iterator[ssh.RemoteShell]:
        """A verified connection: a recording one while a transcript is being recorded."""
        # Only the generated key is offered, never the developer's agent keys.
        os.environ["SSH_AUTH_SOCK"] = ""
        with ssh.connect(self.target()) as connection:
            if self.record_state:
                yield recorded.RecordingShell(
                    connection, self.record_state, secrets=(recorded.SEEDED_SECRET,)
                )
            else:
                yield connection

    def native(self, command: str, *, timeout: float = 300) -> str:
        """Run a harness command in the server container (teardown, probes)."""
        return docker("exec", _setting("CONTAINER"), "sh", "-c", command, timeout=timeout)

    def checkpoint(self, state: str, shell: ssh.RemoteShell) -> None:
        """Write the transcript of ``state`` while recording it; otherwise do nothing."""
        if self.record_state != state:
            return
        if not isinstance(shell, recorded.RecordingShell):
            raise AssertionError(f"the recording of {state} lost its recording shell")
        transcript = shell.transcript(
            pins=recorded.current_pins(),
            release=os.environ.get("BARECTL_SCENARIO_RELEASE", "26.04"),
            architecture=os.environ.get("BARECTL_SCENARIO_ARCH", ""),
        )
        path = recorded.TRANSCRIPTS / f"{state}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(transcript.dumps(), encoding="utf-8")

    def assert_egress_denied(self) -> None:
        status = self.native(f"getent hosts {EGRESS_CANARY} >/dev/null 2>&1; echo $?").strip()
        if status == "0":
            self.fail(f"the server resolved {EGRESS_CANARY}; egress is not denied")

    def _seed_secret(self) -> None:
        secret = shlex.quote(recorded.SEEDED_SECRET)
        self.native(
            "install -d -m 700 /run/barectl/secrets && "
            f"printf %s {secret} >/run/barectl/secrets/seeded"
        )
