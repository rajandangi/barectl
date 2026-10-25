"""Base class for the native lifecycle scenarios (docs/quality.md#native-layer).

A scenario is a Django test class tagged ``scenario``. It runs in its own
``manage.py test`` process against a real server the harness boots on a lane, reaching it
only through the lane's forwarder. It declares the snapshot layer it needs, whether it
needs a server to itself, the name prefix it gives every resource it creates, and the
checkpoint states it records a transcript for.

The harness sets the environment below; a scenario reads nothing else from its host.
"""

import contextlib
import os
import shlex
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import override

from django.test import TestCase

from discovery import recorded, ssh
from servers.ssh_config import ConnectionTarget

from .docker import docker

SCENARIO_TAG = "scenario"
_RECORD_ENV = "BARECTL_SCENARIO_RECORD"


def _setting(name: str) -> str:
    return os.environ[f"BARECTL_SSH_TEST_{name}"]


def repair_runtime_masters(test: ScenarioTestCase) -> None:
    """Restart the shared PHP runtime masters once per validator process.

    A package transaction, a unit write or systemd-analyze's manager interaction can clear
    the running masters' ExecStart metadata (issue #428). The next validator class then
    cannot verify the master or its diagnostic socket. Restarting them once at the start of
    each validator class restores the evidence without changing the product.
    """
    if getattr(type(test), "_runtime_repaired", False):
        return
    type(test)._runtime_repaired = True
    test.native("systemctl restart php-fpm@php84.service php-fpm@php85.service 2>&1 || true")
    test.native(
        "timeout 20 sh -c 'until [ -S /run/php-fpm/php84/diagnostic.sock ] "
        "&& [ -S /run/php-fpm/php85/diagnostic.sock ]; do sleep 0.2; done' || true"
    )


class ScenarioTestCase(TestCase):
    """One native lifecycle scenario; subclasses set the declarations below."""

    layer = "L0"
    exclusive = False
    prefix = "s0"
    records: tuple[str, ...] = ()
    # A preparation scenario is excluded from ordinary discovery; the runner selects it by
    # name only to build a missing snapshot layer (scenarios.prepare_layers).
    preparation = False
    validator = False
    breadth = False
    memory_gib = 0
    repair_masters = False
    _runtime_repaired = False

    @override
    def setUp(self) -> None:
        self.record_state = os.environ.get(_RECORD_ENV, "")
        if self.record_state:
            self._seed_secret()
        if getattr(self, "validator", False) and getattr(self, "repair_masters", False):
            repair_runtime_masters(self)

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

    def reboot(self, *, timeout: float = 90) -> None:
        """Restart the container's init and wait for systemd (a userspace reboot).

        The container shares the Docker VM's kernel, so this is not a kernel reboot; it is
        the closest boot path the lane can prove (docs/phase-c-qualification.md).
        """
        docker("restart", "--time", "5", _setting("CONTAINER"), timeout=timeout + 30)
        self._wait_for_systemd(timeout)

    def stop_for(self, seconds: float) -> None:
        """Stop the container, leave it down for ``seconds``, then start it again."""
        docker("stop", "--time", "5", _setting("CONTAINER"), timeout=60)
        time.sleep(seconds)
        docker("start", _setting("CONTAINER"), timeout=60)
        self._wait_for_systemd(90)

    def _wait_for_systemd(self, timeout: float) -> None:
        end = time.monotonic() + timeout
        state = ""
        while time.monotonic() < end:
            with contextlib.suppress(Exception):
                state = self.native("systemctl is-system-running || true").strip()
            if state in {"running", "degraded"}:
                return
            time.sleep(0.3)
        raise AssertionError(f"systemd did not return in {timeout:.0f} s ({state!r})")

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

    def _seed_secret(self) -> None:
        secret = shlex.quote(recorded.SEEDED_SECRET)
        self.native(
            "install -d -m 700 /run/barectl/secrets && "
            f"printf %s {secret} >/run/barectl/secrets/seeded"
        )
