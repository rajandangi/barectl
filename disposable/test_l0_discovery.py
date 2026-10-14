"""S0: a fresh controller discovers a plain L0 server.

docs/quality.md#native-layer. This is the first scenario on the harness and the one that
re-records the pristine transcript the fast layer replays.
"""

import os
import subprocess
import tempfile
import time
from pathlib import Path
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import override_settings, tag

from bootstrap.standing import Standing
from dashboard.testing import TEST_MANIFEST
from discovery.fakes import run_worker
from discovery.models import ObservationOutcome
from discovery.observations import collect
from discovery.services import read_discovery
from servers.models import Server

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class PlainL0Discovery(ScenarioTestCase):
    layer = "L0"
    exclusive = False
    prefix = "s0"
    records: tuple[str, ...] = ("pristine-26.04",)

    def test_a_fresh_controller_discovers_a_plain_l0_server(self) -> None:
        target = self.target()
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            agent_socket = Path(directory) / "agent"
            agent = subprocess.Popen(  # noqa: S603
                ["ssh-agent", "-D", "-a", str(agent_socket)],  # noqa: S607
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.monotonic() + 5
                while not agent_socket.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                with (
                    mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": str(agent_socket)}),
                    override_settings(
                        SSH_KNOWN_HOSTS_PATH=str(target.known_hosts_files[0]),
                        VITE_MANIFEST_PATH=TEST_MANIFEST,
                    ),
                ):
                    subprocess.run(  # noqa: S603
                        ["ssh-add", str(target.identity_files[0])],  # noqa: S607
                        check=True,
                        capture_output=True,
                    )
                    user = get_user_model().objects.create_superuser(username="scenario")
                    self.client.force_login(user)
                    response = self.client.post(
                        "/servers/add/",
                        {
                            "name": "Scenario",
                            "address": target.hostname,
                            "username": target.user,
                            "port": target.port,
                        },
                    )
                    self.assertEqual(response.status_code, 302)
                    run_worker()
                    server = Server.objects.get()
                    discovered = read_discovery(server).snapshot
                    if discovered is None:
                        self.fail("The dashboard connection check did not publish discovery.")
                    snapshot = discovered.collected
                    self.assertContains(
                        self.client.get(response.headers["Location"]), "Set up server"
                    )
            finally:
                agent.terminate()
                agent.wait(timeout=5)
        if self.record_state:
            with self.shell() as shell:
                snapshot = collect(shell)
                self.checkpoint("pristine-26.04", shell)

        os_release = snapshot.os.value
        if os_release is None:
            self.fail(snapshot.os.warning or "no os-release")
        self.assertEqual(os_release.id, "ubuntu")
        self.assertEqual(os_release.version_id, "26.04")
        self.assertIn(snapshot.architecture.value, {"x86_64", "aarch64"})
        self.assertIsNotNone(snapshot.cpu_count.value)
        self.assertIsNotNone(snapshot.memory_bytes.value)
        self.assertIsNotNone(snapshot.filesystem.value)
        if snapshot.standing is None:
            self.fail("Host standing was not judged during discovery.")
        self.assertEqual(snapshot.standing.standing, Standing.FRESH, snapshot.standing.reasons)
        self.assertEqual(snapshot.standing.reasons, ())
        # A plain server has no web stack or database Barectl would manage.
        self.assertTrue(
            all(
                component.package.outcome is ObservationOutcome.ABSENT
                for component in snapshot.components
            ),
            [component.component for component in snapshot.components],
        )
