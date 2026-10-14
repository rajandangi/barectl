"""Saved-address checks through the dashboard, worker and real SSH negotiation."""

import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import override
from unittest import mock

from django.test import override_settings
from paramiko import ECDSAKey

from servers.testing import ControllerConfigTestCase

from .fakes import run_worker
from .models import DiscoveryAttempt
from .ssh_testing import USER, SshServer


class SavedTransportTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir="/tmp")))
        self.client_key = ECDSAKey.generate()
        self.host_key = ECDSAKey.generate()
        self.remote = SshServer(self.host_key, self.client_key)
        self.addCleanup(self.remote.close)
        self.trust = self.directory / "known_hosts"
        self.trust.write_text(
            f"[127.0.0.1]:{self.remote.port} {self.host_key.get_name()} "
            f"{self.host_key.get_base64()}\n"
        )
        self.key_file = self.directory / "id_ecdsa"
        self.client_key.write_private_key_file(str(self.key_file))
        self.enterContext(override_settings(SSH_KNOWN_HOSTS_PATH=str(self.trust)))
        self.enterContext(mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": ""}))
        self.grant("view_server", "add_server", "add_discoveryattempt")
        self.client.force_login(self.user)

    def start_agent(self, *, load_key: bool = True) -> None:
        socket = self.directory / "agent"
        agent = subprocess.Popen(  # noqa: S603
            ["ssh-agent", "-D", "-a", str(socket)],  # noqa: S607
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(agent.wait)
        self.addCleanup(agent.terminate)
        deadline = time.monotonic() + 5
        while not socket.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        os.environ["SSH_AUTH_SOCK"] = str(socket)
        if load_key:
            subprocess.run(  # noqa: S603
                ["ssh-add", str(self.key_file)],  # noqa: S607
                check=True,
                capture_output=True,
            )

    def check(self, *, username: str = USER) -> DiscoveryAttempt:
        response = self.client.post(
            "/servers/add/",
            {
                "name": "Cloud",
                "address": "127.0.0.1",
                "username": username,
                "port": str(self.remote.port),
            },
        )
        self.assertEqual(response.status_code, 302)
        run_worker()
        return DiscoveryAttempt.objects.get()

    def test_empty_agent_reports_unavailable_credential(self) -> None:
        self.start_agent(load_key=False)
        result = self.check()
        self.assertEqual(result.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("credential is unavailable", result.failure)
        self.assertEqual(self.remote.auth_attempts, 0)

    def test_unknown_identity_is_refused_before_authentication(self) -> None:
        self.start_agent()
        self.trust.write_text("")
        result = self.check()
        self.assertIn("identity not yet trusted", result.failure)
        self.assertEqual(self.remote.auth_attempts, 0)

    def test_agent_authenticates_without_forwarding(self) -> None:
        self.start_agent()
        result = self.check()
        self.assertEqual(result.status, DiscoveryAttempt.Status.SUCCEEDED, result.failure)
        self.assertEqual(self.remote.refused, [])

    def test_file_identity_is_not_a_fallback_for_an_empty_agent(self) -> None:
        self.start_agent(load_key=False)
        self.write_config(
            f"Host *\n  IdentityFile {self.key_file}\n  UserKnownHostsFile {self.trust}\n"
        )
        default_directory = self.directory / ".ssh"
        default_directory.mkdir()
        self.client_key.write_private_key_file(str(default_directory / "id_ecdsa"))
        with mock.patch.dict(os.environ, {"HOME": str(self.directory)}):
            result = self.check()
        self.assertEqual(result.status, DiscoveryAttempt.Status.FAILED)
        self.assertEqual(self.remote.auth_attempts, 0)

    def test_revoked_identity_is_refused_before_authentication(self) -> None:
        self.start_agent()
        self.trust.write_text("@revoked " + self.trust.read_text())
        result = self.check()
        self.assertIn("revoked", result.failure)
        self.assertEqual(self.remote.auth_attempts, 0)

    def test_changed_identity_is_refused_before_authentication(self) -> None:
        self.start_agent()
        other = ECDSAKey.generate()
        self.trust.write_text(
            f"[127.0.0.1]:{self.remote.port} {other.get_name()} {other.get_base64()}\n"
        )
        result = self.check()
        self.assertIn("different host key", result.failure)
        self.assertEqual(self.remote.auth_attempts, 0)

    def test_alias_cannot_bypass_revocation_in_the_owned_trust_file(self) -> None:
        alias_trust = self.directory / "alias_trust"
        alias_trust.write_text(self.trust.read_text())
        self.write_config(
            f"Host cloud\n  HostName 127.0.0.1\n  Port {self.remote.port}\n"
            f"  User {USER}\n  IdentityFile {self.key_file}\n  UserKnownHostsFile {alias_trust}\n"
        )
        self.trust.write_text("@revoked " + self.trust.read_text())
        response = self.client.post("/servers/add/", {"name": "Cloud", "ssh_alias": "cloud"})
        self.assertEqual(response.status_code, 302)
        run_worker()
        self.assertIn("revoked", DiscoveryAttempt.objects.get().failure)
        self.assertEqual(self.remote.auth_attempts, 0)

    def test_unreachable_server_has_a_distinct_sanitized_failure(self) -> None:
        self.remote.close()
        result = self.check()
        self.assertEqual(result.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("could not reach the SSH service", result.failure)
        self.assertNotIn(str(self.directory), result.failure)

    def test_rejected_agent_key_has_a_distinct_authentication_failure(self) -> None:
        self.start_agent()
        result = self.check(username="wrong-user")
        self.assertEqual(result.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("rejected the SSH credentials", result.failure)
        self.assertGreater(self.remote.auth_attempts, 0)
