"""Acceptance against a real, disposable Ubuntu 24.04 SSH server.

Excluded from routine runs: the tests skip unless the server is configured through these
environment variables, and are tagged ``ssh``. See docs/ssh-connections.md.

- ``BARECTL_SSH_TEST_HOST`` and ``BARECTL_SSH_TEST_PORT``: the server's SSH endpoint.
- ``BARECTL_SSH_TEST_USER``: an unprivileged account that accepts ``BARECTL_SSH_TEST_KEY``.
- ``BARECTL_SSH_TEST_KEY``: a private key file without a passphrase.
- ``BARECTL_SSH_TEST_KNOWN_HOSTS``: a known_hosts file with the server's key, obtained
  through a trusted channel rather than by scanning the network.

Never point these at a server that matters: the tests connect with the given account.
"""

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import ClassVar, override
from unittest import mock, skipUnless

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, User
from django.test import TestCase, override_settings, tag
from paramiko import ECDSAKey

from dashboard.tests import TEST_MANIFEST
from servers.models import Server
from servers.ssh_config import resolve_alias

from . import ssh
from .models import DiscoveryAttempt, DiscoverySnapshot
from .tests import run_worker

SETTINGS = ("HOST", "PORT", "USER", "KEY", "KNOWN_HOSTS")
CONFIGURED = all(os.environ.get(f"BARECTL_SSH_TEST_{name}") for name in SETTINGS)
# Configuration and packages that discovery must leave unchanged.
STATE_COMMAND = (
    "find /etc \"$HOME\" -xdev -printf '%p %s %T@ %m\\n' 2>/dev/null | sort | sha256sum; "
    "stat -c '%s %Y' /var/lib/dpkg/status"
)


def setting(name: str) -> str:
    return os.environ[f"BARECTL_SSH_TEST_{name}"]


@tag("ssh")
@skipUnless(CONFIGURED, "Set BARECTL_SSH_TEST_* to run against a disposable server")
class DisposableServerTests(TestCase):
    user: ClassVar[User]
    directory: Path
    config: Path

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.user = get_user_model().objects.create_user("operator")
        for codename in ("view_server", "add_server", "add_discoveryattempt"):
            cls.user.user_permissions.add(Permission.objects.get(codename=codename))

    @override
    def setUp(self) -> None:
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.config = self.directory / "config"
        self.enterContext(
            override_settings(SSH_CONFIG_PATH=str(self.config), VITE_MANIFEST_PATH=TEST_MANIFEST)
        )
        # Only the agent a test starts may supply keys.
        self.enterContext(mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": ""}))
        self.client.force_login(self.user)

    def write_config(self, known_hosts: Path, *, identity: bool = True) -> None:
        lines = [
            "Host disposable",
            f"  HostName {setting('HOST')}",
            f"  Port {setting('PORT')}",
            f"  User {setting('USER')}",
            f"  UserKnownHostsFile {known_hosts}",
            # Ignored: Barectl never disables host key checking.
            "  StrictHostKeyChecking no",
        ]
        if identity:
            lines.append(f"  IdentityFile {setting('KEY')}")
        self.config.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def remote_state(self) -> str:
        """Fingerprint remote configuration through a separate trusted connection."""
        self.write_config(Path(setting("KNOWN_HOSTS")))
        with ssh.connect(resolve_alias(str(self.config), "disposable")) as shell:
            result = shell.run(STATE_COMMAND)
        self.assertEqual(result.exit_status, 0)
        return result.stdout

    def discover(self) -> DiscoveryAttempt:
        self.client.post("/servers/add/", {"name": "Disposable", "ssh_alias": "disposable"})
        run_worker()
        return DiscoveryAttempt.objects.get(server=Server.objects.get(name="Disposable"))

    def test_trusted_server_is_verified_without_remote_changes(self) -> None:
        before = self.remote_state()
        known_hosts = Path(setting("KNOWN_HOSTS"))
        trust_before = known_hosts.read_bytes()
        self.write_config(known_hosts)
        attempt = self.discover()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
        snapshot = DiscoverySnapshot.objects.get()
        self.assertEqual((snapshot.os_id, snapshot.os_version_id), ("ubuntu", "24.04"))
        self.assertEqual(snapshot.os_source, "/etc/os-release")
        self.assertEqual(snapshot.arch_status, "observed")
        self.assertTrue(snapshot.arch_value)
        self.assertEqual(snapshot.arch_source, "uname -m")
        self.assertEqual(snapshot.cpu_status, "observed")
        self.assertIsNotNone(snapshot.cpu_count)
        self.assertGreater(snapshot.cpu_count or 0, 0)
        self.assertEqual(snapshot.memory_status, "observed")
        self.assertIsNotNone(snapshot.memory_bytes)
        self.assertGreater(snapshot.memory_bytes or 0, 0)
        self.assertEqual(snapshot.filesystem_status, "observed")
        self.assertIsNotNone(snapshot.filesystem_size_bytes)
        self.assertIsNotNone(snapshot.filesystem_avail_bytes)
        page = self.client.get(f"/servers/{attempt.server.pk}/")
        self.assertContains(page, "Ubuntu 24.04")
        self.assertContains(page, snapshot.arch_value)
        self.assertContains(page, f"{snapshot.cpu_count} available")
        self.assertContains(page, f"({snapshot.memory_bytes} bytes)")
        self.assertContains(page, f"({snapshot.filesystem_size_bytes} bytes)")
        self.assertContains(page, attempt.host_key)
        self.assertEqual(known_hosts.read_bytes(), trust_before)
        self.assertEqual(self.remote_state(), before)

    def test_unknown_host_key_is_rejected(self) -> None:
        empty = self.directory / "known_hosts"
        empty.touch()
        self.write_config(empty)
        attempt = self.discover()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("does not trust the host key presented for disposable", attempt.failure)
        self.assertEqual(empty.read_bytes(), b"")
        self.assertFalse(DiscoverySnapshot.objects.exists())

    def test_changed_host_key_is_rejected(self) -> None:
        changed = self.directory / "known_hosts"
        pattern = Path(setting("KNOWN_HOSTS")).read_text(encoding="utf-8").split()[0]
        # A different key of a type the server offers, recorded for the same host.
        changed.write_text(
            f"{pattern} ecdsa-sha2-nistp256 {ECDSAKey.generate().get_base64()}\n",
            encoding="utf-8",
        )
        self.write_config(changed)
        attempt = self.discover()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("presented a different host key", attempt.failure)

    @skipUnless(shutil.which("ssh-agent") and shutil.which("ssh-add"), "OpenSSH agent needed")
    def test_agent_key_authenticates(self) -> None:
        socket_dir = Path(self.enterContext(tempfile.TemporaryDirectory(dir="/tmp")))
        sock = socket_dir / "agent"
        agent = subprocess.Popen(  # noqa: S603 - fixed arguments
            ["ssh-agent", "-D", "-a", str(sock)],  # noqa: S607 - found on PATH above
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(agent.wait)
        self.addCleanup(agent.terminate)
        deadline = time.monotonic() + 5
        while not sock.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.enterContext(mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": str(sock)}))
        subprocess.run(  # noqa: S603 - fixed arguments
            ["ssh-add", setting("KEY")],  # noqa: S607 - found on PATH above
            check=True,
            capture_output=True,
        )
        # No IdentityFile: the key is available only through the agent.
        self.write_config(Path(setting("KNOWN_HOSTS")), identity=False)
        with mock.patch.dict(os.environ, {"HOME": str(self.directory)}):
            attempt = self.discover()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
