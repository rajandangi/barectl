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
import re
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
from .tests import PACKAGE_QUERY, UNIT_QUERY, run_worker

SETTINGS = ("HOST", "PORT", "USER", "KEY", "KNOWN_HOSTS")
CONFIGURED = all(os.environ.get(f"BARECTL_SSH_TEST_{name}") for name in SETTINGS)
# Configuration and packages that discovery must leave unchanged.
STATE_COMMAND = (
    "find /etc \"$HOME\" -xdev -printf '%p %s %T@ %m\\n' 2>/dev/null | sort | sha256sum; "
    "stat -c '%s %Y' /var/lib/dpkg/status"
)
# The documented component patterns, stated independently of the collector.
COMPONENT_PACKAGES = {
    "nginx": re.compile(r"nginx"),
    "php-fpm": re.compile(r"php[0-9.]*-fpm"),
    "mariadb": re.compile(r"mariadb-server(-core)?(-[0-9.]+)?"),
    "postgresql": re.compile(r"postgresql(-[0-9.]+)?"),
}
# The documented site and pool locations, stated independently of the collector.
SITE_DIR = "/etc/nginx/sites-enabled"
PHP_DIR = "/etc/php"


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
        self.assertGreater(snapshot.cpu_count or 0, 0)
        self.assertEqual(snapshot.memory_status, "observed")
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

    @staticmethod
    def ground_truth_unit_lines(units: dict[str, ssh.CommandResult]) -> dict[str, str | None]:
        """The expected display line per queried unit, or None when systemd did not answer."""
        lines: dict[str, str | None] = {}
        for unit, result in units.items():
            if result.exit_status != 0:
                lines[unit] = None
                continue
            props = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
            if props.get("LoadState") == "not-found":
                lines[unit] = f"{props['Id']} not found"
                continue
            state = f"{props['Id']} {props['ActiveState']} ({props['SubState']})"
            if props.get("UnitFileState"):
                state += f", {props['UnitFileState']}"
            lines[unit] = state
        return lines

    def test_service_observations_match_the_server(self) -> None:
        """Persisted service observations agree with read-only ground truth.

        The expected values are parsed here, independently of the discovery collectors,
        from commands run through a separate trusted connection.
        """
        self.write_config(Path(setting("KNOWN_HOSTS")))
        with ssh.connect(resolve_alias(str(self.config), "disposable")) as shell:
            dpkg = shell.run(PACKAGE_QUERY)
            # Installed records ("ii", or "hi" when held) have state "i", or "W"/"t" with
            # triggers outstanding; apt-known packages are not installed.
            installed: dict[str, str] = {}
            for line in dpkg.stdout.splitlines():
                parts = line.split()
                if len(parts) == 3 and parts[2][1] in "iWt":
                    installed[parts[0]] = f"{parts[0]} {parts[1]}"
            matched = {
                component: sorted(name for name in installed if pattern.fullmatch(name))
                for component, pattern in COMPONENT_PACKAGES.items()
            }
            # The units discovery queries: one fixed unit per component, except PHP-FPM,
            # which gets one unit per installed package, named after it.
            expected_units = {
                component: (
                    [f"{name}.service" for name in packages]
                    if component == "php-fpm"
                    else [f"{component}.service"]
                )
                for component, packages in matched.items()
                if packages
            }
            unit_names = sorted({unit for units in expected_units.values() for unit in units})
            unit_results = {unit: shell.run(UNIT_QUERY.format(unit)) for unit in unit_names}
        expected_unit_lines = self.ground_truth_unit_lines(unit_results)
        attempt = self.discover()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
        rows = {row.component: row for row in DiscoverySnapshot.objects.get().services.all()}
        self.assertEqual(set(rows), set(COMPONENT_PACKAGES))
        for component in COMPONENT_PACKAGES:
            row = rows[component]
            expected_packages = sorted(installed[name] for name in matched[component])
            self.assertEqual(row.package_source, PACKAGE_QUERY)
            self.assertEqual(row.packages.splitlines(), expected_packages)
            self.assertEqual(row.package_status, "observed" if expected_packages else "absent")
            if component not in expected_units:
                self.assertEqual((row.service_status, row.units), ("absent", ""))
            elif all(expected_unit_lines[unit] is not None for unit in expected_units[component]):
                self.assertEqual(row.service_status, "observed")
                self.assertEqual(
                    row.units.splitlines(),
                    [expected_unit_lines[unit] for unit in expected_units[component]],
                )
            else:
                # systemd did not answer, so the state is uninspectable, not absent.
                self.assertEqual((row.service_status, row.units), ("unsupported", ""))
        # The server services view renders the observations with provenance and time.
        page = self.client.get(f"/servers/{attempt.server.pk}/")
        self.assertContains(page, 'aria-labelledby="services-heading"')
        self.assertContains(page, "<code>dpkg-query -W")
        for row in rows.values():
            for line in row.packages.splitlines() + row.units.splitlines():
                self.assertContains(page, line)
        self.assertContains(
            page, f'datetime="{DiscoverySnapshot.objects.get().collected_at.isoformat()}"'
        )

    @staticmethod
    def ground_truth_sites(shell: ssh.RemoteShell) -> tuple[str, set[tuple[object, ...]]]:
        """The expected site directory verdict and per-site rows, read independently.

        A simple line-based parse of the same safe fields: this is ground truth for
        ordinary site files, not a second implementation of the supported grammar.
        """
        listing = shell.run(f"ls -1 {SITE_DIR}")
        if listing.exit_status != 0:
            if shell.run(f"test -e {SITE_DIR}").exit_status != 0:
                return "absent", set()
            return "inaccessible", set()
        rows: set[tuple[object, ...]] = set()
        for name in listing.stdout.splitlines():
            content = shell.run(f"cat {SITE_DIR}/{name}")
            if content.exit_status != 0:
                rows.add((name, (), (), "inaccessible"))
                continue
            names: list[str] = []
            listens: list[str] = []
            for line in content.stdout.splitlines():
                stripped = line.split("#", 1)[0].strip()
                parts = stripped.split()
                if len(parts) >= 2 and parts[0] == "listen":
                    listens.append(parts[1])
                elif len(parts) >= 2 and parts[0] == "server_name":
                    names.extend(token.strip("'\"") for token in parts[1:] if token.strip("'\""))
            if listens:
                rows.add(
                    (
                        name,
                        tuple(dict.fromkeys(names)),
                        tuple(dict.fromkeys(listens)),
                        "observed",
                    )
                )
        return "observed", rows

    @staticmethod
    def _pool_truth_add(
        pools: list[tuple[str, str]], current: str | None, listen: str | None
    ) -> None:
        if current is not None and current != "global":
            pools.append((current, listen or ""))

    @classmethod
    def _pool_file_truth(cls, content: str) -> list[tuple[str, str]]:
        """The (pool, listen) pairs of one pool file, parsed line by line."""
        pools: list[tuple[str, str]] = []
        current: str | None = None
        listen: str | None = None
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                cls._pool_truth_add(pools, current, listen)
                current = stripped[1:-1]
                listen = None
            elif "=" in stripped and current is not None:
                key, _, value = stripped.partition("=")
                if key.strip() == "listen":
                    listen = value.strip()
        cls._pool_truth_add(pools, current, listen)
        return pools

    @classmethod
    def ground_truth_pools(cls, shell: ssh.RemoteShell) -> tuple[str, set[tuple[object, ...]]]:
        """The expected pool tree verdict and per-pool rows, read independently."""
        listing = shell.run(f"ls -1 {PHP_DIR}")
        if listing.exit_status != 0:
            if shell.run(f"test -e {PHP_DIR}").exit_status != 0:
                return "absent", set()
            return "inaccessible", set()
        rows: set[tuple[object, ...]] = set()
        versions = [v for v in listing.stdout.splitlines() if v and v[0].isdigit()]
        for version in versions:
            pool_dir = f"{PHP_DIR}/{version}/fpm/pool.d"
            entries = shell.run(f"ls -1 {pool_dir}")
            if entries.exit_status != 0:
                continue
            for file in entries.stdout.splitlines():
                if not file.endswith(".conf"):
                    continue
                content = shell.run(f"cat {pool_dir}/{file}")
                if content.exit_status != 0:
                    continue
                for name, listen in cls._pool_file_truth(content.stdout):
                    rows.add((version, name, listen, "observed" if listen else "unsupported"))
        return "observed", rows

    def test_site_and_pool_observations_match_the_server(self) -> None:
        """Persisted site and pool rows agree with read-only ground truth.

        The observations are rediscovered from a fresh Barectl database against the same
        disposable server, proving they do not depend on prior Barectl provisioning, and
        a second discovery replaces the rows without duplicates.
        """
        self.write_config(Path(setting("KNOWN_HOSTS")))
        with ssh.connect(resolve_alias(str(self.config), "disposable")) as shell:
            site_status, site_rows = self.ground_truth_sites(shell)
            pool_status, pool_rows = self.ground_truth_pools(shell)
        attempt = self.discover()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
        snapshot = DiscoverySnapshot.objects.get()
        self.assertEqual(snapshot.sites_status, site_status)
        self.assertEqual(
            {
                (
                    row.name,
                    tuple(row.server_names.splitlines()),
                    tuple(row.listens.splitlines()),
                    row.status,
                )
                for row in snapshot.sites.all()
            },
            site_rows,
        )
        self.assertEqual(snapshot.pools_status, pool_status)
        self.assertEqual(
            {(row.version, row.name, row.listen, row.status) for row in snapshot.pools.all()},
            pool_rows,
        )
        # A fresh database rediscovered the same observations; a second discovery
        # replaces them without duplicates.
        self.client.post(f"/servers/{attempt.server.pk}/verify/")
        run_worker()
        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        current = DiscoverySnapshot.objects.get()
        self.assertEqual(current.sites.count(), snapshot.sites.count())
        self.assertEqual(current.pools.count(), snapshot.pools.count())
        self.assertEqual(
            {(row.version, row.name, row.listen) for row in current.pools.all()},
            {(row.version, row.name, row.listen) for row in snapshot.pools.all()},
        )
        page = self.client.get(f"/servers/{attempt.server.pk}/")
        self.assertContains(page, 'aria-labelledby="sites-heading"')
        self.assertContains(page, 'aria-labelledby="pools-heading"')
        self.assertContains(page, f"Read from <code>{SITE_DIR}</code>")
        for site in current.sites.all():
            for name in site.server_names.splitlines():
                self.assertContains(page, name)
        for pool in current.pools.all():
            self.assertContains(page, f"<code>{pool.name}</code> (PHP {pool.version})")

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
