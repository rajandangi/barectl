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
from dataclasses import replace
from pathlib import Path
from typing import ClassVar, override
from unittest import mock, skipUnless

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, User
from django.test import TestCase, override_settings, tag
from django.utils.html import escape
from django_tasks_db.models import DBTaskResult
from paramiko import ECDSAKey

from dashboard.tests import TEST_MANIFEST
from servers.models import Server
from servers.registration import remove_server
from servers.ssh_config import resolve_alias

from . import ssh
from .fakes import PACKAGE_QUERY, UNIT_QUERY, current, observed, run_worker
from .models import (
    ComponentObservation,
    DiscoveryAttempt,
    DiscoverySnapshot,
    NginxSiteObservation,
    PhpFpmPoolObservation,
)
from .snapshot import CollectedSnapshot, ServiceUnit

SETTINGS = ("HOST", "PORT", "USER", "KEY", "KNOWN_HOSTS")
CONFIGURED = all(os.environ.get(f"BARECTL_SSH_TEST_{name}") for name in SETTINGS)
# Configuration, packages and running services that discovery must leave unchanged: a
# restarted service gets a new main process and activation time.
STATE_COMMAND = (
    "find /etc \"$HOME\" -xdev -printf '%p %s %T@ %m\\n' 2>/dev/null | sort | sha256sum; "
    "stat -c '%s %Y' /var/lib/dpkg/status; "
    "systemctl show -p Id -p MainPID -p ActiveEnterTimestamp "
    "$(systemctl list-units --type=service --state=running --no-legend --plain | cut -d' ' -f1)"
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
PHP_FPM_VERSION = re.compile(r"php([0-9.]+)-fpm")
NGINX_CONF = "/etc/nginx/nginx.conf"


def observed_state(collected: CollectedSnapshot) -> CollectedSnapshot:
    """What a snapshot records about the server, without the free space that changes."""
    filesystem = collected.filesystem
    if filesystem.value is None:
        return collected
    stable = replace(filesystem, value=filesystem.value._replace(avail_bytes=0))
    return replace(collected, filesystem=stable)


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
        # Whatever a test discovers, the server's configuration and packages stay as they were.
        self.addCleanup(self.assert_remote_unchanged, self.remote_state())

    def assert_remote_unchanged(self, before: str) -> None:
        self.assertEqual(self.remote_state(), before, "Discovery changed the server")

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
        known_hosts = Path(setting("KNOWN_HOSTS"))
        trust_before = known_hosts.read_bytes()
        self.write_config(known_hosts)
        attempt = self.discover()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
        collected = current(attempt.server).collected
        release = observed(collected.os)
        self.assertEqual((release.id, release.version_id), ("ubuntu", "24.04"))
        self.assertEqual(collected.os.source, ("/etc/os-release",))
        self.assertEqual(collected.architecture.outcome, "observed")
        architecture = observed(collected.architecture)
        self.assertTrue(architecture)
        self.assertEqual(collected.architecture.source, ("uname -m",))
        self.assertEqual(collected.cpu_count.outcome, "observed")
        self.assertGreater(observed(collected.cpu_count), 0)
        self.assertEqual(collected.memory_bytes.outcome, "observed")
        self.assertGreater(observed(collected.memory_bytes), 0)
        self.assertEqual(collected.filesystem.outcome, "observed")
        filesystem = observed(collected.filesystem)
        page = self.client.get(f"/servers/{attempt.server.pk}/")
        self.assertContains(page, "Ubuntu 24.04")
        self.assertContains(page, architecture)
        self.assertContains(page, f"{collected.cpu_count.value} available")
        self.assertContains(page, f"({collected.memory_bytes.value} bytes)")
        self.assertContains(page, f"({filesystem.size_bytes} bytes)")
        self.assertContains(page, attempt.host_key)
        self.assertEqual(known_hosts.read_bytes(), trust_before)

    @staticmethod
    def ground_truth_units(
        units: dict[str, ssh.CommandResult],
    ) -> dict[str, ServiceUnit | None]:
        """The expected states per queried unit, or None when systemd did not answer."""
        states: dict[str, ServiceUnit | None] = {}
        for unit, result in units.items():
            if result.exit_status != 0:
                states[unit] = None
                continue
            props = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
            states[unit] = ServiceUnit(
                props["Id"],
                props["LoadState"],
                props["ActiveState"],
                props["SubState"],
                props.get("UnitFileState", ""),
            )
        return states

    @staticmethod
    def display_line(unit: ServiceUnit) -> str:
        """The line the page shows for a unit's states."""
        if unit.load_state == "not-found":
            return f"{unit.name} not found"
        line = f"{unit.name} {unit.active_state} ({unit.sub_state})"
        return f"{line}, {unit.unit_file_state}" if unit.unit_file_state else line

    @staticmethod
    def ground_truth_installed(shell: ssh.RemoteShell) -> dict[str, str]:
        """The installed package lines by package name, as the dpkg database lists them."""
        # Installed records ("ii", or "hi" when held) have state "i", or "W"/"t" with
        # triggers outstanding; apt-known packages are not installed.
        installed: dict[str, str] = {}
        for line in shell.run(PACKAGE_QUERY).stdout.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[2][1] in "iWt":
                installed[parts[0]] = f"{parts[0]} {parts[1]}"
        return installed

    @staticmethod
    def ground_truth_matched(installed: dict[str, str]) -> dict[str, list[str]]:
        """Each component's installed package names."""
        return {
            component: sorted(name for name in installed if pattern.fullmatch(name))
            for component, pattern in COMPONENT_PACKAGES.items()
        }

    @staticmethod
    def ground_truth_clusters(shell: ssh.RemoteShell) -> list[str]:
        """Each PostgreSQL cluster's unit, from postgresql-common's own cluster listing.

        pg_lsclusters lists versions in numeric order and clusters by name; only its
        version and cluster columns are used, which it reads from /etc/postgresql.
        """
        result = shell.run("pg_lsclusters --no-header")
        if result.exit_status == 127:
            return []
        units = []
        for line in result.stdout.splitlines():
            version, cluster = line.split()[:2]
            units.append(f"postgresql@{version}-{cluster}.service")
        return units

    def test_service_observations_match_the_server(self) -> None:
        """Persisted service observations agree with read-only ground truth.

        The expected values are parsed here, independently of the discovery collectors,
        from commands run through a separate trusted connection.
        """
        self.write_config(Path(setting("KNOWN_HOSTS")))
        with ssh.connect(resolve_alias(str(self.config), "disposable")) as shell:
            installed = self.ground_truth_installed(shell)
            matched = self.ground_truth_matched(installed)
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
            # PostgreSQL's umbrella unit is followed by each cluster's unit.
            if "postgresql" in expected_units:
                expected_units["postgresql"] += self.ground_truth_clusters(shell)
            unit_names = sorted({unit for units in expected_units.values() for unit in units})
            unit_results = {unit: shell.run(UNIT_QUERY.format(unit)) for unit in unit_names}
        expected_states = self.ground_truth_units(unit_results)
        attempt = self.discover()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
        snapshot = current(attempt.server)
        rows = {row.component.value: row for row in snapshot.collected.components}
        self.assertEqual(set(rows), set(COMPONENT_PACKAGES))
        for component in COMPONENT_PACKAGES:
            row = rows[component]
            packages = [f"{package.name} {package.version}" for package in row.package.value]
            expected_packages = sorted(installed[name] for name in matched[component])
            self.assertEqual(row.package.source, (PACKAGE_QUERY,))
            self.assertEqual(packages, expected_packages)
            self.assertEqual(row.package.outcome, "observed" if expected_packages else "absent")
            if component not in expected_units:
                self.assertEqual((row.service.outcome, row.service.value), ("absent", ()))
            elif all(expected_states[unit] is not None for unit in expected_units[component]):
                self.assertEqual(row.service.outcome, "observed")
                self.assertEqual(
                    list(row.service.value),
                    [expected_states[unit] for unit in expected_units[component]],
                )
            else:
                # systemd did not answer, so the state is uninspectable, not absent.
                self.assertEqual((row.service.outcome, row.service.value), ("unsupported", ()))
            if component == "postgresql" and component in expected_units:
                # The cluster listing is recorded before the unit query.
                self.assertEqual(row.service.source[0], "ls -1b /etc/postgresql")
        # The server services view renders the observations with provenance and time.
        page = self.client.get(f"/servers/{attempt.server.pk}/")
        self.assertContains(page, 'aria-labelledby="web-stack-heading"')
        self.assertContains(page, "<code>dpkg-query -W")
        for row in rows.values():
            packages = [f"{package.name} {package.version}" for package in row.package.value]
            units = [self.display_line(unit) for unit in row.service.value]
            for line in packages + units:
                self.assertContains(page, line)
        self.assertContains(page, f'datetime="{snapshot.collected_at.isoformat()}"')

    @staticmethod
    def truth_verdict(outcomes: set[str], *, listed_empty: bool) -> str:
        """The documented collection outcome, from the outcomes of what was inspected."""
        if "observed" in outcomes:
            return "observed"
        uninspected = outcomes - {"absent"}
        if uninspected == {"inaccessible"}:
            return "inaccessible"
        if uninspected:
            return "unsupported"
        return "observed" if listed_empty else "absent"

    @staticmethod
    def truth_unread(shell: ssh.RemoteShell, path: str, *, missing: str) -> str:
        """Why a path could not be read, judged by the SSH user's own permissions.

        ``missing`` is the outcome when the path does not exist: absent for an entry its
        directory listed, unsupported for a directory Barectl expected to find.
        """
        if shell.run(f"test -e {path}").exit_status == 0:
            return "inaccessible"
        parent = path.rpartition("/")[0]
        return missing if shell.run(f"test -x {parent}").exit_status == 0 else "inaccessible"

    @classmethod
    def truth_include(cls, shell: ssh.RemoteShell, path: str, line: str) -> str | None:
        """Why the main configuration file does not load a directory, or None when it does.

        A line-based check for the stock include line, ground truth for the stock
        configuration rather than a second implementation of the supported grammar.
        """
        content = shell.run(f"cat {path}")
        if content.exit_status != 0:
            return cls.truth_unread(shell, path, missing="unsupported")
        lines = {raw.split("#", 1)[0].strip() for raw in content.stdout.splitlines()}
        return None if line in lines else "unsupported"

    @classmethod
    def ground_truth_sites(
        cls, shell: ssh.RemoteShell, matched: dict[str, list[str]]
    ) -> tuple[str, set[tuple[object, ...]]]:
        """The expected site directory verdict and per-site rows, read independently.

        A simple line-based parse of the same safe fields: this is ground truth for
        ordinary site files, not a second implementation of the supported grammar.
        """
        # Site files are read only when dpkg shows Nginx installed.
        if not matched["nginx"]:
            return "absent", set()
        unloaded = cls.truth_include(shell, NGINX_CONF, f"include {SITE_DIR}/*;")
        if unloaded is not None:
            return unloaded, set()
        listing = shell.run(f"ls -1b {SITE_DIR}")
        if listing.exit_status != 0:
            return cls.truth_unread(shell, SITE_DIR, missing="unsupported"), set()
        rows: set[tuple[object, ...]] = set()
        for name in listing.stdout.splitlines():
            content = shell.run(f"cat {SITE_DIR}/{name}")
            if content.exit_status != 0:
                rows.add(
                    (name, (), (), cls.truth_unread(shell, f"{SITE_DIR}/{name}", missing="absent"))
                )
                continue
            rows.add((name, *cls._site_file_truth(content.stdout)))
        status = cls.truth_verdict({str(row[3]) for row in rows}, listed_empty=not rows)
        return status, rows

    @staticmethod
    def _site_file_truth(content: str) -> tuple[tuple[str, ...], tuple[str, ...], str]:
        """One site file's server names, listen addresses and outcome, parsed by line."""
        names: list[str] = []
        listens: list[str] = []
        servers = 0
        for line in content.splitlines():
            stripped = line.split("#", 1)[0].strip()
            parts = stripped.split()
            if parts[:2] == ["server", "{"]:
                servers += 1
            elif len(parts) >= 2 and parts[0] == "listen":
                listens.append(parts[1].rstrip(";"))
            elif len(parts) >= 2 and parts[0] == "server_name":
                names.extend(
                    token.rstrip(";").strip("'\"")
                    for token in parts[1:]
                    if token.rstrip(";").strip("'\"")
                )
        if not servers:
            return (), (), "unsupported"
        return tuple(dict.fromkeys(names)), tuple(dict.fromkeys(listens)), "observed"

    @staticmethod
    def _pool_truth_add(
        pools: list[tuple[str, str]], current: str | None, listen: str | None
    ) -> None:
        if current is not None and current.lower() != "global":
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
                    listen = value.strip().strip("'\"").replace("$pool", current)
        cls._pool_truth_add(pools, current, listen)
        return pools

    @classmethod
    def ground_truth_pools(
        cls, shell: ssh.RemoteShell, matched: dict[str, list[str]]
    ) -> tuple[str, set[tuple[object, ...]]]:
        """The expected pool tree verdict and per-pool rows, read independently."""
        # Pools are read only for the PHP versions of installed PHP-FPM packages.
        if not matched["php-fpm"]:
            return "absent", set()
        versions = [
            match.group(1)
            for name in matched["php-fpm"]
            if (match := PHP_FPM_VERSION.fullmatch(name))
        ]
        if not versions:
            return "unsupported", set()
        rows: set[tuple[object, ...]] = set()
        outcomes: set[str] = set()
        listed = False
        for version in versions:
            pool_dir = f"{PHP_DIR}/{version}/fpm/pool.d"
            unloaded = cls.truth_include(
                shell, f"{PHP_DIR}/{version}/fpm/php-fpm.conf", f"include={pool_dir}/*.conf"
            )
            if unloaded is not None:
                outcomes.add(unloaded)
                continue
            entries = shell.run(f"ls -1b {pool_dir}")
            if entries.exit_status != 0:
                outcomes.add(cls.truth_unread(shell, pool_dir, missing="unsupported"))
                continue
            listed = True
            for file in entries.stdout.splitlines():
                if not file.endswith(".conf"):
                    continue
                content = shell.run(f"cat {pool_dir}/{file}")
                if content.exit_status != 0:
                    outcomes.add(cls.truth_unread(shell, f"{pool_dir}/{file}", missing="absent"))
                    continue
                for name, listen in cls._pool_file_truth(content.stdout):
                    rows.add((version, name, listen, "observed" if listen else "unsupported"))
        outcomes |= {str(row[3]) for row in rows}
        return cls.truth_verdict(outcomes, listed_empty=listed), rows

    def assert_sites_and_pools_match(
        self,
        collected: CollectedSnapshot,
        sites: tuple[str, set[tuple[object, ...]]],
        pools: tuple[str, set[tuple[object, ...]]],
    ) -> None:
        self.assertEqual(collected.nginx_site_files.outcome, sites[0])
        self.assertEqual(
            {
                (row.name, row.server_names, row.listens, row.outcome)
                for row in collected.nginx_site_files.value
            },
            sites[1],
        )
        self.assertEqual(collected.php_fpm_pools.outcome, pools[0])
        self.assertEqual(
            {
                (row.version, row.name, row.listen, row.outcome)
                for row in collected.php_fpm_pools.value
            },
            pools[1],
        )

    def test_site_and_pool_observations_match_the_server(self) -> None:
        """Persisted site and pool rows agree with read-only ground truth.

        A second discovery replaces the rows without duplicates.
        """
        self.write_config(Path(setting("KNOWN_HOSTS")))
        with ssh.connect(resolve_alias(str(self.config), "disposable")) as shell:
            matched = self.ground_truth_matched(self.ground_truth_installed(shell))
            sites = self.ground_truth_sites(shell, matched)
            pools = self.ground_truth_pools(shell, matched)
        attempt = self.discover()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
        snapshot = DiscoverySnapshot.objects.get()
        self.assert_sites_and_pools_match(current(attempt.server).collected, sites, pools)

        # A second discovery replaces the rows without duplicates.
        self.client.post(f"/servers/{attempt.server.pk}/verify/")
        run_worker()
        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        self.assertNotEqual(DiscoverySnapshot.objects.get().pk, snapshot.pk)
        refreshed = current(attempt.server).collected
        self.assert_sites_and_pools_match(refreshed, sites, pools)
        page = self.client.get(f"/servers/{attempt.server.pk}/")
        self.assertContains(page, 'aria-labelledby="nginx-site-files-heading"')
        self.assertContains(page, 'aria-labelledby="php-fpm-pools-heading"')
        # Without an installed Nginx package, the source is the dpkg query.
        self.assertContains(
            page, f"from <code>{escape(refreshed.nginx_site_files.source[0])}</code>"
        )
        for site in refreshed.nginx_site_files.value:
            for name in site.server_names:
                self.assertContains(page, name)
        for pool in refreshed.php_fpm_pools.value:
            self.assertContains(page, f"<code>{pool.name}</code> (PHP {pool.version})")

    def test_a_fresh_database_rediscovers_the_same_observations(self) -> None:
        """Observed state comes from the server, not from anything Barectl stored before."""
        self.write_config(Path(setting("KNOWN_HOSTS")))
        attempt = self.discover()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
        observed = observed_state(current(attempt.server).collected)
        host_key = attempt.host_key

        # Nothing Barectl recorded about the server survives: registration, attempts, the
        # snapshot and its observations, and the worker's task records.
        remove_server(attempt.server)
        DBTaskResult.objects.all().delete()
        for model in (
            Server,
            DiscoveryAttempt,
            DiscoverySnapshot,
            ComponentObservation,
            NginxSiteObservation,
            PhpFpmPoolObservation,
            DBTaskResult,
        ):
            self.assertFalse(model.objects.exists(), model.__name__)

        attempt = self.discover()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
        self.assertEqual(observed_state(current(attempt.server).collected), observed)
        self.assertEqual(attempt.host_key, host_key)

    def test_limited_permissions_give_partial_results(self) -> None:
        """A file the SSH user cannot read is inaccessible; the rest is still observed."""
        self.write_config(Path(setting("KNOWN_HOSTS")))
        with ssh.connect(resolve_alias(str(self.config), "disposable")) as shell:
            matched = self.ground_truth_matched(self.ground_truth_installed(shell))
            sites = self.ground_truth_sites(shell, matched)
        denied = {str(row[0]) for row in sites[1] if row[3] == "inaccessible"}
        if not denied:
            self.skipTest("Add an Nginx site file the SSH user cannot read; see the docs")
        attempt = self.discover()
        # Barectl never escalates, so the attempt succeeds with partial results.
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
        collected = current(attempt.server).collected
        # Everything the SSH user can read is still observed.
        self.assertEqual(
            [collected.os.outcome, *(observation.outcome for observation in collected.capacity)],
            ["observed"] * 5,
        )
        nginx = next(row for row in collected.components if row.component == "nginx")
        self.assertEqual(nginx.package.outcome, "observed")
        self.assertEqual(collected.nginx_site_files.outcome, sites[0])
        observed = {str(row[0]) for row in sites[1] if row[3] == "observed"}
        self.assertTrue(observed, "Keep a readable site file, such as the stock default")
        rows = {row.name: row for row in collected.nginx_site_files.value}
        self.assertEqual({name for name, row in rows.items() if row.observed}, observed)
        page = self.client.get(f"/servers/{attempt.server.pk}/")
        activity = self.client.get("/activity/")
        for name in denied:
            row = rows[name]
            self.assertEqual(row.outcome, "inaccessible")
            self.assertTrue(row.warning)
            self.assertContains(page, escape(row.warning))
            self.assertContains(activity, escape(row.warning))

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
