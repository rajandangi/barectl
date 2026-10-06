"""docs/ssh-connections.md#acceptance-against-a-real-server

Never point these at a server that matters: the tests connect with the given account.
"""

import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import closing
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

from dashboard.testing import TEST_MANIFEST
from servers.models import Server
from servers.registration import remove_server

from . import ssh
from .fakes import PACKAGE_QUERY, UNIT_QUERY, current, observed, run_worker
from .models import (
    ComponentObservation,
    DiscoveryAttempt,
    DiscoverySnapshot,
    SiteObservation,
)
from .snapshot import CollectedSnapshot, ServiceUnit

SETTINGS = ("HOST", "PORT", "USER", "KEY", "KNOWN_HOSTS")
RELEASE = os.environ.get("BARECTL_SSH_TEST_RELEASE", "24.04")
CONFIGURED = all(os.environ.get(f"BARECTL_SSH_TEST_{name}") for name in SETTINGS)
# Configuration, packages and running services that discovery must leave unchanged: a
# restarted service gets a new main process and activation time.
# Each account's systemd user manager, user@<uid>.service, starts and stops with its SSH
# sessions, as pam_systemd runs it on Ubuntu servers; it is session state, not the server's.
STATE_COMMAND = (
    "find /etc \"$HOME\" -xdev -printf '%p %s %T@ %m\\n' 2>/dev/null | sort | sha256sum; "
    "stat -c '%s %Y' /var/lib/dpkg/status; "
    "systemctl show -p Id -p MainPID -p ActiveEnterTimestamp "
    "$(systemctl list-units --type=service --state=running --no-legend --plain | cut -d' ' -f1 "
    "| grep -v '^user@')"
)
# The documented component patterns, stated independently of the collector.
COMPONENT_PACKAGES = {
    "nginx": re.compile(r"nginx"),
    "php-fpm": re.compile(r"php[0-9.]*-fpm"),
    "mariadb": re.compile(r"mariadb-server(-core)?(-[0-9.]+)?"),
    "postgresql": re.compile(r"postgresql(-[0-9.]+)?"),
    "certbot": re.compile(r"certbot"),
}
# The one fixed unit each non-PHP component's observation queries.
COMPONENT_UNITS = {"certbot": "certbot.timer"}
# The documented site directory, stated independently of the collector.
SITE_DIR = "/etc/nginx/sites-enabled"


# A second Barectl installation: its own database, SSH configuration, key and trust file,
# run in a separate process. It registers the server through the dashboard, runs the worker,
# and prints what it discovered.
OTHER_INSTALLATION = """
import json
import os
import sys
from pathlib import Path

os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
from config import settings as configured

database, ssh_config, manifest = sys.argv[1:]
configured.DATABASES["default"]["NAME"] = database
configured.SSH_CONFIG_PATH = ssh_config
configured.VITE_MANIFEST_PATH = Path(manifest)
configured.VITE_DEV_SERVER_URL = ""
configured.ALLOWED_HOSTS = ["testserver"]

import django

django.setup()

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import Client

from discovery.fakes import current, run_worker
from discovery.models import DiscoveryAttempt
from discovery.test_remote import observed_state

call_command("migrate", verbosity=0)
user = get_user_model().objects.create_user("other-operator")
for codename in ("view_server", "add_server", "add_discoveryattempt"):
    user.user_permissions.add(Permission.objects.get(codename=codename))
client = Client()
client.force_login(user)
client.post("/servers/add/", {"name": "Disposable", "ssh_alias": "disposable"}, secure=True)
run_worker()
attempt = DiscoveryAttempt.objects.get()
page = client.get(f"/servers/{attempt.server.pk}/advanced/", secure=True)
print(json.dumps({
    "status": attempt.status,
    "failure": attempt.failure,
    "host_key": attempt.host_key,
    "page": page.status_code,
    "observed": repr(observed_state(current(attempt.server).collected)),
}))
"""


def observed_state(collected: CollectedSnapshot) -> CollectedSnapshot:
    """What a snapshot records about the server, without the free space that changes."""
    filesystem = collected.filesystem
    if filesystem.value is None:
        return collected
    stable = replace(filesystem, value=filesystem.value._replace(avail_bytes=0))
    return replace(collected, filesystem=stable)


def setting(name: str) -> str:
    return os.environ[f"BARECTL_SSH_TEST_{name}"]


class NativeShell:
    """Ground truth through the controller's OpenSSH client, independent of Barectl.

    One multiplexed OpenSSH connection carries every command, checked against the same
    trusted known_hosts file.
    """

    host_key = ""

    def __init__(self, directory: Path) -> None:
        self.control = directory / "native"

    def options(self) -> list[str]:
        return [
            "-F",
            os.devnull,
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={setting('KNOWN_HOSTS')}",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ControlMaster=auto",
            "-o",
            f"ControlPath={self.control}",
            "-o",
            "ControlPersist=60",
            "-i",
            setting("KEY"),
            "-p",
            setting("PORT"),
            "-l",
            setting("USER"),
            setting("HOST"),
        ]

    def run(self, command: str) -> ssh.CommandResult:
        result = subprocess.run(  # noqa: S603 - the tests' own commands
            ["ssh", *self.options(), command],  # noqa: S607 - OpenSSH on PATH
            capture_output=True,
            timeout=60,
            check=False,
        )
        return ssh.CommandResult(result.returncode, result.stdout.decode("utf-8", "replace"))

    def close(self) -> None:
        if self.control.exists():
            subprocess.run(  # noqa: S603 - fixed arguments
                ["ssh", *self.options()[:-1], "-O", "exit", setting("HOST")],  # noqa: S607
                capture_output=True,
                timeout=60,
                check=False,
            )


@tag("ssh")
@skipUnless(CONFIGURED, "Set BARECTL_SSH_TEST_* to run against a disposable server")
class DisposableServerTests(TestCase):
    user: ClassVar[User]
    baseline: str
    directory: Path
    config: Path

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.user = get_user_model().objects.create_user("operator")
        for codename in (
            "view_server",
            "add_server",
            "add_discoveryattempt",
            "view_siteobservation",
        ):
            cls.user.user_permissions.add(Permission.objects.get(codename=codename))

    @override
    def setUp(self) -> None:
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir="/tmp")))
        self.config = self.directory / "config"
        self.native = NativeShell(self.directory)
        self.addCleanup(self.native.close)
        self.enterContext(
            override_settings(SSH_CONFIG_PATH=str(self.config), VITE_MANIFEST_PATH=TEST_MANIFEST)
        )
        # Only the agent a test starts may supply keys.
        self.enterContext(mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": ""}))
        self.client.force_login(self.user)
        # Whatever a test discovers, the server's configuration and packages stay as they were.
        self.baseline = self.remote_state()
        self.addCleanup(self.assert_remote_unchanged)

    def assert_remote_unchanged(self) -> None:
        self.assertEqual(self.remote_state(), self.baseline, "Discovery changed the server")

    def change_fixture(self, script: str) -> None:
        """Change the server as its administrator would, outside Barectl and its SSH user.

        The change goes through ``docker exec``, and the unchanged-server check starts again
        from its result, so it still covers everything discovery does.
        """
        subprocess.run(  # noqa: S603 - the tests' own fixture scripts
            ["docker", "exec", setting("CONTAINER"), "sh", "-c", script],  # noqa: S607
            check=True,
            capture_output=True,
            timeout=60,
        )
        self.baseline = self.remote_state()

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
        result = self.native.run(STATE_COMMAND)
        self.assertEqual(result.exit_status, 0)
        return result.stdout

    def discover(self) -> DiscoveryAttempt:
        self.client.post("/servers/add/", {"name": "Disposable", "ssh_alias": "disposable"})
        run_worker()
        return DiscoveryAttempt.objects.get(server=Server.objects.get(name="Disposable"))

    def refresh(self, server: Server) -> DiscoveryAttempt:
        self.client.post(f"/servers/{server.pk}/verify/")
        run_worker()
        return DiscoveryAttempt.objects.filter(server=server).latest("queued_at", "pk")

    def test_trusted_server_is_verified_without_remote_changes(self) -> None:
        known_hosts = Path(setting("KNOWN_HOSTS"))
        trust_before = known_hosts.read_bytes()
        self.write_config(known_hosts)
        attempt = self.discover()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
        collected = current(attempt.server).collected
        release = observed(collected.os)
        self.assertEqual((release.id, release.version_id), ("ubuntu", RELEASE))
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
        page = self.client.get(f"/servers/{attempt.server.pk}/advanced/")
        self.assertContains(page, f"Ubuntu {RELEASE}")
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
        shell = self.native
        installed = self.ground_truth_installed(shell)
        matched = self.ground_truth_matched(installed)
        # The units discovery queries: one fixed unit per component, except PHP-FPM,
        # which gets one unit per installed package, named after it.
        expected_units = {
            component: (
                [f"{name}.service" for name in packages]
                if component == "php-fpm"
                else [COMPONENT_UNITS.get(component, f"{component}.service")]
            )
            for component, packages in matched.items()
            if packages
        }
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
        page = self.client.get(f"/servers/{attempt.server.pk}/advanced/")
        self.assertContains(page, 'aria-labelledby="web-stack-heading"')
        self.assertContains(page, "<code>dpkg-query -W")
        for row in rows.values():
            packages = [f"{package.name} {package.version}" for package in row.package.value]
            units = [self.display_line(unit) for unit in row.service.value]
            for line in packages + units:
                self.assertContains(page, line)
        self.assertContains(page, f'datetime="{snapshot.collected_at.isoformat()}"')

    def test_site_observations_match_the_server(self) -> None:
        """Persisted site rows agree with the collected sites, and refresh replaces them."""
        self.write_config(Path(setting("KNOWN_HOSTS")))
        attempt = self.discover()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
        snapshot = DiscoverySnapshot.objects.get()
        sites = current(attempt.server).collected.sites
        self.assertEqual(
            {
                (row.identifier, row.state, row.outcome, row.file, row.missing)
                for row in snapshot.sites.all().order_by("pk")
            },
            {
                (site.identifier, site.state, site.outcome, site.file, "\n".join(site.missing))
                for site in sites.value
            },
        )

        self.client.post(f"/servers/{attempt.server.pk}/verify/")
        run_worker()
        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        self.assertNotEqual(DiscoverySnapshot.objects.get().pk, snapshot.pk)
        refreshed = current(attempt.server).collected.sites
        self.assertEqual(refreshed.outcome, sites.outcome)
        # The server page no longer shows generic Nginx site file or PHP-FPM pool cards.
        page = self.client.get(f"/servers/{attempt.server.pk}/advanced/")
        self.assertNotContains(page, 'aria-labelledby="nginx-site-files-heading"')
        self.assertNotContains(page, 'aria-labelledby="php-fpm-pools-heading"')

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
            SiteObservation,
            DBTaskResult,
        ):
            self.assertFalse(model.objects.exists(), model.__name__)

        attempt = self.discover()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
        self.assertEqual(observed_state(current(attempt.server).collected), observed)
        self.assertEqual(attempt.host_key, host_key)

    @skipUnless(os.environ.get("BARECTL_SSH_TEST_SECOND_KEY"), "Set a second controller key")
    def test_an_independent_installation_reconstructs_the_same_view(self) -> None:
        """Two installations with their own databases and SSH access see the same server.

        Neither imports the other's records, and each keeps its own account and history.
        """
        other = self.directory / "other"
        other.mkdir()
        trust = other / "known_hosts"
        shutil.copyfile(setting("KNOWN_HOSTS"), trust)
        config = other / "config"
        config.write_text(
            "Host disposable\n"
            f"  HostName {setting('HOST')}\n"
            f"  Port {setting('PORT')}\n"
            f"  User {setting('USER')}\n"
            f"  IdentityFile {setting('SECOND_KEY')}\n"
            f"  UserKnownHostsFile {trust}\n",
            encoding="utf-8",
        )
        database = other / "db.sqlite3"
        process = subprocess.run(  # noqa: S603 - the test's own script
            [
                sys.executable,
                "-c",
                OTHER_INSTALLATION,
                str(database),
                str(config),
                str(TEST_MANIFEST),
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr[-3000:])
        theirs = json.loads(process.stdout.strip().splitlines()[-1])
        self.assertEqual(theirs["status"], DiscoveryAttempt.Status.SUCCEEDED, theirs["failure"])
        self.assertEqual(theirs["page"], 200)
        with closing(sqlite3.connect(database)) as records:
            users = records.execute("SELECT username FROM auth_user").fetchall()
            attempts = records.execute("SELECT count(*) FROM discovery_discoveryattempt")
            self.assertEqual((users, attempts.fetchone()), ([("other-operator",)], (1,)))

        # The other installation and its database are gone; this one needs neither.
        database.unlink()
        self.write_config(Path(setting("KNOWN_HOSTS")))
        attempt = self.discover()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
        self.assertEqual(
            repr(observed_state(current(attempt.server).collected)), theirs["observed"]
        )
        self.assertEqual(attempt.host_key, theirs["host_key"])
        self.assertFalse(get_user_model().objects.filter(username="other-operator").exists())
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)
        self.assertEqual(len(self.client.get("/activity/").context["attempts"]), 1)

    @skipUnless(os.environ.get("BARECTL_SSH_TEST_CONTAINER"), "Set the server's container")
    def test_external_changes_replace_observations_on_refresh(self) -> None:
        """Each refresh rereads the server: added, changed and removed foreign files show."""
        self.write_config(Path(setting("KNOWN_HOSTS")))
        attempt = self.discover()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
        server = attempt.server
        available = "/etc/nginx/sites-available/external"
        enabled = f"{SITE_DIR}/external"
        self.addCleanup(self.change_fixture, f"rm -f {enabled} {available}")
        changes = [
            (
                "added",
                (
                    "printf 'server {\\n    listen 8081;\\n    server_name added.test;\\n}\\n' "
                    f">{available} && ln -s ../sites-available/external {enabled}"
                ),
                ("added.test",),
            ),
            ("changed", f"sed -i s/added.test/changed.test/ {available}", ("changed.test",)),
            ("removed", f"rm {enabled} {available}", None),
        ]
        for change, script, names in changes:
            with self.subTest(change):
                self.change_fixture(script)
                attempt = self.refresh(server)
                self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
                collected = current(server).collected.sites
                blocked = {site.file: site for site in collected.value if site.file == enabled}
                if names is None:
                    self.assertFalse(blocked)
                else:
                    self.assertEqual(blocked[enabled].state, "not_following")
                    self.assertEqual(blocked[enabled].server_names, names)
                # Current rows replace the previous ones.
                self.assertEqual(SiteObservation.objects.count(), len(collected.value))
                self.assertEqual(DiscoverySnapshot.objects.count(), 1)

        # Without fresh evidence, the last snapshot is not presented as current.
        snapshot = DiscoverySnapshot.objects.get()
        self.write_config(self.directory / "missing")
        attempt = self.refresh(server)
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertEqual(DiscoverySnapshot.objects.get().pk, snapshot.pk)
        self.assertContains(
            self.client.get(f"/servers/{server.pk}/advanced/"), "may be out of date"
        )

    def test_limited_permissions_give_partial_results(self) -> None:
        """A file the SSH user cannot read is inaccessible; the rest is still observed."""
        self.write_config(Path(setting("KNOWN_HOSTS")))
        attempt = self.discover()
        # Barectl never escalates, so the attempt succeeds with partial results.
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED, attempt.failure)
        collected = current(attempt.server).collected
        self.assertEqual(
            [collected.os.outcome, *(observation.outcome for observation in collected.capacity)],
            ["observed"] * 5,
        )
        nginx = next(row for row in collected.components if row.component == "nginx")
        self.assertEqual(nginx.package.outcome, "observed")
        denied = [
            site
            for site in collected.sites.value
            if site.state == "not_following" and site.outcome == "inaccessible"
        ]
        if not denied:
            self.skipTest("Add an Nginx site file the SSH user cannot read; see the docs")
        page = self.client.get(f"/servers/{attempt.server.pk}/advanced/")
        for site in denied:
            self.assertContains(page, escape(site.file))

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
