"""The registration-to-result workflow through Django requests and the durable worker.

Real views, services, persistence, alias resolution and the ``db_worker`` command run;
only remote execution is substituted, at ``discovery.ssh.connect``.
"""

import datetime
import re
import signal
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import ClassVar, override
from unittest import mock

from django.core.management import call_command
from django.db import IntegrityError, transaction
from django.test import Client
from django.utils import timezone
from django_tasks_db.models import DBTaskResult

from servers.models import Server
from servers.ssh_config import ConnectionTarget
from servers.tests import HTMX_FRAGMENT, ControllerConfigTestCase

from . import services, ssh
from .models import ComponentObservation, DiscoveryAttempt, DiscoverySnapshot, WebStackComponent
from .services import (
    INTERRUPTED_FAILURE,
    STALE_AFTER,
    recover_stale_attempts,
    request_discovery,
)

UBUNTU = """\
PRETTY_NAME="Ubuntu 24.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.3 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
"""
MEMINFO = """\
MemTotal:        4024548 kB
MemFree:         1234567 kB
MemAvailable:    2345678 kB
"""
DF_OUTPUT = """\
      Size      Avail Target
 53689778176 48190049280 /
"""
# The package query and the service unit queries are fixed read-only commands. Fixtures
# reuse the exact output shapes recorded from Ubuntu 24.04 (docs/ssh-connections.md).
PACKAGE_QUERY = (
    "dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\\n' 'nginx' 'php*-fpm' "
    "'mariadb-server*' 'postgresql' 'postgresql-[0-9]*'"
)
UNIT_QUERY = "systemctl show {} -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState"
DPKG_OUTPUT = """\
mariadb-server 1:10.11.14-0ubuntu0.24.04.1 ii
mariadb-server-core 1:10.11.14-0ubuntu0.24.04.1 ii
nginx 1.24.0-2ubuntu7.18 ii
php-fpm  un
php8.3-fpm 8.3.6-0ubuntu0.24.04.11 ii
postgresql 16+257build1.1 ii
postgresql-16 16.15-0ubuntu0.24.04.1 ii
postgresql-16-jit-llvm  un
"""


def unit_report(
    unit: str, *, active: str = "active", sub: str = "running", file_state: str = "enabled"
) -> str:
    return (
        f"Id={unit}\nLoadState=loaded\nActiveState={active}\nSubState={sub}\n"
        f"UnitFileState={file_state}\n"
    )


# The main configuration files as the Ubuntu 24.04 packages install them, abridged. Each
# loads the Debian configuration directory Barectl reads.
NGINX_CONF_TEXT = """\
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;

events {
	worker_connections 768;
	# multi_accept on;
}

http {
	sendfile on;
	tcp_nopush on;
	types_hash_max_size 2048;
	include /etc/nginx/mime.types;
	default_type application/octet-stream;
	ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
	ssl_prefer_server_ciphers on;
	access_log /var/log/nginx/access.log;
	gzip on;

	##
	# Virtual Host Configs
	##

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}

#mail {
#	server {
#		listen     localhost:110;
#	}
#}
"""


def php_fpm_conf(version: str) -> str:
    return (
        ";;;;;;;;;;;;;;;;;;;;;\n; FPM Configuration ;\n;;;;;;;;;;;;;;;;;;;;;\n\n"
        f"[global]\n; Pid file\npid = /run/php/php{version}-fpm.pid\n"
        f"error_log = /var/log/php{version}-fpm.log\n\n"
        "; To configure the pools it is recommended to have one .conf file per\n"
        "; pool in the following directory:\n"
        f"include=/etc/php/{version}/fpm/pool.d/*.conf\n"
    )


HOST_KEY = "ssh-ed25519 SHA256:bZs0Sdo5mnU6ixaSbHkq9ZvXVsP1pxEmGZ0M8oPq3dE"
# The documented site and pool locations, stated independently of the collector.
SITE_DIR = "/etc/nginx/sites-enabled"
PHP_DIR = "/etc/php"
NGINX_CONF = "/etc/nginx/nginx.conf"


def fpm_conf_path(version: str) -> str:
    return f"{PHP_DIR}/{version}/fpm/php-fpm.conf"


# postgresql-common keeps each cluster's configuration in /etc/postgresql/<version>/<name>.
# The Ubuntu 24.04 postgresql package creates the "16/main" cluster, started through the
# postgresql.service umbrella unit (docs/ssh-connections.md).
PG_DIR = "/etc/postgresql"
CLUSTER_UNITS = "postgresql.service postgresql@16-main.service"


def cluster_conf(version: str, name: str) -> str:
    return f"{PG_DIR}/{version}/{name}/postgresql.conf"


def cluster_report(
    version: str,
    name: str,
    *,
    active: str = "active",
    sub: str = "running",
    file_state: str = "enabled-runtime",
) -> str:
    # Clusters started by the umbrella unit are enabled through the systemd generator's
    # runtime links; others report "disabled".
    return unit_report(
        f"postgresql@{version}-{name}.service", active=active, sub=sub, file_state=file_state
    )


# The umbrella unit stays "active (exited)" whether or not its clusters run.
UMBRELLA_REPORT = unit_report("postgresql.service", sub="exited")
UMBRELLA_LINE = "postgresql.service active (exited), enabled"
MAIN_LINE = "postgresql@16-main.service active (running), enabled-runtime"


READ_ONLY = re.compile(
    r"\A(cat|test -e|test -r|test -x) ("
    r"/etc/os-release|/usr/lib/os-release|/proc/meminfo"
    r"|/etc/nginx/nginx\.conf|/etc/php/[0-9.]+/fpm/php-fpm\.conf"
    r"|/etc/nginx/sites-enabled(/[A-Za-z0-9._-]+)?"
    r"|/etc/php(/[0-9.]+/fpm/pool\.d(/[A-Za-z0-9._-]+\.conf)?)?"
    r"|/etc/postgresql(/[0-9.]+)?"
    r")\Z"
    # Parent directories, checked to tell a missing path from a hidden one.
    r"|\Atest -x (/etc|/usr/lib|/proc|/etc/nginx|/etc/php(/[0-9.]+(/fpm)?)?)\Z"
    # PostgreSQL cluster directories and the configuration file that marks one.
    r"|\Atest -[eLdx] /etc/postgresql/[0-9.]+/[A-Za-z0-9._-]+(/postgresql\.conf)?\Z"
    r"|\Auname -m\Z"
    r"|\Anproc\Z"
    r"|\Adf -B1 --output=size,avail,target /\Z"
    rf"|\A{re.escape(PACKAGE_QUERY)}\Z"
    r"|\Asystemctl show \S+\.service(?: \S+\.service)*"
    r" -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState\Z"
    r"|\Als -1b (/etc/nginx/sites-enabled|/etc/php(/[0-9.]+/fpm/pool\.d)?|/etc/postgresql)\Z"
    r"|\Als -1bA /etc/postgresql/[0-9.]+\Z"
)


@dataclass
class FakeServer:
    """A managed server as seen through ``RemoteShell``, recording every command."""

    files: dict[str, str] = field(
        default_factory=lambda: {
            "/etc/os-release": UBUNTU,
            "/proc/meminfo": MEMINFO,
            NGINX_CONF: NGINX_CONF_TEXT,
            fpm_conf_path("8.3"): php_fpm_conf("8.3"),
            # Only the file's existence is checked; its contents are never read.
            cluster_conf("16", "main"): "",
        }
    )
    # Directory listings by path; a path that is listed exists, others do not. The
    # installed Nginx and PHP-FPM 8.3 packages come with their configuration directories.
    directories: dict[str, list[str]] = field(
        default_factory=lambda: {
            SITE_DIR: [],
            f"{PHP_DIR}/8.3/fpm/pool.d": [],
            PG_DIR: ["16"],
            f"{PG_DIR}/16": ["main"],
            f"{PG_DIR}/16/main": ["postgresql.conf"],
        }
    )
    unreadable: set[str] = field(default_factory=set)
    # Directories the SSH user may list but not search, so entries inside cannot be seen.
    unsearchable: set[str] = field(default_factory=set)
    # Symbolic links whose target does not exist: ``test -L`` sees them, ``test -e`` does not.
    dead_links: set[str] = field(default_factory=set)
    # Results for exact commands, checked before files.
    results: dict[str, ssh.CommandResult] = field(
        default_factory=lambda: {
            "uname -m": ssh.CommandResult(0, "x86_64\n"),
            "nproc": ssh.CommandResult(0, "4\n"),
            "df -B1 --output=size,avail,target /": ssh.CommandResult(0, DF_OUTPUT),
            PACKAGE_QUERY: ssh.CommandResult(0, DPKG_OUTPUT),
            UNIT_QUERY.format("nginx.service"): ssh.CommandResult(0, unit_report("nginx.service")),
            UNIT_QUERY.format("php8.3-fpm.service"): ssh.CommandResult(
                0, unit_report("php8.3-fpm.service")
            ),
            UNIT_QUERY.format("mariadb.service"): ssh.CommandResult(
                0, unit_report("mariadb.service")
            ),
            UNIT_QUERY.format(CLUSTER_UNITS): ssh.CommandResult(
                0, UMBRELLA_REPORT + "\n" + cluster_report("16", "main")
            ),
        }
    )
    failure: str = ""
    # Exit mid-task, as the worker does when an operator forces it to stop.
    interrupt: bool = False
    host_key: str = HOST_KEY
    targets: list[ConnectionTarget] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)

    @contextmanager
    def connect(self, target: ConnectionTarget) -> Iterator[ssh.RemoteShell]:
        self.targets.append(target)
        if self.failure:
            raise ssh.ConnectionFailed(self.failure)
        if self.interrupt:
            raise SystemExit(1)
        yield self

    def run(self, command: str) -> ssh.CommandResult:
        self.commands.append(command)
        if command in self.results:
            return self.results[command]
        if command.startswith(("ls -1b ", "ls -1bA ")):
            options, _, path = command.partition(" ")[2].partition(" ")
            if path in self.directories:
                # Without -A, ls omits names that start with ".".
                entries = [e for e in self.directories[path] if "A" in options or e[0] != "."]
                listing = "".join(f"{entry}\n" for entry in entries)
                return ssh.CommandResult(0, listing)
            return ssh.CommandResult(1, "")
        verb, _, path = command.rpartition(" ")
        if verb == "test -x":
            return ssh.CommandResult(1 if path in self.unsearchable else 0, "")
        hidden = path.rpartition("/")[0] in self.unsearchable
        known = path in self.files or path in self.unreadable or path in self.directories
        exists = known and not hidden
        readable = (path in self.files or path in self.directories) and not hidden
        if verb == "test -e":
            return ssh.CommandResult(0 if exists else 1, "")
        if verb == "test -L":
            return ssh.CommandResult(0 if path in self.dead_links and not hidden else 1, "")
        if verb == "test -d":
            return ssh.CommandResult(0 if path in self.directories and not hidden else 1, "")
        if verb == "test -r":
            return ssh.CommandResult(0 if readable else 1, "")
        if readable:
            return ssh.CommandResult(0, self.files[path])
        return ssh.CommandResult(1, "")


def run_worker() -> None:
    """Run the durable worker until the queue is empty, as `manage.py db_worker` does."""
    # The worker installs its own signal handlers; restore the test runner's afterwards.
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        call_command("db_worker", batch=True, startup_delay=False, interval=0, verbosity=0)
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


class DiscoveryTestCase(ControllerConfigTestCase):
    remote: FakeServer

    @override
    def setUp(self) -> None:
        super().setUp()
        self.remote = FakeServer()
        self.enterContext(mock.patch.object(ssh, "connect", self.remote.connect))

    def sign_in_with(self, *codenames: str) -> None:
        self.grant(*codenames)
        self.client.force_login(self.user)

    def run_worker(self) -> None:
        run_worker()

    def register(self, name: str = "Web", alias: str = "web.example.com") -> Server:
        self.sign_in_with("view_server", "add_server")
        self.client.post("/servers/add/", {"name": name, "ssh_alias": alias})
        return Server.objects.get(name=name)

    def discover(self) -> DiscoverySnapshot:
        """Register a server, run the worker, and keep the server page as ``self.page``."""
        server = self.register()
        self.run_worker()
        self.page = self.client.get(f"/servers/{server.pk}/")
        return DiscoverySnapshot.objects.get()


class RegistrationDiscoveryTests(DiscoveryTestCase):
    def test_registration_queues_work_that_the_worker_completes(self) -> None:
        server = self.register()
        # The request only queued the work; nothing connected during it.
        attempt = DiscoveryAttempt.objects.get()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.QUEUED)
        self.assertEqual(attempt.ssh_alias, "web.example.com")
        self.assertEqual(self.remote.targets, [])
        self.assertTrue(DBTaskResult.objects.filter(status="READY").exists())
        page = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(page, "Connection check queued")
        self.assertContains(page, 'hx-trigger="every 2s"')
        self.assertContains(page, "No observations yet.")
        self.assertContains(
            page,
            "No component observations yet. Barectl reads web-stack components after it "
            "verifies the connection.",
        )
        self.assertContains(
            page,
            "No Nginx site file observations yet. Barectl reads Nginx site files after it "
            "verifies the connection.",
        )
        self.assertContains(
            page,
            "No PHP-FPM pool observations yet. Barectl reads PHP-FPM pools after it verifies "
            "the connection.",
        )

        self.run_worker()

        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED)
        self.assertEqual(attempt.host_key, HOST_KEY)
        self.assertIsNotNone(attempt.started_at)
        self.assertIsNotNone(attempt.finished_at)
        (target,) = self.remote.targets
        self.assertEqual(
            (target.alias, target.hostname, target.user),
            ("web.example.com", "203.0.113.10", "deploy"),
        )
        snapshot = DiscoverySnapshot.objects.get()
        self.assertEqual(snapshot.attempt, attempt)
        self.assertEqual(
            (snapshot.os_pretty_name, snapshot.os_id, snapshot.os_version_id, snapshot.os_source),
            ("Ubuntu 24.04.3 LTS", "ubuntu", "24.04", "/etc/os-release"),
        )
        page = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(page, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertContains(page, "<dd>24.04</dd>", html=True)
        self.assertContains(page, "from <code>/etc/os-release</code>")
        self.assertContains(page, f"<code>{HOST_KEY}</code>")
        self.assertContains(page, "This is a snapshot, not live status.")
        self.assertContains(page, f'datetime="{snapshot.collected_at.isoformat()}"')
        self.assertNotContains(page, "hx-trigger")
        # Remote output that Barectl does not display is not stored.
        self.assertNotContains(page, "Noble Numbat")
        self.assertContains(self.client.get("/"), "<td>Verified</td>", html=True)

    def test_discovery_runs_only_read_only_commands_without_sudo(self) -> None:
        self.remote.files = {"/usr/lib/os-release": UBUNTU}
        self.remote.unreadable = {"/etc/os-release"}
        config_before = self.ssh_config.read_bytes()
        self.register()
        self.run_worker()
        self.assertTrue(self.remote.commands)
        for command in self.remote.commands:
            self.assertRegex(command, READ_ONLY)
        # Nor does Barectl change the controller's SSH configuration.
        self.assertEqual(self.ssh_config.read_bytes(), config_before)

    def test_worker_refuses_aliases_removed_before_it_runs(self) -> None:
        server = self.register()
        self.write_config("Host db-1\n")
        self.run_worker()
        attempt = DiscoveryAttempt.objects.get()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("The SSH alias web.example.com", attempt.failure)
        self.assertEqual(self.remote.targets, [])
        page = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(page, "Connection failed")
        self.assertContains(page, "It is no longer a Host entry.")

    def test_aliases_that_connect_differently_from_ssh_are_refused(self) -> None:
        self.register()
        # The configuration changed after registration; the worker reads it again.
        self.write_config("Host web.example.com\n  ProxyJump bastion\n  IdentityAgent /tmp/a\n")
        self.run_worker()
        attempt = DiscoveryAttempt.objects.get()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("uses IdentityAgent, ProxyJump, which Barectl cannot", attempt.failure)
        self.assertNotIn("bastion", attempt.failure)
        self.assertEqual(self.remote.targets, [])

    def test_connection_failures_are_shown_without_a_snapshot(self) -> None:
        self.remote.failure = "The controller host does not trust the host key presented."
        server = self.register()
        self.run_worker()
        self.assertEqual(DiscoveryAttempt.objects.get().status, DiscoveryAttempt.Status.FAILED)
        self.assertFalse(DiscoverySnapshot.objects.exists())
        page = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(page, "does not trust the host key presented.")
        self.assertContains(page, "No observations yet.")
        self.assertContains(self.client.get("/"), "<td>Connection failed</td>", html=True)

    def test_unexpected_errors_are_recorded_without_their_details(self) -> None:
        def broken(target: ConnectionTarget) -> Iterator[ssh.RemoteShell]:
            raise RuntimeError("password=hunter2 from remote output")

        self.register()
        with (
            mock.patch.object(ssh, "connect", broken),
            self.assertLogs("discovery.services", "ERROR") as logs,
        ):
            self.run_worker()
        attempt = DiscoveryAttempt.objects.get()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertNotIn("hunter2", attempt.failure)
        self.assertIn("unexpected error", attempt.failure)
        message = f"Discovery attempt {attempt.pk} failed unexpectedly: RuntimeError"
        self.assertEqual(logs.output, [f"ERROR:discovery.services:{message}"])
        self.assertNotIn("hunter2", str(DBTaskResult.objects.values_list("traceback", flat=True)))


class PartialObservationTests(DiscoveryTestCase):
    def test_unreadable_release_file_is_inaccessible_not_absent(self) -> None:
        self.remote.files = {}
        self.remote.unreadable = {"/etc/os-release"}
        snapshot = self.discover()
        self.assertEqual(snapshot.os_status, "inaccessible")
        self.assertEqual(snapshot.os_pretty_name, "")
        self.assertContains(self.page, "<strong>Inaccessible:</strong>", html=True)
        self.assertContains(self.page, "cannot read /etc/os-release. Barectl does not use sudo.")
        # The connection itself was verified; the warning belongs to the snapshot.
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)

    def test_missing_release_files_are_unsupported_not_absent(self) -> None:
        # Every server runs an operating system; Barectl just cannot identify this one.
        self.remote.files = {}
        snapshot = self.discover()
        self.assertEqual(snapshot.os_status, "unsupported")
        self.assertContains(
            self.page,
            "neither /etc/os-release nor /usr/lib/os-release, so Barectl cannot identify the "
            "operating system.",
        )

    def test_fallback_release_file_is_used(self) -> None:
        self.remote.files = {"/usr/lib/os-release": 'NAME="Debian GNU/Linux"\nID=debian\n'}
        snapshot = self.discover()
        self.assertEqual(
            (snapshot.os_status, snapshot.os_source), ("observed", "/usr/lib/os-release")
        )
        self.assertContains(self.page, "<dd>Debian GNU/Linux</dd>", html=True)
        self.assertContains(self.page, "<dd>Not reported</dd>", html=True)

    def test_unrecognized_content_is_unsupported(self) -> None:
        self.remote.files = {"/etc/os-release": "<html>not a release file</html>\nX=$(id)\n"}
        snapshot = self.discover()
        self.assertEqual(snapshot.os_status, "unsupported")
        self.assertContains(self.page, "<strong>Unsupported:</strong>", html=True)
        self.assertNotContains(self.page, "not a release file")

    def test_values_are_unquoted_bounded_and_never_executed(self) -> None:
        self.remote.files = {
            "/etc/os-release": (
                "# comment\nNAME='Example $(touch /tmp/x)'\nID=example\n"
                f'PRETTY_NAME="{"x" * 500}"\nVERSION_ID="1\\"2"\nBROKEN="unterminated\n'
            )
        }
        snapshot = self.discover()
        self.assertEqual(snapshot.os_name, "Example $(touch /tmp/x)")
        self.assertEqual(len(snapshot.os_pretty_name), 200)
        self.assertEqual(snapshot.os_version_id, '1"2')


class CapacityTests(DiscoveryTestCase):
    def test_capacity_is_collected_with_units_provenance_and_time(self) -> None:
        snapshot = self.discover()
        self.assertEqual(
            (snapshot.arch_status, snapshot.arch_value, snapshot.arch_source),
            ("observed", "x86_64", "uname -m"),
        )
        self.assertEqual(
            (snapshot.cpu_status, snapshot.cpu_count, snapshot.cpu_source),
            ("observed", 4, "nproc"),
        )
        self.assertEqual(
            (snapshot.memory_status, snapshot.memory_bytes, snapshot.memory_source),
            ("observed", 4024548 * 1024, "/proc/meminfo"),
        )
        self.assertEqual(
            (
                snapshot.filesystem_status,
                snapshot.filesystem_size_bytes,
                snapshot.filesystem_avail_bytes,
            ),
            ("observed", 53689778176, 48190049280),
        )
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)
        # The server overview retains the OS observations alongside capacity.
        self.assertContains(self.page, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertContains(self.page, "<dd>x86_64</dd>", html=True)
        self.assertContains(self.page, "<dd>4 available</dd>", html=True)
        # Memory and filesystem show explicit units, not bare numbers.
        self.assertContains(self.page, "(4121137152 bytes)")
        self.assertContains(self.page, "(53689778176 bytes)", count=1)
        self.assertContains(self.page, "48190049280 bytes")
        self.assertContains(self.page, "<code>uname -m</code>", html=True)
        self.assertContains(self.page, "<code>nproc</code>", html=True)
        self.assertContains(self.page, "<code>/proc/meminfo</code>", html=True)
        self.assertContains(self.page, "This is a snapshot, not live status.")
        self.assertContains(self.page, f'datetime="{snapshot.collected_at.isoformat()}"')
        # Only the needed fields are kept; other meminfo lines are discarded.
        self.assertNotContains(self.page, "2345678")
        self.assertContains(self.client.get("/"), "<td>Verified</td>", html=True)

    def test_partial_capacity_shows_warnings_not_zero_values(self) -> None:
        self.remote.files = {"/etc/os-release": UBUNTU}
        self.remote.unreadable = {"/proc/meminfo"}
        self.remote.results["uname -m"] = ssh.CommandResult(1, "")
        self.remote.results["nproc"] = ssh.CommandResult(0, "four\n")
        self.remote.results["df -B1 --output=size,avail,target /"] = ssh.CommandResult(
            0, "Size Avail Target\nnot-a-number 123 /\n"
        )
        snapshot = self.discover()
        self.assertEqual(snapshot.arch_status, "unsupported")
        self.assertIsNone(snapshot.cpu_count)
        self.assertEqual(snapshot.cpu_status, "unsupported")
        self.assertEqual(snapshot.memory_status, "inaccessible")
        self.assertIsNone(snapshot.memory_bytes)
        self.assertEqual(snapshot.filesystem_status, "unsupported")
        self.assertIsNone(snapshot.filesystem_size_bytes)
        # A partial inspection still succeeds; the OS observations remain.
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)
        self.assertContains(self.page, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertContains(self.page, "<strong>Inaccessible:</strong>", html=True)
        self.assertContains(self.page, "cannot read /proc/meminfo. Barectl does not use sudo.")
        self.assertContains(self.page, "<strong>Unsupported:</strong>", html=True)
        self.assertNotContains(self.page, "four")
        # Missing observations never look like zero capacity.
        self.assertNotContains(self.page, "<dd>0</dd>", html=True)
        self.assertNotContains(self.page, "(0 bytes)")

    def test_missing_meminfo_is_unsupported_not_absent(self) -> None:
        self.remote.files = {"/etc/os-release": UBUNTU}
        snapshot = self.discover()
        self.assertEqual(snapshot.memory_status, "unsupported")
        self.assertContains(self.page, "has no /proc/meminfo, so Barectl cannot report memory.")

    def test_missing_and_unrunnable_commands_are_distinct(self) -> None:
        # POSIX shells exit 127 for a missing command and 126 for one they cannot run.
        self.remote.results["uname -m"] = ssh.CommandResult(127, "")
        self.remote.results["nproc"] = ssh.CommandResult(126, "")
        snapshot = self.discover()
        # A missing inspection command is no finding: the server still has an architecture.
        self.assertEqual(
            (snapshot.arch_status, snapshot.cpu_status), ("unsupported", "inaccessible")
        )
        self.assertContains(
            self.page, "The server has no uname command, so Barectl cannot inspect this."
        )
        self.assertContains(self.page, "The SSH user cannot run nproc. Barectl does not use sudo.")
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)

    def test_truncated_capacity_output_is_unsupported(self) -> None:
        self.remote.results = {
            command: ssh.CommandResult(0, result.stdout, truncated=True)
            for command, result in self.remote.results.items()
        }
        self.remote.results["cat /proc/meminfo"] = ssh.CommandResult(0, MEMINFO, truncated=True)
        snapshot = self.discover()
        self.assertEqual(
            (
                snapshot.arch_status,
                snapshot.cpu_status,
                snapshot.memory_status,
                snapshot.filesystem_status,
            ),
            ("unsupported", "unsupported", "unsupported", "unsupported"),
        )
        self.assertContains(self.page, "wrote more output than expected. It was not read.")
        self.assertIsNone(snapshot.memory_bytes)

    def test_unsupported_capacity_never_shows_raw_output(self) -> None:
        self.remote.results["uname -m"] = ssh.CommandResult(0, "x86_64\nmalicious $(touch /tmp/x)")
        self.remote.results["nproc"] = ssh.CommandResult(0, "0\n")
        # "²" passes str.isdigit but int() rejects it.
        self.remote.files["/proc/meminfo"] = "MemTotal: ² kB\n"
        self.remote.results["df -B1 --output=size,avail,target /"] = ssh.CommandResult(
            0, "Size Avail Target\n100 200 /\n"
        )
        snapshot = self.discover()
        self.assertEqual(
            (
                snapshot.arch_status,
                snapshot.cpu_status,
                snapshot.memory_status,
                snapshot.filesystem_status,
            ),
            ("unsupported", "unsupported", "unsupported", "unsupported"),
        )
        self.assertNotContains(self.page, "malicious")
        self.assertNotContains(self.page, "²")


class AttributeTests(DiscoveryTestCase):
    """The operating system and capacity exist on every server, so they are never absent."""

    ATTRIBUTES = ("os_status", "arch_status", "cpu_status", "memory_status", "filesystem_status")

    def test_a_server_without_inspection_tools_has_no_absent_attributes(self) -> None:
        # Every command is missing and every file is gone, with searchable parents.
        self.remote.files = {}
        self.remote.directories = {}
        self.remote.results = {
            command: ssh.CommandResult(127, "") for command in self.remote.results
        }
        snapshot = self.discover()
        self.assertEqual([getattr(snapshot, name) for name in self.ATTRIBUTES], ["unsupported"] * 5)
        # Nothing about the server's software was found either.
        self.assertEqual(
            (snapshot.nginx_site_files_status, snapshot.php_fpm_pools_status),
            ("unsupported", "unsupported"),
        )
        self.assertFalse(snapshot.components.exclude(package_status="unsupported").exists())
        self.assertNotContains(self.page, "Absent")
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)

    def test_the_database_refuses_absent_attributes(self) -> None:
        self.discover()
        snapshot = DiscoverySnapshot.objects.get()
        for name in self.ATTRIBUTES:
            with self.subTest(field=name):
                previous = getattr(snapshot, name)
                setattr(snapshot, name, "absent")
                with self.assertRaises(IntegrityError), transaction.atomic():
                    snapshot.save(update_fields=[name])
                setattr(snapshot, name, previous)


class ServiceTests(DiscoveryTestCase):
    def assert_statuses(self, snapshot: DiscoverySnapshot, field: str, status: str) -> None:
        """Assert every component's ``field`` has ``status``, in display order."""
        self.assertEqual(
            list(snapshot.components.values_list("component", field)),
            [(component, status) for component in WebStackComponent.values],
        )

    def test_service_stack_is_collected_with_versions_states_and_provenance(self) -> None:
        snapshot = self.discover()
        self.assertEqual(
            list(snapshot.components.values_list("component", flat=True)),
            ["nginx", "php-fpm", "mariadb", "postgresql"],
        )
        nginx = ComponentObservation.objects.get(component="nginx")
        self.assertEqual(nginx.package_status, "observed")
        self.assertEqual(nginx.packages, "nginx 1.24.0-2ubuntu7.18")
        self.assertEqual(nginx.package_source, PACKAGE_QUERY)
        self.assertEqual(nginx.service_status, "observed")
        self.assertEqual(nginx.units, "nginx.service active (running), enabled")
        self.assertEqual(nginx.service_source, UNIT_QUERY.format("nginx.service"))
        php = ComponentObservation.objects.get(component="php-fpm")
        self.assertEqual(php.packages, "php8.3-fpm 8.3.6-0ubuntu0.24.04.11")
        self.assertEqual(php.units, "php8.3-fpm.service active (running), enabled")
        mariadb = ComponentObservation.objects.get(component="mariadb")
        self.assertIn("mariadb-server 1:10.11.14-0ubuntu0.24.04.1", mariadb.packages)
        self.assertEqual(mariadb.units, "mariadb.service active (running), enabled")
        postgres = ComponentObservation.objects.get(component="postgresql")
        self.assertIn("postgresql-16 16.15-0ubuntu0.24.04.1", postgres.packages)
        self.assertEqual(
            postgres.units.splitlines(),
            [UMBRELLA_LINE, MAIN_LINE],
        )
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)
        # The services section renders versions, unit states, warnings, provenance and time.
        page = self.page
        self.assertContains(page, 'aria-labelledby="web-stack-heading"')
        self.assertContains(page, '<h2 id="web-stack-heading">Web stack</h2>')
        self.assertContains(page, "nginx 1.24.0-2ubuntu7.18")
        self.assertContains(page, "php8.3-fpm 8.3.6-0ubuntu0.24.04.11")
        self.assertContains(page, "nginx.service active (running), enabled")
        self.assertContains(page, UMBRELLA_LINE)
        # Packages known to apt but not installed, such as the php-fpm metapackage, are not
        # reported as installed.
        self.assertNotContains(page, "php-fpm  un")
        self.assertNotContains(page, "postgresql-16-jit-llvm")
        self.assertContains(page, "<code>dpkg-query -W")
        self.assertContains(page, "<code>systemctl show nginx.service")
        self.assertContains(page, "This is a snapshot, not live status.")
        self.assertContains(page, f'datetime="{snapshot.collected_at.isoformat()}"')

    def test_absent_packages_are_absent_and_skip_service_queries(self) -> None:
        # dpkg-query exits 1 when no pattern matches; nothing is installed.
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(1, "")
        snapshot = self.discover()
        self.assertEqual(
            list(snapshot.components.values_list("component", "package_status", "service_status")),
            [
                ("nginx", "absent", "absent"),
                ("php-fpm", "absent", "absent"),
                ("mariadb", "absent", "absent"),
                ("postgresql", "absent", "absent"),
            ],
        )
        # Without installed packages there is no unit to query; the absent verdict still
        # records the dpkg query it was derived from.
        self.assertFalse([c for c in self.remote.commands if "systemctl" in c])
        nginx = ComponentObservation.objects.get(component="nginx")
        self.assertEqual(nginx.service_source, PACKAGE_QUERY)
        self.assertContains(self.page, "Packages: Absent", count=4)
        self.assertContains(self.page, "Service units: Absent", count=4)
        self.assertContains(self.page, "lists no installed Nginx packages.")

    def test_known_but_uninstalled_packages_are_not_reported(self) -> None:
        # dpkg-query lists packages apt knows about with a status other than "ii".
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(
            1, "nginx  un \nphp8.3-fpm  un \nmariadb-server  rc \n"
        )
        snapshot = self.discover()
        self.assert_statuses(snapshot, "package_status", "absent")
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)

    def test_missing_dpkg_query_is_unsupported_not_absent(self) -> None:
        # POSIX shells exit 127 for a missing command: no dpkg database, no verdict.
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(127, "")
        snapshot = self.discover()
        self.assert_statuses(snapshot, "package_status", "unsupported")
        self.assertFalse([c for c in self.remote.commands if "systemctl" in c])
        # When the dpkg database itself cannot be inspected, no service query is recorded.
        self.assertEqual(ComponentObservation.objects.get(component="nginx").service_source, "")
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)
        self.assertNotContains(self.page, "Packages: Absent")
        self.assertContains(self.page, "Packages: Unsupported", count=4)
        self.assertContains(self.page, "cannot inspect other installation formats.")
        # Both sub-observations of every component carry the warning, and so do the site
        # file and pool observations that depend on them.
        self.assertContains(self.page, "<strong>Unsupported:</strong>", html=True, count=10)

    def test_unrunnable_dpkg_query_is_inaccessible(self) -> None:
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(126, "")
        snapshot = self.discover()
        self.assert_statuses(snapshot, "package_status", "inaccessible")
        self.assertNotContains(self.page, "Packages: Absent")
        self.assertContains(
            self.page, "The SSH user cannot run dpkg-query. Barectl does not use sudo."
        )

    def test_unexpected_dpkg_query_failure_is_unsupported(self) -> None:
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(2, "")
        snapshot = self.discover()
        self.assert_statuses(snapshot, "package_status", "unsupported")
        self.assertNotContains(self.page, "Packages: Absent")

    def test_unparsable_package_output_is_unsupported(self) -> None:
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(0, "nginx 1.24 stuff\ngarbage\n")
        snapshot = self.discover()
        self.assert_statuses(snapshot, "package_status", "unsupported")
        self.assertNotContains(self.page, "Packages: Absent")
        self.assertNotContains(self.page, "nginx 1.24 stuff")

    def test_truncated_package_output_is_unsupported(self) -> None:
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(0, DPKG_OUTPUT, truncated=True)
        snapshot = self.discover()
        self.assert_statuses(snapshot, "package_status", "unsupported")
        self.assertContains(self.page, "wrote more output than expected. It was not read.")

    def test_unavailable_systemd_is_unsupported_not_absent(self) -> None:
        # Containers and minimal servers run without systemd or its bus: exit 1.
        self.remote.results[UNIT_QUERY.format("nginx.service")] = ssh.CommandResult(1, "")
        snapshot = self.discover()
        nginx = ComponentObservation.objects.get(component="nginx")
        self.assertEqual((nginx.package_status, nginx.service_status), ("observed", "unsupported"))
        self.assertEqual(nginx.units, "")
        self.assertNotContains(self.page, "Service units: Absent")
        self.assertContains(self.page, "nginx 1.24.0-2ubuntu7.18")
        self.assertContains(self.page, "could not read service states from systemd.")
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)

    def test_missing_systemctl_is_unsupported(self) -> None:
        self.remote.results = {
            key: (ssh.CommandResult(127, "") if key.startswith("systemctl") else value)
            for key, value in self.remote.results.items()
        }
        snapshot = self.discover()
        self.assert_statuses(snapshot, "service_status", "unsupported")
        self.assertContains(self.page, "has no systemctl command")

    def test_unrunnable_systemctl_is_inaccessible(self) -> None:
        self.remote.results[UNIT_QUERY.format("nginx.service")] = ssh.CommandResult(126, "")
        self.discover()
        nginx = ComponentObservation.objects.get(component="nginx")
        self.assertEqual(nginx.service_status, "inaccessible")
        self.assertContains(
            self.page, "The SSH user cannot run systemctl. Barectl does not use sudo."
        )

    def test_stopped_service_is_observed_not_absent(self) -> None:
        # Installed but stopped: the unit is loaded, enabled and inactive.
        self.remote.results[UNIT_QUERY.format("mariadb.service")] = ssh.CommandResult(
            0, unit_report("mariadb.service", active="inactive", sub="dead")
        )
        self.discover()
        mariadb = ComponentObservation.objects.get(component="mariadb")
        self.assertEqual(mariadb.units, "mariadb.service inactive (dead), enabled")
        self.assertContains(self.page, "mariadb.service inactive (dead), enabled")

    def test_unit_without_a_service_file_is_reported_as_not_found(self) -> None:
        self.remote.results[UNIT_QUERY.format("mariadb.service")] = ssh.CommandResult(
            0,
            "Id=mariadb.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\n"
            "UnitFileState=\n",
        )
        self.discover()
        mariadb = ComponentObservation.objects.get(component="mariadb")
        self.assertEqual(mariadb.service_status, "observed")
        self.assertEqual(mariadb.units, "mariadb.service not found")
        self.assertContains(self.page, "mariadb.service not found")

    def test_unparsable_unit_output_is_unsupported(self) -> None:
        self.remote.results[UNIT_QUERY.format("nginx.service")] = ssh.CommandResult(
            0, "Id=nginx.service\nActiveState=someting-new\n"
        )
        self.discover()
        nginx = ComponentObservation.objects.get(component="nginx")
        self.assertEqual(nginx.service_status, "unsupported")
        # The server-reported unit name is remote data and is never quoted back.
        self.assertNotContains(self.page, "someting-new")
        self.assertContains(
            self.page, "systemctl did not report a service unit in a supported format."
        )

    def test_unit_reported_under_another_name_is_unsupported(self) -> None:
        # An alias resolves to its target unit, which is not the documented unit.
        self.remote.results[UNIT_QUERY.format("mariadb.service")] = ssh.CommandResult(
            0, unit_report("mysql.service")
        )
        self.discover()
        mariadb = ComponentObservation.objects.get(component="mariadb")
        self.assertEqual((mariadb.service_status, mariadb.units), ("unsupported", ""))
        self.assertNotContains(self.page, "mysql.service")

    def test_held_and_reinstall_required_packages_are_installed(self) -> None:
        # "hi" is installed and held by apt-mark; "R" flags a package needing reinstallation.
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(
            0,
            DPKG_OUTPUT.replace(
                "nginx 1.24.0-2ubuntu7.18 ii", "nginx 1.24.0-2ubuntu7.18 hi"
            ).replace(
                "php8.3-fpm 8.3.6-0ubuntu0.24.04.11 ii", "php8.3-fpm 8.3.6-0ubuntu0.24.04.11 iiR"
            ),
        )
        self.discover()
        nginx = ComponentObservation.objects.get(component="nginx")
        php = ComponentObservation.objects.get(component="php-fpm")
        self.assertEqual(
            (nginx.package_status, nginx.packages), ("observed", "nginx 1.24.0-2ubuntu7.18")
        )
        self.assertEqual(nginx.service_status, "observed")
        self.assertEqual(php.packages, "php8.3-fpm 8.3.6-0ubuntu0.24.04.11")

    def test_unfinished_package_is_unsupported_not_absent(self) -> None:
        # "iU" is unpacked but not configured: the software may be partly present.
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(
            0, DPKG_OUTPUT.replace("nginx 1.24.0-2ubuntu7.18 ii", "nginx 1.24.0-2ubuntu7.18 iU")
        )
        self.discover()
        nginx = ComponentObservation.objects.get(component="nginx")
        self.assertEqual(
            (nginx.package_status, nginx.service_status), ("unsupported", "unsupported")
        )
        self.assertEqual(nginx.packages, "")
        self.assertFalse([c for c in self.remote.commands if "nginx.service" in c])
        self.assertNotContains(self.page, "nginx 1.24.0-2ubuntu7.18")
        self.assertContains(self.page, "lists a Nginx package that is not fully installed")

    def test_every_installed_php_fpm_package_gets_its_unit_queried(self) -> None:
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(
            0,
            "php8.1-fpm 8.1.2-1ubuntu2 ii \nphp8.3-fpm 8.3.6-0ubuntu0.24.04.11 ii \n"
            + DPKG_OUTPUT.splitlines()[2]
            + "\n",
        )
        self.remote.results[UNIT_QUERY.format("php8.1-fpm.service php8.3-fpm.service")] = (
            ssh.CommandResult(
                0,
                # systemctl separates the records of several units with an empty line.
                unit_report("php8.1-fpm.service") + "\n" + unit_report("php8.3-fpm.service"),
            )
        )
        self.discover()
        php = ComponentObservation.objects.get(component="php-fpm")
        self.assertEqual(
            php.units.splitlines(),
            [
                "php8.1-fpm.service active (running), enabled",
                "php8.3-fpm.service active (running), enabled",
            ],
        )
        self.assertContains(self.page, "php8.1-fpm.service active (running), enabled")


class PostgresClusterTests(DiscoveryTestCase):
    """Each PostgreSQL cluster's unit is reported next to the postgresql.service umbrella."""

    def postgres(self) -> ComponentObservation:
        return ComponentObservation.objects.get(component="postgresql")

    def postgres_commands(self) -> list[str]:
        """The commands issued after the package query to observe PostgreSQL's service."""
        return [c for c in self.remote.commands if "postgres" in c and c != PACKAGE_QUERY]

    def test_running_cluster_is_reported_with_the_command_that_found_it(self) -> None:
        self.discover()
        postgres = self.postgres()
        self.assertEqual(postgres.service_status, "observed")
        self.assertEqual(
            postgres.units.splitlines(),
            [UMBRELLA_LINE, MAIN_LINE],
        )
        self.assertEqual(
            self.postgres_commands(),
            [
                f"ls -1b {PG_DIR}",
                f"ls -1bA {PG_DIR}/16",
                f"test -e {cluster_conf('16', 'main')}",
                UNIT_QUERY.format(CLUSTER_UNITS),
            ],
        )
        self.assertEqual(
            postgres.service_source.splitlines(),
            [f"ls -1b {PG_DIR}", f"ls -1bA {PG_DIR}/16", UNIT_QUERY.format(CLUSTER_UNITS)],
        )
        self.assertEqual(postgres.service_warning, "")
        self.assertContains(self.page, MAIN_LINE)
        self.assertContains(self.page, f"<code>ls -1b {PG_DIR}</code>")
        self.assertContains(self.page, f"<code>ls -1bA {PG_DIR}/16</code>")
        self.assertContains(self.page, f"<code>{UNIT_QUERY.format(CLUSTER_UNITS)}</code>")

    def add_cluster(self, version: str, name: str) -> None:
        versions = self.remote.directories[PG_DIR]
        if version not in versions:
            versions.append(version)
        self.remote.directories.setdefault(f"{PG_DIR}/{version}", []).append(name)
        self.remote.directories[f"{PG_DIR}/{version}/{name}"] = ["postgresql.conf"]
        self.remote.files[cluster_conf(version, name)] = ""

    def report_units(self, units: str, *reports: str) -> None:
        self.remote.results[UNIT_QUERY.format(units)] = ssh.CommandResult(0, "\n".join(reports))

    def test_stopped_cluster_is_installed_but_stopped_under_a_running_umbrella(self) -> None:
        self.report_units(
            CLUSTER_UNITS,
            UMBRELLA_REPORT,
            cluster_report("16", "main", active="inactive", sub="dead"),
        )
        self.discover()
        postgres = self.postgres()
        self.assertEqual(postgres.service_status, "observed")
        self.assertEqual(
            postgres.units.splitlines(),
            [
                UMBRELLA_LINE,
                "postgresql@16-main.service inactive (dead), enabled-runtime",
            ],
        )
        self.assertContains(
            self.page, "postgresql@16-main.service inactive (dead), enabled-runtime"
        )

    def test_no_clusters_is_observed_with_only_the_umbrella_unit(self) -> None:
        # pg_dropcluster removes a cluster's directory and may leave its version directory.
        self.remote.directories[f"{PG_DIR}/16"] = []
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.discover()
        postgres = self.postgres()
        self.assertEqual(postgres.service_status, "observed")
        self.assertEqual(postgres.units, UMBRELLA_LINE)
        self.assertEqual(
            postgres.service_warning, f"Barectl found no PostgreSQL clusters in {PG_DIR}."
        )
        self.assertContains(self.page, f"Barectl found no PostgreSQL clusters in {PG_DIR}.")
        self.assertNotContains(self.page, "<strong>Observed:</strong>", html=True)

    def assert_uninspected(self, status: str, warning: str) -> ComponentObservation:
        """Assert the clusters could not all be seen: never absent, versions still shown."""
        postgres = self.postgres()
        self.assertEqual(postgres.package_status, "observed")
        self.assertIn("postgresql-16 16.15-0ubuntu0.24.04.1", postgres.packages)
        self.assertEqual(postgres.service_status, status)
        self.assertEqual(postgres.service_warning, warning)
        self.assertContains(self.page, "postgresql-16 16.15-0ubuntu0.24.04.1")
        self.assertContains(self.page, warning)
        self.assertNotContains(self.page, "Absent")
        return postgres

    def test_unreadable_configuration_root_is_inaccessible_not_absent(self) -> None:
        del self.remote.directories[PG_DIR]
        self.remote.unreadable.add(PG_DIR)
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.discover()
        postgres = self.assert_uninspected(
            "inaccessible",
            f"The SSH user cannot read {PG_DIR}. Barectl does not use sudo.",
        )
        # The umbrella unit's state is still reported.
        self.assertEqual(postgres.units, UMBRELLA_LINE)
        self.assertContains(self.page, UMBRELLA_LINE)
        self.assertEqual(
            postgres.service_source.splitlines(),
            [f"ls -1b {PG_DIR}", UNIT_QUERY.format("postgresql.service")],
        )

    def test_unreadable_version_directory_is_inaccessible_and_keeps_other_clusters(self) -> None:
        self.add_cluster("17", "main")
        del self.remote.directories[f"{PG_DIR}/16"]
        self.remote.unreadable.add(f"{PG_DIR}/16")
        units = "postgresql.service postgresql@17-main.service"
        self.report_units(units, UMBRELLA_REPORT, cluster_report("17", "main"))
        self.discover()
        postgres = self.assert_uninspected(
            "inaccessible", f"The SSH user cannot read {PG_DIR}/16. Barectl does not use sudo."
        )
        self.assertEqual(
            postgres.units.splitlines(),
            [
                UMBRELLA_LINE,
                "postgresql@17-main.service active (running), enabled-runtime",
            ],
        )

    def test_unavailable_systemd_keeps_the_listing_warning(self) -> None:
        del self.remote.directories[PG_DIR]
        self.remote.unreadable.add(PG_DIR)
        self.remote.results[UNIT_QUERY.format("postgresql.service")] = ssh.CommandResult(1, "")
        self.discover()
        postgres = self.postgres()
        self.assertEqual((postgres.service_status, postgres.units), ("unsupported", ""))
        self.assertIn("could not read service states from systemd.", postgres.service_warning)
        self.assertIn(f"The SSH user cannot read {PG_DIR}.", postgres.service_warning)
        self.assertContains(self.page, "Service units: Unsupported")

    def test_missing_configuration_root_is_unsupported_not_absent(self) -> None:
        # postgresql-common installs /etc/postgresql; without it the layout is not Debian's.
        del self.remote.directories[PG_DIR]
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.discover()
        self.assert_uninspected(
            "unsupported", f"The server has no {PG_DIR}. Barectl reads only the Debian layout."
        )

    def test_listing_that_cannot_run_is_unsupported(self) -> None:
        self.remote.results[f"ls -1b {PG_DIR}"] = ssh.CommandResult(127, "")
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.discover()
        self.assert_uninspected("unsupported", f"{PG_DIR} could not be read.")

    def test_truncated_listing_is_unsupported(self) -> None:
        self.remote.results[f"ls -1bA {PG_DIR}/16"] = ssh.CommandResult(0, "main\n", truncated=True)
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.discover()
        self.assert_uninspected(
            "unsupported", f"{PG_DIR}/16 holds more than 1000 entries. It was not read."
        )

    def test_more_clusters_than_supported_are_not_queried(self) -> None:
        self.remote.directories[f"{PG_DIR}/16"] = [f"c{n:03}" for n in range(101)]
        for n in range(101):
            self.remote.files[cluster_conf("16", f"c{n:03}")] = ""
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.discover()
        self.assert_uninspected(
            "unsupported",
            f"{PG_DIR} holds more than 100 possible PostgreSQL clusters. They were not queried.",
        )
        self.assertFalse([c for c in self.remote.commands if "c000" in c])
        self.assertEqual(self.postgres().units, UMBRELLA_LINE)

    def test_more_versions_than_supported_are_not_listed(self) -> None:
        self.remote.directories[PG_DIR] = [str(version) for version in range(10, 31)]
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.discover()
        self.assert_uninspected(
            "unsupported",
            f"{PG_DIR} holds more than 20 PostgreSQL versions. They were not listed.",
        )
        self.assertEqual(self.postgres_commands()[1:], [UNIT_QUERY.format("postgresql.service")])

    def test_cluster_without_a_unit_file_is_reported_as_not_found(self) -> None:
        self.report_units(
            CLUSTER_UNITS,
            UMBRELLA_REPORT,
            "Id=postgresql@16-main.service\nLoadState=not-found\nActiveState=inactive\n"
            "SubState=dead\nUnitFileState=\n",
        )
        self.discover()
        postgres = self.postgres()
        self.assertEqual(postgres.service_status, "observed")
        self.assertIn("postgresql@16-main.service not found", postgres.units.splitlines())
        self.assertContains(self.page, "postgresql@16-main.service not found")

    def test_cluster_reported_under_another_name_is_unsupported(self) -> None:
        self.report_units(CLUSTER_UNITS, UMBRELLA_REPORT, unit_report("postgresql@17-main.service"))
        self.discover()
        postgres = self.postgres()
        self.assertEqual(postgres.service_status, "unsupported")
        self.assertEqual(postgres.units, UMBRELLA_LINE)
        self.assertNotContains(self.page, "postgresql@17-main")

    def test_hostile_names_are_never_used_in_commands_or_warnings(self) -> None:
        # As ls -b prints them: spaces and newlines escaped with backslashes.
        hostile = ["db;reboot", "my\\ db", "x\\ny", "$(id)"]
        self.remote.directories[PG_DIR] += ["16;reboot", "17\\nmain"]
        self.remote.directories[f"{PG_DIR}/16"] += hostile
        self.discover()
        postgres = self.assert_uninspected(
            "unsupported",
            f"{PG_DIR}/16 lists 4 entries whose names Barectl does not support. They were skipped.",
        )
        # The valid cluster is still reported.
        self.assertIn(MAIN_LINE, postgres.units)
        self.assertEqual(
            self.postgres_commands(),
            [
                f"ls -1b {PG_DIR}",
                f"ls -1bA {PG_DIR}/16",
                f"test -e {cluster_conf('16', 'main')}",
                UNIT_QUERY.format(CLUSTER_UNITS),
            ],
        )
        stored = " ".join(
            ComponentObservation.objects.values_list(
                "units", "service_warning", "service_source"
            ).get(component="postgresql")
        )
        for name in [*hostile, "16;reboot", "17\\nmain", "reboot", "(id)"]:
            with self.subTest(name=name):
                self.assertNotIn(name, stored)
                self.assertNotContains(self.page, name)

    def test_dead_configuration_symlink_still_marks_a_cluster(self) -> None:
        # postgresql-common counts a postgresql.conf that is a dead symlink.
        del self.remote.files[cluster_conf("16", "main")]
        self.remote.dead_links.add(cluster_conf("16", "main"))
        self.discover()
        self.assertEqual(self.postgres().service_status, "observed")
        self.assertIn("postgresql@16-main.service", self.postgres().units)
        self.assertIn(f"test -L {cluster_conf('16', 'main')}", self.postgres_commands())

    def test_cluster_named_with_a_leading_dot_is_found(self) -> None:
        # postgresql-common reads every directory entry, including names starting with ".".
        self.add_cluster("16", ".staging")
        units = f"{CLUSTER_UNITS} postgresql@16-.staging.service"
        self.report_units(
            units, UMBRELLA_REPORT, cluster_report("16", "main"), cluster_report("16", ".staging")
        )
        self.discover()
        self.assertEqual(
            self.postgres().units.splitlines(),
            [
                UMBRELLA_LINE,
                MAIN_LINE,
                "postgresql@16-.staging.service active (running), enabled-runtime",
            ],
        )

    def test_entries_without_postgresql_conf_are_not_clusters(self) -> None:
        # A searchable directory without postgresql.conf, and a plain file.
        self.remote.directories[f"{PG_DIR}/16"] += ["old", "README"]
        self.remote.directories[f"{PG_DIR}/16/old"] = []
        self.remote.files[f"{PG_DIR}/16/README"] = "notes"
        self.discover()
        postgres = self.postgres()
        self.assertEqual((postgres.service_status, postgres.service_warning), ("observed", ""))
        self.assertEqual(
            postgres.units.splitlines(),
            [UMBRELLA_LINE, MAIN_LINE],
        )

    def test_unsearchable_cluster_directory_is_inaccessible(self) -> None:
        self.add_cluster("16", "private")
        self.remote.unsearchable.add(f"{PG_DIR}/16/private")
        self.discover()
        postgres = self.assert_uninspected(
            "inaccessible",
            f"The SSH user cannot search {PG_DIR}/16/private. Barectl does not use sudo.",
        )
        self.assertIn("postgresql@16-main.service", postgres.units)
        self.assertNotIn("postgresql@16-private.service", postgres.units)

    def test_clusters_are_not_looked_for_without_an_installed_package(self) -> None:
        # Not installed, and unpacked but not configured.
        for dpkg, status in (("", "absent"), ("postgresql 16+257build1.1 iU \n", "unsupported")):
            with self.subTest(status=status):
                DiscoverySnapshot.objects.all().delete()
                Server.objects.all().delete()
                self.remote.commands.clear()
                self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(1, dpkg)
                self.discover()
                self.assertEqual(self.postgres_commands(), [])
                self.assertEqual(self.postgres().service_status, status)

    def test_every_cluster_of_every_version_is_queried_whether_loaded_or_not(self) -> None:
        # A manual cluster is not wanted by the umbrella unit, so systemd has not loaded it;
        # querying it by name loads it, and it reports "disabled".
        self.add_cluster("16", "reports")
        self.add_cluster("9.6", "legacy")
        units = (
            "postgresql.service postgresql@9.6-legacy.service postgresql@16-main.service "
            "postgresql@16-reports.service"
        )
        self.report_units(
            units,
            UMBRELLA_REPORT,
            cluster_report("9.6", "legacy", active="failed", sub="failed"),
            cluster_report("16", "main"),
            cluster_report("16", "reports", active="inactive", sub="dead", file_state="disabled"),
        )
        self.discover()
        postgres = self.postgres()
        self.assertEqual(postgres.service_status, "observed")
        self.assertEqual(
            postgres.units.splitlines(),
            [
                UMBRELLA_LINE,
                "postgresql@9.6-legacy.service failed (failed), enabled-runtime",
                MAIN_LINE,
                "postgresql@16-reports.service inactive (dead), disabled",
            ],
        )
        self.assertEqual(
            self.postgres_commands(),
            [
                f"ls -1b {PG_DIR}",
                f"ls -1bA {PG_DIR}/9.6",
                f"ls -1bA {PG_DIR}/16",
                f"test -e {cluster_conf('9.6', 'legacy')}",
                f"test -e {cluster_conf('16', 'main')}",
                f"test -e {cluster_conf('16', 'reports')}",
                UNIT_QUERY.format(units),
            ],
        )
        self.assertContains(self.page, "postgresql@16-reports.service inactive (dead), disabled")


class SitePoolTests(DiscoveryTestCase):
    """Nginx site and PHP-FPM pool observations through the full workflow."""

    EXAMPLE_SITE = (
        "server {\n  listen 443 ssl;\n  server_name example.com;\n"
        "  ssl_certificate /etc/ssl/example.pem;\n}\n"
    )
    DEFAULT_SITE = "server {\n  listen 80 default_server;\n}\n"
    POOL_CONF = (
        "[www]\nuser = www-data\nlisten = /run/php/php8.3-fpm.sock\npm = dynamic\n"
        "env[APP_SECRET] = hunter2\nphp_value[soap.wsdl_cache_dir] = /tmp\n"
    )

    def list_dir(self, path: str, entries: list[str]) -> None:
        self.remote.directories[path] = entries
        # The listing proves the directory exists and is readable to the SSH user.
        self.remote.unreadable.discard(path)

    def enable_sites(self, sites: dict[str, str]) -> None:
        self.list_dir(SITE_DIR, list(sites))
        for name, content in sites.items():
            self.remote.files[f"{SITE_DIR}/{name}"] = content

    def enable_pools(self, version: str, pools: dict[str, str]) -> None:
        self.remote.files[fpm_conf_path(version)] = php_fpm_conf(version)
        pool_dir = f"{PHP_DIR}/{version}/fpm/pool.d"
        self.list_dir(pool_dir, list(pools))
        for name, content in pools.items():
            self.remote.files[f"{pool_dir}/{name}"] = content

    def test_sites_and_pools_are_collected_with_provenance_and_time(self) -> None:
        self.enable_sites({"example.com": self.EXAMPLE_SITE, "default": self.DEFAULT_SITE})
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        snapshot = self.discover()
        self.assertEqual(snapshot.nginx_site_files_status, "observed")
        self.assertEqual(snapshot.nginx_site_files_source, SITE_DIR)
        self.assertEqual(
            list(snapshot.nginx_site_files.values_list("name", flat=True)),
            ["example.com", "default"],
        )
        example = snapshot.nginx_site_files.get(name="example.com")
        self.assertEqual(example.status, "observed")
        self.assertEqual(example.server_names, "example.com")
        self.assertEqual(example.listens, "443")
        self.assertEqual(example.source, f"{SITE_DIR}/example.com")
        self.assertEqual(
            list(snapshot.php_fpm_pools.values_list("version", "name")), [("8.3", "www")]
        )
        pool = snapshot.php_fpm_pools.get()
        self.assertEqual((pool.status, pool.listen), ("observed", "/run/php/php8.3-fpm.sock"))
        self.assertEqual(pool.source, f"{PHP_DIR}/8.3/fpm/pool.d/www.conf")
        self.assertEqual(snapshot.php_fpm_pools_status, "observed")
        self.assertEqual(snapshot.php_fpm_pools_source, PHP_DIR)
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)
        page = self.page
        self.assertContains(page, 'aria-labelledby="nginx-site-files-heading"')
        self.assertContains(page, 'aria-labelledby="php-fpm-pools-heading"')
        self.assertContains(page, '<h2 id="nginx-site-files-heading">Nginx site files</h2>')
        self.assertContains(page, '<h2 id="php-fpm-pools-heading">PHP-FPM pools</h2>')
        self.assertContains(page, "Listens on 443")
        self.assertContains(page, "Server names example.com")
        self.assertContains(page, "Listens on 80")
        self.assertContains(page, "<code>www</code> (PHP 8.3)")
        self.assertContains(page, f"Listens on {pool.listen}")
        self.assertContains(page, f"from <code>{SITE_DIR}</code>")
        self.assertContains(page, f"from <code>{PHP_DIR}</code>")
        self.assertContains(page, "does not link them to PHP-FPM pools")
        self.assertContains(page, "This is a snapshot, not live status.")
        self.assertContains(page, f'datetime="{snapshot.collected_at.isoformat()}"')
        # Safe fields only: the TLS certificate path, pool user and secret environment
        # values are never stored or shown.
        for secret in ("ssl_certificate", "/etc/ssl/example.pem", "hunter2", "www-data", "soap"):
            self.assertNotContains(page, secret)
        stored = "\n".join(
            str(row) for row in snapshot.nginx_site_files.values_list("server_names", "listens")
        ) + "\n".join(
            str(row) for row in snapshot.php_fpm_pools.values_list("name", "listen", "source")
        )
        self.assertNotIn("hunter2", stored)

    def install_php_fpm(self, *versions: str) -> None:
        """Make dpkg list PHP-FPM packages for ``versions`` besides the other components."""
        packages = "".join(f"php{v}-fpm {v}.0-1 ii \n" for v in versions)
        others = "".join(f"{line}\n" for line in DPKG_OUTPUT.splitlines() if "php" not in line)
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(0, packages + others)

    def assert_nothing_read_under(self, *paths: str) -> None:
        self.assertFalse([c for c in self.remote.commands if any(p in c for p in paths)])

    def test_uninstalled_components_have_absent_sites_and_pools_without_reads(self) -> None:
        # Nginx was removed without purging (dpkg state rc), leaving its site files behind.
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(
            1, "nginx 1.24.0-2ubuntu7.18 rc \nphp8.3-fpm 8.3.6-0ubuntu0.24.04.11 rc \n"
        )
        self.enable_sites({"example.com": self.EXAMPLE_SITE})
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        snapshot = self.discover()
        self.assertEqual(
            (snapshot.nginx_site_files_status, snapshot.php_fpm_pools_status), ("absent", "absent")
        )
        # The verdict and its provenance come from the package observation.
        self.assertEqual(
            (snapshot.nginx_site_files_source, snapshot.php_fpm_pools_source),
            (PACKAGE_QUERY, PACKAGE_QUERY),
        )
        self.assertFalse(snapshot.nginx_site_files.exists())
        self.assertFalse(snapshot.php_fpm_pools.exists())
        self.assert_nothing_read_under(SITE_DIR, PHP_DIR)
        self.assertContains(self.page, "The dpkg database lists no installed Nginx packages.")
        self.assertContains(self.page, "The dpkg database lists no installed PHP-FPM packages.")
        self.assertNotContains(self.page, "Server names example.com")

    def test_uninspectable_packages_leave_sites_and_pools_uninspected(self) -> None:
        for exit_status, outcome in ((127, "unsupported"), (126, "inaccessible")):
            with self.subTest(exit_status=exit_status):
                DiscoverySnapshot.objects.all().delete()
                Server.objects.all().delete()
                self.remote.commands.clear()
                self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(exit_status, "")
                self.enable_sites({"example.com": self.EXAMPLE_SITE})
                snapshot = self.discover()
                self.assertEqual(
                    (snapshot.nginx_site_files_status, snapshot.php_fpm_pools_status),
                    (outcome, outcome),
                )
                self.assertFalse(snapshot.nginx_site_files.exists())
                self.assert_nothing_read_under(SITE_DIR, PHP_DIR)

    def test_installed_components_without_the_debian_layout_are_unsupported(self) -> None:
        # Nginx and PHP-FPM are installed, but keep their configuration elsewhere.
        self.remote.directories.clear()
        snapshot = self.discover()
        self.assertEqual(
            (snapshot.nginx_site_files_status, snapshot.php_fpm_pools_status),
            ("unsupported", "unsupported"),
        )
        self.assertFalse(snapshot.nginx_site_files.exists())
        self.assertFalse(snapshot.php_fpm_pools.exists())
        for path in (SITE_DIR, f"{PHP_DIR}/8.3/fpm/pool.d"):
            self.assertContains(
                self.page, f"The server has no {path}. Barectl reads only the Debian layout."
            )
        self.assertNotContains(self.page, "Absent")

    def test_sites_are_read_only_when_nginx_conf_includes_the_directory(self) -> None:
        self.enable_sites({"example.com": self.EXAMPLE_SITE})
        cases = {
            # The include was commented out, so Nginx does not load sites-enabled.
            "commented": NGINX_CONF_TEXT.replace(
                "\tinclude /etc/nginx/sites-enabled/*;", "\t# include /etc/nginx/sites-enabled/*;"
            ),
            # Loaded from another directory instead.
            "elsewhere": NGINX_CONF_TEXT.replace("sites-enabled/*", "vhosts/*"),
            # Outside the http block, where it does not load server blocks.
            "outside http": NGINX_CONF_TEXT.replace("\tinclude /etc/nginx/sites-enabled/*;\n", "")
            + "include /etc/nginx/sites-enabled/*;\n",
        }
        for case, text in cases.items():
            with self.subTest(case):
                Server.objects.all().delete()
                self.remote.commands.clear()
                self.remote.files[NGINX_CONF] = text
                snapshot = self.discover()
                self.assertEqual(
                    (snapshot.nginx_site_files_status, snapshot.nginx_site_files_source),
                    ("unsupported", NGINX_CONF),
                )
                self.assertFalse(snapshot.nginx_site_files.exists())
                self.assert_nothing_read_under(SITE_DIR)
                self.assertContains(
                    self.page,
                    "/etc/nginx/nginx.conf does not include /etc/nginx/sites-enabled/*, so "
                    "Barectl cannot confirm which files it loads.",
                )

    def test_an_uninspectable_nginx_conf_leaves_sites_unread(self) -> None:
        self.enable_sites({"example.com": self.EXAMPLE_SITE})
        # Per case: the file's contents (None when there is none), whether the SSH user is
        # refused it, the outcome and the warning.
        cases = {
            "missing": (None, False, "unsupported", f"The server has no {NGINX_CONF}."),
            "unreadable": (None, True, "inaccessible", f"The SSH user cannot read {NGINX_CONF}."),
            "unparseable": (
                "http {\n  include x\n",
                False,
                "unsupported",
                f"{NGINX_CONF} is not in a supported",
            ),
        }
        for case, (text, refused, outcome, warning) in cases.items():
            with self.subTest(case):
                Server.objects.all().delete()
                self.remote.commands.clear()
                self.remote.files.pop(NGINX_CONF, None)
                if text is not None:
                    self.remote.files[NGINX_CONF] = text
                self.remote.unreadable = {NGINX_CONF} if refused else set()
                snapshot = self.discover()
                self.assertEqual(snapshot.nginx_site_files_status, outcome)
                self.assert_nothing_read_under(SITE_DIR)
                self.assertContains(self.page, warning)
                self.assertNotContains(self.page, "include x")

    def test_pools_are_read_only_when_php_fpm_conf_includes_the_directory(self) -> None:
        self.install_php_fpm("8.1", "8.3")
        self.enable_pools("8.1", {"www.conf": "[www]\nlisten = 9000\n"})
        self.enable_pools("8.3", {"admin.conf": "[admin]\nlisten = 9100\n"})
        # PHP-FPM 8.3 loads its pools from somewhere else.
        self.remote.files[fpm_conf_path("8.3")] = php_fpm_conf("8.3").replace(
            "/etc/php/8.3/fpm/pool.d/*.conf", "/srv/pools/*.conf"
        )
        snapshot = self.discover()
        self.assertEqual(
            list(snapshot.php_fpm_pools.values_list("version", "name")), [("8.1", "www")]
        )
        self.assertEqual(snapshot.php_fpm_pools_status, "observed")
        self.assertEqual(snapshot.php_fpm_pools_source, PHP_DIR)
        self.assert_nothing_read_under(f"{PHP_DIR}/8.3/fpm/pool.d")
        self.assertIn(
            "/etc/php/8.3/fpm/php-fpm.conf does not include /etc/php/8.3/fpm/pool.d/*.conf",
            snapshot.php_fpm_pools_warning,
        )
        self.assertNotIn("/srv/pools", snapshot.php_fpm_pools_warning)

    def test_a_missing_php_fpm_conf_leaves_that_version_unread(self) -> None:
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        del self.remote.files[fpm_conf_path("8.3")]
        snapshot = self.discover()
        self.assertEqual(snapshot.php_fpm_pools_status, "unsupported")
        self.assertEqual(snapshot.php_fpm_pools_source, fpm_conf_path("8.3"))
        self.assertFalse(snapshot.php_fpm_pools.exists())
        self.assert_nothing_read_under(f"{PHP_DIR}/8.3/fpm/pool.d")
        self.assertContains(self.page, "The server has no /etc/php/8.3/fpm/php-fpm.conf.")

    def test_empty_configuration_directories_are_observed_empty(self) -> None:
        snapshot = self.discover()
        self.assertEqual(
            (snapshot.nginx_site_files_status, snapshot.php_fpm_pools_status),
            ("observed", "observed"),
        )
        self.assertContains(self.page, "No site configuration files are listed")
        self.assertContains(self.page, "No PHP-FPM pools are configured under /etc/php.")

    def test_permission_denied_directories_are_inaccessible(self) -> None:
        self.remote.unreadable.update({SITE_DIR, f"{PHP_DIR}/8.3/fpm/pool.d"})
        del self.remote.directories[SITE_DIR]
        del self.remote.directories[f"{PHP_DIR}/8.3/fpm/pool.d"]
        snapshot = self.discover()
        self.assertEqual(snapshot.nginx_site_files_status, "inaccessible")
        self.assertFalse(snapshot.nginx_site_files.exists())
        self.assertContains(self.page, "cannot read /etc/nginx/sites-enabled.")
        # The only PHP version's pool directory is denied, so nothing was observed.
        self.assertEqual(snapshot.php_fpm_pools_status, "inaccessible")
        self.assertFalse(snapshot.php_fpm_pools.exists())
        self.assertContains(self.page, "cannot read /etc/php/8.3/fpm/pool.d.")

    def test_total_file_denial_is_inaccessible_not_observed(self) -> None:
        self.list_dir(SITE_DIR, ["secret", "other"])
        self.remote.unreadable.update({f"{SITE_DIR}/secret", f"{SITE_DIR}/other"})
        snapshot = self.discover()
        self.assertEqual(snapshot.nginx_site_files_status, "inaccessible")
        self.assertEqual(
            list(snapshot.nginx_site_files.values_list("name", "status")),
            [("secret", "inaccessible"), ("other", "inaccessible")],
        )
        self.assertContains(self.page, "The SSH user cannot read the site configuration files.")

    def test_a_broken_site_symlink_is_absent_for_that_entry(self) -> None:
        self.enable_sites({"good": self.EXAMPLE_SITE})
        self.remote.directories[SITE_DIR].append("gone")
        snapshot = self.discover()
        self.assertEqual(
            list(snapshot.nginx_site_files.values_list("name", "status")),
            [("good", "observed"), ("gone", "absent")],
        )
        self.assertEqual(snapshot.nginx_site_files_status, "observed")
        self.assertContains(self.page, "The server has no /etc/nginx/sites-enabled/gone.")

    def test_restricted_files_keep_partial_results(self) -> None:
        self.enable_sites({"example.com": self.EXAMPLE_SITE})
        self.remote.directories[SITE_DIR].append("private")
        self.remote.unreadable.add(f"{SITE_DIR}/private")
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        self.remote.directories[f"{PHP_DIR}/8.3/fpm/pool.d"].append("stale.conf.bak")
        self.remote.unreadable.add(f"{PHP_DIR}/8.3/fpm/pool.d/stale.conf.bak")
        snapshot = self.discover()
        self.assertEqual(
            list(snapshot.nginx_site_files.values_list("name", "status")),
            [("example.com", "observed"), ("private", "inaccessible")],
        )
        self.assertEqual(
            snapshot.nginx_site_files.get(name="example.com").server_names, "example.com"
        )
        self.assertContains(self.page, "cannot read /etc/nginx/sites-enabled/private.")
        # PHP-FPM would not load the .bak file, so it is skipped without a read.
        self.assertNotContains(self.page, "stale.conf.bak")
        self.assertFalse([c for c in self.remote.commands if "stale.conf.bak" in c])
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)

    def test_parser_failures_are_unsupported_without_dumps(self) -> None:
        self.enable_sites(
            {
                "broken.conf": "server {\n  listen 80\n  server_name broken.example;\n",
                "upstream-only": "upstream backend {\n  server 10.0.0.1:8000;\n}\n",
                "good": self.EXAMPLE_SITE,
            }
        )
        self.enable_pools("8.3", {"bad.conf": "listen without a section\n"})
        snapshot = self.discover()
        self.assertEqual(
            list(snapshot.nginx_site_files.values_list("name", "status")),
            [
                ("broken.conf", "unsupported"),
                ("upstream-only", "unsupported"),
                ("good", "observed"),
            ],
        )
        # An unparseable pool file is no finding, never "no pools configured".
        self.assertEqual(snapshot.php_fpm_pools_status, "unsupported")
        self.assertFalse(snapshot.php_fpm_pools.exists())
        self.assertNotContains(self.page, "No PHP-FPM pools are configured")
        self.assertContains(
            self.page, "does not define a supported Nginx site configuration", count=2
        )
        self.assertContains(self.page, "does not define a supported PHP-FPM pool configuration")
        # The unparseable contents are never stored or shown.
        for dump in ("broken.example", "10.0.0.1:8000", "listen without a section"):
            self.assertNotContains(self.page, dump)
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)

    def test_pools_are_read_only_for_installed_php_fpm_versions(self) -> None:
        self.install_php_fpm("8.1", "8.3")
        self.enable_pools("8.1", {"www.conf": "[www]\nlisten = 9000\n"})
        # PHP 8.2's CLI left a version directory without PHP-FPM, and PHP-FPM 8.3 keeps
        # its pools outside the Debian layout.
        self.list_dir(f"{PHP_DIR}/8.2/fpm/pool.d", ["www.conf"])
        del self.remote.directories[f"{PHP_DIR}/8.3/fpm/pool.d"]
        snapshot = self.discover()
        self.assertEqual(
            list(snapshot.php_fpm_pools.values_list("version", "name")), [("8.1", "www")]
        )
        self.assertEqual(snapshot.php_fpm_pools_status, "observed")
        self.assert_nothing_read_under(f"{PHP_DIR}/8.2")
        self.assertNotIn(f"ls -1b {PHP_DIR}", self.remote.commands)
        self.assertIn(
            "The server has no /etc/php/8.3/fpm/pool.d. Barectl reads only the Debian layout.",
            snapshot.php_fpm_pools_warning,
        )

    def test_php_fpm_without_a_versioned_package_is_unsupported(self) -> None:
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(1, "php-fpm 2:8.3+93ubuntu2 ii \n")
        snapshot = self.discover()
        self.assertEqual(snapshot.php_fpm_pools_status, "unsupported")
        self.assert_nothing_read_under(PHP_DIR)
        self.assertContains(self.page, "lists no PHP-FPM package for a specific PHP version")

    def test_unreadable_pool_files_are_inaccessible_not_empty(self) -> None:
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        pool_file = f"{PHP_DIR}/8.3/fpm/pool.d/www.conf"
        del self.remote.files[pool_file]
        self.remote.unreadable.add(pool_file)
        snapshot = self.discover()
        self.assertEqual(snapshot.php_fpm_pools_status, "inaccessible")
        self.assertContains(self.page, f"cannot read {pool_file}.")
        self.assertNotContains(self.page, "No PHP-FPM pools are configured")

    def test_a_pool_declared_in_two_files_is_unsupported_without_failing(self) -> None:
        self.enable_pools(
            "8.3",
            {
                "a.conf": "[www]\nlisten = 9000\n",
                "b.conf": "[WWW]\nlisten = 9001\n",
                "c.conf": "[admin]\nlisten = 9100\n",
            },
        )
        snapshot = self.discover()
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)
        self.assertEqual(
            list(snapshot.php_fpm_pools.values_list("name", "status", "listen")),
            [("www", "unsupported", ""), ("admin", "observed", "9100")],
        )
        self.assertEqual(snapshot.php_fpm_pools_status, "observed")
        self.assertContains(self.page, "Pool www is declared more than once")

    def test_sites_with_nothing_observed_are_not_observed(self) -> None:
        self.list_dir(SITE_DIR, ["private", "broken"])
        self.remote.unreadable.add(f"{SITE_DIR}/private")
        self.remote.files[f"{SITE_DIR}/broken"] = "server {\n  listen 80\n"
        snapshot = self.discover()
        self.assertEqual(snapshot.nginx_site_files_status, "unsupported")
        self.assertContains(self.page, "could be read as a supported Nginx site configuration.")

    def test_sites_whose_entries_are_all_gone_are_absent(self) -> None:
        self.list_dir(SITE_DIR, ["gone"])
        snapshot = self.discover()
        self.assertEqual(snapshot.nginx_site_files_status, "absent")
        self.assertEqual(
            list(snapshot.nginx_site_files.values_list("name", "status")), [("gone", "absent")]
        )
        self.assertContains(
            self.page, "None of the entries listed in /etc/nginx/sites-enabled exist."
        )

    def test_entries_of_an_unsearchable_directory_are_inaccessible_not_absent(self) -> None:
        # The SSH user may list the directory but not open the files inside it.
        self.enable_sites({"default": self.DEFAULT_SITE})
        self.remote.unsearchable.add(SITE_DIR)
        snapshot = self.discover()
        self.assertEqual(
            list(snapshot.nginx_site_files.values_list("name", "status")),
            [("default", "inaccessible")],
        )
        self.assertEqual(snapshot.nginx_site_files_status, "inaccessible")

    def test_escaped_entry_names_are_skipped_not_split(self) -> None:
        # ls -b prints a name holding a newline as one escaped line, so it cannot repeat
        # another entry's name.
        self.enable_sites({"default": self.DEFAULT_SITE})
        self.remote.directories[SITE_DIR].append("x\\ndefault")
        snapshot = self.discover()
        self.assertEqual(
            list(snapshot.nginx_site_files.values_list("name", flat=True)), ["default"]
        )
        self.assertContains(self.page, "1 entries whose names Barectl does not interpret")
        self.assertIn(f"ls -1b {SITE_DIR}", self.remote.commands)

    def test_the_pool_cap_is_exact(self) -> None:
        def pool_file(start: int) -> str:
            return "".join(f"[p{i}]\nlisten = {9000 + i}\n" for i in range(start, start + 50))

        pools = {f"{n}.conf": pool_file(n * 50) for n in range(4)}
        self.enable_pools("8.3", pools)
        snapshot = self.discover()
        self.assertEqual(snapshot.php_fpm_pools.count(), 200)
        self.assertNotIn("More than 200", snapshot.php_fpm_pools_warning)

        self.enable_pools("8.3", {**pools, "4.conf": "[extra]\nlisten = 9999\n"})
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.client.post(f"/servers/{snapshot.server.pk}/verify/")
        self.run_worker()
        current = DiscoverySnapshot.objects.get()
        self.assertEqual(current.php_fpm_pools.count(), 200)
        self.assertFalse(current.php_fpm_pools.filter(name="extra").exists())
        self.assertIn("More than 200 PHP-FPM pools were found.", current.php_fpm_pools_warning)

    def test_included_files_are_named_in_warnings(self) -> None:
        self.enable_sites(
            {"example.com": "server {\n  listen 80;\n  include snippets/names.conf;\n}\n"}
        )
        self.enable_pools("8.3", {"www.conf": "[www]\nlisten = 9000\ninclude = /srv/*.conf\n"})
        snapshot = self.discover()
        self.assertEqual(
            (snapshot.nginx_site_files_status, snapshot.php_fpm_pools_status),
            ("observed", "observed"),
        )
        self.assertContains(
            self.page,
            f"{SITE_DIR}/example.com includes other configuration files. Barectl does not "
            "read them",
        )
        self.assertContains(
            self.page,
            f"{PHP_DIR}/8.3/fpm/pool.d/www.conf includes other configuration files.",
        )
        self.assertNotContains(self.page, "/srv/")

    def test_entries_with_unsupported_names_are_skipped(self) -> None:
        self.enable_sites({"good": self.EXAMPLE_SITE})
        self.remote.directories[SITE_DIR].append("weird name")
        snapshot = self.discover()
        self.assertEqual(list(snapshot.nginx_site_files.values_list("name", flat=True)), ["good"])
        self.assertContains(self.page, "1 entries whose names Barectl does not interpret")
        self.assertFalse([c for c in self.remote.commands if "weird name" in c])

    def test_repeated_discovery_replaces_state_without_duplicates(self) -> None:
        self.enable_sites({"example.com": self.EXAMPLE_SITE, "default": self.DEFAULT_SITE})
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        first = self.discover()
        self.assertEqual(first.nginx_site_files.count(), 2)
        self.assertEqual(first.php_fpm_pools.count(), 1)
        self.sign_in_with("view_server", "add_discoveryattempt")

        # example.com is removed, default changes its listen address, and a second
        # PHP version appears.
        self.enable_sites(
            {"default": "server {\n  listen 8080;\n  server_name default.example;\n}\n"}
        )
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        self.enable_pools("8.1", {"admin.conf": "[admin]\nlisten = 127.0.0.1:9100\n"})
        self.install_php_fpm("8.1", "8.3")
        self.client.post(f"/servers/{first.server.pk}/verify/")
        self.run_worker()

        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        current = DiscoverySnapshot.objects.get()
        self.assertNotEqual(current.pk, first.pk)
        self.assertEqual(
            list(current.nginx_site_files.values_list("name", "server_names", "listens")),
            [("default", "default.example", "8080")],
        )
        self.assertEqual(
            list(current.php_fpm_pools.values_list("version", "name")),
            [("8.1", "admin"), ("8.3", "www")],
        )
        self.assertEqual(current.php_fpm_pools.count(), 2)
        page = self.client.get(f"/servers/{current.server.pk}/")
        self.assertNotContains(page, "<code>example.com</code>")
        self.assertNotContains(page, "Server names example.com")
        self.assertContains(page, "Listens on 8080")
        self.assertContains(page, "127.0.0.1:9100")


class VerifyConnectionTests(DiscoveryTestCase):
    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def verify_url(self) -> str:
        return f"/servers/{self.server.pk}/verify/"

    def test_verification_requires_permission_and_post(self) -> None:
        self.assertRedirects(
            self.client.post(self.verify_url()), f"/accounts/login/?next={self.verify_url()}"
        )
        self.sign_in_with("view_server")
        self.assertEqual(self.client.post(self.verify_url()).status_code, 403)
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertNotContains(page, "Verify connection")
        self.grant("add_discoveryattempt")
        self.assertEqual(self.client.get(self.verify_url()).status_code, 405)
        self.assertFalse(DiscoveryAttempt.objects.exists())

    def test_verification_requires_csrf(self) -> None:
        self.grant("view_server", "add_discoveryattempt")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        self.assertEqual(client.post(self.verify_url()).status_code, 403)
        self.assertFalse(DiscoveryAttempt.objects.exists())

    def test_explicit_verification_queues_one_attempt(self) -> None:
        self.sign_in_with("view_server", "add_discoveryattempt")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "<strong>Not verified.</strong>", html=True)
        self.assertContains(page, "Verify connection")
        response = self.client.post(self.verify_url())
        self.assertRedirects(response, f"/servers/{self.server.pk}/", fetch_redirect_response=False)
        # Repeated submissions share the active attempt instead of queueing another.
        self.client.post(self.verify_url())
        self.client.post(self.verify_url(), headers=HTMX_FRAGMENT)
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)
        self.assertEqual(DBTaskResult.objects.count(), 1)
        self.run_worker()
        self.assertEqual(self.remote.targets[0].alias, "web.example.com")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "<strong>Verified</strong>", html=True)
        # A verified server offers an explicit refresh that queues new work.
        self.assertContains(page, "Refresh observations")
        response = self.client.post(self.verify_url(), follow=True)
        self.assertContains(response, "Barectl queued a connection check for Web.")
        self.assertEqual(DiscoveryAttempt.objects.count(), 2)

    def test_htmx_verification_returns_a_polling_fragment_and_announces_changes(self) -> None:
        self.sign_in_with("view_server", "add_discoveryattempt")
        response = self.client.post(self.verify_url(), headers=HTMX_FRAGMENT)
        content = response.content.decode()
        self.assertNotIn("<html", content)
        self.assertRegex(content, r'<div id="discovery"[^>]*hx-trigger="every 2s"')
        self.assertIn(f"/servers/{self.server.pk}/discovery/?shown=queued", content)
        self.assertIn('<hx-partial hx-target="#discovery-announcement"', content)
        self.assertIn("Connection check queued.", content)
        poll = f"/servers/{self.server.pk}/discovery/?shown=queued"
        self.assertRegex(
            content, r'<hx-partial hx-target="#connection-status"[^>]*>\s*Connection check queued'
        )
        unchanged = self.client.get(poll, headers=HTMX_FRAGMENT).content.decode()
        self.assertNotIn("hx-partial", unchanged)
        self.run_worker()
        finished = self.client.get(poll, headers=HTMX_FRAGMENT)
        self.assertNotContains(finished, "hx-trigger")
        self.assertContains(finished, "Connection verified.")
        # The Status row above the fragment changes with it.
        self.assertRegex(
            finished.content.decode(),
            r'<hx-partial hx-target="#connection-status"[^>]*>\s*Verified\s*</hx-partial>',
        )
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, '<dd id="connection-status">Verified</dd>', html=True)
        self.assertContains(finished, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertIn("HX-Request-Type", finished.headers["Vary"])
        # A plain request for the fragment URL gets the complete page.
        self.assertRedirects(
            self.client.get(f"/servers/{self.server.pk}/discovery/"),
            f"/servers/{self.server.pk}/",
        )

    def test_failed_verification_can_be_retried(self) -> None:
        self.remote.failure = "The server rejected the SSH credentials available for web."
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.client.post(self.verify_url())
        self.run_worker()
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "rejected the SSH credentials")
        self.assertContains(page, "Retry connection check")
        self.remote.failure = ""
        self.client.post(self.verify_url())
        self.run_worker()
        self.assertEqual(
            list(DiscoveryAttempt.objects.values_list("status", flat=True)),
            ["succeeded", "failed"],
        )

    def test_persistence_allows_one_active_attempt_per_server(self) -> None:
        request_discovery(self.server)
        for status in DiscoveryAttempt.ACTIVE:
            with (
                self.subTest(status=status),
                self.assertRaises(IntegrityError),
                transaction.atomic(),
            ):
                DiscoveryAttempt.objects.create(server=self.server, ssh_alias="x", status=status)
        DiscoveryAttempt.objects.create(server=self.server, ssh_alias="x", status="failed")
        # Other servers are independent.
        other = Server.objects.create(name="Other", ssh_alias="db-1")
        self.assertNotEqual(request_discovery(other), request_discovery(self.server))

    def test_unknown_servers_are_not_found(self) -> None:
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.assertEqual(self.client.get("/servers/999/").status_code, 404)
        self.assertEqual(self.client.post("/servers/999/verify/").status_code, 404)

    def test_detail_requires_view_permission(self) -> None:
        url = f"/servers/{self.server.pk}/"
        self.assertRedirects(self.client.get(url), f"/accounts/login/?next={url}")
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(url).status_code, 403)
        response = self.client.get(f"{url}discovery/", headers=HTMX_FRAGMENT)
        self.assertEqual(response.headers["HX-Refresh"], "true")


class AliasChangeTests(DiscoveryTestCase):
    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def edit(self, name: str, alias: str) -> None:
        self.response = self.client.post(
            f"/servers/{self.server.pk}/edit/", {"name": name, "ssh_alias": alias}
        )

    def test_renaming_does_not_queue_a_check(self) -> None:
        self.sign_in_with("view_server", "change_server")
        self.edit("Renamed", "web.example.com")
        self.assertFalse(DiscoveryAttempt.objects.exists())

    def test_alias_cannot_change_while_a_check_is_active(self) -> None:
        request_discovery(self.server)
        self.sign_in_with("view_server", "change_server")
        self.edit("Web", "db-1")
        self.assertContains(self.response, "Change it after the check finishes.", count=2)
        self.server.refresh_from_db()
        self.assertEqual(self.server.ssh_alias, "web.example.com")
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)

    def test_a_failed_check_keeps_the_earlier_snapshot(self) -> None:
        request_discovery(self.server)
        self.run_worker()
        self.sign_in_with("view_server", "change_server")
        self.edit("Web", "db-1")
        self.remote.failure = "Barectl could not reach the SSH service configured for db-1."
        self.run_worker()
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Connection failed")
        self.assertContains(page, "could not reach the SSH service configured for db-1.")
        # The observations collected through the earlier alias remain, labeled as such.
        self.assertContains(page, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertContains(page, "over SSH alias <code>web.example.com</code>")
        self.assertContains(page, "The latest connection check failed, so these observations")
        self.assertEqual(DiscoverySnapshot.objects.count(), 1)


class RefreshTests(DiscoveryTestCase):
    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def verify_url(self) -> str:
        return f"/servers/{self.server.pk}/verify/"

    def succeed_once(self) -> DiscoverySnapshot:
        request_discovery(self.server)
        self.run_worker()
        return DiscoverySnapshot.objects.get()

    def test_refresh_queues_work_shows_progress_and_replaces_snapshot(self) -> None:
        first = self.succeed_once()
        self.sign_in_with("view_server", "add_discoveryattempt")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Refresh observations")
        self.assertNotContains(page, "hx-trigger")

        response = self.client.post(self.verify_url(), headers=HTMX_FRAGMENT)
        content = response.content.decode()
        self.assertRegex(content, r'<div id="discovery"[^>]*hx-trigger="every 2s"')
        self.assertIn("Connection check queued.", content)
        self.assertIn('<hx-partial hx-target="#discovery-announcement"', content)

        # Repeated refresh submissions share the active attempt.
        self.client.post(self.verify_url())
        self.client.post(self.verify_url(), headers=HTMX_FRAGMENT)
        self.assertEqual(DiscoveryAttempt.objects.count(), 2)
        self.assertEqual(
            DiscoveryAttempt.objects.filter(status__in=DiscoveryAttempt.ACTIVE).count(), 1
        )

        self.remote.files = {"/etc/os-release": 'PRETTY_NAME="Ubuntu 24.04.4 LTS"\nID=ubuntu\n'}
        self.run_worker()

        attempts = list(DiscoveryAttempt.objects.order_by("queued_at"))
        self.assertEqual(
            [attempt.status for attempt in attempts],
            [
                DiscoveryAttempt.Status.SUCCEEDED,
                DiscoveryAttempt.Status.SUCCEEDED,
            ],
        )
        # A successful refresh replaces the current snapshot coherently.
        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        snapshot = DiscoverySnapshot.objects.get()
        self.assertEqual(snapshot.attempt, attempts[1])
        self.assertEqual(snapshot.os_pretty_name, "Ubuntu 24.04.4 LTS")
        self.assertNotEqual(snapshot.pk, first.pk)
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Ubuntu 24.04.4 LTS")
        self.assertNotContains(page, "may be out of date")

    def test_refresh_replaces_service_observations(self) -> None:
        before = self.succeed_once()
        self.assertEqual(before.components.count(), 4)
        # Nginx was uninstalled and MariaDB stopped between the two discoveries.
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(1, DPKG_OUTPUT.replace("nginx ", ""))
        self.remote.results[UNIT_QUERY.format("mariadb.service")] = ssh.CommandResult(
            0, unit_report("mariadb.service", active="inactive", sub="dead")
        )
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.client.post(self.verify_url())
        self.run_worker()
        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        after = DiscoverySnapshot.objects.get()
        self.assertNotEqual(after.pk, before.pk)
        self.assertEqual(
            list(after.components.values_list("component", "package_status", "service_status")),
            [
                ("nginx", "absent", "absent"),
                ("php-fpm", "observed", "observed"),
                ("mariadb", "observed", "observed"),
                ("postgresql", "observed", "observed"),
            ],
        )
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertNotContains(page, "nginx 1.24.0-2ubuntu7.18")
        self.assertContains(page, "mariadb.service inactive (dead), enabled")

    def test_failed_refresh_preserves_snapshot_and_offers_retry(self) -> None:
        self.succeed_once()
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.remote.failure = "Barectl could not reach the SSH service configured for web."
        self.client.post(self.verify_url())
        self.run_worker()

        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        snapshot = DiscoverySnapshot.objects.get()
        self.assertEqual(snapshot.os_pretty_name, "Ubuntu 24.04.3 LTS")
        latest = DiscoveryAttempt.objects.get(status=DiscoveryAttempt.Status.FAILED)
        self.assertEqual(latest.status, DiscoveryAttempt.Status.FAILED)
        self.assertFalse(DiscoverySnapshot.objects.filter(attempt=latest).exists())

        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Connection failed")
        self.assertContains(page, "could not reach the SSH service")
        self.assertContains(page, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertContains(page, "The latest connection check failed, so these observations")
        self.assertContains(page, "Retry connection check")
        # No automatic retry: one failed attempt stays until the operator retries.
        self.assertEqual(DiscoveryAttempt.objects.count(), 2)

        self.remote.failure = ""
        self.client.post(self.verify_url())
        self.run_worker()
        self.assertEqual(DiscoveryAttempt.objects.count(), 3)
        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "<strong>Verified</strong>", html=True)
        self.assertContains(page, "Refresh observations")

    def test_partial_refresh_keeps_warnings_not_absent_software(self) -> None:
        self.succeed_once()
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.remote.files = {}
        self.remote.unreadable = {"/etc/os-release"}
        self.client.post(self.verify_url())
        self.run_worker()

        snapshot = DiscoverySnapshot.objects.get()
        self.assertEqual(snapshot.os_status, "inaccessible")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "<strong>Inaccessible:</strong>", html=True)
        self.assertNotContains(page, "No observations yet.")
        self.assertEqual(snapshot.attempt.status, DiscoveryAttempt.Status.SUCCEEDED)

    def test_unsupported_refresh_is_not_absent_software(self) -> None:
        self.succeed_once()
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.remote.files = {"/etc/os-release": "<html>not a release file</html>\n"}
        self.client.post(self.verify_url())
        self.run_worker()

        snapshot = DiscoverySnapshot.objects.get()
        self.assertEqual(snapshot.os_status, "unsupported")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "<strong>Unsupported:</strong>", html=True)
        self.assertNotContains(page, "not a release file")

    def test_snapshot_age_is_labelled(self) -> None:
        snapshot = self.succeed_once()
        DiscoverySnapshot.objects.filter(pk=snapshot.pk).update(
            collected_at=timezone.now() - datetime.timedelta(hours=3, minutes=5)
        )
        self.sign_in_with("view_server")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "(3\xa0hours, 5\xa0minutes ago)")

    def test_bounded_timeout_failure_preserves_snapshot(self) -> None:
        self.succeed_once()
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.remote.failure = (
            "A discovery command did not finish within 15 seconds. Barectl closed the connection."
        )
        self.client.post(self.verify_url())
        self.run_worker()

        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "did not finish within")
        self.assertContains(page, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertContains(page, "may be out of date")


class RecoveryTests(DiscoveryTestCase):
    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def make_stale(
        self, attempt: DiscoveryAttempt, *, queued: bool = False, started: bool = False
    ) -> None:
        past = timezone.now() - STALE_AFTER - datetime.timedelta(minutes=1)
        query = DiscoveryAttempt.objects.filter(pk=attempt.pk)
        if queued:
            query.update(queued_at=past)
        if started:
            query.update(started_at=past)

    def interrupt_running(self) -> DiscoveryAttempt:
        """Leave a refresh running after a success, as a worker killed mid-task would."""
        request_discovery(self.server)
        self.run_worker()
        interrupted = request_discovery(self.server)
        claimed = DiscoveryAttempt.objects.filter(
            pk=interrupted.pk, status=DiscoveryAttempt.Status.QUEUED
        ).update(status=DiscoveryAttempt.Status.RUNNING, started_at=timezone.now())
        self.assertEqual(claimed, 1)
        interrupted.refresh_from_db()
        return interrupted

    def test_running_interruption_is_recovered_and_retryable(self) -> None:
        attempt = self.interrupt_running()
        snapshot = DiscoverySnapshot.objects.get()
        self.make_stale(attempt, started=True)

        recovered = recover_stale_attempts()
        self.assertEqual(recovered, 1)
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("stopped before finishing", attempt.failure)
        self.assertEqual(attempt.failure, INTERRUPTED_FAILURE)
        # The previous snapshot is preserved and labeled stale in the page.
        self.assertEqual(DiscoverySnapshot.objects.get().pk, snapshot.pk)
        self.sign_in_with("view_server", "add_discoveryattempt")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "stopped before finishing")
        self.assertContains(page, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertContains(page, "may be out of date")
        self.assertContains(page, "Retry connection check")

        self.client.post(f"/servers/{self.server.pk}/verify/")
        self.run_worker()
        self.assertEqual(
            DiscoveryAttempt.objects.filter(status=DiscoveryAttempt.Status.SUCCEEDED).count(), 2
        )

    def test_abandoned_queued_attempt_without_waiting_task_is_recovered(self) -> None:
        attempt = request_discovery(self.server)
        self.make_stale(attempt, queued=True)
        # No worker ever claimed it and no READY task remains (simulating a lost task).
        DBTaskResult.objects.all().delete()
        recovered = recover_stale_attempts()
        self.assertEqual(recovered, 1)
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("stopped before finishing", attempt.failure)

    def test_queued_with_ready_task_waits_for_worker(self) -> None:
        attempt = request_discovery(self.server)
        self.make_stale(attempt, queued=True)
        # A READY task still waits: restarting the worker should run it, not fail it.
        self.assertEqual(recover_stale_attempts(), 0)
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.QUEUED)
        self.run_worker()
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED)

    def test_queued_attempt_whose_task_a_worker_claimed_is_left_until_that_goes_stale(
        self,
    ) -> None:
        attempt = request_discovery(self.server)
        self.make_stale(attempt, queued=True)
        # A worker claimed the task and is about to claim the attempt.
        task = DBTaskResult.objects.get()
        task.claim("worker-1")
        self.assertEqual(recover_stale_attempts(), 0)
        # That worker was killed before claiming the attempt.
        past = timezone.now() - STALE_AFTER - datetime.timedelta(minutes=1)
        DBTaskResult.objects.filter(pk=task.pk).update(started_at=past)
        self.assertEqual(recover_stale_attempts(), 1)
        attempt.refresh_from_db()
        self.assertEqual(attempt.failure, INTERRUPTED_FAILURE)

    def test_stale_worker_cannot_overwrite_recovery_or_newer_result(self) -> None:
        stale = self.interrupt_running()
        first_snapshot = DiscoverySnapshot.objects.get()
        self.make_stale(stale, started=True)
        recover_stale_attempts()
        stale.refresh_from_db()
        self.assertEqual(stale.status, DiscoveryAttempt.Status.FAILED)

        # The stale worker finishes late: its conditional update must not win.
        services._finish_failed(stale.pk, "late failure from stale worker")
        stale.refresh_from_db()
        self.assertEqual(stale.status, DiscoveryAttempt.Status.FAILED)
        self.assertEqual(stale.failure, INTERRUPTED_FAILURE)

        # Nor can it publish a snapshot after recovery.
        with mock.patch.object(ssh, "connect", self.remote.connect):
            services._discover(stale)
        self.assertEqual(DiscoverySnapshot.objects.get().pk, first_snapshot.pk)
        self.assertFalse(
            DiscoverySnapshot.objects.filter(attempt=stale).exists(),
        )

        # A newer refresh still succeeds coherently after the interruption.
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.client.post(f"/servers/{self.server.pk}/verify/")
        self.run_worker()
        self.assertEqual(DiscoverySnapshot.objects.count(), 1)
        self.assertNotEqual(DiscoverySnapshot.objects.get().pk, first_snapshot.pk)

    def test_worker_restart_recovery_through_real_worker_integration(self) -> None:
        interrupted = self.interrupt_running()
        self.make_stale(interrupted, started=True)
        # The next real worker run recovers abandoned attempts before claiming new work.
        other = Server.objects.create(name="Other", ssh_alias="db-1")
        request_discovery(other)
        self.run_worker()
        interrupted.refresh_from_db()
        self.assertEqual(interrupted.status, DiscoveryAttempt.Status.FAILED)
        self.assertIn("stopped before finishing", interrupted.failure)

    def test_polling_recovers_abandoned_attempt_without_new_work(self) -> None:
        interrupted = self.interrupt_running()
        self.sign_in_with("view_server", "add_discoveryattempt")
        # Within the bound the attempt may still finish, so the page keeps polling.
        fragment = self.client.get(
            f"/servers/{self.server.pk}/discovery/?shown=running", headers=HTMX_FRAGMENT
        )
        self.assertContains(fragment, 'hx-trigger="every 2s"')
        self.assertNotContains(fragment, "Retry connection check")

        # Past the bound, with no worker running anything, the next poll recovers it.
        self.make_stale(interrupted, started=True)
        fragment = self.client.get(
            f"/servers/{self.server.pk}/discovery/?shown=running", headers=HTMX_FRAGMENT
        )
        interrupted.refresh_from_db()
        self.assertEqual(interrupted.status, DiscoveryAttempt.Status.FAILED)
        content = fragment.content.decode()
        self.assertNotIn("hx-trigger", content)
        self.assertIn("stopped before finishing", content)
        self.assertIn("Retry connection check", content)
        self.assertContains(fragment, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertRegex(
            content, r'hx-target="#discovery-announcement"[^>]*>\s*The connection failed\.'
        )

    def test_server_list_recovers_abandoned_attempts(self) -> None:
        interrupted = self.interrupt_running()
        self.make_stale(interrupted, started=True)
        self.sign_in_with("view_server")
        page = self.client.get("/")
        self.assertContains(page, "Web")
        self.assertNotContains(page, "Checking connection")
        interrupted.refresh_from_db()
        self.assertEqual(interrupted.status, DiscoveryAttempt.Status.FAILED)

    def test_forced_worker_stop_marks_attempt_interrupted(self) -> None:
        request_discovery(self.server)
        self.run_worker()
        snapshot = DiscoverySnapshot.objects.get()
        # A second Ctrl+C makes the worker exit in the middle of the task.
        self.remote.interrupt = True
        attempt = request_discovery(self.server)
        self.run_worker()
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)
        self.assertEqual(attempt.failure, INTERRUPTED_FAILURE)
        self.assertEqual(DiscoverySnapshot.objects.get().pk, snapshot.pk)
