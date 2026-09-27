"""The registration-to-result workflow through Django requests and the durable worker.

Real views, services, persistence, alias resolution and the ``db_worker`` command run;
only remote execution is substituted, at ``discovery.ssh.connect``.
"""

import datetime
import re
import signal
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import ClassVar, Literal, override
from unittest import mock

from django.core.management import call_command
from django.db import IntegrityError, connection, transaction
from django.db.models.deletion import Collector
from django.http.response import HttpResponseBase
from django.test import Client, SimpleTestCase, TransactionTestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from django.utils.formats import date_format
from django_tasks_db.models import DBTaskResult

from servers.models import Server
from servers.ssh_config import ConnectionTarget
from servers.tests import HTMX_FRAGMENT, ControllerConfigTestCase

from . import ssh
from .models import (
    ComponentObservation,
    DiscoveryAttempt,
    DiscoverySnapshot,
    ObservationOutcome,
    WebStackComponent,
)
from .observations import collect
from .services import (
    INTERRUPTED_FAILURE,
    STALE_AFTER,
    RemovalBlocked,
    read_discovery,
    remove_server,
    request_discovery,
)
from .snapshot import (
    CollectedSnapshot,
    FilesystemSize,
    Observation,
    OsRelease,
    Package,
    Snapshot,
    WebStackComponentObservation,
    current_snapshot,
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
    r"|\Atest -[ex] (/etc|/usr/lib|/proc|/etc/nginx|/etc/php(/[0-9.]+(/fpm)?)?)\Z"
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
    # Directories every supported server has, whatever else a test removes.
    base_directories: set[str] = field(default_factory=lambda: {"/etc", "/proc", "/usr/lib"})
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
        """Answer a probe as a POSIX shell does (checked by test_fake_server.py)."""
        self.commands.append(command)
        if command in self.results:
            return self.results[command]
        if command.startswith(("ls -1b ", "ls -1bA ")):
            options, _, path = command.partition(" ")[2].partition(" ")
            if not self._exists(path) or not self._is_directory(path) or path in self.unreadable:
                return ssh.CommandResult(2, "")
            # Without -A, ls omits names that start with ".".
            entries = [e for e in self._entries(path) if "A" in options or e[0] != "."]
            return ssh.CommandResult(0, "".join(f"{entry}\n" for entry in entries))
        verb, _, path = command.rpartition(" ")
        exists = self._exists(path)
        answers = {
            "test -e": exists,
            "test -d": exists and self._is_directory(path),
            "test -r": exists and path not in self.unreadable,
            # Only directories are searchable; files are never executable here.
            "test -x": exists
            and self._is_directory(path)
            and path not in self.unsearchable
            and path not in self.unreadable,
            "test -L": path in self.dead_links and not self._hidden(path),
        }
        if verb in answers:
            return ssh.CommandResult(0 if answers[verb] else 1, "")
        if exists and path in self.files and path not in self.unreadable:
            return ssh.CommandResult(0, self.files[path])
        return ssh.CommandResult(1, "")

    def _described(self) -> tuple[str, ...]:
        return (
            *self.files,
            *self.directories,
            *self.unreadable,
            *self.dead_links,
            *self.base_directories,
        )

    def _is_directory(self, path: str) -> bool:
        """A listed directory, or an ancestor of any described path."""
        prefix = path if path.endswith("/") else f"{path}/"
        if path in self.directories or path in self.base_directories:
            return True
        return any(p.startswith(prefix) for p in self._described())

    def _hidden(self, path: str) -> bool:
        """Whether an ancestor the SSH user cannot search hides the path."""
        parent = path.rpartition("/")[0] or "/"
        while path != "/":
            if parent in self.unsearchable or (
                parent in self.unreadable and self._is_directory(parent)
            ):
                return True
            path, parent = parent, parent.rpartition("/")[0] or "/"
        return False

    def _exists(self, path: str) -> bool:
        if self._hidden(path) or path in self.dead_links:
            return False
        return path in self.files or path in self.unreadable or self._is_directory(path)

    def _entries(self, path: str) -> list[str]:
        """The listed entries, or the names of the described paths directly inside."""
        if path in self.directories:
            return self.directories[path]
        prefix = path if path.endswith("/") else f"{path}/"
        names: list[str] = []
        for described in self._described():
            if described.startswith(prefix):
                name = described[len(prefix) :].partition("/")[0]
                if name not in names:
                    names.append(name)
        return names


def run_worker() -> None:
    """Run the durable worker until the queue is empty, as `manage.py db_worker` does."""
    # The worker installs its own signal handlers; restore the test runner's afterwards.
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        call_command("db_worker", batch=True, startup_delay=False, interval=0, verbosity=0)
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


def current(server: Server) -> Snapshot:
    """The server's current snapshot, failing the test when it has none."""
    snapshot = current_snapshot(server)
    if snapshot is None:
        raise AssertionError(f"{server} has no snapshot.")
    return snapshot


def observed[T](observation: Observation[T | None]) -> T:
    """The observation's value, failing the test when it was not observed."""
    if observation.value is None:
        raise AssertionError(f"The observation is {observation.outcome}, not observed.")
    return observation.value


def kept_text(value: object) -> str:
    """Every value a collection keeps, as text: what could ever be stored or shown."""
    if is_dataclass(value) and not isinstance(value, type):
        return "\n".join(kept_text(getattr(value, item.name)) for item in fields(value))
    if isinstance(value, tuple):
        return "\n".join(kept_text(item) for item in value)
    return str(value)


class FakeServerMixin(SimpleTestCase):
    """A FakeServer for each test, which may only ever be read from."""

    remote: FakeServer

    @override
    def setUp(self) -> None:
        super().setUp()
        self.remote = FakeServer()
        # Whatever a test's server looks like, discovery only reads from it.
        self.addCleanup(self.assert_read_only)

    def assert_read_only(self) -> None:
        for command in self.remote.commands:
            self.assertRegex(command, READ_ONLY)


class ObservationTestCase(FakeServerMixin):
    """Observation rules, tested through ``collect`` without a database or the worker."""

    collected: CollectedSnapshot

    def collect(self) -> CollectedSnapshot:
        """Collect from ``self.remote``, keeping the result as ``self.collected``."""
        self.collected = collect(self.remote)
        return self.collected

    def component(self, name: str) -> WebStackComponentObservation:
        """The last collection's observation of the ``name`` component."""
        (observation,) = (
            candidate for candidate in self.collected.components if candidate.component == name
        )
        return observation

    def warned(self) -> list[tuple[str, str]]:
        """The last collection's warnings, as (observation, outcome) pairs in display order."""
        return [(item.observation, item.outcome) for item in self.collected.warnings]

    def assert_not_kept(self, *texts: str) -> None:
        """Assert no value of the last collection holds any of ``texts``."""
        kept = kept_text(self.collected)
        for text in texts:
            self.assertNotIn(text, kept)

    def assert_nothing_absent(self) -> None:
        """Assert no observation of the last collection, or of its entries, is absent."""
        collected = self.collected
        outcomes = [
            collected.os.outcome,
            *(observation.outcome for observation in collected.capacity),
            *(c.package.outcome for c in collected.components),
            *(c.service.outcome for c in collected.components),
            collected.nginx_site_files.outcome,
            *(site.outcome for site in collected.nginx_site_files.value),
            collected.php_fpm_pools.outcome,
            *(pool.outcome for pool in collected.php_fpm_pools.value),
        ]
        self.assertNotIn(ObservationOutcome.ABSENT, outcomes)


class DiscoveryTestCase(FakeServerMixin, ControllerConfigTestCase):
    snapshot: Snapshot

    @override
    def setUp(self) -> None:
        super().setUp()
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

    def discover(self) -> CollectedSnapshot:
        """Register a server, run the worker, and return what it observed.

        The server page is kept as ``self.page`` and the snapshot as ``self.snapshot``.
        """
        server = self.register()
        self.run_worker()
        self.page = self.client.get(f"/servers/{server.pk}/")
        self.snapshot = current(server)
        return self.snapshot.collected

    def component(self, name: str) -> WebStackComponentObservation:
        """The current snapshot's observation of the ``name`` component."""
        (observation,) = (
            candidate
            for candidate in current(Server.objects.get()).collected.components
            if candidate.component == name
        )
        return observation

    def assert_succeeded(self) -> None:
        """Assert the server's latest discovery attempt succeeded."""
        attempt = Server.objects.get().discovery_attempts.latest("queued_at", "pk")
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED)


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
        self.assertEqual(DiscoverySnapshot.objects.get().attempt, attempt)
        self.snapshot = current(server)
        release = observed(self.snapshot.collected.os)
        self.assertEqual(
            (
                release.pretty_name,
                release.id,
                release.version_id,
                self.snapshot.collected.os.source,
            ),
            ("Ubuntu 24.04.3 LTS", "ubuntu", "24.04", ("/etc/os-release",)),
        )
        page = self.client.get(f"/servers/{server.pk}/")
        self.assertContains(page, "<dd>Ubuntu 24.04.3 LTS</dd>", html=True)
        self.assertContains(page, "<dd>24.04</dd>", html=True)
        self.assertContains(page, "from <code>/etc/os-release</code>")
        self.assertContains(page, f"<code>{HOST_KEY}</code>")
        self.assertContains(page, "This is a snapshot, not live status.")
        self.assertContains(page, f'datetime="{self.snapshot.collected_at.isoformat()}"')
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
        # Every test checks the commands against READ_ONLY (see assert_read_only).
        self.assertTrue(self.remote.commands)
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


class PartialObservationTests(ObservationTestCase):
    def test_unreadable_release_file_is_inaccessible_not_absent(self) -> None:
        self.remote.files = {}
        self.remote.unreadable = {"/etc/os-release"}
        collected = self.collect()
        self.assertEqual(collected.os.outcome, "inaccessible")
        self.assertIsNone(collected.os.value)
        self.assertIn(("Operating system", "inaccessible"), self.warned())
        self.assertEqual(
            collected.os.warning,
            "The SSH user cannot read /etc/os-release. Barectl does not use sudo.",
        )

    def test_missing_release_files_are_unsupported_not_absent(self) -> None:
        # Every server runs an operating system; Barectl just cannot identify this one.
        self.remote.files = {}
        collected = self.collect()
        self.assertEqual(collected.os.outcome, "unsupported")
        self.assertEqual(
            collected.os.warning,
            "The server has neither /etc/os-release nor /usr/lib/os-release, so Barectl "
            "cannot identify the operating system.",
        )

    def test_fallback_release_file_is_used(self) -> None:
        self.remote.files = {"/usr/lib/os-release": 'NAME="Debian GNU/Linux"\nID=debian\n'}
        collected = self.collect()
        self.assertEqual(
            (collected.os.outcome, collected.os.source), ("observed", ("/usr/lib/os-release",))
        )
        # Fields the file does not set are empty, not guessed.
        self.assertEqual(observed(collected.os), OsRelease("", "Debian GNU/Linux", "debian", ""))

    def test_unrecognized_content_is_unsupported(self) -> None:
        self.remote.files = {"/etc/os-release": "<html>not a release file</html>\nX=$(id)\n"}
        collected = self.collect()
        self.assertEqual(collected.os.outcome, "unsupported")
        self.assertIn(("Operating system", "unsupported"), self.warned())
        self.assert_not_kept("not a release file")

    def test_values_are_unquoted_bounded_and_never_executed(self) -> None:
        self.remote.files = {
            "/etc/os-release": (
                "# comment\nNAME='Example $(touch /tmp/x)'\nID=example\n"
                f'PRETTY_NAME="{"x" * 500}"\nVERSION_ID="1\\"2"\nBROKEN="unterminated\n'
            )
        }
        release = observed(self.collect().os)
        self.assertEqual(release.name, "Example $(touch /tmp/x)")
        self.assertEqual(len(release.pretty_name), 200)
        self.assertEqual(release.version_id, '1"2')


class CapacityTests(ObservationTestCase):
    def test_capacity_is_collected_with_units_provenance_and_time(self) -> None:
        collected = self.collect()
        architecture, cpu_count = collected.architecture, collected.cpu_count
        self.assertEqual(
            (architecture.outcome, architecture.value, architecture.source),
            ("observed", "x86_64", ("uname -m",)),
        )
        self.assertEqual(
            (cpu_count.outcome, cpu_count.value, cpu_count.source), ("observed", 4, ("nproc",))
        )
        memory = collected.memory_bytes
        self.assertEqual(
            (memory.outcome, memory.value, memory.source),
            ("observed", 4024548 * 1024, ("/proc/meminfo",)),
        )
        self.assertEqual(
            (collected.filesystem.outcome, collected.filesystem.value),
            ("observed", FilesystemSize(53689778176, 48190049280)),
        )
        # The OS observations are kept alongside capacity.
        self.assertEqual(observed(collected.os).pretty_name, "Ubuntu 24.04.3 LTS")
        # Only the needed fields are kept; other meminfo lines are discarded.
        self.assert_not_kept("2345678")

    def test_partial_capacity_shows_warnings_not_zero_values(self) -> None:
        self.remote.files = {"/etc/os-release": UBUNTU}
        self.remote.unreadable = {"/proc/meminfo"}
        self.remote.results["uname -m"] = ssh.CommandResult(1, "")
        self.remote.results["nproc"] = ssh.CommandResult(0, "four\n")
        self.remote.results["df -B1 --output=size,avail,target /"] = ssh.CommandResult(
            0, "Size Avail Target\nnot-a-number 123 /\n"
        )
        collected = self.collect()
        self.assertEqual(collected.architecture.outcome, "unsupported")
        self.assertIsNone(collected.cpu_count.value)
        self.assertEqual(collected.cpu_count.outcome, "unsupported")
        self.assertEqual(collected.memory_bytes.outcome, "inaccessible")
        self.assertIsNone(collected.memory_bytes.value)
        self.assertEqual(collected.filesystem.outcome, "unsupported")
        self.assertIsNone(collected.filesystem.value)
        # A partial inspection keeps the OS observations.
        self.assertEqual(observed(collected.os).pretty_name, "Ubuntu 24.04.3 LTS")
        # Every capacity observation warns, before any later observation does.
        self.assertEqual(
            self.warned()[:4],
            [
                ("Architecture", "unsupported"),
                ("CPUs", "unsupported"),
                ("Memory", "inaccessible"),
                ("Root filesystem", "unsupported"),
            ],
        )
        self.assertEqual(
            collected.memory_bytes.warning,
            "The SSH user cannot read /proc/meminfo. Barectl does not use sudo.",
        )
        self.assert_not_kept("four")
        # Missing observations never look like zero capacity.
        self.assertEqual([observation.value for observation in collected.capacity], [None] * 4)

    def test_missing_meminfo_is_unsupported_not_absent(self) -> None:
        self.remote.files = {"/etc/os-release": UBUNTU}
        collected = self.collect()
        self.assertEqual(collected.memory_bytes.outcome, "unsupported")
        self.assertEqual(
            collected.memory_bytes.warning,
            "The server has no /proc/meminfo, so Barectl cannot report memory.",
        )

    def test_missing_and_unrunnable_commands_are_distinct(self) -> None:
        # POSIX shells exit 127 for a missing command and 126 for one they cannot run.
        self.remote.results["uname -m"] = ssh.CommandResult(127, "")
        self.remote.results["nproc"] = ssh.CommandResult(126, "")
        collected = self.collect()
        # A missing inspection command is no finding: the server still has an architecture.
        self.assertEqual(
            (collected.architecture.outcome, collected.cpu_count.outcome),
            ("unsupported", "inaccessible"),
        )
        self.assertEqual(
            collected.architecture.warning,
            "The server has no uname command, so Barectl cannot inspect this.",
        )
        self.assertEqual(
            collected.cpu_count.warning,
            "The SSH user cannot run nproc. Barectl does not use sudo.",
        )

    def test_truncated_capacity_output_is_unsupported(self) -> None:
        self.remote.results = {
            command: ssh.CommandResult(0, result.stdout, truncated=True)
            for command, result in self.remote.results.items()
        }
        self.remote.results["cat /proc/meminfo"] = ssh.CommandResult(0, MEMINFO, truncated=True)
        collected = self.collect()
        self.assertEqual(
            [observation.outcome for observation in collected.capacity],
            ["unsupported", "unsupported", "unsupported", "unsupported"],
        )
        for observation in (collected.architecture, collected.cpu_count, collected.filesystem):
            with self.subTest(source=observation.source):
                self.assertEqual(
                    observation.warning,
                    f"{observation.source[0]} wrote more output than expected. It was not read.",
                )
        self.assertIsNone(collected.memory_bytes.value)

    def test_unsupported_capacity_never_shows_raw_output(self) -> None:
        self.remote.results["uname -m"] = ssh.CommandResult(0, "x86_64\nmalicious $(touch /tmp/x)")
        self.remote.results["nproc"] = ssh.CommandResult(0, "0\n")
        # "²" passes str.isdigit but int() rejects it.
        self.remote.files["/proc/meminfo"] = "MemTotal: ² kB\n"
        self.remote.results["df -B1 --output=size,avail,target /"] = ssh.CommandResult(
            0, "Size Avail Target\n100 200 /\n"
        )
        collected = self.collect()
        self.assertEqual(
            [observation.outcome for observation in collected.capacity],
            ["unsupported", "unsupported", "unsupported", "unsupported"],
        )
        self.assert_not_kept("malicious", "²")


class AttributeTests(ObservationTestCase):
    """The operating system and capacity exist on every server, so they are never absent."""

    def test_a_server_without_inspection_tools_has_no_absent_attributes(self) -> None:
        # Every command is missing and every file is gone, with searchable parents.
        self.remote.files = {}
        self.remote.directories = {}
        self.remote.results = {
            command: ssh.CommandResult(127, "") for command in self.remote.results
        }
        collected = self.collect()
        attributes = (collected.os, *collected.capacity)
        self.assertEqual([attribute.outcome for attribute in attributes], ["unsupported"] * 5)
        # Nothing about the server's software was found either.
        self.assertEqual(
            (collected.nginx_site_files.outcome, collected.php_fpm_pools.outcome),
            ("unsupported", "unsupported"),
        )
        self.assertFalse([c for c in collected.components if c.package.outcome != "unsupported"])
        self.assert_nothing_absent()


class ServiceTests(ObservationTestCase):
    def assert_statuses(
        self, collected: CollectedSnapshot, part: Literal["package", "service"], status: str
    ) -> None:
        """Assert every component's ``part`` observation has ``status``, in display order."""
        self.assertEqual(
            [
                (
                    observation.component,
                    (observation.package if part == "package" else observation.service).outcome,
                )
                for observation in collected.components
            ],
            [(component, status) for component in WebStackComponent.values],
        )

    def test_service_stack_is_collected_with_versions_states_and_provenance(self) -> None:
        collected = self.collect()
        self.assertEqual(
            [observation.component for observation in collected.components],
            ["nginx", "php-fpm", "mariadb", "postgresql"],
        )
        nginx = self.component("nginx")
        self.assertEqual(nginx.package.outcome, "observed")
        self.assertEqual(nginx.package.value, (Package("nginx", "1.24.0-2ubuntu7.18"),))
        self.assertEqual(nginx.package.source, (PACKAGE_QUERY,))
        self.assertEqual(nginx.service.outcome, "observed")
        self.assertEqual(nginx.service.value, ("nginx.service active (running), enabled",))
        self.assertEqual(nginx.service.source, (UNIT_QUERY.format("nginx.service"),))
        php = self.component("php-fpm")
        self.assertEqual(php.package.value, (Package("php8.3-fpm", "8.3.6-0ubuntu0.24.04.11"),))
        self.assertEqual(php.service.value, ("php8.3-fpm.service active (running), enabled",))
        mariadb = self.component("mariadb")
        self.assertIn(
            Package("mariadb-server", "1:10.11.14-0ubuntu0.24.04.1"), mariadb.package.value
        )
        self.assertEqual(mariadb.service.value, ("mariadb.service active (running), enabled",))
        postgres = self.component("postgresql")
        self.assertIn(Package("postgresql-16", "16.15-0ubuntu0.24.04.1"), postgres.package.value)
        self.assertEqual(postgres.service.value, (UMBRELLA_LINE, MAIN_LINE))
        # Packages known to apt but not installed, such as the php-fpm metapackage, are not
        # reported as installed.
        self.assertEqual(
            [
                package.name
                for component in collected.components
                for package in component.package.value
            ],
            [
                "nginx",
                "php8.3-fpm",
                "mariadb-server",
                "mariadb-server-core",
                "postgresql",
                "postgresql-16",
            ],
        )
        self.assert_not_kept("postgresql-16-jit-llvm")

    def test_absent_packages_are_absent_and_skip_service_queries(self) -> None:
        # dpkg-query exits 1 when no pattern matches; nothing is installed.
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(1, "")
        collected = self.collect()
        self.assertEqual(
            [(c.component, c.package.outcome, c.service.outcome) for c in collected.components],
            [
                ("nginx", "absent", "absent"),
                ("php-fpm", "absent", "absent"),
                ("mariadb", "absent", "absent"),
                ("postgresql", "absent", "absent"),
            ],
        )
        self.assertEqual([c.service.value for c in collected.components], [()] * 4)
        # Without installed packages there is no unit to query; the absent verdict still
        # records the dpkg query it was derived from.
        self.assertFalse([c for c in self.remote.commands if "systemctl" in c])
        self.assertEqual(self.component("nginx").service.source, (PACKAGE_QUERY,))
        self.assertEqual(
            self.component("nginx").package.warning,
            "The dpkg database lists no installed Nginx packages.",
        )

    def test_known_but_uninstalled_packages_are_not_reported(self) -> None:
        # dpkg-query lists packages apt knows about with a status other than "ii".
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(
            1, "nginx  un \nphp8.3-fpm  un \nmariadb-server  rc \n"
        )
        collected = self.collect()
        self.assert_statuses(collected, "package", "absent")

    def test_missing_dpkg_query_is_unsupported_not_absent(self) -> None:
        # POSIX shells exit 127 for a missing command: no dpkg database, no verdict.
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(127, "")
        collected = self.collect()
        self.assert_statuses(collected, "package", "unsupported")
        self.assertFalse([c for c in self.remote.commands if "systemctl" in c])
        # No service query runs; the service observation takes the dpkg query's provenance.
        self.assertEqual(self.component("nginx").service.source, (PACKAGE_QUERY,))
        for component in collected.components:
            with self.subTest(component=component.component):
                self.assertIn(
                    "cannot inspect other installation formats.", component.package.warning
                )
        # Both sub-observations of every component carry the warning, and so do the site
        # file and pool observations that depend on them.
        self.assertEqual(
            self.warned(),
            [
                ("Nginx packages", "unsupported"),
                ("Nginx service units", "unsupported"),
                ("PHP-FPM packages", "unsupported"),
                ("PHP-FPM service units", "unsupported"),
                ("MariaDB packages", "unsupported"),
                ("MariaDB service units", "unsupported"),
                ("PostgreSQL packages", "unsupported"),
                ("PostgreSQL service units", "unsupported"),
                ("Nginx site files", "unsupported"),
                ("PHP-FPM pools", "unsupported"),
            ],
        )

    def test_unrunnable_dpkg_query_is_inaccessible(self) -> None:
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(126, "")
        collected = self.collect()
        self.assert_statuses(collected, "package", "inaccessible")
        self.assertEqual(
            self.component("nginx").package.warning,
            "The SSH user cannot run dpkg-query. Barectl does not use sudo.",
        )

    def test_unexpected_dpkg_query_failure_is_unsupported(self) -> None:
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(2, "")
        collected = self.collect()
        self.assert_statuses(collected, "package", "unsupported")

    def test_unparsable_package_output_is_unsupported(self) -> None:
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(0, "nginx 1.24 stuff\ngarbage\n")
        collected = self.collect()
        self.assert_statuses(collected, "package", "unsupported")
        self.assert_not_kept("1.24 stuff", "garbage")

    def test_truncated_package_output_is_unsupported(self) -> None:
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(0, DPKG_OUTPUT, truncated=True)
        collected = self.collect()
        self.assert_statuses(collected, "package", "unsupported")
        self.assertEqual(
            self.component("nginx").package.warning,
            f"{PACKAGE_QUERY} wrote more output than expected. It was not read.",
        )

    def test_unavailable_systemd_is_unsupported_not_absent(self) -> None:
        # Containers and minimal servers run without systemd or its bus: exit 1.
        self.remote.results[UNIT_QUERY.format("nginx.service")] = ssh.CommandResult(1, "")
        self.collect()
        nginx = self.component("nginx")
        self.assertEqual(
            (nginx.package.outcome, nginx.service.outcome), ("observed", "unsupported")
        )
        self.assertEqual(nginx.service.value, ())
        self.assertEqual(nginx.package.value, (Package("nginx", "1.24.0-2ubuntu7.18"),))
        self.assertIn("could not read service states from systemd.", nginx.service.warning)

    def test_missing_systemctl_is_unsupported(self) -> None:
        self.remote.results = {
            key: (ssh.CommandResult(127, "") if key.startswith("systemctl") else value)
            for key, value in self.remote.results.items()
        }
        collected = self.collect()
        self.assert_statuses(collected, "service", "unsupported")
        for component in collected.components:
            with self.subTest(component=component.component):
                self.assertIn("has no systemctl command", component.service.warning)

    def test_unrunnable_systemctl_is_inaccessible(self) -> None:
        self.remote.results[UNIT_QUERY.format("nginx.service")] = ssh.CommandResult(126, "")
        self.collect()
        nginx = self.component("nginx")
        self.assertEqual(nginx.service.outcome, "inaccessible")
        self.assertEqual(
            nginx.service.warning, "The SSH user cannot run systemctl. Barectl does not use sudo."
        )

    def test_stopped_service_is_observed_not_absent(self) -> None:
        # Installed but stopped: the unit is loaded, enabled and inactive.
        self.remote.results[UNIT_QUERY.format("mariadb.service")] = ssh.CommandResult(
            0, unit_report("mariadb.service", active="inactive", sub="dead")
        )
        self.collect()
        mariadb = self.component("mariadb")
        self.assertEqual(mariadb.service.outcome, "observed")
        self.assertEqual(mariadb.service.value, ("mariadb.service inactive (dead), enabled",))

    def test_unit_without_a_service_file_is_reported_as_not_found(self) -> None:
        self.remote.results[UNIT_QUERY.format("mariadb.service")] = ssh.CommandResult(
            0,
            "Id=mariadb.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\n"
            "UnitFileState=\n",
        )
        self.collect()
        mariadb = self.component("mariadb")
        self.assertEqual(mariadb.service.outcome, "observed")
        self.assertEqual(mariadb.service.value, ("mariadb.service not found",))

    def test_unparsable_unit_output_is_unsupported(self) -> None:
        self.remote.results[UNIT_QUERY.format("nginx.service")] = ssh.CommandResult(
            0, "Id=nginx.service\nActiveState=someting-new\n"
        )
        self.collect()
        nginx = self.component("nginx")
        self.assertEqual(nginx.service.outcome, "unsupported")
        # The server-reported unit name is remote data and is never quoted back.
        self.assert_not_kept("someting-new")
        self.assertEqual(
            nginx.service.warning,
            "systemctl did not report a service unit in a supported format.",
        )

    def test_unit_reported_under_another_name_is_unsupported(self) -> None:
        # An alias resolves to its target unit, which is not the documented unit.
        self.remote.results[UNIT_QUERY.format("mariadb.service")] = ssh.CommandResult(
            0, unit_report("mysql.service")
        )
        self.collect()
        mariadb = self.component("mariadb")
        self.assertEqual((mariadb.service.outcome, mariadb.service.value), ("unsupported", ()))
        self.assert_not_kept("mysql.service")

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
        self.collect()
        nginx = self.component("nginx")
        self.assertEqual(
            (nginx.package.outcome, nginx.package.value),
            ("observed", (Package("nginx", "1.24.0-2ubuntu7.18"),)),
        )
        self.assertEqual(nginx.service.outcome, "observed")
        self.assertEqual(
            self.component("php-fpm").package.value,
            (Package("php8.3-fpm", "8.3.6-0ubuntu0.24.04.11"),),
        )

    def test_unfinished_package_is_unsupported_not_absent(self) -> None:
        # "iU" is unpacked but not configured: the software may be partly present.
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(
            0, DPKG_OUTPUT.replace("nginx 1.24.0-2ubuntu7.18 ii", "nginx 1.24.0-2ubuntu7.18 iU")
        )
        self.collect()
        nginx = self.component("nginx")
        self.assertEqual(
            (nginx.package.outcome, nginx.service.outcome), ("unsupported", "unsupported")
        )
        self.assertEqual(nginx.package.value, ())
        self.assertFalse([c for c in self.remote.commands if "nginx.service" in c])
        self.assert_not_kept("1.24.0-2ubuntu7.18")
        self.assertIn("lists a Nginx package that is not fully installed", nginx.package.warning)

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
        self.collect()
        self.assertEqual(
            self.component("php-fpm").service.value,
            (
                "php8.1-fpm.service active (running), enabled",
                "php8.3-fpm.service active (running), enabled",
            ),
        )


class PostgresClusterTests(ObservationTestCase):
    """Each PostgreSQL cluster's unit is reported next to the postgresql.service umbrella."""

    def postgres(self) -> WebStackComponentObservation:
        return self.component("postgresql")

    def postgres_commands(self) -> list[str]:
        """The commands issued after the package query to observe PostgreSQL's service."""
        return [c for c in self.remote.commands if "postgres" in c and c != PACKAGE_QUERY]

    def test_running_cluster_is_reported_with_the_command_that_found_it(self) -> None:
        self.collect()
        postgres = self.postgres()
        self.assertEqual(postgres.service.outcome, "observed")
        self.assertEqual(
            postgres.service.value,
            (UMBRELLA_LINE, MAIN_LINE),
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
            list(postgres.service.source),
            [f"ls -1b {PG_DIR}", f"ls -1bA {PG_DIR}/16", UNIT_QUERY.format(CLUSTER_UNITS)],
        )
        self.assertEqual(postgres.service.warning, "")

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
        self.collect()
        postgres = self.postgres()
        self.assertEqual(postgres.service.outcome, "observed")
        self.assertEqual(
            postgres.service.value,
            (
                UMBRELLA_LINE,
                "postgresql@16-main.service inactive (dead), enabled-runtime",
            ),
        )

    def test_no_clusters_is_observed_with_only_the_umbrella_unit(self) -> None:
        # pg_dropcluster removes a cluster's directory and may leave its version directory.
        self.remote.directories[f"{PG_DIR}/16"] = []
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.collect()
        postgres = self.postgres()
        self.assertEqual(postgres.service.outcome, "observed")
        self.assertEqual(postgres.service.value, (UMBRELLA_LINE,))
        self.assertEqual(
            postgres.service.warning, f"Barectl found no PostgreSQL clusters in {PG_DIR}."
        )
        # The note is a finding, not a warning.
        self.assertEqual(self.warned(), [])

    def assert_uninspected(self, status: str, warning: str) -> WebStackComponentObservation:
        """Assert the clusters could not all be seen: never absent, versions still kept."""
        postgres = self.postgres()
        self.assertEqual(postgres.package.outcome, "observed")
        self.assertIn(Package("postgresql-16", "16.15-0ubuntu0.24.04.1"), postgres.package.value)
        self.assertEqual(postgres.service.outcome, status)
        self.assertEqual(postgres.service.warning, warning)
        self.assert_nothing_absent()
        return postgres

    def test_unreadable_configuration_root_is_inaccessible_not_absent(self) -> None:
        del self.remote.directories[PG_DIR]
        self.remote.unreadable.add(PG_DIR)
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.collect()
        postgres = self.assert_uninspected(
            "inaccessible",
            f"The SSH user cannot read {PG_DIR}. Barectl does not use sudo.",
        )
        # The umbrella unit's state is still reported.
        self.assertEqual(postgres.service.value, (UMBRELLA_LINE,))
        self.assertEqual(
            list(postgres.service.source),
            [f"ls -1b {PG_DIR}", UNIT_QUERY.format("postgresql.service")],
        )

    def test_unreadable_version_directory_is_inaccessible_and_keeps_other_clusters(self) -> None:
        self.add_cluster("17", "main")
        del self.remote.directories[f"{PG_DIR}/16"]
        self.remote.unreadable.add(f"{PG_DIR}/16")
        units = "postgresql.service postgresql@17-main.service"
        self.report_units(units, UMBRELLA_REPORT, cluster_report("17", "main"))
        self.collect()
        postgres = self.assert_uninspected(
            "inaccessible", f"The SSH user cannot read {PG_DIR}/16. Barectl does not use sudo."
        )
        self.assertEqual(
            postgres.service.value,
            (
                UMBRELLA_LINE,
                "postgresql@17-main.service active (running), enabled-runtime",
            ),
        )

    def test_unavailable_systemd_keeps_the_listing_warning(self) -> None:
        del self.remote.directories[PG_DIR]
        self.remote.unreadable.add(PG_DIR)
        self.remote.results[UNIT_QUERY.format("postgresql.service")] = ssh.CommandResult(1, "")
        self.collect()
        postgres = self.postgres()
        self.assertEqual((postgres.service.outcome, postgres.service.value), ("unsupported", ()))
        self.assertIn("could not read service states from systemd.", postgres.service.warning)
        self.assertIn(f"The SSH user cannot read {PG_DIR}.", postgres.service.warning)

    def test_missing_configuration_root_is_unsupported_not_absent(self) -> None:
        # postgresql-common installs /etc/postgresql; without it the layout is not Debian's.
        for described in (self.remote.directories, self.remote.files):
            for path in [path for path in described if path.startswith(PG_DIR)]:
                del described[path]
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.collect()
        self.assert_uninspected(
            "unsupported", f"The server has no {PG_DIR}. Barectl reads only the Debian layout."
        )

    def test_listing_that_cannot_run_is_unsupported(self) -> None:
        self.remote.results[f"ls -1b {PG_DIR}"] = ssh.CommandResult(127, "")
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.collect()
        self.assert_uninspected("unsupported", f"{PG_DIR} could not be read.")

    def test_truncated_listing_is_unsupported(self) -> None:
        self.remote.results[f"ls -1bA {PG_DIR}/16"] = ssh.CommandResult(0, "main\n", truncated=True)
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.collect()
        self.assert_uninspected(
            "unsupported", f"{PG_DIR}/16 holds more than 1000 entries. It was not read."
        )

    def test_more_clusters_than_supported_are_not_queried(self) -> None:
        self.remote.directories[f"{PG_DIR}/16"] = [f"c{n:03}" for n in range(101)]
        for n in range(101):
            self.remote.files[cluster_conf("16", f"c{n:03}")] = ""
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.collect()
        self.assert_uninspected(
            "unsupported",
            f"{PG_DIR} holds more than 100 possible PostgreSQL clusters. They were not queried.",
        )
        self.assertFalse([c for c in self.remote.commands if "c000" in c])
        self.assertEqual(self.postgres().service.value, (UMBRELLA_LINE,))

    def test_more_versions_than_supported_are_not_listed(self) -> None:
        self.remote.directories[PG_DIR] = [str(version) for version in range(10, 31)]
        self.report_units("postgresql.service", UMBRELLA_REPORT)
        self.collect()
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
        self.collect()
        postgres = self.postgres()
        self.assertEqual(postgres.service.outcome, "observed")
        self.assertIn("postgresql@16-main.service not found", postgres.service.value)

    def test_cluster_reported_under_another_name_is_unsupported(self) -> None:
        self.report_units(CLUSTER_UNITS, UMBRELLA_REPORT, unit_report("postgresql@17-main.service"))
        self.collect()
        postgres = self.postgres()
        self.assertEqual(postgres.service.outcome, "unsupported")
        self.assertEqual(postgres.service.value, (UMBRELLA_LINE,))
        self.assert_not_kept("postgresql@17-main")

    def test_hostile_names_are_never_used_in_commands_or_warnings(self) -> None:
        # As ls -b prints them: spaces and newlines escaped with backslashes.
        hostile = ["db;reboot", "my\\ db", "x\\ny", "$(id)"]
        self.remote.directories[PG_DIR] += ["16;reboot", "17\\nmain"]
        self.remote.directories[f"{PG_DIR}/16"] += hostile
        self.collect()
        postgres = self.assert_uninspected(
            "unsupported",
            f"{PG_DIR}/16 lists 4 entries whose names Barectl does not support. They were skipped.",
        )
        # The valid cluster is still reported.
        self.assertIn(MAIN_LINE, postgres.service.value)
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
            (*postgres.service.value, postgres.service.warning, *postgres.service.source)
        )
        for name in [*hostile, "16;reboot", "17\\nmain", "reboot", "(id)"]:
            with self.subTest(name=name):
                self.assertNotIn(name, stored)
                self.assert_not_kept(name)

    def test_dead_configuration_symlink_still_marks_a_cluster(self) -> None:
        # postgresql-common counts a postgresql.conf that is a dead symlink.
        del self.remote.files[cluster_conf("16", "main")]
        self.remote.dead_links.add(cluster_conf("16", "main"))
        self.collect()
        self.assertEqual(self.postgres().service.outcome, "observed")
        self.assertIn(MAIN_LINE, self.postgres().service.value)
        self.assertIn(f"test -L {cluster_conf('16', 'main')}", self.postgres_commands())

    def test_cluster_named_with_a_leading_dot_is_found(self) -> None:
        # postgresql-common reads every directory entry, including names starting with ".".
        self.add_cluster("16", ".staging")
        units = f"{CLUSTER_UNITS} postgresql@16-.staging.service"
        self.report_units(
            units, UMBRELLA_REPORT, cluster_report("16", "main"), cluster_report("16", ".staging")
        )
        self.collect()
        self.assertEqual(
            self.postgres().service.value,
            (
                UMBRELLA_LINE,
                MAIN_LINE,
                "postgresql@16-.staging.service active (running), enabled-runtime",
            ),
        )

    def test_entries_without_postgresql_conf_are_not_clusters(self) -> None:
        # A searchable directory without postgresql.conf, and a plain file.
        self.remote.directories[f"{PG_DIR}/16"] += ["old", "README"]
        self.remote.directories[f"{PG_DIR}/16/old"] = []
        self.remote.files[f"{PG_DIR}/16/README"] = "notes"
        self.collect()
        postgres = self.postgres()
        self.assertEqual((postgres.service.outcome, postgres.service.warning), ("observed", ""))
        self.assertEqual(
            postgres.service.value,
            (UMBRELLA_LINE, MAIN_LINE),
        )

    def test_unsearchable_cluster_directory_is_inaccessible(self) -> None:
        self.add_cluster("16", "private")
        self.remote.unsearchable.add(f"{PG_DIR}/16/private")
        self.collect()
        postgres = self.assert_uninspected(
            "inaccessible",
            f"The SSH user cannot search {PG_DIR}/16/private. Barectl does not use sudo.",
        )
        self.assertIn(MAIN_LINE, postgres.service.value)
        self.assertNotIn("postgresql@16-private.service", "\n".join(postgres.service.value))

    def test_clusters_are_not_looked_for_without_an_installed_package(self) -> None:
        # Not installed, and unpacked but not configured.
        for dpkg, status in (("", "absent"), ("postgresql 16+257build1.1 iU \n", "unsupported")):
            with self.subTest(status=status):
                self.remote.commands.clear()
                self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(1, dpkg)
                self.collect()
                self.assertEqual(self.postgres_commands(), [])
                self.assertEqual(self.postgres().service.outcome, status)

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
        self.collect()
        postgres = self.postgres()
        self.assertEqual(postgres.service.outcome, "observed")
        self.assertEqual(
            postgres.service.value,
            (
                UMBRELLA_LINE,
                "postgresql@9.6-legacy.service failed (failed), enabled-runtime",
                MAIN_LINE,
                "postgresql@16-reports.service inactive (dead), disabled",
            ),
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


class SitePoolFixtures:
    """Nginx sites and PHP-FPM pools on the test's FakeServer."""

    remote: FakeServer

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

    def install_php_fpm(self, *versions: str) -> None:
        """Make dpkg list PHP-FPM packages for ``versions`` besides the other components."""
        packages = "".join(f"php{v}-fpm {v}.0-1 ii \n" for v in versions)
        others = "".join(f"{line}\n" for line in DPKG_OUTPUT.splitlines() if "php" not in line)
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(0, packages + others)


class SitePoolTests(SitePoolFixtures, ObservationTestCase):
    """Nginx site and PHP-FPM pool observations."""

    def test_sites_and_pools_are_collected_with_provenance_and_time(self) -> None:
        self.enable_sites({"example.com": self.EXAMPLE_SITE, "default": self.DEFAULT_SITE})
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        collected = self.collect()
        sites, pools = collected.nginx_site_files, collected.php_fpm_pools
        self.assertEqual(sites.outcome, "observed")
        self.assertEqual(sites.source, (SITE_DIR,))
        self.assertEqual([site.name for site in sites.value], ["example.com", "default"])
        example = sites.value[0]
        self.assertEqual(example.outcome, "observed")
        self.assertEqual(example.server_names, ("example.com",))
        self.assertEqual(example.listens, ("443",))
        self.assertEqual(example.source, f"{SITE_DIR}/example.com")
        self.assertEqual(sites.value[1].listens, ("80",))
        self.assertEqual([(pool.version, pool.name) for pool in pools.value], [("8.3", "www")])
        (pool,) = pools.value
        self.assertEqual((pool.outcome, pool.listen), ("observed", "/run/php/php8.3-fpm.sock"))
        self.assertEqual(pool.source, f"{PHP_DIR}/8.3/fpm/pool.d/www.conf")
        self.assertEqual(pools.outcome, "observed")
        # The pool directory Barectl listed, not /etc/php, which it does not read.
        self.assertEqual(pools.source, (f"{PHP_DIR}/8.3/fpm/pool.d",))
        # Safe fields only: the TLS certificate path, pool user and secret environment
        # values are never kept.
        self.assert_not_kept(
            "ssl_certificate", "/etc/ssl/example.pem", "hunter2", "www-data", "soap"
        )

    def assert_nothing_read_under(self, *paths: str) -> None:
        self.assertFalse([c for c in self.remote.commands if any(p in c for p in paths)])

    def test_uninstalled_components_have_absent_sites_and_pools_without_reads(self) -> None:
        # Nginx was removed without purging (dpkg state rc), leaving its site files behind.
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(
            1, "nginx 1.24.0-2ubuntu7.18 rc \nphp8.3-fpm 8.3.6-0ubuntu0.24.04.11 rc \n"
        )
        self.enable_sites({"example.com": self.EXAMPLE_SITE})
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        collected = self.collect()
        sites, pools = collected.nginx_site_files, collected.php_fpm_pools
        self.assertEqual((sites.outcome, pools.outcome), ("absent", "absent"))
        # The verdict and its provenance come from the package observation.
        self.assertEqual((sites.source, pools.source), ((PACKAGE_QUERY,), (PACKAGE_QUERY,)))
        self.assertEqual(
            (sites.warning, pools.warning),
            (
                "The dpkg database lists no installed Nginx packages.",
                "The dpkg database lists no installed PHP-FPM packages.",
            ),
        )
        self.assertFalse(sites.value)
        self.assertFalse(pools.value)
        self.assert_nothing_read_under(SITE_DIR, PHP_DIR)

    def test_uninspectable_packages_leave_sites_and_pools_uninspected(self) -> None:
        for exit_status, outcome in ((127, "unsupported"), (126, "inaccessible")):
            with self.subTest(exit_status=exit_status):
                self.remote.commands.clear()
                self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(exit_status, "")
                self.enable_sites({"example.com": self.EXAMPLE_SITE})
                collected = self.collect()
                sites, pools = collected.nginx_site_files, collected.php_fpm_pools
                self.assertEqual((sites.outcome, pools.outcome), (outcome, outcome))
                # Every observation that depends on the package observation takes its source.
                self.assertEqual(
                    (self.component("nginx").service.source, sites.source, pools.source),
                    ((PACKAGE_QUERY,), (PACKAGE_QUERY,), (PACKAGE_QUERY,)),
                )
                self.assertFalse(sites.value)
                self.assert_nothing_read_under(SITE_DIR, PHP_DIR)

    def test_installed_components_without_the_debian_layout_are_unsupported(self) -> None:
        # Nginx and PHP-FPM are installed, but keep their configuration elsewhere.
        self.remote.directories.clear()
        collected = self.collect()
        sites, pools = collected.nginx_site_files, collected.php_fpm_pools
        self.assertEqual((sites.outcome, pools.outcome), ("unsupported", "unsupported"))
        self.assertFalse(sites.value)
        self.assertFalse(pools.value)
        self.assertEqual(
            sites.warning, f"The server has no {SITE_DIR}. Barectl reads only the Debian layout."
        )
        self.assertIn(
            f"The server has no {PHP_DIR}/8.3/fpm/pool.d. Barectl reads only the Debian layout.",
            pools.warning,
        )
        self.assert_nothing_absent()

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
                self.remote.commands.clear()
                self.remote.files[NGINX_CONF] = text
                sites = self.collect().nginx_site_files
                self.assertEqual((sites.outcome, sites.source), ("unsupported", (NGINX_CONF,)))
                self.assertFalse(sites.value)
                self.assert_nothing_read_under(SITE_DIR)
                self.assertEqual(
                    sites.warning,
                    "/etc/nginx/nginx.conf does not include /etc/nginx/sites-enabled/*, so "
                    "Barectl cannot confirm which files it loads. Barectl reads only the "
                    "Debian layout.",
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
                self.remote.commands.clear()
                self.remote.files.pop(NGINX_CONF, None)
                if text is not None:
                    self.remote.files[NGINX_CONF] = text
                self.remote.unreadable = {NGINX_CONF} if refused else set()
                sites = self.collect().nginx_site_files
                self.assertEqual(sites.outcome, outcome)
                self.assert_nothing_read_under(SITE_DIR)
                self.assertIn(warning, sites.warning)
                self.assert_not_kept("include x")

    def test_pools_are_read_only_when_php_fpm_conf_includes_the_directory(self) -> None:
        self.install_php_fpm("8.1", "8.3")
        self.enable_pools("8.1", {"www.conf": "[www]\nlisten = 9000\n"})
        self.enable_pools("8.3", {"admin.conf": "[admin]\nlisten = 9100\n"})
        # PHP-FPM 8.3 loads its pools from somewhere else.
        self.remote.files[fpm_conf_path("8.3")] = php_fpm_conf("8.3").replace(
            "/etc/php/8.3/fpm/pool.d/*.conf", "/srv/pools/*.conf"
        )
        pools = self.collect().php_fpm_pools
        self.assertEqual([(pool.version, pool.name) for pool in pools.value], [("8.1", "www")])
        self.assertEqual(pools.outcome, "observed")
        # Each read that decided the outcome, in order: 8.1's directory, then 8.3's main file.
        self.assertEqual(pools.source, (f"{PHP_DIR}/8.1/fpm/pool.d", fpm_conf_path("8.3")))
        self.assert_nothing_read_under(f"{PHP_DIR}/8.3/fpm/pool.d")
        self.assertIn(
            "/etc/php/8.3/fpm/php-fpm.conf does not include /etc/php/8.3/fpm/pool.d/*.conf",
            pools.warning,
        )
        self.assertNotIn("/srv/pools", pools.warning)

    def test_every_main_file_that_stopped_pools_being_read_is_the_source(self) -> None:
        self.install_php_fpm("8.1", "8.3")
        del self.remote.files[fpm_conf_path("8.3")]
        pools = self.collect().php_fpm_pools
        self.assertEqual(pools.outcome, "unsupported")
        # Neither version's php-fpm.conf exists; both are named, never /etc/php.
        self.assertEqual(pools.source, (fpm_conf_path("8.1"), fpm_conf_path("8.3")))

    def test_a_pool_directory_that_cannot_be_listed_is_the_source(self) -> None:
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        pool_dir = f"{PHP_DIR}/8.3/fpm/pool.d"
        del self.remote.directories[pool_dir]
        del self.remote.files[f"{pool_dir}/www.conf"]
        self.remote.unreadable.add(pool_dir)
        pools = self.collect().php_fpm_pools
        self.assertEqual(pools.outcome, "inaccessible")
        self.assertEqual(pools.source, (pool_dir,))

    def test_a_missing_php_fpm_conf_leaves_that_version_unread(self) -> None:
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        del self.remote.files[fpm_conf_path("8.3")]
        pools = self.collect().php_fpm_pools
        self.assertEqual(pools.outcome, "unsupported")
        self.assertEqual(pools.source, (fpm_conf_path("8.3"),))
        self.assertFalse(pools.value)
        self.assert_nothing_read_under(f"{PHP_DIR}/8.3/fpm/pool.d")
        self.assertIn("The server has no /etc/php/8.3/fpm/php-fpm.conf.", pools.warning)

    def test_empty_configuration_directories_are_observed_empty(self) -> None:
        collected = self.collect()
        sites, pools = collected.nginx_site_files, collected.php_fpm_pools
        self.assertEqual((sites.outcome, pools.outcome), ("observed", "observed"))
        self.assertEqual(
            sites.warning, "No site configuration files are listed in /etc/nginx/sites-enabled."
        )
        self.assertEqual(pools.warning, "No PHP-FPM pools are configured under /etc/php.")

    def test_permission_denied_directories_are_inaccessible(self) -> None:
        self.remote.unreadable.update({SITE_DIR, f"{PHP_DIR}/8.3/fpm/pool.d"})
        del self.remote.directories[SITE_DIR]
        del self.remote.directories[f"{PHP_DIR}/8.3/fpm/pool.d"]
        collected = self.collect()
        sites, pools = collected.nginx_site_files, collected.php_fpm_pools
        self.assertEqual(sites.outcome, "inaccessible")
        self.assertFalse(sites.value)
        self.assertIn("cannot read /etc/nginx/sites-enabled.", sites.warning)
        # The only PHP version's pool directory is denied, so nothing was observed.
        self.assertEqual(pools.outcome, "inaccessible")
        self.assertFalse(pools.value)
        self.assertIn("cannot read /etc/php/8.3/fpm/pool.d.", pools.warning)

    def test_total_file_denial_is_inaccessible_not_observed(self) -> None:
        self.list_dir(SITE_DIR, ["secret", "other"])
        self.remote.unreadable.update({f"{SITE_DIR}/secret", f"{SITE_DIR}/other"})
        sites = self.collect().nginx_site_files
        self.assertEqual(sites.outcome, "inaccessible")
        self.assertEqual(
            [(site.name, site.outcome) for site in sites.value],
            [("secret", "inaccessible"), ("other", "inaccessible")],
        )
        self.assertEqual(
            sites.warning,
            "The SSH user cannot read the site configuration files. Barectl does not use sudo.",
        )

    def test_a_broken_site_symlink_is_absent_for_that_entry(self) -> None:
        self.enable_sites({"good": self.EXAMPLE_SITE})
        self.remote.directories[SITE_DIR].append("gone")
        sites = self.collect().nginx_site_files
        self.assertEqual(
            [(site.name, site.outcome) for site in sites.value],
            [("good", "observed"), ("gone", "absent")],
        )
        self.assertEqual(sites.outcome, "observed")
        self.assertEqual(sites.value[1].warning, "The server has no /etc/nginx/sites-enabled/gone.")

    def test_an_observed_site_file_notes_includes_it_skips_once(self) -> None:
        self.enable_sites({"example.com": "include snippets/ssl.conf;\n" + self.EXAMPLE_SITE})
        sites = self.collect().nginx_site_files
        warning = (
            f"{SITE_DIR}/example.com includes other configuration files. Barectl does not "
            "read them, so server names and listen addresses they declare are not shown."
        )
        self.assertEqual(sites.value[0].warning, warning)
        self.assertEqual(kept_text(self.collected).count(warning), 1)
        # The note is a finding, not a warning.
        self.assertEqual(self.warned(), [])

    def test_restricted_files_keep_partial_results(self) -> None:
        self.enable_sites({"example.com": self.EXAMPLE_SITE})
        self.remote.directories[SITE_DIR].append("private")
        self.remote.unreadable.add(f"{SITE_DIR}/private")
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        self.remote.directories[f"{PHP_DIR}/8.3/fpm/pool.d"].append("stale.conf.bak")
        self.remote.unreadable.add(f"{PHP_DIR}/8.3/fpm/pool.d/stale.conf.bak")
        sites = self.collect().nginx_site_files
        self.assertEqual(
            [(site.name, site.outcome) for site in sites.value],
            [("example.com", "observed"), ("private", "inaccessible")],
        )
        self.assertEqual(sites.value[0].server_names, ("example.com",))
        self.assertIn("cannot read /etc/nginx/sites-enabled/private.", sites.value[1].warning)
        # PHP-FPM would not load the .bak file, so it is skipped without a read.
        self.assert_not_kept("stale.conf.bak")
        self.assertFalse([c for c in self.remote.commands if "stale.conf.bak" in c])

    def test_parser_failures_are_unsupported_without_dumps(self) -> None:
        self.enable_sites(
            {
                "broken.conf": "server {\n  listen 80\n  server_name broken.example;\n",
                "upstream-only": "upstream backend {\n  server 10.0.0.1:8000;\n}\n",
                "good": self.EXAMPLE_SITE,
            }
        )
        self.enable_pools("8.3", {"bad.conf": "listen without a section\n"})
        collected = self.collect()
        sites = collected.nginx_site_files
        self.assertEqual(
            [(site.name, site.outcome) for site in sites.value],
            [
                ("broken.conf", "unsupported"),
                ("upstream-only", "unsupported"),
                ("good", "observed"),
            ],
        )
        self.assertEqual(
            [
                "does not define a supported Nginx site configuration" in site.warning
                for site in sites.value
            ],
            [True, True, False],
        )
        # An unparseable pool file is no finding, never "no pools configured".
        pools = collected.php_fpm_pools
        self.assertEqual(pools.outcome, "unsupported")
        self.assertFalse(pools.value)
        self.assertNotIn("No PHP-FPM pools are configured", pools.warning)
        self.assertIn("does not define a supported PHP-FPM pool configuration", pools.warning)
        # The unparseable contents are never kept.
        self.assert_not_kept("broken.example", "10.0.0.1:8000", "listen without a section")

    def test_pools_are_read_only_for_installed_php_fpm_versions(self) -> None:
        self.install_php_fpm("8.1", "8.3")
        self.enable_pools("8.1", {"www.conf": "[www]\nlisten = 9000\n"})
        # PHP 8.2's CLI left a version directory without PHP-FPM, and PHP-FPM 8.3 keeps
        # its pools outside the Debian layout.
        self.list_dir(f"{PHP_DIR}/8.2/fpm/pool.d", ["www.conf"])
        del self.remote.directories[f"{PHP_DIR}/8.3/fpm/pool.d"]
        pools = self.collect().php_fpm_pools
        self.assertEqual([(pool.version, pool.name) for pool in pools.value], [("8.1", "www")])
        self.assertEqual(pools.outcome, "observed")
        self.assert_nothing_read_under(f"{PHP_DIR}/8.2")
        self.assertNotIn(f"ls -1b {PHP_DIR}", self.remote.commands)
        self.assertIn(
            "The server has no /etc/php/8.3/fpm/pool.d. Barectl reads only the Debian layout.",
            pools.warning,
        )

    def test_php_fpm_without_a_versioned_package_is_unsupported(self) -> None:
        self.remote.results[PACKAGE_QUERY] = ssh.CommandResult(1, "php-fpm 2:8.3+93ubuntu2 ii \n")
        pools = self.collect().php_fpm_pools
        self.assertEqual(pools.outcome, "unsupported")
        self.assert_nothing_read_under(PHP_DIR)
        self.assertIn("lists no PHP-FPM package for a specific PHP version", pools.warning)

    def test_unreadable_pool_files_are_inaccessible_not_empty(self) -> None:
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        pool_file = f"{PHP_DIR}/8.3/fpm/pool.d/www.conf"
        del self.remote.files[pool_file]
        self.remote.unreadable.add(pool_file)
        pools = self.collect().php_fpm_pools
        self.assertEqual(pools.outcome, "inaccessible")
        self.assertIn(f"cannot read {pool_file}.", pools.warning)
        self.assertNotIn("No PHP-FPM pools are configured", pools.warning)

    def test_pools_whose_listed_files_are_all_gone_are_absent(self) -> None:
        pool_dir = f"{PHP_DIR}/8.3/fpm/pool.d"
        # The directory lists a pool file that does not exist, such as a broken symlink.
        self.list_dir(pool_dir, ["gone.conf"])
        pools = self.collect().php_fpm_pools
        self.assertEqual(pools.outcome, "absent")
        self.assertEqual(pools.value, ())
        self.assertTrue(
            pools.warning.startswith("None of the PHP-FPM pool files listed under /etc/php exist."),
            pools.warning,
        )
        self.assertNotIn("No PHP-FPM pools are configured", pools.warning)

    def test_an_empty_pool_directory_beside_missing_pool_files_is_absent(self) -> None:
        self.install_php_fpm("8.2", "8.3")
        self.enable_pools("8.2", {})
        self.enable_pools("8.3", {"gone.conf": ""})
        del self.remote.files[f"{PHP_DIR}/8.3/fpm/pool.d/gone.conf"]
        pools = self.collect().php_fpm_pools
        # No pool exists; the one pool file Barectl found listed does not exist.
        self.assertEqual(pools.outcome, "absent")

    def test_pool_directories_that_list_no_pool_files_are_observed_empty(self) -> None:
        self.enable_pools("8.3", {})
        self.list_dir(f"{PHP_DIR}/8.3/fpm/pool.d", ["README"])
        pools = self.collect().php_fpm_pools
        self.assertEqual(pools.outcome, "observed")
        self.assertIn("No PHP-FPM pools are configured under /etc/php.", pools.warning)

    def test_a_pool_declared_in_two_files_is_unsupported_without_failing(self) -> None:
        self.enable_pools(
            "8.3",
            {
                "a.conf": "[www]\nlisten = 9000\n",
                "b.conf": "[WWW]\nlisten = 9001\n",
                "c.conf": "[admin]\nlisten = 9100\n",
            },
        )
        pools = self.collect().php_fpm_pools
        self.assertEqual(
            [(pool.name, pool.outcome, pool.listen) for pool in pools.value],
            [("www", "unsupported", ""), ("admin", "observed", "9100")],
        )
        self.assertEqual(pools.outcome, "observed")
        self.assertIn("Pool www is declared more than once", pools.value[0].warning)

    def test_sites_with_nothing_observed_are_not_observed(self) -> None:
        self.list_dir(SITE_DIR, ["private", "broken"])
        self.remote.unreadable.add(f"{SITE_DIR}/private")
        self.remote.files[f"{SITE_DIR}/broken"] = "server {\n  listen 80\n"
        sites = self.collect().nginx_site_files
        self.assertEqual(sites.outcome, "unsupported")
        self.assertEqual(
            sites.warning,
            "No file in /etc/nginx/sites-enabled could be read as a supported Nginx site "
            "configuration.",
        )

    def test_sites_whose_entries_are_all_gone_are_absent(self) -> None:
        self.list_dir(SITE_DIR, ["gone"])
        sites = self.collect().nginx_site_files
        self.assertEqual(sites.outcome, "absent")
        self.assertEqual([(site.name, site.outcome) for site in sites.value], [("gone", "absent")])
        self.assertEqual(
            sites.warning, "None of the entries listed in /etc/nginx/sites-enabled exist."
        )

    def test_entries_of_an_unsearchable_directory_are_inaccessible_not_absent(self) -> None:
        # The SSH user may list the directory but not open the files inside it.
        self.enable_sites({"default": self.DEFAULT_SITE})
        self.remote.unsearchable.add(SITE_DIR)
        sites = self.collect().nginx_site_files
        self.assertEqual(
            [(site.name, site.outcome) for site in sites.value],
            [("default", "inaccessible")],
        )
        self.assertEqual(sites.outcome, "inaccessible")

    def test_escaped_entry_names_are_skipped_not_split(self) -> None:
        # ls -b prints a name holding a newline as one escaped line, so it cannot repeat
        # another entry's name.
        self.enable_sites({"default": self.DEFAULT_SITE})
        self.remote.directories[SITE_DIR].append("x\\ndefault")
        sites = self.collect().nginx_site_files
        self.assertEqual([site.name for site in sites.value], ["default"])
        self.assertIn("1 entries whose names Barectl does not interpret", sites.warning)
        self.assertIn(f"ls -1b {SITE_DIR}", self.remote.commands)

    def test_the_pool_cap_is_exact(self) -> None:
        def pool_file(start: int) -> str:
            return "".join(f"[p{i}]\nlisten = {9000 + i}\n" for i in range(start, start + 50))

        pools = {f"{n}.conf": pool_file(n * 50) for n in range(4)}
        self.enable_pools("8.3", pools)
        observed_pools = self.collect().php_fpm_pools
        self.assertEqual(len(observed_pools.value), 200)
        self.assertNotIn("More than 200", observed_pools.warning)

        self.enable_pools("8.3", {**pools, "4.conf": "[extra]\nlisten = 9999\n"})
        capped = self.collect().php_fpm_pools
        self.assertEqual(len(capped.value), 200)
        self.assertNotIn("extra", [pool.name for pool in capped.value])
        self.assertIn("More than 200 PHP-FPM pools were found.", capped.warning)

    def test_the_site_file_cap_is_exact(self) -> None:
        sites = {f"s{n:03}": self.DEFAULT_SITE for n in range(200)}
        self.enable_sites(sites)
        observed_sites = self.collect().nginx_site_files
        self.assertEqual(len(observed_sites.value), 200)
        self.assertNotIn("more site entries", observed_sites.warning)

        self.enable_sites({**sites, "s200": self.DEFAULT_SITE, "s201": self.DEFAULT_SITE})
        self.remote.commands.clear()
        capped = self.collect().nginx_site_files
        self.assertEqual(capped.outcome, "observed")
        self.assertEqual(len(capped.value), 200)
        self.assertNotIn("s200", [site.name for site in capped.value])
        self.assertIn("Only the first 200 are shown.", capped.warning)
        # Reading stops once the collection is full.
        self.assert_nothing_read_under(f"{SITE_DIR}/s201")

    def test_included_files_are_named_in_warnings(self) -> None:
        self.enable_sites(
            {"example.com": "server {\n  listen 80;\n  include snippets/names.conf;\n}\n"}
        )
        self.enable_pools("8.3", {"www.conf": "[www]\nlisten = 9000\ninclude = /srv/*.conf\n"})
        collected = self.collect()
        sites, pools = collected.nginx_site_files, collected.php_fpm_pools
        self.assertEqual((sites.outcome, pools.outcome), ("observed", "observed"))
        self.assertIn(
            f"{SITE_DIR}/example.com includes other configuration files. Barectl does not "
            "read them",
            sites.value[0].warning,
        )
        self.assertIn(
            f"{PHP_DIR}/8.3/fpm/pool.d/www.conf includes other configuration files.",
            pools.warning,
        )
        self.assert_not_kept("/srv/")

    def test_entries_with_unsupported_names_are_skipped(self) -> None:
        self.enable_sites({"good": self.EXAMPLE_SITE})
        self.remote.directories[SITE_DIR].append("weird name")
        sites = self.collect().nginx_site_files
        self.assertEqual([site.name for site in sites.value], ["good"])
        self.assertIn("1 entries whose names Barectl does not interpret", sites.warning)
        self.assertFalse([c for c in self.remote.commands if "weird name" in c])


class ObservationWorkflowTests(SitePoolFixtures, DiscoveryTestCase):
    """Observations through the worker, the database and the server page.

    The rules themselves are tested through ``collect``; these check that one collection of
    each kind is stored, replaced and shown.
    """

    def test_unreadable_release_file_is_inaccessible_not_absent(self) -> None:
        self.remote.files = {}
        self.remote.unreadable = {"/etc/os-release"}
        collected = self.discover()
        self.assertEqual(collected.os.outcome, "inaccessible")
        self.assertIsNone(collected.os.value)
        self.assertContains(self.page, "<strong>Inaccessible:</strong>", html=True)
        self.assertContains(self.page, "cannot read /etc/os-release. Barectl does not use sudo.")
        # The connection itself was verified; the warning belongs to the snapshot.
        self.assert_succeeded()

    def test_capacity_is_collected_with_units_provenance_and_time(self) -> None:
        collected = self.discover()
        architecture, cpu_count = collected.architecture, collected.cpu_count
        self.assertEqual(
            (architecture.outcome, architecture.value, architecture.source),
            ("observed", "x86_64", ("uname -m",)),
        )
        self.assertEqual(
            (cpu_count.outcome, cpu_count.value, cpu_count.source), ("observed", 4, ("nproc",))
        )
        memory = collected.memory_bytes
        self.assertEqual(
            (memory.outcome, memory.value, memory.source),
            ("observed", 4024548 * 1024, ("/proc/meminfo",)),
        )
        self.assertEqual(
            (collected.filesystem.outcome, collected.filesystem.value),
            ("observed", FilesystemSize(53689778176, 48190049280)),
        )
        self.assert_succeeded()
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
        self.assertContains(self.page, f'datetime="{self.snapshot.collected_at.isoformat()}"')
        # Only the needed fields are kept; other meminfo lines are discarded.
        self.assertNotContains(self.page, "2345678")
        self.assertContains(self.client.get("/"), "<td>Verified</td>", html=True)

    def test_the_database_refuses_absent_attributes(self) -> None:
        self.discover()
        # The storage itself is under test here, so this reads the stored columns.
        snapshot = DiscoverySnapshot.objects.get()
        columns = ("os_status", "arch_status", "cpu_status", "memory_status", "filesystem_status")
        for name in columns:
            with self.subTest(field=name):
                previous = getattr(snapshot, name)
                setattr(snapshot, name, "absent")
                with self.assertRaises(IntegrityError), transaction.atomic():
                    snapshot.save(update_fields=[name])
                setattr(snapshot, name, previous)

    def test_service_stack_is_collected_with_versions_states_and_provenance(self) -> None:
        collected = self.discover()
        self.assertEqual(
            [observation.component for observation in collected.components],
            ["nginx", "php-fpm", "mariadb", "postgresql"],
        )
        nginx = self.component("nginx")
        self.assertEqual(nginx.package.outcome, "observed")
        self.assertEqual(nginx.package.value, (Package("nginx", "1.24.0-2ubuntu7.18"),))
        self.assertEqual(nginx.package.source, (PACKAGE_QUERY,))
        self.assertEqual(nginx.service.outcome, "observed")
        self.assertEqual(nginx.service.value, ("nginx.service active (running), enabled",))
        self.assertEqual(nginx.service.source, (UNIT_QUERY.format("nginx.service"),))
        php = self.component("php-fpm")
        self.assertEqual(php.package.value, (Package("php8.3-fpm", "8.3.6-0ubuntu0.24.04.11"),))
        self.assertEqual(php.service.value, ("php8.3-fpm.service active (running), enabled",))
        mariadb = self.component("mariadb")
        self.assertIn(
            Package("mariadb-server", "1:10.11.14-0ubuntu0.24.04.1"), mariadb.package.value
        )
        self.assertEqual(mariadb.service.value, ("mariadb.service active (running), enabled",))
        postgres = self.component("postgresql")
        self.assertIn(Package("postgresql-16", "16.15-0ubuntu0.24.04.1"), postgres.package.value)
        self.assertEqual(postgres.service.value, (UMBRELLA_LINE, MAIN_LINE))
        self.assert_succeeded()
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
        self.assertContains(page, f'datetime="{self.snapshot.collected_at.isoformat()}"')

    def test_sites_and_pools_are_collected_with_provenance_and_time(self) -> None:
        self.enable_sites({"example.com": self.EXAMPLE_SITE, "default": self.DEFAULT_SITE})
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        collected = self.discover()
        sites, pools = collected.nginx_site_files, collected.php_fpm_pools
        self.assertEqual(sites.outcome, "observed")
        self.assertEqual(sites.source, (SITE_DIR,))
        self.assertEqual([site.name for site in sites.value], ["example.com", "default"])
        example = sites.value[0]
        self.assertEqual(example.outcome, "observed")
        self.assertEqual(example.server_names, ("example.com",))
        self.assertEqual(example.listens, ("443",))
        self.assertEqual(example.source, f"{SITE_DIR}/example.com")
        self.assertEqual([(pool.version, pool.name) for pool in pools.value], [("8.3", "www")])
        (pool,) = pools.value
        self.assertEqual((pool.outcome, pool.listen), ("observed", "/run/php/php8.3-fpm.sock"))
        self.assertEqual(pool.source, f"{PHP_DIR}/8.3/fpm/pool.d/www.conf")
        self.assertEqual(pools.outcome, "observed")
        # The pool directory Barectl listed, not /etc/php, which it does not read.
        self.assertEqual(pools.source, (f"{PHP_DIR}/8.3/fpm/pool.d",))
        self.assert_succeeded()
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
        self.assertContains(page, f"from <code>{PHP_DIR}/8.3/fpm/pool.d</code>")
        self.assertContains(page, "does not link them to PHP-FPM pools")
        self.assertContains(page, "This is a snapshot, not live status.")
        self.assertContains(page, f'datetime="{self.snapshot.collected_at.isoformat()}"')
        # Safe fields only: the TLS certificate path, pool user and secret environment
        # values are never stored or shown.
        for secret in ("ssl_certificate", "/etc/ssl/example.pem", "hunter2", "www-data", "soap"):
            self.assertNotContains(page, secret)
        stored = "\n".join(str((site.server_names, site.listens)) for site in sites.value) + (
            "\n".join(str((pool.name, pool.listen, pool.source)) for pool in pools.value)
        )
        self.assertNotIn("hunter2", stored)

    def test_repeated_discovery_replaces_state_without_duplicates(self) -> None:
        self.enable_sites({"example.com": self.EXAMPLE_SITE, "default": self.DEFAULT_SITE})
        self.enable_pools("8.3", {"www.conf": self.POOL_CONF})
        collected = self.discover()
        self.assertEqual(len(collected.nginx_site_files.value), 2)
        self.assertEqual(len(collected.php_fpm_pools.value), 1)
        first = DiscoverySnapshot.objects.get()
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
        self.assertNotEqual(DiscoverySnapshot.objects.get().pk, first.pk)
        refreshed = current(first.server).collected
        self.assertEqual(
            [(s.name, s.server_names, s.listens) for s in refreshed.nginx_site_files.value],
            [("default", ("default.example",), ("8080",))],
        )
        self.assertEqual(
            [(pool.version, pool.name) for pool in refreshed.php_fpm_pools.value],
            [("8.1", "admin"), ("8.3", "www")],
        )
        self.assertEqual(len(refreshed.php_fpm_pools.value), 2)
        page = self.client.get(f"/servers/{first.server.pk}/")
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
        """Run one successful discovery and return its stored snapshot row."""
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
        self.assertEqual(
            observed(current(self.server).collected.os).pretty_name, "Ubuntu 24.04.4 LTS"
        )
        self.assertNotEqual(snapshot.pk, first.pk)
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Ubuntu 24.04.4 LTS")
        self.assertNotContains(page, "may be out of date")

    def test_refresh_replaces_service_observations(self) -> None:
        before = self.succeed_once()
        self.assertEqual(len(current(self.server).collected.components), 4)
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
            [
                (c.component, c.package.outcome, c.service.outcome)
                for c in current(self.server).collected.components
            ],
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
        self.assertEqual(
            observed(current(self.server).collected.os).pretty_name, "Ubuntu 24.04.3 LTS"
        )
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

        self.assertEqual(current(self.server).collected.os.outcome, "inaccessible")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "<strong>Inaccessible:</strong>", html=True)
        self.assertNotContains(page, "No observations yet.")
        self.assert_succeeded()

    def test_unsupported_refresh_is_not_absent_software(self) -> None:
        self.succeed_once()
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.remote.files = {"/etc/os-release": "<html>not a release file</html>\n"}
        self.client.post(self.verify_url())
        self.run_worker()

        self.assertEqual(current(self.server).collected.os.outcome, "unsupported")
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

    def latest(self) -> DiscoveryAttempt:
        """The server's latest attempt, as any page reading it would see it."""
        attempt = read_discovery(self.server).attempt
        if attempt is None:
            raise AssertionError("The server has no attempt.")
        return attempt

    def latest_status(self) -> str:
        return self.latest().status

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

        # Reading the latest attempt recovers it; no caller has to remember to.
        attempt = self.latest()
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
        self.assertEqual(self.latest_status(), DiscoveryAttempt.Status.FAILED)
        attempt.refresh_from_db()
        self.assertIn("stopped before finishing", attempt.failure)

    def test_queued_with_ready_task_waits_for_worker(self) -> None:
        attempt = request_discovery(self.server)
        self.make_stale(attempt, queued=True)
        # A READY task still waits: restarting the worker should run it, not fail it.
        self.assertEqual(self.latest_status(), DiscoveryAttempt.Status.QUEUED)
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
        self.assertEqual(self.latest_status(), DiscoveryAttempt.Status.QUEUED)
        # That worker was killed before claiming the attempt.
        past = timezone.now() - STALE_AFTER - datetime.timedelta(minutes=1)
        DBTaskResult.objects.filter(pk=task.pk).update(started_at=past)
        self.assertEqual(self.latest_status(), DiscoveryAttempt.Status.FAILED)
        attempt.refresh_from_db()
        self.assertEqual(attempt.failure, INTERRUPTED_FAILURE)

    def run_recovered_mid_run(self, attempt: DiscoveryAttempt) -> None:
        """Run the worker; while it connects, the attempt goes stale and a page recovers it."""
        connect = ssh.connect

        @contextmanager
        def connect_after_recovery(target: ConnectionTarget) -> Iterator[ssh.RemoteShell]:
            self.make_stale(attempt, started=True)
            self.assertEqual(self.latest_status(), DiscoveryAttempt.Status.FAILED)
            with connect(target) as shell:
                yield shell

        with mock.patch.object(ssh, "connect", connect_after_recovery):
            self.run_worker()

    def test_stale_worker_cannot_overwrite_recovery_or_newer_result(self) -> None:
        request_discovery(self.server)
        self.run_worker()
        first_snapshot = DiscoverySnapshot.objects.get()

        # The stale worker fails late: its failure must not replace the recovery's.
        self.remote.failure = "late failure from stale worker"
        failed = request_discovery(self.server)
        self.run_recovered_mid_run(failed)
        failed.refresh_from_db()
        self.assertEqual(failed.status, DiscoveryAttempt.Status.FAILED)
        self.assertEqual(failed.failure, INTERRUPTED_FAILURE)

        # Nor can a stale worker that succeeds late publish a snapshot after recovery.
        self.remote.failure = ""
        stale = request_discovery(self.server)
        self.run_recovered_mid_run(stale)
        stale.refresh_from_db()
        self.assertEqual(stale.status, DiscoveryAttempt.Status.FAILED)
        self.assertEqual(stale.failure, INTERRUPTED_FAILURE)
        self.assertEqual(stale.host_key, "")
        self.assertEqual(DiscoverySnapshot.objects.get().pk, first_snapshot.pk)

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

    def test_a_running_attempt_that_is_not_stale_is_shown_as_running(self) -> None:
        self.interrupt_running()
        self.sign_in_with("view_server")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "<strong>Checking connection</strong> since", html=False)
        self.assertContains(page, "A new connection check is running")
        self.assertContains(page, 'hx-trigger="every 2s"')

    def test_every_page_that_shows_attempts_recovers_abandoned_ones(self) -> None:
        self.sign_in_with("view_server", "delete_server")
        pages = {
            "server": f"/servers/{self.server.pk}/",
            "activity": "/activity/",
            "removal": f"/servers/{self.server.pk}/remove/",
        }
        for name, url in pages.items():
            with self.subTest(page=name):
                DiscoveryAttempt.objects.all().delete()
                interrupted = self.interrupt_running()
                self.make_stale(interrupted, started=True)
                page = self.client.get(url)
                self.assertEqual(page.status_code, 200)
                self.assertNotContains(page, "Checking connection")
                interrupted.refresh_from_db()
                self.assertEqual(interrupted.failure, INTERRUPTED_FAILURE)

    def test_healthy_attempts_finish_before_recovery_would_interrupt_them(self) -> None:
        # Connecting, the handshake, authentication and opening a channel each have a limit.
        longest = datetime.timedelta(seconds=4 * ssh.CONNECT_TIMEOUT + ssh.ATTEMPT_TIMEOUT)
        self.assertGreater(STALE_AFTER, longest * 1.5)

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


class ActivityHistoryTests(DiscoveryTestCase):
    """Reviewing recorded attempts: each server's history and the Activity view.

    Attempt outcomes and the snapshots successes published stay distinguishable: a failed
    or interrupted attempt remains listed beside the snapshot it did not replace.
    """

    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def verify_url(self) -> str:
        return f"/servers/{self.server.pk}/verify/"

    def test_history_shows_the_attempt_and_its_snapshot_collection_time(self) -> None:
        request_discovery(self.server)
        self.run_worker()
        snapshot = DiscoverySnapshot.objects.get()
        self.sign_in_with("view_server")
        history = self.history_of(self.client.get(f"/servers/{self.server.pk}/"))
        self.assertIn("Discovery history", history)
        self.assertIn("Succeeded", history)
        self.assertIn(date_format(snapshot.collected_at, "M j, Y, H:i:s T"), history)
        self.assertIn("not live status", history)

    def test_a_failed_refresh_stays_listed_with_the_previous_snapshot(self) -> None:
        request_discovery(self.server)
        self.run_worker()
        snapshot = DiscoverySnapshot.objects.get()
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.remote.failure = "Barectl could not reach the SSH service configured for web."
        self.client.post(self.verify_url())
        self.run_worker()

        page = self.client.get(f"/servers/{self.server.pk}/")
        content = page.content.decode()
        # The latest failure is shown although the earlier snapshot is still displayed.
        self.assertIn("The latest connection check failed", content)
        self.assertIn("could not reach the SSH service", content)
        self.assertIn("Ubuntu 24.04.3 LTS", content)
        history = content[content.index('id="discovery-history"') :]
        self.assertLess(history.index("Failed"), history.index("Succeeded"))
        self.assertIn(date_format(snapshot.collected_at, "M j, Y, H:i:s T"), history)

    def test_activity_shows_the_snapshot_warnings_beside_their_attempt(self) -> None:
        del self.remote.files["/proc/meminfo"]
        self.remote.unreadable = {"/proc/meminfo"}
        request_discovery(self.server)
        self.run_worker()
        warning = "cannot read /proc/meminfo. Barectl does not use sudo."
        self.assertIn(warning, current(self.server).collected.memory_bytes.warning)
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.remote.failure = "Barectl could not reach the SSH service configured for web."
        self.client.post(self.verify_url())
        self.run_worker()

        content = self.client.get("/activity/").content.decode()
        table = content[content.index("<table") : content.index("</table>")]
        failed, succeeded = table.split("<tr>")[2:]
        # The failed refresh published nothing, so it carries no snapshot warnings.
        self.assertIn("could not reach the SSH service", failed)
        self.assertNotIn("/proc/meminfo", failed)
        self.assertIn("1 observation warning", succeeded)
        self.assertIn("Memory: <strong>Inaccessible:</strong>", succeeded)
        self.assertIn(warning, succeeded)
        # The server page shows the warning with the snapshot, not again in its history.
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, warning, count=1)
        self.assertNotIn(warning, self.history_of(page))

    def test_history_claims_no_warnings_for_a_complete_snapshot(self) -> None:
        request_discovery(self.server)
        self.run_worker()
        collected = current(self.server).collected
        # Notes on completed observations, such as an empty site directory, are findings.
        self.assertNotEqual(collected.nginx_site_files.warning, "")
        self.assertEqual(collected.warnings, [])
        self.sign_in_with("view_server")
        self.assertNotContains(self.client.get("/activity/"), "observation warning")

    def test_activity_queries_do_not_grow_with_snapshots(self) -> None:
        self.sign_in_with("view_server")
        request_discovery(self.server)
        self.run_worker()
        with CaptureQueriesContext(connection) as one:
            self.client.get("/activity/")
        other = Server.objects.create(name="DB", ssh_alias="stage.example.net")
        request_discovery(other)
        self.run_worker()
        with CaptureQueriesContext(connection) as two:
            page = self.client.get("/activity/")
        self.assertEqual(page.content.decode().count("<tr>"), 3)
        self.assertEqual(len(two), len(one))

    def test_activity_lists_attempts_across_servers_newest_first(self) -> None:
        request_discovery(self.server)
        other = Server.objects.create(name="DB", ssh_alias="stage.example.net")
        request_discovery(other)
        self.run_worker()
        self.sign_in_with("view_server", "add_discoveryattempt")
        self.remote.failure = "Barectl could not reach the SSH service configured for web."
        self.client.post(self.verify_url())
        self.run_worker()

        page = self.client.get("/activity/")
        self.assertContains(page, "Discovery attempts across all servers")
        # Newest recorded first: Web's failed refresh, DB's check, then Web's first.
        content = page.content.decode()
        failure = content.index("could not reach the SSH service")
        db_row = content.index("stage.example.net")
        web_retry = content.index("web.example.com", db_row)
        self.assertLess(failure, db_row)
        self.assertLess(db_row, web_retry)

    def test_activity_shows_interrupted_attempts_after_recovery(self) -> None:
        attempt = request_discovery(self.server)
        DiscoveryAttempt.objects.filter(pk=attempt.pk).update(
            status=DiscoveryAttempt.Status.RUNNING,
            started_at=timezone.now() - STALE_AFTER - datetime.timedelta(minutes=1),
        )
        self.sign_in_with("view_server")
        page = self.client.get("/activity/")
        self.assertContains(page, "stopped before finishing")
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.FAILED)

    def test_unexpected_failures_reach_activity_without_their_details(self) -> None:
        def broken(target: ConnectionTarget) -> Iterator[ssh.RemoteShell]:
            raise RuntimeError("password=hunter2 from remote output")

        request_discovery(self.server)
        with mock.patch.object(ssh, "connect", broken):
            self.run_worker()
        self.sign_in_with("view_server")
        page = self.client.get("/activity/")
        self.assertContains(page, "unexpected error")
        self.assertNotContains(page, "hunter2")


class RemovalTests(DiscoveryTestCase):
    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def remove_url(self, server: Server | None = None) -> str:
        return f"/servers/{(server or self.server).pk}/remove/"

    def confirm(self, client: Client | None = None) -> HttpResponseBase:
        return (client or self.client).post(self.remove_url(), {"confirm": "remove"})

    def test_removal_requires_sign_in_and_permissions(self) -> None:
        url = self.remove_url()
        self.assertRedirects(self.client.get(url), f"/accounts/login/?next={url}")
        self.assertRedirects(self.confirm(), f"/accounts/login/?next={url}")
        for codenames in (("view_server",), ("delete_server",), ("view_server", "change_server")):
            with self.subTest(codenames=codenames):
                self.user.user_permissions.clear()
                self.sign_in_with(*codenames)
                self.assertEqual(self.client.get(url).status_code, 403)
                self.assertContains(self.confirm(), "Access denied", status_code=403)
        self.assertTrue(Server.objects.filter(pk=self.server.pk).exists())
        self.user.user_permissions.clear()
        self.sign_in_with("view_server", "change_server")
        self.assertNotContains(self.client.get(f"/servers/{self.server.pk}/"), url)

    def test_removal_requires_csrf(self) -> None:
        self.grant("view_server", "delete_server")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        self.assertEqual(self.confirm(client).status_code, 403)
        self.assertTrue(Server.objects.filter(pk=self.server.pk).exists())

    def test_removal_requires_confirmation(self) -> None:
        request_discovery(self.server)
        self.run_worker()
        self.sign_in_with("view_server", "delete_server")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(
            page, f'href="{self.remove_url()}">Remove<span class="usa-sr-only"> Web</span></a>'
        )
        # Opening the confirmation, or posting without confirming, deletes nothing.
        page = self.client.get(self.remove_url())
        self.assertContains(page, "<h1>Remove Web</h1>", html=True)
        self.assertContains(
            page,
            '<button type="submit" class="usa-button barectl-button--destructive" '
            'name="confirm" value="remove">Remove server</button>',
            html=True,
        )
        self.assertContains(page, "1 discovery attempt and the latest snapshot")
        self.assertContains(page, "<code>web.example.com</code>")
        self.assertContains(page, "Barectl does not connect to the server")
        self.assertContains(page, "known_hosts")
        response = self.client.post(self.remove_url())
        self.assertContains(response, "<h1>Remove Web</h1>", html=True)
        self.assertEqual(Server.objects.count(), 1)
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)
        self.assertEqual(DiscoverySnapshot.objects.count(), 1)

    def test_removal_deletes_the_registration_and_its_history_only(self) -> None:
        known_hosts = self.ssh_config.with_name("known_hosts")
        known_hosts.write_text(f"web.example.com {HOST_KEY}\n", encoding="utf-8")
        other = Server.objects.create(name="Database", ssh_alias="db-1")
        request_discovery(self.server)
        request_discovery(other)
        self.run_worker()
        # A failed refresh adds history alongside the successful snapshot.
        self.remote.failure = "Barectl could not reach the SSH service configured for web."
        request_discovery(self.server)
        self.run_worker()
        self.assertEqual(DiscoveryAttempt.objects.filter(server=self.server).count(), 2)
        controller_files = {path: path.read_bytes() for path in (self.ssh_config, known_hosts)}
        connections = len(self.remote.targets)
        removed_attempts = list(
            DiscoveryAttempt.objects.filter(server=self.server).values_list("pk", flat=True)
        )

        self.sign_in_with("view_server", "delete_server", "add_server")
        response = self.confirm()

        self.assertRedirects(response, "/", fetch_redirect_response=False)
        self.assertFalse(Server.objects.filter(pk=self.server.pk).exists())
        self.assertFalse(DiscoveryAttempt.objects.filter(server_id=self.server.pk).exists())
        self.assertFalse(DiscoverySnapshot.objects.filter(server_id=self.server.pk).exists())
        self.assertFalse(
            ComponentObservation.objects.filter(snapshot__server_id=self.server.pk).exists()
        )
        # The worker's records of the removed attempts go too.
        tasks = DBTaskResult.objects.values_list("args_kwargs__args__0", flat=True)
        self.assertFalse(set(tasks) & set(removed_attempts))
        # Other servers keep their history.
        self.assertEqual(DiscoveryAttempt.objects.get().server, other)
        self.assertEqual(DiscoverySnapshot.objects.get().server, other)
        self.assertEqual(list(tasks), [DiscoveryAttempt.objects.get().pk])
        # Nothing connected to the server, and the controller's files are unchanged.
        self.assertEqual(len(self.remote.targets), connections)
        for path, content in controller_files.items():
            self.assertEqual(path.read_bytes(), content)
        page = self.client.get("/")
        self.assertContains(page, "Removed Web and its discovery history from Barectl.")
        self.assertNotContains(page, "web.example.com")
        # The alias stays configured on the controller, so it can be registered again.
        form = self.client.get("/servers/add/")
        self.assertContains(form, '<option value="web.example.com">')

    def test_removal_is_refused_while_discovery_is_active(self) -> None:
        attempt = request_discovery(self.server)
        self.sign_in_with("view_server", "delete_server")
        for state in (DiscoveryAttempt.Status.QUEUED, DiscoveryAttempt.Status.RUNNING):
            with self.subTest(state=state):
                DiscoveryAttempt.objects.filter(pk=attempt.pk).update(
                    status=state, started_at=timezone.now()
                )
                page = self.client.get(self.remove_url())
                self.assertContains(page, "Discovery in progress")
                self.assertNotContains(page, 'name="confirm"')
                # Only a confirmed removal is refused as a conflict.
                self.assertEqual(self.client.post(self.remove_url()).status_code, 200)
                response = self.confirm()
                self.assertContains(response, "Discovery in progress", status_code=409)
                self.assertTrue(Server.objects.filter(pk=self.server.pk).exists())
                self.assertTrue(DiscoveryAttempt.objects.filter(pk=attempt.pk).exists())

        # The active job was not lost: once it finishes, removal proceeds.
        DiscoveryAttempt.objects.filter(pk=attempt.pk).update(
            status=DiscoveryAttempt.Status.QUEUED, started_at=None
        )
        self.run_worker()
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED)
        self.assertRedirects(self.confirm(), "/", fetch_redirect_response=False)
        self.assertFalse(Server.objects.exists())

    def test_a_refusal_is_reported_after_the_blocking_check_finishes(self) -> None:
        self.sign_in_with("view_server", "delete_server")
        # A concurrent check blocked the removal and finished before the page rendered.
        with mock.patch("servers.views.remove_server", side_effect=RemovalBlocked):
            response = self.confirm()
        self.assertContains(response, "so the server was not removed", status_code=409)
        self.assertContains(response, 'name="confirm"', status_code=409)
        self.assertTrue(Server.objects.filter(pk=self.server.pk).exists())

    def test_an_abandoned_attempt_does_not_block_removal(self) -> None:
        attempt = request_discovery(self.server)
        past = timezone.now() - STALE_AFTER - datetime.timedelta(minutes=1)
        DiscoveryAttempt.objects.filter(pk=attempt.pk).update(
            status=DiscoveryAttempt.Status.RUNNING, started_at=past
        )
        self.sign_in_with("view_server", "delete_server")
        self.assertRedirects(self.confirm(), "/", fetch_redirect_response=False)
        self.assertFalse(Server.objects.exists())
        self.assertFalse(DiscoveryAttempt.objects.exists())

    def test_removed_and_unknown_servers_are_not_found(self) -> None:
        self.sign_in_with("view_server", "delete_server", "add_discoveryattempt")
        self.assertEqual(self.client.get("/servers/999/remove/").status_code, 404)
        self.confirm()
        self.assertEqual(self.confirm().status_code, 404)
        self.assertEqual(self.client.post(f"/servers/{self.server.pk}/verify/").status_code, 404)
        self.assertFalse(DiscoveryAttempt.objects.exists())


class RemovalRaceTests(TransactionTestCase):
    """Removal against discovery started by a concurrent request, with real commits.

    An attempt created inside removal's transaction, after its check, stands in for any
    interleaving a database allows: the foreign key check at commit refuses it. Foreign
    keys are checked when a transaction commits, so these tests cannot run inside
    TestCase's wrapping transaction. ``discovery.test_race`` runs the two requests in
    separate processes on a database file.
    """

    server: Server

    @override
    def setUp(self) -> None:
        remote = FakeServer()
        self.enterContext(mock.patch.object(ssh, "connect", remote.connect))
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (directory / "config").write_text("Host web.example.com\n", encoding="utf-8")
        self.enterContext(override_settings(SSH_CONFIG_PATH=str(directory / "config")))
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        request_discovery(self.server)
        run_worker()

    def test_discovery_queued_after_the_active_check_blocks_removal(self) -> None:
        delete = Collector.delete
        previous = DiscoveryAttempt.objects.get()

        def queue_then_delete(collector: Collector) -> tuple[int, dict[str, int]]:
            if Server in collector.data:
                # Another request queues discovery after removal checked for active
                # attempts, before the server row is deleted.
                request_discovery(self.server)
            return delete(collector)

        with (
            mock.patch.object(Collector, "delete", queue_then_delete),
            self.assertRaises(RemovalBlocked),
        ):
            remove_server(self.server)
        # The whole removal was rolled back: the registration and its history remain.
        self.assertTrue(Server.objects.filter(pk=self.server.pk).exists())
        self.assertEqual(DiscoveryAttempt.objects.get(), previous)
        self.assertEqual(DiscoverySnapshot.objects.get().attempt, previous)

    def test_discovery_requested_after_removal_is_refused(self) -> None:
        # A request that loaded the server before another request removed it.
        loaded = Server.objects.get(pk=self.server.pk)
        remove_server(self.server)
        with self.assertRaises(Server.DoesNotExist):
            request_discovery(loaded)
        self.assertFalse(DiscoveryAttempt.objects.exists())
        self.assertFalse(DBTaskResult.objects.filter(status="READY").exists())
