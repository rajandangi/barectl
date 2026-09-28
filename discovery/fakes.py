"""The simulated managed server and the fixtures the discovery tests share.

``FakeServer`` substitutes remote execution at the ``RemoteShell`` seam
(docs/adr/0002-keep-the-remote-shell-seam.md); ``discovery/test_fake_server.py`` checks
its probe answers against a real shell. ``COLLECTED`` is a stored snapshot built by
value, and tests record attempts through ``record_attempt`` rather than writing attempt
rows, so the rule for which timestamps a state carries lives in one place. Tests read and
claim the worker's task records through ``task_records`` and ``claim_task``, built on
the lifecycle module's ``_tasks``.
"""

import re
import signal
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import UTC, datetime, timedelta
from typing import override
from unittest import mock

from django.core.management import call_command
from django.tasks import TaskResultStatus
from django.test import SimpleTestCase
from django.utils import timezone
from django_tasks_db.models import DBTaskResultQuerySet

from servers.models import Server
from servers.ssh_config import ConnectionTarget
from servers.testing import ControllerConfigTestCase

from . import services, ssh
from .models import DiscoveryAttempt, ObservationOutcome, WebStackComponent
from .observations import collect
from .presentation import present
from .services import STALE_AFTER
from .snapshot import (
    CollectedSnapshot,
    FilesystemSize,
    Observation,
    OsRelease,
    Package,
    PoolEntryObservation,
    ServiceUnit,
    SiteFileObservation,
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
UMBRELLA_UNIT = ServiceUnit("postgresql.service", "loaded", "active", "exited", "enabled")
MAIN_UNIT = ServiceUnit(
    "postgresql@16-main.service", "loaded", "active", "running", "enabled-runtime"
)


COLLECTED_AT = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)

# Every kind of observation, observed and not, with values that span several lines.
COLLECTED = CollectedSnapshot(
    os=Observation(
        ObservationOutcome.OBSERVED,
        ("/etc/os-release",),
        "",
        OsRelease("Ubuntu 24.04.3 LTS", "Ubuntu", "ubuntu", ""),
    ),
    architecture=Observation(ObservationOutcome.OBSERVED, ("uname -m",), "", "x86_64"),
    cpu_count=Observation(
        ObservationOutcome.UNSUPPORTED, ("nproc",), "nproc did not report the CPU count.", None
    ),
    memory_bytes=Observation(ObservationOutcome.OBSERVED, ("/proc/meminfo",), "", 4_121_137_152),
    filesystem=Observation(
        ObservationOutcome.OBSERVED,
        ("df -B1 --output=size,avail,target /",),
        "",
        FilesystemSize(53_689_778_176, 0),
    ),
    components=(
        WebStackComponentObservation(
            WebStackComponent.POSTGRESQL,
            Observation(
                ObservationOutcome.OBSERVED,
                ("dpkg-query",),
                "",
                (Package("postgresql", "16+257build1.1"), Package("postgresql-16", "16.15-0")),
            ),
            Observation(
                ObservationOutcome.OBSERVED,
                ("ls -1b /etc/postgresql", "systemctl show postgresql.service"),
                "",
                (
                    ServiceUnit("postgresql.service", "loaded", "active", "exited", "enabled"),
                    ServiceUnit("postgresql@16-main.service", "not-found", "inactive", "dead", ""),
                ),
            ),
        ),
        WebStackComponentObservation(
            WebStackComponent.NGINX,
            Observation(ObservationOutcome.ABSENT, ("dpkg-query",), "No Nginx packages.", ()),
            Observation(ObservationOutcome.ABSENT, ("dpkg-query",), "No Nginx packages.", ()),
        ),
    ),
    nginx_site_files=Observation(
        ObservationOutcome.OBSERVED,
        ("/etc/nginx/sites-enabled",),
        "",
        (
            SiteFileObservation(
                "example.com",
                ObservationOutcome.OBSERVED,
                ("example.com", "www.example.com"),
                ("443 ssl", "[::]:443 ssl"),
                "/etc/nginx/sites-enabled/example.com",
                "",
            ),
            SiteFileObservation(
                "private",
                ObservationOutcome.INACCESSIBLE,
                (),
                (),
                "/etc/nginx/sites-enabled/private",
                "The SSH user cannot read it.",
            ),
        ),
    ),
    php_fpm_pools=Observation(
        ObservationOutcome.OBSERVED,
        ("/etc/php",),
        "Pools in skipped files are not shown.",
        (
            PoolEntryObservation(
                "8.3",
                "www",
                ObservationOutcome.OBSERVED,
                "/run/php/php8.3-fpm.sock",
                "/etc/php/8.3/www.conf",
                "",
            ),
        ),
    ),
)


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

    def substituted(self) -> AbstractContextManager[object]:
        """Substitute this server for the SSH transport while the context is open."""
        return mock.patch.object(ssh, "connect", self.connect)

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


# Discovery attempts recorded in any state and age, for tests that need history.
AttemptStatus = DiscoveryAttempt.Status
# Old enough for recovery to treat an active attempt as abandoned.
STALE = STALE_AFTER + timedelta(minutes=1)
_FINISHED = (AttemptStatus.SUCCEEDED, AttemptStatus.FAILED)


def record_attempt(
    target: Server | DiscoveryAttempt,
    status: AttemptStatus = AttemptStatus.QUEUED,
    *,
    age: timedelta = timedelta(),
    failure: str = "",
) -> DiscoveryAttempt:
    """Record an attempt that reached ``status`` ``age`` ago, and return it as stored.

    A server gets a new attempt without a worker task, recorded ``age`` ago. An existing
    attempt, such as one ``request_discovery`` queued with its task, keeps the time it was
    recorded unless it is queued again. Running attempts start ``age`` ago, finished ones
    finish then; a queued attempt has neither time.
    """
    when = timezone.now() - age
    if isinstance(target, Server):
        attempt = DiscoveryAttempt.objects.create(server=target, ssh_alias=target.ssh_alias)
        recorded = True
    else:
        attempt = target
        recorded = status == AttemptStatus.QUEUED
    changes: dict[str, object] = {
        "status": status,
        "failure": failure,
        "finished_at": when if status in _FINISHED else None,
    }
    if status == AttemptStatus.RUNNING:
        changes["started_at"] = when
    elif recorded:
        changes["started_at"] = None
    if recorded:
        # queued_at is set when a row is created; an update makes the recorded time exact.
        changes["queued_at"] = when
    DiscoveryAttempt.objects.filter(pk=attempt.pk).update(**changes)
    attempt.refresh_from_db()
    return attempt


def task_records(*attempts: DiscoveryAttempt) -> DBTaskResultQuerySet:
    """The worker's task records for ``attempts``, or for every attempt when none is given.

    Tests read task records through the lifecycle module, which alone knows how the task
    backend stores an attempt's task.
    """
    if not attempts:
        return services._tasks()
    return services._tasks(attempt.pk for attempt in attempts)


def waiting_tasks(*attempts: DiscoveryAttempt) -> int:
    """How many of ``attempts``' tasks, or of every attempt's, still wait for a worker."""
    return task_records(*attempts).filter(status=TaskResultStatus.READY).count()


def claim_task(attempt: DiscoveryAttempt, *, age: timedelta = timedelta()) -> None:
    """Record that a worker claimed the attempt's task ``age`` ago and still holds it."""
    task_records(attempt).update(status=TaskResultStatus.RUNNING, started_at=timezone.now() - age)


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
        return [(item.label, item.outcome) for item in present(self.collected).warnings]

    def assert_not_kept(self, *texts: str) -> None:
        """Assert no value of the last collection holds any of ``texts``."""
        kept = kept_text(self.collected)
        for text in texts:
            self.assertNotIn(text, kept)

    def assert_nothing_absent(self) -> None:
        """Assert no observation of the last collection, or of its entries, is absent."""
        outcomes = [item.outcome for item in present(self.collected).observations]
        self.assertNotIn(ObservationOutcome.ABSENT, outcomes)


class DiscoveryTestCase(FakeServerMixin, ControllerConfigTestCase):
    snapshot: Snapshot

    @override
    def setUp(self) -> None:
        super().setUp()
        self.enterContext(self.remote.substituted())

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

    def assert_succeeded(self) -> None:
        """Assert the server's latest discovery attempt succeeded."""
        attempt = Server.objects.get().discovery_attempts.latest("queued_at", "pk")
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED)


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
