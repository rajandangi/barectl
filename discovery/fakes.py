"""The simulated managed server and the fixtures the discovery tests share.

``FakeServer`` substitutes remote execution at the ``RemoteShell`` seam
(docs/adr/0002-keep-the-remote-shell-seam.md). Tests record attempts through
``record_attempt`` rather than writing attempt rows, so the rule for which timestamps a
state carries lives in one place.
"""

import posixpath
import re
import shlex
import signal
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, overload, override
from unittest import mock

from django.core.management import call_command
from django.tasks import TaskResultStatus
from django.test import SimpleTestCase
from django.utils import timezone
from django_tasks_db.models import DBTaskResultQuerySet

from operations import lifecycle
from operations.apt import PROCESS_COMMAND
from operations.models import RemoteOperation
from servers.models import Server
from servers.ssh_config import ConnectionTarget
from servers.testing import ControllerConfigTestCase
from sites.observation import PROXY_INVENTORY_COMMAND

from . import ssh
from .models import (
    DiscoveryAttempt,
    ObservationOutcome,
    SiteState,
    WebStackComponent,
)
from .observations import (
    ARCH_COMMAND,
    CPU_COMMAND,
    FILESYSTEM_COMMAND,
    MEMINFO_PATH,
    OS_RELEASE_FILES,
    collect,
)
from .observations.components import version_query
from .presentation import present
from .recorded import ReplayShell, load
from .services import STALE_AFTER
from .snapshot import (
    CollectedSnapshot,
    FilesystemSize,
    Observation,
    ObservedSite,
    OsRelease,
    Package,
    ServiceUnit,
    SiteAccount,
    Snapshot,
    WebStackComponentObservation,
    current_snapshot,
)

UBUNTU = """\
PRETTY_NAME="Ubuntu 26.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="26.04"
VERSION="26.04.1 LTS (Resolute Raccoon)"
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
"""
# The capacity observations as the pristine 26.04 server answered them, so FakeServer
# keeps no hand-shaped output of its own (docs/quality.md#recorded-transcripts).
_RECORDED = dict(load("pristine-26.04").commands)
# Output shapes recorded from Ubuntu 26.04 (docs/ssh-connections.md#component-observations).
PACKAGE_QUERY = (
    "dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\\n' certbot "
    "mariadb-server mariadb-server-core nginx php8.3-fpm php8.4-fpm php8.5-fpm "
    "postgresql postgresql-18"
)
PACKAGE_NAMES_QUERY = "dpkg-query -W -f='${Package} ${db:Status-Abbrev}\\n'"
# Valkey's version read runs only when the package inventory lists it
# (discovery/observations/components.py).
VALKEY_VERSION_QUERY = version_query(("valkey-server", "valkey-tools"))
UNIT_QUERY = "systemctl show {} -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState"
DPKG_OUTPUT = """\
certbot 4.0.0-4 ii
mariadb-server 1:11.8.6-5ubuntu0.1 ii
mariadb-server-core 1:11.8.6-5ubuntu0.1 ii
nginx 1.28.3-2ubuntu1.11 ii
php-fpm  un
php8.5-fpm 8.5.4-0ubuntu1.3 ii
postgresql 18+290ubuntu1 ii
postgresql-18 18.6-0ubuntu0.26.04.1 ii
postgresql-18-jit-llvm  un
"""


def unit_report(
    unit: str, *, active: str = "active", sub: str = "running", file_state: str = "enabled"
) -> str:
    return (
        f"Id={unit}\nLoadState=loaded\nActiveState={active}\nSubState={sub}\n"
        f"UnitFileState={file_state}\n"
    )


HOST_KEY = "ssh-ed25519 SHA256:bZs0Sdo5mnU6ixaSbHkq9ZvXVsP1pxEmGZ0M8oPq3dE"
_FAILED = ssh.CommandResult(1, "")
# The Ubuntu 26.04 postgresql package creates the "18/main" cluster, started through the
# postgresql.service umbrella unit (docs/ssh-connections.md#postgresql-clusters).
PG_DIR = "/etc/postgresql"
CLUSTER_UNITS = "postgresql.service postgresql@18-main.service"


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
    "postgresql@18-main.service", "loaded", "active", "running", "enabled-runtime"
)


COLLECTED_AT = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)

# Every kind of observation, observed and not, with values that span several lines.
COLLECTED = CollectedSnapshot(
    os=Observation(
        ObservationOutcome.OBSERVED,
        ("/etc/os-release",),
        "",
        OsRelease("Ubuntu 26.04.1 LTS", "Ubuntu", "ubuntu", ""),
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
                (Package("postgresql", "18+290ubuntu1"), Package("postgresql-18", "18.6-0")),
            ),
            Observation(
                ObservationOutcome.OBSERVED,
                ("ls -1b /etc/postgresql", "systemctl show postgresql.service"),
                "",
                (
                    ServiceUnit("postgresql.service", "loaded", "active", "exited", "enabled"),
                    ServiceUnit("postgresql@18-main.service", "not-found", "inactive", "dead", ""),
                ),
            ),
        ),
        WebStackComponentObservation(
            WebStackComponent.NGINX,
            Observation(ObservationOutcome.ABSENT, ("dpkg-query",), "No Nginx packages.", ()),
            Observation(ObservationOutcome.ABSENT, ("dpkg-query",), "No Nginx packages.", ()),
        ),
    ),
    sites=Observation(
        ObservationOutcome.OBSERVED,
        ("/etc/caddy/sites", "/etc/php-fpm", "/var/www"),
        "",
        (
            ObservedSite(
                "alpha",
                ("alpha.test", "www.alpha.test"),
                "php85",
                SiteAccount(1001, 1001, "/var/www/alpha", "/usr/sbin/nologin"),
                SiteState.MANAGED,
                ObservationOutcome.OBSERVED,
                file="/etc/caddy/sites/alpha.caddy",
            ),
            ObservedSite(
                "beta",
                ("beta.test",),
                "php85",
                None,
                SiteState.NOT_FOLLOWING,
                ObservationOutcome.OBSERVED,
                file="/etc/caddy/sites/beta.caddy",
            ),
        ),
    ),
)


_ROOT_LISTENER_READ = shlex.quote("ss -Hlnpt '( sport = :80 or sport = :443 )'")
# The fixed command listing the sites a reviewed change reaches (sites/change.py).
_MEMBERSHIP_READ = (
    "find /etc/caddy/sites -maxdepth 1 -type f -name '*.caddy' "
    "-printf '%f\\n' | sed 's/\\.caddy$//' | LC_ALL=C sort"
)
READ_ONLY = re.compile(
    r"\A(cat|test -e|test -r|test -x) ("
    r"/etc/os-release|/usr/lib/os-release|/proc/meminfo"
    r"|/etc/postgresql(/[0-9.]+)?"
    r")\Z"
    # Parent directories, checked to tell a missing path from a hidden one.
    r"|\Atest -[ex] (/|/etc|/usr/lib|/proc)\Z"
    # PostgreSQL cluster directories and the configuration file that marks one.
    r"|\Atest -[eLdx] /etc/postgresql/[0-9.]+/[A-Za-z0-9._-]+(/postgresql\.conf)?\Z"
    r"|\Auname -m\Z"
    r"|\Atest -[ex] /nix(?:/[A-Za-z0-9._-]+)*\Z"
    r"|\Atest -[ex] /etc/nix(?:/[A-Za-z0-9._-]+)*\Z"
    r"|\Atest -[ex] (/usr|/usr/local|/home|/www|/etc/systemd|/etc/systemd/system|"
    r"/etc/systemd/journald\.conf\.d|/etc/caddy|/etc/nix|/nix|/nix/var|/nix/var/nix|"
    r"/nix/var/nix/profiles|/nix/var/nix/profiles/default|/nix/var/nix/profiles/per-user|"
    r"/nix/var/nix/profiles/per-user/root)\Z"
    r"|\Atest -[edrx] (/nix/var/nix/profiles/default/bin/nix|/nix/store|"
    r"/nix/var/nix/profiles/per-user/root/profile/bin/caddy|/etc/nix/nix\.conf|"
    r"/etc/caddy/Caddyfile|/etc/systemd/system/caddy\.service|"
    r"/etc/systemd/journald\.conf\.d/50-barectl\.conf|/etc/caddy/sites|"
    r"/usr/local/cpanel|/usr/local/psa|"
    r"/usr/local/directadmin|/usr/local/hestia|/usr/local/vesta|/usr/local/CyberCP|"
    r"/usr/local/ispconfig|/etc/webmin|/www/server|/etc/runcloud|/home/clp)\Z"
    r"|\Aid -u\Z"
    r"|\Asudo -n (-l )?/usr/bin/sh -c 'id -u'\Z"
    rf"|\Asudo -n (-l )?/usr/bin/sh -c {re.escape(_ROOT_LISTENER_READ)}\Z"
    # The target-stack proxy inventory (sites/observation.py), read as root directly or
    # through the sudo authorization and execution pair.
    rf"|\A{re.escape(PROXY_INVENTORY_COMMAND)}\Z"
    rf"|\A{re.escape(_MEMBERSHIP_READ)}\Z"
    rf"|\Asudo -n (-l )?/usr/bin/sh -c {re.escape(shlex.quote(PROXY_INVENTORY_COMMAND))}\Z"
    r"|\Aapt --version\Z"
    r"|\Adpkg --version\Z"
    r"|\Asystemctl --version\Z"
    r"|\Agetent passwd\Z"
    r"|\Agetent group 30000\Z"
    r"|\Acommand -v (apt-get|dpkg-query|df|systemctl|ss|timedatectl|getent|id|curl|sha256sum|"
    r"tar|xz|flock|journalctl|systemd-analyze|readlink|stat|awk|sed|grep|"
    r"/usr/sbin/(useradd|groupadd|runuser))\Z"
    rf"|\A{re.escape(PROCESS_COMMAND)}\Z"
    r"|\Atimedatectl show -p NTPSynchronized --value\Z"
    r"|\Asystemctl is-active apt-daily\.service apt-daily-upgrade\.service"
    r" unattended-upgrades\.service\Z"
    r"|\Ass -Hlnpt '\( sport = :80 or sport = :443 \)'\Z"
    r"|\Anproc\Z"
    r"|\Adf -B1 --output=size,avail,target /\Z"
    rf"|\A{re.escape(PACKAGE_QUERY)}\Z"
    rf"|\A{re.escape(PACKAGE_NAMES_QUERY)}\Z"
    rf"|\A{re.escape(VALKEY_VERSION_QUERY)}\Z"
    r"|\Asystemctl show \S+\.(?:service|timer)(?: \S+\.(?:service|timer))*"
    r" -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState\Z"
    r"|\Als -1b /etc/postgresql\Z"
    r"|\Als -1bA /etc/postgresql/[0-9.]+\Z"
)


@dataclass
class FakeServer:
    """A managed server as seen through ``RemoteShell``, recording every command."""

    files: dict[str, str] = field(
        default_factory=lambda: {
            "/etc/os-release": UBUNTU,
            MEMINFO_PATH: _RECORDED[f"cat {MEMINFO_PATH}"].result.stdout,
            # Only the file's existence is checked; its contents are never read.
            cluster_conf("18", "main"): "",
        }
    )
    # Directory listings by path; a path that is listed exists, others do not.
    directories: dict[str, list[str]] = field(
        default_factory=lambda: {
            PG_DIR: ["18"],
            f"{PG_DIR}/18": ["main"],
            f"{PG_DIR}/18/main": ["postgresql.conf"],
        }
    )
    unreadable: set[str] = field(default_factory=set)
    # Directories the SSH user may list but not search, so entries inside cannot be seen.
    unsearchable: set[str] = field(default_factory=set)
    # Symbolic links whose target does not exist: ``test -L`` sees them, ``test -e`` does not.
    dead_links: set[str] = field(default_factory=set)
    # Symbolic links by path, with their targets as written; reads follow them.
    links: dict[str, str] = field(default_factory=dict)
    # Directories every supported server has, whatever else a test removes.
    base_directories: set[str] = field(
        default_factory=lambda: {"/etc", "/proc", "/usr", "/usr/lib", "/usr/local", "/home", "/www"}
    )
    # Answers computed from a command, such as a query naming several packages, checked
    # first; each returns ``None`` for commands it does not answer.
    answers: list[Callable[[str], ssh.CommandResult | None]] = field(default_factory=list)
    # Results for exact commands, checked before files.
    results: dict[str, ssh.CommandResult] = field(
        default_factory=lambda: {
            ARCH_COMMAND: ssh.CommandResult(0, _RECORDED[ARCH_COMMAND].result.stdout),
            CPU_COMMAND: ssh.CommandResult(0, _RECORDED[CPU_COMMAND].result.stdout),
            FILESYSTEM_COMMAND: ssh.CommandResult(0, _RECORDED[FILESYSTEM_COMMAND].result.stdout),
            PACKAGE_QUERY: ssh.CommandResult(0, DPKG_OUTPUT),
            UNIT_QUERY.format("nginx.service"): ssh.CommandResult(0, unit_report("nginx.service")),
            UNIT_QUERY.format("php8.5-fpm.service"): ssh.CommandResult(
                0, unit_report("php8.5-fpm.service")
            ),
            UNIT_QUERY.format("mariadb.service"): ssh.CommandResult(
                0, unit_report("mariadb.service")
            ),
            UNIT_QUERY.format(CLUSTER_UNITS): ssh.CommandResult(
                0, UMBRELLA_REPORT + "\n" + cluster_report("18", "main")
            ),
            UNIT_QUERY.format("certbot.timer"): ssh.CommandResult(
                0, unit_report("certbot.timer", active="active", sub="waiting")
            ),
        }
    )
    failure: str = ""
    # Only available during the current answer callback; stdin is never included in the
    # command transcript or retained after the fake answers it.
    current_stdin: bytes | None = None
    # Exit mid-task, as the worker does when an operator forces it to stop.
    interrupt: bool = False
    host_key: str = HOST_KEY
    targets: list[ConnectionTarget] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)

    def install_certbot(
        self, *, active: str = "active", sub: str = "waiting", file_state: str = "enabled"
    ) -> None:
        """Install the packaged Certbot, whose timer reports ``active`` (``sub``)."""
        self.results[PACKAGE_QUERY] = ssh.CommandResult(0, DPKG_OUTPUT)
        self.results[UNIT_QUERY.format("certbot.timer")] = ssh.CommandResult(
            0, unit_report("certbot.timer", active=active, sub=sub, file_state=file_state)
        )

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

    def run(self, command: str, stdin: bytes | None = None) -> ssh.CommandResult:
        """Answer a probe as a POSIX shell does (checked by test_fake_server.py)."""
        self.commands.append(command)
        self.current_stdin = stdin
        try:
            for answer in self.answers:
                answered = answer(command)
                if answered is not None:
                    return answered
        finally:
            self.current_stdin = None
        if (direct := self._direct(command)) is not None:
            return direct
        if command.startswith(("ls -1b ", "ls -1bA ")):
            return self._list(command)
        verb, _, path = command.rpartition(" ")
        linked = (path in self.dead_links or path in self.links) and not self._hidden(path)
        path = self._resolve(path)
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
            "test -L": linked,
        }
        if verb in answers:
            return ssh.CommandResult(0 if answers[verb] else 1, "")
        if exists and path in self.files and path not in self.unreadable:
            return ssh.CommandResult(0, self.files[path])
        return _FAILED

    def _list(self, command: str) -> ssh.CommandResult:
        options, _, path = command.partition(" ")[2].partition(" ")
        if not self._exists(path) or not self._is_directory(path) or path in self.unreadable:
            return ssh.CommandResult(2, "")
        # Without -A, ls omits names that start with ".".
        entries = [e for e in self._entries(path) if "A" in options or e[0] != "."]
        return ssh.CommandResult(0, "".join(f"{entry}\n" for entry in entries))

    def _direct(self, command: str) -> ssh.CommandResult | None:
        """A recorded result, or a host-standing or package-name read."""
        if command in self.results:
            return self.results[command]
        if (standing := self._standing_command(command)) is not None:
            return standing
        if command == PACKAGE_NAMES_QUERY:
            result = self.results.get(PACKAGE_QUERY, _FAILED)
            output = "".join(
                f"{parts[0]} {parts[-1]}\n"
                for line in result.stdout.splitlines()
                if len(parts := line.split()) in {2, 3}
            )
            status = 0 if result.exit_status in {0, 1} else result.exit_status
            return ssh.CommandResult(status, output, result.truncated)
        return None

    def _standing_command(self, command: str) -> ssh.CommandResult | None:
        if command == "getent group 30000":
            return ssh.CommandResult(2, "")
        if command == PROCESS_COMMAND:
            return ssh.CommandResult(0, "")
        answers = {
            "apt --version": "apt 3.2.0 (arm64)\n",
            "dpkg --version": "Debian 'dpkg' package management program version 1.23.0 (arm64).\n",
            "systemctl --version": "systemd 259 (259.1-0ubuntu1)\n",
            "id -u": "0\n",
            "systemctl is-active apt-daily.service apt-daily-upgrade.service "
            "unattended-upgrades.service": ("inactive\ninactive\ninactive\n"),
            "ss -Hlnpt '( sport = :80 or sport = :443 )'": "",
            "timedatectl show -p NTPSynchronized --value": "yes\n",
        }
        if command in answers:
            status = 3 if command.startswith("systemctl is-active") else 0
            return ssh.CommandResult(status, answers[command])
        if command == "getent passwd":
            return ssh.CommandResult(0, "")
        if command.startswith("command -v "):
            name = command.partition("command -v ")[2]
            return ssh.CommandResult(0, f"/usr/bin/{name}\n")
        return None

    def _resolve(self, path: str) -> str:
        """The path a chain of symbolic links leads to."""
        for _ in range(40):
            if path not in self.links or self._hidden(path):
                break
            path = posixpath.normpath(posixpath.join(posixpath.dirname(path), self.links[path]))
        return path

    def _described(self) -> tuple[str, ...]:
        return (
            *self.files,
            *self.directories,
            *self.unreadable,
            *self.dead_links,
            *self.links,
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
        if path in self.links:
            return self._exists(self._resolve(path))
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
    # The worker installs its own signal handlers; restore the test runner's afterwards.
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        call_command("db_worker", batch=True, startup_delay=False, interval=0, verbosity=0)
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


def current(server: Server) -> Snapshot:
    snapshot = current_snapshot(server)
    if snapshot is None:
        raise AssertionError(f"{server} has no snapshot.")
    return snapshot


def observed[T](observation: Observation[T | None]) -> T:
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


AttemptStatus = RemoteOperation.Status
# Old enough for recovery to treat an active attempt as abandoned.
STALE = STALE_AFTER + timedelta(minutes=1)
_FINISHED = (AttemptStatus.SUCCEEDED, AttemptStatus.FAILED)


@overload
def record_attempt(
    target: Server,
    status: AttemptStatus = AttemptStatus.QUEUED,
    *,
    age: timedelta = timedelta(),
    failure: str = "",
) -> DiscoveryAttempt: ...


@overload
def record_attempt[O: RemoteOperation](
    target: O,
    status: AttemptStatus = AttemptStatus.QUEUED,
    *,
    age: timedelta = timedelta(),
    failure: str = "",
) -> O: ...


def record_attempt(
    target: Server | RemoteOperation,
    status: AttemptStatus = AttemptStatus.QUEUED,
    *,
    age: timedelta = timedelta(),
    failure: str = "",
) -> RemoteOperation:
    """Record an operation that reached ``status`` ``age`` ago, and return it as stored.

    A server gets a new discovery attempt without a worker task, recorded ``age`` ago. An
    existing operation of any kind, such as an attempt ``request_discovery`` queued with
    its task, keeps the time it was recorded unless it is queued again. Running operations
    start ``age`` ago, finished ones finish then; a queued operation has neither time.
    """
    when = timezone.now() - age
    operation: RemoteOperation
    if isinstance(target, Server):
        operation = DiscoveryAttempt.objects.create(server=target, ssh_alias=target.ssh_alias)
        recorded = True
    else:
        operation = target
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
    RemoteOperation.objects.filter(pk=operation.pk).update(**changes)
    operation.refresh_from_db()
    return operation


def task_records(*attempts: RemoteOperation) -> DBTaskResultQuerySet:
    """The worker's task records for ``attempts``, or for every attempt when none is given.

    Tests read task records through the lifecycle module, which alone knows how the task
    backend stores an attempt's task.
    """
    if not attempts:
        return lifecycle._tasks()
    return lifecycle._tasks(attempt.pk for attempt in attempts)


def waiting_tasks(*attempts: RemoteOperation) -> int:
    return task_records(*attempts).filter(status=TaskResultStatus.READY).count()


def claim_task(attempt: RemoteOperation, *, age: timedelta = timedelta()) -> None:
    """Record that a worker claimed the attempt's task ``age`` ago and still holds it."""
    task_records(attempt).update(status=TaskResultStatus.RUNNING, started_at=timezone.now() - age)


class FakeServerMixin(SimpleTestCase):
    """A FakeServer for each test, which may only ever be read from."""

    remote: FakeServer

    @override
    def setUp(self) -> None:
        super().setUp()
        self.remote = FakeServer()
        self.addCleanup(self.assert_read_only)

    def assert_read_only(self) -> None:
        for command in self.remote.commands:
            self.assertRegex(command, READ_ONLY)


class CollectedSnapshotMixin(SimpleTestCase):
    """Assertions about one ``collect`` result, shared by the fake and replaying cases."""

    collected: CollectedSnapshot

    def component(self, name: str) -> WebStackComponentObservation:
        (observation,) = (
            candidate for candidate in self.collected.components if candidate.component == name
        )
        return observation

    def warned(self) -> list[tuple[str, str]]:
        """The last collection's warnings, as (observation, outcome) pairs in display order."""
        return [(item.label, item.outcome) for item in present(self.collected).warnings]

    def assert_statuses(
        self, collected: CollectedSnapshot, part: Literal["package", "service"], status: str
    ) -> None:
        """Assert every component's ``part`` observation has ``status``, in display order.

        A component whose packages are absent also skips its service read, so a service
        assertion covers only the components that have a package observation.
        """
        compared = [
            observation
            for observation in collected.components
            if part == "package" or observation.package.outcome != ObservationOutcome.ABSENT
        ]
        self.assertEqual(
            [
                (
                    observation.component,
                    (observation.package if part == "package" else observation.service).outcome,
                )
                for observation in compared
            ],
            [(observation.component, status) for observation in compared],
        )

    def assert_not_kept(self, *texts: str) -> None:
        kept = kept_text(self.collected)
        for text in texts:
            self.assertNotIn(text, kept)

    def assert_nothing_absent(self) -> None:
        """No installed component's observation is absent (Valkey may simply be uninstalled)."""
        outcomes = [
            observation.outcome
            for component in self.collected.components
            if component.component != WebStackComponent.VALKEY
            for observation in (component.package, component.service)
        ]
        self.assertNotIn(ObservationOutcome.ABSENT, outcomes)


class ObservationTestCase(FakeServerMixin, CollectedSnapshotMixin):
    """Observation rules, tested through ``collect`` without a database or the worker."""

    def collect(self) -> CollectedSnapshot:
        self.collected = collect(self.remote)
        return self.collected


class ReplayObservationTestCase(CollectedSnapshotMixin):
    """Observation rules, tested through ``collect`` replaying a recorded transcript.

    docs/quality.md#recorded-transcripts. The transcript alone answers every command; an
    answer a test needs to differ is an ``override`` of a recorded result, never an
    invented one. A test that exercises a failed file read sets ``filesystem`` to a
    described ``FakeServer``, which then answers the ``test``, ``cat`` and ``ls`` probes.
    """

    state: str = "pristine-26.04"
    overrides: dict[str, ssh.CommandResult]
    filesystem: FakeServer | None
    shell: ReplayShell

    @override
    def setUp(self) -> None:
        super().setUp()
        self.overrides = {}
        self.filesystem = None

    def override(self, command: str, result: ssh.CommandResult) -> None:
        self.overrides[command] = result

    def recorded(self, command: str) -> ssh.CommandResult:
        """The result the transcript kept for ``command``, as the server sent it."""
        return dict(load(self.state).commands)[command].result

    def described_files(self) -> dict[str, str]:
        """The recorded contents of the files every server has, for ``filesystem``."""
        return {
            OS_RELEASE_FILES[0]: self.recorded(f"cat {OS_RELEASE_FILES[0]}").stdout,
            MEMINFO_PATH: self.recorded(f"cat {MEMINFO_PATH}").stdout,
        }

    def collect(self) -> CollectedSnapshot:
        self.shell = ReplayShell(load(self.state), self.overrides, self.filesystem)
        self.addCleanup(self.assert_read_only)
        self.collected = collect(self.shell)
        return self.collected

    def assert_read_only(self) -> None:
        for command in self.shell.commands:
            self.assertRegex(command, READ_ONLY)


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
        self.sign_in_with("view_server", "add_server", "add_discoveryattempt")
        self.client.post("/servers/add/", {"name": name, "ssh_alias": alias})
        return Server.objects.get(name=name)

    def discover(self) -> CollectedSnapshot:
        """Keep the server page as ``self.page`` and the snapshot as ``self.snapshot``."""
        server = self.register()
        self.run_worker()
        self.page = self.client.get(f"/servers/{server.pk}/")
        self.snapshot = current(server)
        return self.snapshot.collected

    def assert_succeeded(self) -> None:
        attempt = DiscoveryAttempt.objects.filter(server=Server.objects.get()).latest(
            "queued_at", "pk"
        )
        self.assertEqual(attempt.status, DiscoveryAttempt.Status.SUCCEEDED)
