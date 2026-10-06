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
from typing import overload, override
from unittest import mock

from django.core.management import call_command
from django.tasks import TaskResultStatus
from django.test import SimpleTestCase
from django.utils import timezone
from django_tasks_db.models import DBTaskResultQuerySet

from operations import lifecycle
from operations.models import RemoteOperation
from servers.models import Server
from servers.ssh_config import ConnectionTarget
from servers.testing import ControllerConfigTestCase
from sites.convention import Stage, render_site

from . import ssh
from .models import (
    DatabaseEngine,
    DiscoveryAttempt,
    ObservationOutcome,
    SiteState,
    WebStackComponent,
)
from .observations import collect
from .observations.databases import (
    MARIADB_CLIENT,
    MARIADB_PRIVILEGES,
    MARIADB_STEPS,
    POSTGRESQL_CLIENT,
    POSTGRESQL_STEPS,
    ROOT_QUERY,
    Step,
    satisfied_mariadb_rows,
    satisfied_postgresql_rows,
    satisfied_postgresql_schema,
)
from .presentation import present
from .services import STALE_AFTER
from .snapshot import (
    CollectedSnapshot,
    FilesystemSize,
    Observation,
    ObservedDatabase,
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
# Output shapes recorded from Ubuntu 24.04 (docs/ssh-connections.md#component-observations).
PACKAGE_QUERY = (
    "dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\\n' 'nginx' 'php*-fpm' "
    "'mariadb-server*' 'postgresql' 'postgresql-[0-9]*' 'certbot'"
)
UNIT_QUERY = "systemctl show {} -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState"
DPKG_OUTPUT = """\
certbot 2.9.0-1ubuntu1 ii
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
AVAILABLE_DIR = "/etc/nginx/sites-available"
PHP_DIR = "/etc/php"
NGINX_CONF = "/etc/nginx/nginx.conf"
# The documented site reconstruction reads (docs/ssh-connections.md#site-observations).
STAT_FORMAT = "%n %f %u %U %g %G %h"
TLS_DEFAULT = "/etc/nginx/conf.d/tls-default-reject.conf"
SITE_PATHS = (
    r"/etc/nginx/sites-(enabled|available)/[a-z0-9]+\.conf"
    r"|/var/www/[a-z0-9]+(/public|/private|/\.ssh)?"
    r"|/etc/php/[0-9.]+/fpm/pool\.d/[a-z0-9]+\.conf|/run/php/s[a-z0-9]+\.sock"
    r"|/var/lib/letsencrypt/[a-z0-9]+"
    # The directories above them.
    r"|/var/www|/etc/nginx|/etc/nginx/sites-(enabled|available)|/etc/php/[0-9.]+/fpm/pool\.d"
    r"|/run/php|/var/lib/letsencrypt"
)
ACCOUNT_IDS = {"root": 0, "www-data": 33}
# The stock default site's server block, as Ubuntu's nginx-common installs it, abridged.
STOCK_DEFAULT_SITE = """\
server {
\tlisten 80 default_server;
\tlisten [::]:80 default_server;
\troot /var/www/html;
\tindex index.html index.htm index.nginx-debian.html;
\tserver_name _;
\tlocation / {
\t\ttry_files $uri $uri/ =404;
\t}
}
"""
SITE_UID = 1001
_FAILED = ssh.CommandResult(1, "")
CERTIFICATE_READ = re.compile(
    r"openssl x509 -noout -subject -issuer -dates -serial -fingerprint -sha256 "
    r"-ext subjectAltName -in /etc/letsencrypt/live/([a-z0-9]+)/cert\.pem"
)
SERVED_READ = re.compile(
    r"timeout 5 openssl s_client -connect 127\.0\.0\.1:443 -servername (\S+) </dev/null "
    r"2>/dev/null \| openssl x509 -outform DER 2>/dev/null \| sha256sum"
)


def site_config(identifier: str, names: tuple[str, ...]) -> str:
    """A site's Nginx file exactly as docs/site-conventions.md specifies it."""
    return (
        "server {\n"
        "\tlisten 80;\n"
        "\tlisten [::]:80;\n"
        f"\tserver_name {' '.join(names)};\n"
        f"\troot /var/www/{identifier}/public;\n"
        "\tindex index.php index.html;\n"
        "\tautoindex off;\n"
        "\n"
        "\tlocation / {\n"
        "\t\ttry_files $uri $uri/ =404;\n"
        "\t}\n"
        "\n"
        "\tlocation ~ /\\. {\n"
        "\t\tdeny all;\n"
        "\t}\n"
        "\n"
        "\tlocation ~ \\.php$ {\n"
        "\t\ttry_files $uri =404;\n"
        "\t\tinclude fastcgi.conf;\n"
        '\t\tfastcgi_param HTTP_PROXY "";\n'
        f"\t\tfastcgi_pass unix:/run/php/s{identifier}.sock;\n"
        "\t}\n"
        "}\n"
    )


def pool_config(identifier: str) -> str:
    """A site's PHP-FPM pool exactly as docs/site-conventions.md specifies it."""
    return (
        f"[{identifier}]\n"
        f"user = s{identifier}\n"
        f"group = s{identifier}\n"
        f"listen = /run/php/s{identifier}.sock\n"
        "listen.owner = www-data\n"
        "listen.group = www-data\n"
        "listen.mode = 0600\n"
        "pm = ondemand\n"
        "pm.max_children = 5\n"
        "pm.process_idle_timeout = 10s\n"
        "clear_env = yes\n"
        "security.limit_extensions = .php\n"
    )


CERTIFICATE_DIR = "/etc/letsencrypt/live"
RENEWAL_DIR = "/etc/letsencrypt/renewal"
CERTIFICATE_FINGERPRINT = "a1" * 32


def certificate_output(
    names: tuple[str, ...],
    *,
    issuer: str = "C = US, O = Let's Encrypt, CN = R3",
    not_before: str = "Sep  1 00:00:00 2026 GMT",
    not_after: str = "Nov 30 23:59:59 2026 GMT",
    serial: str = "03A1B2C3D4",
    fingerprint: str = CERTIFICATE_FINGERPRINT,
) -> str:
    """One activated site's ``openssl x509`` output, as recorded from Ubuntu."""
    shown = ":".join(fingerprint[index : index + 2] for index in range(0, len(fingerprint), 2))
    names_extension = ", ".join(f"DNS:{name}" for name in names)
    return (
        f"subject=CN = {names[0] if names else ''}\n"
        f"issuer={issuer}\n"
        f"notBefore={not_before}\n"
        f"notAfter={not_after}\n"
        f"serial={serial}\n"
        f"sha256 Fingerprint={shown}\n"
        "X509v3 Subject Alternative Name: \n"
        f"    {names_extension}\n"
    )


def fpm_conf_path(version: str) -> str:
    return f"{PHP_DIR}/{version}/fpm/php-fpm.conf"


# The Ubuntu 24.04 postgresql package creates the "16/main" cluster, started through the
# postgresql.service umbrella unit (docs/ssh-connections.md#postgresql-clusters).
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
    sites=Observation(
        ObservationOutcome.OBSERVED,
        (SITE_DIR, AVAILABLE_DIR, "/etc/php/8.3/fpm/pool.d"),
        "",
        (
            ObservedSite(
                "alpha",
                ("alpha.test", "www.alpha.test"),
                "8.3",
                SiteAccount(1001, 1001, "/var/www/alpha", "/usr/sbin/nologin"),
                SiteState.MANAGED,
                ObservationOutcome.OBSERVED,
                database=ObservedDatabase(
                    DatabaseEngine.MARIADB,
                    ObservationOutcome.OBSERVED,
                    True,
                    principal="salpha@localhost",
                    database="salpha",
                    authentication="unix_socket",
                    privileges=f"{', '.join(MARIADB_PRIVILEGES)} on salpha.*",
                    character_set="utf8mb4",
                    collation="utf8mb4_unicode_ci",
                    source=("MariaDB catalog",),
                ),
            ),
            ObservedSite(
                "beta",
                ("beta.test",),
                "8.3",
                None,
                SiteState.CHANGED,
                ObservationOutcome.OBSERVED,
                file="/etc/nginx/sites-available/beta.conf",
                expected="server {\n}\n",
            ),
            ObservedSite(
                "",
                ("legacy.test",),
                "8.3",
                None,
                SiteState.NOT_FOLLOWING,
                ObservationOutcome.OBSERVED,
                file="/etc/nginx/sites-enabled/legacy",
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
    r"|\Asystemctl show \S+\.(?:service|timer)(?: \S+\.(?:service|timer))*"
    r" -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState\Z"
    r"|\Als -1b (/etc/nginx/sites-enabled|/etc/php(/[0-9.]+/fpm/pool\.d)?|/etc/postgresql)\Z"
    r"|\Als -1bA /etc/postgresql/[0-9.]+\Z"
    # Site reconstruction reads each site's convention paths, account and FastCGI file.
    r"|\Als -1b /etc/nginx/(sites-available|conf\.d)\Z"
    r"|\Acat (/etc/nginx/sites-available/[a-z0-9]+\.conf|/etc/login\.defs)\Z"
    rf"|\A(cat|test -[erxL]|stat -c {re.escape(shlex.quote(STAT_FORMAT))} --) "
    rf"{re.escape(TLS_DEFAULT)}\Z"
    rf"|\Astat -c {re.escape(shlex.quote(STAT_FORMAT))} --( ({SITE_PATHS}))+\Z"
    rf"|\A(test -[erxL]|readlink) ({SITE_PATHS})\Z"
    r"|\Atest -[erx] (/|/var(/www)?|/run(/php)?|/etc/nginx/(sites-available|conf\.d))\Z"
    r"|\Atest -[erx] (/etc/login\.defs|/etc/shadow)\Z"
    r"|\Agetent (passwd|group) s[a-z0-9]+\Z"
    r"|\Agetent shadow s[a-z0-9]+ \| cut -d: -f2 \| cut -c1\Z"
    r"|\Aid -G s[a-z0-9]+\Z"
    # Database catalogs, read with fixed SELECT statements.
    rf"|\A{re.escape(ROOT_QUERY)}\Z"
    rf"|\A{re.escape(MARIADB_CLIENT)} 'SELECT [^;]+(;SELECT [^;]+)*'\Z"
    rf"|\A{re.escape(POSTGRESQL_CLIENT)} -d s?[a-z0-9]+ -c 'SELECT [^;]+(;SELECT [^;]+)*'\Z"
    # Activated sites' public certificate facts, and the certificate served over 127.0.0.1.
    r"|\Aopenssl x509 -noout -subject -issuer -dates -serial -fingerprint -sha256"
    r" -ext subjectAltName -in /etc/letsencrypt/live/[a-z0-9]+/cert\.pem\Z"
    r"|\Atimeout 5 openssl s_client -connect 127\.0\.0\.1:443 -servername [a-z0-9.-]+"
    r" </dev/null 2>/dev/null \| openssl x509 -outform DER 2>/dev/null \| sha256sum\Z"
    r"|\Atest -[erxL]"
    r" /etc/letsencrypt(/live(/[a-z0-9]+(/cert\.pem)?)?|/renewal(/[a-z0-9]+\.conf)?)?\Z"
)


# Database catalogs --------------------------------------------------------------------
# The rows each engine reports for a binding the convention creates, as recorded in
# docs/v0.3-qualification.md#site-database-observations.

HBA_FILE = "/etc/postgresql/16/main/pg_hba.conf"
POSTGRESQL_SERVER = f"V|160015|/var/lib/postgresql/16/main|{HBA_FILE}|t\n"
POSTGRESQL_HBA = f"""\
H|1|{HBA_FILE}|118|local|{{all}}|{{postgres}}|peer|f|f
H|2|{HBA_FILE}|123|local|{{all}}|{{all}}|peer|f|f
H|3|{HBA_FILE}|125|host|{{all}}|{{all}}|scram-sha-256|f|f
H|4|{HBA_FILE}|127|host|{{all}}|{{all}}|scram-sha-256|f|f
H|5|{HBA_FILE}|130|local|{{replication}}|{{all}}|peer|f|f
H|6|{HBA_FILE}|131|host|{{replication}}|{{all}}|scram-sha-256|f|f
H|7|{HBA_FILE}|132|host|{{replication}}|{{all}}|scram-sha-256|f|f
"""


def mariadb_rows(name: str, steps: tuple[Step, ...] = MARIADB_STEPS) -> str:
    """The catalog rows of a MariaDB binding whose ``steps`` took effect."""
    return satisfied_mariadb_rows(name, steps)


def postgresql_rows(name: str, steps: tuple[Step, ...] = POSTGRESQL_STEPS) -> str:
    """The catalog rows of a PostgreSQL binding whose ``steps`` took effect."""
    return satisfied_postgresql_rows(name, steps)


def schema_row(steps: tuple[Step, ...] = POSTGRESQL_STEPS) -> str:
    return satisfied_postgresql_schema(steps)


@dataclass
class Catalogs:
    """The database engines' catalogs, answering the fixed catalog reads."""

    # Rows by principal name, as ``mariadb_rows`` and ``postgresql_rows`` give them.
    mariadb: dict[str, str] = field(default_factory=dict)
    postgresql: dict[str, str] = field(default_factory=dict)
    # The public schema row read in each site database, by name; None when it cannot be read.
    schemas: dict[str, str | None] = field(default_factory=dict)
    plugin: str = "ACTIVE"
    server: str = POSTGRESQL_SERVER
    hba: str = POSTGRESQL_HBA
    # Engines whose client fails, as when root cannot authenticate.
    failing: set[str] = field(default_factory=set)

    def answer(self, command: str) -> ssh.CommandResult | None:
        if command.startswith(f"{MARIADB_CLIENT} "):
            if "mariadb" in self.failing:
                return ssh.CommandResult(1, "")
            listed = shlex.split(command)[-1].partition("User IN (")[2].partition(")")[0]
            names = re.findall(r"'(s[a-z0-9]+)'", listed)
            rows = "".join(self.mariadb.get(name, "") for name in names)
            return ssh.CommandResult(0, f"P\t{self.plugin}\n{rows}")
        if command.startswith(f"{POSTGRESQL_CLIENT} -d postgres "):
            if "postgresql" in self.failing:
                return ssh.CommandResult(2, "")
            sql = shlex.split(command)[-1]
            names = sql.partition("rolname=ANY('{")[2].partition("}")[0].split(",")
            rows = "".join(self.postgresql.get(name, "") for name in names)
            return ssh.CommandResult(0, f"{self.server}{rows}{self.hba}")
        match = re.fullmatch(rf"{re.escape(POSTGRESQL_CLIENT)} -d (s[a-z0-9]+) -c .*", command)
        if match:
            schema = self.schemas.get(match[1], schema_row())
            return ssh.CommandResult(2, "") if schema is None else ssh.CommandResult(0, schema)
        return None


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
            AVAILABLE_DIR: [],
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
    # Symbolic links by path, with their targets as written; reads follow them.
    links: dict[str, str] = field(default_factory=dict)
    sockets: set[str] = field(default_factory=set)
    # The openssl x509 output of each site's on-disk certificate, by identifier.
    certificates: dict[str, str] = field(default_factory=dict)
    # The SHA-256 fingerprint served over 127.0.0.1:443 for each name.
    served: dict[str, str] = field(default_factory=dict)
    # The identifiers whose /etc/letsencrypt/renewal/<identifier>.conf exists.
    renewals: set[str] = field(default_factory=set)
    # Owner, group and permission bits by path, for ``stat``. Anything else is root's, with
    # the permissions of a file, directory, link or socket created by root.
    ownership: dict[str, tuple[str, str, int]] = field(default_factory=dict)
    # Hard link counts by path, for ``stat``; anything else has one.
    hard_links: dict[str, int] = field(default_factory=dict)
    # Directories every supported server has, whatever else a test removes.
    base_directories: set[str] = field(default_factory=lambda: {"/etc", "/proc", "/usr/lib"})
    # Answers computed from a command, such as a query naming several packages, checked
    # first; each returns ``None`` for commands it does not answer.
    answers: list[Callable[[str], ssh.CommandResult | None]] = field(default_factory=list)
    # Results for exact commands, checked before files.
    results: dict[str, ssh.CommandResult] = field(
        default_factory=lambda: {
            "uname -m": ssh.CommandResult(0, "x86_64\n"),
            "nproc": ssh.CommandResult(0, "4\n"),
            # The SSH user is not root, so database catalogs are inaccessible.
            ROOT_QUERY: ssh.CommandResult(0, "1000\n"),
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
            UNIT_QUERY.format("certbot.timer"): ssh.CommandResult(
                0, unit_report("certbot.timer", active="active", sub="waiting")
            ),
        }
    )
    failure: str = ""
    # Exit mid-task, as the worker does when an operator forces it to stop.
    interrupt: bool = False
    host_key: str = HOST_KEY
    targets: list[ConnectionTarget] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    catalogs: Catalogs = field(default_factory=Catalogs)

    def __post_init__(self) -> None:
        self.answers.append(self.catalogs.answer)

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

    def run(self, command: str) -> ssh.CommandResult:
        """Answer a probe as a POSIX shell does (checked by test_fake_server.py)."""
        self.commands.append(command)
        for answer in self.answers:
            answered = answer(command)
            if answered is not None:
                return answered
        if (direct := self._direct(command)) is not None:
            return direct
        if command.startswith(("ls -1b ", "ls -1bA ")):
            options, _, path = command.partition(" ")[2].partition(" ")
            if not self._exists(path) or not self._is_directory(path) or path in self.unreadable:
                return ssh.CommandResult(2, "")
            # Without -A, ls omits names that start with ".".
            entries = [e for e in self._entries(path) if "A" in options or e[0] != "."]
            return ssh.CommandResult(0, "".join(f"{entry}\n" for entry in entries))
        if command.startswith("stat -c "):
            return self._stat(shlex.split(command)[4:])
        verb, _, path = command.rpartition(" ")
        if verb == "readlink":
            linked = path in self.links and not self._hidden(path)
            return ssh.CommandResult(0, f"{self.links[path]}\n") if linked else _FAILED
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

    def _direct(self, command: str) -> ssh.CommandResult | None:
        """A recorded result, or an openssl read of an activated site's certificates."""
        if command in self.results:
            return self.results[command]
        return self._openssl(command)

    def _openssl(self, command: str) -> ssh.CommandResult | None:
        """The activated site's on-disk certificate or its served TLS certificate."""
        certificate = CERTIFICATE_READ.fullmatch(command)
        if certificate:
            path = f"{CERTIFICATE_DIR}/{certificate[1]}/cert.pem"
            readable = (
                certificate[1] in self.certificates
                and path not in self.unreadable
                and not self._hidden(path)
            )
            return ssh.CommandResult(0, self.certificates[certificate[1]]) if readable else _FAILED
        served = SERVED_READ.fullmatch(command)
        if served:
            fingerprint = self.served.get(served[1], "")
            return ssh.CommandResult(0, f"{fingerprint}  -\n") if fingerprint else _FAILED
        return None

    def _resolve(self, path: str) -> str:
        """The path a chain of symbolic links leads to."""
        for _ in range(40):
            if path not in self.links or self._hidden(path):
                break
            path = posixpath.normpath(posixpath.join(posixpath.dirname(path), self.links[path]))
        return path

    def _stat(self, paths: list[str]) -> ssh.CommandResult:
        """``stat -c '%n %f %u %U %g %G %h'``: a line per path, describing a link, not its
        target.

        Like GNU stat, it exits 1 when any path cannot be described.
        """
        lines = [self._stat_line(path) for path in paths]
        output = "".join(line for line in lines if line)
        return ssh.CommandResult(0 if all(lines) else 1, output)

    def _stat_line(self, path: str) -> str:
        if self._hidden(path) or not (
            path in self.links or path in self.dead_links or self._exists(path)
        ):
            return ""
        if path in self.links or path in self.dead_links:
            kind, default = 0o120000, 0o777
        elif path in self.sockets:
            kind, default = 0o140000, 0o755
        elif self._is_directory(path):
            kind, default = 0o040000, 0o755
        else:
            kind, default = 0o100000, 0o644
        owner, group, mode = self.ownership.get(path, ("root", "root", default))
        ids = (
            f"{ACCOUNT_IDS.get(owner, SITE_UID)} {owner} {ACCOUNT_IDS.get(group, SITE_UID)} {group}"
        )
        return f"{path} {kind | mode:x} {ids} {self.hard_links.get(path, 1)}\n"

    def _renewal_files(self) -> tuple[str, ...]:
        return tuple(f"{RENEWAL_DIR}/{identifier}.conf" for identifier in self.renewals)

    def _described(self) -> tuple[str, ...]:
        return (
            *self.files,
            *self.directories,
            *self.unreadable,
            *self.dead_links,
            *self.links,
            *self.sockets,
            *self._renewal_files(),
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
        return (
            path in self.files
            or path in self.unreadable
            or path in self.sockets
            or path in self._renewal_files()
            or self._is_directory(path)
        )

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


class ObservationTestCase(FakeServerMixin):
    """Observation rules, tested through ``collect`` without a database or the worker."""

    collected: CollectedSnapshot

    def collect(self) -> CollectedSnapshot:
        self.collected = collect(self.remote)
        return self.collected

    def component(self, name: str) -> WebStackComponentObservation:
        (observation,) = (
            candidate for candidate in self.collected.components if candidate.component == name
        )
        return observation

    def warned(self) -> list[tuple[str, str]]:
        """The last collection's warnings, as (observation, outcome) pairs in display order."""
        return [(item.label, item.outcome) for item in present(self.collected).warnings]

    def assert_not_kept(self, *texts: str) -> None:
        kept = kept_text(self.collected)
        for text in texts:
            self.assertNotIn(text, kept)

    def assert_nothing_absent(self) -> None:
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


class SitePoolFixtures:
    """Nginx sites and PHP-FPM pools on the test's FakeServer."""

    remote: FakeServer

    def list_dir(self, path: str, entries: list[str]) -> None:
        self.remote.directories[path] = entries
        # The listing proves the directory exists and is readable to the SSH user.
        self.remote.unreadable.discard(path)

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

    def activate_site(
        self,
        identifier: str = "alpha",
        names: tuple[str, ...] = ("alpha.test", "www.alpha.test"),
        *,
        stage: Stage = Stage.HTTPS,
        fingerprint: str = CERTIFICATE_FINGERPRINT,
        served: dict[str, str] | None = None,
        renewal: bool = True,
    ) -> None:
        """Make the site's file an activated convention form with its certificate facts."""
        self.remote.files[f"{AVAILABLE_DIR}/{identifier}.conf"] = render_site(
            identifier, names, ipv6=True, stage=stage
        )
        webroot = f"/var/lib/letsencrypt/{identifier}"
        self.remote.directories.setdefault(webroot, [])
        self.remote.ownership[webroot] = ("root", "www-data", 0o750)
        self.remote.certificates[identifier] = certificate_output(names, fingerprint=fingerprint)
        for name in names:
            self.remote.served[name] = (served or {}).get(name, fingerprint)
        if renewal:
            self.remote.renewals.add(identifier)


def add_site(
    remote: FakeServer,
    identifier: str = "alpha",
    names: tuple[str, ...] = ("alpha.test", "www.alpha.test"),
    *,
    version: str = "8.3",
) -> None:
    """A site on ``remote`` that meets docs/site-conventions.md, as an administrator made it."""
    user = f"s{identifier}"
    file = f"{identifier}.conf"
    pool_dir = f"{PHP_DIR}/{version}/fpm/pool.d"
    boundary = f"/var/www/{identifier}"
    socket = f"/run/php/{user}.sock"
    remote.files[f"{AVAILABLE_DIR}/{file}"] = site_config(identifier, names)
    remote.files[f"{pool_dir}/{file}"] = pool_config(identifier)
    remote.links[f"{SITE_DIR}/{file}"] = f"{AVAILABLE_DIR}/{file}"
    for directory in (AVAILABLE_DIR, SITE_DIR, pool_dir):
        listing = remote.directories.setdefault(directory, [])
        if file not in listing:
            listing.append(file)
    for path in (f"{boundary}/public", f"{boundary}/private"):
        remote.directories.setdefault(path, [])
    remote.sockets.add(socket)
    remote.directories.setdefault("/run/php", [])
    remote.ownership |= {
        f"{boundary}/public": (user, "www-data", 0o750),
        f"{boundary}/private": (user, user, 0o700),
        socket: ("www-data", "www-data", 0o600),
        "/run/php": ("www-data", "www-data", 0o755),
    }
    if f"{SITE_DIR}/default" not in remote.files:
        remote.files[f"{SITE_DIR}/default"] = STOCK_DEFAULT_SITE
        remote.directories[SITE_DIR].append("default")
    remote.files.setdefault("/etc/login.defs", "UID_MIN\t\t\t 1000\nUID_MAX\t\t\t60000\n")
    # The SSH user can read the shadow database, as a member of the shadow group can.
    remote.files.setdefault("/etc/shadow", "")
    uid = str(SITE_UID)
    remote.results |= {
        f"getent passwd {user}": ssh.CommandResult(
            0, f"{user}:x:{uid}:{uid}::{boundary}:/usr/sbin/nologin\n"
        ),
        f"getent group {user}": ssh.CommandResult(0, f"{user}:x:{uid}:\n"),
        f"id -G {user}": ssh.CommandResult(0, f"{uid}\n"),
        f"getent shadow {user} | cut -d: -f2 | cut -c1": ssh.CommandResult(0, "!\n"),
    }
