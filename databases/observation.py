"""Database-engine recognition and the native reads a change reviews and verifies.

docs/target-architecture.md#stack, ADR 0010 and ADR 0013. Recognition reuses the typed
component observation of `discovery/observations/components.py`: MariaDB and PostgreSQL are
already read there as a package (with its version) and a service unit, from the exact dpkg
query and `systemctl show` a fresh controller reconstructs. Nothing in passive discovery
reads the engine's catalogs or executes a database client; those privileged reads belong to
a change's preparation and verification (docs/ssh-connections.md).
"""

import re
from dataclasses import dataclass
from typing import Final

from discovery.models import WebStackComponent
from discovery.snapshot import (
    CollectedSnapshot,
    Package,
    ServiceUnit,
    WebStackComponentObservation,
)

# One engine per server (settled decision 1, #356).
MARIADB: Final = "mariadb"
POSTGRESQL: Final = "postgresql"
ENGINES: Final = (MARIADB, POSTGRESQL)
GIT_ROOT: Final = "git"


@dataclass(frozen=True)
class EngineSpec:
    """One engine's fixed native shape, from the phase specification."""

    engine: str
    label: str
    component: WebStackComponent
    # The package name whose installed version names the engine.
    versioned: str
    # The root a reviewed installation names.
    root: str
    units: tuple[str, ...]
    port: int
    socket: str
    process: str
    data: tuple[str, ...]
    config_root: str


def _postgres_units() -> tuple[str, ...]:
    from discovery.releases import RESOLUTE

    return ("postgresql.service", f"postgresql@{RESOLUTE.postgresql}-main.service")


def specs() -> dict[str, EngineSpec]:
    from discovery.releases import RESOLUTE

    return {
        MARIADB: EngineSpec(
            MARIADB,
            "MariaDB",
            WebStackComponent.MARIADB,
            "mariadb-server",
            "mariadb-server",
            ("mariadb.service",),
            3306,
            "/run/mysqld/mysqld.sock",
            "mariadbd",
            ("/var/lib/mysql",),
            "/etc/mysql",
        ),
        POSTGRESQL: EngineSpec(
            POSTGRESQL,
            "PostgreSQL",
            WebStackComponent.POSTGRESQL,
            f"postgresql-{RESOLUTE.postgresql}",
            "postgresql",
            _postgres_units(),
            5432,
            "/var/run/postgresql/.s.PGSQL.5432",
            "postgres",
            (f"/var/lib/postgresql/{RESOLUTE.postgresql}/main",),
            "/etc/postgresql",
        ),
    }


@dataclass(frozen=True)
class EngineObservation:
    """One engine's reconstructed state, or the deviations that put it outside the profile."""

    engine: str
    label: str
    version: str
    packages: tuple[Package, ...]
    units: tuple[ServiceUnit, ...]
    managed: bool
    deviations: tuple[str, ...]

    @property
    def present(self) -> bool:
        return bool(self.packages)


def _component(
    collected: CollectedSnapshot, component: WebStackComponent
) -> WebStackComponentObservation | None:
    return next((item for item in collected.components if item.component == component), None)


def observation_of(collected: CollectedSnapshot, engine: str) -> EngineObservation | None:
    spec = specs().get(engine)
    if spec is None:
        return None
    observed: WebStackComponentObservation | None = _component(collected, spec.component)
    if observed is None or not observed.package.value:
        return None
    version = next(
        (package.version for package in observed.package.value if package.name == spec.versioned),
        "",
    )
    return EngineObservation(
        engine,
        spec.label,
        version,
        observed.package.value,
        observed.service.value,
        observed.managed,
        observed.deviations,
    )


def installed_engines(collected: CollectedSnapshot) -> tuple[EngineObservation, ...]:
    return tuple(
        observation
        for engine in ENGINES
        if (observation := observation_of(collected, engine)) is not None and observation.present
    )


def outside_supported_engines(collected: CollectedSnapshot) -> tuple[str, ...]:
    """Why the server's installed engines are outside supported settings for changes."""
    reasons: list[str] = []
    installed = installed_engines(collected)
    if len(installed) > 1:
        names = " and ".join(engine.label for engine in installed)
        reasons.append(
            f"This server already runs {names}. Barectl manages one database engine per "
            "server; remove an engine through ordinary administration, then prepare again."
        )
    for engine in installed:
        if not engine.managed:
            reasons.extend(engine.deviations)
    return tuple(reasons)


def digest_command(engine: str) -> str:
    """The precondition digest the review records and the native body recomputes.

    It covers dpkg's status and automatic marks, APT's Release files and downloaded index
    names, sizes and modification times, the engine's units, the configuration tree and the
    addresses listening on its port or at its socket. A root read computes it at review and
    again under the mutation lock, so a change between review and apply refuses as drift.
    """
    spec = specs()[engine]
    units = " ".join(spec.units)
    parts = [
        "sha256sum /var/lib/dpkg/status /var/lib/apt/extended_states",
        (
            "find /var/lib/apt/lists -maxdepth 1 -type f -name '*_InRelease' "
            "-exec sha256sum -- {} + | LC_ALL=C sort"
        ),
        (
            "find /var/lib/apt/lists -maxdepth 1 -type f ! -name lock "
            "-printf '%f %s %T@\\n' | LC_ALL=C sort"
        ),
        f"systemctl show -p Id -p LoadState -p ActiveState -p UnitFileState {units}",
        f"find {spec.config_root} -xdev -printf '%y %p %l\\n' | LC_ALL=C sort",
        (f"find {spec.config_root} -xdev -type f -exec sha256sum -- {{}} + | LC_ALL=C sort"),
        f"ss -Hltn 'sport = :{spec.port}' | awk '{{print $4}}' | LC_ALL=C sort",
        f"ss -Hlx src {spec.socket} | awk '{{print $5}}' | LC_ALL=C sort",
        "stat -c '%F %U %n' " + " ".join(spec.data),
    ]
    return "{ " + "; ".join(parts) + "; } 2>/dev/null | sha256sum"


# The hardening the phase specification sets: MariaDB listens on its socket only, with no
# anonymous users and no test database. PostgreSQL keeps the distribution's local peer
# authentication and its loopback-only listener, so it needs no file change.
MARIADB_CONFIG_PATH: Final = "/etc/mysql/mariadb.conf.d/60-barectl.cnf"
MARIADB_CONFIG: Final = "[mysqld]\nskip-networking\n"
MARIADB_SQL: Final = (
    "DELETE FROM mysql.global_priv WHERE User = ''; DROP DATABASE IF EXISTS test; FLUSH PRIVILEGES;"
)


def hardening_steps(engine: str) -> tuple[str, ...]:
    """The reviewed hardening steps, as the review page words them."""
    if engine == MARIADB:
        return (
            (
                f"Write {MARIADB_CONFIG_PATH} (root:root, 0644) so MariaDB listens on its "
                "local socket only."
            ),
            "Restart mariadb.service.",
            (
                "As root through the socket, remove every anonymous account and drop the test "
                "database."
            ),
        )
    return (
        "Keep the distribution's pg_hba.conf: local peer authentication and loopback only.",
        "The running server must listen on 127.0.0.1 and ::1 (or localhost) only.",
    )


def usage_command(engine: str) -> str | None:
    """The privileged read of the databases the engine holds, or ``None`` without a client.

    Barectl owns the site-database convention of ADR 0010 but does not adopt catalogs; the
    read lists only the count and the names that follow the convention, never a table.
    """
    spec = specs()[engine]
    if engine == MARIADB:
        # A fixed catalog read; the only interpolation is the engine's own socket path.
        return (
            f"/usr/bin/mariadb --no-defaults --protocol=socket --socket={spec.socket} "  # noqa: S608
            '--user=root -N -B -e "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA"'
        )
    return (
        "/usr/bin/su - postgres -c \"/usr/bin/psql -X -A -t -c 'SELECT datname FROM pg_database'\""
    )


SYSTEM_SCHEMAS: Final = frozenset({"mysql", "information_schema", "performance_schema", "sys"})
SYSTEM_DATABASES: Final = frozenset({"postgres", "template0", "template1"})


def parse_usage(engine: str, text: str) -> tuple[str, ...]:
    """The engine-owned databases the read listed, excluding the engine's own."""
    system = SYSTEM_SCHEMAS if engine == MARIADB else SYSTEM_DATABASES
    return tuple(
        sorted(
            name
            for name in text.splitlines()
            if name and name not in system and re.fullmatch(r"[A-Za-z0-9_$.-]{1,63}", name)
        )
    )


# The native body's fixed steps, generated from the same specs and constants the review
# reads, so the body's digest and hardening cannot drift from the review's wording.
def body_functions() -> str:
    spec = specs()
    digest = "\n".join(f"  {engine})\n    {digest_command(engine)}\n    ;;" for engine in ENGINES)
    units = spec[MARIADB]
    mariadb_config = MARIADB_CONFIG.replace("'", "'\\''")
    return (
        f"engine_main_unit() {{\n"
        f'  case "$1" in\n'
        f"  {MARIADB}) echo {units.units[0]} ;;\n"
        f"  {POSTGRESQL}) echo {spec[POSTGRESQL].units[0]} ;;\n"
        f"  esac\n"
        f"}}\n"
        f"engine_digest() {{\n"
        f'  case "$1" in\n'
        f"{digest}\n"
        f"  esac\n"
        f"}}\n"
        f"engine_harden() {{\n"
        f'  case "$1" in\n'
        f"  {MARIADB})\n"
        f"    [ ! -L {MARIADB_CONFIG_PATH} ] || return 1\n"
        f"    printf '%s' '{mariadb_config}' > {MARIADB_CONFIG_PATH}\n"
        f"    chmod 0644 {MARIADB_CONFIG_PATH}\n"
        f"    systemctl restart mariadb.service\n"
        f"    {_mariadb_sql()}\n"
        f"    ;;\n"
        f"  {POSTGRESQL})\n    :\n    ;;\n"
        f"  esac\n"
        f"}}\n"
        f"wait_socket() {{\n"
        f"  i=0\n"
        f"  while [ $i -lt 100 ]; do\n"
        f'    [ -n "$(ss -Hlx src "$1")" ] && return 0\n'
        f"    sleep 0.1\n"
        f"    i=$((i + 1))\n"
        f"  done\n"
        f"  return 1\n"
        f"}}\n"
        f"wait_listener() {{\n"
        f"  i=0\n"
        f"  while [ $i -lt 100 ]; do\n"
        f'    [ -n "$(ss -Hltn "sport = $1")" ] && return 0\n'
        f"    sleep 0.1\n"
        f"    i=$((i + 1))\n"
        f"  done\n"
        f"  return 1\n"
        f"}}\n"
        f"engine_start() {{\n"
        f'  case "$1" in\n'
        f"  {MARIADB})\n"
        f"    systemctl enable mariadb.service\n"
        f"    systemctl start mariadb.service\n"
        f"    wait_socket {units.socket}\n"
        f"    ;;\n"
        f"  {POSTGRESQL})\n"
        f"    systemctl enable postgresql.service\n"
        f"    systemctl start {spec[POSTGRESQL].units[1]}\n"
        f"    wait_listener :{spec[POSTGRESQL].port}\n"
        f"    ;;\n"
        f"  esac\n"
        f"}}\n"
        f"engine_verify() {{\n"
        f'  case "$1" in\n'
        f"  {MARIADB})\n"
        f'    [ -n "$(ss -Hlx src {units.socket})" ] || return 1\n'
        f"    [ -z \"$(ss -Hltn 'sport = :{units.port}')\" ] || return 1\n"
        f'    [ "$({_mariadb_sql(read=True)})" = 0 ] || return 1\n'
        f'    [ "$({_mariadb_query(_MARIADB_TEST_QUERY)})" = 0 ] || return 1\n'
        f"    ;;\n"
        f"  {POSTGRESQL})\n"
        f"    for unit in {spec[POSTGRESQL].units[0]} {spec[POSTGRESQL].units[1]}; do\n"
        f'      systemctl is-active --quiet "$unit" || return 1\n'
        f"    done\n"
        f"    [ -z \"$(ss -Hltn 'sport = :{spec[POSTGRESQL].port}' "
        f"| awk '$4 !~ /(127\\.0\\.0\\.1|\\[::1\\]):{spec[POSTGRESQL].port}/')\" ] || return 1\n"
        f"    ;;\n"
        f"  esac\n"
        f"}}\n"
    )


_MARIADB_TEST_QUERY: Final = (
    "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = 'test'"
)


def _mariadb_query(sql: str) -> str:
    spec = specs()[MARIADB]
    return (
        f"/usr/bin/mariadb --no-defaults --protocol=socket --socket={spec.socket} "
        f'--user=root -N -B -e "{sql}"'
    )


def _mariadb_sql(*, read: bool = False) -> str:
    if read:
        return _mariadb_query("SELECT COUNT(*) FROM mysql.global_priv WHERE User = ''")
    return _mariadb_query(MARIADB_SQL)


def verification_command(engine: str) -> str:
    """The fixed read that proves the reviewed hardening still holds on the server."""
    return body_functions() + f"\nengine_verify {engine}"


def removal_packages(current: EngineObservation) -> tuple[str, ...]:
    """The engine's observed packages, the exact set a reviewed removal names."""
    return tuple(package.name for package in current.packages)
