"""Site database bindings from native catalogs (docs/ssh-connections.md#site-database-observations).

The catalog queries and their recognition are shared with database plans, which read
the same rows for one site with privilege.
"""

import json
import re
import shlex
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum

from ..models import DatabaseEngine, ObservationOutcome, SiteResource, WebStackComponent
from ..releases import SupportedRelease, supported
from ..snapshot import (
    Observation,
    ObservedDatabase,
    ObservedSite,
    OsRelease,
    ServiceUnit,
    WebStackComponentObservation,
)
from ..ssh import RemoteShell
from .probes import _Failed, _run

OBSERVED = ObservationOutcome.OBSERVED
ABSENT = ObservationOutcome.ABSENT
INACCESSIBLE = ObservationOutcome.INACCESSIBLE
UNSUPPORTED = ObservationOutcome.UNSUPPORTED

# docs/site-conventions.md#database-convention
PRINCIPAL = re.compile(r"s[a-z][a-z0-9]{2,23}")
MARIADB_SOCKET = "/run/mysqld/mysqld.sock"
MARIADB_UNIT = "mariadb.service"
MARIADB_CLIENT = (
    f"mariadb --no-defaults --protocol=socket --socket={MARIADB_SOCKET} --user=root -N -B -e"
)
MARIADB_PRIVILEGES = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "CREATE",
    "ALTER",
    "INDEX",
    "DROP",
    "REFERENCES",
    "CREATE TEMPORARY TABLES",
    "LOCK TABLES",
)
MARIADB_CHARACTER_SET = "utf8mb4"
MARIADB_COLLATION = "utf8mb4_unicode_ci"
POSTGRESQL_SOCKET_DIRECTORY = "/var/run/postgresql"
POSTGRESQL_PORT = 5432
POSTGRESQL_CLIENT = (
    "runuser -u postgres -- psql -X -A -t -q -v ON_ERROR_STOP=1 "
    f"-h {POSTGRESQL_SOCKET_DIRECTORY} -p {POSTGRESQL_PORT}"
)
POSTGRESQL_ENCODING = "UTF8"
# docs/site-conventions.md#database-convention: the libc locales a site database may use.
POSTGRESQL_LOCALES = frozenset({"C.UTF-8", "C.utf8", "en_US.UTF-8", "en_US.utf8"})
# docs/site-conventions.md#database-convention, as PostgreSQL 15 and later create the
# public schema: owned by pg_database_owner, with and without PUBLIC's usage.
PUBLIC_SCHEMA_OWNER = "pg_database_owner"
PUBLIC_SCHEMA_ACL = "{pg_database_owner=UC/pg_database_owner,=U/pg_database_owner}"
PUBLIC_SCHEMA_REVOKED = "{pg_database_owner=UC/pg_database_owner}"
ROOT_QUERY = "id -u"
INACCESSIBLE_CATALOGS = (
    "Database catalogs are readable only by the database administrators, and ordinary "
    "discovery never escalates. An account allowed to prepare database plans can run a "
    "privileged database inspection."
)


class Step(StrEnum):
    """The convention's statements, in the order a binding is created."""

    PRINCIPAL = "principal"
    DATABASE = "database"
    PRIVILEGES = "privileges"
    # PostgreSQL only: PUBLIC's rights on the database's public schema.
    SCHEMA = "schema"


MARIADB_STEPS = (Step.PRINCIPAL, Step.DATABASE, Step.PRIVILEGES)
POSTGRESQL_STEPS = (Step.PRINCIPAL, Step.DATABASE, Step.PRIVILEGES, Step.SCHEMA)


class BindingState(StrEnum):
    ABSENT = "absent"
    SATISFIED = "satisfied"
    # Some of the convention's statements took effect, in order, and nothing else exists.
    PARTIAL = "partial"
    CUSTOM = "custom"


@dataclass(frozen=True)
class Binding:
    """One engine's catalog evidence about one site's name, as the convention reads it."""

    engine: DatabaseEngine
    name: str
    state: BindingState
    # The statements whose effects exist exactly as the convention creates them.
    completed: tuple[Step, ...] = ()
    # What differs from the convention; empty unless the state is custom.
    problems: tuple[str, ...] = ()
    # Grants to other accounts that reach the name. They are not the site's binding, but a
    # binding they reach is not the convention's.
    exposures: tuple[str, ...] = ()
    principal: str = ""
    database: str = ""
    # The authentication method, and for PostgreSQL the pg_hba.conf line that selects it.
    authentication: str = ""
    authentication_line: int | None = None
    privileges: str = ""
    character_set: str = ""
    collation: str = ""
    owner: str = ""


def _names_literal(names: Sequence[str]) -> str:
    return ",".join(f"'{name}'" for name in names)


def _names_table(names: Sequence[str]) -> str:
    return " UNION ALL ".join(f"SELECT '{name}' n" for name in names)


def mariadb_catalog_sql(names: Sequence[str]) -> str:
    """Every row that grants, authenticates or stores anything under the names, each query
    ordered so an unchanged catalog reads the same.

    ``authentication_string`` is read only as whether it is empty, and ``auth_or``, which
    may hold further hashes, only as a key. Grants to other accounts that reach a name are
    read apart from the name's own (``F`` and the other ``G`` rows).
    """
    _check_names(names)
    listed, table = _names_literal(names), _names_table(names)
    grantees = " OR ".join(f"GRANTEE LIKE '''{name}''@%'" for name in names)
    limits = ",".join(
        f"COALESCE(JSON_VALUE(Priv,'$.{key}'),'')" for key in ("access", *_MARIADB_LIMITS)
    )
    own = " UNION ALL ".join(
        f"SELECT 'T',n.n,'{table_name}',COUNT(*) FROM mysql.{table_name} t JOIN ({table}) n "  # noqa: S608 - fixed tables, checked names
        f"ON t.{user}=n.n GROUP BY n.n"
        for table_name, user, _ in _MARIADB_REFERENCES
    )
    foreign = " UNION ALL ".join(
        f"SELECT 'F',n.n,'{table_name}',COUNT(*) FROM mysql.{table_name} t JOIN ({table}) n "  # noqa: S608 - fixed tables, checked names
        f"ON t.{target}=n.n AND t.{user}<>n.n GROUP BY n.n"
        for table_name, user, target in _MARIADB_REFERENCES
    )
    return (
        "SELECT 'P',PLUGIN_STATUS FROM information_schema.PLUGINS "  # noqa: S608 - checked names
        "WHERE PLUGIN_NAME='unix_socket';"
        "SELECT 'U',User,Host,COALESCE(JSON_VALUE(Priv,'$.plugin'),''),"
        "LENGTH(COALESCE(JSON_VALUE(Priv,'$.authentication_string'),''))>0,"
        f"{limits},JSON_KEYS(Priv) FROM mysql.global_priv WHERE User IN ({listed}) "
        "ORDER BY User,Host;"
        "SELECT 'S',SCHEMA_NAME,DEFAULT_CHARACTER_SET_NAME,DEFAULT_COLLATION_NAME "
        f"FROM information_schema.SCHEMATA WHERE SCHEMA_NAME IN ({listed}) ORDER BY 2;"
        f"SELECT 'G',n.n,d.User,d.Host,d.Db FROM mysql.db d JOIN ({table}) n "
        "ON d.User=n.n OR n.n LIKE d.Db ORDER BY 2,3,4,5;"
        "SELECT 'R',GRANTEE,TABLE_SCHEMA,PRIVILEGE_TYPE,IS_GRANTABLE "
        f"FROM information_schema.SCHEMA_PRIVILEGES WHERE {grantees} ORDER BY 2,3,4;"
        f"SELECT * FROM ({own}) o ORDER BY 2,3;"
        f"SELECT * FROM ({foreign}) f ORDER BY 2,3"
    )


def postgresql_catalog_sql(names: Sequence[str]) -> str:
    """Every row that authenticates, owns or grants anything under the names, each query
    ordered so an unchanged catalog reads the same.

    Of ``pg_hba.conf``'s rules only whether a rule has options or an error is read, since
    options may hold an LDAP or RADIUS secret.
    """
    _check_names(names)
    array = "'{" + ",".join(names) + "}'"
    return (
        "SELECT 'V',current_setting('server_version_num'),current_setting('data_directory'),"  # noqa: S608 - checked names
        "current_setting('hba_file'),"
        "pg_conf_load_time()>=(pg_stat_file(current_setting('hba_file'))).modification;"
        "SELECT 'R',rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,"
        "rolreplication,rolbypassrls,rolconnlimit,rolpassword IS NULL,rolvaliduntil IS NULL "
        f"FROM pg_authid WHERE rolname=ANY({array}) ORDER BY 2;"
        "SELECT 'M',r.rolname,count(*) FROM pg_auth_members m JOIN pg_authid r "
        f"ON r.oid IN (m.roleid,m.member,m.grantor) WHERE r.rolname=ANY({array}) GROUP BY 2 "
        "ORDER BY 2;"
        "SELECT 'D',datname,pg_get_userbyid(datdba),pg_encoding_to_char(encoding),"
        "datlocprovider,datcollate,datctype,coalesce(datacl::text,''),datistemplate,"
        f"datallowconn,datconnlimit FROM pg_database WHERE datname=ANY({array}) ORDER BY 2;"
        "SELECT 'S',r.rolname,count(*) FROM pg_db_role_setting s JOIN pg_authid r "
        f"ON r.oid=s.setrole WHERE r.rolname=ANY({array}) GROUP BY 2 ORDER BY 2;"
        "SELECT 'S',d.datname,count(*) FROM pg_db_role_setting s JOIN pg_database d "
        f"ON d.oid=s.setdatabase WHERE d.datname=ANY({array}) GROUP BY 2 ORDER BY 2;"
        "SELECT 'O',r.rolname,coalesce(d.datname,''),s.classid::regclass,s.deptype,count(*) "
        "FROM pg_shdepend s JOIN pg_authid r ON s.refclassid='pg_authid'::regclass "
        "AND s.refobjid=r.oid LEFT JOIN pg_database d ON d.oid=s.dbid "
        f"WHERE r.rolname=ANY({array}) GROUP BY 2,3,4,5 ORDER BY 2,3,4,5;"
        "SELECT 'H',coalesce(rule_number::text,''),coalesce(file_name,''),line_number,"
        "coalesce(type,''),coalesce(database::text,'{}'),coalesce(user_name::text,'{}'),"
        "coalesce(auth_method,''),options IS NOT NULL,error IS NOT NULL "
        "FROM pg_hba_file_rules ORDER BY rule_number NULLS FIRST,file_name,line_number"
    )


# Read in each site's own database, once it is known to be the site's.
POSTGRESQL_SCHEMA_SQL = (
    "SELECT 'N',pg_get_userbyid(nspowner),coalesce(nspacl::text,'') FROM pg_namespace "
    "WHERE nspname='public'"
)


def satisfied_mariadb_rows(name: str, steps: tuple[Step, ...] = ()) -> str:
    """The rows the catalog read reports for ``name`` once the convention's statements
    took effect, all unless ``steps`` names some, as the MariaDB client prints them
    (docs/v0.3-qualification.md#site-database-observations)."""
    _check_names((name,))
    steps = steps or MARIADB_STEPS
    keys = '["access", "version_id", "plugin", "authentication_string", "password_last_changed"]'
    rows = []
    if Step.PRINCIPAL in steps:
        rows.append(f"U\t{name}\tlocalhost\tunix_socket\t0\t0\t\t\t\t\t\t{keys}")
    if Step.DATABASE in steps:
        rows.append(f"S\t{name}\t{MARIADB_CHARACTER_SET}\t{MARIADB_COLLATION}")
    if Step.PRIVILEGES in steps:
        rows.append(f"G\t{name}\t{name}\tlocalhost\t{name}")
        rows += [
            f"R\t'{name}'@'localhost'\t{name}\t{privilege}\tNO"
            for privilege in sorted(MARIADB_PRIVILEGES)
        ]
    return "".join(f"{row}\n" for row in rows)


def mariadb_command(names: Sequence[str]) -> str:
    return f"{MARIADB_CLIENT} {shlex.quote(mariadb_catalog_sql(names))}"


def postgresql_command(names: Sequence[str]) -> str:
    return f"{POSTGRESQL_CLIENT} -d postgres -c {shlex.quote(postgresql_catalog_sql(names))}"


def postgresql_schema_command(name: str) -> str:
    _check_names((name,))
    return f"{POSTGRESQL_CLIENT} -d {name} -c {shlex.quote(POSTGRESQL_SCHEMA_SQL)}"


def _check_names(names: Sequence[str]) -> None:
    if not names or any(PRINCIPAL.fullmatch(name) is None for name in names):
        message = f"Not site principal names: {names!r}"
        raise ValueError(message)


_MARIADB_LIMITS = (
    "max_questions",
    "max_updates",
    "max_connections",
    "max_user_connections",
    "max_statement_time",
)
# Keys every account has, and resource limits, which are checked by value.
_MARIADB_KEYS = frozenset(
    {"access", "version_id", "plugin", "authentication_string", "password_last_changed"}
) | frozenset(_MARIADB_LIMITS)
# Each grant table, its grantee column and the column that names what is granted.
_MARIADB_REFERENCES = (
    ("tables_priv", "User", "Db"),
    ("columns_priv", "User", "Db"),
    ("procs_priv", "User", "Db"),
    ("roles_mapping", "User", "Role"),
    ("proxies_priv", "User", "Proxied_user"),
)


class CatalogFormatError(ValueError):
    pass


@dataclass(frozen=True)
class _MariaDBAccount:
    host: str
    plugin: str
    authenticated: bool
    access: str
    limits: tuple[str, ...]
    keys: frozenset[str]


@dataclass
class _MariaDBName:
    accounts: list[_MariaDBAccount] = field(default_factory=list)
    schema: tuple[str, str] | None = None
    # (host, database pattern) of the name's own mysql.db rows.
    rows: list[tuple[str, str]] = field(default_factory=list)
    # (user, host, database pattern) of other accounts' rows whose pattern matches the name.
    foreign_rows: list[tuple[str, str, str]] = field(default_factory=list)
    # The privileges of the name's own database row, and whether any is grantable.
    privileges: set[str] = field(default_factory=set)
    grantable: bool = False
    # Table, column, routine, role and proxy grants the name's account holds, and those of
    # other accounts on its database or to it, by table.
    references: dict[str, int] = field(default_factory=dict)
    foreign_references: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class MariaDBCatalog:
    plugin_active: bool
    names: dict[str, _MariaDBName]


def parse_mariadb(output: str, names: Sequence[str]) -> MariaDBCatalog:
    found = {name: _MariaDBName() for name in names}
    plugin = False
    for line in output.splitlines():
        fields = line.split("\t")
        match fields:
            case ["P", status]:
                plugin = status == "ACTIVE"
            case ["U", user, host, plugin_name, stored, access, *rest] if (
                user in found and len(rest) == len(_MARIADB_LIMITS) + 1
            ):
                found[user].accounts.append(
                    _MariaDBAccount(
                        host,
                        plugin_name,
                        stored == "1",
                        access,
                        tuple(rest[:-1]),
                        _json_keys(rest[-1]),
                    )
                )
            case ["S", name, character_set, collation] if name in found:
                found[name].schema = (character_set, collation)
            case ["G", name, user, host, pattern] if name in found:
                if user == name:
                    found[name].rows.append((host, pattern))
                else:
                    found[name].foreign_rows.append((user, host, pattern))
            case ["R", grantee, schema, privilege, grantable]:
                _schema_privilege(found, grantee, schema, privilege, grantable)
            case ["T", name, table_name, count] if name in found and count.isdigit():
                found[name].references[table_name] = int(count)
            case ["F", name, table_name, count] if name in found and count.isdigit():
                found[name].foreign_references[table_name] = int(count)
            case _:
                message = f"Unexpected MariaDB catalog line: {line[:200]!r}"
                raise CatalogFormatError(message)
    return MariaDBCatalog(plugin, found)


def _json_keys(text: str) -> frozenset[str]:
    try:
        keys = json.loads(text)
    except json.JSONDecodeError as error:
        message = "Unexpected MariaDB account keys"
        raise CatalogFormatError(message) from error
    if not isinstance(keys, list) or not all(isinstance(key, str) for key in keys):
        message = "Unexpected MariaDB account keys"
        raise CatalogFormatError(message)
    return frozenset(keys)


def _schema_privilege(
    found: dict[str, _MariaDBName], grantee: str, schema: str, privilege: str, grantable: str
) -> None:
    user, _, host = grantee.partition("@")
    name = user.strip("'")
    if name not in found:
        message = f"Unexpected MariaDB grantee: {grantee[:100]!r}"
        raise CatalogFormatError(message)
    # Other hosts' and other databases' rows are mysql.db rows the recognition refuses.
    if host == "'localhost'" and schema == name:
        found[name].privileges.add(privilege)
        found[name].grantable |= grantable != "NO"


@dataclass
class _Findings:
    """What recognition found so far: the statements in effect, and what differs."""

    completed: list[Step] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    def step(self, step: Step, problems: Sequence[str]) -> None:
        self.problems += problems
        if not problems:
            self.completed.append(step)


def recognize_mariadb(catalog: MariaDBCatalog, name: str) -> Binding:
    facts = catalog.names[name]
    engine = DatabaseEngine.MARIADB
    exposures = tuple(
        [
            f"{user}@{host} holds privileges on databases matching {pattern}, which include {name}."
            for user, host, pattern in facts.foreign_rows
        ]
        + [
            f"mysql.{table_name} holds {count} grants of other accounts on {name} or to it."
            for table_name, count in sorted(facts.foreign_references.items())
            if count
        ]
    )
    if not (facts.accounts or facts.schema or facts.rows or any(facts.references.values())):
        return Binding(engine, name, BindingState.ABSENT, exposures=exposures)
    found = _Findings()
    local = [account for account in facts.accounts if account.host == "localhost"]
    found.problems += [
        f"MariaDB also has the account {name}@{account.host}."
        for account in facts.accounts
        if account.host != "localhost"
    ]
    if local:
        found.step(Step.PRINCIPAL, _mariadb_account_problems(local[0], name, catalog.plugin_active))
    if facts.schema is not None:
        found.step(Step.DATABASE, _mariadb_schema_problems(facts.schema, name))
    own = ("localhost", name)
    found.problems += [
        f"{name}@{host} holds privileges on databases matching {pattern}."
        for host, pattern in facts.rows
        if (host, pattern) != own
    ]
    if own in facts.rows:
        found.step(Step.PRIVILEGES, _mariadb_grant_problems(facts, name))
    found.problems += [
        f"mysql.{table_name} holds {count} grants of {name}."
        for table_name, count in sorted(facts.references.items())
        if count
    ]
    listed = ", ".join(p for p in MARIADB_PRIVILEGES if p in facts.privileges)
    binding = Binding(
        engine,
        name,
        BindingState.CUSTOM,
        tuple(found.completed),
        tuple(found.problems),
        exposures,
        principal=f"{name}@localhost" if local else "",
        database=name if facts.schema else "",
        authentication=local[0].plugin if local else "",
        privileges=f"{listed} on {name}.*" if listed else "",
        character_set=facts.schema[0] if facts.schema else "",
        collation=facts.schema[1] if facts.schema else "",
    )
    return _state(binding, MARIADB_STEPS)


def _mariadb_schema_problems(schema: tuple[str, str], name: str) -> list[str]:
    if schema == (MARIADB_CHARACTER_SET, MARIADB_COLLATION):
        return []
    return [
        (
            f"Database {name} uses {schema[0]} with {schema[1]}, not {MARIADB_CHARACTER_SET} "
            f"with {MARIADB_COLLATION}."
        )
    ]


def _mariadb_grant_problems(facts: _MariaDBName, name: str) -> list[str]:
    if facts.privileges == set(MARIADB_PRIVILEGES) and not facts.grantable:
        return []
    held = ", ".join(sorted(facts.privileges)) or "no"
    option = ", with grant option" if facts.grantable else ""
    return [
        f"{name}@localhost holds {held} privileges on {name}{option}, not exactly the convention's."
    ]


def _mariadb_account_problems(account: _MariaDBAccount, name: str, active: bool) -> list[str]:
    problems: list[str] = []
    if account.plugin != "unix_socket" or "auth_or" in account.keys:
        problems.append(f"{name}@localhost does not authenticate by unix_socket alone.")
    elif not active:
        problems.append("The unix_socket authentication plugin is not active.")
    if account.authenticated:
        problems.append(f"{name}@localhost has an authentication string.")
    if account.access != "0":
        problems.append(f"{name}@localhost holds global privileges.")
    if any(value not in {"", "0", "0.000000"} for value in account.limits):
        problems.append(f"{name}@localhost has resource limits.")
    extra = sorted(account.keys - _MARIADB_KEYS)
    if extra:
        problems.append(f"{name}@localhost has account settings: {', '.join(extra)}.")
    return problems


def _state(binding: Binding, steps: tuple[Step, ...]) -> Binding:
    """Custom unless the convention's statements took effect in order and nothing else."""
    if binding.problems:
        return binding
    if binding.completed == steps:
        return replace(binding, state=BindingState.SATISFIED)
    if binding.completed and binding.completed == steps[: len(binding.completed)]:
        return replace(binding, state=BindingState.PARTIAL)
    present = ", ".join(step.value for step in binding.completed)
    verb = "exists" if len(binding.completed) == 1 else "exist"
    return replace(
        binding,
        problems=(
            (
                f"Of the convention's statements, only the {present} {verb}, without the "
                "ones before."
            ),
        ),
    )


@dataclass(frozen=True)
class _PostgreSQLRole:
    flags: tuple[str, ...]


@dataclass
class _PostgreSQLName:
    role: _PostgreSQLRole | None = None
    memberships: int = 0
    settings: int = 0
    database: tuple[str, ...] | None = None
    # (database or "" for shared objects, catalog, dependency type): count.
    dependencies: dict[tuple[str, str, str], int] = field(default_factory=dict)
    # The public schema's owner and ACL in the site's own database, once read.
    schema: tuple[str, str] | None = None
    # Why the public schema is not the convention's when it is missing or unreadable.
    schema_problem: str = ""


@dataclass(frozen=True)
class HbaRule:
    # None for a line with an error, which PostgreSQL does not load.
    rule: int | None
    file: str
    line: int
    type: str
    databases: tuple[str, ...]
    users: tuple[str, ...]
    method: str
    # Whether the rule has options or an error; their values are never read.
    options: bool
    error: bool


@dataclass(frozen=True)
class PostgreSQLCatalog:
    version: str
    data_directory: str
    hba_file: str
    # Whether the server loaded its configuration after pg_hba.conf last changed.
    hba_loaded: bool
    rules: tuple[HbaRule, ...]
    names: dict[str, _PostgreSQLName]


# rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication,
# rolbypassrls, rolconnlimit, password is null, valid-until is null.
_ROLE_FLAGS = ("f", "t", "f", "f", "t", "f", "f", "-1", "t", "t")
_ROLE_FLAG_NAMES = (
    "SUPERUSER",
    "NOINHERIT",
    "CREATEROLE",
    "CREATEDB",
    "NOLOGIN",
    "REPLICATION",
    "BYPASSRLS",
    "a connection limit",
    "a password",
    "an expiry",
)


def parse_postgresql(output: str, names: Sequence[str]) -> PostgreSQLCatalog:
    found = {name: _PostgreSQLName() for name in names}
    version = directory = hba_file = ""
    loaded = False
    rules: list[HbaRule] = []
    for line in output.splitlines():
        fields = line.split("|")
        match fields:
            case ["V", number, data, hba, current] if current in {"t", "f"}:
                version, directory, hba_file, loaded = number, data, hba, current == "t"
            case ["R", name, *flags] if name in found and len(flags) == len(_ROLE_FLAGS):
                found[name].role = _PostgreSQLRole(tuple(flags))
            case ["M", name, count] if name in found and count.isdigit():
                found[name].memberships = int(count)
            case ["D", name, *rest] if name in found and len(rest) == 9:
                found[name].database = tuple(rest)
            case ["S", name, count] if name in found and count.isdigit():
                found[name].settings += int(count)
            case ["O", name, database, catalog, kind, count] if name in found and count.isdigit():
                found[name].dependencies[database, catalog, kind] = int(count)
            case ["H", *_]:
                rules.append(_hba_rule(fields))
            case _:
                message = f"Unexpected PostgreSQL catalog line: {line[:200]!r}"
                raise CatalogFormatError(message)
    if not version:
        message = "The PostgreSQL catalog did not report its server."
        raise CatalogFormatError(message)
    return PostgreSQLCatalog(version, directory, hba_file, loaded, tuple(rules), found)


def _hba_rule(fields: list[str]) -> HbaRule:
    match fields:
        case ["H", rule, file, line, kind, databases, users, method, options, error] if (
            (rule.isdigit() or not rule) and line.isdigit() and {options, error} <= {"t", "f"}
        ):
            broken = error == "t" or not rule
            return HbaRule(
                int(rule) if rule else None,
                file,
                int(line),
                kind,
                () if broken else _array(databases),
                () if broken else _array(users),
                method,
                options == "t",
                broken,
            )
        case _:
            message = f"Unexpected pg_hba.conf rule: {'|'.join(fields)[:200]!r}"
            raise CatalogFormatError(message)


def parse_postgresql_schema(output: str) -> tuple[str, str] | None:
    """The public schema's owner and ACL, or None when the database has none."""
    match output.splitlines():
        case []:
            return None
        case [line] if len(fields := line.split("|")) == 3 and fields[0] == "N":
            return fields[1], fields[2]
        case _:
            message = "Unexpected public schema read."
            raise CatalogFormatError(message)


def _array(text: str) -> tuple[str, ...]:
    if not (text.startswith("{") and text.endswith("}")):
        message = f"Unexpected pg_hba.conf field: {text[:100]!r}"
        raise CatalogFormatError(message)
    return tuple(item for item in text[1:-1].split(",") if item)


def first_local_rule(rules: Iterable[HbaRule], name: str, hba_file: str) -> HbaRule | None:
    """The first pg_hba.conf rule a local connection as ``name`` to ``name`` meets.

    ``None`` when a rule has an error, or a rule up to it comes from a file included into
    ``hba_file`` or uses a form Barectl does not evaluate, such as a group or a regular
    expression.
    """
    for rule in rules:
        if rule.error or rule.file != hba_file:
            return None
        if rule.type != "local":
            continue
        databases = _matches(rule.databases, name, ("all", "sameuser", "samerole"))
        users = _matches(rule.users, name, ("all",))
        if databases is None or users is None:
            return None
        if databases and users:
            return rule
    return None


def _matches(items: tuple[str, ...], name: str, keywords: tuple[str, ...]) -> bool | None:
    matched = False
    for item in items:
        if item.startswith(("+", "@", "/", '"')):
            return None
        matched |= item == name or item in keywords
    return matched


def recognize_postgresql(catalog: PostgreSQLCatalog, name: str) -> Binding:
    facts = catalog.names[name]
    engine = DatabaseEngine.POSTGRESQL
    if facts.role is None and facts.database is None and not facts.settings:
        return Binding(engine, name, BindingState.ABSENT)
    found = _Findings()
    if facts.role is not None:
        found.step(Step.PRINCIPAL, _role_problems(facts.role, facts, name))
    if facts.settings:
        found.problems.append(f"{name} has settings stored with ALTER ROLE or ALTER DATABASE.")
    owner = collate = encoding = ""
    if facts.database is not None:
        owner, encoding, _, collate, *_ = facts.database
        _database_findings(facts.database, name, found)
    found.problems += _dependency_problems(facts, name)
    found.problems += _schema_problems(facts, name, found.completed)
    rule = None
    if facts.role is not None:
        rule = _authentication(catalog, name, found)
    privileges = [
        text
        for step, text in (
            (Step.PRIVILEGES, "PUBLIC's CONNECT and TEMPORARY revoked"),
            (Step.SCHEMA, "PUBLIC's rights on the public schema revoked"),
        )
        if step in found.completed
    ]
    binding = Binding(
        engine,
        name,
        BindingState.CUSTOM,
        tuple(found.completed),
        tuple(found.problems),
        principal=name if facts.role is not None else "",
        database=name if facts.database is not None else "",
        authentication=rule.method if rule else "",
        authentication_line=rule.line if rule else None,
        privileges="; ".join(privileges),
        character_set=encoding,
        collation=collate,
        owner=owner,
    )
    return _state(binding, POSTGRESQL_STEPS)


def _role_problems(role: _PostgreSQLRole, facts: _PostgreSQLName, name: str) -> list[str]:
    differing = [
        label
        for label, value, expected in zip(_ROLE_FLAG_NAMES, role.flags, _ROLE_FLAGS, strict=True)
        if value != expected
    ]
    problems = [f"Role {name} differs: {', '.join(differing)}."] if differing else []
    if facts.memberships:
        problems.append(f"Role {name} has {facts.memberships} role memberships or grants them.")
    return problems


def _database_differences(database: tuple[str, ...], name: str) -> list[str]:
    owner, encoding, provider, collate, ctype, _, template, allowed, limit = database
    differing = []
    if owner != name:
        differing.append(f"it is owned by {owner}")
    if encoding != POSTGRESQL_ENCODING or provider != "c":
        differing.append(f"it uses {encoding} with locale provider {provider}")
    if collate != ctype or collate not in POSTGRESQL_LOCALES:
        differing.append(f"its locale is {collate} and {ctype}")
    if (template, allowed, limit) != ("f", "t", "-1"):
        differing.append("it is a template, refuses connections or has a limit")
    return differing


def _database_findings(database: tuple[str, ...], name: str, found: _Findings) -> None:
    acl = database[5]
    differing = _database_differences(database, name)
    found.step(
        Step.DATABASE,
        [f"Database {name} differs: {'; '.join(differing)}."] if differing else [],
    )
    if differing:
        return
    if acl == f"{{{name}=CTc/{name}}}":
        found.completed.append(Step.PRIVILEGES)
    elif acl:
        found.problems.append(f"Database {name} grants {acl}.")


def _authentication(catalog: PostgreSQLCatalog, name: str, found: _Findings) -> HbaRule | None:
    if not catalog.hba_loaded:
        found.problems.append(
            "pg_hba.conf changed after the server last loaded it, so its rules may not be "
            "the ones in effect."
        )
        return None
    rule = first_local_rule(catalog.rules, name, catalog.hba_file)
    if rule is None:
        found.problems.append(
            f"Barectl cannot tell which pg_hba.conf rule a local connection as {name} meets."
        )
        return None
    if rule.method != "peer" or rule.options:
        options = " with options" if rule.options else ""
        found.problems.append(
            f"A local connection as {name} meets pg_hba.conf line {rule.line}, which uses "
            f"{rule.method}{options}, not peer."
        )
    return rule


def _dependency_problems(facts: _PostgreSQLName, name: str) -> list[str]:
    owned = facts.database is not None and facts.database[0] == name
    problems = []
    for (database, catalog, kind), count in sorted(facts.dependencies.items()):
        if database == name:
            continue
        if (database, catalog, kind, count) == ("", "pg_database", "o", 1) and owned:
            continue
        where = f"database {database}" if database else "shared catalogs"
        problems.append(f"Role {name} owns or is granted {count} objects in {where}.")
    return problems


def _schema_problems(facts: _PostgreSQLName, name: str, completed: list[Step]) -> list[str]:
    if facts.schema_problem:
        return [facts.schema_problem]
    if facts.schema is None:
        return []
    owner, acl = facts.schema
    if owner != PUBLIC_SCHEMA_OWNER:
        return [f"The public schema of {name} is owned by {owner}."]
    if acl == PUBLIC_SCHEMA_REVOKED:
        completed.append(Step.SCHEMA)
        return []
    if acl == PUBLIC_SCHEMA_ACL:
        return []
    return [f"The public schema of {name} grants {acl}."]


def needs_schema(catalog: PostgreSQLCatalog, name: str) -> bool:
    """Whether the site's database otherwise matches the convention, accepting connections,
    so its public schema is read."""
    database = catalog.names[name].database
    return database is not None and not _database_differences(database, name)


def with_schema(catalog: PostgreSQLCatalog, name: str, schema: tuple[str, str] | None) -> None:
    facts = catalog.names[name]
    facts.schema = schema
    if schema is None:
        facts.schema_problem = f"Database {name} has no public schema."


def schema_unread(catalog: PostgreSQLCatalog, name: str) -> None:
    catalog.names[name].schema_problem = f"Barectl could not read the public schema of {name}."


# Discovery ------------------------------------------------------------------------------


@dataclass(frozen=True)
class _EngineRead:
    """One engine's recognition of every site name, or why it could not be read."""

    engine: DatabaseEngine
    bindings: dict[str, Binding]
    outcome: ObservationOutcome
    source: tuple[str, ...]
    warning: str = ""


def collect_databases(
    shell: RemoteShell,
    os: Observation[OsRelease | None],
    components: tuple[WebStackComponentObservation, ...],
    sites: Observation[tuple[ObservedSite, ...]],
) -> Observation[tuple[ObservedSite, ...]]:
    """The sites, each with what the database catalogs hold under its name."""
    if not sites.value:
        return sites
    names = tuple(f"s{site.identifier}" for site in sites.value)
    by_component = {observed.component: observed for observed in components}
    release = supported(os.value.id, os.value.version_id) if os.observed and os.value else None
    root = _is_root(shell)
    reads = (
        _read_mariadb(shell, by_component[WebStackComponent.MARIADB], names, root),
        _read_postgresql(shell, by_component[WebStackComponent.POSTGRESQL], names, root, release),
    )
    return replace(
        sites,
        value=tuple(
            replace(site, database=_site_database(site, f"s{site.identifier}", reads))
            for site in sites.value
        ),
    )


def _is_root(shell: RemoteShell) -> _Failed | bool:
    output = _run(shell, ROOT_QUERY)
    if isinstance(output, _Failed):
        return output
    return output.strip() == "0"


def _installed(component: WebStackComponentObservation) -> ObservationOutcome:
    package = component.package
    if package.outcome == OBSERVED and not package.value:
        return ABSENT
    return package.outcome


def _running(component: WebStackComponentObservation, unit: str) -> bool:
    units: tuple[ServiceUnit, ...] = component.service.value
    return any(
        item.name == unit and item.active_state == "active" and item.sub_state == "running"
        for item in units
    )


def _unread(
    engine: DatabaseEngine,
    component: WebStackComponentObservation,
    unit: str,
    root: _Failed | bool,
) -> _EngineRead | None:
    installed = _installed(component)
    if installed != OBSERVED:
        warning = "" if installed == ABSENT else component.package.warning
        return _EngineRead(engine, {}, installed, component.package.source, warning)
    if isinstance(root, _Failed):
        return _EngineRead(engine, {}, root.status, (root.source,), root.warning)
    if not root:
        return _EngineRead(engine, {}, INACCESSIBLE, (ROOT_QUERY,), INACCESSIBLE_CATALOGS)
    if not _running(component, unit):
        return _EngineRead(
            engine,
            {},
            INACCESSIBLE,
            component.service.source,
            f"{unit} is not running, so Barectl could not read the {engine.label} catalog.",
        )
    return None


def _read_mariadb(
    shell: RemoteShell,
    component: WebStackComponentObservation,
    names: tuple[str, ...],
    root: _Failed | bool,
) -> _EngineRead:
    engine = DatabaseEngine.MARIADB
    unread = _unread(engine, component, MARIADB_UNIT, root)
    if unread is not None:
        return unread
    command = mariadb_command(names)
    source = (_MARIADB_SOURCE,)
    output = _run(
        shell,
        command,
        failed="root could not read the MariaDB catalog through its socket without a "
        "password, as the distribution's administration allows.",
    )
    if isinstance(output, _Failed):
        return _EngineRead(engine, {}, output.status, source, output.warning)
    try:
        catalog = parse_mariadb(output, names)
    except CatalogFormatError:
        return _EngineRead(engine, {}, UNSUPPORTED, source, _FORMAT.format(engine.label))
    bindings = {name: recognize_mariadb(catalog, name) for name in names}
    return _EngineRead(engine, bindings, OBSERVED, source)


def _read_postgresql(
    shell: RemoteShell,
    component: WebStackComponentObservation,
    names: tuple[str, ...],
    root: _Failed | bool,
    release: SupportedRelease | None,
) -> _EngineRead:
    engine = DatabaseEngine.POSTGRESQL
    if _installed(component) == ABSENT:
        return _EngineRead(engine, {}, ABSENT, component.package.source)
    if release is None:
        return _EngineRead(
            engine,
            {},
            UNSUPPORTED,
            (),
            "The server is not a supported release, so Barectl does not know which "
            "PostgreSQL cluster holds site databases.",
        )
    unit = f"postgresql@{release.postgresql}-main.service"
    unread = _unread(engine, component, unit, root)
    if unread is not None:
        return unread
    source = (_postgresql_source(release),)
    output = _run(
        shell,
        postgresql_command(names),
        failed=f"postgres could not read the catalog of PostgreSQL {release.postgresql} main "
        f"through {POSTGRESQL_SOCKET_DIRECTORY}.",
    )
    if isinstance(output, _Failed):
        return _EngineRead(engine, {}, output.status, source, output.warning)
    try:
        catalog = parse_postgresql(output, names)
    except CatalogFormatError:
        return _EngineRead(engine, {}, UNSUPPORTED, source, _FORMAT.format(engine.label))
    expected = f"/var/lib/postgresql/{release.postgresql}/main"
    if not catalog.version.startswith(release.postgresql) or catalog.data_directory != expected:
        return _EngineRead(
            engine,
            {},
            UNSUPPORTED,
            source,
            f"Port {POSTGRESQL_PORT} is not served by PostgreSQL {release.postgresql} main, "
            "the cluster that holds site databases.",
        )
    for name in names:
        if needs_schema(catalog, name):
            _read_schema(shell, catalog, name)
    bindings = {name: recognize_postgresql(catalog, name) for name in names}
    return _EngineRead(engine, bindings, OBSERVED, source)


def _read_schema(shell: RemoteShell, catalog: PostgreSQLCatalog, name: str) -> None:
    schema = _run(shell, postgresql_schema_command(name))
    try:
        if isinstance(schema, _Failed):
            raise CatalogFormatError(schema.warning)
        with_schema(catalog, name, parse_postgresql_schema(schema))
    except CatalogFormatError:
        schema_unread(catalog, name)


_FORMAT = "The {} catalog did not answer in a supported format."
_MARIADB_SOURCE = (
    "MariaDB catalog as root@localhost: mysql.global_priv, mysql.db, mysql.tables_priv, "
    "mysql.columns_priv, mysql.procs_priv, mysql.roles_mapping, mysql.proxies_priv and "
    "information_schema"
)


def _postgresql_source(release: SupportedRelease) -> str:
    return (
        f"PostgreSQL {release.postgresql} main catalog as postgres: pg_authid, "
        "pg_auth_members, pg_database, pg_db_role_setting, pg_shdepend, pg_hba_file_rules "
        "and each site database's public schema"
    )


def _site_database(
    site: ObservedSite, name: str, reads: tuple[_EngineRead, ...]
) -> ObservedDatabase:
    source = tuple(dict.fromkeys(item for read in reads for item in read.source))
    found = [
        read.bindings[name]
        for read in reads
        if name in read.bindings and read.bindings[name].state != BindingState.ABSENT
    ]
    unread = [read for read in reads if read.outcome not in {OBSERVED, ABSENT}]
    exposures = [
        exposure
        for read in reads
        if name in read.bindings
        for exposure in read.bindings[name].exposures
    ]
    if len(found) > 1:
        return ObservedDatabase(
            None,
            UNSUPPORTED,
            False,
            source=source,
            warning=f"Both MariaDB and PostgreSQL hold {name}; a site has at most one "
            "database binding.",
        )
    if not found:
        if unread:
            outcome = (
                INACCESSIBLE if all(r.outcome == INACCESSIBLE for r in unread) else UNSUPPORTED
            )
            warnings = [*dict.fromkeys(read.warning for read in unread if read.warning)]
            return ObservedDatabase(
                None, outcome, False, source=source, warning=" ".join([*warnings, *exposures])
            )
        return ObservedDatabase(
            None,
            ABSENT,
            False,
            source=source,
            warning=" ".join(
                [f"No database engine holds a principal or database named {name}.", *exposures]
            ),
        )
    binding = found[0]
    warnings = [*binding.problems, *exposures]
    if binding.state == BindingState.PARTIAL:
        missing = [
            step.value
            for step in (
                MARIADB_STEPS if binding.engine == DatabaseEngine.MARIADB else POSTGRESQL_STEPS
            )
            if step not in binding.completed
        ]
        warnings.append(
            f"The binding is partial: its {', '.join(missing)} "
            f"{'is' if len(missing) == 1 else 'are'} missing."
        )
    warnings += [
        f"{read.warning} Another binding may exist there."
        for read in unread
        if read.engine != binding.engine and read.warning
    ]
    identity = site.account is not None and any(
        resource.conforms for resource in site.resources if resource.resource == SiteResource.USER
    )
    if binding.state == BindingState.SATISFIED and not identity:
        warnings.append(f"The site user {name} was not observed as the convention requires.")
    conforms = binding.state == BindingState.SATISFIED and identity and not unread and not exposures
    return ObservedDatabase(
        binding.engine,
        OBSERVED,
        conforms,
        principal=binding.principal,
        database=binding.database,
        authentication=binding.authentication,
        authentication_line=binding.authentication_line,
        privileges=binding.privileges,
        character_set=binding.character_set,
        collation=binding.collation,
        owner=binding.owner,
        source=source,
        warning=" ".join(warnings),
    )
