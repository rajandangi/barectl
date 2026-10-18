"""A site's database binding: the convention's statements, catalog read and probe.

docs/databases.md, ADR 0010 and ADR 0013: the database and principal are
both named ``s<identifier>``, they authenticate by MariaDB ``unix_socket`` or PostgreSQL
``peer`` as the site's Linux user, no password exists and no ``AS`` mapping is ever made.
The statements run one by one, and a binding is ready only when PHP under the site's own
master connects through its driver.

Nothing here imports Django: the controller and the asserted native body share one source
of truth (docs/quality.md#python-typing-policy).
"""

import hashlib
import re
import shlex
from dataclasses import dataclass
from typing import Final, NamedTuple

MARIADB: Final = "mariadb"
POSTGRESQL: Final = "postgresql"
ENGINES: Final = (MARIADB, POSTGRESQL)

# The site's own identifier grammar, repeated here so this module stays standard library
# only (sites.names.IDENTIFIER is the same expression).
IDENTIFIER: Final = re.compile(r"[a-z][a-z0-9]{2,23}")
TOKEN: Final = re.compile(r"[0-9a-f]{32}")
DIGEST: Final = re.compile(r"[0-9a-f]{64}")

MARIADB_SOCKET: Final = "/run/mysqld/mysqld.sock"
MARIADB_CHARACTER_SET: Final = "utf8mb4"
MARIADB_COLLATION: Final = "utf8mb4_unicode_ci"
POSTGRESQL_SOCKET_DIRECTORY: Final = "/var/run/postgresql"
POSTGRESQL_PORT: Final = 5432
POSTGRESQL_ENCODING: Final = "UTF8"
# The libc locales a site database may be created with; template1's must be one of them.
POSTGRESQL_LOCALES: Final = frozenset({"C.UTF-8", "C.utf8", "en_US.UTF-8", "en_US.utf8"})

# docs/databases.md: the statements, in the order a binding is created.
STEPS: Final = ("principal", "database", "privileges", "schema")
MARIADB_STEPS: Final = STEPS[:3]

# The read of the engine catalog: each fact is one ``key<TAB>0|1`` line, and the whole
# text is digested, so an unchanged catalog reads as the same bytes (ADR 0013).
FACT_KEYS: Final = (
    "principal",
    "account",
    "database",
    "schema_any",
    "privileges",
    "schema",
    "exposures",
    "grant_option",
)


@dataclass(frozen=True)
class Statement:
    """One reviewed statement: its step, the database it runs in, and its text."""

    step: str
    database: str
    text: str


class Binding(NamedTuple):
    """One site's binding as the engine catalog reads it.

    ``completed`` is the exact ordered prefix of the convention's statements that exist;
    a partially applied binding is finished by running only ``statements[len(completed):]``.
    """

    engine: str
    identifier: str
    state: str
    completed: tuple[str, ...]
    locale: str = ""
    exposures: tuple[str, ...] = ()


def principal(identifier: str) -> str:
    if IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a site identifier.")
    return "s" + identifier


def name_of(identifier: str) -> str:
    """The database and principal share the site's name."""
    return principal(identifier)


def probe_path(identifier: str, token: str) -> str:
    if IDENTIFIER.fullmatch(identifier) is None or TOKEN.fullmatch(token) is None:
        raise ValueError("Not a probe path.")
    return f"/var/www/{identifier}/dbprobe-{token}.php"


def app_socket(identifier: str, runtime: str) -> str:
    if IDENTIFIER.fullmatch(identifier) is None or runtime not in ("php84", "php85"):
        raise ValueError("Not a site socket.")
    return f"/run/php-fpm/sites/{identifier}/{runtime}/app.sock"


def master_unit(identifier: str, runtime: str) -> str:
    if IDENTIFIER.fullmatch(identifier) is None or runtime not in ("php84", "php85"):
        raise ValueError("Not a site master.")
    return f"php-fpm-site-{runtime}@{identifier}.service"


def site_read_command(identifier: str, runtime: str) -> str:
    """The fixed read of the site identity whose digest the payload revalidates."""
    name = principal(identifier)
    socket = app_socket(identifier, runtime)
    unit = master_unit(identifier, runtime)
    return "; ".join(
        (
            f"printf 'account\\t%s\\n' \"$(getent passwd {name})\"",
            f"printf 'socket\\t%s\\n' \"$(stat -c '%u %g %a %F' {socket})\"",
            (
                f"printf 'master\\t%s\\n' \"$(systemctl show -p ActiveState,SubState,MainPID "
                f"--value {unit} | tr '\\n' ' ')\""
            ),
        )
    )


def presence_command(identifier: str) -> str:
    """The affected-sites read: prints the identifier while its Caddy file and directory exist."""
    if IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a site identifier.")
    return (
        f"if [ -f /etc/caddy/sites/{identifier}.caddy ] && [ -d /var/www/{identifier} ]; "
        f"then printf '%s\\n' {identifier}; fi"
    )


def mariadb_statements(name: str) -> tuple[Statement, ...]:
    """docs/databases.md: ALL PRIVILEGES on the site's own database only."""
    if IDENTIFIER.fullmatch(name.removeprefix("s")) is None:
        raise ValueError("Not a site principal.")
    return (
        Statement("principal", "", f"CREATE USER `{name}`@`localhost` IDENTIFIED VIA unix_socket"),
        Statement(
            "database",
            "",
            f"CREATE DATABASE `{name}` CHARACTER SET {MARIADB_CHARACTER_SET} "
            f"COLLATE {MARIADB_COLLATION}",
        ),
        Statement(
            "privileges",
            "",
            f"GRANT ALL PRIVILEGES ON `{name}`.* TO `{name}`@`localhost`",
        ),
    )


def postgresql_statements(name: str, locale: str) -> tuple[Statement, ...]:
    if IDENTIFIER.fullmatch(name.removeprefix("s")) is None:
        raise ValueError("Not a site principal.")
    if locale not in POSTGRESQL_LOCALES:
        raise ValueError("Not a reviewed locale.")
    return (
        Statement(
            "principal",
            "postgres",
            f'CREATE ROLE "{name}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT '
            "NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 PASSWORD NULL",
        ),
        Statement(
            "database",
            "postgres",
            f'CREATE DATABASE "{name}" WITH OWNER "{name}" TEMPLATE template0 '
            f"ENCODING '{POSTGRESQL_ENCODING}' LOCALE_PROVIDER libc "
            f"LC_COLLATE '{locale}' LC_CTYPE '{locale}'",
        ),
        Statement(
            "privileges",
            "postgres",
            f'REVOKE CONNECT, TEMPORARY ON DATABASE "{name}" FROM PUBLIC',
        ),
        Statement("schema", name, "REVOKE ALL ON SCHEMA public FROM PUBLIC"),
    )


def statements(engine: str, name: str, locale: str = "") -> tuple[Statement, ...]:
    if engine == MARIADB:
        return mariadb_statements(name)
    if engine == POSTGRESQL:
        return postgresql_statements(name, locale)
    raise ValueError("Unknown database engine.")


def steps_of(engine: str) -> tuple[str, ...]:
    return MARIADB_STEPS if engine == MARIADB else STEPS


def _mariadb_catalog_sql(name: str) -> str:
    grantee = f"CONCAT(QUOTE('{name}'), '@', QUOTE('localhost'))"
    return (
        "SELECT 'principal', CASE WHEN EXISTS("  # noqa: S608 - checked site principal
        f"SELECT 1 FROM mysql.global_priv WHERE User='{name}' AND Host='localhost' "
        "AND JSON_VALUE(Priv,'$.plugin')='unix_socket') THEN 1 ELSE 0 END;"
        "SELECT 'account', CASE WHEN EXISTS("
        f"SELECT 1 FROM mysql.global_priv WHERE User='{name}') THEN 1 ELSE 0 END;"
        "SELECT 'database', CASE WHEN EXISTS("
        f"SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='{name}' "
        f"AND DEFAULT_CHARACTER_SET_NAME='{MARIADB_CHARACTER_SET}' "
        f"AND DEFAULT_COLLATION_NAME='{MARIADB_COLLATION}') THEN 1 ELSE 0 END;"
        "SELECT 'schema_any', CASE WHEN EXISTS("
        f"SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='{name}') "
        "THEN 1 ELSE 0 END;"
        "SELECT 'privileges', CASE WHEN EXISTS("
        f"SELECT 1 FROM mysql.db WHERE User='{name}' AND Host='localhost' AND Db='{name}') "
        "THEN 1 ELSE 0 END;"
        "SELECT 'schema', 1;"
        "SELECT 'exposures', CASE WHEN EXISTS("
        f"SELECT 1 FROM mysql.db WHERE Db='{name}' "
        f"AND NOT (User='{name}' AND Host='localhost')) THEN 1 ELSE 0 END;"
        "SELECT 'grant_option', CASE WHEN EXISTS("
        f"SELECT 1 FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE={grantee} "
        f"AND TABLE_SCHEMA='{name}' AND IS_GRANTABLE='YES') THEN 1 ELSE 0 END"
    )


def _mariadb_read_command(name: str) -> str:
    return (
        "/usr/bin/mariadb --no-defaults --protocol=socket "
        f"--socket={MARIADB_SOCKET} --user=root -N -B -e " + shlex.quote(_mariadb_catalog_sql(name))
    )


def _postgresql_account_sql(name: str) -> str:
    return (
        "SELECT 'principal', CASE WHEN EXISTS("  # noqa: S608 - checked site principal
        f"SELECT 1 FROM pg_authid WHERE rolname='{name}' AND NOT rolsuper "
        "AND rolinherit AND NOT rolcreaterole AND NOT rolcreatedb AND rolcanlogin "
        "AND NOT rolreplication AND NOT rolbypassrls AND rolconnlimit=-1 "
        "AND rolpassword IS NULL) THEN 1 ELSE 0 END;"
        "SELECT 'account', CASE WHEN EXISTS("
        f"SELECT 1 FROM pg_authid WHERE rolname='{name}') THEN 1 ELSE 0 END;"
        "SELECT 'database', CASE WHEN EXISTS("
        f"SELECT 1 FROM pg_database WHERE datname='{name}' "
        f"AND pg_get_userbyid(datdba)='{name}' "
        f"AND pg_encoding_to_char(encoding)='{POSTGRESQL_ENCODING}' "
        "AND datlocprovider='c' AND datcollate=datctype) THEN 1 ELSE 0 END;"
        "SELECT 'schema_any', CASE WHEN EXISTS("
        f"SELECT 1 FROM pg_database WHERE datname='{name}') THEN 1 ELSE 0 END;"
        "SELECT 'privileges', CASE WHEN EXISTS("
        f"SELECT 1 FROM pg_database d WHERE d.datname='{name}' AND NOT EXISTS ("
        "SELECT 1 FROM aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) a "
        "WHERE a.grantee=0 AND a.privilege_type IN ('CONNECT','TEMPORARY'))) "
        "THEN 1 ELSE 0 END;"
        "SELECT 'exposures', CASE WHEN EXISTS("
        f"SELECT 1 FROM pg_database d, "
        "aclexplode(COALESCE(d.datacl, '{}'::aclitem[])) a "
        f"WHERE d.datname='{name}' AND a.grantee NOT IN (0, d.datdba)) "
        "THEN 1 ELSE 0 END"
    )


def _postgresql_template_sql() -> str:
    return (
        "SELECT 'template', pg_encoding_to_char(encoding), datlocprovider, datcollate, datctype "
        "FROM pg_database WHERE datname='template1'"
    )


def _postgresql_schema_sql(name: str) -> str:
    return (
        "SELECT 'schema', CASE WHEN EXISTS("
        "SELECT 1 FROM pg_namespace WHERE nspname='public') AND NOT EXISTS ("
        "SELECT 1 FROM pg_namespace n, "
        "aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) a "
        "WHERE n.nspname='public' AND a.grantee=0) THEN 1 ELSE 0 END"
    )


def _postgresql_read_command(name: str) -> str:
    account = _psql(_postgresql_account_sql(name))
    template = _psql(_postgresql_template_sql())
    schema = _psql(_postgresql_schema_sql(name))
    return (
        "{ "
        f"/usr/bin/su - postgres -c {shlex.quote(account)}; "
        f"/usr/bin/su - postgres -c {shlex.quote(template)}; "
        f"( /usr/sbin/runuser -u {name} -- sh -c {shlex.quote(schema)} ) 2>/dev/null || "
        "printf 'schema\\t0\\n'; "
        "} 2>/dev/null"
    )


def _psql(sql: str) -> str:
    return f"/usr/bin/psql -X -A -t -q -c {shlex.quote(sql)}"


def read_command(engine: str, name: str) -> str:
    """The fixed privileged read of one site's binding in the engine's catalog."""
    if engine == MARIADB:
        return _mariadb_read_command(name)
    if engine == POSTGRESQL:
        return _postgresql_read_command(name)
    raise ValueError("Unknown database engine.")


def parse_facts(engine: str, text: str) -> dict[str, str]:
    """The facts the catalog read printed, or a ``ValueError`` for an unsupported read."""
    facts: dict[str, str] = {}
    for line in text.splitlines():
        if not line:
            continue
        key, separator, value = line.partition("\t")
        if not separator:
            key, separator, value = line.partition("|")
        if not separator:
            raise ValueError("The database catalog read is not in the supported form.")
        if key == "template":
            continue
        if key not in FACT_KEYS or key in facts or value not in ("0", "1"):
            raise ValueError("The database catalog read is not in the supported form.")
        facts[key] = value
    if engine == POSTGRESQL and "schema" not in facts:
        raise ValueError("The database catalog read did not report the public schema.")
    for key in FACT_KEYS:
        if key not in facts and not (engine == POSTGRESQL and key == "schema"):
            facts[key] = "0"
    return facts


def read_locale(text: str) -> str:
    """template1's libc locale when it is UTF8, one locale and on the allowlist; else empty."""
    for line in text.splitlines():
        parts = line.split("|")
        if len(parts) == 5 and parts[0] == "template":
            encoding, provider, collate, ctype = parts[1:]
            if (encoding, provider) == (POSTGRESQL_ENCODING, "c") and collate == ctype:
                return collate if collate in POSTGRESQL_LOCALES else ""
    return ""


def recognize(engine: str, identifier: str, facts: dict[str, str], *, locale: str = "") -> Binding:
    """The binding state the facts describe, following ADR 0015's shape recognition."""
    steps = steps_of(engine)
    present = {step: facts.get(step, "0") == "1" for step in steps}
    extra = int(facts.get("account", "0")) > 1
    any_schema = int(facts.get("schema_any", "0")) > 0
    exposures = int(facts.get("exposures", "0")) > 0
    grant_option = int(facts.get("grant_option", "0")) > 0
    completed = tuple(step for step in steps if present[step])
    prefix = all(present[step] for step in steps[: len(completed)])
    custom = (
        extra
        or exposures
        or grant_option
        or (any_schema and not present["database"])
        or (present["database"] and not present["principal"])
        or (not prefix)
        or (engine == POSTGRESQL and present["database"] and not locale)
    )
    if not any(present.values()):
        state = "absent"
        completed = ()
    elif custom:
        state = "custom"
        completed = ()
    elif all(present[step] for step in steps):
        state = "satisfied"
    else:
        state = "partial"
    return Binding(engine, identifier, state, completed, locale)


def absent(engine: str, identifier: str) -> Binding:
    return Binding(engine, identifier, "absent", ())


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# The probe -------------------------------------------------------------------------------
# It is published in the root-owned site directory, never the document root, and the
# payload sends it FastCGI requests as root directly to the site's own master socket
# (ADR 0013#proof-through-the-pool). Each flag is 1 when its check holds.

PROBE_FLAGS: Final = (
    "connected",
    "identity",
    "roundtrip",
    "isolated",
    "create_denied",
    "role_denied",
    "catalog_denied",
    "tcp_denied",
)
MARIADB_MODULES: Final = ("mysqlnd", "mysqli", "pdo_mysql")
POSTGRESQL_MODULES: Final = ("pgsql", "pdo_pgsql")


def render_probe(engine: str, name: str, token: str) -> str:
    """The temporary probe the site's own master runs as the site user."""
    if engine not in ENGINES or TOKEN.fullmatch(token) is None:
        raise ValueError("Not a probe request.")
    if principal(name.removeprefix("s")) != name:
        raise ValueError("Not a site principal.")
    modules = ",".join(f"'{module}'" for module in _modules(engine))
    body = _mariadb_probe(name, token) if engine == MARIADB else _postgresql_probe(name, token)
    return (
        "<?php\n"
        f"$t='{token}';$u='{name}';$o=[];\n"
        f"foreach([{modules}] as $m)$o[]=extension_loaded($m)?1:0;\n"
        "if(($_SERVER['QUERY_STRING']??'')==='pre'){"
        'echo "barectl-db $t pre ",posix_geteuid()," ",posix_getegid()," ",implode(" ",$o),"\\n";'
        "exit;}\n"
        f"{body}"
        'echo "barectl-db $t ",posix_geteuid()," ",implode(" ",$r),"\\n";\n'
    )


def _modules(engine: str) -> tuple[str, ...]:
    return MARIADB_MODULES if engine == MARIADB else POSTGRESQL_MODULES


def _deny(queries: tuple[str, ...]) -> str:
    """PHP that appends 1 for each statement the engine refuses."""
    return "$r=array_merge($r,[]);" + "".join(
        "try{$p->exec(" + _php_string(query) + ");$r[]=0;}catch(Throwable $e){$r[]=1;}"
        for query in queries
    )


def _mariadb_probe(name: str, token: str) -> str:
    dsn = _php_string(f"mysql:unix_socket={MARIADB_SOCKET};dbname={name}")
    tail = (
        _deny(  # noqa: S608 - fixed probe statements
            (
                f"CREATE DATABASE barectl_{token}",
                f"CREATE USER barectl_{token}",
                "SELECT User FROM mysql.global_priv",
            )
        )
        + "try{new PDO("
        + _php_string(f"mysql:host=127.0.0.1;port=3306;dbname={name}")
        + ",$u,null);$r[]=0;}catch(Throwable $e){$r[]=1;}"
    )
    return _probe_body(dsn, _mariadb_identity(), _mariadb_isolated(), tail)


def _postgresql_probe(name: str, token: str) -> str:
    dsn = _php_string(
        f"pgsql:host={POSTGRESQL_SOCKET_DIRECTORY};port={POSTGRESQL_PORT};dbname={name}"
    )
    tail = (
        _deny(  # noqa: S608 - fixed probe statements
            (
                f"CREATE DATABASE barectl_{token}",
                f"CREATE ROLE barectl_{token}",
                "SELECT rolname FROM pg_authid",
            )
        )
        + "try{new PDO("
        + _php_string(f"pgsql:host=127.0.0.1;port={POSTGRESQL_PORT};dbname={name}")
        + ",$u,null);$r[]=0;}catch(Throwable $e){$r[]=1;}"
    )
    return _probe_body(dsn, _postgresql_identity(), _postgresql_isolated(), tail)


def _mariadb_identity() -> str:
    return "SELECT SUBSTRING_INDEX(CURRENT_USER(),'@',1)"


def _mariadb_isolated() -> str:
    return (
        "SELECT COUNT(*) FROM information_schema.SCHEMATA "
        "WHERE SCHEMA_NAME REGEXP '^s[a-z][a-z0-9]{2,23}$'"
    )


def _postgresql_identity() -> str:
    return "SELECT current_user"


def _postgresql_isolated() -> str:
    return (
        "SELECT COUNT(*) FROM pg_database d WHERE "
        "d.datname ~ '^s[a-z][a-z0-9]{2,23}$' AND has_database_privilege(d.oid,'CONNECT')"
    )


def _probe_body(dsn: str, identity: str, isolated: str, tail: str) -> str:
    return (
        "$r=[];"  # noqa: S608 - fixed probe statements
        f"try{{$p=new PDO({dsn},$u,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);"
        "$r[]=1;"
        f"$r[]=(strval($p->query({_php_string(identity)})->fetchColumn())===$u)?1:0;"
        "$p->exec('CREATE TABLE barectl_'.$t.'(i INT PRIMARY KEY)');"
        "$p->exec('INSERT INTO barectl_'.$t.' VALUES (7)');"
        "$v=$p->query('SELECT i FROM barectl_'.$t)->fetchColumn();"
        "$p->exec('DROP TABLE barectl_'.$t);"
        "$r[]=($v==7)?1:0;"
        f"$r[]=(intval($p->query({_php_string(isolated)})->fetchColumn())===1)?1:0;"
        "}catch(Throwable $e){while(count($r)<4)$r[]=0;}"
        f"{tail}"
    )


def _php_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def expected_probe(engine: str, name: str, token: str, uid: int, gid: int) -> tuple[str, str]:
    """The exact ``pre`` and ``full`` lines the site's own master must print."""
    modules = " ".join("1" for _ in _modules(engine))
    pre = f"barectl-db {token} pre {uid} {gid} {modules}"
    full = f"barectl-db {token} {uid} " + " ".join("1" for _ in PROBE_FLAGS)
    return pre, full


def probe_digest(source: str) -> str:
    return hashlib.sha256(source.encode()).hexdigest()
