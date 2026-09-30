"""A site's database binding: its statements, catalog read and probe
(docs/databases.md#database-bindings, docs/site-conventions.md#database-convention).

Every value here is derived from the site identifier; nothing an operator types reaches a
statement except through ``sites.names`` validation, and identifiers are always quoted.
"""

import hashlib
import re
import shlex
from dataclasses import dataclass

from bootstrap.models import Action
from discovery.models import DatabaseEngine
from discovery.observations.databases import (
    MARIADB_CHARACTER_SET,
    MARIADB_CLIENT,
    MARIADB_COLLATION,
    MARIADB_PRIVILEGES,
    MARIADB_SOCKET,
    MARIADB_STEPS,
    POSTGRESQL_CLIENT,
    POSTGRESQL_ENCODING,
    POSTGRESQL_LOCALES,
    POSTGRESQL_PORT,
    POSTGRESQL_SCHEMA_SQL,
    POSTGRESQL_SOCKET_DIRECTORY,
    POSTGRESQL_STEPS,
    Binding,
    CatalogFormatError,
    Step,
    mariadb_catalog_sql,
    needs_schema,
    parse_mariadb,
    parse_postgresql,
    parse_postgresql_schema,
    postgresql_catalog_sql,
    recognize_mariadb,
    recognize_postgresql,
    satisfied_mariadb_rows,
    satisfied_postgresql_rows,
    satisfied_postgresql_schema,
    with_schema,
)
from sites.names import IDENTIFIER

# docs/site-conventions.md#database-convention: the probe's name part.
TOKEN = re.compile(r"[0-9a-f]{32}")
MARIADB_SECTION = "== mariadb"
POSTGRESQL_SECTION = "== postgresql"


@dataclass(frozen=True)
class EngineSpec:
    engine: DatabaseEngine
    # The binding's own action, the engine's bootstrap profile and the PHP driver it needs.
    action: Action
    profile: Action
    driver: Action
    steps: tuple[Step, ...]
    # The PHP modules the probe needs loaded.
    modules: tuple[str, ...]


ENGINES = {
    DatabaseEngine.MARIADB: EngineSpec(
        DatabaseEngine.MARIADB,
        Action.DATABASE_MARIADB,
        Action.MARIADB,
        Action.PHP_MYSQL,
        MARIADB_STEPS,
        ("mysqlnd", "mysqli", "pdo_mysql"),
    ),
    DatabaseEngine.POSTGRESQL: EngineSpec(
        DatabaseEngine.POSTGRESQL,
        Action.DATABASE_POSTGRESQL,
        Action.POSTGRESQL,
        Action.PHP_PGSQL,
        POSTGRESQL_STEPS,
        ("pgsql", "pdo_pgsql"),
    ),
}
BY_ACTION: dict[str, EngineSpec] = {spec.action: spec for spec in ENGINES.values()}


def principal(identifier: str) -> str:
    if not IDENTIFIER.fullmatch(identifier):
        message = f"Not a site identifier: {identifier!r}"
        raise ValueError(message)
    return f"s{identifier}"


@dataclass(frozen=True)
class Statement:
    step: Step
    # The database a PostgreSQL statement runs in; empty for MariaDB.
    database: str
    text: str


def mariadb_statements(name: str) -> tuple[Statement, ...]:
    """docs/site-conventions.md#database-convention, in order."""
    grants = ", ".join(MARIADB_PRIVILEGES)
    return (
        Statement(
            Step.PRINCIPAL, "", f"CREATE USER `{name}`@`localhost` IDENTIFIED VIA unix_socket"
        ),
        Statement(
            Step.DATABASE,
            "",
            f"CREATE DATABASE `{name}` CHARACTER SET {MARIADB_CHARACTER_SET} "
            f"COLLATE {MARIADB_COLLATION}",
        ),
        Statement(Step.PRIVILEGES, "", f"GRANT {grants} ON `{name}`.* TO `{name}`@`localhost`"),
    )


def postgresql_statements(name: str, locale: str) -> tuple[Statement, ...]:
    """docs/site-conventions.md#database-convention, in order; ``locale`` is template1's,
    reviewed against the allowlist."""
    if locale not in POSTGRESQL_LOCALES:
        message = f"Not a reviewed locale: {locale!r}"
        raise ValueError(message)
    return (
        Statement(
            Step.PRINCIPAL,
            "postgres",
            f'CREATE ROLE "{name}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT '
            "NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 PASSWORD NULL",
        ),
        Statement(
            Step.DATABASE,
            "postgres",
            f'CREATE DATABASE "{name}" WITH OWNER "{name}" TEMPLATE template0 '
            f"ENCODING '{POSTGRESQL_ENCODING}' LOCALE_PROVIDER libc "
            f"LC_COLLATE '{locale}' LC_CTYPE '{locale}'",
        ),
        Statement(
            Step.PRIVILEGES,
            "postgres",
            f'REVOKE CONNECT, TEMPORARY ON DATABASE "{name}" FROM PUBLIC',
        ),
        Statement(Step.SCHEMA, name, "REVOKE ALL ON SCHEMA public FROM PUBLIC"),
    )


def statements(engine: DatabaseEngine, name: str, locale: str = "") -> tuple[Statement, ...]:
    if engine == DatabaseEngine.MARIADB:
        return mariadb_statements(name)
    return postgresql_statements(name, locale)


def client(engine: DatabaseEngine) -> str:
    """The administrator's client, as root, through the engine's local socket only."""
    if engine == DatabaseEngine.MARIADB:
        return MARIADB_CLIENT
    return POSTGRESQL_CLIENT


def mariadb_absence_sql(name: str) -> str:
    """Whether MariaDB holds an account, database or grant under ``name``."""
    return (
        f"SELECT 'A',User,Host FROM mysql.global_priv WHERE User='{name}' ORDER BY 2,3;"  # noqa: S608 - checked name
        f"SELECT 'A',SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='{name}';"
        f"SELECT 'A',User,Host,Db FROM mysql.db WHERE User='{name}' ORDER BY 2,3,4"
    )


def postgresql_absence_sql(name: str) -> str:
    """Whether PostgreSQL holds a role or database under ``name``."""
    return (
        f"SELECT 'A',rolname FROM pg_authid WHERE rolname='{name}';"  # noqa: S608 - checked name
        f"SELECT 'A',datname FROM pg_database WHERE datname='{name}'"
    )


# The template whose locale a site database is created with.
POSTGRESQL_TEMPLATE_SQL = (
    "SELECT 'T',pg_encoding_to_char(encoding),datlocprovider,datcollate,datctype "
    "FROM pg_database WHERE datname='template1'"
)


def catalog_function(name: str, engine: DatabaseEngine, other: bool) -> str:
    """``c``: the binding engine's catalog rows under ``name`` and, when ``other``, whether
    the other engine holds anything under it, each after its section line, as ordered
    text whose digest the plan records. PostgreSQL's rows add template1's locale and the
    public schema of a database named ``name``, which prints nothing while none exists."""
    principal(name.removeprefix("s"))
    postgresql = (
        f"{POSTGRESQL_CLIENT} -d postgres -c {shlex.quote(postgresql_catalog_sql((name,)))}; "
        f"{POSTGRESQL_CLIENT} -d postgres -c {shlex.quote(POSTGRESQL_TEMPLATE_SQL)}; "
        f"{POSTGRESQL_CLIENT} -d {name} -c {shlex.quote(POSTGRESQL_SCHEMA_SQL)}"
    )
    reads = {
        DatabaseEngine.MARIADB: (
            MARIADB_SECTION,
            f"{MARIADB_CLIENT} {shlex.quote(mariadb_catalog_sql((name,)))}",
            f"{MARIADB_CLIENT} {shlex.quote(mariadb_absence_sql(name))}",
        ),
        DatabaseEngine.POSTGRESQL: (
            POSTGRESQL_SECTION,
            postgresql,
            f"{POSTGRESQL_CLIENT} -d postgres -c {shlex.quote(postgresql_absence_sql(name))}",
        ),
    }
    section, full, _ = reads[engine]
    parts = [f"echo '{section}'", full]
    if other:
        (other_section, _, absence) = next(value for key, value in reads.items() if key != engine)
        parts += [f"echo '{other_section}'", absence]
    return "c(){ " + "; ".join(parts) + "; } 2>/dev/null"


def other_engine(engine: DatabaseEngine) -> DatabaseEngine:
    return DatabaseEngine.POSTGRESQL if engine == DatabaseEngine.MARIADB else DatabaseEngine.MARIADB


def _section(engine: DatabaseEngine) -> str:
    return MARIADB_SECTION if engine == DatabaseEngine.MARIADB else POSTGRESQL_SECTION


def sections(text: str, engine: DatabaseEngine) -> tuple[str, str | None]:
    """The binding engine's rows and, when the read covers it, the other engine's."""
    own, other = _section(engine), _section(other_engine(engine))
    head, marker, rest = text.partition(f"{own}\n")
    if head or not marker:
        message = "The catalog read does not start with the engine's section."
        raise ValueError(message)
    rows, separator, tail = rest.partition(f"{other}\n")
    return rows, tail if separator else None


def _joined(engine: DatabaseEngine, rows: str, other: str | None) -> str:
    tail = "" if other is None else f"{_section(other_engine(engine))}\n{other}"
    return f"{_section(engine)}\n{rows}{tail}"


@dataclass(frozen=True)
class CatalogRead:
    """Discovery's recognition of the binding engine's rows in ``c``'s output."""

    binding: Binding
    # The other engine's rows under the name, or None when it is not installed.
    other: str | None
    # PostgreSQL: template1's encoding, locale provider, collation and character type.
    template: tuple[str, ...] = ()


def recognize(text: str, engine: DatabaseEngine, name: str) -> CatalogRead:
    own, other = sections(text, engine)
    if engine == DatabaseEngine.MARIADB:
        return CatalogRead(recognize_mariadb(parse_mariadb(own, (name,)), name), other)
    lines = own.splitlines()
    template = [line.split("|")[1:] for line in lines if line.startswith("T|")]
    schema = [line for line in lines if line.startswith("N|")]
    rest = "".join(f"{line}\n" for line in lines if not line.startswith(("T|", "N|")))
    if len(template) != 1 or len(template[0]) != 4 or len(schema) > 1:
        message = "Unexpected template or schema read."
        raise CatalogFormatError(message)
    catalog = parse_postgresql(rest, (name,))
    if needs_schema(catalog, name):
        with_schema(catalog, name, parse_postgresql_schema(schema[0]) if schema else None)
    return CatalogRead(recognize_postgresql(catalog, name), other, tuple(template[0]))


def reviewed_locale(template: tuple[str, ...]) -> str:
    """docs/site-conventions.md#database-convention: template1's libc locale when it is UTF8,
    one locale and on the allowlist; otherwise empty."""
    encoding, provider, collate, ctype = template
    if (encoding, provider) == (POSTGRESQL_ENCODING, "c") and collate == ctype:
        return collate if collate in POSTGRESQL_LOCALES else ""
    return ""


def predicted_after(before: str, engine: DatabaseEngine, name: str, locale: str = "") -> str:
    """The catalog read's text once the binding exists: ``before``, an absent binding, with
    the engine's section holding exactly the convention's rows."""
    own, other = sections(before, engine)
    lines = own.splitlines(keepends=True)
    if engine == DatabaseEngine.MARIADB:
        return _joined(engine, "".join([*lines[:1], satisfied_mariadb_rows(name)]), other)
    kept = [line for line in lines if not line.startswith("N|")]
    rows = [
        *kept[:1],
        satisfied_postgresql_rows(name, locale=locale),
        *kept[1:],
        satisfied_postgresql_schema(),
    ]
    return _joined(engine, "".join(rows), other)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# The probe ------------------------------------------------------------------------------


def probe_path(identifier: str, token: str) -> str:
    """docs/databases.md#the-probe: in the root-owned site directory, never the document
    root, which the site user owns."""
    if not TOKEN.fullmatch(token):
        message = "Not a probe token."
        raise ValueError(message)
    return f"/var/www/{identifier}/dbprobe-{token}.php"


def _mariadb_checks() -> str:
    return (
        "$r=[];$x=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION];\n"  # noqa: S608 - PHP source; the principal and token are checked
        f"try{{$p=new PDO('mysql:unix_socket={MARIADB_SOCKET};dbname='.$u,$u,null,$x);\n"
        "$r[]=$p->query('SELECT CURRENT_USER()')->fetchColumn();\n"
        '$p->exec("CREATE TABLE barectl_$t(i INT PRIMARY KEY)");'
        '$p->exec("INSERT INTO barectl_$t VALUES (7)");\n'
        '$r[]=$p->query("SELECT i FROM barectl_$t")->fetchColumn();'
        '$p->exec("DROP TABLE barectl_$t");\n'
        "$r[]=implode(',',$p->query('SHOW DATABASES')->fetchAll(PDO::FETCH_COLUMN));\n"
        'foreach(["CREATE DATABASE barectl_$t","CREATE USER barectl_$t",'
        "'SELECT User FROM mysql.global_priv'] as $q){"
        "try{$p->exec($q);$r[]='allowed';}catch(PDOException $e){$r[]=$e->errorInfo[1];}}\n"
        "}catch(PDOException $e){$r[]='error';}\n"
        f"$m=@mysqli_connect(null,$u,null,$u,0,'{MARIADB_SOCKET}');"
        "$r[]=$m?mysqli_query($m,'SELECT 1')->fetch_row()[0]:'error';\n"
        "try{new PDO('mysql:host=127.0.0.1;port=3306',$u,null,$x);$r[]='allowed';}"
        "catch(PDOException $e){$r[]=$e->errorInfo[1]??'error';}\n"
    )


def _postgresql_checks() -> str:
    host = f"host={POSTGRESQL_SOCKET_DIRECTORY};port={POSTGRESQL_PORT}"
    return (
        "$r=[];$x=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION];\n"  # noqa: S608 - PHP source; the principal and token are checked
        f"try{{$p=new PDO('pgsql:{host};dbname='.$u,$u,null,$x);\n"
        "$r[]=$p->query(\"SELECT current_user||','||session_user\")->fetchColumn();\n"
        '$p->exec("CREATE TABLE barectl_$t(i INT PRIMARY KEY)");'
        '$p->exec("INSERT INTO barectl_$t VALUES (7)");\n'
        '$r[]=$p->query("SELECT i FROM barectl_$t")->fetchColumn();'
        '$p->exec("DROP TABLE barectl_$t");\n'
        # Every other site database, by the convention's names, this role may connect to.
        '$r[]=$p->query("SELECT count(*) FROM pg_database d WHERE '
        "d.datname ~ '^s[a-z][a-z0-9]{2,23}\\$' AND pg_get_userbyid(d.datdba)=d.datname "
        "AND d.datname<>current_database() AND has_database_privilege(d.oid,'CONNECT')\")"
        "->fetchColumn();\n"
        'foreach(["CREATE DATABASE barectl_$t","CREATE ROLE barectl_$t",'
        "'SELECT rolname FROM pg_authid'] as $q){"
        "try{$p->exec($q);$r[]='allowed';}catch(PDOException $e){$r[]=$e->errorInfo[0];}}\n"
        "}catch(PDOException $e){$r[]='error';}\n"
        f'$c=@pg_connect("host={POSTGRESQL_SOCKET_DIRECTORY} port={POSTGRESQL_PORT} '
        'dbname=$u user=$u");'
        "$r[]=$c?pg_fetch_result(pg_query($c,'SELECT 1'),0,0):'error';\n"
        f"try{{new PDO('pgsql:host=127.0.0.1;port={POSTGRESQL_PORT};dbname='.$u,$u,null,$x);"
        "$r[]='allowed';}catch(PDOException $e){$r[]=$e->errorInfo[0]??'error';}\n"
    )


def render_probe(engine: DatabaseEngine, name: str, token: str) -> str:
    """The temporary probe the site's pool runs: ``?pre`` reports its identity and modules,
    anything else connects through the driver and reports each check's outcome."""
    if not TOKEN.fullmatch(token) or not re.fullmatch(r"s[a-z][a-z0-9]{2,23}", name):
        message = "Not a probe token or principal."
        raise ValueError(message)
    modules = ",".join(f"'{module}'" for module in ENGINES[engine].modules)
    checks = _mariadb_checks() if engine == DatabaseEngine.MARIADB else _postgresql_checks()
    return (
        "<?php\n"
        f"$t='{token}';$u='{name}';$o=[];\n"
        f"foreach([{modules}] as $m)$o[]=extension_loaded($m)?1:0;\n"
        "if(($_SERVER['QUERY_STRING']??'')==='pre'){"
        'echo "barectl-db $t pre ",posix_geteuid()," ",posix_getegid()," ",implode(" ",$o),"\\n";'
        "exit;}\n"
        f"{checks}"
        'echo "barectl-db $t ",posix_geteuid()," ",implode(" ",$r),"\\n";\n'
    )


def expected_pre(token: str, uid: int, gid: int, engine: DatabaseEngine) -> str:
    ones = " ".join("1" for _ in ENGINES[engine].modules)
    return f"barectl-db {token} pre {uid} {gid} {ones}"


def expected_proof(token: str, uid: int, engine: DatabaseEngine, name: str) -> str:
    """docs/databases.md#the-probe: what the probe reports for a binding that works as
    reviewed."""
    if engine == DatabaseEngine.MARIADB:
        # Identity, DDL and DML, the databases it sees, denied CREATE DATABASE, CREATE USER
        # and system tables, mysqli through the socket, and TCP without a password denied.
        return (
            f"barectl-db {token} {uid} {name}@localhost 7 information_schema,{name} "
            "1044 1227 1142 1 1698"
        )
    # Identity, DDL and DML, no other site database it may connect to, denied CREATE
    # DATABASE, CREATE ROLE and pg_authid, pgsql through the socket, and TCP denied.
    return f"barectl-db {token} {uid} {name},{name} 7 0 42501 42501 42501 1 08006"


def fastcgi_client(php: str) -> str:
    """``f SOCKET SCRIPT QUERY``: the body of one FastCGI request, as root, which may connect
    to the pool's socket. ``-n`` ignores php.ini; the CLI is a prerequisite."""
    if not re.fullmatch(r"8\.[0-9]", php):
        message = "Not a PHP version."
        raise ValueError(message)
    return (
        "f(){ /usr/bin/php" + php + " -n -r '"
        '[$k,$s,$q]=array_slice($argv,1);$c=@stream_socket_client("unix://$k",$n,$e,5);'
        "if(!$c)exit(1);stream_set_timeout($c,10);"
        '$r=fn($t,$b)=>pack("CCnnCx",1,$t,1,strlen($b),0).$b;'
        '$l=fn($n)=>$n<128?chr($n):pack("N",$n|0x80000000);'
        "$v=fn($a,$b)=>$l(strlen($a)).$l(strlen($b)).$a.$b;"
        '$p=$v("SCRIPT_FILENAME",$s).$v("SCRIPT_NAME","/".basename($s))'
        '.$v("REQUEST_METHOD","GET").$v("QUERY_STRING",$q);'
        'fwrite($c,$r(1,pack("nCx5",1,0)).$r(4,$p).$r(4,"").$r(5,""));$o="";'
        'while(strlen($h=fread($c,8))==8){$d=unpack("Cv/Ct/nid/nlen/Cpad/x",$h);'
        '$b=$d["len"]?fread($c,$d["len"]):"";if($d["pad"])fread($c,$d["pad"]);'
        'if($d["t"]==6)$o.=$b;if($d["t"]==3)break;}'
        '$i=strpos($o,"\\r\\n\\r\\n");echo $i===false?"":substr($o,$i+4);'
        '\' "$1" "$2" "$3"; }'
    )


def all_steps(engine: DatabaseEngine) -> tuple[Step, ...]:
    return ENGINES[engine].steps


# The bootstrap profile of each engine, whose root package shows whether it is installed.
ENGINE_PROFILES = {
    DatabaseEngine.MARIADB: Action.MARIADB,
    DatabaseEngine.POSTGRESQL: Action.POSTGRESQL,
}


def character_set(engine: DatabaseEngine) -> str:
    return MARIADB_CHARACTER_SET if engine == DatabaseEngine.MARIADB else POSTGRESQL_ENCODING


def collation(engine: DatabaseEngine, locale: str) -> str:
    """MariaDB's collation, or the PostgreSQL database's reviewed libc locale."""
    return MARIADB_COLLATION if engine == DatabaseEngine.MARIADB else locale


def record_locale(engine: DatabaseEngine, collation: str) -> str:
    """The locale a stored binding record's statements use, from its collation."""
    return "" if engine == DatabaseEngine.MARIADB else collation


def authentication_text(engine: DatabaseEngine) -> str:
    if engine == DatabaseEngine.MARIADB:
        return "unix_socket, without a password or another method"
    return "peer, by the distribution's pg_hba.conf rule for local connections, without a password"


def privileges_text(engine: DatabaseEngine, name: str) -> str:
    if engine == DatabaseEngine.MARIADB:
        return (
            f"Grants {name} only the convention's privileges on its own database: no global, "
            "grant, file or administrative privilege."
        )
    return (
        f"{name} owns its database and nothing else, with no superuser, database or role "
        "creation, replication or row-security bypass; PUBLIC's CONNECT and TEMPORARY on the "
        "database and its rights on the public schema are revoked, so other roles cannot "
        "connect to it or create objects in it."
    )


def encoding_text(engine: DatabaseEngine, locale: str = "") -> str:
    if engine == DatabaseEngine.MARIADB:
        return f"the character set {MARIADB_CHARACTER_SET} and the collation {MARIADB_COLLATION}"
    return (
        f"the {POSTGRESQL_ENCODING} encoding and template1's libc locale {locale}, from template0"
    )


def connection_text(engine: DatabaseEngine, identifier: str) -> str:
    """docs/databases.md#connecting: what the site's code uses; never a secret."""
    name = principal(identifier)
    if engine == DatabaseEngine.MARIADB:
        return (
            f"The site connects through the socket {MARIADB_SOCKET} to the database {name} as "
            f"the user {name} with no password, for example with the PDO DSN "
            f"mysql:unix_socket={MARIADB_SOCKET};dbname={name} and a null password. TCP "
            "connections are refused."
        )
    return (
        f"The site connects through {POSTGRESQL_SOCKET_DIRECTORY} on port {POSTGRESQL_PORT} to "
        f"the database {name} as the user {name} with no password, for example with the PDO "
        f"DSN pgsql:host={POSTGRESQL_SOCKET_DIRECTORY};port={POSTGRESQL_PORT};dbname={name}. "
        "TCP connections are refused."
    )
