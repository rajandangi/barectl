"""MariaDB and PostgreSQL commands an administrator runs by hand inside the disposable server,
for the native acceptance tests (docs/databases.md)."""

import shlex
import subprocess

from discovery.native_testing import setting

MARIADB = "mariadb --no-defaults -N -B -e"
PSQL = "runuser -u postgres -- psql -X -q -v ON_ERROR_STOP=1"
PRIVILEGES = (
    "SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES, "
    "CREATE TEMPORARY TABLES, LOCK TABLES"
)


def mariadb(statement: str) -> str:
    return f"{MARIADB} {shlex.quote(statement)}"


def psql(statement: str, database: str = "postgres") -> str:
    return f"{PSQL} -d {database} -c {shlex.quote(statement)}"


# The convention's statements (docs/site-conventions.md#database-convention), as an
# administrator runs them by hand.
def mariadb_binding(name: str) -> tuple[str, ...]:
    return (
        mariadb(f"CREATE USER `{name}`@`localhost` IDENTIFIED VIA unix_socket"),
        mariadb(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"),
        mariadb(f"GRANT {PRIVILEGES} ON `{name}`.* TO `{name}`@`localhost`"),
    )


def postgresql_binding(name: str) -> tuple[str, ...]:
    return (
        psql(f'CREATE ROLE "{name}" LOGIN'),
        psql(
            f'CREATE DATABASE "{name}" WITH OWNER "{name}" TEMPLATE template0 '
            "ENCODING 'UTF8' LOCALE_PROVIDER libc LC_COLLATE 'C.UTF-8' LC_CTYPE 'C.UTF-8'"
        ),
        psql(f'REVOKE CONNECT, TEMPORARY ON DATABASE "{name}" FROM PUBLIC'),
        psql("REVOKE ALL ON SCHEMA public FROM PUBLIC", name),
    )


def drop(name: str) -> str:
    return "; ".join(
        (
            mariadb(f"DROP DATABASE IF EXISTS `{name}`"),
            mariadb(f"DROP USER IF EXISTS `{name}`@`localhost`"),
            psql(f'DROP DATABASE IF EXISTS "{name}"'),
            psql(f'DROP ROLE IF EXISTS "{name}"'),
            "true",
        )
    )


def docker(script: str) -> str:
    return subprocess.run(  # noqa: S603 - the tests' own fixture scripts
        ["docker", "exec", setting("CONTAINER"), "sh", "-c", script],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
        timeout=600,
    ).stdout
