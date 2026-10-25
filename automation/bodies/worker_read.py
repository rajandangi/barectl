"""One bounded privileged read of a Laravel site's activation (Phase C #266).

Run as ``python3 -c <source> <identifier> <host>``. It reads the site's CLI build, its
database and its own health endpoint through the private proxy connection, and prints one
JSON object. It never prints an application value and never writes anything.
"""

import json
import pathlib
import re
import socket
import subprocess
import sys

MIGRATION_FILE = re.compile(r"^([0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{6}_[a-z0-9_]+)\.php$")
TIMEOUT = 20
SITE_ROOT = "/var/www"


def _user(argv: list[str], identifier: str, cwd: str) -> subprocess.CompletedProcess[str]:
    environment = {"HOME": f"{SITE_ROOT}/{identifier}", "PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    return subprocess.run(  # noqa: S603 - fixed argv as the site's own user
        ["/usr/sbin/runuser", "-u", f"s{identifier}", "--", *argv],
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )


def _database_argv(identifier: str) -> list[str] | None:
    database = "s" + identifier
    if pathlib.Path("/usr/bin/mariadb").exists():
        return ["/usr/bin/mariadb", database, "--batch", "--skip-column-names", "-e"]
    if pathlib.Path("/usr/bin/psql").exists():
        return ["/usr/bin/psql", "-X", "-t", "-A", "-d", database, "-c"]
    return None


def _migrations(identifier: str, current: pathlib.Path) -> tuple[bool, list[str]]:
    directory = current / "database" / "migrations"
    if not directory.is_dir():
        return True, []
    names = [
        match.group(1)
        for path in sorted(directory.iterdir())
        if path.is_file() and (match := MIGRATION_FILE.match(path.name)) is not None
    ]
    argv = _database_argv(identifier)
    if argv is None:
        return False, names
    completed = _user([*argv, "SELECT migration FROM migrations"], identifier, str(current))
    if completed.returncode:
        return False, names
    recorded = set(completed.stdout.split())
    return True, [name for name in names if name not in recorded]


def _jobs(identifier: str, current: pathlib.Path) -> bool:
    argv = _database_argv(identifier)
    if argv is None:
        return False
    if "/usr/bin/mariadb" in argv[0]:
        statement = (
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema = DATABASE() AND table_name = 'jobs'"
        )
    else:
        statement = "SELECT CASE WHEN to_regclass('public.jobs') IS NULL THEN 0 ELSE 1 END"
    completed = _user([*argv, statement], identifier, str(current))
    return completed.returncode == 0 and completed.stdout.strip() == "1"


def _pcntl(identifier: str, current: pathlib.Path) -> bool:
    php = f"{SITE_ROOT}/{identifier}/bin/php"
    if not pathlib.Path(php).is_file():
        return False
    completed = _user(
        [php, "-r", "echo extension_loaded('pcntl') ? '1' : '0';"], identifier, str(current)
    )
    return completed.returncode == 0 and completed.stdout.strip() == "1"


def _health(identifier: str, host: str) -> int:
    import http.client

    path = f"/run/haproxy/{identifier}/http.sock"
    headers = {
        "Host": host,
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": host,
        "X-Forwarded-Uri": "/up",
    }
    try:
        unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        unix.settimeout(5)
        unix.connect(path)
        connection = http.client.HTTPConnection(host)
        connection.sock = unix
        connection.request("GET", "/index.php/up", headers=headers)
        status = connection.getresponse().status
        connection.close()
        return int(status)
    except OSError, ValueError, http.client.HTTPException:
        return 0


def read(identifier: str, host: str) -> dict[str, object]:
    current = pathlib.Path(SITE_ROOT) / identifier / "current"
    migrations_readable, pending = _migrations(identifier, current)
    return {
        "version": 1,
        "sites": [
            {
                "identifier": identifier,
                "pcntl": _pcntl(identifier, current),
                "jobs": _jobs(identifier, current),
                "pending": pending,
                "migrations_readable": migrations_readable,
                "http": _health(identifier, host),
            }
        ],
    }


if __name__ == "__main__":
    sys.stdout.write(
        json.dumps(read(sys.argv[1], sys.argv[2]), sort_keys=True, separators=(",", ":")) + "\n"
    )
    sys.stdout.flush()
