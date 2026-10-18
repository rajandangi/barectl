"""The native body that creates one site's database binding (docs/databases.md).

Executed on the target as root by the change engine's staged payload, which already holds
the mutation lock and admitted the review. It revalidates the site and catalog the review
read, publishes the pool probe, proves the driver through the site's own master, runs the
reviewed statements one by one, and proves the finished binding. Nothing it does is undone.
"""

import base64
import gzip
import hashlib
import json
import os
import pathlib
import pwd
import shlex
import signal
import stat
import subprocess
import sys
from typing import Final

MARIADB: Final = "mariadb"
POSTGRESQL: Final = "postgresql"
# Every fact a satisfied binding must read as "1", and every exposure fact as "0".
SATISFIED: Final[dict[str, str]] = {
    "principal": "1",
    "account": "1",
    "database": "1",
    "schema_any": "1",
    "privileges": "1",
    "schema": "1",
    "exposures": "0",
    "grant_option": "0",
}
MARIADB_SOCKET: Final = "/run/mysqld/mysqld.sock"
STEP_REASON: Final[dict[str, str]] = {
    "principal": "site_database_principal",
    "database": "site_database_database",
    "privileges": "site_database_privileges",
    "schema": "site_database_schema",
}
_stopped = False


def result(outcome: str, reason: str = "") -> None:
    value = {"class": outcome}
    if reason:
        value["reason"] = reason
    sys.stdout.write("barectl-result " + json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def stage(value: str) -> None:
    sys.stdout.write("barectl-stage " + value + "\n")
    sys.stdout.flush()


def on_term(_signum: int, _frame: object) -> None:
    result("timed_out")
    sys.exit(3)


def run(args: list[str], *, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - fixed native argv from the reviewed document
        args, input=stdin, capture_output=True, timeout=120, check=False
    )


def shell(command: str) -> str:
    completed = subprocess.run(  # noqa: S603 - the reviewed fixed read
        ["/bin/sh", "-c", command], capture_output=True, timeout=120, check=False
    )
    return completed.stdout.decode("utf-8", "replace")


def read_facts(document: dict[str, object]) -> str:
    return shell(str(document["read_command"]))


def facts_satisfied(text: str) -> bool:
    seen: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("\t")
        if not separator:
            key, separator, value = line.partition("|")
        if separator and key in SATISFIED:
            seen[key] = value
    return all(seen.get(key, "0") == value for key, value in SATISFIED.items())


def admin_argv(engine: str, database: str, statement: str) -> list[str]:
    if engine == MARIADB:
        return [
            "/usr/bin/mariadb",
            "--no-defaults",
            "--protocol=socket",
            f"--socket={MARIADB_SOCKET}",
            "--user=root",
            "-e",
            statement,
        ]
    psql = ["/usr/bin/psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", database, "-c", statement]
    if database == "postgres":
        return ["/usr/bin/su", "-", "postgres", "-c", shlex.join(psql)]
    return ["/usr/sbin/runuser", "-u", database, "--", *psql]


def publish_probe(document: dict[str, object]) -> bool:
    path = pathlib.Path(str(document["probe_path"]))
    parent = path.parent
    try:
        metadata = parent.lstat()
    except OSError:
        return False
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        return False
    contents = str(document["probe_source"]).encode()
    if hashlib.sha256(contents).hexdigest() != document["probe_sha256"]:
        return False
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(contents)
            os.fsync(output.fileno())
        account = pwd.getpwnam(str(document["principal"]))
        os.chown(path, 0, account.pw_gid)
        os.chmod(path, 0o640)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return True


def remove_probe(document: dict[str, object]) -> bool:
    path = pathlib.Path(str(document["probe_path"]))
    try:
        if not stat.S_ISREG(path.lstat().st_mode) or path.is_symlink():
            return False
        if hashlib.sha256(path.read_bytes()).hexdigest() != document["probe_sha256"]:
            return False
        path.unlink()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return True


def probe(document: dict[str, object], query: str) -> str:
    request = "/probe.php" + (f"?{query}" if query else "")
    completed = run(
        [
            "/usr/bin/timeout",
            "6",
            "/usr/bin/env",
            "-i",
            f"SCRIPT_FILENAME={document['probe_path']}",
            "SCRIPT_NAME=/probe.php",
            "REQUEST_METHOD=GET",
            f"QUERY_STRING={query}",
            f"REQUEST_URI={request}",
            f"{document['fcgi_path']}/bin/cgi-fcgi",
            "-bind",
            "-connect",
            str(document["app_socket"]),
        ]
    )
    text = completed.stdout.decode("utf-8", "replace").replace("\r\n", "\n")
    return text.partition("\n\n")[2].strip()


def site_changed(document: dict[str, object]) -> bool:
    observed = hashlib.sha256(shell(str(document["site_read_command"])).encode()).hexdigest()
    return observed != document["site_digest"]


def refuse(document: dict[str, object], reason: str) -> int:
    remove_probe(document)
    result("refused", reason)
    return 1


def partial(document: dict[str, object], reason: str) -> int:
    remove_probe(document)
    result("partial", reason)
    return 2


def preflight(document: dict[str, object]) -> str:
    if os.geteuid() != 0:
        return "privilege"
    if str(document.get("engine")) not in (MARIADB, POSTGRESQL):
        return "site_database"
    if site_changed(document):
        return "precondition"
    if hashlib.sha256(read_facts(document).encode()).hexdigest() != document["catalog_digest"]:
        return "precondition"
    if os.path.realpath("/nix/var/nix/profiles/barectl/fcgi") != document["fcgi_path"]:
        return "runtime_cache"
    return ""


def apply_statements(document: dict[str, object]) -> str:
    statements = document["statements"]
    if not isinstance(statements, list):
        return "site_database"
    for entry in statements:
        if (
            not isinstance(entry, list)
            or len(entry) != 3
            or not all(isinstance(value, str) for value in entry)
        ):
            return "site_database"
        step, database, text = str(entry[0]), str(entry[1]), str(entry[2])
        stage(step)
        if run(admin_argv(str(document["engine"]), database, text)).returncode != 0:
            return STEP_REASON.get(step, "site_database_after")
    return ""


def prove(document: dict[str, object]) -> str:
    stage("verify")
    if not facts_satisfied(read_facts(document)):
        return "site_database_after"
    if probe(document, "") != document["expected_full"]:
        return "site_database_proof"
    return ""


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        return 3
    document: dict[str, object] = json.loads(gzip.decompress(base64.b64decode(argv[1])))
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    stage("preflight")
    reason = preflight(document)
    if reason:
        return refuse(document, reason)
    if not publish_probe(document):
        return refuse(document, "site_database")
    stage("probe")
    observed_pre = probe(document, "pre")
    if observed_pre != document["expected_pre"]:
        return refuse(document, "site_database_driver")
    reason = apply_statements(document)
    if reason:
        return partial(document, reason)
    reason = prove(document)
    if reason:
        return partial(document, reason)
    if not remove_probe(document):
        return partial(document, "site_database_probe")
    result("succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
