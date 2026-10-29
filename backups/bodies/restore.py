"""Restore one database recovery point into the site's own database (#400).

The body re-lists the reviewed point under the site's deploy lock, refuses a missing,
incomplete or different-engine-major copy, takes and verifies a database-only safety backup
when the target holds data, then pauses and drains the site exactly as a full capture does.
``restic dump`` is streamed into the site's own engine client as the site user over the
local socket, as the ``s<id>`` principal, never a superuser. Import, data checks and the
site's readiness answer are verified separately before the gate opens. A stop after the
gate leaves the site gated for **Reopen site** (docs/adr/0022, docs/adr/0038).
"""

import base64
import gzip
import http.client
import json
import os
import pwd
import re
import socket
import subprocess
import sys
import time
from types import SimpleNamespace
from typing import Final

from automation.bodies.units import fence, restore
from backups.bodies.native import (
    FAILED,
    HEADROOM_BYTES,
    LOCK_BUSY,
    PARTIAL,
    REFUSED,
    REPOSITORY_ROOT,
    RESTIC_BIN,
    RESTIC_TIME,
    SUCCESS,
    controlled,
    document_result,
    emit_result,
    free_bytes,
    locked_file,
    restic,
    restic_environment,
    safe_config,
    site_lock,
    snapshots,
)
from backups.bodies.paused import (
    APPLICATIONS,
    drain,
    open_file,
    open_site,
    publish_gate,
    site_settings,
)
from sites.bodies.common import stage
from sites.names import readiness_ok

IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}")
POINT = re.compile(r"[0-9a-f]{16}")
SNAPSHOT = re.compile(r"[0-9a-f]{64}")
MARIADB_SOCKET: Final = "/run/mysqld/mysqld.sock"
READY_SECONDS: Final = 30
HEADER_BYTES: Final = 8192
MARIADB_VERSION = re.compile(r"-- Server version\s+([0-9]+(?:\.[0-9]+)+)")
POSTGRESQL_VERSION = re.compile(r"-- Dumped from database version ([0-9]+(?:\.[0-9]+)+)")
MARIADB_MAJOR = re.compile(r"(?:[0-9]+:)?([0-9]+)\.([0-9]+)")
POSTGRESQL_MAJOR = re.compile(r"(?:[0-9]+:)?([0-9]+)")


def engine_major(engine: str, version: str) -> str:
    """The engine family's major line: MariaDB keeps two components, PostgreSQL one.

    The package version may carry a Debian epoch (``1:11.8.6-5ubuntu0.1``); the dump's
    server line does not. Both name the same major.
    """
    if engine == "postgresql":
        match = POSTGRESQL_MAJOR.match(version)
        return match[1] if match is not None else ""
    match = MARIADB_MAJOR.match(version)
    return match[1] + "." + match[2] if match is not None else ""


def dump_version(engine: str, text: str) -> str:
    pattern = POSTGRESQL_VERSION if engine == "postgresql" else MARIADB_VERSION
    match = pattern.search(text)
    return match[1] if match is not None else ""


def dump_argv(snapshot: str, filename: str) -> list[str]:
    return [RESTIC_BIN, "dump", "--no-lock", snapshot, "/" + filename.lstrip("/")]


def count_sql(engine: str) -> str:
    if engine == "mariadb":
        return (
            "SELECT COUNT(*) FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE'"
        )
    return (
        "SELECT COUNT(*) FROM information_schema.tables "
        "WHERE table_schema='public' AND table_type='BASE TABLE'"
    )


def count_argv(engine: str, identifier: str) -> list[str]:
    name = "s" + identifier
    if engine == "mariadb":
        return [
            "/usr/sbin/runuser",
            "-u",
            name,
            "--",
            "/usr/bin/mariadb",
            "--no-defaults",
            "--protocol=socket",
            f"--socket={MARIADB_SOCKET}",
            f"--user={name}",
            "-N",
            "-B",
            "-e",
            count_sql(engine),
            name,
        ]
    return [
        "/usr/sbin/runuser",
        "-u",
        name,
        "--",
        "/usr/bin/psql",
        "-X",
        "-A",
        "-t",
        "-q",
        "-d",
        name,
        "-c",
        count_sql(engine),
    ]


def import_argv(engine: str, identifier: str) -> list[str]:
    name = "s" + identifier
    if engine == "mariadb":
        return [
            "/usr/sbin/runuser",
            "-u",
            name,
            "--",
            "/usr/bin/mariadb",
            "--no-defaults",
            "--protocol=socket",
            f"--socket={MARIADB_SOCKET}",
            f"--user={name}",
        ]
    return [
        "/usr/sbin/runuser",
        "-u",
        name,
        "--",
        "/usr/bin/psql",
        "-X",
        "-q",
        "-v",
        "ON_ERROR_STOP=1",
        "-d",
        name,
    ]


def import_preamble(engine: str, identifier: str) -> bytes:
    """Replace the site's own database, never a superuser or another site's data.

    The site principal owns its database and schema, so the reviewed import starts from an
    empty one and cannot leave a table or view the recovery point did not contain.
    """
    name = "s" + identifier
    if engine == "mariadb":
        return (
            "SET FOREIGN_KEY_CHECKS=0;\n"
            f"DROP DATABASE IF EXISTS `{name}`;\n"
            f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n"
            f"USE `{name}`;\n"
        ).encode()
    return (
        b"SET client_min_messages TO warning;\n"
        b"DROP SCHEMA IF EXISTS public CASCADE;\n"
        b"CREATE SCHEMA public;\n"
    )


def count_command(engine: str, identifier: str) -> str:
    return " ".join(_quote(item) for item in count_argv(engine, identifier))


def count_tables(engine: str, identifier: str) -> int | None:
    """The site principal's view of its own tables, or ``None`` when it cannot be read."""
    try:
        completed = subprocess.run(  # noqa: S603 - fixed native argv and validated paths
            count_argv(engine, identifier),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=20,
            check=False,
        )
    except OSError, subprocess.TimeoutExpired:
        return None
    if completed.returncode:
        return None
    text = completed.stdout.decode("ascii", "replace").strip()
    return int(text) if text.isdigit() else None


def _quote(value: str) -> str:
    import shlex

    return shlex.quote(value)


def header_bytes(repository: str, key: str, snapshot: str, filename: str) -> bytes | None:
    process = subprocess.Popen(  # noqa: S603 - fixed native argv and validated paths
        dump_argv(snapshot, filename),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=restic_environment(repository, key),
        start_new_session=True,
    )
    try:
        if process.stdout is None:
            return None
        output = process.stdout.read(HEADER_BYTES)
    finally:
        process.kill()
        process.wait()
    return output or None


def import_stream(
    repository: str,
    key: str,
    snapshot: str,
    filename: str,
    engine: str,
    identifier: str,
) -> tuple[bool, int]:
    """Stream the dump into the site's engine client, counting the tables it creates."""
    client = subprocess.Popen(  # noqa: S603 - fixed native argv and validated paths
        import_argv(engine, identifier),
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    source = subprocess.Popen(  # noqa: S603 - fixed native argv and validated paths
        dump_argv(snapshot, filename),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=restic_environment(repository, key),
        start_new_session=True,
    )
    expected = 0
    stdin = client.stdin
    stdout = source.stdout
    failed = stdin is None or stdout is None
    try:
        if stdin is not None and stdout is not None:
            stdin.write(import_preamble(engine, identifier))
            stdin.flush()
            for line in stdout:
                if line.startswith(b"CREATE TABLE"):
                    expected += 1
                stdin.write(line)
            stdin.close()
            client.stdin = None
            stdout.close()
            source.stdout = None
    except BrokenPipeError, OSError:
        failed = True
    finally:
        if failed:
            client.kill()
            source.kill()
        source_status = source.wait()
        client_status = client.wait()
    return (not failed and source_status == 0 and client_status == 0), expected


def readiness_request(settings: SimpleNamespace, path: str, original: str) -> int:
    host = str(settings.names[0])
    headers = {
        "Host": host,
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": host,
        "X-Forwarded-Uri": original,
    }
    unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    unix.settimeout(5)
    try:
        unix.connect(f"/run/haproxy/{settings.identifier}/http.sock")
        connection = http.client.HTTPConnection(host)
        connection.sock = unix
        connection.request("GET", path, headers=headers)
        status = connection.getresponse().status
        connection.close()
        return int(status)
    except OSError, ValueError, http.client.HTTPException:
        return 0
    finally:
        unix.close()


def site_ready(settings: SimpleNamespace, application: str) -> bool:
    """The site's own readiness answer through its private path, while the gate is up."""
    deadline = time.monotonic() + READY_SECONDS
    while True:
        if application == "laravel":
            ok = readiness_request(settings, "/index.php", "/up") == 200
        elif application == "wordpress":
            ok = (
                readiness_request(settings, "/index.php", "/") == 200
                and readiness_request(settings, "/wp-login.php", "/wp-login.php") == 200
            )
        else:
            status = readiness_request(settings, settings.readiness, settings.readiness)
            ok = readiness_ok(settings.readiness, status)
        if ok or time.monotonic() >= deadline:
            return ok
        time.sleep(0.5)


def safety_backup(document: dict[str, object], repository: str, key: str) -> bool:
    stage("safety")
    argv = [
        "backup",
        "--json",
        "--stdin-from-command",
        "--stdin-filename",
        str(document.get("filename", "database.sql")),
        "--time",
        str(document.get("safety_restic_time", "")),
    ]
    tags = document.get("safety_tags")
    dump = document.get("dump")
    if not isinstance(tags, list) or not isinstance(dump, list):
        return False
    for tag in tags:
        argv.extend(("--tag", str(tag)))
    argv.append("--")
    argv.extend(str(item) for item in dump)
    status, _output = restic(argv, repository=repository, password=key)
    if status != 0:
        return False
    point = str(document.get("safety_point", ""))
    for row in snapshots(repository, key, point):
        tags = row.get("tags")
        if isinstance(tags, list) and "complete" in tags and "point:" + point in tags:
            return True
    return False


def reviewed_point(document: dict[str, object], repository: str, key: str) -> bool:
    """Re-list under the lock: the exact reviewed database snapshot must be complete."""
    point = str(document.get("point", ""))
    snapshot = str(document.get("snapshot", ""))
    rows = snapshots(repository, key, point)
    found = 0
    for row in rows:
        tags = row.get("tags")
        if not isinstance(tags, list):
            continue
        if "part:database" not in tags or "complete" not in tags:
            continue
        found += 1
        if row.get("id") != snapshot:
            return False
    return found == 1


def main(argument: str | None = None) -> None:  # noqa: C901 - one reviewed restore
    encoded = sys.argv[1] if argument is None else argument
    document = json.loads(gzip.decompress(base64.b64decode(encoded)))
    identifier = str(document.get("identifier", ""))
    repository = str(document.get("repository", ""))
    key = str(document.get("server_key", ""))
    point = str(document.get("point", ""))
    snapshot = str(document.get("snapshot", ""))
    filename = str(document.get("filename", ""))
    engine = str(document.get("engine", ""))
    major = str(document.get("engine_major", ""))
    application = str(document.get("application", ""))
    scope = str(document.get("scope", ""))
    at = str(document.get("at", ""))
    if (
        IDENTIFIER.fullmatch(identifier) is None
        or repository != f"{REPOSITORY_ROOT}/{identifier}/onsite"
        or not key.startswith("/etc/barectl/backups/")
        or POINT.fullmatch(point) is None
        or SNAPSHOT.fullmatch(snapshot) is None
        or engine not in ("mariadb", "postgresql")
        or not major
        or application not in APPLICATIONS
        or scope != "database"
        or RESTIC_TIME.fullmatch(str(document.get("restic_time", ""))) is None
        or not at
        or type(document.get("point_size")) is not int
    ):
        emit_result({"class": "failed"})
        raise SystemExit(FAILED)
    stage("preflight")
    try:
        account = pwd.getpwnam("s" + identifier)
    except KeyError:
        emit_result(
            document_result(
                document,
                "refused",
                "restore_site",
                point=point,
                snapshots=0,
                size=0,
                kind="restore",
            )
        )
        raise SystemExit(REFUSED) from None
    if account.pw_uid < 1000 or account.pw_uid >= 30000:
        emit_result(
            document_result(
                document,
                "refused",
                "restore_site",
                point=point,
                snapshots=0,
                size=0,
                kind="restore",
            )
        )
        raise SystemExit(REFUSED)
    if (
        not os.path.isfile(os.path.join(repository, "config"))
        or not safe_config(os.path.join(repository, "config"))
        or not locked_file(key, mode=0o600)
        or not controlled(REPOSITORY_ROOT)
        or not os.access(RESTIC_BIN, os.X_OK)
    ):
        emit_result(
            document_result(
                document,
                "refused",
                "restore_repository",
                point=point,
                snapshots=0,
                size=0,
                kind="restore",
            )
        )
        raise SystemExit(REFUSED)
    try:
        settings = site_settings(document)
        if open_file(settings, application) != document.get("caddy"):
            raise ValueError("The site's open configuration changed.")
        if not isinstance(document.get("gate"), str) or not document["gate"]:
            raise ValueError("The restore has no maintenance page.")
    except ValueError:
        emit_result(
            document_result(
                document,
                "refused",
                "restore_evidence",
                point=point,
                snapshots=0,
                size=0,
                kind="restore",
            )
        )
        raise SystemExit(REFUSED) from None
    try:
        lock = site_lock(identifier, account.pw_gid)
    except OSError, ValueError:
        emit_result(
            document_result(
                document,
                "refused",
                "restore_lock",
                point=point,
                snapshots=0,
                size=0,
                kind="restore",
            )
        )
        raise SystemExit(REFUSED) from None
    if lock is None:
        emit_result(
            document_result(
                document,
                "lock_busy",
                "restore_lock",
                point=point,
                snapshots=0,
                size=0,
                kind="restore",
            )
        )
        raise SystemExit(LOCK_BUSY)
    try:
        if free_bytes() < HEADROOM_BYTES + int(str(document.get("point_size", 0))):
            emit_result(
                document_result(
                    document,
                    "refused",
                    "restore_disk",
                    point=point,
                    snapshots=0,
                    size=0,
                    kind="restore",
                )
            )
            raise SystemExit(REFUSED)
        stage("check")
        if not reviewed_point(document, repository, key):
            emit_result(
                document_result(
                    document,
                    "refused",
                    "restore_point",
                    point=point,
                    snapshots=0,
                    size=0,
                    kind="restore",
                )
            )
            raise SystemExit(REFUSED)
        header = header_bytes(repository, key, snapshot, filename)
        if (
            header is None
            or engine_major(engine, dump_version(engine, header.decode("utf-8", "replace")))
            != major
        ):
            emit_result(
                document_result(
                    document,
                    "refused",
                    "restore_engine",
                    point=point,
                    snapshots=0,
                    size=0,
                    kind="restore",
                )
            )
            raise SystemExit(REFUSED)
        empty = count_tables(engine, identifier)
        if empty is None or (empty == 0) != bool(document.get("target_empty")):
            emit_result(
                document_result(
                    document,
                    "refused",
                    "restore_target",
                    point=point,
                    snapshots=0,
                    size=0,
                    kind="restore",
                )
            )
            raise SystemExit(REFUSED)
        if not bool(document.get("target_empty")) and not safety_backup(document, repository, key):
            emit_result(
                document_result(
                    document,
                    "refused",
                    "restore_safety",
                    point=point,
                    snapshots=0,
                    size=0,
                    kind="restore",
                )
            )
            raise SystemExit(REFUSED)
        if not fence(document, identifier, gate=True):
            emit_result(
                document_result(
                    document,
                    "refused",
                    "automation_fence",
                    point=point,
                    snapshots=0,
                    size=0,
                    kind="restore",
                )
            )
            raise SystemExit(REFUSED)
        stage("gate")
        try:
            gate_up = publish_gate(settings, document)
        except OSError, ValueError:
            gate_up = False
        if not gate_up:
            if not restore(document, identifier):
                emit_result(
                    document_result(
                        document,
                        "partial",
                        "automation_restore",
                        point=point,
                        snapshots=0,
                        size=0,
                        kind="restore",
                    )
                )
                raise SystemExit(PARTIAL)
            emit_result(
                document_result(
                    document,
                    "refused",
                    "restore_gate",
                    point=point,
                    snapshots=0,
                    size=0,
                    kind="restore",
                )
            )
            raise SystemExit(REFUSED)
        emit_result(
            document_result(
                document,
                "partial",
                "restore_paused",
                point=point,
                snapshots=0,
                size=0,
                kind="restore",
            )
        )
        stage("drain")
        try:
            drained = drain(settings)
        except OSError, ValueError:
            drained = False
        if not drained:
            emit_result(
                document_result(
                    document,
                    "partial",
                    "restore_idle",
                    point=point,
                    snapshots=0,
                    size=0,
                    kind="restore",
                )
            )
            raise SystemExit(PARTIAL)
        stage("import")
        imported, expected = import_stream(repository, key, snapshot, filename, engine, identifier)
        if not imported:
            emit_result(
                document_result(
                    document,
                    "partial",
                    "restore_import",
                    point=point,
                    snapshots=1,
                    size=0,
                    kind="restore",
                )
            )
            raise SystemExit(PARTIAL)
        stage("checks")
        actual = count_tables(engine, identifier)
        if actual is None or actual != expected:
            emit_result(
                document_result(
                    document,
                    "partial",
                    "restore_data",
                    point=point,
                    snapshots=1,
                    size=0,
                    kind="restore",
                )
            )
            raise SystemExit(PARTIAL)
        stage("readiness")
        if not site_ready(settings, application):
            emit_result(
                document_result(
                    document,
                    "partial",
                    "restore_readiness",
                    point=point,
                    snapshots=1,
                    size=0,
                    kind="restore",
                )
            )
            raise SystemExit(PARTIAL)
        stage("open")
        try:
            opened = open_site(settings, document)
        except OSError, ValueError:
            opened = False
        if not opened:
            emit_result(
                document_result(
                    document,
                    "partial",
                    "restore_open",
                    point=point,
                    snapshots=1,
                    size=0,
                    kind="restore",
                )
            )
            raise SystemExit(PARTIAL)
        if not restore(document, identifier):
            emit_result(
                document_result(
                    document,
                    "partial",
                    "automation_restore",
                    point=point,
                    snapshots=1,
                    size=0,
                    kind="restore",
                )
            )
            raise SystemExit(PARTIAL)
        emit_result(
            document_result(
                document,
                "succeeded",
                "restore_done",
                point=point,
                snapshots=1,
                size=int(str(document.get("point_size", 0))),
                kind="restore",
            )
        )
        raise SystemExit(SUCCESS)
    finally:
        os.close(lock)


if __name__ == "__main__":
    main()
