"""Restore a recovery point into a site (#400, #401).

The body re-lists the reviewed point under the site's deploy lock, refuses a missing,
incomplete or different-engine-major copy, takes and verifies a safety backup in the restore's
own scope, restores the files into private staging and admits them there before touching the
site, then pauses and drains the site exactly as a full capture does. Files become a new
site-owned release with the convention's permission classification and the native
configuration is re-rendered from the convention, never from the archive. ``restic dump`` is
streamed into the site's own engine client as the site user over the local socket, as the
``s<id>`` principal, never a superuser. Import, data checks and the site's readiness answer
are verified separately before the gate opens. A stop after the gate leaves the site gated
for **Reopen site** (docs/adr/0022, docs/adr/0038, docs/adr/0040).
"""

import base64
import contextlib
import gzip
import http.client
import json
import os
import pathlib
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from typing import Final

from automation.bodies.units import fence, restore
from backups.bodies.native import (
    FAILED,
    HEADROOM_BYTES,
    KEY_ROOT,
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
    environment_file,
    free_bytes,
    locked_file,
    offsite_extra,
    repository_locks,
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
from sites.bodies.admission import hap_validate
from sites.bodies.common import (
    known_redis,
    reload_site_fpm,
    site_client,
    site_fpm_files,
    stage,
)
from sites.names import readiness_ok
from sites.serving import haproxy_config

IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}")
POINT = re.compile(r"[0-9a-f]{16}")
SNAPSHOT = re.compile(r"[0-9a-f]{64}")
RELEASE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
SCOPES = ("database", "files", "full")
# The private state beside a release, replaced as a whole rather than overlaid (#358).
SHARED = {
    "laravel": ("private/laravel.env", "private/storage", "private/cache"),
    "wordpress": ("private/wp-config.php",),
    "plain": (),
}
STAGE_ROOT: Final = "/var/lib/barectl-restore"
OFFSITE_CAPTURE: Final = "/etc/barectl/backups/offsite/capture.env"
MARIADB_SOCKET: Final = "/run/mysqld/mysqld.sock"
READY_SECONDS: Final = 30
HEADER_BYTES: Final = 8192
DUMP_TAIL_BYTES: Final = 65536
RESTORE_LOCK_WAIT_SECONDS: Final = 5.0
DUMP_COMPLETE: Final = {
    "mariadb": b"-- Dump completed",
    "postgresql": b"-- PostgreSQL database dump complete",
}
MARIADB_VERSION = re.compile(r"-- Server version\s+([0-9]+(?:\.[0-9]+)+)")
POSTGRESQL_VERSION = re.compile(r"-- Dumped from database version ([0-9]+(?:\.[0-9]+)+)")
MARIADB_MAJOR = re.compile(r"(?:[0-9]+:)?([0-9]+)\.([0-9]+)")
POSTGRESQL_MAJOR = re.compile(r"(?:[0-9]+:)?([0-9]+)")
SETUID: Final = stat.S_ISUID | stat.S_ISGID
WP_DATABASE: Final = (
    "ABSPATH",
    "DB_NAME",
    "DB_USER",
    "DB_PASSWORD",
    "DB_HOST",
    "DB_CHARSET",
    "DB_COLLATE",
)
WP_SALTS: Final = (
    "AUTH_KEY",
    "SECURE_AUTH_KEY",
    "LOGGED_IN_KEY",
    "NONCE_KEY",
    "AUTH_SALT",
    "SECURE_AUTH_SALT",
    "LOGGED_IN_SALT",
    "NONCE_SALT",
)
WP_TABLE_PREFIX: Final = re.compile(r"\$table_prefix = '[A-Za-z0-9_]{1,64}';")


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


def dump_argv(snapshot: str, filename: str, repository: str = "") -> list[str]:
    # restic selects virtual-hosted URLs for Amazon endpoints; Barectl's templates and the
    # connected source repositories are path-style, the same option every other call uses.
    options = ["-o", "s3.bucket-lookup=path"] if repository.startswith("s3:") else []
    return [RESTIC_BIN, *options, "dump", "--no-lock", snapshot, "/" + filename.lstrip("/")]


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


def write_dump(
    repository: str,
    key: str,
    snapshot: str,
    filename: str,
    target: pathlib.Path,
    extra: dict[str, str] | None = None,
) -> bool:
    """Download one whole dump into the private stage before the site is touched."""
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            process = subprocess.Popen(  # noqa: S603 - fixed native argv and validated paths
                dump_argv(snapshot, filename, repository),
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.DEVNULL,
                env=restic_environment(repository, key, extra),
                start_new_session=True,
            )
            status = process.wait()
            output.flush()
            os.fsync(output.fileno())
    finally:
        with contextlib.suppress(OSError):
            os.close(descriptor)
    return status == 0 and target.is_file() and target.stat().st_size > 0


def dump_problem(engine: str, path: pathlib.Path, major: str) -> str:
    """Why a staged dump cannot be imported, or "" when it is complete and same-major."""
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            header = handle.read(HEADER_BYTES)
            handle.seek(max(0, size - DUMP_TAIL_BYTES))
            tail = handle.read()
    except OSError:
        return "restore_repository"
    if engine_major(engine, dump_version(engine, header.decode("utf-8", "replace"))) != major:
        return "restore_engine"
    if DUMP_COMPLETE[engine] not in tail:
        return "restore_dump"
    return ""


def import_staged(path: pathlib.Path, engine: str, identifier: str) -> tuple[bool, int]:
    """Import one validated private dump as the site principal, counting its tables."""
    client = subprocess.Popen(  # noqa: S603 - fixed native argv and validated paths
        import_argv(engine, identifier),
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    expected = 0
    stdin = client.stdin
    failed = stdin is None
    try:
        if stdin is not None:
            stdin.write(import_preamble(engine, identifier))
            stdin.flush()
            with path.open("rb") as source:
                for line in source:
                    if line.startswith(b"CREATE TABLE"):
                        expected += 1
                    stdin.write(line)
            stdin.close()
            client.stdin = None
    except BrokenPipeError, OSError:
        failed = True
    finally:
        if failed:
            client.kill()
        client_status = client.wait()
    return (not failed and client_status == 0), expected


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
            # The same /up path Deploy verifies: the front controller receives PATH_INFO and
            # the original path, and a redirect or any non-200 answer fails the check.
            ok = readiness_request(settings, "/index.php/up", "/up") == 200
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


def expected_parts(document: dict[str, object]) -> list[str]:
    parts: list[str] = []
    if document.get("snapshot"):
        parts.append("database")
    if document.get("files_snapshot"):
        parts.append("files")
    return parts


def reviewed_files(settings: SimpleNamespace, application: str) -> list[str]:
    """The target's release and private state, exactly as the review bound them."""
    directory = pathlib.Path(settings.directory)
    current = directory / "current"
    if not current.is_symlink():
        raise ValueError("The site has no current release.")
    target = pathlib.Path(os.path.realpath(current))
    if target.parent != directory / "releases" or not target.is_dir():
        raise ValueError("The site's current release is outside the convention.")
    shared: list[str] = []
    for relative in SHARED[application]:
        path = directory / relative
        if path.is_symlink() or not path.exists():
            raise ValueError("The site's private files are incomplete.")
        shared.append(str(path))
    return [str(current), *shared]


def _safety_backup(  # noqa: C901 - one reviewed safety capture
    document: dict[str, object], repository: str, key: str, settings: SimpleNamespace
) -> bool:
    """Write and verify the reviewed safety point in the restore's own scope."""
    tags = document.get("safety_tags")
    if not isinstance(tags, dict):
        return False
    at = str(document.get("safety_restic_time", ""))
    for part in sorted(tags):
        argv = ["backup", "--json", "--time", at]
        for tag in tags[part]:
            argv.extend(("--tag", str(tag)))
        if part == "database":
            argv.extend(
                (
                    "--stdin-from-command",
                    "--stdin-filename",
                    str(document.get("filename", "database.sql")),
                    "--",
                )
            )
            dump = document.get("dump")
            if not isinstance(dump, list):
                return False
            argv.extend(str(item) for item in dump)
        else:
            files = document.get("files")
            if not isinstance(files, list) or not files:
                return False
            current = pathlib.Path(str(files[0]))
            if current.name != "current" or not current.is_symlink():
                return False
            release = pathlib.Path(os.path.realpath(current))
            if release.parent != current.parent / "releases" or not release.is_dir():
                return False
            argv.extend([str(release), *(str(item) for item in files[1:])])
        status, _output = restic(argv, repository=repository, password=key)
        if status != 0:
            return False
    point = str(document.get("safety_point", ""))
    found: set[str] = set()
    for row in snapshots(repository, key, point):
        row_tags = row.get("tags")
        if not isinstance(row_tags, list) or "complete" not in row_tags:
            continue
        part = next(
            (
                tag.removeprefix("part:")
                for tag in row_tags
                if isinstance(tag, str) and tag.startswith("part:")
            ),
            "",
        )
        if part in tags:
            found.add(part)
    return found == set(tags)


def reviewed_point(
    document: dict[str, object],
    repository: str,
    key: str,
    extra: dict[str, str] | None = None,
) -> bool:
    """Re-list under the lock: each reviewed snapshot must still be complete and exact."""
    point = str(document.get("point", ""))
    parts = expected_parts(document)
    rows = snapshots(repository, key, point, extra)
    found: dict[str, str] = {}
    for row in rows:
        tags = row.get("tags")
        identifier = row.get("id")
        if not isinstance(tags, list) or not isinstance(identifier, str):
            continue
        if "complete" not in tags:
            continue
        part = next(
            (
                tag.removeprefix("part:")
                for tag in tags
                if isinstance(tag, str) and tag.startswith("part:")
            ),
            "",
        )
        if part not in parts or part in found:
            continue
        found[part] = identifier
    if set(found) != set(parts):
        return False
    expected = {
        "database": str(document.get("snapshot", "")),
        "files": str(document.get("files_snapshot", "")),
    }
    return all(found[part] == expected[part] for part in parts)


def _link_target_problem(
    path: pathlib.Path, target: str, base: pathlib.Path, identifier: str
) -> bool:
    """Whether one staged link stays inside the convention's own paths."""
    if not target or "\x00" in target:
        return True
    relative = path.relative_to(base)
    if target.startswith("/"):
        private = f"/var/www/{identifier}/private"
        allowed = {
            (".env",): f"{private}/laravel.env",
            ("storage",): f"{private}/storage",
            ("bootstrap", "cache"): f"{private}/cache",
        }
        if len(relative.parts) < 2 or relative.parts[0] != "releases":
            return True
        return allowed.get(tuple(relative.parts[2:])) != target
    try:
        resolved = pathlib.Path(os.path.realpath(path.parent / target))
    except OSError, RuntimeError:
        return True
    return resolved != base and base not in resolved.parents


def _admitted_tree(base: pathlib.Path, target: str) -> None:
    """Refuse traversal, foreign links, devices, FIFOs, sockets, setuid and setgid."""
    for root, directories, files in os.walk(base, followlinks=False):
        here = pathlib.Path(root)
        for name in (*directories, *files):
            path = here / name
            relative = path.relative_to(base)
            if any(part in ("", ".", "..") or "/" in part for part in relative.parts):
                raise ValueError("The recovery point holds an unsupported path.")
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                if _link_target_problem(path, os.readlink(path), base, target):
                    raise ValueError("The recovery point holds a link outside the convention.")
                continue
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise ValueError("The recovery point holds a device, FIFO or socket.")
            # A directory may keep the convention's own setgid bit (public is 2750);
            # setuid and setgid on a regular file are never admitted.
            if stat.S_ISREG(info.st_mode) and info.st_mode & SETUID:
                raise ValueError("The recovery point holds a setuid or setgid file.")


def admitted(  # noqa: C901 - one closed admission
    stage_directory: pathlib.Path, identifier: str, application: str, target: str = ""
) -> dict[str, object]:
    """Admit one staged file point, returning its release and private state.

    ``identifier`` is the site the point was taken from and ``target`` the site it becomes;
    a removed site's point therefore keeps no absolute link into its old directory (#407).
    """
    if application not in APPLICATIONS:
        raise ValueError("The site's application is not supported.")
    base = stage_directory / "var" / "www" / identifier
    if base.is_symlink() or not base.is_dir():
        raise ValueError("The recovery point has no site directory.")
    _admitted_tree(base, target or identifier)
    entries = {entry.name for entry in base.iterdir()}
    allowed = {"releases", "private"} if SHARED[application] else {"releases"}
    if entries != allowed:
        raise ValueError("The recovery point holds files outside the site convention.")
    releases = base / "releases"
    if releases.is_symlink() or not releases.is_dir():
        raise ValueError("The recovery point has no release directory.")
    names = [entry.name for entry in releases.iterdir()]
    if len(names) != 1 or RELEASE.fullmatch(names[0]) is None:
        raise ValueError("The recovery point does not hold exactly one release.")
    release = releases / names[0]
    if release.is_symlink() or not release.is_dir():
        raise ValueError("The recovery point's release is not a directory.")
    if not (release / "public").is_dir() or (release / "public").is_symlink():
        raise ValueError("The recovery point's release has no public directory.")
    shared: dict[str, pathlib.Path] = {}
    if SHARED[application]:
        private = base / "private"
        if private.is_symlink() or not private.is_dir():
            raise ValueError("The recovery point has no private directory.")
        relative = {path.split("/", 1)[1]: path for path in SHARED[application]}
        if {entry.name for entry in private.iterdir()} != set(relative):
            raise ValueError("The recovery point's private files are incomplete.")
        for name, path in relative.items():
            staged = private / name
            expected = private / path.split("/")[-1]
            if staged != expected or staged.is_symlink():
                raise ValueError("The recovery point's private files are outside the convention.")
            if path.endswith(("laravel.env", "wp-config.php")):
                if not staged.is_file():
                    raise ValueError("The recovery point's private configuration is missing.")
            elif not staged.is_dir():
                raise ValueError("The recovery point's private directory is missing.")
            shared[path] = staged
    if application == "laravel" and not (release / "artisan").is_file():
        raise ValueError("The recovery point is not a supported Laravel release.")
    return {"release": release, "shared": shared, "base": base}


def _private(settings: SimpleNamespace) -> pathlib.Path:
    return pathlib.Path(settings.directory) / "private"


def _place_private(path: pathlib.Path, owner: int, group: int) -> None:
    for root, directories, files in os.walk(path, followlinks=False):
        here = pathlib.Path(root)
        for name in directories:
            entry = here / name
            if entry.is_symlink():
                os.lchown(entry, owner, group)
                continue
            os.chown(entry, owner, group)
            os.chmod(entry, 0o700)
        for name in files:
            entry = here / name
            if entry.is_symlink():
                os.lchown(entry, owner, group)
                continue
            os.chown(entry, owner, group)
            os.chmod(entry, 0o600)
    os.chown(path, owner, group)
    os.chmod(path, 0o700)


def classify_release(
    release: pathlib.Path, application: str, owner: int, group: int, caddy: int
) -> None:
    """Re-apply the convention's classification, never the archive's modes (#380, #421)."""
    public = release / "public"
    wordpress = application == "wordpress"
    for root, directories, files in os.walk(release, followlinks=False):
        here = pathlib.Path(root)
        public_below = here == public or public in here.parents
        for name in directories:
            path = here / name
            if path.is_symlink():
                os.lchown(path, owner, group)
                continue
            if path == public or public_below or wordpress:
                os.chown(path, owner, caddy)
                os.chmod(path, 0o2750)  # noqa: S103 - the root Caddy serves from
            else:
                os.chown(path, owner, group)
                os.chmod(path, 0o711)  # noqa: S103 - traversal only
        for name in files:
            path = here / name
            if path.is_symlink():
                os.lchown(path, owner, group)
                continue
            if wordpress or (public_below and path.suffix != ".php"):
                os.chown(path, owner, caddy)
                os.chmod(path, 0o640)
            else:
                os.chown(path, owner, group)
                os.chmod(path, 0o600)
    os.chown(release, owner, group)
    os.chmod(release, 0o711)  # noqa: S103 - the site user's release, traversal only


def merge_private_configuration(text: str, target: str, identifier: str) -> str:
    """The point's application state, with the target's own paths and database kept.

    The site database is always ``s<identifier>`` and the public root is the target's, so
    the target's fixed Barectl block comes from the live file. The point supplies only the
    salts, table prefix and operator constants that follow it. Every line from the point
    must belong to that grammar, so a backup cannot plant arbitrary PHP in the file
    WordPress executes next.
    """
    point_lines = text.splitlines()
    target_lines = target.splitlines()
    point_salt = _salt_start(point_lines, "The recovery point's private configuration")
    target_salt = _salt_start(target_lines, "The site's private configuration")
    written: set[str] = set()
    prefix = False
    for line in point_lines[point_salt:]:
        parsed = _wp_constant(line)
        if parsed is not None:
            key = parsed[0]
            if key in WP_DATABASE or key in written:
                raise ValueError("The recovery point's private configuration is not supported.")
            written.add(key)
            continue
        if WP_TABLE_PREFIX.fullmatch(line) is not None and not prefix:
            prefix = True
            continue
        raise ValueError("The recovery point's private configuration is not supported.")
    if not prefix or not set(WP_SALTS) <= written:
        raise ValueError("The recovery point's private configuration is not supported.")
    names = [
        parsed
        for line in target_lines[:target_salt]
        if (parsed := _wp_constant(line)) is not None and parsed[0] == "DB_NAME"
    ]
    if names != [("DB_NAME", "s" + identifier)]:
        raise ValueError("The site's private configuration is outside the supported grammar.")
    return "\n".join([*target_lines[:target_salt], *point_lines[point_salt:]]) + "\n"


def _salt_start(lines: list[str], subject: str) -> int:
    for index, line in enumerate(lines):
        parsed = _wp_constant(line)
        if parsed is not None and parsed[0] == WP_SALTS[0]:
            return index
    raise ValueError(f"{subject} has no fixed Barectl block.")


def _wp_constant(line: str) -> tuple[str, str] | None:
    match = re.fullmatch(r"define\( '([A-Z][A-Z0-9_]{0,63})', '(.*)' \);", line.lstrip("\t"))
    return (match[1], match[2]) if match is not None else None


def _replace_tree(  # noqa: C901 - one whole replacement with its rollback
    target: pathlib.Path, staged: pathlib.Path, owner: int, group: int
) -> None:
    """Replace one private directory or file as a whole, never overlaid.

    A directory on an overlayfs lower layer cannot be renamed within its parent (EXDEV),
    so a directory is copied aside and removed before the new tree is renamed into place.
    The copy is the rollback for a failed rename; a file keeps the atomic rename.
    """
    temporary = target.parent / (".restore-" + target.name)
    previous = target.parent / (".replaced-" + target.name)
    for leftover in (temporary, previous):
        if leftover.is_symlink() or leftover.is_file():
            leftover.unlink()
        elif leftover.exists():
            shutil.rmtree(leftover)
    directory = staged.is_dir()
    if directory:
        shutil.copytree(staged, temporary, symlinks=True)
        _place_private(temporary, owner, group)
    else:
        shutil.copyfile(staged, temporary, follow_symlinks=False)
        os.chown(temporary, owner, group)
        os.chmod(temporary, 0o600)
    aside: pathlib.Path | None = None
    if target.is_dir() and not target.is_symlink():
        aside = previous
        shutil.copytree(target, aside, symlinks=True)
        shutil.rmtree(target)
    elif target.is_symlink() or target.exists():
        os.replace(target, previous)
        aside = previous
    try:
        os.replace(temporary, target)
    except OSError:
        if aside is not None:
            if aside.is_dir():
                shutil.copytree(aside, target, symlinks=True)
            else:
                os.replace(aside, target)
        raise
    if aside is not None:
        if aside.is_symlink() or aside.is_file():
            aside.unlink()
        elif aside.exists():
            shutil.rmtree(aside)


def _replace_shared(
    staged: dict[str, pathlib.Path],
    settings: SimpleNamespace,
    application: str,
    owner: int,
    group: int,
) -> None:
    private = _private(settings)
    for relative in SHARED[application]:
        target = pathlib.Path(settings.directory) / relative
        source = staged.get(relative)
        if source is None:
            raise ValueError("The recovery point's private files are incomplete.")
        if application == "wordpress" and relative.endswith("wp-config.php"):
            target_text = target.read_text(encoding="utf-8") if target.is_file() else ""
            merged = merge_private_configuration(
                source.read_text(encoding="utf-8"), target_text, settings.identifier
            )
            temporary = target.parent / (".restore-" + target.name)
            descriptor = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                    output.write(merged)
                    output.flush()
                    os.fsync(output.fileno())
                    os.fchown(output.fileno(), owner, group)
                    os.fchmod(output.fileno(), 0o600)
                os.replace(temporary, target)
            finally:
                pathlib.Path(temporary).unlink(missing_ok=True)
            continue
        _replace_tree(target, source, owner, group)
    if private.is_dir() and application == "laravel":
        for name in ("laravel.env", "storage", "cache"):
            if not (private / name).exists():
                raise ValueError("The site's private files are incomplete.")


def _link_shared(release: pathlib.Path, settings: SimpleNamespace) -> None:
    private = _private(settings)
    for source, name in (
        (".env", "laravel.env"),
        ("storage", "storage"),
        ("bootstrap/cache", "cache"),
    ):
        destination = release / source
        if destination.is_symlink():
            if os.readlink(destination) == str(private / name):
                continue
            raise ValueError("A release shared-state link is outside the convention.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.symlink_to(private / name)


def _switch_current(settings: SimpleNamespace, release: str) -> None:
    current = pathlib.Path(settings.directory) / "current"
    temporary = current.parent / (".current-" + release)
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    temporary.symlink_to("releases/" + release)
    os.replace(temporary, current)


def place(
    staged: dict[str, object],
    settings: SimpleNamespace,
    application: str,
    release_name: str,
    owner: int,
    group: int,
    caddy: int,
) -> pathlib.Path:
    """Publish the admitted files as a new site-owned release and switch ``current``."""
    directory = pathlib.Path(settings.directory)
    target = directory / "releases" / release_name
    if target.exists() or target.is_symlink():
        raise ValueError("The reviewed release already exists.")
    target.mkdir(mode=0o700)
    staged_release = staged.get("release")
    if not isinstance(staged_release, pathlib.Path):
        raise ValueError("The recovery point has no release.")
    shutil.copytree(staged_release, target, symlinks=True, dirs_exist_ok=True)
    if application == "laravel":
        _link_shared(target, settings)
    classify_release(target, application, owner, group, caddy)
    staged_shared = staged.get("shared")
    if not isinstance(staged_shared, dict):
        raise ValueError("The recovery point's private files are incomplete.")
    _replace_shared(staged_shared, settings, application, owner, group)
    _switch_current(settings, release_name)
    return target


def _same(path: pathlib.Path, value: str) -> bool:
    try:
        if path.is_symlink():
            return False
        return path.read_text(encoding="utf-8") == value
    except OSError:
        return False


def _write_root_file(path: pathlib.Path, value: str, mode: int) -> None:
    if path.is_symlink() or not path.parent.is_dir():
        raise ValueError("A native configuration path is outside the convention.")
    descriptor, temporary = tempfile.mkstemp(prefix=".barectl-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
            os.fchown(output.fileno(), 0, 0)
            os.fchmod(output.fileno(), mode)
        os.replace(temporary, path)
    finally:
        pathlib.Path(temporary).unlink(missing_ok=True)


def render_native(settings: SimpleNamespace) -> None:
    """Re-render HAProxy and PHP-FPM from the convention, never from the archive."""
    extension = known_redis(settings.runtime) if site_client(settings) else ""
    changed = False
    for path, value in site_fpm_files(settings, extension).items():
        location = pathlib.Path(path)
        if _same(location, value):
            continue
        _write_root_file(location, value, 0o644)
        changed = True
    haproxy = pathlib.Path(f"/etc/haproxy/sites/{settings.identifier}.cfg")
    value = haproxy_config(settings)
    if not _same(haproxy, value):
        _write_root_file(haproxy, value, 0o600)
        hap_validate(settings.identifier)
    if changed:
        reload_site_fpm(settings)


def files_problem(settings: SimpleNamespace, application: str, release_name: str) -> str:
    """The files finding: the site serves the admitted release and keeps the old one."""
    directory = pathlib.Path(settings.directory)
    current = directory / "current"
    try:
        if current.is_symlink() is False or os.readlink(current) != "releases/" + release_name:
            return "The restored release is not the site's current release."
    except OSError:
        return "The site's current release could not be read."
    release = directory / "releases" / release_name
    if release.is_symlink() or not release.is_dir() or not (release / "public").is_dir():
        return "The restored release is incomplete."
    if application == "laravel":
        for name in (".env", "storage", "bootstrap/cache"):
            link = release / name
            if not link.is_symlink() or not link.resolve().exists():
                return "The restored release's private state is incomplete."
    if application == "wordpress":
        private = directory / "private" / "wp-config.php"
        info = private.lstat() if private.exists() else None
        if (
            info is None
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != release.stat().st_uid
        ):
            return "The restored private configuration is not site-only."
    return ""


def _stage(identifier: str, point: str, suffix: str = "") -> pathlib.Path:
    root = pathlib.Path(STAGE_ROOT)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    directory = root / identifier / (point + suffix)
    if directory.is_symlink() or directory.is_file():
        directory.unlink()
    elif directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(mode=0o700, parents=True)
    os.chmod(directory, 0o700)
    return directory


def _restore_files(
    document: dict[str, object],
    repository: str,
    key: str,
    target: pathlib.Path,
    extra: dict[str, str] | None = None,
) -> bool:
    snapshot = str(document.get("files_snapshot", ""))
    status, _output = restic(
        ["restore", "--no-lock", snapshot, "--target", str(target)],
        repository=repository,
        password=key,
        extra=extra,
    )
    return status == 0


def begin_pause(
    document: dict[str, object],
    settings: SimpleNamespace,
    identifier: str,
    point: str,
) -> tuple[str, str] | None:
    """Fence, publish the gate and drain. Returns a failure result, or None when paused."""
    if not fence(document, identifier, gate=True):
        return ("refused", "automation_fence")
    stage("gate")
    try:
        gate_up = publish_gate(settings, document)
    except OSError, ValueError:
        gate_up = False
    if not gate_up:
        if not restore(document, identifier):
            return ("partial", "automation_restore")
        return ("refused", "restore_gate")
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
        return ("partial", "restore_idle")
    return None


def resume(document: dict[str, object], settings: SimpleNamespace, identifier: str) -> bool:
    try:
        opened = open_site(settings, document)
    except OSError, ValueError:
        opened = False
    if not opened:
        return False
    return restore(document, identifier)


def main(argument: str | None = None) -> None:  # noqa: C901 - one reviewed restore
    encoded = sys.argv[1] if argument is None else argument
    document = json.loads(gzip.decompress(base64.b64decode(encoded)))
    identifier = str(document.get("identifier", ""))
    repository = str(document.get("repository", ""))
    key = str(document.get("server_key", ""))
    safety_repository = str(document.get("safety_repository") or repository)
    safety_key = str(document.get("safety_key") or key)
    point = str(document.get("point", ""))
    scope = str(document.get("scope", ""))
    application = str(document.get("application", ""))
    release = str(document.get("release", ""))
    snapshot = str(document.get("snapshot", ""))
    files_snapshot = str(document.get("files_snapshot", ""))
    engine = str(document.get("engine", ""))
    major = str(document.get("engine_major", ""))
    at = str(document.get("at", ""))
    tags = document.get("safety_tags")
    safety_scope = str(document.get("safety_scope", ""))
    source = str(document.get("source", ""))
    source_storage = document.get("source_storage")
    source_repository = str(document.get("source_repository", ""))
    secret_path = str(document.get("secret_path", ""))
    # A connected offsite source (#408) captures from the source repository with the typed
    # passphrase; a removed site's kept repository (#407) names its own repository and key.
    connected = bool(source) and isinstance(source_storage, dict) and bool(source_storage)
    source_extra: dict[str, str] | None = None
    if connected:
        if (
            IDENTIFIER.fullmatch(source) is None
            or not source_repository.startswith("s3:https://")
            or not isinstance(source_storage, dict)
            or source_storage.get("provider") not in ("s3", "r2")
            or source_repository
            != f"s3:{source_storage.get('endpoint')}/{source_storage.get('bucket')}/"
            f"{source_storage.get('prefix')}/{source}"
            or not secret_path.startswith("/run/barectl/secrets/")
            or not locked_file(secret_path, mode=0o600)
            or document.get("source_application") != application
        ):
            emit_result({"class": "failed"})
            raise SystemExit(FAILED)
        try:
            source_extra = offsite_extra(source_storage, environment_file(OFFSITE_CAPTURE))
        except OSError, ValueError:
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
            raise SystemExit(REFUSED) from None
    capture_repository = source_repository if connected else repository
    capture_key = secret_path if connected else key
    expected_source = identifier if connected else (source or identifier)
    parts = expected_parts(document)
    if (
        IDENTIFIER.fullmatch(identifier) is None
        or (source and IDENTIFIER.fullmatch(source) is None)
        or repository != f"{REPOSITORY_ROOT}/{expected_source}/onsite"
        or key != f"{KEY_ROOT}/{expected_source}.key"
        or safety_repository != f"{REPOSITORY_ROOT}/{identifier}/onsite"
        or safety_key != f"{KEY_ROOT}/{identifier}.key"
        or POINT.fullmatch(point) is None
        or scope not in SCOPES
        or application not in APPLICATIONS
        or RELEASE.fullmatch(release) is None
        or (snapshot and SNAPSHOT.fullmatch(snapshot) is None)
        or (files_snapshot and SNAPSHOT.fullmatch(files_snapshot) is None)
        or (scope == "database" and "database" not in parts)
        or (scope in ("files", "full") and "files" not in parts)
        or (scope == "files" and "database" in parts)
        or RESTIC_TIME.fullmatch(str(document.get("restic_time", ""))) is None
        or not at
        or type(document.get("point_size")) is not int
        or not isinstance(tags, dict)
        or safety_scope not in SCOPES
        or (safety_scope == "full" and set(parts) != {"database", "files"})
        or (safety_scope == "files" and "files" not in parts)
        or (safety_scope == "database" and ("database" not in parts or scope != "database"))
        or type(document.get("target_empty")) is not bool
        or ("database" in parts and engine not in ("mariadb", "postgresql"))
        or ("database" in parts and not major)
        or bool(source_repository) != connected
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
        if document.get("files") != reviewed_files(settings, application):
            raise ValueError("The restore file scope changed.")
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
        repository_lock_list = repository_locks(
            (expected_source, identifier), wait_seconds=RESTORE_LOCK_WAIT_SECONDS
        )
    except OSError, ValueError:
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
        raise SystemExit(REFUSED) from None
    if repository_lock_list is None:
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
    staging: pathlib.Path | None = None
    dump_stage: pathlib.Path | None = None
    dump_path: pathlib.Path | None = None
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
        if not reviewed_point(document, capture_repository, capture_key, source_extra):
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
        # Only a database restore may skip its safety copy, so only it depends on the
        # target already being empty; a full restore always takes the reviewed one.
        if "database" in parts and scope == "database":
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
        # The safety backup matches the restore's scope. A database-only restore takes it
        # live; a files or full restore pauses the site briefly for an exact point.
        if tags:
            if safety_scope == "database":
                stage("safety")
                if not _safety_backup(document, safety_repository, safety_key, settings):
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
            else:
                failure = begin_pause(document, settings, identifier, point)
                if failure is not None:
                    emit_result(
                        document_result(
                            document,
                            failure[0],
                            failure[1],
                            point=point,
                            snapshots=0,
                            size=0,
                            kind="restore",
                        )
                    )
                    raise SystemExit(PARTIAL if failure[0] == "partial" else REFUSED)
                stage("safety")
                backed_up = _safety_backup(document, safety_repository, safety_key, settings)
                if not resume(document, settings, identifier):
                    emit_result(
                        document_result(
                            document,
                            "partial",
                            "restore_open",
                            point=point,
                            snapshots=0,
                            size=0,
                            kind="restore",
                        )
                    )
                    raise SystemExit(PARTIAL)
                if not backed_up:
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
        if "files" in parts:
            stage("stage")
            staging = _stage(identifier, point)
            if not _restore_files(document, capture_repository, capture_key, staging, source_extra):
                emit_result(
                    document_result(
                        document,
                        "refused",
                        "restore_files",
                        point=point,
                        snapshots=0,
                        size=0,
                        kind="restore",
                    )
                )
                raise SystemExit(REFUSED)
            try:
                staged = admitted(staging, source or identifier, application, identifier)
            except ValueError:
                emit_result(
                    document_result(
                        document,
                        "refused",
                        "restore_files",
                        point=point,
                        snapshots=0,
                        size=0,
                        kind="restore",
                    )
                )
                raise SystemExit(REFUSED) from None
        if "database" in parts:
            # The whole dump is downloaded and checked in private staging before the pause:
            # a truncated or different-major copy is refused while the site still serves.
            stage("dump")
            dump_stage = _stage(identifier, point, "-database")
            dump_path = dump_stage / "dump.sql"
            if not write_dump(
                capture_repository,
                capture_key,
                snapshot,
                str(document.get("filename", "")),
                dump_path,
                source_extra,
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
            problem = dump_problem(engine, dump_path, major)
            if problem:
                emit_result(
                    document_result(
                        document,
                        "refused",
                        problem,
                        point=point,
                        snapshots=0,
                        size=0,
                        kind="restore",
                    )
                )
                raise SystemExit(REFUSED)
        failure = begin_pause(document, settings, identifier, point)
        if failure is not None:
            emit_result(
                document_result(
                    document,
                    failure[0],
                    failure[1],
                    point=point,
                    snapshots=0,
                    size=0,
                    kind="restore",
                )
            )
            raise SystemExit(PARTIAL if failure[0] == "partial" else REFUSED)
        imported = 0
        if "database" in parts:
            stage("import")
            if dump_path is None:
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
            ok, imported = import_staged(dump_path, engine, identifier)
            if not ok:
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
        if "files" in parts:
            stage("files")
            try:
                caddy = pwd.getpwnam("caddy").pw_gid
                place(staged, settings, application, release, account.pw_uid, account.pw_gid, caddy)
            except OSError, ValueError, shutil.Error:
                emit_result(
                    document_result(
                        document,
                        "partial",
                        "restore_files",
                        point=point,
                        snapshots=1,
                        size=0,
                        kind="restore",
                    )
                )
                raise SystemExit(PARTIAL) from None
            stage("config")
            try:
                render_native(settings)
            except OSError, ValueError, subprocess.TimeoutExpired:
                emit_result(
                    document_result(
                        document,
                        "partial",
                        "restore_config",
                        point=point,
                        snapshots=1,
                        size=0,
                        kind="restore",
                    )
                )
                raise SystemExit(PARTIAL) from None
        stage("checks")
        if "database" in parts:
            actual = count_tables(engine, identifier)
            if actual is None or actual != imported:
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
        if "files" in parts and files_problem(settings, application, release):
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
        if not resume(document, settings, identifier):
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
        emit_result(
            document_result(
                document,
                "succeeded",
                "restore_done",
                point=point,
                snapshots=len(parts),
                size=int(str(document.get("point_size", 0))),
                kind="restore",
            )
        )
        raise SystemExit(SUCCESS)
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        if dump_stage is not None:
            shutil.rmtree(dump_stage, ignore_errors=True)
        for held in repository_lock_list:
            os.close(held)
        os.close(lock)


if __name__ == "__main__":
    main()
