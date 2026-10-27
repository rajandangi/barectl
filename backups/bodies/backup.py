"""Take one database-only recovery point for a site, streamed into its onsite repository.

The dump runs as the site's own Linux user with ``--stdin-from-command``, so restic cancels
the backup and creates no snapshot when the dump fails, and no plain-text dump touches disk
(Phase D #396 and #358). The body holds the site's deploy lock, keeps the repository's
headroom, and prints one safe ``barectl-result`` line.
"""

import base64
import gzip
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

REPOSITORY_ROOT = "/var/lib/barectl-backups"
CACHE_DIR = "/var/cache/barectl/restic"
RESTIC_BIN = "/nix/var/nix/profiles/barectl/restic/bin/restic"
HEADROOM_BYTES = 1024 * 1024 * 1024
SUCCESS = 0
REFUSED = 1
PARTIAL = 2
FAILED = 3
LOCK_BUSY = 10
RESTIC_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}")


def emit(text: str) -> None:
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def stage(name: str) -> None:
    emit("barectl-stage " + name)


def result(value: dict[str, object]) -> None:
    emit("barectl-result " + json.dumps(value, separators=(",", ":")))


def document_result(
    document: dict[str, object],
    result_class: str,
    reason: str,
    *,
    point: str,
    snapshots: int,
    size: int,
) -> dict[str, object]:
    return {
        "class": result_class,
        "reason": reason,
        "kind": "backup",
        "site": str(document.get("identifier", "")),
        "scope": "database",
        "origin": "manual",
        "at": str(document.get("at", "")),
        "point": point,
        "snapshots": snapshots,
        "bytes": size,
    }


def safe(path: str, *, mode: int, gid: int = 0, links: int = 1) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    return (
        info.st_uid == 0
        and info.st_gid == gid
        and (info.st_mode & 0o170000) == 0o100000
        and (info.st_mode & 0o777) == mode
        and info.st_nlink == links
    )


def safe_config(path: str) -> bool:
    """restic's local backend writes its config read-only (0400) on some versions."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    return (
        info.st_uid == 0
        and info.st_gid == 0
        and (info.st_mode & 0o170000) == 0o100000
        and (info.st_mode & 0o777) in (0o400, 0o600)
        and info.st_nlink == 1
    )


def controlled(path: str) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    return (
        info.st_uid == 0
        and info.st_gid == 0
        and (info.st_mode & 0o170000) == 0o040000
        and (info.st_mode & 0o022) == 0
    )


def site_lock(identifier: str, gid: int) -> int | None:
    """The site's own deploy lock, or ``None`` when another change holds it."""
    path = pathlib.Path("/var/www") / identifier / ".deploy.lock"
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        if not safe(str(path), mode=0o640, gid=gid):
            raise ValueError("The site deploy lock is outside the convention.")
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not safe(str(path), mode=0o640, gid=gid):
            raise ValueError("The site deploy lock changed.")
        return descriptor
    except BlockingIOError:
        os.close(descriptor)
        return None
    except OSError, ValueError:
        os.close(descriptor)
        raise


def restic(argv: list[str], *, repository: str, password: str) -> tuple[int, str]:
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/root",
        "LANG": "C",
        "RESTIC_REPOSITORY": repository,
        "RESTIC_PASSWORD_FILE": password,
        "RESTIC_CACHE_DIR": CACHE_DIR,
        "TZ": "UTC",
    }
    process = subprocess.Popen(  # noqa: S603 - fixed native argv and validated paths
        [RESTIC_BIN, *argv],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=environment,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate()
    except BaseException:
        process.kill()
        process.communicate()
        raise
    return process.returncode, output.decode("utf-8", "replace")


def snapshots(repository: str, password: str, point: str) -> list[dict[str, object]]:
    status, text = restic(
        ["snapshots", "--json", "--tag", "point:" + point],
        repository=repository,
        password=password,
    )
    if status:
        return []
    try:
        value = json.loads(text)
    except ValueError:
        return []
    rows = value if isinstance(value, list) else []
    return [row for row in rows if isinstance(row, dict)]


def summary(output: str) -> dict[str, object] | None:
    for line in output.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("message_type") == "summary":
            return value
    return None


def classify(status: int, saved: bool) -> tuple[str, str, int]:
    """Map restic's exit status and a saved snapshot to the engine's result classes."""
    if status in (0, 3):
        if not saved:
            return "failed", "backup_verify", FAILED
        return ("succeeded", "", SUCCESS) if status == 0 else ("partial", "backup_partial", PARTIAL)
    if saved:
        return "partial", "backup_partial", PARTIAL
    if status == 10:
        return "refused", "backup_repository", REFUSED
    if status == 11:
        return "lock_busy", "backup_lock", LOCK_BUSY
    if status == 12:
        return "refused", "backup_password", REFUSED
    if status == 1:
        return "refused", "backup_dump", REFUSED
    return "failed", "backup_unknown", FAILED


def main() -> None:
    document = json.loads(gzip.decompress(base64.b64decode(sys.argv[1])))
    identifier = str(document.get("identifier", ""))
    repository = str(document.get("repository", ""))
    key = str(document.get("server_key", ""))
    engine = str(document.get("engine", ""))
    point = str(document.get("point", ""))
    at = str(document.get("at", ""))
    dump = document.get("dump")
    tags = document.get("tags")
    if (
        not identifier
        or repository != f"{REPOSITORY_ROOT}/{identifier}/onsite"
        or not key.startswith("/etc/barectl/backups/")
        or engine not in ("mariadb", "postgresql")
        or len(point) != 16
        or not at
        or not isinstance(document.get("restic_time"), str)
        or RESTIC_TIME.fullmatch(str(document.get("restic_time"))) is None
        or not isinstance(dump, list)
        or not all(isinstance(item, str) for item in dump)
        or not isinstance(tags, list)
        or not all(isinstance(tag, str) and len(tag) <= 48 for tag in tags)
    ):
        result({"class": "failed"})
        raise SystemExit(FAILED)
    stage("preflight")
    try:
        import pwd

        account = pwd.getpwnam("s" + identifier)
    except KeyError:
        result(
            document_result(document, "refused", "backup_site", point=point, snapshots=0, size=0)
        )
        raise SystemExit(REFUSED) from None
    if account.pw_uid < 1000 or account.pw_uid >= 30000:
        result(
            document_result(document, "refused", "backup_site", point=point, snapshots=0, size=0)
        )
        raise SystemExit(REFUSED)
    if (
        not os.path.isfile(os.path.join(repository, "config"))
        or not safe_config(os.path.join(repository, "config"))
        or not safe(key, mode=0o600)
        or not controlled(REPOSITORY_ROOT)
        or not os.access(RESTIC_BIN, os.X_OK)
    ):
        result(
            document_result(
                document, "refused", "backup_repository", point=point, snapshots=0, size=0
            )
        )
        raise SystemExit(REFUSED)
    try:
        lock = site_lock(identifier, account.pw_gid)
    except OSError, ValueError:
        result(
            document_result(document, "refused", "backup_lock", point=point, snapshots=0, size=0)
        )
        raise SystemExit(REFUSED) from None
    if lock is None:
        result(
            document_result(document, "lock_busy", "backup_lock", point=point, snapshots=0, size=0)
        )
        raise SystemExit(LOCK_BUSY)
    try:
        free = shutil.disk_usage(REPOSITORY_ROOT).free
        if free < HEADROOM_BYTES:
            result(
                document_result(
                    document, "refused", "backup_disk", point=point, snapshots=0, size=0
                )
            )
            raise SystemExit(REFUSED)
        stage("backup")
        argv = [
            "backup",
            "--json",
            "--stdin-from-command",
            "--stdin-filename",
            str(document.get("filename", "database.sql")),
            "--time",
            str(document.get("restic_time", "")),
        ]
        for tag in tags:
            argv.extend(("--tag", tag))
        argv.append("--")
        argv.extend(dump)
        status, output = restic(argv, repository=repository, password=key)
        stage("verify")
        found = snapshots(repository, key, point)
        saved = summary(output) or {}
        size = saved.get("total_bytes_processed", saved.get("data_added", 0))
        size = int(size) if type(size) is int and size >= 0 else 0
        result_class, reason, code = classify(status, bool(found))
        result(
            document_result(
                document,
                result_class,
                reason,
                point=point,
                snapshots=len(found) if found else 0,
                size=size,
            )
        )
        raise SystemExit(code)
    finally:
        os.close(lock)


if __name__ == "__main__":
    main()
