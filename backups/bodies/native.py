"""Shared native helpers for a site's backup bodies.

The database-only and full-site bodies are staged as one standalone Python program, so the
helpers they share arrive as source text rather than an import (Phase D #396/#399).
"""

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


def emit_result(value: dict[str, object]) -> None:
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
        "scope": str(document.get("scope", "database")),
        "origin": str(document.get("origin", "manual")),
        "at": str(document.get("at", "")),
        "point": point,
        "snapshots": snapshots,
        "bytes": size,
    }


def locked_file(path: str, *, mode: int, gid: int = 0, links: int = 1) -> bool:
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
        if not locked_file(str(path), mode=0o640, gid=gid):
            raise ValueError("The site deploy lock is outside the convention.")
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not locked_file(str(path), mode=0o640, gid=gid):
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


def summary_size(output: str) -> int:
    saved = summary(output) or {}
    value = saved.get("total_bytes_processed", saved.get("data_added", 0))
    return int(value) if type(value) is int and value >= 0 else 0


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


def free_bytes() -> int:
    return shutil.disk_usage(REPOSITORY_ROOT).free
