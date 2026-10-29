"""Shared native helpers for a site's backup bodies.

The database-only and full-site bodies are staged as one standalone Python program, so the
helpers they share arrive as source text rather than an import (Phase D #396/#399).
"""

import contextlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

REPOSITORY_ROOT = "/var/lib/barectl-backups"
KEY_ROOT = "/etc/barectl/backups"
CACHE_DIR = "/var/cache/barectl/restic"
RESTIC_BIN = "/nix/var/nix/profiles/barectl/restic/bin/restic"
REPOSITORY_LOCK_ROOT = "/run/lock/barectl"
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
    kind: str = "backup",
    offsite: str = "",
) -> dict[str, object]:
    value: dict[str, object] = {
        "class": result_class,
        "reason": reason,
        "kind": kind,
        "site": str(document.get("identifier", "")),
        "scope": str(document.get("scope", "database")),
        "origin": str(document.get("origin", "manual")),
        "at": str(document.get("at", "")),
        "point": point,
        "snapshots": snapshots,
        "bytes": size,
    }
    if offsite:
        value["offsite"] = offsite
    return value


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


def repository_lock(identifier: str) -> int | None:
    """The one native lock for a site's repositories, or ``None`` when a copy holds it."""
    if not re.fullmatch(r"[a-z][a-z0-9]{2,23}", identifier):
        raise ValueError("Not a site identifier.")
    if not controlled(REPOSITORY_LOCK_ROOT):
        raise ValueError("The repository lock directory is outside the convention.")
    path = f"{REPOSITORY_LOCK_ROOT}/backup-{identifier}.lock"
    descriptor = os.open(path, os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        if not locked_file(path, mode=0o600):
            raise ValueError("The repository lock is outside the convention.")
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not locked_file(path, mode=0o600):
            raise ValueError("The repository lock changed.")
        return descriptor
    except BlockingIOError:
        os.close(descriptor)
        return None
    except OSError:
        os.close(descriptor)
        raise


def release_mutation_lock() -> None:
    """Release the engine's shared mutation lock before a slow copy continues.

    The capture's exact point is already safe and the site is serving again; a copy then
    holds only its per-repository lock, so hosting changes are not blocked by an upload.
    """
    with contextlib.suppress(OSError):
        os.close(9)


def environment_file(path: str) -> dict[str, str]:
    """Read a root-owned 0600 environment file without putting a value in argv."""
    if not locked_file(path, mode=0o600):
        raise ValueError("Not a root-owned environment file.")
    values: dict[str, str] = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle.read().splitlines():
            name, separator, value = line.partition("=")
            if separator and name.isupper() and name.replace("_", "").isalnum():
                values[name] = value
    return values


def restic_environment(
    repository: str, password: str, extra: dict[str, str] | None = None
) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/root",
        "LANG": "C",
        "RESTIC_REPOSITORY": repository,
        "RESTIC_PASSWORD_FILE": password,
        "RESTIC_CACHE_DIR": CACHE_DIR,
        "TZ": "UTC",
        **(extra or {}),
    }


def restic(
    argv: list[str],
    *,
    repository: str,
    password: str,
    extra: dict[str, str] | None = None,
) -> tuple[int, str]:
    environment = restic_environment(repository, password, extra)
    # restic selects virtual-hosted URLs for Amazon endpoints; Barectl's templates are
    # path-style. The extended option is accepted by every backend.
    options = ["-o", "s3.bucket-lookup=path"] if repository.startswith("s3:") else []
    process = subprocess.Popen(  # noqa: S603 - fixed native argv and validated paths
        [RESTIC_BIN, *options, *argv],
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


def snapshots(
    repository: str, password: str, point: str, extra: dict[str, str] | None = None
) -> list[dict[str, object]]:
    status, text = restic(
        ["snapshots", "--json", "--tag", "point:" + point],
        repository=repository,
        password=password,
        extra=extra,
    )
    if status:
        return []
    try:
        value = json.loads(text)
    except ValueError:
        return []
    rows = value if isinstance(value, list) else []
    return [row for row in rows if isinstance(row, dict)]


def copy_point(  # noqa: C901 - one reviewed copy
    identifier: str,
    point: str,
    onsite: str,
    key: str,
    plan: object,
    *,
    release: bool = True,
) -> tuple[str, str]:
    """Copy one point to the reviewed offsite repository under the repository lock.

    Returns the engine result class and its reason. A copy that fails never touches the
    onsite repository.
    """
    storage = plan.get("storage") if isinstance(plan, dict) else None
    destination = plan.get("repository") if isinstance(plan, dict) else ""
    capture = plan.get("capture_env") if isinstance(plan, dict) else ""
    if (
        not isinstance(storage, dict)
        or storage.get("provider") not in ("s3", "r2")
        or not isinstance(storage.get("endpoint"), str)
        or not storage["endpoint"].startswith("https://")
        or not isinstance(storage.get("bucket"), str)
        or not isinstance(storage.get("prefix"), str)
        or storage.get("prune") not in ("yes", "no")
        or destination
        != f"s3:{storage['endpoint']}/{storage['bucket']}/{storage['prefix']}/{identifier}"
        or capture != "/etc/barectl/backups/offsite/capture.env"
    ):
        return "failed", "offsite_copy"
    if release:
        release_mutation_lock()
    try:
        extra = environment_file(str(capture))
    except OSError, ValueError:
        return "failed", "offsite_key"
    if not extra.get("AWS_ACCESS_KEY_ID") or not extra.get("AWS_SECRET_ACCESS_KEY"):
        return "failed", "offsite_key"
    if isinstance(storage.get("region"), str):
        extra["AWS_DEFAULT_REGION"] = storage["region"]
    try:
        lock = repository_lock(identifier)
    except OSError, ValueError:
        return "failed", "offsite_key"
    if lock is None:
        return "lock_busy", "backup_lock"
    try:
        status, _output = restic(
            ["snapshots", "--json", "--no-lock"],
            repository=str(destination),
            password=key,
            extra=extra,
        )
        if status == 10:
            status, _output = restic(
                [
                    "init",
                    "--from-repo",
                    onsite,
                    "--from-password-file",
                    key,
                    "--copy-chunker-params",
                ],
                repository=str(destination),
                password=key,
                extra=extra,
            )
            if status:
                return "failed", "offsite_repository"
        elif status:
            return "failed", "offsite_repository"
        status, _output = restic(
            [
                "copy",
                "--from-repo",
                onsite,
                "--from-password-file",
                key,
                "--tag",
                "point:" + point,
            ],
            repository=str(destination),
            password=key,
            extra=extra,
        )
        if status:
            return "failed", "offsite_copy"
        rows = snapshots(str(destination), key, point, extra)
        complete = False
        for row in rows:
            tags = row.get("tags")
            if isinstance(tags, list) and "complete" in tags and "barectl" in tags:
                complete = True
        if not complete:
            return "failed", "offsite_copy"
        return "succeeded", ""
    finally:
        os.close(lock)


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
