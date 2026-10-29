"""Private controller staging and the expiring download for an export (#409).

The worker moves one export's two artifacts from the server's bounded stage through the same
``RemoteShell`` connection it already has, in bounded reads, and keeps them in a private
directory on this computer. A download is authenticated, no-store and expiring; it is never a
public URL and never a database blob. Both stages are removed on completion, expiry or
cancellation.
"""

import base64
import binascii
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Final

from django.conf import settings
from django.utils import timezone

from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native
from operations.models import ChangeReview
from servers.models import Server

from .bodies import export as export_body
from .models import BackupExport

TOKEN: Final = re.compile(r"[0-9a-f]{32}")
SHA256: Final = re.compile(r"[0-9a-f]{64}")
# A read returns at most ssh.MAX_OUTPUT bytes, so one chunk's base64 stays below it.
CHUNK_BYTES: Final = 32 * 1024
TRANSFER_SECONDS: Final = 120
LIFETIME: Final = timedelta(minutes=30)
MANIFEST_LIMIT: Final = 16 * 1024
ARTIFACTS: Final = {"files": export_body.FILES_NAME, "database": export_body.DATABASE_NAME}


class TransferFailed(Exception):
    """The controller could not move a bounded, complete export."""


@dataclass(frozen=True)
class Transfer:
    token: str
    files: pathlib.Path | None
    files_bytes: int
    database: pathlib.Path | None
    database_bytes: int


def staging_root() -> pathlib.Path:
    root = pathlib.Path(settings.EXPORT_STAGING_PATH)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    return root


def local_root(token: str) -> pathlib.Path:
    if TOKEN.fullmatch(token) is None:
        raise TransferFailed("The export token is invalid.")
    return staging_root() / token


def local_path(token: str, artifact: str) -> pathlib.Path:
    return local_root(token) / ARTIFACTS[artifact]


def _remove_local(token: str) -> None:
    """Remove one controller stage, retrying after restoring write permission.

    Both stages are private directories this process created. A failed first removal can
    only be a mode left by an interrupted worker, so make the tree writable and retry once.
    A stage that still cannot be removed is bounded and `_prune_orphans` retries it after an
    hour; it is never served without its row.
    """
    root = local_root(token)
    try:
        shutil.rmtree(root)
        return
    except FileNotFoundError:
        return
    except OSError:
        pass
    for directory, _children, files in os.walk(root):
        try:
            os.chmod(directory, 0o700)
            for name in files:
                os.chmod(os.path.join(directory, name), 0o600)
        except OSError:
            continue
    try:
        shutil.rmtree(root)
    except FileNotFoundError:
        return
    except OSError:
        pass


def chunk_command(path: str, index: int) -> str:
    return (
        shlex.join(
            [
                "/usr/bin/dd",
                f"if={path}",
                f"bs={CHUNK_BYTES}",
                f"skip={index}",
                "count=1",
            ]
        )
        + " | /usr/bin/base64"
    )


def _manifest(  # noqa: C901 - one closed manifest
    shell: RemoteShell, identifier: str, point: str, token: str
) -> dict[str, object]:
    path = str(export_body.stage_path(identifier, token) / export_body.MANIFEST)
    result = run_root(shell, f"cat {shlex.quote(path)}")
    if result.exit_status or result.truncated or len(result.stdout) > MANIFEST_LIMIT:
        raise TransferFailed("The export's manifest could not be read.")
    try:
        value: object = json.loads(result.stdout)
    except ValueError:
        raise TransferFailed("The export's manifest is not readable.") from None
    if not isinstance(value, dict) or value.get("version") != 1:
        raise TransferFailed("The export's manifest is not supported.")
    if value.get("identifier") != identifier or value.get("point") != point:
        raise TransferFailed("The export's manifest does not match the review.")
    if value.get("token") != token:
        raise TransferFailed("The export's manifest does not match the review.")
    files = value.get("files")
    database = value.get("database")
    if files is None and database is None:
        raise TransferFailed("The export is empty.")
    total = 0
    for entry, name, limit in (
        (files, export_body.FILES_NAME, export_body.MAX_FILES_BYTES),
        (database, export_body.DATABASE_NAME, export_body.MAX_DATABASE_BYTES),
    ):
        if entry is None:
            continue
        if not isinstance(entry, dict):
            raise TransferFailed("The export's manifest is not supported.")
        size, digest = entry.get("size"), entry.get("sha256")
        if (
            entry.get("name") != name
            or type(size) is not int
            or size <= 0
            or size > limit
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
        ):
            raise TransferFailed("The export's manifest is not supported.")
        total += size
    if total > export_body.MAX_EXPORT_BYTES:
        raise TransferFailed("The export is larger than Barectl moves safely.")
    return value


def _receive(
    shell: RemoteShell,
    source: str,
    target: pathlib.Path,
    size: int,
    digest: str,
    *,
    deadline: float,
    root: bool,
) -> None:
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(target.parent, 0o700)
    hasher = hashlib.sha256()
    remaining = size
    index = 0
    with target.open("xb") as handle:
        os.chmod(target, 0o600)
        while remaining > 0:
            if time.monotonic() >= deadline:
                raise TransferFailed("The export did not finish in time.")
            command = chunk_command(source, index)
            answer = shell.run(command) if root else run_root(shell, command)
            if answer.exit_status or answer.truncated:
                raise TransferFailed("The export could not be moved.")
            try:
                chunk = base64.b64decode(answer.stdout)
            except binascii.Error:
                raise TransferFailed("The export could not be moved.") from None
            if not chunk or len(chunk) > remaining:
                raise TransferFailed("The export changed while it was moved.")
            handle.write(chunk)
            hasher.update(chunk)
            remaining -= len(chunk)
            index += 1
        handle.flush()
        os.fsync(handle.fileno())
    if remaining or hasher.hexdigest() != digest:
        raise TransferFailed("The export changed while it was moved.")


def transfer(shell: RemoteShell, identifier: str, point: str, token: str) -> Transfer:
    """Move one reviewed export from its server stage to private controller staging."""
    if TOKEN.fullmatch(token) is None:
        raise TransferFailed("The export token is invalid.")
    manifest = _manifest(shell, identifier, point, token)
    server_root = export_body.stage_path(identifier, token)
    _remove_local(token)
    root = native.is_root(shell)
    if root is None:
        raise TransferFailed("Barectl could not read the server's privilege.")
    deadline = time.monotonic() + TRANSFER_SECONDS
    files_path: pathlib.Path | None = None
    database_path: pathlib.Path | None = None
    files_bytes = 0
    database_bytes = 0
    try:
        files = manifest.get("files")
        if isinstance(files, dict):
            files_bytes = int(files["size"])
            files_path = local_path(token, "files")
            _receive(
                shell,
                str(server_root / export_body.FILES_NAME),
                files_path,
                files_bytes,
                str(files["sha256"]),
                deadline=deadline,
                root=root is True,
            )
        database = manifest.get("database")
        if isinstance(database, dict):
            database_bytes = int(database["size"])
            database_path = local_path(token, "database")
            _receive(
                shell,
                str(server_root / export_body.DATABASE_NAME),
                database_path,
                database_bytes,
                str(database["sha256"]),
                deadline=deadline,
                root=root is True,
            )
    except BaseException:
        _remove_local(token)
        raise
    finally:
        cleanup = run_root(shell, f"/usr/bin/rm -rf -- {shlex.quote(str(server_root))}")
        if cleanup.exit_status:
            _remove_local(token)
            raise TransferFailed("The server's export stage could not be removed.")
    return Transfer(token, files_path, files_bytes, database_path, database_bytes)


def record(review: ChangeReview, transfer: Transfer) -> object | None:
    """Store the one download row this export's review produced."""
    from .models import BackupExport

    preparation = review.preparation
    if preparation is None or preparation.server is None:
        return None
    try:
        return BackupExport.objects.create(
            server=preparation.server,
            identifier=str(review.document["identifier"]),
            point=str(review.document["point"]),
            token=transfer.token,
            requested_by=preparation.requested_by,
            files_bytes=transfer.files_bytes,
            database_bytes=transfer.database_bytes,
            expires_at=timezone.now() + LIFETIME,
        )
    except Exception:
        _remove_local(transfer.token)
        raise


def expire(server: Server | None = None, identifier: str = "") -> None:
    """Remove every expired controller stage without connecting to a server."""
    rows = BackupExport.objects.filter(status=BackupExport.Status.READY)
    if server is not None:
        rows = rows.filter(server=server)
    if identifier:
        rows = rows.filter(identifier=identifier)
    for row in rows.filter(expires_at__lte=timezone.now()):
        _remove_local(row.token)
        BackupExport.objects.filter(pk=row.pk).update(status=BackupExport.Status.EXPIRED)
    _prune_orphans()


def _prune_orphans() -> None:
    """Remove a staging directory a killed worker left with no row to expire."""
    root = staging_root()
    referenced = set(BackupExport.objects.values_list("token", flat=True))
    cutoff = time.time() - 60 * 60
    for entry in root.iterdir():
        if entry.name in referenced or entry.is_symlink() or not entry.is_dir():
            continue
        try:
            if entry.stat().st_mtime < cutoff:
                shutil.rmtree(entry)
        except OSError:
            continue


def forget_exports(server: Server) -> None:
    """Remove a removed server's export stages; its rows go with the server."""
    for row in BackupExport.objects.filter(server=server):
        _remove_local(row.token)


def cancel(row: BackupExport) -> None:
    token = row.token
    if token:
        _remove_local(token)
    BackupExport.objects.filter(pk=row.pk).update(status=BackupExport.Status.CANCELLED)


def served(row: BackupExport, artifact: str) -> pathlib.Path:
    """The one-shot file to serve, or a failure after cleaning the row's stage."""
    path = local_path(row.token, artifact)
    if not path.is_file() or path.is_symlink():
        _remove_local(row.token)
        raise FileNotFoundError("The export's staging is gone.")
    return path


def mark_served(row: BackupExport, artifact: str) -> None:
    if artifact == "files":
        row.files_served = True
        field = "files_served"
    else:
        row.database_served = True
        field = "database_served"
    row.save(update_fields=[field])
