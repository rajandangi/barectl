"""Export one recovery point into bounded private staging (#409).

The body restores the reviewed file snapshot into a root-only stage, admits the tree with
the restore admission rules, and builds one tar archive of the site's application files and,
for Laravel, its shared ``storage`` directory. The site's private configuration
(WordPress's ``wp-config.php``, Laravel's ``.env`` and ``bootstrap/cache``) is never added.
It writes the database dump beside the archive, checks that neither the private
configuration's bytes nor its names are in the archive, enforces one size bound, and leaves
the stage for the controller to transfer through the existing SSH connection. A stale stage
is bounded and pruned on the next export.
"""

import base64
import gzip
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import time
from typing import Final

from backups.bodies.native import (
    FAILED,
    REFUSED,
    REPOSITORY_ROOT,
    RESTIC_BIN,
    SUCCESS,
    controlled,
    emit_result,
    locked_file,
    repository_lock,
    restic,
    restic_environment,
    safe_config,
    stage,
)
from backups.bodies.restore import POINT, SNAPSHOT, admitted, dump_version

IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}")
TOKEN = re.compile(r"[0-9a-f]{32}")
DUMP = re.compile(r"s[a-z][a-z0-9]{2,23}\.sql")
STAGE_ROOT: Final = "/var/lib/barectl-export"
MANIFEST: Final = "manifest.json"
FILES_NAME: Final = "files.tar"
DATABASE_NAME: Final = "database.sql"
# One export is bounded so a stage, a transfer and a download cannot exhaust either side.
MAX_FILES_BYTES: Final = 32 * 1024 * 1024
MAX_DATABASE_BYTES: Final = 32 * 1024 * 1024
MAX_EXPORT_BYTES: Final = 48 * 1024 * 1024
# A stage left by a killed worker is removed by the next export of the same site.
STAGE_TTL_SECONDS: Final = 60 * 60
CANARY_BYTES: Final = 4096
APPLICATIONS: Final = ("plain", "wordpress", "laravel")
PRIVATE_FILES: Final = {
    "plain": (),
    "wordpress": ("private/wp-config.php",),
    "laravel": ("private/laravel.env", "private/cache"),
}
EXCLUDED_PATHS: Final = ("wp-config.php", "laravel.env", "private/cache", "bootstrap/cache")


class ExportRefused(Exception):
    """A bounded, safe refusal with a reason the engine can record."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def stage_path(identifier: str, token: str) -> pathlib.Path:
    return pathlib.Path(STAGE_ROOT) / identifier / token


def _root() -> pathlib.Path:
    root = pathlib.Path(STAGE_ROOT)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not controlled(STAGE_ROOT):
        raise ExportRefused("export_stage")
    os.chmod(root, 0o700)
    return root


def _prune(site_root: pathlib.Path, keep: pathlib.Path) -> None:
    """Remove a bounded stage another run left behind; never follow a link."""
    if site_root.is_symlink() or not site_root.is_dir():
        if site_root.exists():
            site_root.unlink()
        return
    os.chmod(site_root, 0o700)
    cutoff = time.time() - STAGE_TTL_SECONDS
    for entry in site_root.iterdir():
        if entry == keep or entry.is_symlink() or not entry.is_dir():
            continue
        try:
            if entry.stat().st_mtime < cutoff:
                shutil.rmtree(entry)
        except OSError:
            continue


def _prepare_stage(identifier: str, token: str) -> pathlib.Path:
    root = _root()
    site_root = root / identifier
    if site_root.is_symlink():
        site_root.unlink()
    site_root.mkdir(mode=0o700, exist_ok=True)
    directory = stage_path(identifier, token)
    _prune(site_root, directory)
    os.chmod(site_root, 0o700)
    if directory.is_symlink() or directory.is_file():
        directory.unlink()
    elif directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(mode=0o700, parents=True)
    os.chmod(directory, 0o700)
    return directory


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _private_paths(base: pathlib.Path, application: str) -> list[pathlib.Path]:
    paths: list[pathlib.Path] = []
    for relative in PRIVATE_FILES[application]:
        path = base / relative
        if path.is_symlink():
            continue
        if path.is_file():
            paths.append(path)
        elif path.is_dir():
            paths.extend(
                entry for entry in path.rglob("*") if entry.is_file() and not entry.is_symlink()
            )
    return paths


def _needles(paths: list[pathlib.Path]) -> list[bytes]:
    """The first bytes of each private file, which a leaky archive would contain."""
    values: list[bytes] = []
    for path in paths:
        try:
            with path.open("rb") as handle:
                value = handle.read(CANARY_BYTES).strip()
        except OSError:
            continue
        if len(value) >= 8:
            values.append(value)
    return values


def _contains(path: pathlib.Path, needle: bytes) -> bool:
    window = b""
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            if needle in window + chunk:
                return True
            window = (window + chunk)[-(len(needle) - 1) :]
    return False


def _rewrite_links(base: pathlib.Path, release: pathlib.Path, application: str) -> None:
    current = base / "current"
    if current.is_symlink():
        current.unlink()
    elif current.exists():
        raise ExportRefused("export_files")
    current.symlink_to(pathlib.Path("releases") / release.name)
    if application == "laravel":
        storage = release / "storage"
        if storage.is_symlink():
            storage.unlink()
            storage.symlink_to(pathlib.Path("..") / ".." / "private" / "storage")
        cache = release / "bootstrap" / "cache"
        if cache.is_symlink():
            cache.unlink()


def _members(base: pathlib.Path, release: pathlib.Path, application: str) -> list[str]:
    members = ["current", str(pathlib.Path("releases") / release.name)]
    if application == "laravel":
        members.append("private/storage")
    return members


def _archive(
    directory: pathlib.Path,
    base: pathlib.Path,
    release: pathlib.Path,
    application: str,
    limit: int,
) -> pathlib.Path:
    archive = directory / FILES_NAME
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as bundle:
        for member in _members(base, release, application):
            path = base / member
            if not path.exists() and not path.is_symlink():
                raise ExportRefused("export_files")
            bundle.add(
                path,
                arcname=member,
                recursive=True,
                filter=lambda info: (
                    None
                    if info.name.endswith("bootstrap/cache") or info.name == "bootstrap/cache"
                    else info
                ),
            )
    os.chmod(archive, 0o600)
    if archive.stat().st_size > limit:
        raise ExportRefused("export_size")
    return archive


def _archive_is_clean(archive: pathlib.Path, base: pathlib.Path, application: str) -> bool:
    try:
        with tarfile.open(archive, "r") as bundle:
            names = bundle.getnames()
    except OSError, tarfile.TarError:
        return False
    for name in names:
        if any(part in name for part in EXCLUDED_PATHS):
            return False
    for needle in _needles(_private_paths(base, application)):
        if _contains(archive, needle):
            return False
    return True


def _dump(
    snapshot: str,
    filename: str,
    directory: pathlib.Path,
    repository: str,
    key: str,
    engine: str,
    major: str,
    limit: int,
) -> pathlib.Path:
    target = directory / DATABASE_NAME
    environment = restic_environment(repository, key)
    with target.open("wb") as handle:
        os.chmod(target, 0o600)
        process = subprocess.Popen(  # noqa: S603 - fixed native argv and validated paths
            [RESTIC_BIN, "dump", "--no-lock", snapshot, "/" + filename.lstrip("/")],
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=subprocess.DEVNULL,
            env=environment,
            start_new_session=True,
        )
        try:
            process.wait()
        except BaseException:
            process.kill()
            process.wait()
            raise
    if process.returncode != 0:
        raise ExportRefused("export_database")
    size = target.stat().st_size
    if size <= 0 or size > limit:
        raise ExportRefused("export_size")
    with target.open("rb") as handle:
        header = handle.read(8192).decode("utf-8", "replace")
    if dump_version(engine, header) != major:
        raise ExportRefused("export_database")
    return target


def _write_manifest(
    directory: pathlib.Path,
    identifier: str,
    point: str,
    token: str,
    files: pathlib.Path | None,
    database: pathlib.Path | None,
) -> pathlib.Path:
    document: dict[str, object] = {
        "version": 1,
        "identifier": identifier,
        "point": point,
        "token": token,
        "files": None
        if files is None
        else {"name": FILES_NAME, "size": files.stat().st_size, "sha256": _sha256(files)},
        "database": None
        if database is None
        else {
            "name": DATABASE_NAME,
            "size": database.stat().st_size,
            "sha256": _sha256(database),
        },
    }
    manifest = directory / MANIFEST
    manifest.write_text(json.dumps(document, separators=(",", ":")), encoding="utf-8")
    os.chmod(manifest, 0o600)
    return manifest


def _validate(document: dict[str, object]) -> None:
    identifier = document.get("identifier")
    application = document.get("application")
    point = document.get("point")
    token = document.get("token")
    repository = document.get("repository")
    key = document.get("server_key")
    snapshot = document.get("snapshot")
    files_snapshot = document.get("files_snapshot")
    filename = document.get("filename")
    engine = document.get("engine")
    major = document.get("engine_major")
    if (
        not isinstance(identifier, str)
        or IDENTIFIER.fullmatch(identifier) is None
        or application not in APPLICATIONS
        or not isinstance(point, str)
        or POINT.fullmatch(point) is None
        or not isinstance(token, str)
        or TOKEN.fullmatch(token) is None
        or repository != f"{REPOSITORY_ROOT}/{identifier}/onsite"
        or not isinstance(key, str)
        or not key.startswith("/etc/barectl/backups/")
        or not isinstance(filename, str)
        or DUMP.fullmatch(filename) is None
        or (snapshot and (not isinstance(snapshot, str) or SNAPSHOT.fullmatch(snapshot) is None))
        or (
            files_snapshot
            and (not isinstance(files_snapshot, str) or SNAPSHOT.fullmatch(files_snapshot) is None)
        )
        or (not snapshot and not files_snapshot)
        or (snapshot and (engine not in ("mariadb", "postgresql") or not major))
    ):
        raise ExportRefused("export_evidence")


def main(argument: str | None = None) -> None:  # noqa: C901 - one reviewed export
    encoded = sys.argv[1] if argument is None else argument
    document = json.loads(gzip.decompress(base64.b64decode(encoded)))
    identifier = str(document.get("identifier", ""))
    application = str(document.get("application", ""))
    point = str(document.get("point", ""))
    token = str(document.get("token", ""))
    repository = str(document.get("repository", ""))
    key = str(document.get("server_key", ""))
    snapshot = str(document.get("snapshot", ""))
    files_snapshot = str(document.get("files_snapshot", ""))
    filename = str(document.get("filename", ""))
    engine = str(document.get("engine", ""))
    major = str(document.get("engine_major", ""))
    directory: pathlib.Path | None = None
    lock = -1
    try:
        _validate(document)
        stage("preflight")
        if (
            not os.path.isfile(os.path.join(repository, "config"))
            or not safe_config(os.path.join(repository, "config"))
            or not locked_file(key, mode=0o600)
            or not controlled(REPOSITORY_ROOT)
            or not os.access(RESTIC_BIN, os.X_OK)
        ):
            raise ExportRefused("export_repository")
        lock = repository_lock(identifier) or -1
        if lock == -1:
            raise ExportRefused("export_lock")
        directory = _prepare_stage(identifier, token)
        stage("stage")
        base: pathlib.Path | None = None
        release: pathlib.Path | None = None
        if files_snapshot:
            status, _output = restic(
                ["restore", "--no-lock", files_snapshot, "--target", str(directory)],
                repository=repository,
                password=key,
            )
            if status != 0:
                raise ExportRefused("export_files")
            base, release = _admit(directory, identifier, application)
            stage("files")
        database: pathlib.Path | None = None
        if snapshot:
            database = _dump(
                snapshot,
                filename,
                directory,
                repository,
                key,
                engine,
                major,
                MAX_DATABASE_BYTES,
            )
            stage("database")
        files: pathlib.Path | None = None
        if base is not None and release is not None:
            _rewrite_links(base, release, application)
            files = _archive(directory, base, release, application, MAX_FILES_BYTES)
            if not _archive_is_clean(files, base, application):
                raise ExportRefused("export_secret")
        total = (files.stat().st_size if files is not None else 0) + (
            database.stat().st_size if database is not None else 0
        )
        if total <= 0 or total > MAX_EXPORT_BYTES:
            raise ExportRefused("export_size")
        _write_manifest(directory, identifier, point, token, files, database)
        stage("verify")
        emit_result(
            {
                "class": "succeeded",
                "reason": "",
                "kind": "export",
                "site": identifier,
                "point": point,
                "bytes": total,
                "files": files.stat().st_size if files is not None else 0,
                "database": database.stat().st_size if database is not None else 0,
            }
        )
        raise SystemExit(SUCCESS)
    except ExportRefused as refused:
        if directory is not None:
            shutil.rmtree(directory, ignore_errors=True)
        emit_result({"class": "refused", "reason": refused.reason})
        raise SystemExit(REFUSED) from None
    except SystemExit:
        raise
    except BaseException:
        if directory is not None:
            shutil.rmtree(directory, ignore_errors=True)
        emit_result({"class": "failed", "reason": ""})
        raise SystemExit(FAILED) from None
    finally:
        if lock != -1:
            os.close(lock)


def _admit(
    directory: pathlib.Path, identifier: str, application: str
) -> tuple[pathlib.Path, pathlib.Path]:
    try:
        value = admitted(directory, identifier, application)
    except ValueError:
        raise ExportRefused("export_files") from None
    base = value["base"]
    release = value["release"]
    if not isinstance(base, pathlib.Path) or not isinstance(release, pathlib.Path):
        raise ExportRefused("export_files")
    return base, release


if __name__ == "__main__":
    main()
