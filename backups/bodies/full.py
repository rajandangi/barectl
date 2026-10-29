"""Take one paused Full site recovery point: database stream and files (#399).

The body holds the site's deploy lock, fences the site's background work, publishes the
maintenance gate, drains HAProxy admission and the site's FPM workers, then writes the
database stream and the files as two snapshots sharing one point and ``--time``. It tags
both complete only after both are verified present, and opens the gate only then. A stop
after the gate stays gated (docs/adr/0022, docs/adr/0036, docs/adr/0038).
"""

import base64
import gzip
import json
import os
import pathlib
import pwd
import re
import sys
from types import SimpleNamespace

from automation.bodies.units import fence, restore
from backups.bodies.native import (
    HEADROOM_BYTES,
    LOCK_BUSY,
    PARTIAL,
    REFUSED,
    REPOSITORY_ROOT,
    RESTIC_TIME,
    SUCCESS,
    controlled,
    copy_point,
    document_result,
    emit_result,
    free_bytes,
    locked_file,
    restic,
    safe_config,
    site_lock,
    snapshots,
    summary_size,
)
from backups.bodies.paused import (
    APPLICATIONS,
    SHARED,
    drain,
    open_file,
    open_site,
    publish_gate,
    site_settings,
)
from sites.bodies.common import maintenance_file, stage

IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}")


def reviewed_files(settings: SimpleNamespace, application: str) -> list[str]:
    if application not in APPLICATIONS:
        raise ValueError("The site's application is not supported.")
    directory = pathlib.Path(settings.directory)
    release = directory / "current"
    if not release.is_symlink():
        raise ValueError("The site has no current release.")
    target = pathlib.Path(os.path.realpath(release))
    if target.parent != directory / "releases" or not target.is_dir():
        raise ValueError("The site's current release is outside the convention.")
    shared = []
    for relative in SHARED[application]:
        path = directory / relative
        if path.is_symlink() or not path.exists():
            raise ValueError("The site's private files are incomplete.")
        shared.append(str(path))
    return [str(release), *shared]


def restic_paths(document: dict[str, object]) -> list[str]:
    """The current release resolves to its real directory; restic keeps symlinks as links."""
    files = document.get("files")
    if not isinstance(files, list) or not files or not all(isinstance(item, str) for item in files):
        raise ValueError("The full backup has no files.")
    current = pathlib.Path(files[0])
    if current.name != "current" or not current.is_symlink():
        raise ValueError("The full backup has no current release.")
    target = pathlib.Path(os.path.realpath(current))
    if target.parent != current.parent / "releases" or not target.is_dir():
        raise ValueError("The site's current release is outside the convention.")
    return [str(target), *[str(path) for path in files[1:]]]


def capture(
    document: dict[str, object],
    *,
    part: str,
    argv: list[str],
    repository: str,
    key: str,
) -> tuple[int, int]:
    """One part's restic answer: its exit status and bytes processed."""
    stage("backup-" + part)
    status, output = restic(argv, repository=repository, password=key)
    return status, summary_size(output)


def tags_of(document: dict[str, object], part: str) -> list[str]:
    value = document.get("tags")
    rows = value.get(part) if isinstance(value, dict) else None
    if not isinstance(rows, list) or not all(isinstance(item, str) for item in rows):
        raise ValueError("The full backup has no tags.")
    return rows


def backup_argv(document: dict[str, object], part: str) -> list[str]:
    argv = ["backup", "--json", "--time", str(document.get("restic_time", ""))]
    for tag in tags_of(document, part):
        argv.extend(("--tag", tag))
    if part == "database":
        argv.extend(
            [
                "--stdin-from-command",
                "--stdin-filename",
                str(document.get("filename", "database.sql")),
                "--",
            ]
        )
        dump = document.get("dump")
        if not isinstance(dump, list) or not all(isinstance(item, str) for item in dump):
            raise ValueError("The full backup has no database command.")
        argv.extend(dump)
    else:
        argv.extend(restic_paths(document))
    return argv


def complete_point(document: dict[str, object], repository: str, key: str) -> bool:
    point = str(document.get("point", ""))
    found = snapshots(repository, key, point)
    rows: dict[str, str] = {}
    for row in found:
        tags = row.get("tags")
        snapshot_id = row.get("id")
        if not isinstance(tags, list) or not isinstance(snapshot_id, str):
            return False
        part = next(
            (
                tag.removeprefix("part:")
                for tag in tags
                if isinstance(tag, str) and tag.startswith("part:")
            ),
            "",
        )
        if part not in ("database", "files") or part in rows:
            return False
        if "complete" not in tags:
            return False
        rows[part] = snapshot_id
    expected = ["files"] if document.get("scope") == "files" else ["database", "files"]
    return set(rows) == set(expected)


def mark_complete(document: dict[str, object], repository: str, key: str) -> bool:
    point = str(document.get("point", ""))
    found = snapshots(repository, key, point)
    ids: list[str] = []
    for row in found:
        tags = row.get("tags")
        snapshot_id = row.get("id")
        if not isinstance(tags, list) or not isinstance(snapshot_id, str):
            return False
        if "complete" not in tags:
            ids.append(snapshot_id)
    if not ids:
        return False
    status, _output = restic(
        ["tag", "--add", "complete", *ids],
        repository=repository,
        password=key,
    )
    return status == 0


def main(argument: str | None = None) -> None:  # noqa: C901 - one reviewed capture
    encoded = sys.argv[1] if argument is None else argument
    document = json.loads(gzip.decompress(base64.b64decode(encoded)))
    identifier = str(document.get("identifier", ""))
    repository = str(document.get("repository", ""))
    key = str(document.get("server_key", ""))
    point = str(document.get("point", ""))
    at = str(document.get("at", ""))
    scope = str(document.get("scope", ""))
    application = str(document.get("application", ""))
    if (
        IDENTIFIER.fullmatch(identifier) is None
        or repository != f"{REPOSITORY_ROOT}/{identifier}/onsite"
        or not key.startswith("/etc/barectl/backups/")
        or len(point) != 16
        or not at
        or scope not in ("full", "files")
        or application not in APPLICATIONS
        or not isinstance(document.get("restic_time"), str)
        or RESTIC_TIME.fullmatch(str(document["restic_time"])) is None
    ):
        emit_result({"class": "failed"})
        raise SystemExit(REFUSED)
    stage("preflight")
    try:
        account = pwd.getpwnam("s" + identifier)
    except KeyError:
        emit_result(
            document_result(document, "refused", "backup_site", point=point, snapshots=0, size=0)
        )
        raise SystemExit(REFUSED) from None
    if account.pw_uid < 1000 or account.pw_uid >= 30000:
        emit_result(
            document_result(document, "refused", "backup_site", point=point, snapshots=0, size=0)
        )
        raise SystemExit(REFUSED)
    if (
        not os.path.isfile(os.path.join(repository, "config"))
        or not safe_config(os.path.join(repository, "config"))
        or not locked_file(key, mode=0o600)
        or not controlled(REPOSITORY_ROOT)
    ):
        emit_result(
            document_result(
                document, "refused", "backup_repository", point=point, snapshots=0, size=0
            )
        )
        raise SystemExit(REFUSED)
    try:
        settings = site_settings(document)
        files = reviewed_files(settings, application)
        if files != document.get("files"):
            raise ValueError("The full backup file set changed.")
        if open_file(settings, application) != document.get("caddy"):
            raise ValueError("The site's open configuration changed.")
        if maintenance_file(settings) != document.get("gate"):
            raise ValueError("The maintenance gate changed.")
        if (scope == "files") != (not document.get("engine")):
            raise ValueError("The full backup scope changed.")
    except ValueError:
        emit_result(
            document_result(document, "refused", "evidence", point=point, snapshots=0, size=0)
        )
        raise SystemExit(REFUSED) from None
    try:
        lock = site_lock(identifier, account.pw_gid)
    except OSError, ValueError:
        emit_result(
            document_result(document, "refused", "backup_lock", point=point, snapshots=0, size=0)
        )
        raise SystemExit(REFUSED) from None
    if lock is None:
        emit_result(
            document_result(document, "lock_busy", "backup_lock", point=point, snapshots=0, size=0)
        )
        raise SystemExit(LOCK_BUSY) from None
    try:
        if free_bytes() < HEADROOM_BYTES:
            emit_result(
                document_result(
                    document, "refused", "backup_disk", point=point, snapshots=0, size=0
                )
            )
            raise SystemExit(REFUSED)
        if not fence(document, identifier, gate=True):
            emit_result(
                document_result(
                    document, "refused", "automation_fence", point=point, snapshots=0, size=0
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
                    )
                )
                raise SystemExit(PARTIAL)
            emit_result(
                document_result(
                    document, "refused", "backup_gate", point=point, snapshots=0, size=0
                )
            )
            raise SystemExit(REFUSED)
        emit_result(
            document_result(document, "partial", "backup_paused", point=point, snapshots=0, size=0)
        )
        stage("drain")
        try:
            drained = drain(settings)
        except OSError, ValueError:
            drained = False
        if not drained:
            emit_result(
                document_result(
                    document, "partial", "backup_idle", point=point, snapshots=0, size=0
                )
            )
            raise SystemExit(PARTIAL)
        stage("paused")
        size = 0
        expected = ["files"] if scope == "files" else ["database", "files"]
        for part in expected:
            status, part_size = capture(
                document,
                part=part,
                argv=backup_argv(document, part),
                repository=repository,
                key=key,
            )
            size += part_size
            found = set()
            for row in snapshots(repository, key, point):
                tags = row.get("tags")
                if isinstance(tags, list) and f"part:{part}" in tags:
                    found.add(row.get("id"))
            reason = "backup_dump" if part == "database" else "backup_files"
            if status != 0 or len(found) != 1:
                emit_result(
                    document_result(
                        document,
                        "partial",
                        "backup_partial" if found else reason,
                        point=point,
                        snapshots=sum(
                            1
                            for row in snapshots(repository, key, point)
                            if isinstance(row.get("tags"), list)
                        ),
                        size=size,
                    )
                )
                raise SystemExit(PARTIAL)
        if not mark_complete(document, repository, key) or not complete_point(
            document, repository, key
        ):
            emit_result(
                document_result(
                    document,
                    "partial",
                    "backup_verify",
                    point=point,
                    snapshots=len(expected),
                    size=size,
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
                    "backup_gate",
                    point=point,
                    snapshots=len(expected),
                    size=size,
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
                    snapshots=len(expected),
                    size=size,
                )
            )
            raise SystemExit(PARTIAL)
        offsite = ""
        reason = ""
        plan = document.get("offsite")
        if isinstance(plan, dict):
            copy_class, copy_reason = copy_point(identifier, point, repository, key, plan)
            offsite = "copied" if copy_class == "succeeded" else "failed"
            if copy_class != "succeeded":
                reason = copy_reason
        emit_result(
            document_result(
                document,
                "succeeded",
                reason,
                point=point,
                snapshots=len(expected),
                size=size,
                offsite=offsite,
            )
        )
        raise SystemExit(SUCCESS)
    finally:
        os.close(lock)


if __name__ == "__main__":
    main()
