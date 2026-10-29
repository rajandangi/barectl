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
import sys

from backups.bodies.native import (
    FAILED,
    HEADROOM_BYTES,
    LOCK_BUSY,
    REFUSED,
    REPOSITORY_ROOT,
    RESTIC_BIN,
    RESTIC_TIME,
    classify,
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
    stage,
    summary_size,
)


def main() -> None:  # noqa: C901 - one reviewed capture
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
        emit_result({"class": "failed"})
        raise SystemExit(FAILED)
    stage("preflight")
    try:
        import pwd

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
        or not os.access(RESTIC_BIN, os.X_OK)
    ):
        emit_result(
            document_result(
                document, "refused", "backup_repository", point=point, snapshots=0, size=0
            )
        )
        raise SystemExit(REFUSED)
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
        raise SystemExit(LOCK_BUSY)
    try:
        if free_bytes() < HEADROOM_BYTES:
            emit_result(
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
        saved = summary_size(output)
        result_class, reason, code = classify(status, bool(found))
        offsite = ""
        if result_class in ("succeeded", "partial"):
            plan = document.get("offsite")
            if isinstance(plan, dict):
                os.close(lock)
                lock = -1
                copy_class, copy_reason = copy_point(identifier, point, repository, key, plan)
                offsite = "copied" if copy_class == "succeeded" else "failed"
                if copy_class != "succeeded" and result_class == "succeeded":
                    reason = copy_reason
        emit_result(
            document_result(
                document,
                result_class,
                reason,
                point=point,
                snapshots=len(found) if found else 0,
                size=saved,
                offsite=offsite,
            )
        )
        raise SystemExit(code)
    finally:
        if lock != -1:
            os.close(lock)


if __name__ == "__main__":
    main()
