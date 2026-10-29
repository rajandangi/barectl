"""Copy one existing recovery point from the onsite repository offsite (Phase D #403).

The copy holds the site's per-repository native lock, initialises the offsite repository
from the onsite one with copied chunker parameters when it is missing, and copies only the
reviewed point. A failed copy leaves the onsite point untouched and reports that the offsite
copy failed.
"""

import base64
import gzip
import json
import os
import re
import sys
from typing import NoReturn

from backups.bodies.native import (
    FAILED,
    KEY_ROOT,
    LOCK_BUSY,
    REFUSED,
    REPOSITORY_ROOT,
    SUCCESS,
    controlled,
    emit_result,
    environment_file,
    locked_file,
    release_mutation_lock,
    repository_lock,
    restic,
    safe_config,
)

IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}")
POINT = re.compile(r"[0-9a-f]{16}")


def refused(reason: str) -> NoReturn:
    emit_result({"class": "refused", "reason": reason, "kind": "copy"})
    raise SystemExit(REFUSED)


def failed(reason: str) -> NoReturn:
    emit_result({"class": "failed", "reason": reason, "kind": "copy"})
    raise SystemExit(FAILED)


def storage_ok(config: object) -> bool:
    return bool(
        isinstance(config, dict)
        and config.get("provider") in ("s3", "r2")
        and isinstance(config.get("bucket"), str)
        and isinstance(config.get("region"), str)
        and isinstance(config.get("endpoint"), str)
        and config.get("endpoint", "").startswith("https://")
        and isinstance(config.get("prefix"), str)
        and config.get("prune") in ("yes", "no")
    )


def complete_point(rows: list[dict[str, object]], point: str) -> bool:
    found = 0
    for row in rows:
        tags = row.get("tags")
        if not isinstance(tags, list) or "complete" not in tags:
            continue
        if f"point:{point}" in tags and "barectl" in tags:
            found += 1
    return found > 0


def copy(document: dict[str, object]) -> tuple[int, str]:  # noqa: C901 - one reviewed copy
    identifier = str(document.get("identifier", ""))
    point = str(document.get("point", ""))
    onsite = str(document.get("repository", ""))
    key = str(document.get("server_key", ""))
    offsite = document.get("offsite")
    if (
        IDENTIFIER.fullmatch(identifier) is None
        or POINT.fullmatch(point) is None
        or onsite != f"{REPOSITORY_ROOT}/{identifier}/onsite"
        or not key.startswith(KEY_ROOT + "/")
        or not isinstance(offsite, dict)
        or not storage_ok(offsite.get("storage"))
        or offsite.get("capture_env") != KEY_ROOT + "/offsite/capture.env"
    ):
        failed("offsite_copy")
    storage = offsite["storage"]
    destination = str(offsite.get("repository", ""))
    expected = f"s3:{storage['endpoint']}/{storage['bucket']}/{storage['prefix']}/{identifier}"
    if destination != expected:
        failed("offsite_copy")
    capture = str(offsite.get("capture_env", ""))
    stage_names = ("preflight", "lock", "copy", "verify")
    sys.stdout.write("barectl-stage " + stage_names[0] + "\n")
    sys.stdout.flush()
    if (
        not os.path.isfile(onsite + "/config")
        or not safe_config(onsite + "/config")
        or not locked_file(key, mode=0o600)
        or not controlled(KEY_ROOT)
        or not controlled(REPOSITORY_ROOT)
    ):
        refused("offsite_repository")
    try:
        extra = environment_file(capture)
    except OSError, ValueError:
        refused("offsite_key")
    if not extra.get("AWS_ACCESS_KEY_ID") or not extra.get("AWS_SECRET_ACCESS_KEY"):
        refused("offsite_key")
    if isinstance(storage.get("region"), str):
        extra["AWS_DEFAULT_REGION"] = storage["region"]
    release_mutation_lock()
    try:
        lock = repository_lock(identifier)
    except OSError, ValueError:
        refused("offsite_key")
    if lock is None:
        emit_result(
            {
                "class": "lock_busy",
                "reason": "backup_lock",
                "kind": "copy",
                "site": identifier,
                "point": point,
            }
        )
        raise SystemExit(LOCK_BUSY)
    try:
        sys.stdout.write("barectl-stage " + stage_names[2] + "\n")
        sys.stdout.flush()
        status, _output = restic(
            ["snapshots", "--json", "--no-lock"],
            repository=destination,
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
                repository=destination,
                password=key,
                extra=extra,
            )
            if status:
                return FAILED, "offsite_repository"
        elif status:
            return FAILED, "offsite_repository"
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
            repository=destination,
            password=key,
            extra=extra,
        )
        sys.stdout.write("barectl-stage " + stage_names[3] + "\n")
        sys.stdout.flush()
        found = snapshots_with_environment(destination, key, point, extra)
        if status or not found:
            return FAILED, "offsite_copy"
        return SUCCESS, ""
    finally:
        os.close(lock)


def snapshots_with_environment(
    repository: str, password: str, point: str, extra: dict[str, str]
) -> list[dict[str, object]]:
    status, text = restic(
        ["snapshots", "--json", "--no-lock", "--tag", "point:" + point],
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
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def main() -> None:
    document = json.loads(gzip.decompress(base64.b64decode(sys.argv[1])))
    code, reason = copy(document)
    identifier = str(document.get("identifier", ""))
    point = str(document.get("point", ""))
    if code == SUCCESS:
        emit_result(
            {
                "class": "succeeded",
                "kind": "copy",
                "site": identifier,
                "point": point,
                "offsite": "copied",
            }
        )
    else:
        emit_result(
            {
                "class": "failed",
                "reason": reason,
                "kind": "copy",
                "site": identifier,
                "point": point,
                "offsite": "failed",
            }
        )
    raise SystemExit(code)


if __name__ == "__main__":
    main()
