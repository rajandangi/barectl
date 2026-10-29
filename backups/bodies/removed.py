"""Delete the kept backups of one removed site (#410).

The review binds the removed site's onsite repository, server key and, when offsite storage
exists, its offsite repository. The body holds that repository's native lock, removes the
offsite recovery points with restic's filtered remove-all and prune, then removes the onsite
repository directory and server key. It never touches another site's repository or the
offsite setting itself.
"""

import base64
import gzip
import json
import os
import pathlib
import re
import shutil
import sys
from typing import NoReturn, cast

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
    offsite_extra,
    repository_lock,
    restic,
    safe_config,
    stage,
)

IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}\Z")
PROVIDERS = ("s3", "r2")
OFFSITE_ROOT = KEY_ROOT + "/offsite"
OFFSITE_CAPTURE = OFFSITE_ROOT + "/capture.env"
OFFSITE_PRUNE = OFFSITE_ROOT + "/prune.env"
LOCK_WAIT_SECONDS = 5.0


def refused(reason: str) -> NoReturn:
    emit_result({"class": "refused", "reason": reason, "kind": "removed"})
    raise SystemExit(REFUSED)


def failed(reason: str) -> NoReturn:
    emit_result({"class": "failed", "reason": reason, "kind": "removed"})
    raise SystemExit(FAILED)


def config_ok(config: object) -> bool:
    return bool(
        isinstance(config, dict)
        and config.get("provider") in PROVIDERS
        and isinstance(config.get("bucket"), str)
        and isinstance(config.get("region"), str)
        and isinstance(config.get("endpoint"), str)
        and isinstance(config.get("prefix"), str)
        and config.get("prune") in ("yes", "no")
    )


def offsite(value: object, identifier: str) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "repository",
        "capture_env",
        "prune_env",
        "storage",
    }:
        refused("evidence")
    config = cast(dict[str, object], value["storage"])
    if (
        not config_ok(config)
        or value["capture_env"] != OFFSITE_CAPTURE
        or value["prune_env"] != OFFSITE_PRUNE
        or value["repository"]
        != f"s3:{config['endpoint']}/{config['bucket']}/{config['prefix']}/{identifier}"
    ):
        refused("evidence")
    return {
        "repository": str(value["repository"]),
        "capture_env": OFFSITE_CAPTURE,
        "prune_env": OFFSITE_PRUNE,
        "storage": config,
    }


def _connection(value: dict[str, object]) -> tuple[str, dict[str, str]]:
    storage = cast(dict[str, object], value["storage"])
    prune = pathlib.Path(str(value["prune_env"]))
    capture = str(value["capture_env"])
    try:
        extra = environment_file(str(prune) if prune.is_file() else capture)
    except OSError, ValueError:
        refused("offsite_key")
    if not extra.get("AWS_ACCESS_KEY_ID") or not extra.get("AWS_SECRET_ACCESS_KEY"):
        refused("offsite_key")
    return str(value["repository"]), offsite_extra(storage, extra)


def remove_offsite(value: dict[str, object], identifier: str) -> None:
    repository, extra = _connection(value)
    status, _output = restic(
        ["forget", "--tag", "barectl", "--unsafe-allow-remove-all", "--prune"],
        repository=repository,
        password=f"{KEY_ROOT}/{identifier}.key",
        extra=extra,
    )
    if status:
        failed("removed_backup")
    status, text = restic(
        ["snapshots", "--json", "--no-lock", "--tag", "barectl"],
        repository=repository,
        password=f"{KEY_ROOT}/{identifier}.key",
        extra=extra,
    )
    if status:
        failed("removed_backup")
    try:
        rows = json.loads(text)
    except ValueError:
        failed("removed_backup")
    if not isinstance(rows, list) or rows:
        failed("removed_backup")


def remove_onsite(identifier: str) -> None:
    directory = pathlib.Path(f"{REPOSITORY_ROOT}/{identifier}")
    if not controlled(str(directory)) or not safe_config(str(directory / "onsite" / "config")):
        refused("evidence")
    key = pathlib.Path(f"{KEY_ROOT}/{identifier}.key")
    if not locked_file(str(key), mode=0o600):
        refused("evidence")
    try:
        shutil.rmtree(directory)
        key.unlink(missing_ok=True)
    except OSError:
        failed("removed_backup")
    if directory.exists() or key.exists():
        failed("removed_backup")


def main(argument: str | None = None) -> None:
    encoded = sys.argv[1] if argument is None else argument
    document = json.loads(gzip.decompress(base64.b64decode(encoded)))
    if not isinstance(document, dict):
        refused("evidence")
    identifier = document.get("identifier")
    if (
        document.get("version") != 1
        or not isinstance(identifier, str)
        or IDENTIFIER.fullmatch(identifier) is None
        or document.get("repository") != f"{REPOSITORY_ROOT}/{identifier}/onsite"
        or document.get("server_key") != f"{KEY_ROOT}/{identifier}.key"
    ):
        refused("evidence")
    try:
        storage = offsite(document.get("offsite"), identifier)
    except ValueError:
        refused("evidence")
    stage("preflight")
    try:
        lock = repository_lock(identifier, wait_seconds=LOCK_WAIT_SECONDS)
    except OSError, ValueError:
        refused("evidence")
    if lock is None:
        emit_result({"class": "lock_busy", "reason": "backup_lock", "kind": "removed"})
        raise SystemExit(LOCK_BUSY)
    try:
        stage("delete")
        if storage is not None:
            remove_offsite(storage, identifier)
        stage("verify")
        remove_onsite(identifier)
    finally:
        os.close(lock)
    emit_result(
        {
            "class": "succeeded",
            "reason": "",
            "kind": "removed",
            "site": identifier,
        }
    )
    raise SystemExit(SUCCESS)


if __name__ == "__main__":
    main()
