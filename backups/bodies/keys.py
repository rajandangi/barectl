"""Replace the recovery passphrase without re-encrypting any backup (#408).

The old and new passphrases arrive only as the staged confidential file, and neither is
stored. The body adds the new key to every site repository (onsite and, when configured,
offsite), proves the new passphrase opens each one, and only then removes the old key. restic
keeps the data and the server key untouched; replacing a password never rewrites a pack.
"""

import base64
import gzip
import json
import os
import pathlib
import sys
from typing import NoReturn, cast

from backups.bodies.native import (
    KEY_ROOT,
    REFUSED,
    REPOSITORY_ROOT,
    controlled,
    emit_result,
    environment_file,
    locked_file,
    offsite_extra,
    restic,
    safe_config,
    stage,
)

OFFSITE_ROOT = KEY_ROOT + "/offsite"
OFFSITE_CAPTURE = OFFSITE_ROOT + "/capture.env"
PROVIDERS = ("s3", "r2")


def refused(reason: str) -> NoReturn:
    emit_result({"class": "refused", "reason": reason, "kind": "passphrase"})
    raise SystemExit(REFUSED)


def failed(reason: str) -> NoReturn:
    emit_result({"class": "failed", "reason": reason, "kind": "passphrase"})
    raise SystemExit(REFUSED)


def key_value(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Not a confidential value.")
    text = value.strip()
    if not 1 <= len(text) <= 256 or any(character in text for character in "\x00\r\n"):
        raise ValueError("Not a confidential value.")
    return text


def secret_values(path: str) -> dict[str, object]:
    if (
        not path.startswith("/run/barectl/secrets/")
        or not os.path.isfile(path)
        or not locked_file(path, mode=0o600)
        or os.path.getsize(path) > 4096
    ):
        raise ValueError("Not a confidential value.")
    try:
        value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except OSError, ValueError:
        raise ValueError("Not a confidential value.") from None
    if not isinstance(value, dict) or not isinstance(value.get("values"), dict):
        raise ValueError("Not a confidential value.")
    return cast(dict[str, object], value["values"])


def write_password(path: str, password: str) -> str:
    target = path
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, password.encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return target


def current_key(text: str) -> str:
    try:
        value = json.loads(text)
    except ValueError:
        return ""
    if not isinstance(value, list):
        return ""
    for row in value:
        if isinstance(row, dict) and row.get("current") is True and isinstance(row.get("id"), str):
            return str(row["id"])
    return ""


def opens(repository: str, password: str, extra: dict[str, str] | None = None) -> int:
    status, _output = restic(
        ["snapshots", "--json", "--no-lock"],
        repository=repository,
        password=password,
        extra=extra,
    )
    return status


def repository_list(document: dict[str, object]) -> list[tuple[str, str, dict[str, str] | None]]:
    """Every reviewed site repository as (label, URL, backend environment)."""
    sites = document.get("sites")
    config = cast(dict[str, object], document.get("config"))
    if not isinstance(sites, list) or not all(isinstance(site, str) for site in sites):
        return []
    offsite: dict[str, str] | None = None
    if config.get("provider") in PROVIDERS:
        try:
            offsite = environment_file(OFFSITE_CAPTURE)
        except OSError, ValueError:
            return []
    rows: list[tuple[str, str, dict[str, str] | None]] = []
    for site in sites:
        onsite = f"{REPOSITORY_ROOT}/{site}/onsite"
        key = f"{KEY_ROOT}/{site}.key"
        if not os.path.isfile(onsite + "/config") or not safe_config(onsite + "/config"):
            return []
        if not locked_file(key, mode=0o600):
            return []
        rows.append((f"onsite:{site}", onsite, None))
        if offsite is not None:
            destination = f"s3:{config['endpoint']}/{config['bucket']}/{config['prefix']}/{site}"
            rows.append(
                (
                    f"offsite:{site}",
                    destination,
                    offsite_extra(config, dict(offsite)),
                )
            )
    return rows


def replace(document: dict[str, object], secret_path: str) -> None:  # noqa: C901 - one sequence
    raw_config = document.get("config")
    if (
        document.get("version") != 1
        or not isinstance(raw_config, dict)
        or not isinstance(document.get("sites"), list)
        or document.get("config_path") != OFFSITE_ROOT + "/config"
        or document.get("capture_path") != OFFSITE_CAPTURE
    ):
        failed("passphrase_review")
    stage("preflight")
    try:
        values = secret_values(secret_path)
        old = key_value(values.get("old_passphrase"))
        new = key_value(values.get("new_passphrase"))
        if len(old) < 12 or len(new) < 12 or old == new:
            raise ValueError("Not a confidential value.")
    except ValueError:
        refused("passphrase_value")
    if not controlled(KEY_ROOT):
        refused("passphrase_key")
    rows = repository_list(document)
    if not rows:
        refused("passphrase_repository")
    old_file = write_password(secret_path + ".old", old)
    new_file = write_password(secret_path + ".new", new)
    replaced: list[tuple[str, str, str, dict[str, str] | None]] = []
    try:
        stage("keys")
        for label, repository, extra in rows:
            status, output = restic(
                ["key", "list", "--json"],
                repository=repository,
                password=old_file,
                extra=extra,
            )
            if status:
                refused("passphrase_old")
            old_id = current_key(output)
            if not old_id:
                failed("passphrase_key")
            if opens(repository, new_file, extra) != 0:
                status, _output = restic(
                    [
                        "key",
                        "add",
                        "--new-password-file",
                        new_file,
                        "--user",
                        "barectl-recovery",
                    ],
                    repository=repository,
                    password=old_file,
                    extra=extra,
                )
                if status:
                    failed("passphrase_key")
                if opens(repository, new_file, extra) != 0:
                    failed("passphrase_key")
            replaced.append((label, old_id, repository, extra))
        stage("verify")
        # Every repository opens with the new passphrase before any old key is removed.
        for _label, repository, extra in rows:
            if opens(repository, new_file, extra) != 0:
                failed("passphrase_new")
        for _label, old_id, repository, extra in replaced:
            status, _output = restic(
                ["key", "remove", old_id],
                repository=repository,
                password=new_file,
                extra=extra,
            )
            if status:
                failed("passphrase_old")
        closed = all(opens(repository, old_file, extra) == 12 for _label, repository, extra in rows)
        if not closed:
            failed("passphrase_old")
        for label, repository, extra in rows:
            site = label.split(":", 1)[1]
            if opens(repository, f"{KEY_ROOT}/{site}.key", extra) != 0:
                failed("passphrase_server_key")
    finally:
        pathlib.Path(old_file).unlink(missing_ok=True)
        pathlib.Path(new_file).unlink(missing_ok=True)
    emit_result(
        {
            "class": "succeeded",
            "kind": "passphrase",
            "repositories": len(rows),
        }
    )
    raise SystemExit(0)


def main() -> None:
    document = json.loads(gzip.decompress(base64.b64decode(sys.argv[1])))
    replace(document, str(document.get("secret_path", "")))


if __name__ == "__main__":
    main()
