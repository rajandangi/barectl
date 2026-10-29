"""Connect existing backup storage on another server (#408).

The access keys and the recovery passphrase arrive only as the staged confidential file.
The body proves the bucket answers with those keys, opens each source site repository with
the passphrase alone and lists its Barectl recovery points read-only. It writes only the
root-only non-secret config and key files on this server, and emits the bounded listing as
one safe result line so a fresh controller reconstructs what it can restore.
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
    controlled,
    emit_result,
    locked_file,
    offsite_extra,
    restic,
    stage,
)

OFFSITE_ROOT = KEY_ROOT + "/offsite"
OFFSITE_CAPTURE = OFFSITE_ROOT + "/capture.env"
OFFSITE_PRUNE = OFFSITE_ROOT + "/prune.env"
OFFSITE_SOURCES = OFFSITE_ROOT + "/sources"
PROVIDERS = ("s3", "r2")
MAX_ROWS = 500
MAX_SITES = 64


def refused(reason: str) -> NoReturn:
    emit_result({"class": "refused", "reason": reason, "kind": "connect"})
    raise SystemExit(REFUSED)


def failed(reason: str) -> NoReturn:
    emit_result({"class": "failed", "reason": reason, "kind": "connect"})
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


def write_private(path: str, text: str) -> None:
    temporary = path + ".tmp"
    payload = text.encode()
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    if not locked_file(path, mode=0o600):
        raise ValueError("The connected storage file was not written safely.")


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


def repository(config: dict[str, object], identifier: str) -> str:
    return f"s3:{config['endpoint']}/{config['bucket']}/{config['prefix']}/{identifier}"


def passphrase_file(secret_path: str, passphrase: str) -> str:
    path = secret_path + ".passphrase"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, passphrase.encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def safe_rows(text: str) -> list[dict[str, object]] | None:
    try:
        value = json.loads(text)
    except ValueError:
        return None
    if not isinstance(value, list):
        return None
    rows: list[dict[str, object]] = []
    for row in value[:MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        identifier = row.get("id")
        tags = row.get("tags")
        when = row.get("time")
        if not isinstance(identifier, str) or len(identifier) != 64:
            continue
        if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
            continue
        if "barectl" not in tags:
            continue
        summary = row.get("summary")
        kept: dict[str, object] = {
            "id": identifier,
            "time": when if isinstance(when, str) and len(when) <= 40 else "",
            "tags": tags[:16],
        }
        if isinstance(summary, dict):
            kept["summary"] = {
                key: summary[key]
                for key in ("total_bytes_processed", "data_added")
                if type(summary.get(key)) is int
            }
        rows.append(kept)
    return rows


def existing_config() -> dict[str, str] | None:
    path = OFFSITE_ROOT + "/config"
    if not os.path.isfile(path) or not locked_file(path, mode=0o600):
        return None
    values: dict[str, str] = {}
    for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if not separator:
            return None
        values[name] = value
    return values


def connect(document: dict[str, object], secret_path: str) -> None:  # noqa: C901 - one connect
    config = cast(dict[str, object], document.get("config"))
    sites_value = document.get("sites")
    if (
        not config_ok(config)
        or not isinstance(sites_value, list)
        or not 1 <= len(sites_value) <= MAX_SITES
        or not all(isinstance(site, str) and site for site in sites_value)
        or len(set(sites_value)) != len(sites_value)
        or document.get("config_path") != OFFSITE_ROOT + "/config"
        or document.get("capture_path") != OFFSITE_CAPTURE
        or document.get("prune_path") != OFFSITE_PRUNE
        or document.get("sources_path") != OFFSITE_SOURCES
    ):
        failed("connect_review")
    sites = [str(site) for site in sites_value]
    stage("preflight")
    try:
        values = secret_values(secret_path)
        access = key_value(values.get("access_key"))
        secret = key_value(values.get("secret_key"))
        passphrase = key_value(values.get("passphrase"))
        if len(passphrase) < 12:
            raise ValueError("Not a confidential value.")
        prune_access = (
            key_value(values.get("prune_access_key")) if values.get("prune_access_key") else ""
        )
        prune_secret = (
            key_value(values.get("prune_secret_key")) if values.get("prune_secret_key") else ""
        )
        if bool(prune_access) != bool(prune_secret):
            raise ValueError("Not a confidential value.")
        if config.get("provider") != "s3" and (prune_access or prune_secret):
            raise ValueError("Not a confidential value.")
    except ValueError:
        refused("connect_key")
    existing = existing_config()
    reviewed = {
        name: str(config[name])
        for name in ("provider", "bucket", "region", "endpoint", "prefix", "prune")
    }
    if existing is not None and existing != reviewed:
        refused("connect_settings")
    if not controlled(KEY_ROOT):
        refused("connect_key")
    extra = offsite_extra(config, {"AWS_ACCESS_KEY_ID": access, "AWS_SECRET_ACCESS_KEY": secret})
    temporary = passphrase_file(secret_path, passphrase)
    sources: list[dict[str, object]] = []
    try:
        stage("credentials")
        for identifier in sites:
            status, output = restic(
                ["snapshots", "--json", "--no-lock"],
                repository=repository(config, identifier),
                password=temporary,
                extra=extra,
            )
            if status == 10:
                refused("connect_repository")
            if status == 12:
                refused("connect_password")
            if status:
                failed("connect_repository")
            rows = safe_rows(output)
            if rows is None:
                failed("connect_repository")
            sources.append({"site": identifier, "rows": rows, "problem": ""})
        stage("sources")
        if not os.path.lexists(OFFSITE_ROOT):
            os.makedirs(OFFSITE_ROOT, mode=0o700)
        if not controlled(OFFSITE_ROOT) or (os.stat(OFFSITE_ROOT).st_mode & 0o777) != 0o700:
            raise ValueError("The offsite directory is outside the convention.")
        write_private(
            OFFSITE_CAPTURE,
            f"AWS_ACCESS_KEY_ID={access}\nAWS_SECRET_ACCESS_KEY={secret}\n",
        )
        if prune_access:
            write_private(
                OFFSITE_PRUNE,
                f"AWS_ACCESS_KEY_ID={prune_access}\nAWS_SECRET_ACCESS_KEY={prune_secret}\n",
            )
        else:
            pathlib.Path(OFFSITE_PRUNE).unlink(missing_ok=True)
        write_private(
            OFFSITE_ROOT + "/config",
            "".join(f"{name}={reviewed[name]}\n" for name in reviewed),
        )
        write_private(
            OFFSITE_SOURCES,
            json.dumps({"version": 1, "sites": sites}, separators=(",", ":")),
        )
    except OSError, ValueError:
        failed("connect_key")
    finally:
        pathlib.Path(temporary).unlink(missing_ok=True)
    stage("verify")
    emit_result({"class": "succeeded", "kind": "connect", "sources": sources})
    raise SystemExit(0)


def main() -> None:
    document = json.loads(gzip.decompress(base64.b64decode(sys.argv[1])))
    connect(document, str(document.get("secret_path", "")))


if __name__ == "__main__":
    main()
