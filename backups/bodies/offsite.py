"""Set up or remove offsite storage on one server (Phase D #403).

Access keys and the recovery passphrase arrive only as the staged confidential file. The
body proves the bucket answers writes and listings, initialises each backed-up site's
offsite repository from its onsite repository with copied chunker parameters, adds the
recovery passphrase as a key there, and only then writes the root-only config and key files.
Removing the setting deletes those files and never an offsite copy.
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
    SUCCESS,
    controlled,
    emit_result,
    locked_file,
    offsite_extra,
    restic,
    safe_config,
    stage,
)

OFFSITE_ROOT = KEY_ROOT + "/offsite"
OFFSITE_CAPTURE = OFFSITE_ROOT + "/capture.env"
OFFSITE_PRUNE = OFFSITE_ROOT + "/prune.env"
OFFSITE_HEALTH = "_health"
PROVIDERS = ("s3", "r2")


def refused(reason: str) -> NoReturn:
    emit_result({"class": "refused", "reason": reason, "kind": "offsite"})
    raise SystemExit(REFUSED)


def failed(reason: str) -> NoReturn:
    emit_result({"class": "failed", "reason": reason, "kind": "offsite"})
    raise SystemExit(REFUSED)


def key_value(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Not a confidential value.")
    text = value.strip()
    if not 1 <= len(text) <= 256 or any(character in text for character in "\x00\r\n"):
        raise ValueError("Not a confidential value.")
    return text


def write_private(path: str, text: str) -> None:
    temporary = path + ".tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, text.encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    if not locked_file(path, mode=0o600):
        raise ValueError("The offsite file was not written safely.")


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


def repository(config: dict[str, object], identifier: str) -> str:
    return f"s3:{config['endpoint']}/{config['bucket']}/{config['prefix']}/{identifier}"


def environment(access: str, secret: str) -> dict[str, str]:
    return {"AWS_ACCESS_KEY_ID": access, "AWS_SECRET_ACCESS_KEY": secret}


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


def healthy(config: dict[str, object], health_key: str, extra: dict[str, str]) -> bool:
    health = repository(config, OFFSITE_HEALTH)
    status, _output = restic(
        ["snapshots", "--json", "--no-lock"],
        repository=health,
        password=health_key,
        extra=extra,
    )
    if status == 0:
        return True
    status, _output = restic(["init"], repository=health, password=health_key, extra=extra)
    if status:
        return False
    status, _output = restic(
        ["snapshots", "--json", "--no-lock"],
        repository=health,
        password=health_key,
        extra=extra,
    )
    return status == 0


def passphrase_file(secret_path: str, passphrase: str) -> str:
    path = secret_path + ".passphrase"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, passphrase.encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def site_repository(
    identifier: str,
    config: dict[str, object],
    extra: dict[str, str],
    passphrase: str,
    secret_path: str,
) -> bool:
    onsite = f"{REPOSITORY_ROOT}/{identifier}/onsite"
    key = f"{KEY_ROOT}/{identifier}.key"
    if not os.path.isfile(onsite + "/config") or not safe_config(onsite + "/config"):
        return False
    if not locked_file(key, mode=0o600):
        return False
    destination = repository(config, identifier)
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
            return False
    elif status:
        return False
    temporary = passphrase_file(secret_path, passphrase)
    try:
        status, _output = restic(
            ["snapshots", "--json", "--no-lock"],
            repository=destination,
            password=temporary,
            extra=extra,
        )
        if status:
            status, _output = restic(
                ["key", "add", "--new-password-file", temporary],
                repository=destination,
                password=key,
                extra=extra,
            )
            if status:
                return False
            status, _output = restic(
                ["snapshots", "--json", "--no-lock"],
                repository=destination,
                password=temporary,
                extra=extra,
            )
            if status:
                return False
    finally:
        pathlib.Path(temporary).unlink(missing_ok=True)
    return True


def setup(document: dict[str, object], secret_path: str) -> None:  # noqa: C901 - one reviewed setup
    config = cast(dict[str, object], document.get("config"))
    sites_value = document.get("sites")
    if (
        not config_ok(config)
        or not isinstance(sites_value, list)
        or not all(isinstance(site, str) for site in sites_value)
        or document.get("config_path") != OFFSITE_ROOT + "/config"
        or document.get("capture_path") != OFFSITE_CAPTURE
        or document.get("prune_path") != OFFSITE_PRUNE
    ):
        failed("offsite_repository")
    sites = [str(site) for site in sites_value]
    stage("preflight")
    try:
        values = secret_values(secret_path)
        access = key_value(values.get("access_key"), "access_key")
        secret = key_value(values.get("secret_key"), "secret_key")
        passphrase = key_value(values.get("passphrase"), "passphrase")
        if len(passphrase) < 12:
            raise ValueError("Not a confidential value.")
        prune_access = (
            key_value(values.get("prune_access_key", ""), "prune_access_key")
            if values.get("prune_access_key")
            else ""
        )
        prune_secret = (
            key_value(values.get("prune_secret_key", ""), "prune_secret_key")
            if values.get("prune_secret_key")
            else ""
        )
        if bool(prune_access) != bool(prune_secret):
            raise ValueError("Not a confidential value.")
        if config.get("provider") != "s3" and (prune_access or prune_secret):
            raise ValueError("Not a confidential value.")
    except ValueError:
        refused("offsite_key")
    health_key = document.get("health_key")
    if not isinstance(health_key, str) or not health_key.startswith(KEY_ROOT + "/"):
        refused("offsite_key")
    if not os.path.isfile(health_key) or not locked_file(health_key, mode=0o600):
        refused("offsite_key")
    if not controlled(KEY_ROOT):
        refused("offsite_key")
    extra = offsite_extra(config, environment(access, secret))
    stage("credentials")
    if not healthy(config, health_key, extra):
        refused("offsite_bucket")
    stage("bucket")
    for identifier in sites:
        if not site_repository(identifier, config, extra, passphrase, secret_path):
            failed("offsite_repository")
    stage("repositories")
    try:
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
            "".join(
                f"{name}={config[name]}\n"
                for name in ("provider", "bucket", "region", "endpoint", "prefix", "prune")
            ),
        )
    except OSError, ValueError:
        failed("offsite_key")
    stage("verify")
    if not healthy(config, health_key, extra):
        failed("offsite_bucket")
    emit_result({"class": "succeeded", "kind": "offsite", "action": "setup"})
    raise SystemExit(SUCCESS)


def remove(document: dict[str, object], secret_path: str) -> None:
    config = cast(dict[str, object], document.get("config"))
    if not config_ok(config):
        failed("offsite_remove")
    stage("preflight")
    try:
        values = secret_values(secret_path)
    except ValueError:
        refused("offsite_key")
    if str(values.get("bucket", "")) != str(config.get("bucket", "")):
        refused("offsite_remove")
    stage("remove")
    for path in (OFFSITE_ROOT + "/config", OFFSITE_CAPTURE, OFFSITE_PRUNE):
        try:
            pathlib.Path(path).unlink(missing_ok=True)
        except OSError:
            failed("offsite_remove")
    stage("verify")
    for path in (OFFSITE_ROOT + "/config", OFFSITE_CAPTURE, OFFSITE_PRUNE):
        if os.path.lexists(path):
            failed("offsite_remove")
    emit_result({"class": "succeeded", "kind": "offsite", "action": "remove"})
    raise SystemExit(SUCCESS)


def main() -> None:
    document = json.loads(gzip.decompress(base64.b64decode(sys.argv[1])))
    secret_path = str(document.get("secret_path", ""))
    if document.get("action") == "remove":
        remove(document, secret_path)
    else:
        setup(document, secret_path)


if __name__ == "__main__":
    main()
