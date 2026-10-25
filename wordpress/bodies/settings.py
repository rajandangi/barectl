"""Write a WordPress site's extra constants in its private configuration (Phase B #383).

The reviewed values arrive in ADR 0032's root-only staging file. The body computes the new
configuration while preserving every fixed and untouched line, then hands the text to a
fixed writer running as the site user over standard input.
"""

import base64
import gzip
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

from sites.bodies.common import open_site_lock, result, site_account, stage
from wordpress.convention import (
    apply_constants,
    extra_constants,
    private_configuration_path,
    private_configuration_problem,
    valid_constant_key,
    write_as_site,
)

SECRET_PATH = re.compile(r"/run/barectl/secrets/[0-9a-f]{32}")
SECRET_BYTES = 4096
MAX_CHANGE = 64


def _private(path: pathlib.Path, account: str) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    try:
        import pwd

        owner = pwd.getpwnam(account)
    except KeyError:
        return False
    return (
        info.st_uid == owner.pw_uid
        and info.st_mode & 0o077 == 0
        and info.st_mode & 0o170000 == 0o100000
    )


def read_configuration(identifier: str) -> str:
    path = pathlib.Path(private_configuration_path(identifier))
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError, ValueError:
        return ""
    return text if len(text.encode("utf-8", "replace")) <= 65536 else ""


def _changes(document: dict[str, object]) -> list[dict[str, object]]:
    raw = document.get("changes")
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_CHANGE:
        raise ValueError("The reviewed settings changes are not valid.")
    changes: list[dict[str, object]] = []
    keys: set[str] = set()
    for change in raw:
        if not isinstance(change, dict) or set(change) != {"key", "action", "digest"}:
            raise ValueError("The reviewed settings changes are not valid.")
        key, action = change["key"], change["action"]
        if (
            not isinstance(key, str)
            or not valid_constant_key(key)
            or action not in ("set", "remove")
            or key in keys
        ):
            raise ValueError("The reviewed settings changes are not valid.")
        keys.add(key)
        changes.append(change)
    return changes


def _values(secret_path: str, fields: list[dict[str, object]]) -> dict[str, str]:
    path = pathlib.Path(secret_path)
    try:
        raw = path.read_bytes()
    finally:
        path.unlink(missing_ok=True)
    if not 0 < len(raw) <= SECRET_BYTES or b"\0" in raw:
        raise ValueError("The confidential value could not be used.")
    try:
        document = json.loads(raw)
    except ValueError as error:
        raise ValueError("The confidential value could not be used.") from error
    values = document.get("values") if isinstance(document, dict) else None
    if not isinstance(values, dict):
        raise ValueError("The confidential value could not be used.")
    wanted = {str(field["key"]): field for field in fields if field.get("key")}
    if set(values) != set(wanted):
        raise ValueError("The confidential value could not be used.")
    decoded: dict[str, str] = {}
    for key, value in values.items():
        if not isinstance(value, str) or len(value) > 2048:
            raise ValueError("The confidential value could not be used.")
        if any(character in "\x00\r\n" for character in value):
            raise ValueError("The confidential value could not be used.")
        decoded[key] = value
    return decoded


def edit_constants(document: dict[str, object]) -> None:  # noqa: C901 - reviewed stages
    identifier = str(document.get("identifier", ""))
    secret_path = str(document.get("secret_path", ""))
    if re.fullmatch(r"[a-z][a-z0-9]{2,23}", identifier) is None:
        result("refused", "evidence")
        return
    path = pathlib.Path(private_configuration_path(identifier))
    lock: int | None = None
    try:
        changes = _changes(document)
        fields = document.get("secret_fields")
        if not isinstance(fields, list):
            result("refused", "evidence")
            return
        values: dict[str, str] = {}
        if fields:
            if SECRET_PATH.fullmatch(secret_path) is None:
                result("refused", "settings_secret")
                return
            values = _values(secret_path, fields)
        try:
            lock = open_site_lock(identifier)
        except BlockingIOError:
            result("lock_busy")
            return
        except OSError, ValueError:
            result("refused", "unsafe_lock")
            return
        stage("preflight")
        if site_account(identifier) is None or not _private(path, "s" + identifier):
            result("refused", "wordpress_settings")
            return
        before = read_configuration(identifier)
        if not before or hashlib.sha256(before.encode("utf-8")).hexdigest() != document.get(
            "configuration_digest"
        ):
            result("refused", "evidence")
            return
        if private_configuration_problem(before, identifier):
            result("refused", "wordpress_settings")
            return
        existing = {key for key, _value in extra_constants(before, identifier)}
        for change in changes:
            key, action = str(change["key"]), str(change["action"])
            if action == "remove" and key not in existing:
                result("refused", "evidence")
                return
            if action == "set" and key not in values:
                result("refused", "settings_secret")
                return
        stage("write")
        reviewed: list[dict[str, object]] = [
            {
                "key": str(change["key"]),
                "action": str(change["action"]),
                "value": values.get(str(change["key"]), ""),
            }
            for change in changes
        ]
        try:
            text = apply_constants(before, reviewed, identifier)
            if private_configuration_problem(text, identifier):
                raise ValueError("The new configuration is outside the supported grammar.")
            write_as_site("s" + identifier, str(path), text)
        except ValueError, OSError, subprocess.TimeoutExpired:
            result("refused", "wordpress_settings")
            return
        after = read_configuration(identifier)
        if after != text or private_configuration_problem(after, identifier):
            result("partial", "wordpress_settings")
            return
        stage("verify")
        result("succeeded")
    except ValueError, OSError, subprocess.TimeoutExpired:
        sys.stderr.write("barectl-problem The private configuration could not be changed.\n")
        sys.stderr.flush()
        result("refused", "wordpress_settings")
    finally:
        if secret_path:
            pathlib.Path(secret_path).unlink(missing_ok=True)
        if lock is not None:
            os.close(lock)


if __name__ == "__main__":
    edit_constants(json.loads(gzip.decompress(base64.b64decode(sys.argv[1]))))
