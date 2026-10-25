"""Write a Laravel site's private environment and rebuild its cached configuration.

The reviewed values arrive in the root-only staging file of ADR 0032. This body computes the
new file while preserving every untouched line, then hands the whole text to a fixed writer
running as the site user over standard input, so the values never reach argv or a
world-readable file (Phase B #383).
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
from types import SimpleNamespace

from automation.bodies.worker_env import restart_workers
from laravel.bodies.common import (
    ENVIRONMENT_KEY,
    _private_file_ok,
    apply_environment,
    environment_entries_from_text,
    environment_path,
    read_environment,
    user_command,
)
from sites.bodies.common import open_site_lock, result, setting, site_account, stage

SECRET_PATH = re.compile(r"/run/barectl/secrets/[0-9a-f]{32}")
SECRET_BYTES = 4096
MAX_CHANGE = 64
WRITE_SCRIPT = (
    "import json,os,sys,tempfile\n"
    "payload=json.load(sys.stdin)\n"
    "path=payload['path']\n"
    "text=payload['text']\n"
    "directory=os.path.dirname(path)\n"
    "name=os.path.basename(path)\n"
    "fd,temp=tempfile.mkstemp(prefix='.barectl-',suffix='.tmp',dir=directory)\n"
    "try:\n"
    "    os.fchmod(fd,0o600)\n"
    "    with os.fdopen(fd,'w',encoding='utf-8') as output:\n"
    "        output.write(text)\n"
    "        output.flush()\n"
    "        os.fsync(output.fileno())\n"
    "    os.replace(temp,path)\n"
    "except BaseException:\n"
    "    try: os.unlink(temp)\n"
    "    except OSError: pass\n"
    "    raise\n"
)


def _write_as_site(settings: SimpleNamespace, path: pathlib.Path, text: str) -> None:
    payload = json.dumps({"path": str(path), "text": text}).encode()
    completed = subprocess.run(  # noqa: S603 - fixed argv as the site user
        [
            "/usr/sbin/runuser",
            "-u",
            str(settings.account),
            "--",
            "/usr/bin/python3",
            "-c",
            WRITE_SCRIPT,
        ],
        input=payload,
        capture_output=True,
        timeout=120,
        check=False,
    )
    if completed.returncode:
        raise ValueError("The environment could not be written as the site user.")


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


def _changes(document: dict[str, object]) -> list[dict[str, object]]:
    raw = document.get("changes")
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_CHANGE:
        raise ValueError("The reviewed environment changes are not valid.")
    changes: list[dict[str, object]] = []
    keys: set[str] = set()
    for change in raw:
        if not isinstance(change, dict) or set(change) != {"key", "action", "digest"}:
            raise ValueError("The reviewed environment changes are not valid.")
        key, action = change["key"], change["action"]
        if (
            not isinstance(key, str)
            or ENVIRONMENT_KEY.fullmatch(key) is None
            or action not in ("set", "remove")
            or key in keys
        ):
            raise ValueError("The reviewed environment changes are not valid.")
        keys.add(key)
        changes.append(change)
    return changes


def _config(settings: SimpleNamespace) -> bool:
    """Rebuild Laravel's cached configuration only when one is in use."""
    current = pathlib.Path(str(settings.directory)) / "current"
    cache = current / "bootstrap" / "cache" / "config.php"
    artisan = current / "artisan"
    if not cache.exists() or not artisan.is_file():
        return True
    stage("config")
    php = f"/nix/var/nix/profiles/barectl/{settings.runtime}/bin/php"
    try:
        user_command(settings, [php, "artisan", "config:cache"], cwd=str(current))
    except ValueError, OSError, subprocess.TimeoutExpired:
        return False
    return True


def edit_environment(document: dict[str, object]) -> None:  # noqa: C901 - reviewed stages
    names = document.get("names")
    selection = document.get("selection")
    if (
        not isinstance(names, list)
        or not all(isinstance(name, str) for name in names)
        or not isinstance(selection, str)
    ):
        result("refused", "evidence")
        return
    settings = setting(
        str(document["identifier"]), names, selection, https=document.get("https") is True
    )
    secret_path = str(document.get("secret_path", ""))
    account = site_account(settings.identifier)
    path = environment_path(settings.identifier)
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
            lock = open_site_lock(settings.identifier)
        except BlockingIOError:
            result("lock_busy")
            return
        except OSError, ValueError:
            result("refused", "unsafe_lock")
            return
        stage("preflight")
        if account is None or not _private_file_ok(path, settings.identifier):
            result("refused", "laravel_environment")
            return
        before = read_environment(settings.identifier)
        if hashlib.sha256(before.encode("utf-8")).hexdigest() != document.get("environment_digest"):
            result("refused", "evidence")
            return
        existing = {key for key, _value in environment_entries_from_text(before)}
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
            text = apply_environment(before, reviewed)
            _write_as_site(settings, path, text)
        except ValueError, OSError, subprocess.TimeoutExpired:
            result("refused", "laravel_environment")
            return
        after = read_environment(settings.identifier)
        if after != text:
            result("partial", "laravel_environment")
            return
        if not _config(settings):
            result("partial", "laravel_config")
            return
        restarted, workers_ok = restart_workers(settings.identifier)
        if restarted:
            stage("workers")
        if not workers_ok:
            result("partial", "laravel_worker")
            return
        stage("verify")
        result("succeeded")
    except ValueError, OSError, subprocess.TimeoutExpired:
        sys.stderr.write("barectl-problem " + "The environment could not be changed.\n")
        sys.stderr.flush()
        result("refused", "laravel_environment")
    finally:
        if secret_path:
            pathlib.Path(secret_path).unlink(missing_ok=True)
        if lock is not None:
            os.close(lock)


if __name__ == "__main__":
    edit_environment(json.loads(gzip.decompress(base64.b64decode(sys.argv[1]))))
