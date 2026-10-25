"""Start, stop or gracefully restart a Laravel site's queue workers (Phase C #266).

The reviewed retry interval is written through the site's private environment before any
worker starts. Start enables boot activation; Stop disables it, so an explicit stop
survives a reboot. A restart is ``systemctl restart``: SIGTERM lets each process finish its
current job within its own stop budget.
"""

import contextlib
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
from types import SimpleNamespace

from automation.bodies.units import (
    active_state,
    current_text,
    daemon_reload,
    disable_and_stop_service,
    enable_service,
    load_state,
    publish_unit_file,
    reset_failed,
    restart_service,
    systemctl,
    wait_services_active,
)
from automation.convention import (
    SITE_IDENTIFIER,
    SYSTEMD_DIRECTORY,
    digest,
    role_of,
    service_name,
    slice_name,
    unit_file,
)
from automation.workers import (
    RETRY_AFTER_KEY,
    WORKER_ROLES,
    WorkerDefinition,
    checked_definition,
    render_worker_units,
)
from laravel.bodies.common import (
    _private_file_ok,
    apply_environment,
    environment_path,
    read_environment,
    user_command,
)
from sites.bodies.common import open_site_lock, result, setting, site_account, stage

DIGEST = re.compile(r"[0-9a-f]{64}\Z")
RELEASE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
MAX_NAMES = 64
MAX_WAIT = 15
UNIT_KEYS = ("slice", *WORKER_ROLES)


def _reviewed_preimage(path: str, reviewed: str) -> str | None:
    text = current_text(pathlib.Path(path))
    now = "absent" if text is None else digest(text)
    if now != reviewed:
        raise ValueError("The reviewed automation evidence changed before publication.")
    return text


def publish_worker_units(identifier: str, definition: object, expected: dict[str, str]) -> None:
    value = checked_definition(definition)
    for kind, name, text in render_worker_units(identifier, value):
        role = "slice" if kind == "slice" else role_of(name, identifier) or ""
        path = f"{SYSTEMD_DIRECTORY}/{name}"
        publish_unit_file(path, text, _reviewed_preimage(path, expected.get(role, "")))


def remove_worker_service(identifier: str, role: str, expected: str) -> None:
    path = unit_file(identifier, role, "service")
    _reviewed_preimage(path, expected)
    if pathlib.Path(path).exists():
        pathlib.Path(path).unlink()
    with contextlib.suppress(ValueError):
        systemctl("reset-failed", service_name(identifier, role))


WRITE_SCRIPT = (
    "import json,os,sys,tempfile\n"
    "payload=json.load(sys.stdin)\n"
    "path=payload['path']\n"
    "text=payload['text']\n"
    "directory=os.path.dirname(path)\n"
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


def _document(document: dict[str, object]) -> dict[str, object]:
    action = document.get("action")
    definition = None if action == "stop" else checked_definition(document.get("definition"))
    identifier = document.get("identifier")
    names = document.get("names")
    units = document.get("units")
    current = document.get("current")
    if (
        document.get("version") != 1
        or not isinstance(identifier, str)
        or SITE_IDENTIFIER.fullmatch(identifier) is None
        or document.get("action") not in ("start", "stop", "restart")
        or document.get("runtime") not in ("php84", "php85")
        or type(document.get("https")) is not bool
        or not isinstance(names, list)
        or not 1 <= len(names) <= MAX_NAMES
        or not all(isinstance(name, str) and len(name) <= 254 for name in names)
        or not isinstance(current, str)
        or (document.get("action") != "stop" and RELEASE.fullmatch(current) is None)
        or type(document.get("uid")) is not int
        or type(document.get("gid")) is not int
        or not isinstance(document.get("environment_digest"), str)
        or (
            document.get("action") != "stop"
            and DIGEST.fullmatch(str(document["environment_digest"])) is None
        )
        or not isinstance(units, dict)
        or set(units) != set(UNIT_KEYS)
        or not all(
            units.get(key) == "absent" or DIGEST.fullmatch(str(units.get(key))) is not None
            for key in UNIT_KEYS
        )
    ):
        raise ValueError("The queue-worker review is not a valid immutable selection.")
    return {
        "version": 1,
        "identifier": identifier,
        "action": document["action"],
        "definition": definition.document() if definition is not None else None,
        "runtime": document["runtime"],
        "https": document["https"],
        "names": list(names),
        "current": current,
        "uid": document["uid"],
        "gid": document["gid"],
        "environment_digest": document["environment_digest"],
        "units": {key: str(units[key]) for key in UNIT_KEYS},
    }


def apply(document: dict[str, object]) -> None:  # noqa: C901 - reviewed stages
    value = _document(document)
    identifier = str(value["identifier"])
    definition = checked_definition(value["definition"]) if value["action"] != "stop" else None
    names = value["names"]
    if not isinstance(names, list):
        raise ValueError("The queue-worker review is not a valid immutable selection.")
    settings = setting(
        identifier,
        [str(name) for name in names],
        str(value["runtime"]),
        https=bool(value["https"]),
    )
    lock: int | None = None
    try:
        try:
            lock = open_site_lock(identifier)
        except BlockingIOError:
            result("lock_busy")
            return
        except OSError, ValueError:
            result("refused", "unsafe_lock")
            return
        stage("preflight")
        if site_account(identifier) is None or not _current_directory(settings).is_dir():
            result("refused", "queue_workers_site")
            return
        if value["action"] == "stop":
            if not _unit_preimages(value, identifier):
                result("refused", "evidence")
                return
            _stop(value, identifier)
            return
        if _current_name(identifier) != value["current"]:
            result("refused", "queue_workers_activation")
            return
        if definition is None:
            result("refused", "queue_workers")
            return
        if not _environment_ready(identifier, value):
            return
        if value["action"] == "restart" and not _unit_preimages(value, identifier):
            result("refused", "evidence")
            return
        stage("environment")
        if not _write_retry(settings, identifier, definition):
            return
        if not _rebuild_configuration(settings):
            result("partial", "queue_workers_environment")
            return
        if value["action"] == "start":
            stage("units")
            _publish(value, identifier, definition)
            stage("start")
            ok = _start(identifier, definition)
        else:
            stage("restart")
            ok = _restart(identifier, definition)
        if not ok:
            result("partial", "queue_workers_start")
            return
        stage("verify")
        result("succeeded")
    except ValueError, OSError, subprocess.TimeoutExpired:
        sys.stderr.write("barectl-problem The queue workers could not be changed.\n")
        sys.stderr.flush()
        result("refused", "queue_workers")
    finally:
        if lock is not None:
            os.close(lock)


def _current_directory(settings: SimpleNamespace) -> pathlib.Path:
    return pathlib.Path(str(settings.directory)) / "current"


def _current_name(identifier: str) -> str:
    link = pathlib.Path(f"/var/www/{identifier}/current")
    try:
        target = os.readlink(link)
    except OSError:
        return ""
    if not target.startswith("releases/"):
        return ""
    return target.removeprefix("releases/")


def _environment_ready(identifier: str, document: dict[str, object]) -> bool:
    path = environment_path(identifier)
    if not _private_file_ok(path, identifier):
        result("refused", "queue_workers_environment")
        return False
    digest = hashlib.sha256(read_environment(identifier).encode("utf-8")).hexdigest()
    if digest != document["environment_digest"]:
        result("refused", "evidence")
        return False
    return True


def _rebuild_configuration(settings: SimpleNamespace) -> bool:
    """Rebuild Laravel's cached configuration when one is in use, before workers start."""
    current = pathlib.Path(str(settings.directory)) / "current"
    if not (current / "bootstrap" / "cache" / "config.php").exists():
        return True
    try:
        user_command(
            settings,
            [f"{settings.directory}/bin/php", "artisan", "config:cache"],
            cwd=str(current),
        )
    except ValueError, OSError, subprocess.TimeoutExpired:
        return False
    return True


def _write_retry(settings: SimpleNamespace, identifier: str, definition: WorkerDefinition) -> bool:
    before = read_environment(identifier)
    try:
        text = apply_environment(
            before,
            [{"key": RETRY_AFTER_KEY, "action": "set", "value": str(definition.retry_after)}],
        )
        _write_as_site(settings, environment_path(identifier), text)
    except ValueError, OSError, subprocess.TimeoutExpired:
        result("refused", "queue_workers_environment")
        return False
    if read_environment(identifier) != text:
        result("partial", "queue_workers_environment")
        return False
    return True


def _publish(document: dict[str, object], identifier: str, definition: WorkerDefinition) -> None:
    units = document["units"]
    if not isinstance(units, dict):
        raise ValueError("The queue-worker review is not a valid immutable selection.")
    publish_worker_units(identifier, definition.document(), units)
    for role in WORKER_ROLES:
        if role in definition.roles or units.get(role) == "absent":
            continue
        remove_worker_service(identifier, role, str(units[role]))
    daemon_reload()


def _digest_or_absent(path: str) -> str:
    text = current_text(pathlib.Path(path))
    return "absent" if text is None else digest(text)


def _unit_preimages(document: dict[str, object], identifier: str) -> bool:
    units = document["units"]
    return isinstance(units, dict) and all(
        _digest_or_absent(unit_file(identifier, role, "service")) == str(units[role])
        for role in WORKER_ROLES
    )


def _start(identifier: str, definition: WorkerDefinition) -> bool:
    problems = False
    for role in definition.roles:
        name = service_name(identifier, role)
        try:
            reset_failed(name)
            enable_service(name)
            restart_service(name)
        except ValueError:
            problems = True
    if not wait_services_active(
        [service_name(identifier, role) for role in definition.roles], MAX_WAIT
    ):
        return False
    return not problems


def _restart(identifier: str, definition: WorkerDefinition) -> bool:
    problems = False
    for role in definition.roles:
        name = service_name(identifier, role)
        try:
            reset_failed(name)
            restart_service(name)
        except ValueError:
            problems = True
    if not wait_services_active(
        [service_name(identifier, role) for role in definition.roles], MAX_WAIT
    ):
        return False
    return not problems


def _stop(document: dict[str, object], identifier: str) -> None:
    units = document["units"]
    if not isinstance(units, dict):
        raise ValueError("The queue-worker review is not a valid immutable selection.")
    stage("stop")
    for role in WORKER_ROLES:
        if units.get(role) == "absent":
            continue
        disable_and_stop_service(service_name(identifier, role))
    if load_state(slice_name(identifier)) != "not-found":
        systemctl("stop", slice_name(identifier))
    stage("verify")
    if any(
        load_state(service_name(identifier, role)) != "not-found"
        and active_state(service_name(identifier, role)) != "inactive"
        for role in WORKER_ROLES
        if units.get(role) != "absent"
    ):
        result("partial", "queue_workers_stop")
        return
    result("succeeded")


if __name__ == "__main__":
    import base64
    import gzip

    apply(json.loads(gzip.decompress(base64.b64decode(sys.argv[1]))))
