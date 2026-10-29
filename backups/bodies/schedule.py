"""Install, remove or run one site's fixed backup schedule (#402).

The reviewed change writes a root-only runtime payload and a fixed body, publishes the
site's backup slice, service and timer, and verifies systemd reports the next run. The timer
then runs the same body in run mode without any controller: it takes the global mutation lock
with a bounded wait, captures the database first and then the files, tags the point live and
scheduled, and records a skipped run when the lock is held. It never pauses the site and
never catches up.
"""

import base64
import datetime
import fcntl
import gzip
import hashlib
import json
import os
import pathlib
import pwd
import re
import secrets
import stat
import sys
import time
from types import SimpleNamespace
from typing import NoReturn, cast

from automation.bodies.units import (
    current_text,
    daemon_reload,
    enable_timer,
    load_state,
    properties,
    publish_unit_file,
    remove_unit_file,
    systemctl,
    timer_ready,
)
from backups.bodies.native import (
    HEADROOM_BYTES,
    LOCK_BUSY,
    PARTIAL,
    REFUSED,
    REPOSITORY_ROOT,
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
from backups.convention import (
    FREQUENCIES,
    SCHEDULE_LOCK_WAIT_SECONDS,
    SCHEDULE_ROOT,
    SCHEDULE_SCOPES,
    TIME,
    dump_argv,
    render_schedule,
    schedule_payload,
    schedule_script,
    schedule_unit_file,
    schedule_unit_name,
    tags,
)
from sites.bodies.common import result, stage

LOCK_DIRECTORY = "/run/lock/barectl"
LOCK_FILE = "/run/lock/barectl/mutation.lock"
IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}\Z")
DIGEST = 64
KINDS = ("slice", "service", "timer")


def _fail(result_class: str, reason: str) -> NoReturn:
    emit_result({"class": result_class, "reason": reason})
    raise SystemExit(REFUSED if result_class == "refused" else PARTIAL)


def _digest(text: str | None) -> str:
    return "absent" if text is None else hashlib.sha256(text.encode("utf-8")).hexdigest()


def _read_units(identifier: str) -> dict[str, str | None]:
    return {
        kind: current_text(pathlib.Path(schedule_unit_file(identifier, kind))) for kind in KINDS
    }


def _runtime(document: dict[str, object]) -> dict[str, object]:
    return {
        "version": 1,
        "identifier": str(document["identifier"]),
        "frequency": str(document["frequency"]),
        "at": str(document["at"]),
        "scope": str(document["scope"]),
        "offsite": document.get("offsite") is True,
        "engine": str(document.get("engine", "")),
        "repository": str(document["repository"]),
        "server_key": str(document["server_key"]),
        "files": list(cast("list[object]", document.get("files", []))),
        "dump": list(cast("list[object]", document.get("dump", []))),
        "filename": str(document.get("filename", "")),
        "offsite_plan": document.get("offsite_plan", {}),
        "origin": "scheduled",
        "lock_wait_seconds": SCHEDULE_LOCK_WAIT_SECONDS,
    }


def _checked(document: dict[str, object], *, state: str) -> SimpleNamespace:
    identifier = document.get("identifier")
    units = document.get("units")
    frequency = str(document.get("frequency", ""))
    at = str(document.get("at", ""))
    scope = str(document.get("scope", ""))
    if (
        document.get("version") != 1
        or not isinstance(identifier, str)
        or IDENTIFIER.fullmatch(identifier) is None
        or state not in ("on", "off")
        or not isinstance(units, dict)
        or set(units) != set(KINDS)
        or not all(
            units.get(kind) == "absent"
            or (
                isinstance(units.get(kind), str)
                and len(str(units[kind])) == DIGEST
                and all(character in "0123456789abcdef" for character in str(units[kind]))
            )
            for kind in KINDS
        )
    ):
        raise ValueError("The backup schedule review is not a valid immutable selection.")
    if state == "on" and (
        frequency not in FREQUENCIES
        or TIME.fullmatch(at) is None
        or scope not in SCHEDULE_SCOPES
        or not isinstance(document.get("repository"), str)
        or document.get("repository") != f"{REPOSITORY_ROOT}/{identifier}/onsite"
        or not isinstance(document.get("server_key"), str)
        or not str(document["server_key"]).startswith("/etc/barectl/backups/")
    ):
        raise ValueError("The backup schedule review is not a valid immutable selection.")
    return SimpleNamespace(
        identifier=identifier,
        state=state,
        frequency=frequency,
        at=at,
        scope=scope,
        units={kind: str(units[kind]) for kind in KINDS},
        document=document,
    )


def _stop(identifier: str) -> None:
    timer = schedule_unit_name(identifier, "timer")
    service = schedule_unit_name(identifier, "service")
    slice_name = schedule_unit_name(identifier, "slice")
    if load_state(timer) != "not-found":
        systemctl("disable", "--now", timer)
    if load_state(service) != "not-found":
        systemctl("stop", service)
    if load_state(slice_name) != "not-found":
        systemctl("stop", slice_name)


def _install(value: SimpleNamespace, source: str, preimage: dict[str, str | None]) -> None:
    directory = pathlib.Path(SCHEDULE_ROOT)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not controlled(str(directory)):
        raise ValueError("The backup schedule directory is outside supported settings.")
    script = pathlib.Path(schedule_script(value.identifier))
    if script.exists() and not safe_config(str(script)):
        raise ValueError("The backup schedule body is outside supported settings.")
    script.write_bytes(pathlib.Path(source).read_bytes())
    os.chmod(script, 0o600)
    payload = pathlib.Path(schedule_payload(value.identifier))
    payload.write_text(
        json.dumps(_runtime(value.document), sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    os.chmod(payload, 0o600)
    for kind in KINDS:
        path = schedule_unit_file(value.identifier, kind)
        publish_unit_file(
            path,
            render_schedule(value.identifier, kind, value.frequency, value.at),
            preimage[kind],
        )
    daemon_reload()


def _remove(value: SimpleNamespace, preimage: dict[str, str | None]) -> None:
    _stop(value.identifier)
    for kind in ("service", "timer", "slice"):
        path = schedule_unit_file(value.identifier, kind)
        if pathlib.Path(path).exists():
            remove_unit_file(path, preimage[kind])
    pathlib.Path(schedule_script(value.identifier)).unlink(missing_ok=True)
    pathlib.Path(schedule_payload(value.identifier)).unlink(missing_ok=True)
    daemon_reload()


def _install_result(value: SimpleNamespace) -> None:
    timer = schedule_unit_name(value.identifier, "timer")
    if not timer_ready(value.identifier, "backup"):
        _fail("partial", "schedule_timer")
    shown = properties(timer)
    next_elapse = shown.get("NextElapseUSecRealtime", "").removeprefix("@")
    if shown.get("ActiveState") != "active" or not next_elapse.isdigit() or int(next_elapse) <= 0:
        _fail("partial", "schedule_timer")
    emit_result(
        {
            "class": "succeeded",
            "reason": "",
            "kind": "schedule",
            "site": value.identifier,
            "state": "on",
            "next": next_elapse,
        }
    )
    raise SystemExit(SUCCESS)


def _remove_result(value: SimpleNamespace) -> None:
    for kind in KINDS:
        if load_state(schedule_unit_name(value.identifier, kind)) != "not-found":
            _fail("partial", "schedule_units")
    if (
        pathlib.Path(schedule_script(value.identifier)).exists()
        or pathlib.Path(schedule_payload(value.identifier)).exists()
    ):
        _fail("partial", "schedule_units")
    emit_result(
        {
            "class": "succeeded",
            "reason": "",
            "kind": "schedule",
            "site": value.identifier,
            "state": "off",
            "next": "0",
        }
    )
    raise SystemExit(SUCCESS)


def apply_mode(source: str, argument: str) -> None:
    document = json.loads(gzip.decompress(base64.b64decode(argument)))
    if not isinstance(document, dict):
        _fail("refused", "evidence")
    value = _checked(document, state=str(document.get("state", "")))
    stage("preflight")
    try:
        account = pwd.getpwnam("s" + value.identifier)
    except KeyError:
        _fail("refused", "backup_site")
    if account.pw_uid < 1000 or account.pw_uid >= 30000:
        _fail("refused", "backup_site")
    current = _read_units(value.identifier)
    if not all(_digest(current[kind]) == value.units[kind] for kind in KINDS):
        _fail("refused", "evidence")
    stage("install")
    try:
        if value.state == "on":
            _stop(value.identifier)
            _install(value, source, current)
            enable_timer(schedule_unit_name(value.identifier, "timer"))
        else:
            _remove(value, current)
    except OSError, ValueError:
        _fail("refused", "schedule_install")
    stage("verify")
    if value.state == "on":
        _install_result(value)
    _remove_result(value)


def _mutations_lock(wait_seconds: int) -> int | None:
    directory = pathlib.Path(LOCK_DIRECTORY)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not controlled(LOCK_DIRECTORY):
        raise ValueError("The shared lock directory is outside supported settings.")
    path = pathlib.Path(LOCK_FILE)
    descriptor = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
            raise ValueError("The shared lock file is outside supported settings.")
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return descriptor
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(descriptor)
                    return None
                time.sleep(0.25)
    except BaseException:
        os.close(descriptor)
        raise


def _at(document: dict[str, object]) -> dict[str, object]:
    moment = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
    return {**document, "at": moment.isoformat()}


def _runtime_payload(argument: str) -> dict[str, object]:
    path = pathlib.Path(argument)
    try:
        info = path.lstat()
    except OSError:
        raise ValueError("The backup schedule payload is missing.") from None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o077
        or info.st_size > 16384
    ):
        raise ValueError("The backup schedule payload is outside supported settings.")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("The backup schedule payload is not valid.")
    return value


def _run_checked(document: dict[str, object]) -> SimpleNamespace:
    identifier = document.get("identifier")
    scope = str(document.get("scope", ""))
    frequency = document.get("frequency")
    at = document.get("at")
    if (
        document.get("version") != 1
        or not isinstance(identifier, str)
        or IDENTIFIER.fullmatch(identifier) is None
        or frequency not in FREQUENCIES
        or not isinstance(at, str)
        or TIME.fullmatch(at) is None
        or scope not in SCHEDULE_SCOPES
        or document.get("origin") != "scheduled"
        or document.get("repository") != f"{REPOSITORY_ROOT}/{identifier}/onsite"
        or not isinstance(document.get("server_key"), str)
        or not str(document["server_key"]).startswith("/etc/barectl/backups/")
    ):
        raise ValueError("The backup schedule payload is not a supported capture.")
    files = document.get("files")
    dump = document.get("dump")
    engine = str(document.get("engine", ""))
    root = f"/var/www/{identifier}/"
    if (
        not isinstance(files, list)
        or not all(isinstance(item, str) for item in files)
        or not isinstance(dump, list)
        or not all(isinstance(item, str) for item in dump)
        or (scope in ("full", "files") and not files)
        or (scope == "database" and (files or not dump))
        or (scope == "full" and not dump)
        or (
            files
            and (
                files[0] != root + "current"
                or not all(item.startswith(root) and ".." not in item for item in files)
            )
        )
        or (
            dump
            and (engine not in ("mariadb", "postgresql") or dump != dump_argv(identifier, engine))
        )
        or (not dump and engine)
        or (type(document.get("offsite")) is not bool)
        or (document.get("offsite") is False and document.get("offsite_plan") != {})
        or (document.get("offsite") is True and not isinstance(document.get("offsite_plan"), dict))
    ):
        raise ValueError("The backup schedule payload is not a supported capture.")
    return SimpleNamespace(
        identifier=identifier,
        scope=scope,
        repository=str(document["repository"]),
        key=str(document["server_key"]),
        files=files,
        dump=dump,
        filename=str(document.get("filename", "")),
        offsite=document.get("offsite") is True,
        offsite_plan=document.get("offsite_plan", {}),
        document=document,
    )


def _paths(files: list[str]) -> list[str]:
    current = pathlib.Path(files[0])
    if current.name != "current" or not current.is_symlink():
        raise ValueError("The backup schedule has no current release.")
    target = pathlib.Path(os.path.realpath(current))
    if target.parent != current.parent / "releases" or not target.is_dir():
        raise ValueError("The current release is outside the convention.")
    return [str(target), *files[1:]]


def _backup_argv(
    value: SimpleNamespace, part: str, tag_values: list[str], restic_time: str
) -> list[str]:
    argv = ["backup", "--json", "--time", restic_time]
    for tag in tag_values:
        argv.extend(("--tag", tag))
    if part == "database":
        argv.extend(
            [
                "--stdin-from-command",
                "--stdin-filename",
                value.filename,
                "--",
                *value.dump,
            ]
        )
    else:
        argv.extend(_paths(value.files))
    return argv


def _mark_complete(value: SimpleNamespace, point: str) -> bool:
    found = snapshots(value.repository, value.key, point)
    ids = [
        str(row["id"])
        for row in found
        if isinstance(row.get("tags"), list)
        and "complete" not in cast("list[object]", row["tags"])
        and isinstance(row.get("id"), str)
    ]
    if not ids:
        return bool(found)
    status, _output = restic(
        ["tag", "--add", "complete", *ids],
        repository=value.repository,
        password=value.key,
    )
    return status == 0


def _complete(value: SimpleNamespace, point: str) -> bool:
    found = snapshots(value.repository, value.key, point)
    if len(found) != len(("database", "files") if value.scope == "full" else (value.scope,)):
        return False
    return all(
        isinstance(row.get("tags"), list) and "complete" in cast("list[object]", row["tags"])
        for row in found
    )


def _copy_offsite(value: SimpleNamespace, point: str) -> tuple[str, str]:
    if not value.offsite:
        return "", ""
    plan = value.offsite_plan
    if not isinstance(plan, dict) or not plan:
        return "failed", "offsite_copy"
    copy_class, copy_reason = copy_point(
        value.identifier,
        point,
        value.repository,
        value.key,
        plan,
        release=False,
    )
    if copy_class == "succeeded":
        return "copied", ""
    return "failed", copy_reason or "offsite_copy"


def run_mode(argument: str) -> None:  # noqa: C901 - one bounded capture
    try:
        value = _run_checked(_runtime_payload(argument))
    except OSError, ValueError:
        _fail("refused", "evidence")
    stage("preflight")
    try:
        account = pwd.getpwnam("s" + value.identifier)
    except KeyError:
        _fail("refused", "backup_site")
    if account.pw_uid < 1000 or account.pw_uid >= 30000:
        _fail("refused", "backup_site")
    if (
        not os.path.isfile(os.path.join(value.repository, "config"))
        or not safe_config(os.path.join(value.repository, "config"))
        or not locked_file(value.key, mode=0o600)
        or not controlled(REPOSITORY_ROOT)
    ):
        _fail("refused", "backup_repository")
    stage("lock")
    try:
        lock = _mutations_lock(
            int(value.document.get("lock_wait_seconds", SCHEDULE_LOCK_WAIT_SECONDS))
        )
    except OSError, ValueError:
        _fail("refused", "unsafe_lock")
    if lock is None:
        emit_result(
            document_result(
                _at(value.document),
                "lock_busy",
                "backup_lock",
                point="",
                snapshots=0,
                size=0,
            )
        )
        raise SystemExit(LOCK_BUSY)
    site_lock_fd = None
    try:
        try:
            site_lock_fd = site_lock(value.identifier, account.pw_gid)
        except OSError, ValueError:
            _fail("refused", "backup_lock")
        if site_lock_fd is None:
            emit_result(
                document_result(
                    _at(value.document),
                    "lock_busy",
                    "backup_lock",
                    point="",
                    snapshots=0,
                    size=0,
                )
            )
            raise SystemExit(LOCK_BUSY)
        if free_bytes() < HEADROOM_BYTES:
            _fail("refused", "backup_disk")
        now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
        restic_time = now.strftime("%Y-%m-%d %H:%M:%S")
        point = secrets.token_hex(8)
        parts = ["database", "files"] if value.scope == "full" else [value.scope]
        size = 0
        for part in parts:
            stage("backup-" + part)
            part_tags = list(
                tags(
                    value.identifier,
                    value.scope,
                    part=part,
                    origin="scheduled",
                    live=True,
                    point=point,
                    complete=False,
                )
            )
            status, output = restic(
                _backup_argv(value, part, part_tags, restic_time),
                repository=value.repository,
                password=value.key,
            )
            size += summary_size(output)
            found = snapshots(value.repository, value.key, point)
            reason = "backup_dump" if part == "database" else "backup_files"
            if status not in (0, 3) or not found:
                emit_result(
                    document_result(
                        _at(value.document),
                        "partial" if found else "refused",
                        reason,
                        point=point,
                        snapshots=len(found),
                        size=size,
                    )
                )
                raise SystemExit(PARTIAL if found else REFUSED)
        stage("verify")
        if not _mark_complete(value, point) or not _complete(value, point):
            _fail("partial", "backup_verify")
        offsite_status = ""
        copy_reason = ""
        if value.offsite:
            if site_lock_fd is not None:
                os.close(site_lock_fd)
                site_lock_fd = None
            os.close(lock)
            lock = -1
            offsite_status, copy_reason = _copy_offsite(value, point)
        result_document = {**value.document, "at": now.isoformat()}
        emit_result(
            document_result(
                result_document,
                "succeeded",
                copy_reason,
                point=point,
                snapshots=len(parts),
                size=size,
                offsite=offsite_status,
            )
        )
        raise SystemExit(SUCCESS)
    finally:
        if site_lock_fd is not None:
            os.close(site_lock_fd)
        if lock != -1:
            os.close(lock)


def main() -> None:
    source = sys.argv[1]
    argument = sys.argv[2]
    try:
        if argument.startswith("/") and os.path.isfile(argument):
            run_mode(argument)
        else:
            apply_mode(source, argument)
    except SystemExit:
        raise
    except (OSError, ValueError) as error:
        sys.stderr.write(f"barectl-problem {type(error).__name__}: {error}\n")
        sys.stderr.flush()
        result("refused", "evidence")
    except Exception:
        sys.stderr.write("barectl-problem The backup schedule could not be changed.\n")
        sys.stderr.flush()
        result("failed", "backup_unknown")


if __name__ == "__main__":
    main()
