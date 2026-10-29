"""Retention cleanup and keeping one recovery point (#404).

The checked-in body installs, removes and runs a site's fixed cleanup units, and toggles the
``keep`` tag on one recovery point. Cleanup runs daily onsite and weekly offsite: it requires
a synchronized clock, holds the per-repository lock, checks the newest complete point in each
scope by reading it back, forgets only Barectl's own complete snapshots with ``--keep-within``,
``--keep-last 1`` and ``--keep-tag keep``, and then prunes. A failed read-back keeps every
point in that scope (docs/adr/0031, Phase D #358 and #404).
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
from datetime import UTC, datetime
from typing import NoReturn, cast

from automation.bodies.units import (
    current_text,
    daemon_reload,
    enable_timer,
    load_state,
    publish_unit_file,
    remove_unit_file,
    systemctl,
    timer_ready,
)
from backups.bodies.native import (
    LOCK_BUSY,
    PARTIAL,
    REFUSED,
    SUCCESS,
    controlled,
    emit_result,
    locked_file,
    offsite_extra,
    repository_lock,
    restic,
    stage,
)

RETENTION_ROOT = "/etc/barectl/backups/retention"
BACKUP_SLICE_NAME = "barectl-site-{identifier}-backup.slice"
UNIT_NAME = "barectl-site-{identifier}-{role}"
ROLE_ONSITE = "cleanup"
ROLE_OFFSITE = "cleanupoffsite"
ROLES = {ROLE_ONSITE: "onsite", ROLE_OFFSITE: "offsite"}
LOCATIONS = ("onsite", "offsite")
KINDS = ("service", "timer")
DAYS = (7, 14, 21, 30, 182)
SCOPES = ("database", "files", "full")
PARTS = {"database": ("database",), "files": ("files",), "full": ("database", "files")}
ONSITE_CALENDAR = "*-*-* 03:15:00 UTC"
OFFSITE_CALENDAR = "Mon *-*-* 04:15:00 UTC"
RUN_TIMEOUT = "6h"
IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
SNAPSHOT = re.compile(r"[0-9a-f]{64}\Z")
POINT = re.compile(r"[0-9a-f]{16}\Z")
UNIT_KEYS = (
    "slice",
    "cleanup.service",
    "cleanup.timer",
    "cleanupoffsite.service",
    "cleanupoffsite.timer",
)
OFFSITE_SKIPPED = {"deleted": 0, "kept": 0, "skipped": 0, "failed": 0, "foreign": 0}


def _checked_identifier(identifier: str) -> str:
    if IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a site identifier.")
    return identifier


def _role(location: str) -> str:
    if location not in LOCATIONS:
        raise ValueError("Not a backup location.")
    return ROLE_ONSITE if location == "onsite" else ROLE_OFFSITE


def script_path(identifier: str) -> str:
    return f"{RETENTION_ROOT}/{_checked_identifier(identifier)}.sh"


def payload_path(identifier: str) -> str:
    return f"{RETENTION_ROOT}/{_checked_identifier(identifier)}.json"


def slice_path(identifier: str) -> str:
    name = BACKUP_SLICE_NAME.format(identifier=_checked_identifier(identifier))
    return f"/etc/systemd/system/{name}"


def unit_name(identifier: str, role: str) -> str:
    return UNIT_NAME.format(identifier=_checked_identifier(identifier), role=role)


def unit_path(identifier: str, role: str, kind: str) -> str:
    if kind not in KINDS:
        raise ValueError("Not a unit kind.")
    return f"/etc/systemd/system/{unit_name(identifier, role)}.{kind}"


def render_slice(identifier: str) -> str:
    _checked_identifier(identifier)
    return f"[Unit]\nDescription=Barectl backups for {identifier}\n\n[Slice]\n"


def render_service(identifier: str, role: str) -> str:
    _checked_identifier(identifier)
    if role not in (ROLE_ONSITE, ROLE_OFFSITE):
        raise ValueError("Not a retention role.")
    location = "onsite" if role == ROLE_ONSITE else "offsite"
    return (
        "[Unit]\n"
        f"Description=Barectl backup cleanup for {identifier}\n"
        f"ConditionPathIsDirectory=/var/lib/barectl-backups/{identifier}\n"
        f"ConditionFileIsExecutable={script_path(identifier)}\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"TimeoutStartSec={RUN_TIMEOUT}\n"
        "KillMode=control-group\n"
        f"Slice={BACKUP_SLICE_NAME.format(identifier=identifier)}\n"
        f"ExecStart=/bin/sh {script_path(identifier)} {payload_path(identifier)} {location}\n"
    )


def render_timer(identifier: str, role: str) -> str:
    _checked_identifier(identifier)
    if role not in (ROLE_ONSITE, ROLE_OFFSITE):
        raise ValueError("Not a retention role.")
    calendar = ONSITE_CALENDAR if role == ROLE_ONSITE else OFFSITE_CALENDAR
    return (
        "[Unit]\n"
        f"Description=Barectl backup cleanup schedule for {identifier}\n"
        "\n"
        "[Timer]\n"
        f"OnCalendar={calendar}\n"
        "AccuracySec=1s\n"
        "RandomizedDelaySec=0\n"
        "Persistent=false\n"
        "DeferReactivation=yes\n"
        f"Unit={unit_name(identifier, role)}.service\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def render_unit(identifier: str, role: str, kind: str) -> str:
    if kind == "slice":
        return render_slice(identifier)
    if kind == "service":
        return render_service(identifier, role)
    if kind == "timer":
        return render_timer(identifier, role)
    raise ValueError("Not a unit kind.")


def unit_texts(identifier: str) -> dict[str, str]:
    values = {"slice": render_slice(identifier)}
    for role in (ROLE_ONSITE, ROLE_OFFSITE):
        for kind in KINDS:
            values[f"{role}.{kind}"] = render_unit(identifier, role, kind)
    return values


def digest(text: str | None) -> str:
    return "absent" if text is None else hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_private(path: str, data: bytes) -> None:
    temporary = path + ".tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    if not locked_file(path, mode=0o600):
        raise ValueError("The retention file was not written safely.")


def _fail(result_class: str, reason: str, code: int) -> NoReturn:
    emit_result({"class": result_class, "reason": reason, "kind": "retention"})
    raise SystemExit(code)


def _checked_units(value: object) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or set(value) != set(UNIT_KEYS)
        or not all(
            isinstance(value.get(key), str)
            and (value[key] == "absent" or DIGEST.fullmatch(value[key]))
            for key in UNIT_KEYS
        )
    ):
        raise ValueError("The retention review is not a valid immutable selection.")
    return {key: str(value[key]) for key in UNIT_KEYS}


def _offsite(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) not in (
        {"repository", "capture_env", "prune_env", "storage"},
        {"repository", "config", "capture_env", "prune_env", "storage"},
    ):
        raise ValueError("The offsite cleanup is not the reviewed one.")
    repository, capture, prune, storage = (
        value["repository"],
        value["capture_env"],
        value["prune_env"],
        value["storage"],
    )
    if (
        not isinstance(repository, str)
        or not repository.startswith("s3:https://")
        or capture != "/etc/barectl/backups/offsite/capture.env"
        or prune != "/etc/barectl/backups/offsite/prune.env"
        or (
            value.get("config", "/etc/barectl/backups/offsite/config")
            != "/etc/barectl/backups/offsite/config"
        )
        or not isinstance(storage, dict)
    ):
        raise ValueError("The offsite cleanup is not the reviewed one.")
    if not repository.startswith(
        f"s3:{storage.get('endpoint')}/{storage.get('bucket')}/{storage.get('prefix')}/"
    ):
        raise ValueError("The offsite cleanup is not the reviewed one.")
    return {
        "repository": repository,
        "capture_env": capture,
        "prune_env": prune,
        "storage": {str(key): str(item) for key, item in storage.items()},
    }


def checked_document(document: dict[str, object], action: str) -> dict[str, object]:
    identifier = document.get("identifier")
    days = document.get("days", 0)
    units = _checked_units(document.get("units"))
    offsite = _offsite(document.get("offsite"))
    if (
        document.get("version") != 1
        or action not in ("set", "disable")
        or not isinstance(identifier, str)
        or IDENTIFIER.fullmatch(identifier) is None
        or document.get("action") != action
    ):
        raise ValueError("The retention review is not a supported policy.")
    if action == "set":
        if (
            type(days) is not int
            or days not in DAYS
            or document.get("repository") != f"/var/lib/barectl-backups/{identifier}/onsite"
            or document.get("server_key") != f"/etc/barectl/backups/{identifier}.key"
        ):
            raise ValueError("The retention review is not a supported policy.")
    elif days != 0:
        raise ValueError("Disabling retention has no period.")
    return {
        "version": 1,
        "action": action,
        "identifier": identifier,
        "days": days,
        "units": units,
        "repository": str(document.get("repository", "")),
        "server_key": str(document.get("server_key", "")),
        "filename": str(document.get("filename", "")),
        "offsite": offsite,
        "at": str(document.get("at", "")),
    }


def _preimage(value: dict[str, object]) -> None:
    identifier = str(value["identifier"])
    expected = unit_texts(identifier)
    units = cast("dict[str, str]", value["units"])
    for key in expected:
        current = current_text(pathlib.Path(_unit_file(identifier, key)))
        if digest(current) != units[key]:
            raise ValueError("The reviewed retention evidence changed before publication.")
    # The shared backup slice may be owned by the schedule. Publish it only when absent and
    # require the reviewed text when it exists.
    current_slice = current_text(pathlib.Path(slice_path(identifier)))
    if digest(current_slice) != units["slice"]:
        raise ValueError("The reviewed retention evidence changed before publication.")
    if current_slice is not None and current_slice != render_slice(identifier):
        raise ValueError("The site's backup slice is outside supported settings.")


def _unit_file(identifier: str, key: str) -> str:
    if key == "slice":
        return slice_path(identifier)
    role, _, kind = key.partition(".")
    return unit_path(identifier, role, kind)


def _install(source: str, value: dict[str, object]) -> None:
    identifier = str(value["identifier"])
    try:
        directory = pathlib.Path(RETENTION_ROOT)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not controlled(RETENTION_ROOT) or (directory.stat().st_mode & 0o777) != 0o700:
            raise ValueError("The retention directory is outside supported settings.")
        write_private(script_path(identifier), pathlib.Path(source).read_bytes())
        os.chmod(script_path(identifier), 0o700)
        payload = {
            "version": 1,
            "identifier": identifier,
            "days": value["days"],
            "repository": value["repository"],
            "server_key": value["server_key"],
            "filename": value["filename"],
            "offsite": value["offsite"],
            "at": value["at"],
        }
        write_private(
            payload_path(identifier),
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
        )
        if current_text(pathlib.Path(slice_path(identifier))) is None:
            publish_unit_file(slice_path(identifier), render_slice(identifier), None)
        for role in (ROLE_ONSITE, ROLE_OFFSITE):
            for kind in KINDS:
                path = unit_path(identifier, role, kind)
                previous = current_text(pathlib.Path(path))
                publish_unit_file(path, render_unit(identifier, role, kind), previous)
        daemon_reload()
        for role in (ROLE_ONSITE, ROLE_OFFSITE):
            enable_timer(f"{unit_name(identifier, role)}.timer")
    except OSError, ValueError:
        _fail("refused", "evidence", REFUSED)


def _remove(identifier: str) -> None:
    for role in (ROLE_ONSITE, ROLE_OFFSITE):
        timer = f"{unit_name(identifier, role)}.timer"
        service = f"{unit_name(identifier, role)}.service"
        if load_state(timer) != "not-found":
            systemctl("disable", "--now", timer)
        if load_state(service) != "not-found":
            systemctl("stop", service)
        for kind in KINDS:
            path = unit_path(identifier, role, kind)
            text = current_text(pathlib.Path(path))
            if text is not None:
                remove_unit_file(path, text)
    pathlib.Path(script_path(identifier)).unlink(missing_ok=True)
    pathlib.Path(payload_path(identifier)).unlink(missing_ok=True)
    daemon_reload()


def apply_mode(source: str, argument: str) -> None:  # noqa: C901 - one reviewed install
    document = json.loads(gzip.decompress(base64.b64decode(argument)))
    if not isinstance(document, dict):
        _fail("refused", "evidence", REFUSED)
    action = str(document.get("action", ""))
    try:
        value = checked_document(document, action)
    except ValueError:
        _fail("refused", "evidence", REFUSED)
    identifier = str(value["identifier"])
    stage("preflight")
    try:
        _preimage(value)
        account = pathlib.Path(f"/var/www/{identifier}")
        if not account.is_dir():
            _fail("refused", "backup_site", REFUSED)
        stage("install")
        if action == "set":
            _install(source, value)
        else:
            _remove(identifier)
    except OSError, ValueError:
        _fail("refused", "evidence", REFUSED)
    stage("verify")
    if action == "set":
        for role in (ROLE_ONSITE, ROLE_OFFSITE):
            if not timer_ready(identifier, role):
                _fail("partial", "backup_verify", PARTIAL)
        emit_result(
            {
                "class": "succeeded",
                "reason": "",
                "kind": "retention",
                "site": identifier,
                "action": "set",
                "days": value["days"],
            }
        )
        raise SystemExit(SUCCESS)
    for role in (ROLE_ONSITE, ROLE_OFFSITE):
        if load_state(f"{unit_name(identifier, role)}.timer") != "not-found":
            _fail("partial", "backup_verify", PARTIAL)
    emit_result(
        {
            "class": "succeeded",
            "reason": "",
            "kind": "retention",
            "site": identifier,
            "action": "disable",
        }
    )
    raise SystemExit(SUCCESS)


# The cleanup run --------------------------------------------------------------------------


def _payload(path: str) -> dict[str, object]:
    target = pathlib.Path(path)
    try:
        info = target.lstat()
    except OSError:
        raise ValueError("The retention payload is missing.") from None
    if (
        (info.st_mode & 0o170000) != 0o100000
        or info.st_uid != 0
        or info.st_mode & 0o077
        or info.st_size > 16384
    ):
        raise ValueError("The retention payload is outside supported settings.")
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except OSError, ValueError:
        raise ValueError("The retention payload is not valid.") from None
    if not isinstance(value, dict):
        raise ValueError("The retention payload is not valid.")
    return value


def _run_document(document: dict[str, object]) -> dict[str, object]:
    identifier = document.get("identifier")
    days = document.get("days")
    if (
        document.get("version") != 1
        or not isinstance(identifier, str)
        or IDENTIFIER.fullmatch(identifier) is None
        or type(days) is not int
        or days not in DAYS
        or document.get("repository") != f"/var/lib/barectl-backups/{identifier}/onsite"
        or document.get("server_key") != f"/etc/barectl/backups/{identifier}.key"
    ):
        raise ValueError("The retention payload is not a supported policy.")
    return {
        "identifier": identifier,
        "days": days,
        "repository": str(document["repository"]),
        "server_key": str(document["server_key"]),
        "filename": str(document.get("filename", "")),
        "offsite": _offsite(document.get("offsite")),
    }


def clock_synchronized() -> bool:
    try:
        completed = subprocess.run(
            ["/usr/bin/timedatectl", "show", "--property=NTPSynchronized", "--value"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            check=False,
        )
    except OSError:
        return False
    text = completed.stdout.decode("utf-8", "replace").strip()
    return completed.returncode == 0 and text == "yes"


def _repository(value: dict[str, object], location: str) -> tuple[str, str, dict[str, str]] | None:
    if location == "onsite":
        return str(value["repository"]), str(value["server_key"]), {}
    offsite = value.get("offsite")
    if not isinstance(offsite, dict):
        return None
    extra: dict[str, str] = {}
    prune = pathlib.Path(str(offsite["prune_env"]))
    capture = str(offsite["capture_env"])
    try:
        extra = environment_values(str(prune) if prune.is_file() else capture)
    except OSError, ValueError:
        return None
    if not extra.get("AWS_ACCESS_KEY_ID") or not extra.get("AWS_SECRET_ACCESS_KEY"):
        return None
    return (
        str(offsite["repository"]),
        str(value["server_key"]),
        offsite_extra(offsite.get("storage"), extra),
    )


def environment_values(path: str) -> dict[str, str]:
    if not locked_file(path, mode=0o600):
        raise ValueError("Not a root-owned environment file.")
    values: dict[str, str] = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle.read().splitlines():
            name, separator, value = line.partition("=")
            if separator and name.isupper() and name.replace("_", "").isalnum():
                values[name] = value
    return values


def _tags(row: dict[str, object]) -> list[str] | None:
    tags = row.get("tags")
    if not isinstance(tags, list) or len(tags) > 16:
        return None
    if not all(isinstance(tag, str) for tag in tags):
        return None
    return [str(tag) for tag in tags]


def _snapshot_points(rows: list[dict[str, object]]) -> tuple[dict[str, dict[str, object]], int]:
    points: dict[str, dict[str, object]] = {}
    foreign = 0
    for row in rows:
        tags = _tags(row)
        snapshot = row.get("id")
        if tags is None or not isinstance(snapshot, str) or SNAPSHOT.fullmatch(snapshot) is None:
            foreign += 1
            continue
        if "barectl" not in tags:
            foreign += 1
            continue
        point = next((tag.removeprefix("point:") for tag in tags if tag.startswith("point:")), "")
        scope = next((tag.removeprefix("scope:") for tag in tags if tag.startswith("scope:")), "")
        part = next((tag.removeprefix("part:") for tag in tags if tag.startswith("part:")), "")
        moment = row.get("time")
        if (
            POINT.fullmatch(point) is None
            or scope not in SCOPES
            or part not in PARTS[scope]
            or not isinstance(moment, str)
        ):
            foreign += 1
            continue
        entry = points.setdefault(
            point,
            {
                "point": point,
                "scope": scope,
                "time": moment,
                "parts": {},
                "keep": "keep" in tags,
            },
        )
        if "complete" in tags:
            cast("dict[str, str]", entry["parts"])[part] = snapshot
    return points, foreign


def _complete(points: dict[str, dict[str, object]], scope: str) -> list[dict[str, object]]:
    expected = set(PARTS[scope])
    return [
        point
        for point in points.values()
        if point["scope"] == scope and set(cast("dict[str, str]", point["parts"])) == expected
    ]


def _forget_points(text: str, field: str) -> set[str]:
    try:
        value = json.loads(text)
    except ValueError:
        return set()
    groups = value if isinstance(value, list) else []
    found: set[str] = set()
    for group in groups:
        if not isinstance(group, dict):
            continue
        rows = group.get(field)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            tags = _tags(row)
            if tags is None:
                continue
            point = next(
                (tag.removeprefix("point:") for tag in tags if tag.startswith("point:")),
                "",
            )
            if POINT.fullmatch(point) is not None:
                found.add(point)
    return found


def _forget_argv(days: int, scope: str, part: str, *, dry_run: bool = False) -> list[str]:
    argv = [
        "forget",
        "--json",
        "--group-by",
        "",
        "--tag",
        ",".join(("barectl", "complete", f"scope:{scope}", f"part:{part}")),
        "--keep-within",
        f"{days}d",
        "--keep-last",
        "1",
        "--keep-tag",
        "keep",
    ]
    if dry_run:
        argv.insert(1, "--dry-run")
    return argv


def _read_back(
    repository: str, password: str, extra: dict[str, str], point: dict[str, object], filename: str
) -> bool:
    parts = cast("dict[str, str]", point["parts"])
    for part, snapshot in parts.items():
        target = "/" if part == "files" else "/" + filename.lstrip("/")
        status, _output = restic(
            ["dump", "--no-lock", snapshot, target],
            repository=repository,
            password=password,
            extra=extra,
            stream=True,
        )
        if status:
            return False
    return True


def _empty() -> dict[str, int]:
    return {"deleted": 0, "kept": 0, "skipped": 0, "failed": 0, "foreign": 0}


def cleanup_location(  # noqa: C901 - one reviewed cleanup of a location
    value: dict[str, object], location: str, filename: str = ""
) -> dict[str, int]:
    counts = _empty()
    connection = _repository(value, location)
    if connection is None:
        return counts
    repository, password, extra = connection
    status, text = restic(
        ["snapshots", "--json", "--no-lock"], repository=repository, password=password, extra=extra
    )
    if status:
        counts["failed"] = 1
        return counts
    try:
        rows = json.loads(text)
    except ValueError:
        rows = None
    if not isinstance(rows, list):
        counts["failed"] = 1
        return counts
    points, foreign = _snapshot_points([row for row in rows if isinstance(row, dict)])
    counts["foreign"] = foreign
    deleted: set[str] = set()
    kept: set[str] = set()
    skipped: set[str] = set()
    for scope in SCOPES:
        candidates = _complete(points, scope)
        if not candidates:
            skipped.update(
                str(point["point"]) for point in points.values() if point["scope"] == scope
            )
            continue
        newest = max(candidates, key=lambda point: str(point["time"]))
        if not _read_back(repository, password, extra, newest, filename):
            counts["failed"] += 1
            kept.update(str(point["point"]) for point in candidates)
            continue
        if scope == "full":
            previews: list[set[str]] = []
            for part in PARTS[scope]:
                status, text = restic(
                    _forget_argv(int(str(value["days"])), scope, part, dry_run=True),
                    repository=repository,
                    password=password,
                    extra=extra,
                )
                if status:
                    counts["failed"] += 1
                    kept.update(str(point["point"]) for point in candidates)
                    previews = []
                    break
                previews.append(_forget_points(text, "remove"))
            if not previews:
                continue
            if len(previews) != 2 or previews[0] != previews[1]:
                counts["failed"] += 1
                kept.update(str(point["point"]) for point in candidates)
                continue
        failed = False
        for part in PARTS[scope]:
            status, text = restic(
                _forget_argv(int(str(value["days"])), scope, part),
                repository=repository,
                password=password,
                extra=extra,
            )
            if status == 11:
                counts["skipped"] += len(candidates)
                failed = True
                break
            if status:
                counts["failed"] += 1
                failed = True
                break
            deleted |= _forget_points(text, "remove")
            kept |= _forget_points(text, "keep")
        if failed:
            continue
        kept.add(str(newest["point"]))
    if deleted:
        status, _output = restic(["prune"], repository=repository, password=password, extra=extra)
        if status == 11:
            counts["skipped"] += len(deleted)
            deleted.clear()
        elif status:
            counts["failed"] += 1
    counts["deleted"] = len(deleted)
    counts["kept"] = len(kept)
    counts["skipped"] += len(skipped)
    return counts


def _result(
    value: dict[str, object], location: str, counts: dict[str, int], reason: str = ""
) -> dict[str, object]:
    result: dict[str, object] = {
        "class": "succeeded",
        "reason": reason,
        "kind": "cleanup",
        "site": str(value["identifier"]),
        "at": datetime.now(tz=UTC).replace(microsecond=0).isoformat(),
        "onsite": _empty(),
        "offsite": dict(OFFSITE_SKIPPED),
    }
    result[location] = counts
    if reason:
        result["class"] = "refused"
    if counts["failed"]:
        result["class"] = "partial"
    return result


def run_cleanup(payload: str, location: str) -> None:
    stage("preflight")
    try:
        document = _payload(payload)
        value = _run_document(document)
    except ValueError:
        _fail("refused", "evidence", REFUSED)
    if not clock_synchronized():
        result = _result(value, location, _empty(), "cleanup_clock")
        result["class"] = "refused"
        emit_result(result)
        raise SystemExit(REFUSED)
    try:
        lock = repository_lock(str(value["identifier"]))
    except OSError, ValueError:
        _fail("refused", "evidence", REFUSED)
    if lock is None:
        result = _result(value, location, _empty())
        result["class"] = "lock_busy"
        result["reason"] = "backup_lock"
        emit_result(result)
        raise SystemExit(LOCK_BUSY)
    try:
        stage("cleanup")
        try:
            counts = cleanup_location(value, location, str(value.get("filename", "")))
        except OSError, ValueError:
            counts = _empty()
            counts["failed"] = 1
        result = _result(value, location, counts)
    finally:
        os.close(lock)
    stage("verify")
    emit_result(result)
    if result["class"] == "partial":
        raise SystemExit(PARTIAL)
    raise SystemExit(SUCCESS)


# Keeping one recovery point ---------------------------------------------------------------


def checked_keep(document: dict[str, object]) -> dict[str, object]:
    identifier = document.get("identifier")
    point = document.get("point")
    action = document.get("action")
    snapshots = document.get("snapshots")
    if (
        document.get("version") != 1
        or not isinstance(identifier, str)
        or IDENTIFIER.fullmatch(identifier) is None
        or not isinstance(point, str)
        or POINT.fullmatch(point) is None
        or action not in ("add", "remove")
        or not isinstance(snapshots, list)
        or not 1 <= len(snapshots) <= 16
        or not all(isinstance(item, str) and SNAPSHOT.fullmatch(item) for item in snapshots)
        or document.get("repository") != f"/var/lib/barectl-backups/{identifier}/onsite"
        or document.get("server_key") != f"/etc/barectl/backups/{identifier}.key"
    ):
        raise ValueError("The keep review is not a supported change.")
    return {
        "identifier": identifier,
        "point": point,
        "action": action,
        "snapshots": [str(item) for item in snapshots],
        "repository": str(document["repository"]),
        "server_key": str(document["server_key"]),
    }


def _point_rows(
    repository: str, password: str, point: str
) -> tuple[list[dict[str, object]], dict[str, bool]]:
    status, text = restic(
        ["snapshots", "--json", "--no-lock", "--tag", "point:" + point],
        repository=repository,
        password=password,
    )
    if status:
        return [], {}
    try:
        rows = json.loads(text)
    except ValueError:
        return [], {}
    kept: dict[str, bool] = {}
    found: list[dict[str, object]] = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        tags = _tags(row)
        snapshot = row.get("id")
        if (
            tags is None
            or not isinstance(snapshot, str)
            or SNAPSHOT.fullmatch(snapshot) is None
            or "barectl" not in tags
            or "point:" + point not in tags
        ):
            continue
        kept[snapshot] = "keep" in tags
        found.append(row)
    return found, kept


def keep_mode(argument: str) -> None:
    document = json.loads(gzip.decompress(base64.b64decode(argument)))
    if not isinstance(document, dict):
        _fail("refused", "evidence", REFUSED)
    try:
        value = checked_keep(document)
    except ValueError:
        _fail("refused", "evidence", REFUSED)
    stage("preflight")
    try:
        lock = repository_lock(str(value["identifier"]))
    except OSError, ValueError:
        _fail("refused", "evidence", REFUSED)
    if lock is None:
        _fail("lock_busy", "backup_lock", LOCK_BUSY)
    try:
        _rows, kept = _point_rows(
            str(value["repository"]), str(value["server_key"]), str(value["point"])
        )
        wanted = set(cast("list[str]", value["snapshots"]))
        if not wanted or set(kept) != wanted:
            _fail("refused", "evidence", REFUSED)
        action = "add" if value["action"] == "add" else "remove"
        selected = [snapshot for snapshot, state in kept.items() if state != (action == "add")]
        if not selected:
            _fail("refused", "evidence", REFUSED)
        stage("tag")
        status, _output = restic(
            ["tag", "--" + action, "keep", *selected],
            repository=str(value["repository"]),
            password=str(value["server_key"]),
        )
        if status:
            _fail("failed", "backup_unknown", REFUSED)
        _rows, after = _point_rows(
            str(value["repository"]), str(value["server_key"]), str(value["point"])
        )
        if len(after) != len(wanted) or any(state != (action == "add") for state in after.values()):
            _fail("partial", "backup_verify", PARTIAL)
    finally:
        os.close(lock)
    stage("verify")
    emit_result(
        {
            "class": "succeeded",
            "reason": "",
            "kind": "keep",
            "site": str(value["identifier"]),
            "point": str(value["point"]),
            "keep": value["action"] == "add",
        }
    )
    raise SystemExit(SUCCESS)


def _decoded(argument: str) -> dict[str, object]:
    value = json.loads(gzip.decompress(base64.b64decode(argument)))
    if not isinstance(value, dict):
        raise ValueError("The retention change is not valid.")
    return value


def main() -> None:
    try:
        if len(sys.argv) == 2:
            document = _decoded(sys.argv[1])
            if document.get("kind") == "keep":
                keep_mode(sys.argv[1])
                return
            raise ValueError("The retention change is not valid.")
        if len(sys.argv) == 4 and sys.argv[3] in LOCATIONS:
            run_cleanup(sys.argv[2], sys.argv[3])
        elif len(sys.argv) == 3:
            apply_mode(sys.argv[1], sys.argv[2])
        else:
            raise ValueError("The retention change is not valid.")
    except SystemExit:
        raise
    except (OSError, ValueError) as error:
        sys.stderr.write(f"barectl-problem {type(error).__name__}: {error}\n")
        sys.stderr.flush()
        emit_result({"class": "refused", "reason": "evidence", "kind": "retention"})
        raise SystemExit(REFUSED) from None
    except Exception as error:
        sys.stderr.write(f"barectl-problem {type(error).__name__}: {error}\n")
        sys.stderr.flush()
        emit_result({"class": "failed", "reason": "backup_unknown", "kind": "retention"})
        raise SystemExit(REFUSED) from None


if __name__ == "__main__":
    main()
