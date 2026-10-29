"""Weekly repository integrity checks for one site (#405).

The checked-in body is installed by **Enable backups** as two fixed weekly units in the
site's backup slice, one per location. A run holds the per-repository native lock, runs
``restic check`` with a rotating ``--read-data-subset``, and reads the newest complete
recovery point back through ``restic dump`` and a private staging directory. A held lock or an
unconfigured offsite store is a skip, never a success; a corrupted pack or a failed read-back
is an integrity failure and never changes a capture or a snapshot (docs/adr/0031, Phase D
#358 and #405).

The result line carries only counts, bytes, the short point identifier, the subset and the
result class. No path, repository URL, credential or dump content is printed.
"""

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from typing import NoReturn, cast

from backups.bodies.native import (
    CACHE_DIR,
    LOCK_BUSY,
    REFUSED,
    RESTIC_BIN,
    SUCCESS,
    controlled,
    emit_result,
    environment_file,
    locked_file,
    repository_lock,
    restic,
    restic_environment,
    stage,
)

INTEGRITY_ROOT = "/etc/barectl/backups/integrity"
BACKUP_SLICE_NAME = "barectl-site-{identifier}-backup.slice"
UNIT_NAME = "barectl-site-{identifier}-{role}"
ROLE_ONSITE = "check"
ROLE_OFFSITE = "checkoffsite"
ROLES = {ROLE_ONSITE: "onsite", ROLE_OFFSITE: "offsite"}
LOCATIONS = ("onsite", "offsite")
KINDS = ("service", "timer")
CALENDARS = {ROLE_ONSITE: "Sun *-*-* 05:15:00 UTC", ROLE_OFFSITE: "Sun *-*-* 05:45:00 UTC"}
RUN_TIMEOUT = "6h"
SUBSETS = 20
IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}\Z")
SNAPSHOT = re.compile(r"[0-9a-f]{64}\Z")
POINT = re.compile(r"[0-9a-f]{16}\Z")
SUBSET = re.compile(r"([0-9]{1,3})/([0-9]{1,3})\Z")
SCOPES = ("database", "files", "full")
PARTS = {"database": ("database",), "files": ("files",), "full": ("database", "files")}
UNIT_KEYS = (
    "slice",
    "check.service",
    "check.timer",
    "checkoffsite.service",
    "checkoffsite.timer",
)
PROVIDERS = ("s3", "r2")
OFFSITE_ROOT = "/etc/barectl/backups/offsite"
OFFSITE_CONFIG = OFFSITE_ROOT + "/config"
OFFSITE_CAPTURE = OFFSITE_ROOT + "/capture.env"


def _checked_identifier(identifier: str) -> str:
    if IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a site identifier.")
    return identifier


def _role(location: str) -> str:
    if location not in LOCATIONS:
        raise ValueError("Not a backup location.")
    return ROLE_ONSITE if location == "onsite" else ROLE_OFFSITE


def script_path(identifier: str) -> str:
    return f"{INTEGRITY_ROOT}/{_checked_identifier(identifier)}.sh"


def payload_path(identifier: str) -> str:
    return f"{INTEGRITY_ROOT}/{_checked_identifier(identifier)}.json"


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
        raise ValueError("Not an integrity role.")
    location = ROLES[role]
    return (
        "[Unit]\n"
        f"Description=Barectl backup integrity check for {identifier}\n"
        f"ConditionPathIsDirectory=/var/lib/barectl-backups/{identifier}\n"
        f"ConditionFileIsExecutable={script_path(identifier)}\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"TimeoutStartSec={RUN_TIMEOUT}\n"
        "KillMode=control-group\n"
        f"Slice={BACKUP_SLICE_NAME.format(identifier=identifier)}\n"
        f"ExecStart=/bin/sh {script_path(identifier)} check {payload_path(identifier)} {location}\n"
    )


def render_timer(identifier: str, role: str) -> str:
    _checked_identifier(identifier)
    if role not in (ROLE_ONSITE, ROLE_OFFSITE):
        raise ValueError("Not an integrity role.")
    return (
        "[Unit]\n"
        f"Description=Barectl backup integrity schedule for {identifier}\n"
        "\n"
        "[Timer]\n"
        f"OnCalendar={CALENDARS[role]}\n"
        "AccuracySec=1s\n"
        "RandomizedDelaySec=0\n"
        "Persistent=false\n"
        "DeferReactivation=yes\n"
        f"Unit={unit_name(identifier, role)}.service\n"
        f"Slice={BACKUP_SLICE_NAME.format(identifier=identifier)}\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def render_unit(identifier: str, role: str, kind: str) -> str:
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


# The weekly run --------------------------------------------------------------------------


def _payload(path: str) -> dict[str, object]:
    target = pathlib.Path(path)
    try:
        info = target.lstat()
    except OSError:
        raise ValueError("The integrity payload is missing.") from None
    if (
        (info.st_mode & 0o170000) != 0o100000
        or info.st_uid != 0
        or info.st_mode & 0o077
        or info.st_size > 16384
    ):
        raise ValueError("The integrity payload is outside supported settings.")
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except OSError, ValueError:
        raise ValueError("The integrity payload is not valid.") from None
    if not isinstance(value, dict):
        raise ValueError("The integrity payload is not valid.")
    return value


def checked_document(document: dict[str, object]) -> dict[str, object]:
    identifier = document.get("identifier")
    if (
        document.get("version") != 1
        or not isinstance(identifier, str)
        or IDENTIFIER.fullmatch(identifier) is None
        or document.get("repository") != f"/var/lib/barectl-backups/{identifier}/onsite"
        or document.get("server_key") != f"/etc/barectl/backups/{identifier}.key"
        or not isinstance(document.get("filename", ""), str)
    ):
        raise ValueError("The integrity review is not a supported check.")
    return {
        "identifier": identifier,
        "repository": str(document["repository"]),
        "server_key": str(document["server_key"]),
        "filename": str(document.get("filename", "")),
    }


def _result(
    value: dict[str, object],
    location: str,
    result_class: str,
    reason: str = "",
    *,
    point: str = "",
    checked: int = 0,
    snapshots: int = 0,
    size: int = 0,
    subset: str = "",
) -> dict[str, object]:
    return {
        "class": result_class,
        "reason": reason,
        "kind": "integrity",
        "site": str(value["identifier"]),
        "location": location,
        "at": datetime.now(tz=UTC).replace(microsecond=0).isoformat(),
        "point": point,
        "checked": checked,
        "snapshots": snapshots,
        "bytes": size,
        "subset": subset,
    }


def _fail(
    value: dict[str, object], location: str, result_class: str, reason: str, code: int
) -> NoReturn:
    emit_result(_result(value, location, result_class, reason))
    raise SystemExit(code)


def _offsite_values() -> dict[str, str] | None:
    if not os.path.lexists(OFFSITE_ROOT) or not controlled(OFFSITE_ROOT):
        return None
    if not locked_file(OFFSITE_CONFIG, mode=0o600):
        return None
    try:
        text = pathlib.Path(OFFSITE_CONFIG).read_text(encoding="utf-8")
    except OSError:
        return None
    values: dict[str, str] = {}
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        if (
            not separator
            or name in values
            or name not in {"provider", "bucket", "region", "endpoint", "prefix", "prune"}
        ):
            return None
        values[name] = value
    if set(values) != {"provider", "bucket", "region", "endpoint", "prefix", "prune"}:
        return None
    if (
        values["provider"] not in PROVIDERS
        or not values["bucket"]
        or len(values["bucket"]) > 63
        or not values["region"]
        or len(values["region"]) > 32
        or not values["endpoint"].startswith("https://")
        or len(values["endpoint"]) > 200
        or not values["prefix"]
        or len(values["prefix"]) > 200
        or ".." in values["prefix"].split("/")
        or values["prune"] not in ("yes", "no")
    ):
        return None
    return values


def _connection(value: dict[str, object], location: str) -> tuple[str, str, dict[str, str]] | None:
    if location == "onsite":
        return str(value["repository"]), str(value["server_key"]), {}
    config = _offsite_values()
    if config is None:
        return None
    repository = (
        f"s3:{config['endpoint']}/{config['bucket']}/{config['prefix']}/{value['identifier']}"
    )
    try:
        extra = environment_file(OFFSITE_CAPTURE)
    except OSError, ValueError:
        return None
    if not extra.get("AWS_ACCESS_KEY_ID") or not extra.get("AWS_SECRET_ACCESS_KEY"):
        return None
    extra["AWS_DEFAULT_REGION"] = config["region"]
    return repository, str(value["server_key"]), extra


def default_subset(now: float | None = None) -> str:
    """A deterministic starting subset; consecutive weeks advance through all of them."""
    index = int((time.time() if now is None else now) // (7 * 86400)) % SUBSETS
    return f"{index + 1}/{SUBSETS}"


def rotate(previous: str | None, now: float | None = None) -> str:
    """The subset after ``previous``, or a week-derived one when nothing was recorded."""
    if previous is not None:
        match = SUBSET.fullmatch(previous)
        if match is not None:
            number, total = int(match.group(1)), int(match.group(2))
            if total == SUBSETS and 1 <= number <= total:
                return f"{number % total + 1}/{total}"
    return default_subset(now)


def previous_subset(identifier: str, location: str) -> str | None:
    """The subset of this site's newest recorded check, from the native journal."""
    try:
        completed = subprocess.run(
            [
                "/usr/bin/journalctl",
                "--no-pager",
                "--reverse",
                "-o",
                "cat",
                "-n",
                "500",
                "--grep",
                "^barectl-result ",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            timeout=20,
            check=False,
        )
    except OSError, subprocess.TimeoutExpired:
        return None
    for line in completed.stdout.decode("utf-8", "replace").splitlines():
        if not line.startswith("barectl-result "):
            continue
        try:
            row = json.loads(line[len("barectl-result ") :])
        except ValueError:
            continue
        if (
            isinstance(row, dict)
            and row.get("kind") == "integrity"
            and row.get("site") == identifier
            and row.get("location") == location
            and isinstance(row.get("subset"), str)
        ):
            return str(row["subset"])
    return None


def _tags(row: dict[str, object]) -> list[str] | None:
    tags = row.get("tags")
    if not isinstance(tags, list) or len(tags) > 16:
        return None
    if not all(isinstance(tag, str) for tag in tags):
        return None
    return [str(tag) for tag in tags]


def complete_points(text: str) -> list[dict[str, object]]:
    """The newest first Barectl recovery points whose every part is complete."""
    try:
        rows = json.loads(text)
    except ValueError:
        return []
    points: dict[str, dict[str, object]] = {}
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
        ):
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
            continue
        entry = points.setdefault(
            point, {"point": point, "scope": scope, "time": moment, "parts": {}}
        )
        if "complete" in tags:
            cast("dict[str, str]", entry["parts"])[part] = snapshot
    complete = [
        point
        for point in points.values()
        if set(cast("dict[str, str]", point["parts"])) == set(PARTS[str(point["scope"])])
    ]
    return sorted(complete, key=lambda point: str(point["time"]), reverse=True)


def _stage_directory() -> str:
    parent = pathlib.Path(CACHE_DIR)
    if not controlled(CACHE_DIR):
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not controlled(CACHE_DIR):
        raise ValueError("The integrity stage is outside the convention.")
    return tempfile.mkdtemp(prefix="integrity-", dir=CACHE_DIR)


def read_back(
    repository: str,
    password: str,
    extra: dict[str, str],
    point: dict[str, object],
    filename: str,
) -> tuple[int, int] | None:
    """Read every part of one point back through a private stage, counting bytes."""
    try:
        directory = _stage_directory()
    except OSError, ValueError:
        return None
    options = ["-o", "s3.bucket-lookup=path"] if repository.startswith("s3:") else []
    total = 0
    count = 0
    try:
        parts = cast("dict[str, str]", point["parts"])
        for part, snapshot in parts.items():
            target = "/" if part == "files" else "/" + filename.lstrip("/")
            process = subprocess.Popen(  # noqa: S603 - fixed native argv and validated paths
                [RESTIC_BIN, *options, "dump", "--no-lock", snapshot, target],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=restic_environment(repository, password, extra),
                start_new_session=True,
            )
            if process.stdout is None:
                return None
            try:
                while chunk := process.stdout.read(65536):
                    total += len(chunk)
                status = process.wait()
            except BaseException:
                process.kill()
                process.communicate()
                raise
            if status:
                return None
            count += 1
        return count, total
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _check_failure(status: int) -> tuple[str, str, int]:
    """Map ``restic check``'s exit status to a class, reason and process exit."""
    if status == 10:
        return "refused", "backup_repository", REFUSED
    if status == 11:
        return "lock_busy", "backup_lock", LOCK_BUSY
    if status == 12:
        return "refused", "backup_password", REFUSED
    return "failed", "integrity_pack", 3


def run_check(payload: str, location: str) -> None:
    stage("preflight")
    try:
        value = checked_document(_payload(payload))
    except ValueError:
        emit_result(
            {
                "class": "refused",
                "reason": "evidence",
                "kind": "integrity",
                "site": "",
                "location": location,
            }
        )
        raise SystemExit(REFUSED) from None
    try:
        lock = repository_lock(str(value["identifier"]))
    except OSError, ValueError:
        _fail(value, location, "refused", "evidence", REFUSED)
    if lock is None:
        emit_result(_result(value, location, "lock_busy", "backup_lock"))
        raise SystemExit(LOCK_BUSY)
    try:
        connection = _connection(value, location)
        if connection is None:
            _fail(value, location, "refused", "integrity_offsite", REFUSED)
        repository, password, extra = connection
        stage("check")
        subset = rotate(previous_subset(str(value["identifier"]), location))
        status, _output = restic(
            ["check", "--no-lock", "--read-data-subset", subset],
            repository=repository,
            password=password,
            extra=extra,
        )
        if status:
            result_class, reason, code = _check_failure(status)
            _fail(value, location, result_class, reason, code)
        status, text = restic(
            ["snapshots", "--json", "--no-lock"],
            repository=repository,
            password=password,
            extra=extra,
        )
        if status:
            _fail(value, location, "refused", "backup_repository", REFUSED)
        points = complete_points(text)
        if not points:
            result = _result(value, location, "succeeded", point="", checked=0, subset=subset)
        else:
            stage("read-back")
            newest = points[0]
            read = read_back(repository, password, extra, newest, str(value.get("filename", "")))
            if read is None:
                _fail(value, location, "failed", "integrity_readback", 3)
            count, size = read
            result = _result(
                value,
                location,
                "succeeded",
                point=str(newest["point"]),
                checked=len(points),
                snapshots=count,
                size=size,
                subset=subset,
            )
    finally:
        os.close(lock)
    stage("verify")
    emit_result(result)
    raise SystemExit(SUCCESS)


def check_mode(payload: str, location: str) -> None:
    """Run one weekly check; an unexpected failure is a failed finding, never a success."""
    try:
        if location not in LOCATIONS:
            raise ValueError("The integrity check is not valid.")
        run_check(payload, location)
    except SystemExit:
        raise
    except (OSError, ValueError) as error:
        sys.stderr.write(f"barectl-problem {type(error).__name__}: {error}\n")
        sys.stderr.flush()
        emit_result({"class": "refused", "reason": "evidence", "kind": "integrity"})
        raise SystemExit(REFUSED) from None
    except Exception:
        sys.stderr.write("barectl-problem The integrity check could not finish.\n")
        sys.stderr.flush()
        emit_result({"class": "failed", "reason": "backup_unknown", "kind": "integrity"})
        raise SystemExit(REFUSED) from None
