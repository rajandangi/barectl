"""Read backups from native evidence without running restic or touching a repository.

The controller validates this bounded answer strictly. It reports the restic profile, each
site's root-only repository and server key, whether the site database exists, and the newest
safe result line in the journal; it never reads key contents or snapshot data.
"""

import datetime
import json
import os
import pathlib
import pwd
import stat
import subprocess
import sys
from typing import NamedTuple

REPOSITORY_ROOT = "/var/lib/barectl-backups"
KEY_ROOT = "/etc/barectl/backups"
OFFSITE_ROOT = KEY_ROOT + "/offsite"
OFFSITE_CONFIG = OFFSITE_ROOT + "/config"
OFFSITE_CAPTURE = OFFSITE_ROOT + "/capture.env"
OFFSITE_PRUNE = OFFSITE_ROOT + "/prune.env"
OFFSITE_SOURCES = OFFSITE_ROOT + "/sources"
OFFSITE_HEALTH = "_health"
PROFILE_ROOT = "/nix/var/nix/profiles/barectl"
RESTIC_PROFILE = PROFILE_ROOT + "/restic"
MAX_SITES = 64
MAX_TEXT = 500
# Jobs reads only this many recent runs and this many timers per site from the one read.
MAX_RUNS = 6
MAX_RUN_ROWS = 96
MAX_TIMERS = 5
# The controller discards an answer above MAX_OUTPUT (64 KiB). Keep a margin so a read
# always returns a parseable answer, trimming the oldest runs first and timers last.
MAX_OUTPUT_BYTES = 56 * 1024
# A timer's last trigger is used only as missing-result evidence inside Jobs' 30-day range.
RUN_EVIDENCE_US = 30 * 24 * 60 * 60 * 1_000_000
JOURNAL_LINES = 400
TIMER_ROLES = (
    ("backup", "backup", ""),
    ("check", "check", "onsite"),
    ("check", "checkoffsite", "offsite"),
    ("cleanup", "cleanup", "onsite"),
    ("cleanup", "cleanupoffsite", "offsite"),
)
ENABLED_STATES = frozenset({"enabled", "enabled-runtime", "static", "indirect"})
PROVIDERS = ("s3", "r2")
# The controller prepends databases/binding.py to this body; its names are our globals.
binding = sys.modules[__name__]


def metadata(path: str) -> dict[str, object] | None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        return {"unreadable": True}
    return {
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "type": stat.S_IFMT(info.st_mode),
        "links": info.st_nlink,
    }


def controlled(path: str) -> bool:
    value = metadata(path)
    return bool(
        value
        and value.get("uid") == 0
        and value.get("gid") == 0
        and value.get("type") == stat.S_IFDIR
        and isinstance(value.get("mode"), int)
        and int(str(value["mode"])) & 0o022 == 0
    )


def site_account(identifier: str) -> bool:
    try:
        user = pwd.getpwnam("s" + identifier)
    except KeyError:
        return False
    return 1000 <= user.pw_uid < 30000


def database_present(engine: str, identifier: str) -> tuple[bool, str]:
    if engine not in ("mariadb", "postgresql"):
        return False, "This server has no database engine."
    name = "s" + identifier
    try:
        status, output = bounded(["/bin/sh", "-c", binding.read_command(engine, name)])
    except OSError, ValueError:
        return False, "The site's database could not be read."
    if status:
        return False, "The site's database could not be read."
    try:
        facts = binding.parse_facts(engine, output.decode("utf-8", "replace"))
        locale = (
            binding.read_locale(output.decode("utf-8", "replace"))
            if engine == binding.POSTGRESQL
            else ""
        )
        found = binding.recognize(engine, identifier, facts, locale=locale)
    except ValueError:
        return False, "The site's database could not be read."
    return (
        found.state == "satisfied" and "database" in found.completed,
        "",
    )


def bounded(argv: list[str], *, limit: int = 32768) -> tuple[int, bytes]:
    process = subprocess.Popen(  # noqa: S603 - fixed native argv
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        return 124, b""
    if len(output) > limit:
        return 125, b""
    return process.returncode, output


class Journal(NamedTuple):
    """The one bounded journal read, reduced to the safe fields Jobs needs."""

    newest: dict[str, dict[str, object]]
    copies: dict[str, dict[str, object]]
    integrity: dict[str, dict[str, dict[str, object]]]
    connections: dict[str, dict[str, object]]
    runs: dict[str, list[dict[str, object]]]
    truncated: set[str]


def journal() -> Journal:  # noqa: C901 - one journal read
    status, output = bounded(
        [
            "/usr/bin/journalctl",
            "--no-pager",
            "--reverse",
            "-o",
            "json",
            "--output-fields=MESSAGE,__REALTIME_TIMESTAMP",
            "-n",
            str(JOURNAL_LINES),
            "--grep",
            "^barectl-result ",
        ],
        limit=768 * 1024,
    )
    if status:
        return Journal({}, {}, {}, {}, {}, set())
    newest: dict[str, dict[str, object]] = {}
    copies: dict[str, dict[str, object]] = {}
    integrity: dict[str, dict[str, dict[str, object]]] = {}
    connections: dict[str, dict[str, object]] = {}
    runs: dict[str, list[dict[str, object]]] = {}
    truncated: set[str] = set()
    final_capture: set[str] = set()
    total_runs = 0
    for entry in _entries(output):
        value = entry.value
        kind = value.get("kind")
        if kind == "connect":
            _connection(value, connections)
            continue
        identifier = value.get("site")
        if not isinstance(identifier, str) or not identifier:
            continue
        if kind == "integrity":
            finding_row = _integrity(value)
            location = value.get("location")
            if finding_row is None or location not in ("onsite", "offsite"):
                continue
            integrity.setdefault(identifier, {}).setdefault(str(location), finding_row)
            if total_runs < MAX_RUN_ROWS:
                run = _run(value, "check", entry.at)
                if run is not None:
                    runs.setdefault(identifier, []).append(run)
                    total_runs += 1
            else:
                truncated.add(identifier)
            continue
        if kind == "copy":
            if identifier not in copies:
                copies[identifier] = _copy_row(value, entry.at)
            if total_runs < MAX_RUN_ROWS:
                run = _run(value, "copy", entry.at)
                if run is not None:
                    runs.setdefault(identifier, []).append(run)
                    total_runs += 1
            else:
                truncated.add(identifier)
            continue
        if kind == "cleanup":
            if total_runs < MAX_RUN_ROWS:
                run = _run(value, "cleanup", entry.at)
                if run is not None:
                    runs.setdefault(identifier, []).append(run)
                    total_runs += 1
            else:
                truncated.add(identifier)
            continue
        if kind != "backup":
            continue
        # A full capture writes one interim backup_paused line before its final line. The
        # newest final line describes the run; an interrupted run keeps its interim line.
        interim = value.get("reason") == "backup_paused"
        if identifier not in newest:
            newest[identifier] = _capture_row(value, entry.at)
        if total_runs < MAX_RUN_ROWS and not (interim and identifier in final_capture):
            run = _run(value, "capture", entry.at)
            if run is not None:
                runs.setdefault(identifier, []).append(run)
                total_runs += 1
                if not interim:
                    final_capture.add(identifier)
        elif not (interim and identifier in final_capture):
            truncated.add(identifier)
    for identifier, rows in list(runs.items()):
        if len(rows) > MAX_RUNS:
            del rows[MAX_RUNS:]
            truncated.add(identifier)
        if not rows:
            del runs[identifier]
    return Journal(newest, copies, integrity, connections, runs, truncated)


class Entry(NamedTuple):
    value: dict[str, object]
    at: str


def _entries(output: bytes) -> list[Entry]:
    entries: list[Entry] = []
    for line in output.decode("utf-8", "replace").splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        message = record.get("MESSAGE")
        if not isinstance(message, str) or not message.startswith("barectl-result "):
            continue
        try:
            value = json.loads(message[len("barectl-result ") :])
        except ValueError:
            continue
        if not isinstance(value, dict):
            continue
        entries.append(Entry(value, _timestamp(record.get("__REALTIME_TIMESTAMP"))))
    return entries


def _timestamp(value: object) -> str:
    try:
        microseconds = int(str(value))
        moment = datetime.datetime.fromtimestamp(microseconds / 1_000_000, datetime.UTC)
    except OverflowError, OSError, ValueError:
        return ""
    return moment.replace(microsecond=0).isoformat()


def _capture_row(value: dict[str, object], at: str) -> dict[str, object]:
    row: dict[str, object] = {}
    for key in ("class", "reason", "scope", "origin", "at", "point", "offsite"):
        item = value.get(key)
        row[key] = item if isinstance(item, str) and len(item) <= MAX_TEXT else ""
    for key in ("snapshots", "bytes"):
        item = value.get(key)
        row[key] = item if type(item) is int and item >= 0 else 0
    if not row["at"]:
        row["at"] = at
    if row["class"] not in ("succeeded", "partial", "failed", "refused", "lock_busy"):
        row["class"] = "failed"
    if row["offsite"] not in ("", "copied", "failed"):
        row["offsite"] = ""
    return row


def _copy_row(value: dict[str, object], at: str) -> dict[str, object]:
    copy: dict[str, object] = {}
    for key in ("class", "reason", "at", "point"):
        item = value.get(key)
        copy[key] = item if isinstance(item, str) and len(item) <= MAX_TEXT else ""
    if not copy["at"]:
        copy["at"] = at
    if copy["class"] not in ("succeeded", "partial", "failed", "refused", "lock_busy"):
        copy["class"] = "failed"
    return copy


def _run(value: dict[str, object], kind: str, at: str) -> dict[str, object] | None:
    result_class = value.get("class")
    if not isinstance(result_class, str) or result_class not in (
        "succeeded",
        "partial",
        "failed",
        "refused",
        "lock_busy",
    ):
        return None
    run: dict[str, object] = {
        "kind": kind,
        "class": result_class,
        "reason": _text(value.get("reason")),
        "at": _text(value.get("at")) or at,
    }
    if not run["at"]:
        return None
    if kind == "capture":
        run.update(
            point=_point(value.get("point")),
            scope=_text(value.get("scope")),
            origin=_text(value.get("origin")),
            snapshots=_count(value.get("snapshots")),
            bytes=_count(value.get("bytes")),
            offsite=(value.get("offsite") if value.get("offsite") in ("copied", "failed") else ""),
        )
    elif kind == "copy":
        run["point"] = _point(value.get("point"))
    elif kind == "check":
        location = value.get("location")
        if location not in ("onsite", "offsite"):
            return None
        run.update(
            location=location,
            point=_point(value.get("point")),
            checked=_count(value.get("checked")),
            snapshots=_count(value.get("snapshots")),
            bytes=_count(value.get("bytes")),
            subset=_text(value.get("subset")),
        )
    else:
        run.update(
            onsite=_counts(value.get("onsite")),
            offsite=_counts(value.get("offsite")),
        )
    return run


def _text(value: object) -> str:
    return value if isinstance(value, str) and len(value) <= MAX_TEXT else ""


def _point(value: object) -> str:
    return value if isinstance(value, str) and len(value) == 16 else ""


def _count(value: object) -> int:
    return value if type(value) is int and 0 <= value <= 10_000 else 0


def _counts(value: object) -> dict[str, int]:
    if not isinstance(value, dict):
        return {"deleted": 0, "kept": 0, "skipped": 0, "failed": 0}
    return {key: _count(value.get(key)) for key in ("deleted", "kept", "skipped", "failed")}


def schedules(identifiers: list[str]) -> dict[str, list[dict[str, object]]]:
    """Each site's backup, check and cleanup timers, on or off, from systemd only.

    A timer systemd does not report is absent from the answer: the controller shows it as
    unknown and never invents a schedule.
    """
    listed = _systemctl(
        [
            "systemctl",
            "list-timers",
            "--all",
            "--no-pager",
            "--full",
            "--output=json",
        ]
    )
    files = _systemctl(
        [
            "systemctl",
            "list-unit-files",
            "--type=timer",
            "--no-pager",
            "--output=json",
        ]
    )
    if listed is None or files is None:
        return {}
    states = {
        str(row.get("unit_file")): str(row.get("state"))
        for row in files or []
        if isinstance(row, dict) and isinstance(row.get("unit_file"), str)
    }
    timers = {
        str(row.get("unit")): row
        for row in listed or []
        if isinstance(row, dict) and isinstance(row.get("unit"), str)
    }
    now = datetime.datetime.now(datetime.UTC).timestamp() * 1_000_000
    rows: dict[str, list[dict[str, object]]] = {}
    for identifier in identifiers:
        found: list[dict[str, object]] = []
        for work, role, location in TIMER_ROLES:
            name = f"barectl-site-{identifier}-{role}.timer"
            if name not in states and name not in timers:
                continue
            row = timers.get(name, {})
            next_elapse = row.get("next")
            last_trigger = row.get("last")
            next_us = next_elapse if type(next_elapse) is int and next_elapse > 0 else 0
            last_us = last_trigger if type(last_trigger) is int and last_trigger > 0 else 0
            if last_us and now - last_us > RUN_EVIDENCE_US:
                last_us = 0
            found.append(
                {
                    "work": work,
                    "location": location,
                    "on": states.get(name, "") in ENABLED_STATES and next_us > 0,
                    "next": next_us,
                    "last": last_us,
                }
            )
        if found:
            rows[identifier] = found[:MAX_TIMERS]
    return rows


def _systemctl(argv: list[str]) -> list[object] | None:
    status, output = bounded(argv, limit=256 * 1024)
    if status:
        return None
    try:
        value = json.loads(output.decode("utf-8", "replace") or "[]")
    except ValueError:
        return None
    return value if isinstance(value, list) else None


def _connection(value: dict[str, object], found: dict[str, dict[str, object]]) -> None:
    rows = value.get("sources")
    if not isinstance(rows, list) or len(rows) > MAX_SITES:
        return
    for source in rows:
        if not isinstance(source, dict):
            continue
        site = source.get("site")
        if not isinstance(site, str) or site in found:
            continue
        snapshots = source.get("rows")
        if not isinstance(snapshots, list) or len(snapshots) > 500:
            continue
        kept: list[dict[str, object]] = []
        for snapshot in snapshots:
            if not isinstance(snapshot, dict):
                continue
            trimmed = {
                key: snapshot[key] for key in ("id", "time", "tags", "summary") if key in snapshot
            }
            if not isinstance(trimmed.get("id"), str) or not isinstance(trimmed.get("tags"), list):
                continue
            kept.append(trimmed)
        found[site] = {"site": site, "rows": kept, "problem": ""}


def _integrity(value: dict[str, object]) -> dict[str, object] | None:
    row: dict[str, object] = {}
    for key in ("location", "class", "reason", "at", "point", "subset"):
        item = value.get(key)
        row[key] = item if isinstance(item, str) and len(item) <= MAX_TEXT else ""
    for key in ("checked", "snapshots", "bytes"):
        item = value.get(key)
        row[key] = item if type(item) is int and item >= 0 else 0
    if row["class"] not in ("succeeded", "partial", "failed", "refused", "lock_busy"):
        return None
    return row


def config_values(text: str) -> dict[str, object] | None:
    """The non-secret offsite setting, or ``None`` when it is outside the template."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        if (
            not separator
            or name in values
            or name not in ("provider", "bucket", "region", "endpoint", "prefix", "prune")
        ):
            return None
        values[name] = value
    if set(values) != {"provider", "bucket", "region", "endpoint", "prefix", "prune"}:
        return None
    provider = values.get("provider", "")
    endpoint = values.get("endpoint", "")
    if (
        provider not in PROVIDERS
        or not values.get("bucket")
        or len(values["bucket"]) > 63
        or not values.get("region")
        or len(values["region"]) > 32
        or not endpoint.startswith("https://")
        or len(endpoint) > 200
        or not values.get("prefix")
        or len(values["prefix"]) > 200
        or ".." in values["prefix"].split("/")
        or values.get("prune") not in ("yes", "no")
    ):
        return None
    return {
        "provider": provider,
        "bucket": values["bucket"],
        "region": values["region"],
        "endpoint": endpoint,
        "prefix": values["prefix"],
        "prune": values["prune"] == "yes",
        "problem": "",
    }


def source_sites() -> tuple[list[str], bool]:
    """The source identifiers a connected storage was opened with, and whether it is safe."""
    found = metadata(OFFSITE_SOURCES)
    if found is None:
        return [], True
    if not (
        found.get("uid") == 0
        and found.get("gid") == 0
        and found.get("type") == stat.S_IFREG
        and found.get("mode") == 0o600
        and found.get("links") == 1
    ):
        return [], False
    try:
        value = json.loads(pathlib.Path(OFFSITE_SOURCES).read_text(encoding="utf-8"))
    except OSError, ValueError:
        return [], False
    if not isinstance(value, dict) or set(value) != {"version", "sites"}:
        return [], False
    if value.get("version") != 1 or not isinstance(value.get("sites"), list):
        return [], False
    sites = value["sites"]
    if (
        len(sites) > MAX_SITES
        or not all(isinstance(site, str) and site for site in sites)
        or len(set(sites)) != len(sites)
    ):
        return [], False
    return [str(site) for site in sites], True


def offsite(  # noqa: C901 - one closed offsite read
    connections: dict[str, dict[str, object]],
) -> dict[str, object] | None:
    if not os.path.lexists(OFFSITE_ROOT):
        return None
    if not controlled(OFFSITE_ROOT):
        return {
            "provider": "",
            "bucket": "",
            "region": "",
            "endpoint": "",
            "prefix": "",
            "prune": False,
            "problem": "The storage setting's directory has unexpected ownership or permissions.",
        }
    config = metadata(OFFSITE_CONFIG)
    if config is None:
        return None
    safe = bool(
        config.get("uid") == 0
        and config.get("gid") == 0
        and config.get("type") == stat.S_IFREG
        and config.get("mode") == 0o600
        and config.get("links") == 1
    )
    if not safe:
        return {
            "provider": "",
            "bucket": "",
            "region": "",
            "endpoint": "",
            "prefix": "",
            "prune": False,
            "problem": "The storage setting's files have unexpected ownership or permissions.",
        }
    try:
        text = pathlib.Path(OFFSITE_CONFIG).read_text(encoding="utf-8")
    except OSError:
        text = ""
    value = config_values(text)
    if value is None:
        return {
            "provider": "",
            "bucket": "",
            "region": "",
            "endpoint": "",
            "prefix": "",
            "prune": metadata(OFFSITE_PRUNE) is not None,
            "problem": "The storage setting is empty or incomplete.",
        }
    value["prune"] = metadata(OFFSITE_PRUNE) is not None
    for path in (OFFSITE_CAPTURE, OFFSITE_PRUNE):
        found = metadata(path)
        if found is not None and not (
            found.get("uid") == 0
            and found.get("gid") == 0
            and found.get("type") == stat.S_IFREG
            and found.get("mode") == 0o600
            and found.get("links") == 1
        ):
            value["problem"] = (
                "The storage setting's key files have unexpected ownership or permissions."
            )
    if metadata(OFFSITE_CAPTURE) is None:
        value["problem"] = "The storage setting's key files are missing."
    sites, safe_sources = source_sites()
    value["sites"] = sites
    if not safe_sources:
        value["problem"] = "The connected backup storage sources are outside supported settings."
    value["sources"] = [
        connections.get(site)
        or {
            "site": site,
            "rows": [],
            "problem": "Connect the storage again to read this source's recovery points.",
        }
        for site in sites
    ]
    return value


def main() -> None:
    payload = json.loads(sys.argv[1])
    engine = str(payload.get("engine", ""))
    sites = payload.get("sites")
    known = payload.get("known")
    if (
        not isinstance(sites, list)
        or len(sites) > MAX_SITES
        or not all(isinstance(item, str) for item in sites)
        or not isinstance(known, list)
        or not all(isinstance(item, str) and item.startswith("/nix/store/") for item in known)
    ):
        raise SystemExit(1)
    profile = os.path.realpath(RESTIC_PROFILE) if os.path.lexists(RESTIC_PROFILE) else ""
    root_safe = (not os.path.lexists(REPOSITORY_ROOT) or controlled(REPOSITORY_ROOT)) and (
        not os.path.lexists(KEY_ROOT) or controlled(KEY_ROOT)
    )
    read = journal()
    latest = read.newest
    copies = read.copies
    integrities = read.integrity
    storage = offsite(read.connections)
    timers = schedules(sites)
    rows = []
    for identifier in sites:
        problems = []
        if not root_safe:
            problems.append("The backup directory is outside supported settings.")
        if profile and profile not in known:
            problems.append("The backup tool is outside supported settings.")
        directory = f"{REPOSITORY_ROOT}/{identifier}"
        repository = directory + "/onsite"
        key = f"{KEY_ROOT}/{identifier}.key"
        if os.path.lexists(directory) and not controlled(directory):
            problems.append("The site's backup directory is outside supported settings.")
        config = metadata(repository + "/config")
        repository_present = bool(
            config
            and config.get("uid") == 0
            and config.get("gid") == 0
            and config.get("type") == stat.S_IFREG
            and config.get("mode") in (0o400, 0o600)
            and config.get("links") == 1
        )
        if config is not None and not repository_present:
            problems.append("The site's backup repository is outside supported settings.")
        key_value = metadata(key)
        key_present = bool(
            key_value
            and key_value.get("uid") == 0
            and key_value.get("gid") == 0
            and key_value.get("type") == stat.S_IFREG
            and key_value.get("mode") == 0o600
            and key_value.get("links") == 1
        )
        if key_value is not None and not key_present:
            problems.append("The site's backup key is outside supported settings.")
        if repository_present != key_present or (
            (repository_present or key_present) and not profile
        ):
            problems.append("The site's backup setup is incomplete.")
        found, database_problem = (
            database_present(engine, identifier)
            if site_account(identifier)
            else (False, "The site's Linux account could not be read.")
        )
        found_integrity = integrities.get(identifier)
        rows.append(
            {
                "identifier": identifier,
                "profile": profile,
                "repository": repository_present,
                "key": key_present,
                "problems": problems[:8],
                "database": found,
                "database_problem": database_problem[:MAX_TEXT],
                "last": latest.get(identifier),
                "copy": copies.get(identifier),
                "integrity": (
                    {
                        "onsite": found_integrity.get("onsite"),
                        "offsite": found_integrity.get("offsite"),
                    }
                    if found_integrity
                    else None
                ),
                "runs": read.runs.get(identifier, [])[:MAX_RUNS],
                "timers": timers.get(identifier, []),
                "runs_truncated": identifier in read.truncated,
                "timers_truncated": False,
            }
        )
    sys.stdout.write(_bounded_answer(rows, storage))


def _bounded_answer(rows: list[dict[str, object]], storage: dict[str, object] | None) -> str:
    """The answer under the controller's byte ceiling, trimming oldest evidence first."""
    answer: dict[str, object] = {"version": 1, "sites": rows, "offsite": storage}

    def encode() -> str:
        return json.dumps(answer, separators=(",", ":"))

    text = encode()
    while len(text.encode("utf-8")) > MAX_OUTPUT_BYTES:
        runs: list[tuple[str, int]] = []
        for index, row in enumerate(rows):
            found = row.get("runs")
            if isinstance(found, list) and found:
                last = found[-1]
                at = last.get("at") if isinstance(last, dict) else ""
                runs.append((at if isinstance(at, str) else "", index))
        if runs:
            _, index = min(runs)
            found = rows[index]["runs"]
            if isinstance(found, list):
                found.pop()
                rows[index]["runs_truncated"] = True
        else:
            timers = [
                (len(found), index)
                for index, row in enumerate(rows)
                if isinstance((found := row.get("timers")), list) and found
            ]
            if not timers:
                break
            _, index = max(timers)
            found = rows[index]["timers"]
            if isinstance(found, list):
                found.pop()
                rows[index]["timers_truncated"] = True
        text = encode()
    return text


if __name__ == "__main__":
    main()
