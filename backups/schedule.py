"""One backup schedule per site, created and disabled through a reviewed change (#402).

The schedule is a fixed native timer in the site's own backup slice, separate from its
automation slice. The review reads the installed units, the timer's systemd properties and
the runtime payload, refuses a window that overlaps another site's, and never invents a next
run: systemd has to report it. A fresh controller reconstructs the same schedule from those
units and the payload; a hand-edited unit is Outside supported settings and blocks only this
site's backup changes.
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import re
import shlex
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final, cast

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import User
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from automation.bodies.source import AUTOMATION_SOURCE
from automation.convention import ENABLED_STATES, directives_map
from bootstrap.standing import Standing
from databases import observation as database_observation
from discovery.presentation import VIEW_SITES
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native, services
from operations.consent import PREPARE_PERMISSIONS, DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.lifecycle import OperationRefused
from operations.models import ChangeReview
from runtimes.catalog import architecture_of
from servers.models import Server
from sites import observation as site_observation
from sites.bodies.common import SITE_GATED
from sites.names import valid_identifier

from . import convention, observation
from .change import ALL_SITES_READ
from .models import BackupSchedule

SLUG: Final = "set_backup_schedule"
LABEL: Final = "Change backup schedule"
KINDS: Final = ("slice", "service", "timer")
DIGEST: Final = re.compile(r"[0-9a-f]{64}\Z")
RECENT: Final = timedelta(hours=48)
MAX_TEXT: Final = 16384
SHOW_PROPERTIES: Final = frozenset(
    {
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "UnitFileState",
        "Result",
        "ExecMainStatus",
        "ExecMainStartTimestamp",
        "ExecMainExitTimestamp",
        "LastTriggerUSec",
        "NextElapseUSecRealtime",
        "ControlGroup",
        "RefuseManualStart",
    }
)
RUNTIME_KEYS: Final = frozenset(
    {
        "version",
        "identifier",
        "frequency",
        "at",
        "scope",
        "application",
        "offsite",
        "engine",
        "repository",
        "server_key",
        "files",
        "dump",
        "filename",
        "offsite_plan",
        "origin",
        "lock_wait_seconds",
    }
)


@dataclass(frozen=True)
class ObservedBackupSchedule:
    """One site's fixed backup schedule, from the units and systemd only."""

    identifier: str
    frequency: str = ""
    at: str = ""
    scope: str = ""
    offsite: bool = False
    installed: bool = False
    timer_active: bool = False
    timer_enabled: bool = False
    service_active: bool = False
    next_elapse_us: int = 0
    last_trigger_us: int = 0
    last_start_us: int = 0
    last_exit_us: int = 0
    result: str = ""
    exec_status: int = 0
    problem: str = ""
    units: dict[str, str] = field(default_factory=dict)

    @property
    def configured(self) -> bool:
        return bool(self.installed and self.frequency and self.at and self.scope)

    @property
    def next_at(self) -> datetime | None:
        if self.next_elapse_us <= 0:
            return None
        try:
            return datetime.fromtimestamp(self.next_elapse_us / 1_000_000, tz=UTC)
        except OverflowError, OSError, ValueError:
            return None

    def same(self, frequency: str, at: str, scope: str, offsite: bool) -> bool:
        return (
            self.configured
            and self.frequency == frequency
            and self.at == at
            and self.scope == scope
            and self.offsite is offsite
        )


@dataclass(frozen=True)
class ScheduleEvidence:
    standing: Standing | None
    site: dict[str, object] | None
    backup: observation.ObservedBackup | None
    schedules: tuple[ObservedBackupSchedule, ...]
    engine: str
    database: bool
    database_problem: str
    current_sites: tuple[str, ...]
    boot_id: str
    uptime_centiseconds: int | None
    problem: str = ""


def _without_imports(text: str, modules: tuple[str, ...]) -> str:
    kept: list[str] = []
    skipping = False
    for line in text.splitlines():
        if any(line.startswith(f"from {module} import") for module in modules):
            skipping = line.rstrip().endswith("(")
            continue
        if skipping:
            skipping = not line.strip().endswith(")")
            continue
        kept.append(line)
    return "\n".join(kept)


CONVENTION_SOURCE: Final = (
    importlib.resources.files("backups").joinpath("convention.py").read_text()
)
OBSERVE_SOURCE: Final = (
    CONVENTION_SOURCE
    + "\n"
    + _without_imports(
        importlib.resources.files("backups.bodies").joinpath("observe_schedule.py").read_text(),
        ("backups.convention",),
    )
)
NATIVE_SOURCE: Final = importlib.resources.files("backups.bodies").joinpath("native.py").read_text()
BODY_SOURCE: Final = "\n".join(
    (
        site_observation.COMMON_SOURCE,
        AUTOMATION_SOURCE,
        NATIVE_SOURCE,
        CONVENTION_SOURCE,
        _without_imports(
            importlib.resources.files("backups.bodies").joinpath("schedule.py").read_text(),
            (
                "automation.bodies.units",
                "backups.bodies.native",
                "backups.convention",
                "sites.bodies.common",
            ),
        ),
    )
)
BODY_BYTES: Final = (
    (
        "#!/bin/sh\nexec python3 -c "
        + shlex.quote(
            "import base64,gzip; exec(gzip.decompress(base64.b64decode("
            + repr(base64.b64encode(gzip.compress(BODY_SOURCE.encode(), mtime=0)).decode())
            + ")))"
        )
        + ' "$0" "$@"\n'
    )
    .encode()
    .rstrip(b"\n")
)
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()
ON_STAGES: Final = ("preflight", "install", "verify")
OFF_STAGES: Final = ("preflight", "install", "verify")


def observe_command(identifiers: tuple[str, ...]) -> str:
    payload = json.dumps({"sites": list(identifiers)}, separators=(",", ":"))
    command = site_observation.python_command(OBSERVE_SOURCE, (payload,))
    return "sh -c " + shlex.quote("; ".join([*native.read_lock_steps(), "exec " + command]))


def _valid_show(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == SHOW_PROPERTIES
        and all(isinstance(item, str) and len(item) <= 200 for item in value.values())
    )


def _valid_text(value: object) -> bool:
    return value is None or (isinstance(value, str) and len(value) <= MAX_TEXT)


def _valid_row(value: object, identifier: str) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "identifier",
        "units",
        "payload",
        "script",
        "show",
        "timers",
        "slice_populated",
    }:
        return False
    units = value["units"]
    show = value["show"]
    timers = value["timers"]
    return (
        value["identifier"] == identifier
        and isinstance(units, dict)
        and set(units) == set(KINDS)
        and all(_valid_text(units[kind]) for kind in KINDS)
        and _valid_text(value["payload"])
        and _valid_text(value["script"])
        and isinstance(show, dict)
        and set(show) == set(KINDS)
        and all(item is None or _valid_show(item) for item in show.values())
        and isinstance(timers, list)
        and all(_valid_timer(item) for item in timers)
        and type(value["slice_populated"]) is bool
    )


def _valid_timer(value: object) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("unit"), str)
        and len(value["unit"]) <= 120
        and type(value.get("next")) is int
        and 0 <= value["next"] <= 10**18
    )


def read(
    shell: RemoteShell, identifiers: tuple[str, ...]
) -> tuple[ObservedBackupSchedule, ...] | None:
    result = run_root(shell, observe_command(identifiers))
    if result.exit_status or result.truncated:
        return None
    try:
        value: object = json.loads(result.stdout)
    except ValueError:
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "sites"}
        or value.get("version") != 1
        or not isinstance(value.get("sites"), list)
        or len(value["sites"]) != len(identifiers)
    ):
        return None
    rows = value["sites"]
    if not all(
        isinstance(row, dict) and _valid_row(row, identifier)
        for row, identifier in zip(rows, identifiers, strict=True)
    ):
        return None
    return tuple(_project(row) for row in rows)


def _project(row: dict[str, object]) -> ObservedBackupSchedule:
    identifier = str(row["identifier"])
    units_value = row["units"]
    units_raw = units_value if isinstance(units_value, dict) else {}
    units = {kind: str(units_raw[kind]) for kind in KINDS if isinstance(units_raw.get(kind), str)}
    # The slice is shared with the integrity units Enable backups installs (#405), so a
    # slice on its own is not a schedule. Only the payload or the schedule's own service
    # and timer mean a schedule exists.
    installed = bool(units_raw.get("service") or units_raw.get("timer"))
    payload = _runtime(row["payload"])
    problem = ""
    frequency = at = scope = ""
    offsite = False
    if payload is None:
        if installed:
            problem = "The backup schedule is outside supported settings."
    else:
        frequency = str(payload["frequency"])
        at = str(payload["at"])
        scope = str(payload["scope"])
        offsite = payload["offsite"] is True
        installed = True
        if set(units) != set(KINDS):
            problem = "The backup schedule is outside supported settings."
        else:
            for kind in KINDS:
                expected = convention.render_schedule(identifier, kind, frequency, at)
                if directives_map(units[kind]) != directives_map(expected):
                    problem = "The backup schedule was changed outside Barectl."
                    break
    show = row["show"]
    shows = show if isinstance(show, dict) else {}
    timer = shows.get("timer")
    service = shows.get("service")
    timer_values = timer if isinstance(timer, dict) else {}
    service_values = service if isinstance(service, dict) else {}
    timers = row["timers"]
    listed = (
        next(
            (
                item
                for item in timers
                if isinstance(item, dict)
                and item.get("unit") == convention.schedule_unit_name(identifier, "timer")
            ),
            None,
        )
        if isinstance(timers, list)
        else None
    )
    next_elapse_us = (
        int(listed["next"]) if isinstance(listed, dict) and type(listed.get("next")) is int else 0
    )
    if next_elapse_us <= 0:
        next_elapse_us = _timestamp(timer_values.get("NextElapseUSecRealtime", ""))
    masked = (
        timer_values.get("UnitFileState") in ("masked", "masked-runtime")
        or service_values.get("UnitFileState") in ("masked", "masked-runtime")
        or timer_values.get("RefuseManualStart") == "yes"
        or service_values.get("RefuseManualStart") == "yes"
    )
    return ObservedBackupSchedule(
        identifier=identifier,
        frequency=frequency,
        at=at,
        scope=scope,
        offsite=offsite,
        installed=installed,
        timer_active=timer_values.get("ActiveState") == "active",
        timer_enabled=(timer_values.get("UnitFileState") in ENABLED_STATES and not masked),
        service_active=service_values.get("ActiveState") in ("active", "activating"),
        next_elapse_us=next_elapse_us,
        last_trigger_us=_timestamp(timer_values.get("LastTriggerUSec", "")),
        last_start_us=_timestamp(service_values.get("ExecMainStartTimestamp", "")),
        last_exit_us=_timestamp(service_values.get("ExecMainExitTimestamp", "")),
        result=str(service_values.get("Result", "")),
        exec_status=_int(service_values.get("ExecMainStatus", "0")),
        problem=problem,
        units={kind: convention_digest(units[kind]) for kind in KINDS if kind in units},
    )


def convention_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _runtime(value: object) -> dict[str, object] | None:
    if not isinstance(value, str) or len(value) > MAX_TEXT:
        return None
    try:
        document = json.loads(value)
    except ValueError:
        return None
    if (
        not isinstance(document, dict)
        or set(document) != RUNTIME_KEYS
        or document.get("version") != 1
        or not isinstance(document.get("identifier"), str)
        or document.get("identifier") is None
        or document.get("frequency") not in convention.FREQUENCIES
        or not isinstance(document.get("at"), str)
        or convention.TIME.fullmatch(str(document["at"])) is None
        or document.get("scope") not in convention.SCHEDULE_SCOPES
        or document.get("application") not in ("", *convention.APPLICATIONS)
        or type(document.get("offsite")) is not bool
        or not isinstance(document.get("engine"), str)
        or not isinstance(document.get("repository"), str)
        or not isinstance(document.get("server_key"), str)
        or not isinstance(document.get("files"), list)
        or not all(isinstance(item, str) for item in document["files"])
        or not isinstance(document.get("dump"), list)
        or not all(isinstance(item, str) for item in document["dump"])
        or not isinstance(document.get("filename"), str)
        or not isinstance(document.get("offsite_plan"), dict)
        or document.get("origin") != "scheduled"
        or document.get("lock_wait_seconds") != convention.SCHEDULE_LOCK_WAIT_SECONDS
    ):
        return None
    if document["repository"] != convention.repository(str(document["identifier"])):
        return None
    if document["server_key"] != convention.server_key(str(document["identifier"])):
        return None
    return document


def _timestamp(value: str) -> int:
    text = value.removeprefix("@")
    return int(text) * 1_000_000 if text.isdigit() and len(text) <= 20 else 0


def _int(value: str) -> int:
    return int(value) if value.isdigit() and len(value) <= 9 else 0


def _site_record(
    shell: RemoteShell, identifier: str
) -> tuple[dict[str, object] | None, tuple[str, ...], str, int | None]:
    listing = site_observation.read(shell, "observed", "", protections=False)
    if listing is None:
        return None, (), "", None
    record = next(
        (site for site in listing["sites"] if site["identifier"] == identifier),
        None,
    )
    current = tuple(sorted(str(site) for site in listing["current_sites"]))
    if record is None:
        return None, current, str(listing["boot"]), int(str(listing["uptime"]))
    return dict(record), current, str(listing["boot"]), int(str(listing["uptime"]))


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> ScheduleEvidence:
    from discovery.observations import collect

    observed = collect(shell, sites=False)
    architecture = architecture_of(observed.architecture.value or "")
    engines = database_observation.installed_engines(observed)
    engine = engines[0].engine if len(engines) == 1 and engines[0].managed else ""
    record, current_sites, boot_id, uptime = _site_record(shell, inputs.identifier)
    listing = shell.run(ALL_SITES_READ)
    if listing.exit_status == 0 and not listing.truncated:
        current_sites = tuple(listing.stdout.splitlines())
    backup_value = observation.read(shell, (inputs.identifier,), engine, architecture)
    backup = _backup(backup_value, inputs.identifier) if backup_value is not None else None
    schedules = read(shell, current_sites) if current_sites else ()
    problem = ""
    if backup_value is None:
        problem = "Backups could not be read from the server."
    elif schedules is None:
        problem = "The backup schedule could not be read from the server."
    return ScheduleEvidence(
        observed.standing.standing if observed.standing else None,
        record,
        backup,
        schedules or (),
        engine,
        bool(backup.database) if backup is not None else False,
        backup.database_problem if backup is not None else "",
        current_sites,
        boot_id,
        uptime,
        problem,
    )


def _backup(value: dict[str, object], identifier: str) -> observation.ObservedBackup | None:
    rows = value.get("sites")
    item = (
        next(
            (row for row in rows if isinstance(row, dict) and row.get("identifier") == identifier),
            None,
        )
        if isinstance(rows, list)
        else None
    )
    if not isinstance(item, dict):
        return None
    last = item.get("last")
    return observation.ObservedBackup(
        identifier,
        str(item["profile"]),
        bool(item["repository"]),
        bool(item["key"]),
        tuple(str(problem) for problem in item["problems"]),
        bool(item["database"]),
        str(item["database_problem"]),
        observation.BackupResult(
            str(last["class"]),
            str(last["reason"]),
            str(last["scope"]),
            str(last["origin"]),
            str(last["at"]),
            str(last["point"]),
            int(str(last["snapshots"])),
            int(str(last["bytes"])),
        )
        if isinstance(last, dict)
        else None,
    )


def _current(evidence: ScheduleEvidence, identifier: str) -> ObservedBackupSchedule:
    return next(
        (row for row in evidence.schedules if row.identifier == identifier),
        ObservedBackupSchedule(identifier),
    )


def _site_problem(evidence: ScheduleEvidence) -> str:
    if evidence.site is None:
        return "The site's native configuration could not be read."
    if (
        str(evidence.site.get("state", "")) != "complete"
        or evidence.site.get("problem") == SITE_GATED
    ):
        return "The site is not complete, so its backup schedule cannot change."
    return ""


def _offsite_plan(evidence: ScheduleEvidence, identifier: str) -> dict[str, object]:
    storage = evidence.backup.offsite if evidence.backup is not None else None
    if storage is None or not storage.configured:
        return {}
    config = {
        "provider": storage.provider,
        "bucket": storage.bucket,
        "region": storage.region,
        "endpoint": storage.endpoint,
        "prefix": storage.prefix,
        "prune": "yes" if storage.prune else "no",
    }
    try:
        repository = convention.offsite_repository(config, identifier)
    except ValueError:
        return {}
    return {
        "storage": {
            "provider": storage.provider,
            "bucket": storage.bucket,
            "region": storage.region,
            "endpoint": storage.endpoint,
            "prefix": storage.prefix,
            "prune": config["prune"],
        },
        "repository": repository,
        "capture_env": convention.OFFSITE_CAPTURE,
    }


def _files(identifier: str, application: str) -> list[str]:
    directory = f"/var/www/{identifier}"
    shared = {
        "laravel": ["private/laravel.env", "private/storage", "private/cache"],
        "wordpress": ["private/wp-config.php"],
        "plain": [],
    }.get(application, [])
    return [f"{directory}/current", *(f"{directory}/{path}" for path in shared)]


def _overlap(
    evidence: ScheduleEvidence, identifier: str, frequency: str, at: str
) -> tuple[bool, str]:
    """Whether another site's window overlaps, and the next free slot."""
    minute = _minute(at)
    others = [
        row
        for row in evidence.schedules
        if row.identifier != identifier
        and row.configured
        and row.frequency in convention.FREQUENCIES
        and row.at
    ]
    clash = next(
        (
            row
            for row in others
            if _same_day(row.frequency, frequency)
            and abs(_minute(row.at) - minute) < convention.SCHEDULE_WINDOW_MINUTES
        ),
        None,
    )
    if clash is None:
        return False, ""
    for hours in range(1, 24):
        candidate = (minute + hours * 60) % (24 * 60)
        text = f"{candidate // 60:02d}:{candidate % 60:02d}"
        if not any(
            _same_day(row.frequency, frequency)
            and abs(_minute(row.at) - candidate) < convention.SCHEDULE_WINDOW_MINUTES
            for row in others
        ):
            return True, text
    return True, ""


def _same_day(left: str, right: str) -> bool:
    return left == "daily" or right == "daily" or left == right


def _minute(value: str) -> int:
    match = convention.TIME.fullmatch(value)
    return int(match.group(1)) * 60 + int(match.group(2)) if match else -1


def _scope_choice(evidence: ScheduleEvidence, scope: str) -> str:
    if scope == "database" and not evidence.database:
        return "database"
    if scope == "full" and not evidence.database:
        return "files"
    if scope == "full":
        return "full"
    return scope


def _refusals(  # noqa: C901 - one list of every refusal
    evidence: ScheduleEvidence,
    inputs: PreparationInputs,
    current: ObservedBackupSchedule,
    frequency: str,
    at: str,
    scope: str,
    offsite: bool,
) -> list[str]:
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before changing a backup schedule.")
    site_problem = _site_problem(evidence)
    if site_problem:
        refusals.append(site_problem)
    if evidence.problem:
        refusals.append(evidence.problem)
    if current.problem:
        refusals.append(current.problem)
    if inputs.schedule_state not in ("on", "off"):
        refusals.append("Choose whether to set or turn off the backup schedule.")
    if evidence.backup is None or not evidence.backup.enabled:
        refusals.append("Enable backups for this site first.")
    if inputs.schedule_state == "off":
        return refusals
    if frequency not in convention.FREQUENCIES or convention.TIME.fullmatch(at) is None:
        refusals.append("Choose a daily or weekly time in UTC.")
        return refusals
    if scope not in convention.SCHEDULE_SCOPES:
        refusals.append("Choose what the schedule copies.")
    elif scope == "database" and not evidence.database:
        refusals.append(evidence.database_problem or "This site has no site database.")
    if not evidence.engine and scope in ("database", "full"):
        refusals.append("This server has no managed database engine to dump.")
    if offsite and not _offsite_plan(evidence, str(inputs.identifier)):
        refusals.append("Set up offsite storage before scheduling an offsite copy.")
    account = evidence.site.get("account") if evidence.site is not None else None
    if not (isinstance(account, list) and len(account) >= 2 and type(account[0]) is int):
        refusals.append("The site's Linux account is not observed.")
    clash, next_slot = _overlap(evidence, str(inputs.identifier), frequency, at)
    if clash:
        refusals.append(
            f"Another site's backup runs in that window. Choose {next_slot} UTC instead."
            if next_slot
            else "Another site's backup runs in that window, and no free hour remains today."
        )
    return refusals


def _details(
    evidence: ScheduleEvidence,
    inputs: PreparationInputs,
    current: ObservedBackupSchedule,
    frequency: str,
    at: str,
    scope: str,
    offsite: bool,
) -> list[dict[str, str]]:
    if inputs.schedule_state == "off":
        return [
            {"label": "Site", "value": inputs.identifier},
            {"label": "Backup schedule", "value": "Turned off"},
            {
                "label": "Current schedule",
                "value": _state_label(current),
            },
        ]
    label = "Full site" if scope in ("full", "files") else "Database only"
    database = (
        "The database and the site's files"
        if scope == "full"
        else ("The site's files" if scope == "files" else "The database")
    )
    return [
        {"label": "Site", "value": inputs.identifier},
        {
            "label": "Runs",
            "value": f"{frequency.capitalize()} at {at} UTC",
        },
        {"label": "Copies", "value": f"{label}: {database}."},
        {
            "label": "During the copy",
            "value": "The site keeps serving; the database is copied first, then the files.",
        },
        {
            "label": "Offsite copy",
            "value": (
                "Yes, after the onsite copy finishes."
                if offsite
                else "No. The recovery point stays on this server."
            ),
        },
        {
            "label": "Next run",
            "value": _next_label(current) or "Systemd has not reported it yet.",
        },
        {
            "label": "Current schedule",
            "value": _state_label(current),
        },
    ]


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, ScheduleEvidence):
        raise ValueError("A backup schedule change needs native evidence.")
    current = _current(evidence, str(inputs.identifier))
    frequency = inputs.frequency
    at = inputs.at
    scope = _scope_choice(evidence, inputs.scope)
    offsite = bool(inputs.offsite)
    plan = _offsite_plan(evidence, str(inputs.identifier)) if offsite else {}
    refusals = _refusals(evidence, inputs, current, frequency, at, scope, offsite)
    unchanged = (
        (inputs.schedule_state == "off" and not current.installed)
        or (inputs.schedule_state == "on" and current.same(frequency, at, scope, offsite))
    ) and not refusals
    application = (
        str(evidence.site.get("application", "plain")) if evidence.site is not None else ""
    )
    files = _files(str(inputs.identifier), application) if scope in ("full", "files") else []
    dump = (
        convention.dump_argv(str(inputs.identifier), evidence.engine)
        if evidence.engine and scope in ("database", "full")
        else []
    )
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": inputs.identifier,
        "state": inputs.schedule_state,
        "frequency": frequency,
        "at": at,
        "scope": scope,
        "application": application,
        "engine": evidence.engine if dump else "",
        "repository": convention.repository(str(inputs.identifier)),
        "server_key": convention.server_key(str(inputs.identifier)),
        "files": files,
        "dump": dump,
        "filename": convention.dump_filename(str(inputs.identifier)),
        "offsite": offsite,
        "offsite_plan": plan,
        "units": {kind: current.units.get(kind, "absent") for kind in KINDS},
        "details": _details(evidence, inputs, current, frequency, at, scope, offsite),
    }
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals and not unchanged:
        effects = (
            DeclaredEffect(
                Scope.SITE,
                (
                    f"Run {inputs.identifier}'s {frequency} backup at {at} UTC on the server."
                    if inputs.schedule_state == "on"
                    else f"Stop running {inputs.identifier}'s backup schedule on the server."
                ),
                (inputs.identifier,),
            ),
        )
    note = ""
    if unchanged:
        note = (
            "The backup schedule is already set to this window."
            if inputs.schedule_state == "on"
            else "This site has no backup schedule."
        )
    return ReviewDraft(
        SLUG,
        (
            f"Set the backup schedule for {inputs.identifier}."
            if inputs.schedule_state == "on"
            else f"Turn off the backup schedule for {inputs.identifier}."
        ),
        effects=effects,
        stages=ON_STAGES if inputs.schedule_state == "on" else OFF_STAGES,
        postconditions=(
            (
                "The timer runs at the reviewed UTC time with no catch-up and a finite run window.",
                "Systemd reports the timer active and its next run.",
                "The schedule lives in the site's own backup slice, not its automation slice.",
            )
            if inputs.schedule_state == "on"
            else (
                "The timer, service and slice are removed from the server.",
                "No scheduled capture runs until a new schedule is reviewed.",
            )
        ),
        refusals=tuple(dict.fromkeys(refusals)),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        sites_read=presence_command(str(inputs.identifier)) if evidence.site is not None else "",
        current_sites=(str(inputs.identifier),) if evidence.site is not None else None,
        document={**document, "note": note} if note else document,
    )


def presence_command(identifier: str) -> str:
    path = shlex.quote(f"/etc/caddy/sites/{identifier}.caddy")
    return f"test -f {path} && printf '%s\\n' {shlex.quote(identifier)}"


def _document(document: dict[str, object]) -> dict[str, object]:
    identifier = str(document.get("identifier", ""))
    state = document.get("state")
    units = document.get("units")
    frequency = str(document.get("frequency", ""))
    at = str(document.get("at", ""))
    scope = str(document.get("scope", ""))
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or not valid_identifier(identifier)
        or state not in ("on", "off")
        or not isinstance(units, dict)
        or set(units) != set(KINDS)
        or not all(
            units.get(kind) == "absent"
            or (isinstance(units.get(kind), str) and DIGEST.fullmatch(str(units[kind])))
            for kind in KINDS
        )
        or type(document.get("offsite")) is not bool
        or document.get("application") not in ("", *convention.APPLICATIONS)
    ):
        raise ValueError("The backup schedule review is not a valid immutable selection.")
    files = document.get("files")
    dump = document.get("dump")
    root = f"/var/www/{identifier}/"
    if state == "on" and (
        frequency not in convention.FREQUENCIES
        or convention.TIME.fullmatch(at) is None
        or scope not in convention.SCHEDULE_SCOPES
        or document.get("repository") != convention.repository(identifier)
        or document.get("server_key") != convention.server_key(identifier)
        or document.get("filename") != convention.dump_filename(identifier)
        or not isinstance(files, list)
        or not all(isinstance(item, str) for item in files)
        or not isinstance(dump, list)
        or not all(isinstance(item, str) for item in dump)
        or (
            scope == "database"
            and (files or not dump or document.get("engine") not in ("mariadb", "postgresql"))
        )
        or (scope in ("full", "files") and not files)
        or (scope == "full" and not dump)
        or (scope == "files" and dump)
        or (
            files
            and (
                files[0] != root + "current"
                or not all(
                    isinstance(item, str) and item.startswith(root) and ".." not in item
                    for item in files
                )
            )
        )
        or (dump and dump != convention.dump_argv(identifier, str(document.get("engine", ""))))
        or (
            document["offsite"]
            and not _valid_offsite_plan(document.get("offsite_plan"), identifier)
        )
        or (not document["offsite"] and document.get("offsite_plan") != {})
    ):
        raise ValueError("The backup schedule review is not a valid immutable selection.")
    return {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": identifier,
        "state": state,
        "frequency": frequency,
        "at": at,
        "scope": scope,
        "application": str(document.get("application", "")),
        "offsite": document["offsite"],
        "engine": str(document.get("engine", "")),
        "repository": str(document.get("repository", "")),
        "server_key": str(document.get("server_key", "")),
        "files": list(cast("list[object]", files or [])),
        "dump": list(cast("list[object]", dump or [])),
        "filename": str(document.get("filename", "")),
        "offsite_plan": document.get("offsite_plan", {}),
        "units": {kind: str(units[kind]) for kind in KINDS},
    }


def _valid_offsite_plan(value: object, identifier: str) -> bool:
    if not isinstance(value, dict) or set(value) != {"storage", "repository", "capture_env"}:
        return False
    storage = value.get("storage")
    if not isinstance(storage, dict) or set(storage) != {
        "provider",
        "bucket",
        "region",
        "endpoint",
        "prefix",
        "prune",
    }:
        return False
    if not (
        isinstance(storage.get("provider"), str)
        and isinstance(storage.get("bucket"), str)
        and isinstance(storage.get("region"), str)
        and isinstance(storage.get("endpoint"), str)
        and isinstance(storage.get("prefix"), str)
        and storage.get("prune") in ("yes", "no")
        and value.get("capture_env") == convention.OFFSITE_CAPTURE
    ):
        return False
    config = {
        "provider": str(storage["provider"]),
        "bucket": str(storage["bucket"]),
        "region": str(storage["region"]),
        "endpoint": str(storage["endpoint"]),
        "prefix": str(storage["prefix"]),
        "prune": str(storage["prune"]),
    }
    try:
        return value.get("repository") == convention.offsite_repository(config, identifier)
    except ValueError:
        return False


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    payload = _document(document)
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES, (encoded,))


def verify(shell: RemoteShell, review: ChangeReview) -> bool | None:
    document = review.document
    identifier = str(document.get("identifier", ""))
    rows = read(shell, (identifier,))
    if rows is None:
        return None
    row = rows[0]
    _record_review(review, row)
    if document.get("state") == "on":
        return bool(
            row.configured
            and row.installed
            and row.timer_active
            and row.timer_enabled
            and row.next_elapse_us > 0
        )
    return not row.installed


def _record_review(review: ChangeReview, row: ObservedBackupSchedule) -> None:
    preparation = review.preparation
    if preparation is None or preparation.server_id is None:
        return
    server = Server.objects.filter(pk=preparation.server_id).first()
    if server is not None:
        record(server, row)


def record(server: Server, row: ObservedBackupSchedule) -> None:
    BackupSchedule.objects.update_or_create(
        server=server,
        identifier=row.identifier,
        defaults={
            "frequency": row.frequency,
            "at": row.at,
            "scope": row.scope,
            "offsite": row.offsite,
            "installed": row.installed,
            "timer_active": row.timer_active,
            "timer_enabled": row.timer_enabled,
            "service_active": row.service_active,
            "next_elapse_us": row.next_elapse_us,
            "last_trigger_us": row.last_trigger_us,
            "last_start_us": row.last_start_us,
            "last_exit_us": row.last_exit_us,
            "result": row.result,
            "exec_status": row.exec_status,
            "problem": row.problem,
            "checked_at": datetime.now(tz=UTC),
        },
    )


def stored(server: Server, identifier: str) -> BackupSchedule | None:
    return BackupSchedule.objects.filter(server=server, identifier=identifier).first()


def listing(row: ObservedBackupSchedule | None) -> dict[str, object]:
    """The bounded schedule block a Check backups listing stores."""
    if row is None:
        return {}
    return {
        "frequency": row.frequency,
        "at": row.at,
        "scope": row.scope,
        "offsite": row.offsite,
        "installed": row.installed,
        "timer_active": row.timer_active,
        "timer_enabled": row.timer_enabled,
        "next_elapse_us": row.next_elapse_us,
        "problem": row.problem,
    }


def _next_label(row: ObservedBackupSchedule | BackupSchedule | None) -> str:
    if row is None or row.next_elapse_us <= 0:
        return ""
    try:
        value = datetime.fromtimestamp(row.next_elapse_us / 1_000_000, tz=UTC)
    except OverflowError, OSError, ValueError:
        return ""
    return value.strftime("%-d %b %Y, %H:%M UTC")


def _state_label(row: ObservedBackupSchedule | BackupSchedule | None) -> str:
    if row is None or not row.installed:
        return "No schedule"
    if row.problem:
        return row.problem
    scope = {
        "database": "Database only",
        "full": "Full site",
        "files": "Full site (files only)",
    }.get(row.scope, "Full site")
    offsite = ", plus an offsite copy" if row.offsite else ""
    return f"{row.frequency.capitalize()} at {row.at} UTC: {scope}{offsite}"


def context_for_site(server: Server, identifier: str, context: dict[str, object]) -> None:
    """The schedule block the Backups section shows, from the last verified read."""
    row = stored(server, identifier)
    context["backup_schedule"] = row
    context["backup_schedule_state"] = _state_label(row)
    context["backup_schedule_next"] = _next_label(row)
    context["backup_schedule_problem"] = row.problem if row is not None else ""
    context["backup_schedule_offsite"] = bool(row.offsite) if row is not None else False
    context["backups_can_schedule"] = bool(context.get("backups_can_back_up_full"))


def recent_missing(collected: object, now: datetime | None = None) -> set[str] | None:
    """Sites without a complete point in the fixed 48-hour window, or ``None`` unread."""
    from discovery.models import ObservationOutcome

    backups = getattr(collected, "backups", None)
    if backups is None or backups.outcome != ObservationOutcome.OBSERVED:
        return None
    moment = now or datetime.now(tz=UTC)
    recent: set[str] = set()
    for row in backups.value:
        last = row.last
        if last is None or last.result_class != "succeeded":
            continue
        if last.reason.startswith("restore_") or last.scope not in convention.SCOPES:
            continue
        when = last.time
        if when is not None and moment - when <= RECENT:
            recent.add(row.identifier)
    return {row.identifier for row in backups.value} - recent


SET_BACKUP_SCHEDULE: Final = ChangeKind(
    SLUG,
    LABEL,
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_shape=InputShape.BACKUP_SCHEDULE,
    input_choices=(),
)


@require_POST
@login_required
@permission_required((*PREPARE_PERMISSIONS, VIEW_SITES), raise_exception=True)
def prepare_schedule(request: HttpRequest, pk: int, identifier: str) -> HttpResponse:
    if not valid_identifier(identifier) or not isinstance(request.user, User):
        raise Http404
    server = get_object_or_404(Server, pk=pk)
    state = request.POST.get("state", "on")
    if state not in ("on", "off"):
        raise Http404
    inputs: dict[str, object] = {"version": 1, "identifier": identifier, "state": state}
    if state == "on":
        frequency = request.POST.get("frequency", "daily")
        at = request.POST.get("at", "03:00")
        scope = request.POST.get("scope", "full")
        offsite = request.POST.get("offsite") == "on"
        if (
            frequency not in convention.FREQUENCIES
            or convention.TIME.fullmatch(at) is None
            or scope not in ("database", "full")
        ):
            messages.error(request, "Choose a daily or weekly time in UTC and what to copy.")
            return redirect("site_backups", pk=pk, identifier=identifier)
        inputs.update(
            frequency=frequency,
            at=at,
            scope=scope,
            offsite=offsite,
        )
    try:
        queued = services.request_prepare(server, request.user, SLUG, inputs=inputs)
    except OperationRefused, ValueError:
        messages.error(request, "The saved connection changed. Refresh and prepare again.")
        return redirect("site_backups", pk=pk, identifier=identifier)
    except Server.DoesNotExist:
        raise Http404 from None
    if queued is None:
        messages.error(request, "Wait for the current operation before preparing this review.")
        return redirect("site_backups", pk=pk, identifier=identifier)
    return redirect("change_detail", operation_id=queued.pk)
