"""A Laravel site's scheduler as one reviewed site change (Phase C #357, #265).

**Settings > Scheduled tasks** turns the site's timer on or off and can run one tick now.
The review reads native evidence only: the site's layout, the current release, the
maintenance gate, the recorded migrations and the automation units. The body publishes or
removes the units, or starts the installed oneshot service and waits for its result. Nothing
is remembered in the controller.
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import re
import shlex
from dataclasses import dataclass
from typing import Final

from bootstrap.standing import Standing
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from sites import observation as site_observation
from sites.bodies.common import SITE_GATED, SiteRecord
from sites.configuration import PHP_RUNTIMES

from . import convention, observation
from .change import presence_command
from .status import STATUS_SENTENCE, ScheduleStatus

SLUG: Final = "set_laravel_scheduler"
LABEL: Final = "Change scheduled tasks"
KINDS: Final = ("slice", "service", "timer")
DIGEST: Final = re.compile(r"[0-9a-f]{64}\Z")
MIGRATION_FILE: Final = re.compile(r"([0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{6}_[a-z0-9_]+)\.php\Z")
RELEASE_NAME: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
ON_STAGES: Final = ("preflight", "install", "verify")
OFF_STAGES: Final = ("preflight", "install", "verify")
RUN_STAGES: Final = ("preflight", "run", "verify")
ON_STATES: Final = frozenset(
    {
        ScheduleStatus.WAITING,
        ScheduleStatus.RUNNING,
        ScheduleStatus.SUCCEEDED,
        ScheduleStatus.FAILED,
        ScheduleStatus.TIMED_OUT,
        ScheduleStatus.SKIPPED,
    }
)
# How long a Run now waits for the tick inside the change's own 30-minute run limit.
RUN_NOW_WAIT_SECONDS: Final = 1500
_IMPORTS: Final = (
    "sites.bodies.common",
    "automation.convention",
    "automation.bodies.units",
)


def _without_imports(text: str) -> str:
    """Drop the imports the assembled body receives from its concatenated neighbours."""
    kept: list[str] = []
    skipping = False
    for line in text.splitlines():
        if any(line.startswith(f"from {module} import") for module in _IMPORTS):
            skipping = line.rstrip().endswith("(")
            continue
        if skipping:
            skipping = not line.strip().endswith(")")
            continue
        kept.append(line)
    return "\n".join(kept)


BODY_SOURCE: Final = "\n".join(
    (
        site_observation.COMMON_SOURCE,
        importlib.resources.files("automation").joinpath("convention.py").read_text(),
        _without_imports(
            importlib.resources.files("automation.bodies").joinpath("units.py").read_text()
        ),
        _without_imports(
            importlib.resources.files("automation.bodies").joinpath("scheduler.py").read_text()
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
        + ' "$@"\n'
    )
    .encode()
    .rstrip(b"\n")
)
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()


@dataclass(frozen=True)
class SchedulerEvidence:
    """Everything the pure review may decide from, read once during preparation."""

    standing: Standing | None
    site: SiteRecord | None
    laravel: dict[str, object] | None
    automation: dict[str, object] | None
    pending: tuple[str, ...] | None
    boot_id: str
    uptime_centiseconds: int | None


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> SchedulerEvidence:
    from discovery.observations import collect
    from laravel import observation as laravel_observation

    snapshot = collect(shell, sites=False)
    state = site_observation.read(shell, "observed", "", protections=False)
    laravel = laravel_observation.read(shell)
    site = (
        next(
            (row for row in state["sites"] if row["identifier"] == inputs.identifier),
            None,
        )
        if state is not None
        else None
    )
    pending: tuple[str, ...] | None = ()
    if inputs.schedule_state in ("on", "run"):
        pending = _pending_migrations(shell, inputs.identifier, site, laravel)
    return SchedulerEvidence(
        snapshot.standing.standing if snapshot.standing else None,
        site,
        laravel,
        observation.read(shell),
        pending,
        str(state["boot"]) if state is not None else "",
        int(str(state["uptime"])) if state is not None else None,
    )


def _account(site: SiteRecord | None) -> tuple[int, int] | None:
    account = site["account"] if site is not None else None
    if not isinstance(account, list) or len(account) < 2:
        return None
    uid, gid = account[0], account[1]
    if type(uid) is not int or type(gid) is not int:
        return None
    return uid, gid


def _laravel_row(laravel: dict[str, object] | None, identifier: str) -> dict[str, object] | None:
    if laravel is None:
        return None
    from laravel.observation import site as laravel_site

    return laravel_site(laravel, identifier)


def _release(row: dict[str, object] | None) -> dict[str, object] | None:
    if row is None:
        return None
    current = str(row.get("current", ""))
    releases = row.get("releases")
    for entry in releases if isinstance(releases, list) else []:
        if isinstance(entry, dict) and str(entry.get("name", "")) == current:
            return entry
    return None


def _migration_files_command(identifier: str, release: str) -> str:
    directory = f"{convention.site_directory(identifier)}/releases/{shlex.quote(release)}"
    return "sh -c " + shlex.quote(
        "; ".join(
            [
                *native.read_lock_steps(),
                "exec find "
                + shlex.quote(directory + "/database/migrations")
                + " -maxdepth 1 -type f -name '*.php' -printf '%f\\n'",
            ]
        )
    )


def _recorded_migrations_command(identifier: str) -> str:
    account = convention.account(identifier)
    query = "SELECT migration FROM migrations"
    mariadb = (
        f"exec /usr/sbin/runuser -u {account} -- /usr/bin/mariadb --no-defaults "
        f"--protocol=socket --socket=/run/mysqld/mysqld.sock {account} -N -B "
        f"-e {shlex.quote(query)}"
    )
    postgres = (
        f"exec /usr/sbin/runuser -u {account} -- /usr/bin/psql -X -t -A -d {account} "
        f"-c {shlex.quote(query)}"
    )
    script = (
        f"if [ -x /usr/bin/mariadb ]; then {mariadb}; "
        f"elif [ -x /usr/bin/psql ]; then {postgres}; else exit 9; fi"
    )
    return "sh -c " + shlex.quote("; ".join([*native.read_lock_steps(), script]))


def _pending_migrations(
    shell: RemoteShell,
    identifier: str,
    site: SiteRecord | None,
    laravel: dict[str, object] | None,
) -> tuple[str, ...] | None:
    """The migrations the current release carries but the database has not recorded."""
    row = _laravel_row(laravel, identifier)
    if site is None or row is None or row["application"] != "laravel":
        return ()
    current = str(row.get("current", ""))
    if not current or RELEASE_NAME.fullmatch(current) is None:
        return None
    files = run_root(shell, _migration_files_command(identifier, current))
    if files.truncated or files.exit_status not in (0, 1):
        return None
    if files.exit_status == 1:
        # A release without a migrations directory is a supported, empty answer.
        return ()
    found = {
        match.group(1)
        for line in files.stdout.splitlines()
        if (match := MIGRATION_FILE.fullmatch(line.strip()))
    }
    if not found:
        return ()
    records = run_root(shell, _recorded_migrations_command(identifier))
    if records.exit_status or records.truncated:
        return None
    recorded = {line.strip() for line in records.stdout.splitlines() if line.strip()}
    return tuple(sorted(found - recorded))


def _unit_digests(
    value: dict[str, object] | None, identifier: str
) -> tuple[dict[str, str] | None, list[str]]:
    """The reviewed preimage digests, or the unsupported findings that block the change."""
    digests = dict.fromkeys(KINDS, "absent")
    if value is None:
        return None, []
    rows = value.get("sites")
    candidates = rows if isinstance(rows, list) else []
    row = next(
        (
            item
            for item in candidates
            if isinstance(item, dict) and item.get("identifier") == identifier
        ),
        None,
    )
    if row is None:
        return digests, []
    problems: list[str] = []
    units = row.get("units")
    for unit in units if isinstance(units, list) else []:
        if not isinstance(unit, dict):
            continue
        kind, name, text = (
            str(unit.get("kind", "")),
            str(unit.get("name", "")),
            str(unit.get("text", "")),
        )
        if kind not in KINDS:
            continue
        if kind != "slice" and convention.role_of(name, identifier) != convention.ROLE_SCHEDULE:
            continue
        shape = convention.parse_unit(name, text, identifier, convention.ROLE_SCHEDULE, kind)
        if not shape.supported:
            problems.append(shape.problem)
            continue
        if digests[kind] != "absent":
            problems.append("The background task files are duplicated.")
            continue
        digests[kind] = convention.digest(text)
    return digests, list(dict.fromkeys(problems))


def _refusals(  # noqa: C901 - one list of every refusal
    evidence: SchedulerEvidence, inputs: PreparationInputs, schedule: observation.ObservedSchedule
) -> tuple[list[str], dict[str, str] | None]:
    refusals: list[str] = []
    state = inputs.schedule_state
    if state not in ("on", "off", "run"):
        refusals.append("Choose whether to turn the scheduler on, off or run it now.")
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before changing a site.")
    if evidence.site is None:
        refusals.append("The site's native configuration could not be read.")
    if evidence.automation is None:
        refusals.append("The site's scheduled tasks could not be read.")
    digests, problems = _unit_digests(evidence.automation, inputs.identifier)
    refusals.extend(problems)
    if state == "off":
        # Stopping is always available while the site's own unit evidence is readable.
        if digests is None:
            refusals.append("The site's scheduled tasks could not be read.")
        return refusals, digests
    site = evidence.site
    row = _laravel_row(evidence.laravel, inputs.identifier)
    if row is not None and row["application"] != "laravel":
        refusals.append("This site is not a Laravel application.")
    if site is not None and (
        site["state"] != "complete" or site["application_problem"] or site["problem"] == SITE_GATED
    ):
        refusals.append("The site is not deployed completely and verified.")
    if site is not None and (site["runtime"] not in PHP_RUNTIMES or _account(site) is None):
        refusals.append("The site's PHP runtime or Linux account is not observed.")
    if row is None or not row.get("current"):
        refusals.append("Deploy this site before turning on its scheduler.")
    release = _release(row)
    if (
        row is not None
        and row.get("current")
        and (release is None or release.get("state") != "complete")
    ):
        refusals.append("The site's current release is not complete.")
    if site is not None and site["problem"] == SITE_GATED:
        refusals.append(
            "The site is in maintenance. Finish the change in progress before running "
            "scheduled tasks."
        )
    if evidence.pending is None:
        refusals.append("Barectl could not read the site's migration state.")
    elif evidence.pending:
        refusals.append(
            "The site has pending migrations. Deploy it before running scheduled tasks."
        )
    if state == "run" and not (
        schedule.installed and schedule.timer_present and schedule.service_present
    ):
        refusals.append("Turn on the scheduler before running it now.")
    if state == "on" and schedule.duplicate:
        refusals.append(schedule.duplicate)
    return refusals, digests


def _already(inputs: PreparationInputs, schedule: observation.ObservedSchedule) -> bool:
    if inputs.schedule_state == "on":
        return schedule.installed and schedule.timer_enabled and schedule.status in ON_STATES
    if inputs.schedule_state == "off":
        return not schedule.installed
    return schedule.service_active


def _details(
    inputs: PreparationInputs,
    schedule: observation.ObservedSchedule,
    evidence: SchedulerEvidence,
) -> list[dict[str, str]]:
    row = _laravel_row(evidence.laravel, inputs.identifier)
    return [
        {"label": "Site", "value": inputs.identifier},
        {
            "label": "Scheduled tasks",
            "value": "Run on the server every minute" if inputs.schedule_state != "off" else "Off",
        },
        {
            "label": "Current release",
            "value": str(row.get("current", "")) if row is not None else "Not observed",
        },
        {
            "label": "Deployment",
            "value": (
                "Verified: the current release is open and migrations are recorded"
                if inputs.schedule_state != "off"
                else "Not required to turn the scheduler off"
            ),
        },
        {
            "label": "Run limit",
            "value": "One hour for each run, and a slow run delays the next one",
        },
        {"label": "Current state", "value": STATUS_SENTENCE[schedule.status]},
    ]


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, SchedulerEvidence):
        raise ValueError("A scheduler change needs native evidence.")
    gate = bool(evidence.site and evidence.site["problem"] == SITE_GATED)
    schedule = observation.schedule_for(
        evidence.automation,
        inputs.identifier,
        role=convention.ROLE_SCHEDULE,
        gate=gate,
    )
    refusals, digests = _refusals(evidence, inputs, schedule)
    unchanged = _already(inputs, schedule) and not refusals
    account = _account(evidence.site)
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": inputs.identifier,
        "state": inputs.schedule_state,
        "run_wait_seconds": RUN_NOW_WAIT_SECONDS,
        "details": _details(inputs, schedule, evidence),
    }
    if evidence.site is not None and account is not None and digests is not None:
        document.update(uid=account[0], gid=account[1], units=digests)
    elif inputs.schedule_state != "off":
        refusals.append("The site's reviewed evidence is incomplete.")
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals and not unchanged:
        effects = (
            DeclaredEffect(
                Scope.SITE,
                {
                    "on": (
                        f"Run {inputs.identifier}'s Laravel schedule on the server every "
                        "minute as its own account."
                    ),
                    "off": f"Stop running {inputs.identifier}'s Laravel schedule on the server.",
                    "run": (f"Run {inputs.identifier}'s Laravel schedule once now, on the server."),
                }[inputs.schedule_state],
                (inputs.identifier,),
            ),
        )
    note = ""
    if unchanged:
        note = {
            "on": "The scheduler is already on for this site.",
            "off": "The scheduler is already off for this site.",
            "run": "A scheduled run is already in progress for this site.",
        }[inputs.schedule_state]
    return ReviewDraft(
        SLUG,
        {
            "on": f"Turn on the scheduler for {inputs.identifier}.",
            "off": f"Turn off the scheduler for {inputs.identifier}.",
            "run": f"Run the scheduler now for {inputs.identifier}.",
        }[inputs.schedule_state],
        effects=effects,
        stages={
            "on": ON_STAGES,
            "off": OFF_STAGES,
            "run": RUN_STAGES,
        }[inputs.schedule_state],
        postconditions=(
            {
                "on": (
                    (
                        "The timer runs every minute as the site's own account, from the "
                        "current release and selected PHP, with no catch-up burst."
                    ),
                    "The schedule's previous units are the ones the review read.",
                ),
                "off": (
                    "The site's schedule no longer runs on the server and its units are gone.",
                ),
                "run": ("One run of the site's schedule finished on the server.",),
            }[inputs.schedule_state]
        ),
        refusals=tuple(dict.fromkeys(refusals)),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        sites_read=presence_command(inputs.identifier) if evidence.site is not None else "",
        current_sites=(inputs.identifier,) if evidence.site is not None else None,
        document={**document, "note": note} if note else document,
    )


def _document(document: dict[str, object]) -> dict[str, object]:
    identifier = str(document.get("identifier", ""))
    state = document.get("state")
    units = document.get("units")
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or convention.SITE_IDENTIFIER.fullmatch(identifier) is None
        or state not in ("on", "off", "run")
        or type(document.get("uid")) is not int
        or type(document.get("gid")) is not int
        or not isinstance(units, dict)
        or set(units) != set(KINDS)
        or not all(
            units.get(kind) == "absent" or DIGEST.fullmatch(str(units.get(kind))) is not None
            for kind in KINDS
        )
        or type(document.get("run_wait_seconds")) is not int
        or document["run_wait_seconds"] != RUN_NOW_WAIT_SECONDS
    ):
        raise ValueError("The scheduler review is not a valid immutable selection.")
    return {
        "version": 1,
        "identifier": identifier,
        "state": state,
        "uid": document["uid"],
        "gid": document["gid"],
        "units": {kind: str(units[kind]) for kind in KINDS},
        "run_wait_seconds": RUN_NOW_WAIT_SECONDS,
    }


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    payload = _document(document)
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES, (encoded,))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    document = stored.document
    identifier = str(document.get("identifier", ""))
    state = document.get("state")
    automation = observation.read(shell)
    if automation is None:
        return None
    schedule = observation.schedule_for(automation, identifier, role=convention.ROLE_SCHEDULE)
    if state == "on":
        return schedule.installed and schedule.timer_active and schedule.timer_enabled
    if state == "off":
        return not schedule.installed
    return schedule.installed and not schedule.service_active


SET_LARAVEL_SCHEDULER: Final = ChangeKind(
    SLUG,
    LABEL,
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_shape=InputShape.AUTOMATION_SCHEDULE,
)
