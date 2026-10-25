"""WordPress server cron as one reviewed site change (Phase C #357, docs/automation.md).

The review reads the site, its private configuration's cron value and the automation
evidence, then declares the ordered effects. The body publishes the units, waits for one
successful run, and only then sets ``DISABLE_WP_CRON``; turning off clears the constant
before it stops the timer. Nothing is remembered in the controller.
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
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from sites import observation as site_observation
from sites.bodies.common import SITE_GATED, NativeState, SiteRecord
from sites.configuration import PHP_RUNTIMES
from wordpress import observation as wordpress_observation

from . import convention, observation
from .status import STATUS_SENTENCE, ScheduleStatus

SLUG: Final = "set_wordpress_server_cron"
LABEL: Final = "Change scheduled tasks"
KINDS: Final = ("slice", "service", "timer")
DIGEST: Final = re.compile(r"[0-9a-f]{64}\Z")
ON_STAGES: Final = ("preflight", "install", "tick", "configuration", "verify")
OFF_STAGES: Final = ("preflight", "configuration", "install", "verify")
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
_IMPORTS: Final = (
    "sites.bodies.common",
    "automation.convention",
    "automation.bodies.units",
    "wordpress.convention",
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
        importlib.resources.files("wordpress").joinpath("convention.py").read_text(),
        importlib.resources.files("automation").joinpath("convention.py").read_text(),
        _without_imports(
            importlib.resources.files("automation.bodies").joinpath("units.py").read_text()
        ),
        _without_imports(
            importlib.resources.files("automation.bodies").joinpath("schedule.py").read_text()
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
class ScheduleEvidence:
    standing: Standing | None
    native: NativeState | None
    wordpress: dict[str, object] | None
    automation: dict[str, object] | None


def inspect(shell: RemoteShell, _inputs: PreparationInputs) -> ScheduleEvidence:
    from discovery.observations import collect

    snapshot = collect(shell, sites=False)
    return ScheduleEvidence(
        snapshot.standing.standing if snapshot.standing else None,
        site_observation.read(shell, "observed", "", protections=False),
        wordpress_observation.read(shell),
        observation.read(shell),
    )


def _site_of(native: NativeState | None, identifier: str) -> SiteRecord | None:
    if native is None:
        return None
    return next((row for row in native["sites"] if row["identifier"] == identifier), None)


def _account(site: SiteRecord | None) -> tuple[int, int] | None:
    account = site["account"] if site is not None else None
    if not isinstance(account, list) or len(account) < 2:
        return None
    uid, gid = account[0], account[1]
    if type(uid) is not int or type(gid) is not int:
        return None
    return uid, gid


def _private_row(wordpress: dict[str, object] | None, identifier: str) -> dict[str, object] | None:
    return wordpress_observation.site(wordpress, identifier) if wordpress else None


def _cron_value(row: dict[str, object] | None) -> str:
    cron = row.get("cron") if row is not None else None
    disable = cron.get("disable") if isinstance(cron, dict) else ""
    return str(disable) if disable in ("true", "false") else ""


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
        shape = convention.parse_unit(name, text, identifier, convention.ROLE_WPCRON, kind)
        if not shape.supported:
            problems.append(shape.problem)
            continue
        if digests[kind] != "absent":
            problems.append("The background task files are duplicated.")
            continue
        digests[kind] = convention.digest(text)
    return digests, list(dict.fromkeys(problems))


def presence_command(identifier: str) -> str:
    """The one site this change names, proved by its own Caddy file."""
    return (
        "find /etc/caddy/sites -maxdepth 1 -type f -name "
        + shlex.quote(identifier + ".caddy")
        + " -printf '%f\\n' | sed 's/\\.caddy$//' | LC_ALL=C sort"
    )


def _refusals(  # noqa: C901 - one list of every refusal
    evidence: ScheduleEvidence, inputs: PreparationInputs
) -> tuple[list[str], SiteRecord | None, dict[str, object] | None, dict[str, str] | None]:
    refusals: list[str] = []
    if inputs.schedule_state not in ("on", "off"):
        refusals.append("Choose whether to turn server cron on or off.")
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before changing a site.")
    if evidence.native is None:
        refusals.append("The site's native configuration could not be read.")
        return refusals, None, None, None
    site = _site_of(evidence.native, inputs.identifier)
    if site is None:
        refusals.append("The site was not observed in the current server configuration.")
        return refusals, None, None, None
    if site["application"] != "wordpress":
        refusals.append("This site is not a WordPress application.")
    if site["state"] != "complete" or site["application_problem"] or site["problem"] == SITE_GATED:
        refusals.append("WordPress is not installed completely and verified on this site.")
    if site["runtime"] not in PHP_RUNTIMES or _account(site) is None:
        refusals.append("The site's PHP runtime or Linux account is not observed.")
    row = _private_row(evidence.wordpress, inputs.identifier)
    if row is None:
        refusals.append("The private WordPress configuration could not be read.")
    if evidence.automation is None:
        refusals.append("The site's scheduled tasks could not be read.")
    digests, problems = _unit_digests(evidence.automation, inputs.identifier)
    refusals.extend(problems)
    schedule = observation.schedule_for(
        evidence.automation,
        inputs.identifier,
        disable_wp_cron=_cron_value(row),
        gate=site["problem"] == SITE_GATED,
    )
    if inputs.schedule_state == "on" and schedule.duplicate:
        refusals.append(schedule.duplicate)
    return refusals, site, row, digests


def _already(
    inputs: PreparationInputs, schedule: observation.ObservedSchedule, site: SiteRecord | None
) -> bool:
    if site is None:
        return False
    on = schedule.disable_wp_cron == "true" and schedule.status in ON_STATES
    off = not schedule.installed and schedule.disable_wp_cron != "true"
    return on if inputs.schedule_state == "on" else off


def _details(
    inputs: PreparationInputs, schedule: observation.ObservedSchedule
) -> list[dict[str, str]]:
    return [
        {"label": "Site", "value": inputs.identifier},
        {"label": "WordPress", "value": "Installed and verified"},
        {
            "label": "Scheduled tasks",
            "value": "Run on the server every minute" if inputs.schedule_state == "on" else "Off",
        },
        {
            "label": "Page-load cron",
            "value": (
                "Turned off after one successful run"
                if inputs.schedule_state == "on"
                else "Turned back on before the server task stops"
            ),
        },
        {"label": "Current state", "value": STATUS_SENTENCE[schedule.status]},
    ]


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, ScheduleEvidence):
        raise ValueError("A scheduled-tasks change needs native evidence.")
    refusals, site, row, digests = _refusals(evidence, inputs)
    schedule = observation.schedule_for(
        evidence.automation,
        inputs.identifier,
        disable_wp_cron=_cron_value(row),
        gate=bool(site and site["problem"] == SITE_GATED),
    )
    unchanged = _already(inputs, schedule, site) and not refusals
    account = _account(site)
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": inputs.identifier,
        "state": inputs.schedule_state,
        "tick_budget_seconds": convention.TICK_BUDGET_SECONDS,
        "details": _details(inputs, schedule),
    }
    if site is not None and row is not None and account is not None and digests is not None:
        document.update(
            uid=account[0],
            gid=account[1],
            configuration_digest=str(row["digest"]),
            units=digests,
        )
    else:
        refusals.append("The site's reviewed evidence is incomplete.")
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals and not unchanged:
        effects = (
            DeclaredEffect(
                Scope.SITE,
                (
                    f"Run {inputs.identifier}'s scheduled WordPress events on the server every "
                    "minute, and stop page loads from running them."
                    if inputs.schedule_state == "on"
                    else f"Give {inputs.identifier}'s scheduled WordPress events back to page "
                    "loads and stop the server task."
                ),
                (inputs.identifier,),
            ),
        )
    note = ""
    if unchanged:
        note = (
            "Server cron is already on for this site."
            if inputs.schedule_state == "on"
            else "Server cron is already off for this site."
        )
    return ReviewDraft(
        SLUG,
        (
            f"Turn on server cron for {inputs.identifier}."
            if inputs.schedule_state == "on"
            else f"Turn off server cron for {inputs.identifier}."
        ),
        effects=effects,
        stages=ON_STAGES if inputs.schedule_state == "on" else OFF_STAGES,
        postconditions=(
            (
                "One run succeeds on the server before page loads stop running cron."
                if inputs.schedule_state == "on"
                else "Page loads run cron again before the server task stops."
            ),
            "The site's private configuration keeps its fixed lines and stays a site-owned file.",
            "The timer runs every minute as the site's own account, with no catch-up burst.",
        ),
        refusals=tuple(dict.fromkeys(refusals)),
        boot_id=evidence.native["boot"] if evidence.native is not None else "",
        uptime_centiseconds=(
            int(str(evidence.native["uptime"])) if evidence.native is not None else None
        ),
        sites_read=presence_command(inputs.identifier) if site is not None else "",
        current_sites=(inputs.identifier,) if site is not None else None,
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
        or state not in ("on", "off")
        or type(document.get("uid")) is not int
        or type(document.get("gid")) is not int
        or not isinstance(document.get("configuration_digest"), str)
        or DIGEST.fullmatch(str(document["configuration_digest"])) is None
        or not isinstance(units, dict)
        or set(units) != set(KINDS)
        or not all(
            units.get(kind) == "absent" or DIGEST.fullmatch(str(units.get(kind))) is not None
            for kind in KINDS
        )
        or type(document.get("tick_budget_seconds")) is not int
        or document["tick_budget_seconds"] != convention.TICK_BUDGET_SECONDS
    ):
        raise ValueError("The scheduled-tasks review is not a valid immutable selection.")
    return {
        "version": 1,
        "identifier": identifier,
        "state": state,
        "uid": document["uid"],
        "gid": document["gid"],
        "configuration_digest": document["configuration_digest"],
        "units": {kind: str(units[kind]) for kind in KINDS},
        "tick_budget_seconds": convention.TICK_BUDGET_SECONDS,
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
    wordpress = wordpress_observation.read(shell)
    if automation is None or wordpress is None:
        return None
    row = _private_row(wordpress, identifier)
    if row is None:
        return False
    schedule = observation.schedule_for(automation, identifier, disable_wp_cron=_cron_value(row))
    if state == "on":
        return (
            schedule.status in ON_STATES
            and schedule.timer_active
            and schedule.timer_enabled
            and schedule.disable_wp_cron == "true"
        )
    return not schedule.installed and schedule.disable_wp_cron != "true"


SET_WORDPRESS_SERVER_CRON: Final = ChangeKind(
    SLUG,
    LABEL,
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_shape=InputShape.AUTOMATION_SCHEDULE,
)
