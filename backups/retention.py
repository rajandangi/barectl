"""Retention policy and keeping one recovery point (Phase D #404).

**Keep backups for** is one reviewed Destructive change that runs ``restic forget --dry-run
--json`` against fresh onsite and offsite listings and lists every point it would delete now.
Applying it installs the site's fixed cleanup units and deletes nothing itself. Cleanup runs
daily onsite and weekly offsite, requires a synchronized clock, restore-reads the newest
complete point in each scope before forgetting, and filters every command by Barectl's own
tags (docs/adr/0031, Phase D #358 and #404).

**Keep** toggles one recovery point's ``keep`` tag through a Site change. It never deletes a
snapshot and never touches a tag other than ``keep``.
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import re
import shlex
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from django.utils import timezone as django_timezone

from automation.bodies.source import AUTOMATION_SOURCE, without_imports
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from servers.models import Server
from sites import observation as site_observation

from . import change, check, convention
from .bodies import retention as retention_body
from .observation import OffsiteStorage

SET_SLUG: Final = "set_backup_retention"
SET_LABEL: Final = "Set retention"
DISABLE_SLUG: Final = "disable_backup_retention"
DISABLE_LABEL: Final = "Disable retention"
KEEP_SLUG: Final = "keep_recovery_point"
KEEP_LABEL: Final = "Keep recovery point"
SET_STAGES: Final = ("preflight", "install", "verify")
DISABLE_STAGES: Final = ("preflight", "install", "verify")
KEEP_STAGES: Final = ("preflight", "tag", "verify")
PERIOD_LABELS: Final = {
    7: "1 week",
    14: "2 weeks",
    21: "3 weeks",
    30: "1 month",
    182: "6 months",
}
DAYS: Final = retention_body.DAYS
DELETION_PERMANENT: Final = (
    "Deletion is permanent. A recovery point this policy expires cannot be restored later."
)
NEWEST_KEPT: Final = (
    "The newest readable point in each scope and each location is always kept, even when the "
    "schedule has stopped."
)
CLEANUP_SKIPPED: Final = (
    "Cleanup waits while the server's clock is not synchronized, so a wrong clock cannot make "
    "every backup look old."
)
NOTHING_DELETED: Final = "Nothing is old enough to be deleted now."
RETENTION_CORE: Final = without_imports(
    importlib.resources.files("backups.bodies").joinpath("retention.py").read_text(),
    ("automation.bodies.units", "backups.bodies.native"),
)
RETENTION_SOURCE: Final = (
    site_observation.COMMON_SOURCE
    + "\n"
    + AUTOMATION_SOURCE
    + "\n"
    + change.NATIVE_SOURCE
    + "\n"
    + RETENTION_CORE
)
RETENTION_BYTES: Final = change._packed(RETENTION_SOURCE, script_path=True)
RETENTION_BODY_SHA256: Final = hashlib.sha256(RETENTION_BYTES).hexdigest()
KEEP_CORE: Final = without_imports(
    importlib.resources.files("backups.bodies").joinpath("retention.py").read_text(),
    ("automation.bodies.units", "backups.bodies.native"),
)
KEEP_SOURCE: Final = change.NATIVE_SOURCE + "\n" + KEEP_CORE
KEEP_BYTES: Final = change._packed(KEEP_SOURCE)
KEEP_SHA256: Final = hashlib.sha256(KEEP_BYTES).hexdigest()
POINT_LIMIT: Final = 200
SNAPSHOT: Final = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class RetentionPolicy:
    """A site's reviewed cleanup policy, read from its units and payload."""

    installed: bool = False
    days: int = 0
    offsite: bool = False
    problem: str = ""
    texts: dict[str, str | None] | None = None


@dataclass(frozen=True)
class LocationSurvey:
    """What one location's fresh listing says a reviewed policy would delete now."""

    deletions: tuple[dict[str, object], ...] = ()
    foreign: int = 0
    problem: str = ""


@dataclass(frozen=True)
class RetentionEvidence:
    """One site's policy, clock and dry-run effect, from fresh native reads."""

    base: change.BackupEvidence
    policy: RetentionPolicy
    clock: bool
    onsite: LocationSurvey
    offsite: LocationSurvey


@dataclass(frozen=True)
class KeepEvidence:
    """One recovery point's current keep state, from the onsite repository."""

    base: change.BackupEvidence
    point: dict[str, object] | None
    snapshots: tuple[str, ...]
    keep: bool


def period_label(days: int) -> str:
    return PERIOD_LABELS.get(days, f"{days} days")


def unit_key_paths(identifier: str) -> dict[str, str]:
    return {
        "slice": retention_body.slice_path(identifier),
        "cleanup.service": retention_body.unit_path(
            identifier, retention_body.ROLE_ONSITE, "service"
        ),
        "cleanup.timer": retention_body.unit_path(identifier, retention_body.ROLE_ONSITE, "timer"),
        "cleanupoffsite.service": retention_body.unit_path(
            identifier, retention_body.ROLE_OFFSITE, "service"
        ),
        "cleanupoffsite.timer": retention_body.unit_path(
            identifier, retention_body.ROLE_OFFSITE, "timer"
        ),
    }


def unit_read_command(identifier: str) -> str:
    paths = [
        retention_body.slice_path(identifier),
        *(
            retention_body.unit_path(identifier, role, kind)
            for role in (retention_body.ROLE_ONSITE, retention_body.ROLE_OFFSITE)
            for kind in retention_body.KINDS
        ),
        retention_body.script_path(identifier),
        retention_body.payload_path(identifier),
    ]
    steps = []
    script = retention_body.script_path(identifier)
    for path in paths:
        quoted = shlex.quote(path)
        steps.append(f"printf 'barectl-file %s\\n' {quoted}")
        if path == script:
            # The packed body is larger than the SSH answer bound; its presence is enough.
            steps.append(
                f"if [ -f {quoted} ]; then printf 'cHJlc2VudA==\\n'; else printf -- '-\\n'; fi"
            )
        else:
            steps.append(
                f"if [ -f {quoted} ]; then base64 -w0 {quoted}; "
                "printf '\\n'; else printf -- '-\\n'; fi"
            )
    return "sh -c " + shlex.quote("; ".join(steps))


def clock_command() -> str:
    return "/usr/bin/timedatectl show --property=NTPSynchronized --value"


def read_clock(shell: RemoteShell) -> bool:
    result = run_root(shell, clock_command())
    return result.exit_status == 0 and not result.truncated and result.stdout.strip() == "yes"


def _files(text: str) -> list[str | None] | None:
    lines = text.splitlines()
    if len(lines) % 2:
        return None
    values: list[str | None] = []
    for index in range(0, len(lines), 2):
        if not lines[index].startswith("barectl-file "):
            return None
        value = lines[index + 1].strip()
        if value == "-":
            values.append(None)
            continue
        try:
            values.append(base64.b64decode(value, validate=True).decode("utf-8"))
        except ValueError:
            return None
    return values


def parse_policy(text: str, identifier: str) -> RetentionPolicy:
    values = _files(text)
    paths = [
        retention_body.slice_path(identifier),
        *(
            retention_body.unit_path(identifier, role, kind)
            for role in (retention_body.ROLE_ONSITE, retention_body.ROLE_OFFSITE)
            for kind in retention_body.KINDS
        ),
        retention_body.script_path(identifier),
        retention_body.payload_path(identifier),
    ]
    if values is None or len(values) != len(paths):
        return RetentionPolicy(problem="The retention policy could not be read.")
    keys = list(unit_key_paths(identifier))
    texts = {
        **{key: values[index] for index, key in enumerate(keys)},
        "script": values[-2],
        "payload": values[-1],
    }
    expected = retention_body.unit_texts(identifier)
    ours = [key for key in keys if key != "slice" and texts[key] is not None]
    if not ours:
        if any(texts[key] is not None for key in ("script", "payload")):
            return RetentionPolicy(
                problem="The retention policy is outside supported settings.", texts=texts
            )
        return RetentionPolicy(texts=texts)
    if len(ours) != len(keys) - 1 or texts["slice"] is None:
        return RetentionPolicy(
            problem="The retention policy is outside supported settings.", texts=texts
        )
    if any(texts[key] != expected[key] for key in keys):
        return RetentionPolicy(
            problem="The retention policy was changed outside Barectl.", texts=texts
        )
    if texts["script"] is None or texts["payload"] is None:
        return RetentionPolicy(
            problem="The retention policy is outside supported settings.", texts=texts
        )
    try:
        payload = json.loads(str(texts["payload"]))
    except ValueError:
        return RetentionPolicy(
            problem="The retention policy is outside supported settings.", texts=texts
        )
    if (
        not isinstance(payload, dict)
        or payload.get("version") != 1
        or payload.get("identifier") != identifier
        or type(payload.get("days")) is not int
        or payload.get("days") not in DAYS
        or payload.get("repository") != convention.repository(identifier)
        or payload.get("server_key") != convention.server_key(identifier)
    ):
        return RetentionPolicy(
            problem="The retention policy is outside supported settings.", texts=texts
        )
    return RetentionPolicy(
        installed=True,
        days=int(str(payload["days"])),
        offsite=texts["cleanupoffsite.service"] is not None
        and texts["cleanupoffsite.timer"] is not None,
        texts=texts,
    )


def read_policy(shell: RemoteShell, identifier: str) -> RetentionPolicy:
    result = run_root(shell, unit_read_command(identifier))
    if result.exit_status or result.truncated:
        return RetentionPolicy(problem="The retention policy could not be read.")
    return parse_policy(result.stdout, identifier)


def _inventory(  # noqa: C901 - one strict listing parser
    text: str,
) -> tuple[dict[str, dict[str, object]], int] | None:
    try:
        rows = json.loads(text)
    except ValueError:
        return None
    if not isinstance(rows, list):
        return None
    points: dict[str, dict[str, object]] = {}
    foreign = 0
    for row in rows:
        if not isinstance(row, dict):
            foreign += 1
            continue
        tags = row.get("tags")
        snapshot = row.get("id")
        if (
            not isinstance(tags, list)
            or len(tags) > 16
            or not all(isinstance(tag, str) for tag in tags)
            or not isinstance(snapshot, str)
            or check.POINT.fullmatch(next((t[6:] for t in tags if t.startswith("point:")), ""))
            is None
        ):
            foreign += 1
            continue
        if convention.MARKER not in tags:
            foreign += 1
            continue
        point = next(tag[6:] for tag in tags if tag.startswith("point:"))
        scope = next((tag[6:] for tag in tags if tag.startswith("scope:")), "")
        part = next((tag[5:] for tag in tags if tag.startswith("part:")), "")
        moment = row.get("time")
        if (
            scope not in convention.SCOPES
            or part not in convention.PARTS
            or not isinstance(moment, str)
        ):
            foreign += 1
            continue
        entry = points.setdefault(
            point,
            {"point": point, "scope": scope, "time": moment, "parts": set(), "keep": False},
        )
        if "complete" in tags:
            parts = entry["parts"]
            if isinstance(parts, set):
                parts.add(part)
        if "keep" in tags:
            entry["keep"] = True
    return points, foreign


def _complete_points(points: dict[str, dict[str, object]], scope: str) -> list[dict[str, object]]:
    expected = set(convention.expected_parts(scope))
    return [
        point
        for point in points.values()
        if point["scope"] == scope
        and isinstance(point["parts"], set)
        and point["parts"] == expected
    ]


def _forget_points(text: str) -> set[str]:
    try:
        value = json.loads(text)
    except ValueError:
        return set()
    found: set[str] = set()
    for group in value if isinstance(value, list) else []:
        if not isinstance(group, dict) or not isinstance(group.get("remove"), list):
            continue
        for row in group["remove"]:
            if not isinstance(row, dict) or not isinstance(row.get("tags"), list):
                continue
            point = next(
                (
                    tag[6:]
                    for tag in row["tags"]
                    if isinstance(tag, str) and tag.startswith("point:")
                ),
                "",
            )
            if check.POINT.fullmatch(point) is not None:
                found.add(point)
    return found


def forget_argv(days: int, scope: str, part: str, *, dry_run: bool = False) -> list[str]:
    argv = [
        "forget",
        "--json",
        "--group-by",
        "",
        "--tag",
        ",".join((convention.MARKER, "complete", f"scope:{scope}", f"part:{part}")),
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


def _offsite_plan(storage: OffsiteStorage | None, identifier: str) -> dict[str, object] | None:
    from . import offsite

    plan = offsite.capture_plan(identifier, storage)
    if plan is None:
        return None
    return {**plan, "prune_env": convention.OFFSITE_PRUNE}


def onsite_command(identifier: str, *arguments: str) -> str:
    return shlex.join(
        [
            "/usr/bin/env",
            f"RESTIC_REPOSITORY={convention.repository(identifier)}",
            f"RESTIC_PASSWORD_FILE={convention.server_key(identifier)}",
            f"RESTIC_CACHE_DIR={convention.CACHE_DIR}",
            convention.RESTIC_BIN,
            *arguments,
        ]
    )


def offsite_command(plan: dict[str, object] | None, identifier: str, *arguments: str) -> str:
    if plan is None:
        raise ValueError("The offsite cleanup is not the reviewed one.")
    storage = plan.get("storage")
    if not isinstance(storage, dict):
        raise ValueError("The offsite cleanup is not the reviewed one.")
    return convention.offsite_restic_command(
        identifier,
        {str(key): str(value) for key, value in storage.items()},
        *arguments,
        env_paths=(convention.OFFSITE_PRUNE, convention.OFFSITE_CAPTURE),
    )


def _location_command(
    plan: dict[str, object] | None, identifier: str, offsite: bool, arguments: list[str]
) -> str:
    return (
        offsite_command(plan, identifier, *arguments)
        if offsite
        else onsite_command(identifier, *arguments)
    )


def survey(
    shell: RemoteShell,
    identifier: str,
    plan: dict[str, object] | None,
    days: int,
    *,
    offsite: bool = False,
) -> LocationSurvey:
    result = run_root(
        shell,
        _location_command(plan, identifier, offsite, ["snapshots", "--json", "--no-lock"]),
    )
    if result.exit_status or result.truncated:
        return LocationSurvey(problem="The recovery points could not be read.")
    inventory = _inventory(result.stdout)
    if inventory is None:
        return LocationSurvey(problem="The recovery points could not be read.")
    points, foreign = inventory
    deletions: list[dict[str, object]] = []
    problem = ""
    for scope in convention.SCOPES:
        if not _complete_points(points, scope):
            continue
        for part in convention.expected_parts(scope):
            dry = run_root(
                shell,
                _location_command(
                    plan,
                    identifier,
                    offsite,
                    forget_argv(days, scope, part, dry_run=True),
                ),
            )
            if dry.exit_status or dry.truncated:
                problem = "The retention policy's effect could not be read."
                continue
            for point_id in _forget_points(dry.stdout):
                point = points.get(point_id)
                if point is None:
                    continue
                deletions.append(
                    {
                        "location": "offsite" if offsite else "onsite",
                        "scope": scope,
                        "point": point_id,
                        "time": point["time"],
                    }
                )
    unique = {str(item["point"]): item for item in deletions}
    return LocationSurvey(
        tuple(sorted(unique.values(), key=lambda item: str(item["time"]), reverse=True)),
        foreign,
        problem,
    )


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> RetentionEvidence:
    base = change.inspect(shell, inputs)
    policy = read_policy(shell, inputs.identifier)
    clock = read_clock(shell)
    empty = LocationSurvey()
    enabled = base.backup is not None and base.backup.enabled and inputs.days in DAYS
    onsite = survey(shell, inputs.identifier, None, inputs.days) if enabled else empty
    plan = _offsite_plan(base.offsite, inputs.identifier)
    offsite = (
        survey(shell, inputs.identifier, plan, inputs.days, offsite=True)
        if enabled and plan is not None
        else empty
    )
    return RetentionEvidence(base, policy, clock, onsite, offsite)


def inspect_keep(shell: RemoteShell, inputs: PreparationInputs) -> KeepEvidence:
    base = change.inspect(shell, inputs)
    point, snapshots, keep = _read_keep(shell, inputs.identifier, inputs.point)
    return KeepEvidence(base, point, snapshots, keep)


def keep_listing_command(identifier: str, point: str) -> str:
    return onsite_command(
        identifier, "snapshots", "--json", "--no-lock", "--tag", convention.POINT_TAG + point
    )


def _read_keep(
    shell: RemoteShell, identifier: str, point: str
) -> tuple[dict[str, object] | None, tuple[str, ...], bool]:
    result = run_root(shell, keep_listing_command(identifier, point))
    if result.exit_status or result.truncated:
        return None, (), False
    try:
        rows = json.loads(result.stdout)
    except ValueError:
        return None, (), False
    if not isinstance(rows, list):
        return None, (), False
    snapshots: list[str] = []
    moment = ""
    scope = ""
    complete = False
    keep = False
    for row in rows:
        if not isinstance(row, dict):
            continue
        tags = row.get("tags")
        snapshot = row.get("id")
        if not isinstance(tags, list) or not isinstance(snapshot, str):
            continue
        values = [tag for tag in tags if isinstance(tag, str)]
        if convention.MARKER not in values or convention.POINT_TAG + point not in values:
            continue
        snapshots.append(snapshot)
        moment = str(row.get("time", moment))
        scope = next((tag[6:] for tag in values if tag.startswith("scope:")), scope)
        complete = complete or "complete" in values
        keep = keep or "keep" in values
    if not snapshots or not complete:
        return None, (), False
    return (
        {"point": point, "time": moment, "scope": scope},
        tuple(snapshots),
        keep,
    )


def _refusals(evidence: RetentionEvidence) -> list[str]:
    refusals = [
        *change._platform_refusals(evidence.base),
        *change._profile_refusals(evidence.base),
    ]
    if evidence.base.site is None or str(evidence.base.site.get("state", "")) != "complete":
        refusals.append("The site is not complete, so its retention cannot change.")
    if evidence.base.backup is None or not evidence.base.backup.enabled:
        refusals.append("Enable backups for this site first.")
    if evidence.policy.problem:
        refusals.append(evidence.policy.problem)
    if evidence.base.offsite is not None and evidence.base.offsite.problem:
        refusals.append(evidence.base.offsite.problem)
    if evidence.onsite.problem:
        refusals.append(evidence.onsite.problem)
    if evidence.offsite.problem:
        refusals.append(evidence.offsite.problem)
    return refusals


def _deletion_rows(evidence: RetentionEvidence) -> list[dict[str, object]]:
    rows = [*evidence.onsite.deletions, *evidence.offsite.deletions]
    return sorted(rows, key=lambda row: str(row["time"]), reverse=True)[:POINT_LIMIT]


def _when(value: object) -> str:
    if not isinstance(value, str):
        return "time not recorded"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return "time not recorded"
    return django_timezone.localtime(parsed).strftime("%-d %b %Y, %H:%M")


def _deletion_detail(rows: list[dict[str, object]]) -> str:
    if not rows:
        return NOTHING_DELETED
    listed = "; ".join(
        f"{_when(row['time'])}, {row['scope']} ({row['location']})" for row in rows[:6]
    )
    more = "" if len(rows) <= 6 else f", and {len(rows) - 6} more"
    return f"{len(rows)} recovery points would be deleted now: {listed}{more}."


def _policy_document(
    evidence: RetentionEvidence, inputs: PreparationInputs, days: int
) -> dict[str, object]:
    texts = evidence.policy.texts or {}
    units = {
        key: retention_body.digest(texts.get(key)) for key in unit_key_paths(inputs.identifier)
    }
    return {
        "version": 1,
        "body_sha256": RETENTION_BODY_SHA256,
        "action": "set",
        "identifier": inputs.identifier,
        "days": days,
        "units": units,
        "repository": convention.repository(inputs.identifier),
        "server_key": convention.server_key(inputs.identifier),
        "filename": convention.dump_filename(inputs.identifier),
        "offsite": _offsite_plan(evidence.base.offsite, inputs.identifier),
        "at": change.schedule_time(),
        "stages": list(SET_STAGES),
    }


def review_set(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, RetentionEvidence):
        raise ValueError("Setting retention needs native evidence.")
    if inputs.days not in DAYS:
        raise ValueError("Not a reviewed retention period.")
    refusals = _refusals(evidence)
    rows = _deletion_rows(evidence)
    same = not refusals and evidence.policy.installed and evidence.policy.days == inputs.days
    details = [
        {"label": "Keep backups for", "value": period_label(inputs.days)},
        {
            "label": "Cleanup",
            "value": "Daily on this server; weekly for offsite storage.",
        },
        {"label": "Would be deleted now", "value": _deletion_detail(rows)},
        {"label": "Deletion is permanent", "value": DELETION_PERMANENT},
        {"label": "Newest point", "value": NEWEST_KEPT},
        {
            "label": "Server clock",
            "value": "Synchronized." if evidence.clock else CLEANUP_SKIPPED,
        },
        {
            "label": "Untouched points",
            "value": (
                f"{evidence.onsite.foreign + evidence.offsite.foreign} snapshots not made by "
                "Barectl were found. They are reported and never deleted."
                if evidence.onsite.foreign or evidence.offsite.foreign
                else "Only Barectl's own complete recovery points are considered."
            ),
        },
        {
            "label": "Offsite",
            "value": (
                "Onsite and offsite copies are cleaned independently."
                if evidence.base.offsite is not None
                else "Offsite storage is not set up; only the copies on this server are cleaned."
            ),
        },
    ]
    document = {
        **_policy_document(evidence, inputs, inputs.days),
        "details": details,
        "deletions": rows,
        "foreign": evidence.onsite.foreign + evidence.offsite.foreign,
        "confirmation": inputs.identifier,
        "confirmation_label": f"Type {inputs.identifier} to confirm this retention policy.",
        "note": (
            "Applying this policy installs the cleanup units and deletes nothing now. Cleanup "
            "checks the newest point in each location before it forgets anything."
        ),
    }
    effects: tuple[DeclaredEffect, ...] = ()
    if same:
        document["note"] = "This retention policy is already set. Nothing will change."
    elif not refusals:
        effects = (
            DeclaredEffect(
                Scope.SITE,
                (
                    f"Keep {period_label(inputs.days)} of recovery points for "
                    f"{inputs.identifier} and let cleanup permanently delete older ones."
                ),
                (inputs.identifier,),
                destroys_data=True,
            ),
        )
    return ReviewDraft(
        kind=SET_SLUG,
        intent=f"Set how long backups are kept for {inputs.identifier}.",
        effects=effects,
        stages=SET_STAGES if effects else (),
        postconditions=(
            "The cleanup units are installed and enabled on the server.",
            NEWEST_KEPT,
            "Applying this review deletes no recovery point.",
        )
        if effects
        else (),
        refusals=tuple(refusals),
        boot_id=evidence.base.boot_id,
        uptime_centiseconds=evidence.base.uptime_centiseconds,
        sites_read=change.sites_read(inputs.identifier) if effects else "",
        current_sites=(inputs.identifier,) if effects else None,
        document=document,
    )


def review_disable(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, RetentionEvidence):
        raise ValueError("Disabling retention needs native evidence.")
    refusals = _refusals(evidence)
    texts = evidence.policy.texts or {}
    document = {
        "version": 1,
        "body_sha256": RETENTION_BODY_SHA256,
        "action": "disable",
        "identifier": inputs.identifier,
        "days": 0,
        "units": {
            key: retention_body.digest(texts.get(key)) for key in unit_key_paths(inputs.identifier)
        },
        "repository": "",
        "server_key": "",
        "filename": "",
        "offsite": None,
        "at": change.schedule_time(),
        "stages": list(DISABLE_STAGES),
        "details": [
            {"label": "Keep backups for", "value": "No retention policy"},
            {
                "label": "Effect",
                "value": "The cleanup units stop running. No recovery point is deleted.",
            },
        ],
        "confirmation": inputs.identifier,
        "confirmation_label": f"Type {inputs.identifier} to turn retention off.",
        "note": "Turning retention off deletes no recovery point.",
    }
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals and evidence.policy.installed:
        effects = (
            DeclaredEffect(
                Scope.SITE,
                f"Stop the backup cleanup units for {inputs.identifier}.",
                (inputs.identifier,),
            ),
        )
    return ReviewDraft(
        kind=DISABLE_SLUG,
        intent=f"Turn off backup retention for {inputs.identifier}.",
        effects=effects,
        stages=DISABLE_STAGES if effects else (),
        postconditions=(
            "The cleanup units are gone from the server.",
            "Every recovery point on the server and offsite is unchanged.",
        )
        if effects
        else (),
        refusals=tuple(refusals),
        boot_id=evidence.base.boot_id,
        uptime_centiseconds=evidence.base.uptime_centiseconds,
        sites_read=change.sites_read(inputs.identifier) if effects else "",
        current_sites=(inputs.identifier,) if effects else None,
        document=document,
    )


def review_keep(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, KeepEvidence):
        raise ValueError("Keeping a recovery point needs native evidence.")
    refusals = [
        *change._platform_refusals(evidence.base),
        *change._profile_refusals(evidence.base),
    ]
    if evidence.base.backup is None or not evidence.base.backup.enabled:
        refusals.append("Enable backups for this site first.")
    if evidence.point is None:
        refusals.append("That recovery point is no longer listed. Check backups and choose again.")
    action = "remove" if evidence.keep else "add"
    label = "Keep" if action == "add" else "Stop keeping"
    scope_label = (
        "Full site"
        if evidence.point is not None and evidence.point.get("scope") == "full"
        else "Database only"
    )
    taken = _when(evidence.point.get("time") if evidence.point else "")
    kept_detail = "Yes. This point is protected from cleanup." if evidence.keep else "No."
    document = {
        "version": 1,
        "kind": "keep",
        "body_sha256": KEEP_SHA256,
        "identifier": inputs.identifier,
        "point": inputs.point,
        "action": action,
        "snapshots": list(evidence.snapshots),
        "repository": convention.repository(inputs.identifier),
        "server_key": convention.server_key(inputs.identifier),
        "details": [
            {
                "label": "Recovery point",
                "value": f"{scope_label}, taken {taken}.",
            },
            {"label": "Kept", "value": kept_detail},
        ],
        "note": (
            "Keeping a point changes only its keep tag. It never deletes a snapshot and never "
            "changes another tag."
        ),
    }
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals:
        effects = (
            DeclaredEffect(
                Scope.SITE,
                f"{label} one recovery point of {inputs.identifier}.",
                (inputs.identifier,),
            ),
        )
    return ReviewDraft(
        kind=KEEP_SLUG,
        intent=f"{label} a recovery point of {inputs.identifier}.",
        effects=effects,
        stages=KEEP_STAGES if effects else (),
        postconditions=(
            (
                "The recovery point carries the keep tag."
                if action == "add"
                else "The recovery point no longer carries the keep tag."
            ),
            "Retention never removes a point that is kept.",
        )
        if effects
        else (),
        refusals=tuple(refusals),
        boot_id=evidence.base.boot_id,
        uptime_centiseconds=evidence.base.uptime_centiseconds,
        sites_read=change.sites_read(inputs.identifier) if effects else "",
        current_sites=(inputs.identifier,) if effects else None,
        document=document,
    )


def _retention_document(document: dict[str, object], action: str) -> None:
    if (
        document.get("version") != 1
        or document.get("body_sha256") != RETENTION_BODY_SHA256
        or document.get("action") != action
    ):
        raise ValueError("Unsupported retention review.")
    if action == "set":
        if document.get("days") not in DAYS:
            raise ValueError("The retention review is not a reviewed period.")
        raw = document.get("offsite")
        if raw is not None:
            from . import offsite

            if (
                not isinstance(raw, dict)
                or raw.get("prune_env") != convention.OFFSITE_PRUNE
                or offsite.validate_capture(
                    {key: value for key, value in raw.items() if key != "prune_env"}
                )
                is None
            ):
                raise ValueError("The retention offsite location is not the reviewed one.")
    if action == "disable" and document.get("days") != 0:
        raise ValueError("Disabling retention has no period.")


def _keep_document(document: dict[str, object]) -> None:
    if (
        document.get("version") != 1
        or document.get("body_sha256") != KEEP_SHA256
        or document.get("kind") != "keep"
        or document.get("action") not in ("add", "remove")
    ):
        raise ValueError("Unsupported keep review.")
    snapshots = document.get("snapshots")
    if (
        not isinstance(snapshots, list)
        or not 1 <= len(snapshots) <= 16
        or not all(isinstance(item, str) and SNAPSHOT.fullmatch(item) for item in snapshots)
        or not isinstance(document.get("point"), str)
        or convention.POINT.fullmatch(str(document["point"])) is None
    ):
        raise ValueError("The keep review is not a supported point.")


def body_set(document: dict[str, object], context: BodyContext) -> NativeBody:
    _retention_document(document, "set")
    value = {
        key: document[key]
        for key in (
            "version",
            "action",
            "identifier",
            "days",
            "units",
            "repository",
            "server_key",
            "filename",
            "offsite",
            "at",
        )
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(value).encode(), mtime=0)).decode()
    return NativeBody(RETENTION_BYTES, (encoded,))


def body_disable(document: dict[str, object], context: BodyContext) -> NativeBody:
    _retention_document(document, "disable")
    value = {
        key: document[key]
        for key in (
            "version",
            "action",
            "identifier",
            "days",
            "units",
            "repository",
            "server_key",
            "filename",
            "offsite",
            "at",
        )
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(value).encode(), mtime=0)).decode()
    return NativeBody(RETENTION_BYTES, (encoded,))


def body_keep(document: dict[str, object], context: BodyContext) -> NativeBody:
    _keep_document(document)
    value = {
        key: document[key]
        for key in (
            "version",
            "kind",
            "identifier",
            "point",
            "action",
            "snapshots",
            "repository",
            "server_key",
        )
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(value).encode(), mtime=0)).decode()
    return NativeBody(KEEP_BYTES, (encoded,))


def record(server: Server, identifier: str, policy: RetentionPolicy) -> None:
    from .models import BackupRetention

    BackupRetention.objects.update_or_create(
        server=server,
        identifier=identifier,
        defaults={
            "installed": policy.installed,
            "days": policy.days if policy.installed else 0,
            "offsite": policy.offsite,
            "problem": policy.problem,
            "checked_at": django_timezone.now(),
        },
    )


def stored(server: Server, identifier: str) -> object | None:
    from .models import BackupRetention

    return BackupRetention.objects.filter(server=server, identifier=identifier).first()


def context_for_site(server: Server, identifier: str, context: dict[str, object]) -> None:
    row = stored(server, identifier)
    days = int(getattr(row, "days", 0) or 0)
    installed = bool(getattr(row, "installed", False))
    problem = str(getattr(row, "problem", "") or "")
    context["backups_retention_days"] = days if installed and not problem else 0
    context["backups_retention_label"] = (
        period_label(days) if installed and not problem else "No retention policy yet"
    )
    context["backups_retention_problem"] = problem
    context["backups_can_disable_retention"] = bool(
        context.get("backups_can_back_up_full") and installed and not problem
    )


def verify_set(shell: RemoteShell, review: ChangeReview) -> bool | None:
    body_set(review.document, BodyContext("", "", 0))
    identifier = str(review.document["identifier"])
    policy = read_policy(shell, identifier)
    if policy.problem:
        return False
    server = review.preparation.server if review.preparation is not None else None
    if server is not None:
        record(server, identifier, policy)
    return policy.installed and policy.days == int(str(review.document["days"]))


def verify_disable(shell: RemoteShell, review: ChangeReview) -> bool | None:
    body_disable(review.document, BodyContext("", "", 0))
    identifier = str(review.document["identifier"])
    policy = read_policy(shell, identifier)
    if policy.problem:
        return False
    server = review.preparation.server if review.preparation is not None else None
    if server is not None:
        record(server, identifier, policy)
    return not policy.installed


def verify_keep(shell: RemoteShell, review: ChangeReview) -> bool | None:
    body_keep(review.document, BodyContext("", "", 0))
    point, _snapshots, keep = _read_keep(
        shell, str(review.document["identifier"]), str(review.document["point"])
    )
    return None if point is None else keep == (review.document["action"] == "add")


SET: Final = ChangeKind(
    slug=SET_SLUG,
    label=SET_LABEL,
    inspect=inspect,
    review=review_set,
    body=body_set,
    verify=verify_set,
    refresh_discovery=True,
    input_shape=InputShape.BACKUP_RETENTION,
)

DISABLE: Final = ChangeKind(
    slug=DISABLE_SLUG,
    label=DISABLE_LABEL,
    inspect=inspect,
    review=review_disable,
    body=body_disable,
    verify=verify_disable,
    refresh_discovery=True,
    input_shape=InputShape.SITE,
)

KEEP: Final = ChangeKind(
    slug=KEEP_SLUG,
    label=KEEP_LABEL,
    inspect=inspect_keep,
    review=review_keep,
    body=body_keep,
    verify=verify_keep,
    refresh_discovery=True,
    input_shape=InputShape.SITE_BACKUP_POINT,
)
