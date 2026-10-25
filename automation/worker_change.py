"""One Laravel site's database queue workers as a reviewed change (Phase C #266).

Start writes the retry interval through Phase B's Edit-settings path before it publishes
and starts the ``queue1`` to ``queueN`` services. Stop disables boot activation. Restart
uses ``systemctl restart`` so each process finishes its current job; it never uses
``queue:restart``, which depends on the application cache.
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
from laravel import observation as laravel_observation
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from sites import observation as site_observation
from sites.bodies.common import SITE_GATED, NativeState, SiteRecord
from sites.configuration import PHP_RUNTIMES

from . import convention, worker_observation, worker_preconditions, workers
from .worker_status import STATUS_SENTENCE

SLUG: Final = "set_laravel_queue_workers"
LABEL: Final = "Change queue workers"
ON_STAGES: Final = ("preflight", "environment", "units", "start", "verify")
RESTART_STAGES: Final = ("preflight", "environment", "restart", "verify")
STOP_STAGES: Final = ("preflight", "stop", "verify")
DIGEST: Final = re.compile(r"[0-9a-f]{64}\Z")
RELEASE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
UNIT_KEYS: Final = ("slice", *workers.WORKER_ROLES)
_IMPORTS: Final = (
    "automation.convention",
    "automation.workers",
    "automation.bodies.units",
    "automation.bodies.worker",
    "laravel.bodies.common",
    "sites.bodies.common",
)


def _without_imports(text: str) -> str:
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
        laravel_observation.LARAVEL_SOURCE,
        importlib.resources.files("automation").joinpath("convention.py").read_text(),
        _without_imports(
            importlib.resources.files("automation").joinpath("workers.py").read_text()
        ),
        _without_imports(
            importlib.resources.files("automation.bodies").joinpath("units.py").read_text()
        ),
        _without_imports(
            importlib.resources.files("automation.bodies").joinpath("worker.py").read_text()
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
class WorkerChangeEvidence:
    standing: Standing | None
    native: NativeState | None
    laravel: dict[str, object] | None
    workers: dict[str, object] | None
    preconditions: dict[str, object] | None


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> WorkerChangeEvidence:
    from discovery.observations import collect

    snapshot = collect(shell, sites=False)
    native = site_observation.read(shell, "observed", "", protections=False)
    site = _site_of(native, inputs.identifier)
    host = str(site["names"][0]) if site is not None and site["names"] else ""
    preconditions = (
        worker_preconditions.read(shell, inputs.identifier, host)
        if inputs.worker_action in ("start", "restart") and host
        else None
    )
    return WorkerChangeEvidence(
        snapshot.standing.standing if snapshot.standing else None,
        native,
        laravel_observation.read(shell),
        worker_observation.read(shell),
        preconditions,
    )


def _site_of(native: NativeState | None, identifier: str) -> SiteRecord | None:
    if native is None:
        return None
    return next((row for row in native["sites"] if row["identifier"] == identifier), None)


def _laravel_of(value: dict[str, object] | None, identifier: str) -> dict[str, object] | None:
    return laravel_observation.site(value, identifier) if value is not None else None


def _account(site: SiteRecord | None) -> tuple[int, int] | None:
    account = site["account"] if site is not None else None
    if not isinstance(account, list) or len(account) < 2:
        return None
    uid, gid = account[0], account[1]
    if type(uid) is not int or type(gid) is not int:
        return None
    return uid, gid


def _worker_row(
    evidence: WorkerChangeEvidence, inputs: PreparationInputs, site: SiteRecord | None
) -> worker_observation.ObservedWorker:
    return worker_observation.worker_for(
        evidence.workers,
        inputs.identifier,
        gate=bool(site and site["problem"] == SITE_GATED),
    )


def _unit_digests(value: dict[str, object] | None, identifier: str) -> dict[str, str] | None:
    """The reviewed preimage digests of the slice and all four possible processes."""
    if value is None:
        return None
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
    digests = dict.fromkeys(UNIT_KEYS, "absent")
    if row is None:
        return digests
    units = row.get("units")
    for unit in units if isinstance(units, list) else []:
        if not isinstance(unit, dict):
            continue
        kind, name, text = (
            str(unit.get("kind", "")),
            str(unit.get("name", "")),
            str(unit.get("text", "")),
        )
        if kind == "slice":
            digests["slice"] = convention.digest(text)
        elif kind == "service":
            role = convention.role_of(name, identifier)
            if role in workers.WORKER_ROLES:
                digests[role] = convention.digest(text)
    return digests


def _definition(
    inputs: PreparationInputs, row: worker_observation.ObservedWorker
) -> workers.WorkerDefinition | None:
    if inputs.worker_action == "start":
        try:
            return workers.parse_definition(
                ",".join(inputs.worker_queues), inputs.worker_processes, inputs.worker_timeout
            )
        except ValueError:
            return None
    return row.definition


def presence_command(identifier: str) -> str:
    return (
        "find /etc/caddy/sites -maxdepth 1 -type f -name "
        + shlex.quote(identifier + ".caddy")
        + " -printf '%f\\n' | sed 's/\\.caddy$//' | LC_ALL=C sort"
    )


def _release_problem(
    laravel: dict[str, object] | None,
) -> str:
    if laravel is None:
        return "The site's current release could not be read."
    current = str(laravel.get("current", ""))
    releases = laravel.get("releases")
    rows = releases if isinstance(releases, list) else []
    row = next(
        (entry for entry in rows if isinstance(entry, dict) and entry.get("name") == current),
        None,
    )
    if not current or row is None:
        return "The site has no current release to run background work against."
    if row.get("state") != "complete":
        return "The site's current release is not completely deployed."
    return ""


def _refusals(  # noqa: C901 - one list of every refusal
    evidence: WorkerChangeEvidence,
    inputs: PreparationInputs,
    site: SiteRecord | None,
    row: worker_observation.ObservedWorker,
    definition: workers.WorkerDefinition | None,
) -> list[str]:
    refusals: list[str] = []
    if inputs.worker_action not in ("start", "stop", "restart"):
        refusals.append("Choose whether to start, stop or restart the queue workers.")
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before changing a site.")
    if evidence.native is None:
        refusals.append("The site's native configuration could not be read.")
        return refusals
    if site is None:
        refusals.append("The site was not observed in the current server configuration.")
        return refusals
    if evidence.workers is None:
        refusals.append("The site's queue workers could not be read.")
        return refusals
    if inputs.worker_action == "stop":
        if not row.installed:
            refusals = [
                item for item in refusals if item != "The site's reviewed evidence is incomplete."
            ]
        return refusals
    laravel = _laravel_of(evidence.laravel, inputs.identifier)
    if laravel is None or laravel.get("application") != "laravel":
        refusals.append("This site is not a Laravel application.")
        return refusals
    if site["state"] != "complete" or site["application_problem"]:
        refusals.append("The site is not completely applied, so its background work is unknown.")
    if site["runtime"] not in PHP_RUNTIMES or _account(site) is None:
        refusals.append("The site's PHP runtime or Linux account is not observed.")
    if row.problem:
        refusals.append(row.problem)
    if definition is None:
        refusals.append("The queue worker definition could not be read.")
    if site["problem"] == SITE_GATED:
        refusals.append("The site's maintenance gate is up, so background work cannot start.")
    if definition is not None and inputs.worker_action == "start":
        try:
            workers.parse_definition(
                ",".join(definition.queues), definition.processes, definition.timeout
            )
        except ValueError as error:
            refusals.append(str(error))
    if laravel is not None:
        release_problem = _release_problem(laravel)
        if release_problem:
            refusals.append(release_problem)
    ready, problem = worker_preconditions.ready(evidence.preconditions)
    if not ready:
        refusals.append(problem)
    if row.duplicate:
        refusals.append(row.duplicate)
    if inputs.worker_action == "restart" and not row.installed:
        refusals.append("The queue workers are not installed yet, so start them first.")
    return refusals


def _unchanged(
    inputs: PreparationInputs,
    row: worker_observation.ObservedWorker,
    definition: workers.WorkerDefinition | None,
) -> bool:
    if inputs.worker_action == "stop":
        return not row.installed or (not row.enabled and row.active_processes == 0)
    if inputs.worker_action == "start":
        return (
            row.installed
            and row.enabled
            and row.definition == definition
            and row.active_processes == row.processes
            and not row.problem
        )
    return False


def _details(
    inputs: PreparationInputs,
    row: worker_observation.ObservedWorker,
    definition: workers.WorkerDefinition | None,
) -> list[dict[str, str]]:
    details = [
        {"label": "Site", "value": inputs.identifier},
        {"label": "Action", "value": inputs.worker_action.title()},
        {"label": "Queue connection", "value": "Database queue"},
        {"label": "Current state", "value": STATUS_SENTENCE[row.status]},
    ]
    if definition is not None:
        details.extend(
            (
                {"label": "Queues", "value": ", ".join(definition.queues)},
                {"label": "Processes", "value": str(definition.processes)},
                {"label": "Job timeout", "value": f"{definition.timeout} seconds"},
                {
                    "label": "Retry interval",
                    "value": (
                        f"{definition.retry_after} seconds, written before the workers start"
                    ),
                },
            )
        )
    details.append(
        {
            "label": "Repeated jobs",
            "value": (
                "A crash or a forced stop can leave a job to be retried, so the "
                "application's jobs must be safe to repeat. This assumes the application's "
                "queue configuration reads DB_QUEUE_RETRY_AFTER, as Laravel's default does."
            ),
        }
    )
    return details


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, WorkerChangeEvidence):
        raise ValueError("A queue-worker change needs native evidence.")
    site = _site_of(evidence.native, inputs.identifier)
    row = _worker_row(evidence, inputs, site)
    definition = _definition(inputs, row)
    refusals = _refusals(evidence, inputs, site, row, definition)
    unchanged = not refusals and _unchanged(inputs, row, definition)
    laravel = _laravel_of(evidence.laravel, inputs.identifier)
    account = _account(site)
    digests = _unit_digests(evidence.workers, inputs.identifier)
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": inputs.identifier,
        "action": inputs.worker_action,
        "details": _details(inputs, row, definition),
    }
    current = str(laravel.get("current", "")) if laravel is not None else ""
    environment_digest = str(laravel.get("environment_digest", "")) if laravel is not None else ""
    stop = inputs.worker_action == "stop"
    if (
        site is not None
        and account is not None
        and digests is not None
        and (stop or (RELEASE.fullmatch(current) and DIGEST.fullmatch(environment_digest)))
        and (definition is not None or stop)
    ):
        document.update(
            uid=account[0],
            gid=account[1],
            runtime=site["runtime"],
            https=bool(site["https"]),
            names=list(site["names"]),
            current=current,
            environment_digest=environment_digest if not stop else "",
            units=digests,
            definition=definition.document() if definition is not None else None,
        )
    else:
        refusals.append("The site's reviewed evidence is incomplete.")
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals and not unchanged:
        effects = (DeclaredEffect(Scope.SITE, _effect(inputs, definition), (inputs.identifier,)),)
    note = ""
    if unchanged:
        note = (
            "The queue workers are already stopped for this site."
            if inputs.worker_action == "stop"
            else "The queue workers are already running with these settings."
        )
    stages = {
        "start": ON_STAGES,
        "restart": RESTART_STAGES,
        "stop": STOP_STAGES,
    }.get(inputs.worker_action, ON_STAGES)
    return ReviewDraft(
        SLUG,
        f"{inputs.worker_action.title()} the queue workers of {inputs.identifier}.",
        effects=effects,
        stages=stages,
        postconditions=_postconditions(inputs.worker_action),
        refusals=tuple(dict.fromkeys(refusals)),
        boot_id=str(evidence.native["boot"]) if evidence.native is not None else "",
        uptime_centiseconds=(
            int(str(evidence.native["uptime"])) if evidence.native is not None else None
        ),
        sites_read=presence_command(inputs.identifier) if site is not None else "",
        current_sites=(inputs.identifier,) if site is not None else None,
        document={**document, "note": note} if note else document,
    )


def _effect(inputs: PreparationInputs, definition: workers.WorkerDefinition | None) -> str:
    if inputs.worker_action == "stop":
        return f"Stop {inputs.identifier}'s queue workers and keep them stopped after a reboot."
    if inputs.worker_action == "restart":
        return f"Restart {inputs.identifier}'s queue workers gracefully."
    queues = ", ".join(definition.queues) if definition is not None else ""
    processes = definition.processes if definition is not None else 0
    return (
        f"Run {inputs.identifier}'s database queue with {processes} process(es) for "
        f"{queues}, and write its retry interval before they start."
    )


def _postconditions(action: str) -> tuple[str, ...]:
    common = (
        "The retry interval is written before any worker starts.",
        "Every process runs as the site's own account from its current release.",
        (
            "A crash or a forced stop can leave a job to be retried, so the application's "
            "jobs must be safe to repeat."
        ),
    )
    if action == "stop":
        return (
            "The workers are stopped and stay stopped after a reboot.",
            *common,
        )
    if action == "restart":
        return (
            "Each process finishes its current job within its stop budget.",
            *common,
        )
    return (
        "Every reviewed process runs and returns after a reboot.",
        *common,
    )


def _document(document: dict[str, object]) -> dict[str, object]:
    action = document.get("action")
    raw_definition = document.get("definition")
    identifier = document.get("identifier")
    names = document.get("names")
    units = document.get("units")
    current = document.get("current")
    environment_digest = document.get("environment_digest")
    if action == "stop":
        definition: dict[str, object] | None = None
    else:
        definition = workers.checked_definition(raw_definition).document()
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or not isinstance(identifier, str)
        or convention.SITE_IDENTIFIER.fullmatch(identifier) is None
        or action not in ("start", "stop", "restart")
        or document.get("runtime") not in ("php84", "php85")
        or type(document.get("https")) is not bool
        or not isinstance(names, list)
        or not names
        or not all(isinstance(name, str) for name in names)
        or type(document.get("uid")) is not int
        or type(document.get("gid")) is not int
        or not isinstance(environment_digest, str)
        or (action != "stop" and DIGEST.fullmatch(environment_digest) is None)
        or not isinstance(current, str)
        or (action != "stop" and RELEASE.fullmatch(current) is None)
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
        "body_sha256": BODY_SHA256,
        "identifier": identifier,
        "action": action,
        "definition": definition,
        "runtime": document["runtime"],
        "https": document["https"],
        "names": list(names),
        "current": current,
        "uid": document["uid"],
        "gid": document["gid"],
        "environment_digest": environment_digest,
        "units": {key: str(units[key]) for key in UNIT_KEYS},
    }


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    payload = _document(document)
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES, (encoded,))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    document = stored.document
    identifier = str(document.get("identifier", ""))
    action = document.get("action")
    value = worker_observation.read(shell)
    if value is None:
        return None
    row = worker_observation.worker_for(value, identifier)
    if action == "stop":
        return row.installed and not row.enabled and row.active_processes == 0
    definition = row.definition
    raw = document.get("definition")
    if definition is None or not isinstance(raw, dict):
        return False
    return (
        definition.document() == raw
        and row.enabled
        and row.active_processes == row.processes
        and not row.problem
    )


SET_LARAVEL_QUEUE_WORKERS: Final = ChangeKind(
    SLUG,
    LABEL,
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_shape=InputShape.LARAVEL_QUEUE_WORKERS,
)
