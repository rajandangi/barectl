"""Deploy a Laravel site as one reviewed change (docs/adr/0019-…, Phase B #259)."""

import base64
import gzip
import hashlib
import importlib.resources
import json
import re
import secrets
import shlex
from dataclasses import dataclass
from typing import Final

from automation.bodies.source import AUTOMATION_SOURCE
from bootstrap.standing import Standing
from discovery.snapshot import CollectedSnapshot
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from runtimes.catalog import Architecture, architecture_of
from sites.bodies.common import NativeState, SiteRecord
from sites.configuration import SiteSettings, render_laravel_caddy

from . import observation
from .configuration import GATE_TEMPLATE, RETAINED_RELEASES, repository_locator, repository_ref

SLUG: Final = "deploy_laravel_site"
MIGRATION_ACKNOWLEDGEMENT: Final = (
    "I understand pending migrations may change data, that rolling back code does not "
    "reverse them, and that Barectl has no automatic backup."
)
BODY_SOURCE: Final = (
    AUTOMATION_SOURCE
    + "\n"
    + observation.LARAVEL_SOURCE
    + "\n"
    + importlib.resources.files("laravel.bodies")
    .joinpath("deploy.py")
    .read_text()
    .replace("from laravel.bodies.common import deploy\n", "")
    + "\n"
    + AUTOMATION_SOURCE
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
class DeployEvidence:
    standing: Standing | None
    architecture: Architecture | None
    disk_available: int
    boot_id: str
    uptime_centiseconds: int | None
    site: SiteRecord | None
    laravel: dict[str, object] | None
    commit: str | None
    resolved: bool
    runtime_version: str


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> DeployEvidence:
    from discovery.observations import collect
    from sites import observation as site_observation

    snapshot = collect(shell, sites=False)
    state = site_observation.read(shell, "observed", "")
    laravel = observation.read(shell)
    architecture = architecture_of(snapshot.architecture.value or "")
    disk = snapshot.filesystem.value.avail_bytes if snapshot.filesystem.value else 0
    row = None
    commit = None
    resolved = False
    site_row = _site_row(state, inputs.identifier)
    if laravel is not None:
        row = observation.site(laravel, inputs.identifier)
    if row is not None and isinstance(row.get("repository"), str) and row["repository"]:
        resolved = True
        commit = observation.resolve(
            shell, inputs.identifier, str(row["repository"]), str(row["branch"])
        )
    return DeployEvidence(
        snapshot.standing.standing if snapshot.standing else None,
        architecture,
        disk,
        str(state["boot"]) if state else "",
        int(str(state["uptime"])) if state else None,
        site_row,
        row,
        commit,
        resolved,
        _runtime_version(shell, snapshot, site_row, row, architecture),
    )


def _runtime_version(
    shell: RemoteShell,
    snapshot: CollectedSnapshot,
    site_row: SiteRecord | None,
    row: dict[str, object] | None,
    architecture: Architecture | None,
) -> str:
    """The selected runtime's exact PHP version, read only when a requirement needs it."""
    from runtimes import observation as runtime_observation

    if (
        architecture is None
        or site_row is None
        or row is None
        or not row.get("php_requirement")
        or snapshot.standing is None
        or snapshot.standing.standing != Standing.TARGET_STACK
    ):
        return ""
    selection = str(site_row["runtime"])
    if not selection:
        return ""
    value = runtime_observation.read(shell, selection, architecture)
    if value is None:
        return ""
    for candidate in runtime_observation.observations(value["runtimes"], architecture):
        if candidate.entry == selection and candidate.version:
            return candidate.version
    return ""


def _site_row(state: NativeState | None, identifier: str) -> SiteRecord | None:
    if state is None:
        return None
    for site in state["sites"]:
        if site["identifier"] == identifier:
            return site
    return None


def releases_of(row: dict[str, object]) -> list[dict[str, object]]:
    raw = row.get("releases")
    if not isinstance(raw, list):
        return []
    records = [record for record in raw if isinstance(record, dict)]
    return sorted(records, key=lambda record: (-int(str(record["created"])), str(record["name"])))


def _string_list(value: object) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def prune_names(row: dict[str, object]) -> list[str]:
    """The releases a Deploy removes: beyond ``current`` plus the newest five others."""
    current = str(row["current"])
    ordered = [record for record in releases_of(row) if str(record["name"]) != current]
    return [str(record["name"]) for record in ordered[RETAINED_RELEASES:]]


def _eligibility(evidence: DeployEvidence) -> list[str]:
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before deploying.")
    if evidence.site is None or evidence.site["state"] != "complete":
        refusals.append("The site's native layout is incomplete or outside supported settings.")
    row = evidence.laravel
    if row is None:
        refusals.append("The site's release layout could not be read.")
    elif row["application"] != "laravel":
        refusals.append("This site has no current Laravel release to deploy from.")
    elif not row["repository"]:
        refusals.append("The site's repository could not be read from its release metadata.")
    elif not evidence.resolved or evidence.commit is None:
        refusals.append("The branch could not be resolved to an exact commit.")
    refusals.extend(_source_refusals(row))
    requirement = str(row.get("php_requirement", "")) if row is not None else ""
    shortfall = _shortfall(requirement, evidence.runtime_version)
    if shortfall is not None:
        refusals.append(shortfall)
    problem = str(row.get("repository_problem", "")) if row is not None else ""
    if problem:
        refusals.append(problem)
    return refusals


def _source_refusals(row: dict[str, object] | None) -> list[str]:
    """The repository locator and branch grammar the Deploy path re-validates (Phase B #259)."""
    if row is None or not row["repository"]:
        return []
    try:
        repository_locator(str(row["repository"]))
        if row["branch"]:
            repository_ref(str(row["branch"]))
    except ValueError as error:
        return [str(error)]
    return []


_CONSTRAINT: Final = re.compile(r"(\d+)(?:\.(\d+))?")


def _minimum(requirement: str) -> tuple[int, int] | None:
    """The lowest version a Composer constraint accepts, when it states one."""
    text = requirement.strip()
    if not text or text.startswith("<"):
        return None
    match = _CONSTRAINT.search(text)
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2) or 0))


def _shortfall(requirement: str, runtime_version: str) -> str | None:
    """A refusal naming the requirement when the selected runtime cannot satisfy it."""
    if not requirement or not runtime_version:
        return None
    minimum = _minimum(requirement)
    match = _CONSTRAINT.match(runtime_version.strip())
    if minimum is None or match is None:
        return None
    current = (int(match.group(1)), int(match.group(2) or 0))
    if current >= minimum:
        return None
    return (
        f"The site's application requires PHP {requirement}, but its runtime is "
        f"PHP {runtime_version}."
    )


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, DeployEvidence):
        raise ValueError("A deploy needs native evidence.")
    refusals = _eligibility(evidence)
    site = evidence.site
    row = evidence.laravel
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": inputs.identifier,
        "acknowledgement": MIGRATION_ACKNOWLEDGEMENT,
    }
    effects: tuple[DeclaredEffect, ...] = ()
    repository = str(row["repository"]) if row else ""
    if site is not None and row is not None:
        names = tuple(str(name) for name in site["names"])
        runtime = str(site["runtime"])
        current = str(row["current"])
        prune = prune_names(row)
        commit = evidence.commit or ""
        token = secrets.token_hex(8)
        shared = row["shared"]
        if isinstance(shared, dict) and not all(shared.values()):
            refusals.append(
                "The site's shared environment, storage or cache is missing, so a release "
                "cannot be linked safely."
            )
        required = _disk_required()
        if evidence.disk_available and evidence.disk_available < required:
            refusals.append("The server lacks the free space this deploy needs.")
        try:
            caddy = render_laravel_caddy(
                SiteSettings(inputs.identifier, tuple(names), runtime, https=bool(site["https"]))
            )
        except ValueError:
            caddy = ""
        document.update(
            names=list(names),
            runtime=runtime,
            repository=repository,
            branch=str(row["branch"]),
            commit=commit,
            token=token,
            release=f"{commit}-{token}" if commit else "",
            current=current,
            releases=[str(record["name"]) for record in releases_of(row)],
            prune=prune,
            disk_required=required,
            migrations=bool(inputs.migrations),
            gate=GATE_TEMPLATE,
            caddy=caddy,
            https=bool(site["https"]),
            details=_details(row, commit, prune, required, bool(inputs.migrations)),
        )
        if not refusals:
            effects = (
                DeclaredEffect(
                    Scope.SITE,
                    f"Deploy commit {commit[:12]} to {inputs.identifier} and switch its "
                    "current release.",
                    (inputs.identifier,),
                ),
            )
    return ReviewDraft(
        SLUG,
        f"Deploy {inputs.identifier} from {repository}.",
        effects=effects,
        stages=(
            "preflight",
            "fetch",
            "build",
            "shared",
            "discover",
            "classify",
            "gate",
            "migrations",
            "switch",
            "reload",
            "readiness",
            "prune",
        ),
        postconditions=(
            "The site's current release is the reviewed commit.",
            "The site answers its readiness check over its own address.",
            "Only the releases the review named were removed.",
        ),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        sites_read=(
            "find /etc/caddy/sites -maxdepth 1 -type f -name "
            + shlex.quote(inputs.identifier + ".caddy")
            + " -printf '%f\\n' | sed 's/\\.caddy$//'"
        )
        if site is not None
        else "",
        current_sites=(inputs.identifier,) if site is not None else None,
        document=document,
    )


def _disk_required() -> int:
    # A build needs room for a second copy of the source plus its installed dependencies.
    return 512 * 1024 * 1024


def _details(
    row: dict[str, object], commit: str, prune: list[str], required: int, migrations: bool
) -> list[dict[str, str]]:
    return [
        {"label": "Repository", "value": str(row["repository"])},
        {"label": "Branch", "value": str(row["branch"])},
        {"label": "Commit", "value": commit},
        {"label": "Current release", "value": str(row["current"])},
        {"label": "Releases removed", "value": ", ".join(prune) or "None"},
        {"label": "Free disk required", "value": f"{required // (1024 * 1024)} MiB"},
        {
            "label": "Migrations",
            "value": "Run pending migrations"
            if migrations
            else "Off, pending migrations are reported in the run's journal and not run",
        },
    ]


_DOCUMENT_KEYS: Final = (
    "version",
    "identifier",
    "names",
    "runtime",
    "repository",
    "commit",
    "token",
    "current",
    "releases",
    "prune",
    "disk_required",
    "migrations",
    "gate",
    "caddy",
    "https",
    "branch",
)


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or document.get("acknowledgement") != MIGRATION_ACKNOWLEDGEMENT
    ):
        raise ValueError("The deploy review is not a valid immutable selection.")
    value = {key: document.get(key) for key in _DOCUMENT_KEYS}
    encoded = base64.b64encode(gzip.compress(json.dumps(value).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES.rstrip(b"\n"), (encoded,))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    document = stored.document
    value = observation.read(shell)
    if value is None:
        return None
    row = observation.site(value, str(document.get("identifier", "")))
    if row is None:
        return False
    if str(row["current"]) != str(document.get("release", "")):
        return False
    remaining = {str(record["name"]) for record in releases_of(row)}
    removed = set(_string_list(document.get("prune")))
    return not (removed & remaining)


DEPLOY_SITE: Final = ChangeKind(
    SLUG,
    "Deploy Laravel site",
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_shape=InputShape.LARAVEL_DEPLOY,
)
