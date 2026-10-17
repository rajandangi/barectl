"""Deploy a Laravel site as one reviewed change (docs/adr/0019-…, Phase B #259)."""

import base64
import gzip
import hashlib
import importlib.resources
import json
import secrets
import shlex
from dataclasses import dataclass
from typing import Final

from bootstrap.standing import Standing
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from runtimes.catalog import Architecture, architecture_of
from sites.bodies.common import NativeState, SiteRecord

from . import observation
from .configuration import GATE_TEMPLATE, RETAINED_RELEASES

SLUG: Final = "deploy_laravel_site"
MIGRATION_ACKNOWLEDGEMENT: Final = (
    "I understand pending migrations may change data, that rolling back code does not "
    "reverse them, and that Barectl has no automatic backup."
)
BODY_SOURCE: Final = (
    observation.LARAVEL_SOURCE
    + "\n"
    + importlib.resources.files("laravel.bodies")
    .joinpath("deploy.py")
    .read_text()
    .replace("from laravel.bodies.common import deploy\n", "")
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
        _site_row(state, inputs.identifier),
        row,
        commit,
        resolved,
    )


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
    return refusals


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
            migrations=True,
            gate=GATE_TEMPLATE,
            details=_details(row, commit, prune, required),
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
            "migrations",
            "switch",
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
    row: dict[str, object], commit: str, prune: list[str], required: int
) -> list[dict[str, str]]:
    return [
        {"label": "Repository", "value": str(row["repository"])},
        {"label": "Branch", "value": str(row["branch"])},
        {"label": "Commit", "value": commit},
        {"label": "Current release", "value": str(row["current"])},
        {"label": "Releases removed", "value": ", ".join(prune) or "None"},
        {"label": "Free disk required", "value": f"{required // (1024 * 1024)} MiB"},
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
