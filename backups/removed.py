"""Delete the kept backups of a removed site (#410).

Remove site keeps a site's onsite repository, its server key and its offsite copies. They are
listed as **Backups of a removed site** and are deleted only by this reviewed Destructive
change. The review names the removed site, the onsite and offsite repository paths, and says
that deletion is permanent (Phase D #358, #407 and #410).
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import shlex
from dataclasses import dataclass
from typing import Final

from automation.bodies.source import without_imports
from bootstrap.standing import Standing
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from runtimes.catalog import Architecture

from . import change, convention, observation

SLUG: Final = "delete_removed_backups"
LABEL: Final = "Delete removed-site backups"
STAGES: Final = ("preflight", "lock", "delete", "verify")
DELETION_PERMANENT: Final = (
    "Deletion is permanent. Barectl removes the removed site's onsite repository, its "
    "server key and, when offsite storage is set up, its offsite recovery points. It cannot "
    "undo this, and the removed site is not recreated."
)
REMOVED_BODY_CORE: Final = without_imports(
    importlib.resources.files("backups.bodies").joinpath("removed.py").read_text(),
    ("backups.bodies.native",),
)
REMOVED_SOURCE: Final = change.NATIVE_SOURCE + "\n" + REMOVED_BODY_CORE
REMOVED_BYTES: Final = change._packed(REMOVED_SOURCE)
REMOVED_SHA256: Final = hashlib.sha256(REMOVED_BYTES).hexdigest()


@dataclass(frozen=True)
class RemovedEvidence:
    architecture: Architecture | None
    standing: Standing | None
    engine: str
    offsite: observation.OffsiteStorage | None
    current_sites: tuple[str, ...]
    boot_id: str
    uptime_centiseconds: int | None
    identifier: str
    repository: bool
    key: bool
    profile: str
    removed: bool
    problem: str


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> RemovedEvidence:
    base = change.inspect(shell, inputs)
    current = base.current_sites
    removed = observation.removed(shell, current)
    problem = base.problem
    if removed is None:
        problem = "The kept repositories could not be read from the server."
    elif inputs.identifier not in removed:
        problem = "That site is still on the server, so its backups are not removed-site backups."
    backup = base.backup
    return RemovedEvidence(
        base.architecture,
        base.standing,
        base.engine,
        base.offsite,
        current,
        base.boot_id,
        base.uptime_centiseconds,
        inputs.identifier,
        bool(backup is not None and backup.repository),
        bool(backup is not None and backup.key),
        backup.profile if backup is not None else "",
        inputs.identifier in (removed or ()),
        problem,
    )


def _offsite_plan(evidence: RemovedEvidence, identifier: str) -> dict[str, object] | None:
    storage = evidence.offsite
    if storage is None or not storage.configured:
        return None
    config = {
        "provider": storage.provider,
        "bucket": storage.bucket,
        "region": storage.region,
        "endpoint": storage.endpoint,
        "prefix": storage.prefix,
        "prune": "yes" if storage.prune else "no",
    }
    return {
        "repository": convention.offsite_repository(config, identifier),
        "capture_env": convention.OFFSITE_CAPTURE,
        "prune_env": convention.OFFSITE_PRUNE,
        "storage": config,
    }


def _refusals(evidence: RemovedEvidence) -> list[str]:
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before deleting backups.")
    if evidence.architecture is None:
        refusals.append("The server's architecture is not supported.")
    if evidence.problem:
        refusals.append(evidence.problem)
    if not evidence.removed:
        refusals.append("That site's backups are not listed as the backups of a removed site.")
    if not evidence.repository or not evidence.key:
        refusals.append("The removed site's repository or server key is missing.")
    if evidence.offsite is not None and evidence.offsite.problem:
        refusals.append(evidence.offsite.problem)
    if evidence.offsite is not None and evidence.offsite.configured and not evidence.profile:
        refusals.append("The pinned backup tool is unavailable for this architecture.")
    return refusals


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, RemovedEvidence):
        raise ValueError("Deleting a removed site's backups needs native evidence.")
    refusals = _refusals(evidence)
    identifier = inputs.identifier
    repository = convention.repository(identifier)
    key = convention.server_key(identifier)
    try:
        offsite = _offsite_plan(evidence, identifier)
    except ValueError:
        offsite = None
        refusals.append("The offsite storage setting is outside supported settings.")
    details = [
        {"label": "Removed site", "value": identifier},
        {"label": "Onsite repository", "value": repository},
        {"label": "Server key", "value": key},
        {
            "label": "Offsite repository",
            "value": (
                str(offsite["repository"])
                if offsite is not None
                else "Offsite storage is not set up."
            ),
        },
        {"label": "Deletion is permanent", "value": DELETION_PERMANENT},
        {
            "label": "The site is not recreated",
            "value": (
                "This deletes only the kept backups. It does not recreate the removed site, "
                "its account, its database or its Caddy route."
            ),
        },
    ]
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": REMOVED_SHA256,
        "identifier": identifier,
        "repository": repository,
        "server_key": key,
        "offsite": offsite,
        "stages": list(STAGES),
        "details": details,
        "confirmation": identifier,
        "confirmation_label": f"Type {identifier} to confirm deleting its backups.",
        "note": DELETION_PERMANENT,
    }
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals:
        effects = (
            DeclaredEffect(
                Scope.SERVER,
                (
                    f"Permanently delete the kept onsite repository and offsite recovery "
                    f"points of removed site {identifier}."
                ),
                (),
                destroys_data=True,
            ),
        )
    return ReviewDraft(
        kind=SLUG,
        intent=f"Delete the kept backups of removed site {identifier}.",
        effects=effects,
        stages=STAGES if effects else (),
        postconditions=(
            "The removed site's onsite repository and server key are gone from this server.",
            "No Barectl offsite recovery point for that removed site remains in the bucket.",
        )
        if effects
        else (),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        document=document,
    )


def _document(document: dict[str, object]) -> None:
    if document.get("version") != 1 or document.get("body_sha256") != REMOVED_SHA256:
        raise ValueError("Unsupported removed-backups review.")
    identifier = document.get("identifier")
    if (
        not isinstance(identifier, str)
        or convention.SITE_IDENTIFIER.fullmatch(identifier) is None
        or document.get("repository") != convention.repository(identifier)
        or document.get("server_key") != convention.server_key(identifier)
    ):
        raise ValueError("The removed-backups review is not a supported deletion.")
    offsite = document.get("offsite")
    if offsite is not None:
        if not isinstance(offsite, dict) or set(offsite) != {
            "repository",
            "capture_env",
            "prune_env",
            "storage",
        }:
            raise ValueError("The removed-backups review has no supported offsite copy.")
        storage = offsite.get("storage")
        if (
            not isinstance(storage, dict)
            or offsite.get("capture_env") != convention.OFFSITE_CAPTURE
            or offsite.get("prune_env") != convention.OFFSITE_PRUNE
        ):
            raise ValueError("The removed-backups review has no supported offsite copy.")
        values = {str(name): str(value) for name, value in storage.items()}
        convention.read_config(convention.render_config(values))
        if offsite.get("repository") != convention.offsite_repository(values, identifier):
            raise ValueError("The removed-backups review changed its offsite repository.")


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    _document(document)
    _ = context
    value = {
        "version": 1,
        **{
            key: document[key]
            for key in (
                "identifier",
                "repository",
                "server_key",
                "offsite",
            )
        },
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(value).encode(), mtime=0)).decode()
    return NativeBody(REMOVED_BYTES, (encoded,))


def verify(shell: RemoteShell, review: ChangeReview) -> bool | None:
    body(review.document, BodyContext("", "", 0))
    identifier = str(review.document["identifier"])
    expected = (convention.repository(identifier), convention.server_key(identifier))
    command = " && ".join(f"test ! -e {shlex.quote(path)}" for path in expected)
    result = run_root(shell, f"sh -c {shlex.quote(command)}")
    if result.exit_status:
        return False if not result.truncated else None
    return True


DELETE: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    refresh_discovery=True,
    input_shape=InputShape.REMOVED_BACKUP,
)
