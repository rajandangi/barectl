"""Change one site's bounded PHP-FPM pool settings (docs/site-conventions.md)."""

import base64
import gzip
import hashlib
import importlib.resources
import json
import shlex
from dataclasses import dataclass
from typing import Final

from bootstrap.standing import Standing
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from operations.models import ChangeReview

from . import observation
from .bodies.common import NativeState
from .bodies.pool import SitePool

SLUG: Final = "set_site_pool"
BODY_SOURCE: Final = (
    observation.COMMON_SOURCE
    + "\n"
    + importlib.resources.files("sites.bodies")
    .joinpath("pool_change.py")
    .read_text()
    .replace("from sites.bodies.common import set_site_pool\n", "")
)
BODY_BYTES: Final = (
    "#!/bin/sh\nexec python3 -c "
    + shlex.quote(
        "import base64,gzip; exec(gzip.decompress(base64.b64decode("
        + repr(base64.b64encode(gzip.compress(BODY_SOURCE.encode(), mtime=0)).decode())
        + ")))"
    )
    + ' "$@"'
).encode()
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()


@dataclass(frozen=True)
class PoolEvidence:
    standing: Standing | None
    native: NativeState | None


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> PoolEvidence:
    from discovery.observations import collect

    snapshot = collect(shell, sites=False)
    return PoolEvidence(
        snapshot.standing.standing if snapshot.standing else None,
        observation.read(shell, "observed", "", protections=False),
    )


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, PoolEvidence):
        raise ValueError("A PHP settings change needs native evidence.")
    native = evidence.native
    site = (
        next(
            (row for row in native["sites"] if row["identifier"] == inputs.identifier),
            None,
        )
        if native is not None
        else None
    )
    refusals: list[str] = []
    if inputs.pool is None or not inputs.pool.valid_change():
        refusals.append("Choose PHP settings within the supported bounds.")
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before changing a site.")
    if native is None:
        refusals.append("The site's native serving configuration could not be read.")
    elif site is None:
        refusals.append("The site was not observed in the current server configuration.")
    elif site["state"] != "complete":
        refusals.append(site["problem"] or "The site is incomplete or outside supported settings.")
    elif site["pool"] is None:
        refusals.append("The site's PHP pool settings could not be read.")
    current = SitePool.from_document(site["pool"]) if site is not None else None
    reportable = site is not None and site["state"] == "complete" and current is not None
    unchanged = reportable and inputs.pool is not None and current == inputs.pool
    document: dict[str, object] = {
        "version": 1,
        "identifier": inputs.identifier,
        "pool": inputs.pool.document() if inputs.pool is not None else None,
        "body_sha256": BODY_SHA256,
        "precondition_digest": native["digest"] if native is not None else "",
        "details": [
            {"label": "Site", "value": inputs.identifier},
            {"label": "Previous settings", "value": _describe(current)},
            {"label": "New settings", "value": _describe(inputs.pool)},
            {
                "label": "Apply",
                "value": "Rewrite this site's pool and gracefully reload only its own master.",
            },
        ],
    }
    return ReviewDraft(
        SLUG,
        f"Change {inputs.identifier}'s PHP settings.",
        effects=()
        if refusals or unchanged
        else (
            DeclaredEffect(
                Scope.SITE,
                "Rewrite this site's PHP pool and reload only its own master.",
                (inputs.identifier,),
            ),
        ),
        sites_read=(
            "find /etc/caddy/sites -maxdepth 1 -type f -name "
            + shlex.quote(inputs.identifier + ".caddy")
            + " -printf '%f\\n' | sed 's/\\.caddy$//'"
        )
        if reportable
        else "",
        current_sites=(inputs.identifier,) if reportable else None,
        stages=("preflight", "pool", "reload", "verify"),
        refusals=tuple(refusals),
        document=document,
        boot_id=native["boot"] if native is not None else "",
        uptime_centiseconds=native["uptime"] if native is not None else None,
    )


def _describe(pool: SitePool | None) -> str:
    if pool is None:
        return "Not observed"
    return (
        f"{pool.process_manager}, {pool.max_children} children, "
        f"{_seconds(pool.terminate_timeout)} request limit, "
        f"{_megabytes(pool.memory_limit)} memory"
    )


def _seconds(value: int | None) -> str:
    return "Unset" if value is None else f"{value}s"


def _megabytes(value: int | None) -> str:
    return "Unset" if value is None else f"{value}M"


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    inputs = decode_inputs(
        {key: document.get(key) for key in ("version", "identifier", "pool")},
        (),
        InputShape.SITE_POOL,
    )
    digest = document.get("precondition_digest")
    if (
        document.get("body_sha256") != BODY_SHA256
        or inputs.pool is None
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("The PHP settings review is not a valid immutable native selection.")
    encoded = base64.b64encode(gzip.compress(json.dumps(document).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES, (encoded,))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    body(stored.document, BodyContext("", "", 0))
    native = observation.read(shell, "observed", "", protections=False)
    if native is None:
        return None
    site = next(
        (row for row in native["sites"] if row["identifier"] == stored.document["identifier"]),
        None,
    )
    return (
        site is not None
        and site["state"] == "complete"
        and SitePool.from_document(site["pool"]) == SitePool.from_document(stored.document["pool"])
    )


SET_SITE_POOL: Final = ChangeKind(
    SLUG,
    "Change site PHP settings",
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_shape=InputShape.SITE_POOL,
)
