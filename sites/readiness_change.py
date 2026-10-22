"""Change one plain PHP site's readiness path as native Caddy evidence.

docs/sites.md#readiness: the path lives in the site's own Caddy file, so a fresh controller
reconstructs it without a Barectl marker, and every later check reads the same value.
"""

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
from .change import membership_command

SLUG: Final = "set_site_readiness"
BODY_SOURCE: Final = (
    observation.COMMON_SOURCE
    + "\n"
    + importlib.resources.files("sites.bodies")
    .joinpath("readiness.py")
    .read_text()
    .replace("from sites.bodies.common import set_site_readiness\n", "")
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
class ReadinessEvidence:
    standing: Standing | None
    native: NativeState | None


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> ReadinessEvidence:
    from discovery.observations import collect

    # The affected site comes from this preparation's own bounded read; the snapshot's site
    # inventory would read every other site's protections for nothing.
    snapshot = collect(shell, sites=False)
    return ReadinessEvidence(
        snapshot.standing.standing if snapshot.standing else None,
        observation.read(shell, "observed", "", protections=False),
    )


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, ReadinessEvidence):
        raise ValueError("A readiness path change needs native evidence.")
    native = evidence.native
    refusals: list[str] = []
    site = (
        next(
            (row for row in native["sites"] if row["identifier"] == inputs.identifier),
            None,
        )
        if native is not None
        else None
    )
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before changing a site.")
    if native is None:
        refusals.append("The site's native serving configuration could not be read.")
    elif site is None:
        refusals.append("The site was not observed in the current server configuration.")
    elif site["state"] != "complete":
        refusals.append(site["problem"] or "The site is incomplete or outside supported settings.")
    current = site["readiness"] if site is not None else ""
    reportable = site is not None and site["state"] == "complete"
    unchanged = reportable and current == inputs.readiness
    sites_read = membership_command(site["runtime"]) if reportable and site is not None else ""
    document: dict[str, object] = {
        "version": 1,
        "identifier": inputs.identifier,
        "readiness": inputs.readiness,
        "body_sha256": BODY_SHA256,
        "precondition_digest": native["digest"] if native is not None else "",
        "details": [
            {"label": "Site", "value": inputs.identifier},
            {"label": "Readiness path", "value": inputs.readiness},
            {"label": "Previous path", "value": current or "Not observed"},
            {
                "label": "Check",
                "value": (
                    "A GET with the primary Host must answer below 500 at /, or exactly 200 "
                    "at another path."
                ),
            },
            {
                "label": "Storage",
                "value": "Native Caddy configuration; no Barectl marker on the server.",
            },
        ],
    }
    return ReviewDraft(
        SLUG,
        f"Set {inputs.identifier}'s readiness path to {inputs.readiness}.",
        effects=()
        if refusals or unchanged
        else (
            DeclaredEffect(
                Scope.SITE,
                "Publish this site's readiness path in its Caddy file and check it.",
                (inputs.identifier,),
            ),
        ),
        sites_read=sites_read,
        current_sites=(inputs.identifier,) if reportable else None,
        stages=("preflight", "caddy", "verify"),
        refusals=tuple(refusals),
        document=document,
        boot_id=native["boot"] if native is not None else "",
        uptime_centiseconds=native["uptime"] if native is not None else None,
    )


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    decode_inputs(
        {key: document.get(key) for key in ("version", "identifier", "readiness")},
        (),
        InputShape.SITE_READINESS,
    )
    digest = document.get("precondition_digest")
    if (
        document.get("body_sha256") != BODY_SHA256
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("The readiness review is not a valid immutable native selection.")
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
        and site["readiness"] == stored.document["readiness"]
    )


SET_SITE_READINESS: Final = ChangeKind(
    SLUG,
    "Set site readiness path",
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_shape=InputShape.SITE_READINESS,
)
