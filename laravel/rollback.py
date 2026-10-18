"""Roll back a Laravel site to a retained release (Phase B #264)."""

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
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from runtimes.catalog import Architecture, architecture_of
from sites.bodies.common import NativeState, SiteRecord
from sites.configuration import SiteSettings, render_caddy

from . import observation
from .change import releases_of
from .configuration import GATE_TEMPLATE, ROLLBACK_ACKNOWLEDGEMENT

SLUG: Final = "rollback_laravel_site"
BODY_SOURCE: Final = (
    observation.LARAVEL_SOURCE
    + "\n"
    + importlib.resources.files("laravel.bodies")
    .joinpath("rollback.py")
    .read_text()
    .replace("from laravel.bodies.common import roll_back\n", "")
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
class RollbackEvidence:
    standing: Standing | None
    architecture: Architecture | None
    boot_id: str
    uptime_centiseconds: int | None
    site: SiteRecord | None
    laravel: dict[str, object] | None


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> RollbackEvidence:
    from discovery.observations import collect
    from sites import observation as site_observation

    snapshot = collect(shell, sites=False)
    state = site_observation.read(shell, "observed", "")
    laravel = observation.read(shell)
    row = observation.site(laravel, inputs.identifier) if laravel is not None else None
    return RollbackEvidence(
        snapshot.standing.standing if snapshot.standing else None,
        architecture_of(snapshot.architecture.value or ""),
        str(state["boot"]) if state else "",
        int(str(state["uptime"])) if state else None,
        _site_row(state, inputs.identifier),
        row,
    )


def _site_row(state: NativeState | None, identifier: str) -> SiteRecord | None:
    if state is None:
        return None
    for site in state["sites"]:
        if site["identifier"] == identifier:
            return site
    return None


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, RollbackEvidence):
        raise ValueError("A roll back needs native evidence.")
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before rolling back.")
    site = evidence.site
    if site is None or site["state"] != "complete":
        refusals.append("The site's native layout is incomplete or outside supported settings.")
    row = evidence.laravel
    if row is None:
        refusals.append("The site's release layout could not be read.")
    runtime = str(site["runtime"]) if site is not None else ""
    names = tuple(str(name) for name in site["names"]) if site is not None else ()
    current = str(row["current"]) if row is not None else ""
    releases = [str(record["name"]) for record in releases_of(row)] if row is not None else []
    if row is not None:
        if inputs.release == current:
            refusals.append("This release is already current; there is nothing to roll back.")
        elif inputs.release not in releases:
            refusals.append("The chosen release is no longer retained on the server.")
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": inputs.identifier,
        "acknowledgement": ROLLBACK_ACKNOWLEDGEMENT,
    }
    effects: tuple[DeclaredEffect, ...] = ()
    if site is not None and row is not None:
        document.update(_rollback_document(site, inputs, current, releases, names, runtime))
        if not refusals:
            effects = (
                DeclaredEffect(
                    Scope.SITE,
                    f"Reactivate release {inputs.release} for {inputs.identifier}.",
                    (inputs.identifier,),
                ),
            )
    return ReviewDraft(
        SLUG,
        f"Roll back {inputs.identifier} to {inputs.release}.",
        effects=effects,
        stages=("preflight", "gate", "switch", "readiness"),
        postconditions=(
            "The site's current release is the chosen retained release.",
            "The site answers its readiness check over its own address.",
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


_DOCUMENT_KEYS: Final = (
    "version",
    "identifier",
    "names",
    "runtime",
    "release",
    "current",
    "releases",
    "gate",
    "caddy",
    "https",
)


def _rollback_document(
    site: SiteRecord,
    inputs: PreparationInputs,
    current: str,
    releases: list[str],
    names: tuple[str, ...],
    runtime: str,
) -> dict[str, object]:
    try:
        caddy = render_caddy(
            SiteSettings(inputs.identifier, names, runtime, https=bool(site["https"]))
        )
    except ValueError:
        caddy = ""
    return {
        "names": list(names),
        "runtime": runtime,
        "release": inputs.release,
        "current": current,
        "releases": releases,
        "gate": GATE_TEMPLATE,
        "caddy": caddy,
        "https": bool(site["https"]),
        "details": [
            {"label": "Release to activate", "value": inputs.release},
            {"label": "Currently serving", "value": current},
            {
                "label": "Not reversed",
                "value": "Schema, data, storage, settings and queued jobs are unchanged.",
            },
        ],
    }


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or document.get("acknowledgement") != ROLLBACK_ACKNOWLEDGEMENT
    ):
        raise ValueError("The roll back review is not a valid immutable selection.")
    value = {key: document.get(key) for key in _DOCUMENT_KEYS}
    encoded = base64.b64encode(gzip.compress(json.dumps(value).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES.rstrip(b"\n"), (encoded,))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    document = stored.document
    value = observation.read(shell)
    if value is None:
        return None
    row = observation.site(value, str(document.get("identifier", "")))
    return row is not None and str(row["current"]) == str(document.get("release", ""))


ROLLBACK_SITE: Final = ChangeKind(
    SLUG,
    "Roll back Laravel site",
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_shape=InputShape.LARAVEL_ROLLBACK,
)
