"""Create one HTTP PHP site through the engine's four operational members."""

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
from runtimes import observation as runtime_observation
from runtimes.catalog import Architecture, architecture_of

from . import observation
from .bodies.common import CADDY_OUTSIDE, NativeState
from .configuration import PHP_RUNTIMES, SiteSettings, render_caddy, render_pool

SLUG: Final = "create_http_site"
BODY_SOURCE: Final = (
    observation.COMMON_SOURCE.replace(
        'RUNTIME_READ_SOURCE = ""', "RUNTIME_READ_SOURCE = " + repr(runtime_observation.READ_SOURCE)
    )
    + "\n"
    + importlib.resources.files("sites.bodies")
    .joinpath("create.py")
    .read_text()
    .replace("from sites.bodies.common import create\n", "")
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
class SiteEvidence:
    architecture: Architecture | None
    standing: Standing | None
    runtime: dict[str, object] | None
    native: NativeState | None


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> SiteEvidence:
    from discovery.observations import collect

    settings = SiteSettings(inputs.identifier, inputs.names, inputs.selection)
    # This preparation takes its affected sites from its own read, so the snapshot's site
    # inventory is unused; reading every other site's protections is the costliest part of
    # discovery on a multi-site host.
    snapshot = collect(shell, sites=False)
    architecture = architecture_of(snapshot.architecture.value or "")
    runtime = (
        runtime_observation.read(shell, settings.runtime, architecture) if architecture else None
    )
    runtime_ready = (
        architecture is not None
        and runtime is not None
        and any(
            row.entry == settings.runtime and row.manageable
            for row in runtime_observation.observations(runtime["runtimes"], architecture)
        )
    )
    return SiteEvidence(
        architecture,
        snapshot.standing.standing if snapshot.standing else None,
        runtime,
        observation.read(
            shell,
            settings.identifier,
            settings.runtime,
            settings.names if runtime_ready else (),
            protections=False,
        ),
    )


def runtime_refusals(evidence: SiteEvidence, settings: SiteSettings) -> list[str]:
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before creating a site.")
    if evidence.runtime is None or evidence.architecture is None:
        refusals.append("The selected master's native evidence is unavailable.")
    else:
        rows = runtime_observation.observations(evidence.runtime["runtimes"], evidence.architecture)
        if not any(row.entry == settings.runtime and row.manageable for row in rows):
            refusals.append("The selected PHP master is not verified within supported settings.")
    return refusals


def runtime_document(evidence: SiteEvidence, inputs: PreparationInputs) -> dict[str, object]:
    document: dict[str, object] = {}
    if evidence.architecture is not None and evidence.runtime is not None:
        document["architecture"] = str(evidence.architecture)
        document["runtime_arguments"] = list(
            runtime_observation.read_arguments(inputs.selection, evidence.architecture)
        )
        document["runtime_digest"] = evidence.runtime["digest"]
        installed = next(
            (
                row
                for row in runtime_observation.observations(
                    evidence.runtime["runtimes"], evidence.architecture
                )
                if row.entry == inputs.selection
            ),
            None,
        )
        if installed is not None:
            document["runtime_version"] = installed.version
    return document


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, SiteEvidence):
        raise ValueError("Site creation needs native evidence.")
    settings = SiteSettings(inputs.identifier, inputs.names, inputs.selection)
    refusals: list[str] = []
    native = evidence.native
    refusals.extend(runtime_refusals(evidence, settings))
    if native is None:
        refusals.append(
            "Site files, accounts or Caddy's running configuration are unreadable or unsupported."
        )
    if native is not None and native["pool_validation"] != "valid":
        refusals.append(
            "The selected master's future pool could not pass native scratch validation."
        )
    if native is not None and native["validation"] != "valid":
        refusals.append(
            "The exact complete Caddy tree could not be validated as caddy "
            "in its private scratch environment."
        )
    current: tuple[str, ...] = ()
    existing = False
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": inputs.identifier,
        "names": list(inputs.names),
        "selection": inputs.selection,
    }
    document.update(runtime_document(evidence, inputs))
    if native is not None:
        current = tuple(str(site) for site in native["current_sites"])
        existing, collisions = existing_site(native, inputs)
        refusals.extend(collisions)
        if not existing and native["evidence"].get(settings.directory) is not None:
            refusals.append(
                "The site directory is already occupied. Review its native state first."
            )
        document.update(
            precondition_digest=native["digest"],
            disk_digest=native["disk_digest"],
            identity=review_identity(native, settings.identifier),
            proxy_identity=native["next_proxy_id"],
            caddy=render_caddy(settings),
            pool=render_pool(settings),
            membership={settings.runtime: list(current)},
            details=[
                {"label": "Caddy validation", "value": native["validation"]},
                {"label": "PHP pool scratch validation", "value": native["pool_validation"]},
                {
                    "label": "Pool identity validation",
                    "value": (
                        "Reviewed numeric UID/GID before creation; "
                        "exact named pool -t before reload"
                    ),
                },
                {"label": "Linux account", "value": settings.account},
                {
                    "label": "Numeric UID/GID",
                    "value": str(review_identity(native, settings.identifier)),
                },
                {
                    "label": "Deployment",
                    "value": "releases/initial; current symlink; stable .deploy.lock",
                },
                {
                    "label": "Source permissions",
                    "value": "PHP0600 site:site; public assets0640 site:caddy",
                },
                {
                    "label": "CLI wrappers",
                    "value": "Root-owned PHP, Composer and WP-CLI using selected PHP",
                },
                {"label": "Site directory", "value": settings.directory},
                {"label": "PHP pool", "value": render_pool(settings)},
                {"label": "Caddy site file", "value": render_caddy(settings)},
            ],
        )
    effects = (
        ()
        if refusals or existing
        else (
            DeclaredEffect(
                Scope.SITE,
                "Create the account, release layout, wrappers and HTTP PHP route.",
                (inputs.identifier,),
            ),
            *(
                (
                    DeclaredEffect(
                        Scope.SHARED,
                        "Publish the shared Caddy route without restarting other sites.",
                        current,
                    ),
                )
                if current
                else ()
            ),
        )
    )
    return ReviewDraft(
        SLUG,
        f"Create HTTP PHP site {inputs.identifier}.",
        effects=effects,
        stages=("preflight", "account", "layout", "pool", "caddy", "verify"),
        refusals=tuple(refusals),
        boot_id=str(native["boot"]) if native else "",
        uptime_centiseconds=int(str(native["uptime"])) if native else None,
        sites_read=membership_command(inputs.selection)
        if native and native["master_present"]
        else "",
        current_sites=current if native and native["master_present"] else None,
        document=document,
    )


def review_identity(native: NativeState, identifier: str) -> int:
    for site in native["sites"]:
        account = site["account"]
        if site["identifier"] == identifier and account is not None and type(account[0]) is int:
            return account[0]
    return native["next_id"]


def existing_site(native: NativeState, inputs: PreparationInputs) -> tuple[bool, list[str]]:
    existing = False
    refusals: list[str] = []
    for site in native["sites"]:
        if site["problem"] == CADDY_OUTSIDE:
            refusals.append(f"Site {site['identifier']} has unsupported Caddy settings.")
        if site["identifier"] == inputs.identifier:
            existing = (
                site["names"] == list(inputs.names)
                and site["runtime"] == inputs.selection
                and site["state"] == "complete"
            )
            if site["state"] != "complete":
                refusals.append(
                    site["problem"]
                    or "The existing site is incomplete or outside supported settings."
                )
            elif not existing:
                refusals.append("This identifier already names another observed site.")
        elif set(site["names"]).intersection(inputs.names):
            refusals.append("A requested DNS name already belongs to another site.")
    return existing, refusals


def membership_command(runtime: str) -> str:
    if runtime not in PHP_RUNTIMES:
        raise ValueError("Unknown PHP master.")
    directory = shlex.quote("/etc/caddy/sites")
    return (
        f"find {directory} -maxdepth 1 -type f -name '*.caddy' "
        "-printf '%f\\n' | sed 's/\\.caddy$//' | LC_ALL=C sort"
    )


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    from operations.inputs import decode_inputs

    inputs = decode_inputs(
        {key: document.get(key) for key in ("version", "selection", "identifier", "names")},
        PHP_RUNTIMES,
        InputShape.SITE_CREATE,
    )
    settings = SiteSettings(inputs.identifier, inputs.names, inputs.selection)
    try:
        architecture = Architecture(str(document.get("architecture", "")))
    except ValueError:
        raise ValueError("The review has no supported catalog architecture.") from None
    if document.get("runtime_arguments") != list(
        runtime_observation.read_arguments(inputs.selection, architecture)
    ):
        raise ValueError("The reviewed native client arguments changed.")
    identity = document.get("identity")
    proxy_identity = document.get("proxy_identity")
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or document.get("caddy") != render_caddy(settings)
        or document.get("pool") != render_pool(settings)
        or type(identity) is not int
        or not 1000 <= identity < 30000
        or type(proxy_identity) is not int
        or not 1000 <= proxy_identity < 30000
        or proxy_identity == identity
    ):
        raise ValueError("The site review is not a valid immutable native selection.")
    encoded = base64.b64encode(gzip.compress(json.dumps(document).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES.rstrip(b"\n"), (encoded,))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    from operations.inputs import decode_inputs

    body(stored.document, BodyContext("", "", 0))
    inputs = decode_inputs(
        {key: stored.document.get(key) for key in ("version", "selection", "identifier", "names")},
        PHP_RUNTIMES,
        InputShape.SITE_CREATE,
    )
    architecture = Architecture(str(stored.document["architecture"]))
    value = observation.read(shell, inputs.identifier, inputs.selection, site_only=True)
    runtime = runtime_observation.read(shell, inputs.selection, architecture)
    if value is None or runtime is None:
        return None
    rows = runtime_observation.observations(runtime["runtimes"], architecture)
    if not any(row.entry == inputs.selection and row.manageable for row in rows):
        return False
    return any(
        site["identifier"] == inputs.identifier
        and site["names"] == list(inputs.names)
        and site["runtime"] == inputs.selection
        and site["state"] == "complete"
        and site["account"] is not None
        and site["account"][:2] == [stored.document["identity"]] * 2
        for site in value["sites"]
    )


CREATE_SITE: Final = ChangeKind(
    SLUG,
    "Create PHP site",
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_choices=PHP_RUNTIMES,
    input_shape=InputShape.SITE_CREATE,
)
