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
from .configuration import PHP_RUNTIMES, SiteSettings, render_caddy, render_pool

SLUG: Final = "create_http_site"
BODY_SOURCE: Final = (
    observation.COMMON_SOURCE
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
    native: dict[str, object] | None


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> SiteEvidence:
    from discovery.observations import collect

    settings = SiteSettings(inputs.identifier, inputs.names, inputs.selection)
    snapshot = collect(shell)
    architecture = architecture_of(snapshot.architecture.value or "")
    runtime = (
        runtime_observation.read(shell, settings.runtime, architecture) if architecture else None
    )
    return SiteEvidence(
        architecture,
        snapshot.standing.standing if snapshot.standing else None,
        runtime,
        observation.read(shell, settings.identifier, settings.runtime),
    )


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, SiteEvidence):
        raise ValueError("Site creation needs native evidence.")
    settings = SiteSettings(inputs.identifier, inputs.names, inputs.selection)
    refusals: list[str] = []
    native = evidence.native
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before creating a site.")
    if evidence.runtime is None or evidence.architecture is None:
        refusals.append("The selected master's native evidence is unavailable.")
    else:
        rows = runtime_observation.observations(evidence.runtime["runtimes"], evidence.architecture)
        if not any(row.entry == settings.runtime and row.manageable for row in rows):
            refusals.append("The selected PHP master is not verified within supported settings.")
    if native is None:
        refusals.append(
            "Site files, accounts or Caddy's running configuration are unreadable or unsupported."
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
    if native is not None:
        current = tuple(str(site) for site in native["current_sites"])
        for site in native["sites"]:
            if site["identifier"] == inputs.identifier:
                existing = (
                    site["names"] == list(inputs.names) and site["runtime"] == inputs.selection
                )
                if not existing:
                    refusals.append("This identifier already names another observed site.")
            elif set(site["names"]).intersection(inputs.names):
                refusals.append("A requested DNS name already belongs to another site.")
        if not existing and native["evidence"].get(settings.directory) is not None:
            refusals.append(
                "The site directory is already occupied. Review its native state first."
            )
        document.update(
            precondition_digest=native["digest"],
            disk_digest=native["disk_digest"],
            identity=native["next_id"],
            caddy=render_caddy(settings),
            pool=render_pool(settings),
            membership={settings.runtime: list(current)},
            details=[
                {"label": "Linux account", "value": settings.account},
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
                        "Reload the selected PHP master and its existing site workers.",
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
        sites_read=membership_command(inputs.selection) if native else "",
        current_sites=current if native else None,
        document=document,
    )


def membership_command(runtime: str) -> str:
    if runtime not in PHP_RUNTIMES:
        raise ValueError("Unknown PHP master.")
    directory = shlex.quote(f"/etc/php-fpm/{runtime}/pools")
    return (
        f"find {directory} -maxdepth 1 -type f -name '*.conf' ! -name diagnostic.conf "
        "-printf '%f\\n' | sed 's/\\.conf$//' | LC_ALL=C sort"
    )


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    inputs = PreparationInputs(
        str(document.get("selection", "")),
        str(document.get("identifier", "")),
        tuple(document.get("names", ())),
    )
    settings = SiteSettings(inputs.identifier, inputs.names, inputs.selection)
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or document.get("caddy") != render_caddy(settings)
        or document.get("pool") != render_pool(settings)
        or type(document.get("identity")) is not int
        or not 1000 <= document["identity"] < 30000
    ):
        raise ValueError("The site review is not a valid immutable native selection.")
    encoded = base64.b64encode(gzip.compress(json.dumps(document).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES.rstrip(b"\n"), (encoded,))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    return None


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
