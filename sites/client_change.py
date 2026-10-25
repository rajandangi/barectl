"""Load the object cache's PHP client for one site, from the catalog lock (#390).

The client is phpredis, the Hydra-built ``redis`` extension package the catalog lock names
for each PHP runtime. Enabling it is native state on the site alone: the site pool and its
diagnostic pool carry ``php_admin_value[extension]`` with the locked shared object, the
site's PHP commands pass ``-dextension=`` (the build's own ini is parsed before a ``-c``
ini, so an ini line cannot resolve phpredis's session symbol), and only the site's own PHP
master restarts. Disabling removes exactly those three things. Site consent; no other site
or runtime master changes.
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
from runtimes.catalog import Architecture, Kind, architecture_of, load
from runtimes.extensions import CLIENT, entry_for, shared_object
from runtimes.extensions import build as redis_build

from . import observation
from .bodies.common import NativeState, SiteRecord

SLUG: Final = "set_site_php_client"
BODY_SOURCE: Final = (
    observation.COMMON_SOURCE
    + "\n"
    + importlib.resources.files("sites.bodies")
    .joinpath("client_change.py")
    .read_text()
    .replace("from sites.bodies.common import set_site_client\n", "")
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
class ClientEvidence:
    standing: Standing | None
    architecture: Architecture | None
    native: NativeState | None
    build: str
    extension: str
    version: str


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> ClientEvidence:
    from discovery.observations import collect

    snapshot = collect(shell, sites=False)
    architecture = architecture_of(snapshot.architecture.value or "")
    native = observation.read(shell, "observed", "", protections=False)
    site = _site(native, inputs.identifier)
    build = redis_build(architecture, str(site["runtime"])) if architecture and site else None
    return ClientEvidence(
        snapshot.standing.standing if snapshot.standing else None,
        architecture,
        native,
        build.path if build is not None else "",
        shared_object(build) if build is not None else "",
        build.version if build is not None else "",
    )


def _site(native: NativeState | None, identifier: str) -> SiteRecord | None:
    return (
        next((row for row in native["sites"] if row["identifier"] == identifier), None)
        if native is not None
        else None
    )


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, ClientEvidence):
        raise ValueError("A cache client change needs native evidence.")
    site = _site(evidence.native, inputs.identifier)
    runtime = str(site["runtime"]) if site is not None else ""
    current = str(site.get("client", "")) if site is not None else ""
    enabled = inputs.php_client is True
    desired = CLIENT if enabled else ""
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before changing a site.")
    if evidence.native is None:
        refusals.append("The site's native serving configuration could not be read.")
    elif site is None:
        refusals.append("The site was not observed in the current server configuration.")
    elif site["state"] != "complete":
        refusals.append(site["problem"] or "The site is incomplete or outside supported settings.")
    elif not runtime:
        refusals.append("The site's PHP runtime is unknown.")
    if (
        site is not None
        and site["state"] == "complete"
        and runtime
        and enabled
        and not evidence.extension
    ):
        refusals.append(
            "This Barectl release does not supply the object cache's PHP client for "
            + str(evidence.architecture or "this architecture")
            + " and "
            + runtime
            + "."
        )
    reportable = site is not None and site["state"] == "complete" and bool(runtime)
    unchanged = reportable and current == desired and not refusals
    document: dict[str, object] = {
        "version": 1,
        "identifier": inputs.identifier,
        "enabled": enabled,
        "runtime": runtime,
        "architecture": str(evidence.architecture or ""),
        "build": evidence.build if enabled else "",
        "extension": evidence.extension if enabled else "",
        "version_name": evidence.version if enabled else "",
        "current": current,
        "body_sha256": BODY_SHA256,
        "precondition_digest": evidence.native["digest"] if evidence.native is not None else "",
        "details": [
            {"label": "Site", "value": inputs.identifier},
            {"label": "PHP runtime", "value": runtime or "Unknown"},
            {"label": "Cache PHP client", "value": _describe(desired, evidence)},
            {"label": "Locked extension", "value": evidence.extension if desired else "None"},
            {
                "label": "Apply",
                "value": (
                    "Resolve the locked extension, then restart only this site's own PHP "
                    "master. Requests to this site are refused while it restarts."
                ),
            },
        ],
    }
    return ReviewDraft(
        SLUG,
        (
            f"Load {CLIENT} for {inputs.identifier}."
            if desired
            else f"Remove {CLIENT} from {inputs.identifier}."
        ),
        effects=()
        if refusals or unchanged
        else (
            DeclaredEffect(
                Scope.SITE,
                (
                    "Load the object cache's PHP client for this site's PHP master and "
                    "commands, restarting only its own master."
                    if desired
                    else "Remove the object cache's PHP client from this site and restart only "
                    "its own master."
                ),
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
        stages=("preflight", "realise", "pool", "commands", "restart", "verify"),
        refusals=tuple(refusals),
        document=document,
        boot_id=evidence.native["boot"] if evidence.native is not None else "",
        uptime_centiseconds=evidence.native["uptime"] if evidence.native is not None else None,
    )


def _describe(desired: str, evidence: ClientEvidence) -> str:
    if not desired:
        return "Disabled"
    return f"{CLIENT} {evidence.version}"


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    inputs = decode_inputs(
        {
            "version": 1,
            "identifier": document.get("identifier"),
            "php_client": document.get("enabled"),
        },
        (),
        InputShape.SITE_CLIENT,
    )
    digest = document.get("precondition_digest")
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or type(document.get("enabled")) is not bool
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("The cache client review is not a valid immutable native selection.")
    enabled = inputs.php_client is True
    build = document.get("build")
    extension = document.get("extension")
    if enabled:
        try:
            architecture = Architecture(str(document.get("architecture")))
        except ValueError:
            raise ValueError("Unknown catalog architecture.") from None
        item = load().identify(architecture, str(build))
        if (
            item is None
            or item.kind is not Kind.EXTENSION
            or item.entry != entry_for(str(document.get("runtime")))
            or extension != shared_object(item)
        ):
            raise ValueError("The reviewed cache client build is invalid.")
    elif build or extension:
        raise ValueError("A disabled review must not name an extension build.")
    encoded = base64.b64encode(gzip.compress(json.dumps(document).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES, (encoded,))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    body(stored.document, BodyContext("", "", 0))
    evidence = inspect(shell, PreparationInputs(identifier=str(stored.document["identifier"])))
    site = _site(evidence.native, str(stored.document["identifier"]))
    if site is None:
        return None
    desired = CLIENT if stored.document.get("enabled") is True else ""
    return site.get("client", "") == desired


SET_SITE_PHP_CLIENT: Final = ChangeKind(
    SLUG,
    "Load the site cache PHP client",
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_shape=InputShape.SITE_CLIENT,
)
