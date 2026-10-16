"""Select one installed site Node profile without changing PHP or server defaults."""

import base64
import gzip
import hashlib
import importlib.resources
import json
import shlex
from dataclasses import dataclass
from typing import Final, cast

from bootstrap.standing import Standing
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from operations.models import ChangeReview
from runtimes.catalog import Architecture, architecture_of, load

from . import observation
from .bodies.common import SiteNodeState

CHOICES: Final = ("nodejs_22", "nodejs_24")
SLUG: Final = "set_site_node"
READ_SOURCE: Final = (
    observation.COMMON_SOURCE + "\nprint(canonical(site_node_state(sys.argv[1])))\n"
)
BODY_SOURCE: Final = (
    observation.COMMON_SOURCE
    + "\n"
    + importlib.resources.files("sites.bodies")
    .joinpath("node.py")
    .read_text()
    .replace("from sites.bodies.common import set_site_node\n", "")
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
class NodeEvidence:
    standing: Standing | None
    architecture: Architecture | None
    state: SiteNodeState | None


def read(shell: RemoteShell, identifier: str, architecture: Architecture) -> SiteNodeState | None:
    decode_inputs(
        {"version": 1, "identifier": identifier, "selection": CHOICES[0]},
        CHOICES,
        InputShape.SITE_RUNTIME,
    )
    command = observation.python_command(READ_SOURCE, (identifier,))
    command = "sh -c " + shlex.quote("; ".join([*native.read_lock_steps(), "exec " + command]))
    result = run_root(shell, command)
    if result.exit_status or result.truncated:
        return None
    try:
        value: object = json.loads(result.stdout)
    except ValueError:
        return None
    if not isinstance(value, dict) or set(value) != {
        "native",
        "selection",
        "problem",
        "profiles",
        "links",
        "digest",
    }:
        return None
    if not isinstance(value["native"], dict) or not observation.valid_state(value["native"]):
        return None
    if (
        value["selection"] not in ("", *CHOICES)
        or not isinstance(value["problem"], str)
        or len(value["problem"]) > 1024
    ):
        return None
    profiles, links, digest = value["profiles"], value["links"], value["digest"]
    if not valid_profiles(profiles, architecture):
        return None
    if (
        not isinstance(links, dict)
        or set(links) != {"node", "npm", "npx"}
        or any(
            target is not None and (not isinstance(target, str) or len(target) > 256)
            for target in links.values()
        )
    ):
        return None
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(c not in "0123456789abcdef" for c in digest)
    ):
        return None
    return cast(SiteNodeState, value)


def valid_profiles(value: object, architecture: Architecture) -> bool:
    if not isinstance(value, dict) or set(value) != set(CHOICES):
        return False
    for entry, path in value.items():
        if not isinstance(path, str):
            return False
        build = load().identify(architecture, path) if path else None
        if path and (build is None or build.entry != entry):
            return False
    return True


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> NodeEvidence:
    from discovery.observations import collect

    snapshot = collect(shell, sites=False)
    architecture = architecture_of(snapshot.architecture.value or "")
    return NodeEvidence(
        snapshot.standing.standing if snapshot.standing else None,
        architecture,
        read(shell, inputs.identifier, architecture) if architecture else None,
    )


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, NodeEvidence):
        raise ValueError("Site Node selection needs validated native evidence.")
    state = evidence.state
    refusals = []
    selected = ""
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before selecting a site runtime.")
    if evidence.architecture is None or state is None:
        refusals.append("The site's current native state could not be read.")
    else:
        selected = state["profiles"].get(inputs.selection, "")
        if not selected:
            refusals.append("Choose a known installed Node runtime.")
        site = next(
            (site for site in state["native"]["sites"] if site["identifier"] == inputs.identifier),
            None,
        )
        if site is None or (
            site["state"] != "complete"
            and site["problem"] != "The site's Node command links have an interrupted selection."
        ):
            refusals.append(site["problem"] if site else "The site was not observed.")
    unchanged = state is not None and state["selection"] == inputs.selection
    document: dict[str, object] = {
        **inputs.document(),
        "body_sha256": BODY_SHA256,
        "architecture": str(evidence.architecture or ""),
        "path": selected,
        "precondition_digest": state["digest"] if state else "",
        "details": [
            {"label": "Site Node runtime", "value": inputs.selection},
            {"label": "Exact installed build", "value": selected},
            {
                "label": "Command links",
                "value": (
                    "bin/node, bin/npm and bin/npx; PHP pools and server defaults are unchanged."
                ),
            },
        ],
    }
    return ReviewDraft(
        SLUG,
        f"Set {inputs.identifier}'s Node runtime to {inputs.selection}.",
        effects=()
        if refusals or unchanged
        else (
            DeclaredEffect(
                Scope.SITE,
                "Select this site's Node, npm and npx command links.",
                (inputs.identifier,),
            ),
        ),
        sites_read=(
            "find /etc/caddy/sites -maxdepth 1 -type f -name "
            + shlex.quote(inputs.identifier + ".caddy")
            + " -printf '%f\\n' | sed 's/\\.caddy$//'"
        )
        if state
        else "",
        current_sites=(inputs.identifier,) if state else None,
        stages=("preflight", "links", "verify"),
        refusals=tuple(refusals),
        document=document,
        boot_id=state["native"]["boot"] if state else "",
        uptime_centiseconds=state["native"]["uptime"] if state else None,
    )


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    decode_inputs(
        {key: document.get(key) for key in ("version", "identifier", "selection")},
        CHOICES,
        InputShape.SITE_RUNTIME,
    )
    if document.get("body_sha256") != BODY_SHA256:
        raise ValueError("Unknown site Node payload.")
    try:
        architecture = Architecture(str(document.get("architecture")))
    except ValueError:
        raise ValueError("Unknown catalog architecture.") from None
    path = document.get("path")
    build = load().identify(architecture, path) if isinstance(path, str) else None
    if build is None or build.entry != document["selection"]:
        raise ValueError("Unknown reviewed installed Node build.")
    digest = document.get("precondition_digest")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(c not in "0123456789abcdef" for c in digest)
    ):
        raise ValueError("Invalid native precondition.")
    encoded = base64.b64encode(gzip.compress(json.dumps(document).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES, (encoded,))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    body(stored.document, BodyContext("", "", 0))
    architecture = Architecture(str(stored.document["architecture"]))
    state = read(shell, str(stored.document["identifier"]), architecture)
    if state is None:
        return None
    return (
        state["selection"] == stored.document["selection"]
        and state["profiles"][state["selection"]] == stored.document["path"]
        and not state["problem"]
    )


SET_SITE_NODE: Final = ChangeKind(
    SLUG,
    "Select site Node runtime",
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_choices=CHOICES,
    input_shape=InputShape.SITE_RUNTIME,
)
