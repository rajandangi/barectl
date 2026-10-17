"""Observed native command defaults and reviewed link changes."""

import base64
import gzip
import hashlib
import importlib.resources
import json
import re
import shlex
from dataclasses import dataclass
from typing import Final

from bootstrap.standing import Standing
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import PreparationInputs
from operations.models import ChangeReview

from .catalog import Architecture, architecture_of, load

PHP_CHOICES: Final = ("php84", "php85")
NODE_CHOICES: Final = ("nodejs_22", "nodejs_24")
SOURCE: Final = importlib.resources.files("runtimes.bodies").joinpath("defaults.py").read_text()
BODY_BYTES: Final = (
    (
        "#!/bin/sh\ntrap 'rm -f -- \"$0\"' EXIT\npython3 -c "
        + shlex.quote(
            "import base64,gzip; exec(gzip.decompress(base64.b64decode("
            + repr(base64.b64encode(gzip.compress(SOURCE.encode(), mtime=0)).decode())
            + ")))"
        )
        + ' "$@"\n'
    )
    .encode()
    .rstrip(b"\n")
)
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()


@dataclass(frozen=True)
class DefaultEvidence:
    architecture: Architecture | None
    standing: Standing | None
    native: dict[str, object] | None


@dataclass(frozen=True)
class DefaultsObservation:
    php: str = ""
    node: str = ""
    php_problem: str = ""
    node_problem: str = ""
    php_choices: tuple[str, ...] = ()
    node_choices: tuple[str, ...] = ()


def known(architecture: Architecture) -> dict[str, tuple[str, ...]]:
    return {
        entry: tuple(
            build.path
            for build in load().builds
            if build.architecture == architecture and build.entry == entry
        )
        for entry in (*PHP_CHOICES, *NODE_CHOICES, "composer", "wp-cli")
    }


def read(shell: RemoteShell, architecture: Architecture) -> dict[str, object] | None:
    source = SOURCE.replace(
        "KNOWN: dict[str, tuple[str, ...]] = {}", "KNOWN = " + repr(known(architecture))
    )
    command = shlex.join(["python3", "-c", source, "read"])
    result = run_root(
        shell,
        "sh -c " + shlex.quote("; ".join([*native.read_lock_steps(), "exec " + command])),
    )
    if result.exit_status or result.truncated:
        return None
    try:
        value: object = json.loads(result.stdout)
    except ValueError:
        return None
    if not isinstance(value, dict) or set(value) != {
        "boot",
        "uptime",
        "digest",
        "profiles",
        "helpers",
        "php",
        "node",
        "php_problem",
        "node_problem",
    }:
        return None
    if (
        not isinstance(value["boot"], str)
        or re.fullmatch(r"[a-f0-9-]{36}", value["boot"]) is None
        or type(value["uptime"]) is not int
        or value["uptime"] < 0
        or not isinstance(value["digest"], str)
        or re.fullmatch(r"[a-f0-9]{64}", value["digest"]) is None
        or not isinstance(value["profiles"], dict)
        or len(value["profiles"]) > 6
        or not isinstance(value["helpers"], list)
        or len(value["helpers"]) > 128
    ):
        return None
    profiles = value["profiles"]
    if any(
        not isinstance(entry, str)
        or not isinstance(path, str)
        or path not in known(architecture).get(entry, ())
        for entry, path in profiles.items()
    ):
        return None
    if any(
        not isinstance(path, str)
        or re.fullmatch(r"/nix/store/[a-z0-9]{32}-[A-Za-z0-9+._?=-]+/bin", path) is None
        for path in value["helpers"]
    ):
        return None
    if value["php"] not in ("", *PHP_CHOICES) or value["node"] not in ("", *NODE_CHOICES):
        return None
    for key in ("php", "node", "php_problem", "node_problem"):
        if not isinstance(value[key], str) or len(value[key]) > 1024:
            return None
    return value


def observations(value: dict[str, object] | None) -> DefaultsObservation:
    if value is None:
        return DefaultsObservation(
            "",
            "",
            "Default commands could not be read.",
            "Default commands could not be read.",
            (),
            (),
        )
    profiles = value["profiles"]
    if not isinstance(profiles, dict):
        raise ValueError("Invalid native default profiles.")
    return DefaultsObservation(
        str(value["php"]),
        str(value["node"]),
        str(value["php_problem"]),
        str(value["node_problem"]),
        tuple(entry for entry in PHP_CHOICES if entry in profiles),
        tuple(entry for entry in NODE_CHOICES if entry in profiles),
    )


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> DefaultEvidence:
    from discovery.observations import collect

    snapshot = collect(shell, sites=False)
    architecture = architecture_of(snapshot.architecture.value or "")
    return DefaultEvidence(
        architecture,
        snapshot.standing.standing if snapshot.standing else None,
        read(shell, architecture) if architecture else None,
    )


def _review(evidence: object, inputs: PreparationInputs, family: str) -> ReviewDraft:
    if not isinstance(evidence, DefaultEvidence):
        raise ValueError("Default changes need native evidence.")
    value = evidence.native
    refusals = []
    choices = PHP_CHOICES if family == "php" else NODE_CHOICES
    if inputs.selection not in choices:
        refusals.append("Select an installed runtime of the correct language.")
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Verify the target foundation before changing server defaults.")
    if value is None or evidence.architecture is None:
        refusals.append("The native default commands could not be read.")
    elif value[family + "_problem"]:
        refusals.append(str(value[family + "_problem"]))
    profiles = value.get("profiles") if value else None
    path = profiles.get(inputs.selection) if isinstance(profiles, dict) else None
    build = load().identify(evidence.architecture, str(path)) if evidence.architecture else None
    if build is None or build.entry != inputs.selection:
        refusals.append("The selected runtime is not installed from a known catalog build.")
    if (
        family == "php"
        and isinstance(profiles, dict)
        and any(entry not in profiles for entry in ("composer", "wp-cli"))
    ):
        refusals.append("The installed Composer and WP-CLI profiles must be known catalog builds.")
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "selection": inputs.selection,
        "architecture": str(evidence.architecture or ""),
        "path": path,
        "precondition_digest": value["digest"] if value else "",
        "known": known(evidence.architecture) if evidence.architecture else {},
        "details": [
            {"label": "Default runtime", "value": inputs.selection},
            {
                "label": "Existing sites",
                "value": "Their runtime links, sockets, pools and units stay unchanged.",
            },
        ],
    }
    unchanged = value is not None and value[family] == inputs.selection
    return ReviewDraft(
        kind="set_default_" + family,
        intent=f"Set the server's default {family.upper()} commands to {inputs.selection}.",
        effects=()
        if refusals or unchanged
        else (
            DeclaredEffect(
                Scope.SERVER, "Change the server's plain commands for operators and future sites."
            ),
        ),
        stages=("preflight", "commands"),
        refusals=tuple(refusals),
        postconditions=(
            "The plain commands execute the selected runtime.",
            "Existing sites keep their own selections.",
        ),
        boot_id=str(value["boot"]) if value else "",
        uptime_centiseconds=int(str(value["uptime"])) if value else None,
        document=document,
    )


def review_php(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    return _review(evidence, inputs, "php")


def review_node(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    return _review(evidence, inputs, "node")


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    try:
        architecture = Architecture(str(document["architecture"]))
    except KeyError, ValueError:
        raise ValueError("Invalid default runtime architecture.") from None
    selection = document.get("selection")
    build = load().identify(architecture, str(document.get("path")))
    if (
        type(document.get("version")) is not int
        or document["version"] != 1
        or document.get("body_sha256") != BODY_SHA256
        or selection not in (*PHP_CHOICES, *NODE_CHOICES)
        or build is None
        or build.entry != selection
        or json.dumps(document.get("known"), sort_keys=True)
        != json.dumps(known(architecture), sort_keys=True)
        or not isinstance(document.get("precondition_digest"), str)
        or re.fullmatch(r"[a-f0-9]{64}", str(document["precondition_digest"])) is None
    ):
        raise ValueError("The default review no longer matches its immutable native selection.")
    return NativeBody(BODY_BYTES, (json.dumps(document), json.dumps(known(architecture))))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    body(stored.document, BodyContext("", "", 0))
    value = read(shell, Architecture(str(stored.document["architecture"])))
    if value is None:
        return None
    selection = str(stored.document["selection"])
    family = "php" if selection in PHP_CHOICES else "node"
    return value[family] == selection and not value[family + "_problem"]


SET_DEFAULT_PHP: Final = ChangeKind(
    "set_default_php",
    "Set default PHP",
    inspect,
    review_php,
    body,
    verify,
    refresh_discovery=True,
    input_choices=PHP_CHOICES,
)
SET_DEFAULT_NODE: Final = ChangeKind(
    "set_default_node",
    "Set default Node",
    inspect,
    review_node,
    body,
    verify,
    refresh_discovery=True,
    input_choices=NODE_CHOICES,
)


def decode_observation(value: object) -> DefaultsObservation | None:
    if not isinstance(value, dict) or set(value) != {
        "php",
        "node",
        "php_problem",
        "node_problem",
        "php_choices",
        "node_choices",
    }:
        return None
    if any(
        not isinstance(value[key], str) or len(value[key]) > 1024
        for key in ("php", "node", "php_problem", "node_problem")
    ):
        return None
    if value["php"] not in ("", *PHP_CHOICES) or value["node"] not in ("", *NODE_CHOICES):
        return None
    for key, choices in (("php_choices", PHP_CHOICES), ("node_choices", NODE_CHOICES)):
        selected = value[key]
        if (
            not isinstance(selected, list)
            or len(selected) > len(choices)
            or any(item not in choices for item in selected)
            or len(set(selected)) != len(selected)
        ):
            return None
    return DefaultsObservation(
        str(value["php"]),
        str(value["node"]),
        str(value["php_problem"]),
        str(value["node_problem"]),
        tuple(value["php_choices"]),
        tuple(value["node_choices"]),
    )
