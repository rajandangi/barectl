"""Select a site's installed PHP through authenticated private admission (ADR 0038)."""

import base64
import gzip
import hashlib
import importlib.resources
import json
import re
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
from .bodies.admission import state_rows
from .bodies.php_runtime import PHPState, missing_php_modules

CHOICES: Final = ("php84", "php85")
SLUG: Final = "set_site_php"
SOURCE: Final = (
    observation.COMMON_SOURCE
    + "\n"
    + importlib.resources.files("sites.bodies")
    .joinpath("php_runtime.py")
    .read_text()
    .replace("import sites.bodies.common as common\n", "")
    .replace("from sites.bodies.site_fpm import site_fpm_idle\n", "")
    .replace("from sites.serving import php_directory\n", "")
    .replace("common.", "")
    .replace("import sites.bodies.admission as admission\n", "")
    .replace("admission.", "")
)
READ_SOURCE: Final = SOURCE + "\nprint(canonical(php_state(sys.argv[1])))\n"
BODY_SOURCE: Final = (
    SOURCE + "\nswitch_php(json.loads(gzip.decompress(base64.b64decode(sys.argv[1]))))\n"
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
class PHPEvidence:
    standing: Standing | None
    architecture: Architecture | None
    state: PHPState | None


def valid_module_set(value: object, *, allow_empty: bool = False) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= 256
        and (allow_empty or bool(value))
        and all(
            isinstance(name, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_ .-]{0,99}", name)
            for name in value
        )
        and value == sorted(set(value))
    )


def valid_php_service(value: object) -> bool:
    if value is None:
        return True
    if not isinstance(value, dict):
        return False
    pid, invocation, children = value.get("pid"), value.get("invocation"), value.get("app_pids")
    return (
        type(pid) is int
        and pid > 0
        and isinstance(invocation, str)
        and re.fullmatch(r"[0-9a-f]{32}", invocation) is not None
        and valid_module_set(value.get("extensions"))
        and isinstance(children, list)
        and len(children) == 2
        and all(type(child) is int and child > 0 for child in children)
        and len(set(children)) == 2
        and isinstance(value.get("load"), dict)
        and isinstance(value.get("protections"), dict)
    )


def valid_proxy_errors(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == set(CHOICES)
        and all(
            isinstance(counts, dict)
            and set(counts) == {"econ", "eresp", "cli_abrt", "srv_abrt"}
            and all(type(count) is int and 0 <= count < 2**64 for count in counts.values())
            for counts in value.values()
        )
    )


def valid_proxy(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "selection",
        "ready",
        "persistent",
        "state",
        "process",
        "digest",
        "errors",
    }:
        return False
    if value["selection"] not in ("", *CHOICES) or value["persistent"] not in CHOICES:
        return False
    ready, raw, process = value["ready"], value["state"], value["process"]
    if (
        not isinstance(ready, list)
        or not ready
        or len(ready) > 2
        or any(entry not in CHOICES for entry in ready)
        or len(set(ready)) != len(ready)
    ):
        return False
    if not isinstance(raw, str) or not isinstance(process, dict):
        return False
    try:
        rows = state_rows(raw)
    except ValueError:
        return False
    actual = [entry for entry, row in rows.items() if row[6] == "4"]
    if ready != actual or value["selection"] != (actual[0] if len(actual) == 1 else ""):
        return False
    return (
        type(process.get("pid")) is int
        and int(str(process["pid"])) > 0
        and isinstance(process.get("invocation"), str)
        and re.fullmatch(r"[0-9a-f]{32}", str(process["invocation"])) is not None
        and set(process) == {"pid", "invocation", "start", "files", "execution", "sockets"}
        and all(
            isinstance(process.get(key), dict) and bool(process[key])
            for key in ("files", "execution", "sockets")
        )
        and isinstance(process.get("start"), str)
        and str(process["start"]).isdecimal()
        and isinstance(value["digest"], str)
        and re.fullmatch(r"[0-9a-f]{64}", value["digest"]) is not None
        and valid_proxy_errors(value["errors"])
    )


def read(shell: RemoteShell, identifier: str, architecture: Architecture) -> PHPState | None:
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
    return decode_state(value, architecture, identifier)


def decode_state(value: object, architecture: Architecture, identifier: str) -> PHPState | None:
    if not isinstance(value, dict) or set(value) != {
        "native",
        "proxy",
        "services",
        "profiles",
        "modules",
        "builtins",
        "wrapper_runtime",
        "complete",
        "digest",
    }:
        return None
    if not isinstance(value["native"], dict) or not observation.valid_state(value["native"]):
        return None
    if (
        not valid_proxy(value["proxy"])
        or value["wrapper_runtime"] not in (*CHOICES, "")
        or type(value["complete"]) is not bool
    ):
        return None
    profiles, services, digest = value["profiles"], value["services"], value["digest"]
    modules, builtins = value["modules"], value["builtins"]
    if (
        not isinstance(builtins, dict)
        or set(builtins) != set(CHOICES)
        or not isinstance(modules, dict)
        or set(modules) != set(CHOICES)
        or not isinstance(profiles, dict)
        or set(profiles) != set(CHOICES)
        or not isinstance(services, dict)
        or set(services) != set(CHOICES)
    ):
        return None
    for entry in CHOICES:
        path, service = profiles[entry], services[entry]
        available = modules[entry]
        if not valid_module_set(available, allow_empty=not bool(path)) or not valid_module_set(
            builtins[entry], allow_empty=not bool(path)
        ):
            return None
        build = load().identify(architecture, path) if isinstance(path, str) and path else None
        if not isinstance(path, str) or (path and (build is None or build.entry != entry)):
            return None
        if not valid_php_service(service):
            return None
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(c not in "0123456789abcdef" for c in digest)
    ):
        return None
    state = cast(PHPState, value)
    return state if valid_php_selection(state, identifier) else None


def valid_php_selection(state: PHPState, identifier: str) -> bool:
    proxy, services = state["proxy"], state["services"]
    sites = [row for row in state["native"]["sites"] if row["identifier"] == identifier]
    if len(sites) != 1 or any(services[entry] is None for entry in proxy["ready"]):
        return False
    if services[proxy["persistent"]] is None:
        return False
    if state["complete"]:
        selected = proxy["selection"]
        other = "php85" if selected == "php84" else "php84"
        return (
            selected == proxy["persistent"] == state["wrapper_runtime"]
            and proxy["ready"] == [selected]
            and services[other] is None
            and sites[0]["state"] == "complete"
        )
    return True


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> PHPEvidence:
    from discovery.observations import collect

    # This preparation takes its affected sites from its own read, so the snapshot's site
    # inventory is unused; reading every other site's protections is the costliest part of
    # discovery on a multi-site host.
    snapshot = collect(shell, sites=False)
    architecture = architecture_of(snapshot.architecture.value or "")
    return PHPEvidence(
        snapshot.standing.standing if snapshot.standing else None,
        architecture,
        read(shell, inputs.identifier, architecture) if architecture else None,
    )


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, PHPEvidence):
        raise ValueError("PHP selection needs validated native evidence.")
    state = evidence.state
    refusals = []
    selected = ""
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before selecting a site runtime.")
    if evidence.architecture is None or state is None:
        refusals.append("The site's private native serving evidence is unavailable.")
    else:
        selected = state["profiles"].get(inputs.selection, "")
        if not selected:
            refusals.append("Choose a known installed PHP runtime.")
    missing = missing_php_modules(state, inputs.selection) if state is not None else []
    if missing:
        refusals.append(
            "The target PHP build is missing current optional modules: " + ", ".join(missing)
        )
    unchanged = (
        state is not None and state["complete"] and state["proxy"]["selection"] == inputs.selection
    )
    document: dict[str, object] = {
        **inputs.document(),
        "body_sha256": BODY_SHA256,
        "architecture": str(evidence.architecture or ""),
        "path": selected,
        "precondition_digest": state["digest"] if state else "",
        "details": [
            {"label": "Site PHP runtime", "value": inputs.selection},
            {"label": "Exact installed build", "value": selected},
            {"label": "Missing target modules", "value": ", ".join(missing) or "None"},
            {
                "label": "Admission",
                "value": "Native admission, durable restart selection and bounded source drain.",
            },
            {
                "label": "Incomplete drain",
                "value": "Preserve source PHP and require fresh review to finish or reverse.",
            },
        ],
    }
    return ReviewDraft(
        SLUG,
        f"Set {inputs.identifier}'s PHP runtime to {inputs.selection}.",
        effects=()
        if refusals or unchanged
        else (
            DeclaredEffect(
                Scope.SITE,
                "Switch this site's PHP service and PHP, Composer and WP commands.",
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
        stages=("preflight", "target", "admission", "persist", "drain", "commands", "verify"),
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
        raise ValueError("Unknown site PHP payload.")
    try:
        architecture = Architecture(str(document.get("architecture")))
    except ValueError:
        raise ValueError("Unknown catalog architecture.") from None
    path = document.get("path")
    build = load().identify(architecture, path) if isinstance(path, str) else None
    digest = document.get("precondition_digest")
    if (
        build is None
        or build.entry != document["selection"]
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(c not in "0123456789abcdef" for c in digest)
    ):
        raise ValueError("Invalid reviewed PHP build or precondition.")
    encoded = base64.b64encode(gzip.compress(json.dumps(document).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES, (encoded,))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    body(stored.document, BodyContext("", "", 0))
    state = read(
        shell,
        str(stored.document["identifier"]),
        Architecture(str(stored.document["architecture"])),
    )
    if state is None:
        return None
    selected = str(stored.document["selection"])
    return (
        state["complete"]
        and state["proxy"]["selection"] == selected
        and state["profiles"][selected] == stored.document["path"]
    )


SET_SITE_PHP: Final = ChangeKind(
    slug=SLUG,
    label="Select site PHP",
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    input_choices=CHOICES,
    input_shape=InputShape.SITE_RUNTIME,
    refresh_discovery=True,
)
