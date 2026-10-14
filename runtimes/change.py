"""Add one exact offered runtime through the engine's four operational parts."""

import base64
import gzip
import hashlib
import importlib.resources
from dataclasses import dataclass
from typing import Final

from bootstrap.standing import Standing
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import PreparationInputs
from operations.models import ChangeReview

from . import observation
from .catalog import Architecture, Build, architecture_of, load
from .configuration import ENTRIES, PROBE, render

SLUG: Final = "add_runtime"
STAGES: Final = ("preflight", "realise", "configure", "validate", "verify")
BODY_BYTES: Final = (
    importlib.resources.files("runtimes.bodies").joinpath("add.sh").read_bytes().rstrip(b"\n")
)
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()


@dataclass(frozen=True)
class RuntimeEvidence:
    architecture: Architecture | None
    standing: Standing | None
    native: dict[str, object] | None


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> RuntimeEvidence:
    from discovery.observations import collect

    snapshot = collect(shell)
    architecture = architecture_of(snapshot.architecture.value or "")
    values = observation.read(shell, inputs.selection, architecture) if architecture else None
    return RuntimeEvidence(
        architecture, snapshot.standing.standing if snapshot.standing else None, values
    )


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, RuntimeEvidence):
        raise ValueError("Add runtime needs validated native evidence.")
    document: dict[str, object] = {"version": 1, "body_sha256": BODY_SHA256}
    refusals = []
    build: Build | None = None
    existing = False
    if evidence.architecture:
        build = next(
            (
                b
                for b in load().offered(evidence.architecture)
                if b.entry == inputs.selection and b.entry in ENTRIES
            ),
            None,
        )
    if build is None:
        refusals.append("This runtime is not offered for the observed architecture.")
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before adding a runtime.")
    values = evidence.native
    if values is None:
        refusals.append("Barectl could not read the runtime's native evidence.")
    elif build:
        if values.get("admissible") is not True:
            refusals.append(
                "Runtime paths, shared configuration or diagnostic identity "
                "do not follow the convention."
            )
        existing, runtime_refusals = _existing(values, build)
        refusals.extend(runtime_refusals)
        fcgi = next(b for b in load().offered(build.architecture) if b.entry == "fcgi")
        document.update(
            selection=build.entry,
            architecture=str(build.architecture),
            path=build.path,
            fcgi_path=fcgi.path,
            precondition_digest=values["digest"],
        )
        files = render(build.entry) if build.kind.value == "php" else None
        document["details"] = [
            {"label": "Catalog entry", "value": build.entry},
            {"label": "Exact store path", "value": build.path},
            {"label": "FastCGI client", "value": fcgi.path},
            {"label": "PHP-FPM unit", "value": files.unit if files else "No service; profile only"},
            {"label": "PHP ini", "value": files.ini if files else "Not applicable"},
            {"label": "Initial private pool", "value": files.pool if files else "Not applicable"},
        ]
    return ReviewDraft(
        kind=SLUG,
        intent=f"Add runtime {inputs.selection}.",
        effects=()
        if refusals or existing
        else (
            DeclaredEffect(
                Scope.SERVER,
                f"Add the {inputs.selection} runtime profile "
                "and its shared PHP master when applicable.",
            ),
        ),
        stages=STAGES,
        postconditions=(
            "The exact catalog build is selected by its native profile.",
            (
                "PHP masters report mandatory protections through their private live pool. "
                "Node starts no service."
            ),
        ),
        refusals=tuple(refusals),
        boot_id=str(values["boot"]) if values else "",
        uptime_centiseconds=values["uptime"]
        if values and isinstance(values["uptime"], int)
        else None,
        document=document,
    )


def _existing(values: dict[str, object], build: Build) -> tuple[bool, tuple[str, ...]]:
    rows = observation.observations(values["runtimes"], build.architecture)
    current = next((row for row in rows if row.entry == build.entry), None)
    if current is not None:
        if current.problem:
            return True, (current.problem,)
        if current.path != build.path:
            return True, (
                (
                    "This runtime has an earlier catalog build. "
                    "A separate reviewed build update is required."
                ),
            )
        return True, ()
    return False, ()


def decode_document(document: dict[str, object]) -> tuple[Build, str]:
    if (
        type(document.get("version")) is not int
        or document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
    ):
        raise ValueError("Unknown runtime review version or body.")
    architecture = document.get("architecture")
    selection, path = document.get("selection"), document.get("path")
    digest = document.get("precondition_digest")
    if (
        not isinstance(architecture, str)
        or architecture not in tuple(Architecture)
        or not isinstance(selection, str)
        or selection not in ENTRIES
    ):
        raise ValueError("Invalid reviewed runtime selection.")
    build = next(
        (
            b
            for b in load().offered(Architecture(architecture))
            if b.entry == selection and b.path == path
        ),
        None,
    )
    fcgi = next(b for b in load().offered(Architecture(architecture)) if b.entry == "fcgi")
    if (
        build is None
        or document.get("fcgi_path") != fcgi.path
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(c not in "0123456789abcdef" for c in digest)
    ):
        raise ValueError("Invalid reviewed runtime paths or evidence.")
    return build, fcgi.path


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    build, fcgi = decode_document(document)
    files = render(build.entry) if build.kind.value == "php" else None
    encoded = tuple(
        base64.b64encode(text.encode()).decode()
        for text in (
            PROBE,
            files.ini if files else "",
            files.master if files else "",
            files.pool if files else "",
            files.unit if files else "",
        )
    )
    return NativeBody(
        BODY_BYTES,
        (
            build.entry,
            build.path,
            fcgi,
            str(document["precondition_digest"]),
            base64.b64encode(gzip.compress(observation.READ_SOURCE.encode(), mtime=0)).decode(),
            *encoded,
        ),
    )


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    build, _ = decode_document(stored.document)
    value = observation.read(shell, build.entry, build.architecture)
    if value is None:
        return None
    rows = observation.observations(value["runtimes"], build.architecture)
    return any(
        row.entry == build.entry and row.path == build.path and row.manageable for row in rows
    )


ADD_RUNTIME: Final = ChangeKind(
    slug=SLUG,
    label="Add runtime",
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    refresh_discovery=True,
    input_choices=ENTRIES,
)
