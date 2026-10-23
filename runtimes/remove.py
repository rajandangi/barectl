"""Remove a runtime profile no site and no server default uses (Phase B #386).

docs/php-versions.md, docs/runtimes.md and ADR 0028. The review names the exact catalog
build and every native file it deletes, and is refused while a site or a server default
selects the runtime. The native body rechecks the profile, the site wrappers and the
default commands under the mutation lock, stops the diagnostic master, removes only the
convention's configuration, deletes the profile's generations and collects what became
unreachable.
"""

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
from discovery.models import ObservationOutcome, SiteState
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import PreparationInputs
from operations.models import ChangeReview
from sites.observation import SITE_IDENTIFIERS_COMMAND

from . import observation as runtime_observation
from .catalog import Architecture, Build, Kind, architecture_of, load
from .configuration import ENTRIES, render
from .defaults import DefaultsObservation
from .defaults import known as known_defaults
from .defaults import observations as default_observations
from .defaults import read as read_defaults
from .observation import RuntimeObservation, observations

SLUG: Final = "remove_runtime"
LABEL: Final = "Remove runtime"
STAGES: Final = ("preflight", "services", "configuration", "profile", "collect", "verify")
PACKAGE: Final = importlib.resources.files("runtimes.bodies")
_DEFAULTS_SOURCE: Final = PACKAGE.joinpath("defaults.py").read_text()
_REMOVE_SOURCE: Final = PACKAGE.joinpath("remove.py").read_text()


def _packed(source: str) -> str:
    return base64.b64encode(gzip.compress(source.encode(), mtime=0)).decode()


BODY_BYTES: Final = (
    (
        "#!/bin/sh\n"
        "set -eu\n"
        "trap 'rm -f -- \"$0\"' EXIT\n"
        "python3 -c "
        + shlex.quote(
            "import base64,gzip; exec(gzip.decompress(base64.b64decode("
            + repr(_packed(_DEFAULTS_SOURCE))
            + ")))"
        )
        + ' read "$9" | python3 -c '
        + shlex.quote(
            "import base64,gzip; exec(gzip.decompress(base64.b64decode("
            + repr(_packed(_REMOVE_SOURCE))
            + ")))"
        )
        + ' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"\n'
    )
    .encode()
    .rstrip(b"\n")
)
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()
_GENERATION = re.compile(r"[a-z][a-z0-9_-]{0,31}-[0-9]{1,9}-link")
_DIGEST = re.compile(r"[0-9a-f]{64}")
SITE_FILES: Final = SITE_IDENTIFIERS_COMMAND


@dataclass(frozen=True)
class RemovalEvidence:
    architecture: Architecture | None
    standing: Standing | None
    native: dict[str, object] | None
    defaults: DefaultsObservation
    site_names: tuple[str, ...]
    site_runtime: tuple[tuple[str, str], ...]
    incomplete_sites: tuple[str, ...]
    sites_outcome: ObservationOutcome


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> RemovalEvidence:
    from discovery.observations import collect

    snapshot = collect(shell)
    architecture = architecture_of(snapshot.architecture.value or "")
    values = None
    defaults = DefaultsObservation()
    if architecture is not None and inputs.selection in ENTRIES:
        values = runtime_observation.read(shell, inputs.selection, architecture)
        defaults = default_observations(read_defaults(shell, architecture))
    names = tuple(
        sorted(
            site.identifier
            for site in snapshot.sites.value
            if site.identifier and site.file.startswith("/etc/caddy/sites/")
        )
    )
    runtimes = tuple(
        (site.identifier, site.php_version or site.node_runtime)
        for site in snapshot.sites.value
        if site.identifier
    )
    incomplete = tuple(
        sorted(
            site.identifier
            for site in snapshot.sites.value
            if site.identifier and site.state == SiteState.PARTLY_APPLIED
        )
    )
    return RemovalEvidence(
        architecture,
        snapshot.standing.standing if snapshot.standing else None,
        values,
        defaults,
        names,
        runtimes,
        incomplete,
        snapshot.sites.outcome,
    )


def _runtime_row(evidence: RemovalEvidence, selection: str) -> RuntimeObservation | None:
    if evidence.native is None or evidence.architecture is None:
        return None
    return next(
        (
            row
            for row in observations(evidence.native["runtimes"], evidence.architecture)
            if row.entry == selection
        ),
        None,
    )


def _build(evidence: RemovalEvidence, selection: str) -> Build | None:
    row = _runtime_row(evidence, selection)
    if row is None or not row.path or evidence.architecture is None:
        return None
    build = load().identify(evidence.architecture, row.path)
    if build is None or build.entry != selection:
        return None
    return build


def _using_sites(evidence: RemovalEvidence, selection: str) -> tuple[str, ...]:
    return tuple(
        sorted(
            identifier
            for identifier, entry in evidence.site_runtime
            if identifier and entry == selection
        )
    )


def _default_family(selection: str) -> str:
    return "php" if selection.startswith("php") else "node"


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:  # noqa: C901 - one review
    if not isinstance(evidence, RemovalEvidence):
        raise ValueError("Remove runtime needs validated native evidence.")
    selection = inputs.selection
    row = _runtime_row(evidence, selection)
    build = _build(evidence, selection)
    defaults = evidence.defaults
    family = _default_family(selection)
    default_problem = defaults.php_problem if family == "php" else defaults.node_problem
    default_entry = defaults.php if family == "php" else defaults.node
    using = _using_sites(evidence, selection)
    refusals: list[str] = []
    installed = build is not None
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before removing a runtime.")
    if evidence.architecture is None or evidence.native is None:
        refusals.append("The runtime's native profile evidence is unavailable.")
    elif row is not None and row.path and not installed:
        refusals.append(
            "The installed profile is not a known catalog build for this entry, so Barectl "
            "will not delete it. Remove it through ordinary administration."
        )
    if evidence.sites_outcome != ObservationOutcome.OBSERVED:
        refusals.append("The server's site inventory could not be read.")
    if family == "php" and evidence.incomplete_sites:
        refusals.append(
            "A site's PHP transition is incomplete. Finish or reverse it on the site's "
            "Runtime page before removing a PHP runtime."
        )
    if using:
        refusals.append(
            "Sites still select this runtime: " + ", ".join(using) + ". Move them first."
        )
    if default_entry == selection:
        refusals.append(
            f"The server default {family.upper()} commands select this runtime. Change the "
            "default before removing it."
        )
    elif default_problem:
        refusals.append(
            f"The server default {family.upper()} commands could not be verified: "
            + default_problem
        )
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "entry": selection,
        "kind": build.kind.value if build is not None else "",
        "architecture": str(evidence.architecture or ""),
        "path": row.path if row is not None else "",
        "generation": row.generation if row is not None else "",
        "build_version": build.version if build is not None else "",
        "precondition_digest": evidence.native["digest"] if evidence.native else "",
        "sites": list(using),
        "default": default_entry == selection,
        "details": _details(selection, row, build),
    }
    if not refusals and not installed:
        document["note"] = f"The {selection} runtime is not installed on this server."
        return ReviewDraft(
            kind=SLUG,
            intent=f"Remove runtime {selection}.",
            stages=STAGES,
            refusals=(),
            boot_id=str(evidence.native["boot"]) if evidence.native else "",
            uptime_centiseconds=evidence.native["uptime"]
            if evidence.native and isinstance(evidence.native["uptime"], int)
            else None,
            document=document,
            current_sites=evidence.site_names,
            sites_read=SITE_FILES,
        )
    effects = (
        (
            DeclaredEffect(
                Scope.SERVER,
                (
                    f"Delete the {selection} runtime profile and its generations, stop and "
                    "remove its native configuration, and collect the store paths that "
                    "become unreachable."
                ),
            ),
        )
        if not refusals
        else ()
    )
    return ReviewDraft(
        kind=SLUG,
        intent=f"Remove runtime {selection}.",
        effects=effects,
        stages=STAGES,
        postconditions=(
            "The runtime's profile, generations and native configuration are gone.",
            "No site or server default refers to the removed runtime.",
            "Other runtimes, sites and their services keep serving.",
        ),
        refusals=tuple(refusals),
        boot_id=str(evidence.native["boot"]) if evidence.native else "",
        uptime_centiseconds=evidence.native["uptime"]
        if evidence.native and isinstance(evidence.native["uptime"], int)
        else None,
        document=document,
        current_sites=evidence.site_names,
        sites_read=SITE_FILES,
    )


def _details(
    selection: str, row: RuntimeObservation | None, build: Build | None
) -> list[dict[str, str]]:
    kind = build.kind if build is not None else None
    version = build.version if build is not None else "Not installed"
    files = (
        [
            f"/etc/php-fpm/{selection}/php.ini",
            f"/etc/php-fpm/{selection}/php-fpm.conf",
            f"/etc/php-fpm/{selection}/pools/diagnostic.conf",
        ]
        if kind is Kind.PHP
        else []
    )
    return [
        {"label": "Runtime", "value": f"{selection} ({version})"},
        {"label": "Exact store path", "value": row.path if row is not None else "Not installed"},
        {
            "label": "Profile generation",
            "value": row.generation if row is not None and row.generation else "Not a link",
        },
        {
            "label": "Native configuration deleted",
            "value": "\n".join(files) or "Profile only; no service configuration.",
        },
        {
            "label": "Service",
            "value": (
                f"php-fpm@{selection}.service is stopped, disabled and removed with its "
                "configuration."
                if kind is Kind.PHP
                else "No service."
            ),
        },
        {
            "label": "Space",
            "value": (
                "The profile's generations are deleted and unreachable store paths are "
                "collected. Other runtimes and their generations stay."
            ),
        },
    ]


def decode_document(document: dict[str, object]) -> tuple[str, Kind, str, str, str, Architecture]:
    selection = document.get("entry")
    kind = document.get("kind")
    architecture = document.get("architecture")
    path = document.get("path")
    generation = document.get("generation")
    digest = document.get("precondition_digest")
    if (
        type(document.get("version")) is not int
        or document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or not isinstance(selection, str)
        or selection not in ENTRIES
        or kind not in tuple(item.value for item in Kind)
        or not isinstance(architecture, str)
        or architecture not in tuple(Architecture)
        or not isinstance(path, str)
        or not isinstance(generation, str)
        or (generation and _GENERATION.fullmatch(generation) is None)
        or not isinstance(digest, str)
        or _DIGEST.fullmatch(digest) is None
        or document.get("sites") != []
        or document.get("default") is not False
    ):
        raise ValueError("Unsupported runtime removal.")
    build = load().identify(Architecture(architecture), path)
    if build is None or build.entry != selection or build.kind.value != kind:
        raise ValueError("The runtime removal is not a known catalog build.")
    if kind == "php" and generation and not generation.startswith(selection + "-"):
        raise ValueError("The runtime removal names another profile's generation.")
    return selection, Kind(str(kind)), path, generation, digest, Architecture(architecture)


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    selection, kind, path, generation, digest, architecture = decode_document(document)
    files = render(selection) if kind is Kind.PHP else None
    arguments = (
        selection,
        kind.value,
        path,
        generation,
        digest,
        base64.b64encode(files.ini.encode()).decode() if files else "",
        base64.b64encode(files.master.encode()).decode() if files else "",
        base64.b64encode(files.pool.encode()).decode() if files else "",
        json.dumps(known_defaults(architecture), sort_keys=True),
    )
    return NativeBody(BODY_BYTES, arguments)


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    selection, kind, _path, _generation, _digest, architecture = decode_document(stored.document)
    value = runtime_observation.read(shell, selection, architecture)
    if value is None:
        return None
    if any(row.entry == selection for row in observations(value["runtimes"], architecture)):
        return False
    result = run_root(shell, _absence_command(selection, kind))
    if result.exit_status or result.truncated:
        return None
    return result.stdout.strip() == "absent"


def _absence_command(selection: str, kind: Kind) -> str:
    profile = f"/nix/var/nix/profiles/barectl/{selection}"
    paths = [profile]
    if kind is Kind.PHP:
        paths.append(f"/etc/php-fpm/{selection}")
    checks = " || ".join(
        f"[ -e {shlex.quote(path)} ] || [ -L {shlex.quote(path)} ]" for path in paths
    )
    generations = (
        "find /nix/var/nix/profiles/barectl -maxdepth 1 "
        f"-name {shlex.quote(selection + '-*-link')} -print -quit"
    )
    unit = (
        f"systemctl is-active --quiet php-fpm@{selection}.service" if kind is Kind.PHP else "false"
    )
    return (
        f'if {checks} || {unit} || [ -n "$({generations})" ]; '
        "then printf 'present\\n'; else printf 'absent\\n'; fi"
    )


REMOVE_RUNTIME: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    refresh_discovery=True,
    input_choices=ENTRIES,
)
