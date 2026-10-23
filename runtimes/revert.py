"""Revert one installed runtime to its preceding Nix generation (Phase B #386).

The review names the exact current and previous catalog builds, the sites that select the
runtime and the requests that keep serving through the private drain. The native body is the
same reviewed replacement a catalog update uses, so a site moves to the other installed PHP
runtime, the profile returns to its predecessor, and the site moves back without refused
requests. The current generation stays installed; a later collection keeps it as the
successor generation.
"""

from dataclasses import dataclass
from typing import Final

from bootstrap.standing import Standing
from discovery.models import ObservationOutcome, SiteState
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import PreparationInputs
from operations.models import ChangeReview
from sites import php_change
from sites.bodies.php_runtime import PHPState, missing_php_modules
from sites.observation import SITE_IDENTIFIERS_COMMAND

from . import update
from .catalog import Architecture, Build, Kind, architecture_of, load
from .updates import usage_by_entry

SLUG: Final = "revert_runtime"
LABEL: Final = "Revert runtime build"
STAGES: Final = update.STAGES
PHP_ENTRIES: Final = ("php84", "php85")


@dataclass(frozen=True)
class RevertEvidence:
    architecture: Architecture | None
    standing: Standing | None
    profiles: update.Profiles | None
    states: dict[str, PHPState | None]
    sites: tuple[str, ...]
    site_names: tuple[str, ...]
    site_files: dict[str, str]
    sites_outcome: ObservationOutcome
    incomplete_sites: tuple[str, ...]


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> RevertEvidence:
    from discovery.observations import collect

    snapshot = collect(shell)
    architecture = architecture_of(snapshot.architecture.value or "")
    profiles = update.read_profiles(shell) if architecture is not None else None
    sites = usage_by_entry(snapshot.sites.value).get(inputs.selection, ())
    states: dict[str, PHPState | None] = {}
    if architecture is not None:
        for identifier in sites:
            states[identifier] = php_change.read(shell, identifier, architecture)
    return RevertEvidence(
        architecture,
        snapshot.standing.standing if snapshot.standing else None,
        profiles,
        states,
        sites,
        tuple(
            sorted(
                site.identifier
                for site in snapshot.sites.value
                if site.identifier and site.file.startswith("/etc/caddy/sites/")
            )
        ),
        {site.identifier: site.file for site in snapshot.sites.value if site.identifier},
        snapshot.sites.outcome,
        tuple(
            sorted(
                site.identifier
                for site in snapshot.sites.value
                if site.identifier and site.state == SiteState.PARTLY_APPLIED
            )
        ),
    )


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:  # noqa: C901 - one review
    if not isinstance(evidence, RevertEvidence):
        raise ValueError("A runtime revert needs validated native evidence.")
    selection = inputs.selection
    profiles = evidence.profiles
    refusals: list[str] = []
    current = profiles.paths.get(selection, "") if profiles is not None else ""
    previous = profiles.previous.get(selection, "") if profiles is not None else ""
    current_build = (
        load().identify(evidence.architecture, current)
        if evidence.architecture is not None and current
        else None
    )
    previous_build = (
        load().identify(evidence.architecture, previous)
        if evidence.architecture is not None and previous
        else None
    )
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before reverting a runtime.")
    if evidence.sites_outcome != ObservationOutcome.OBSERVED:
        refusals.append("The server's site inventory could not be read.")
    if evidence.incomplete_sites:
        refusals.append(
            "A site's PHP transition is incomplete. Finish or reverse it on the site's "
            "Runtime page before reverting a PHP runtime."
        )
    if evidence.architecture is None or profiles is None:
        refusals.append("The installed profile paths could not be read.")
    elif not current_build or current_build.entry != selection:
        refusals.append("The current runtime is not a known catalog build.")
    elif not previous_build or previous_build.entry != selection:
        refusals.append(
            "The runtime has no earlier generation that is a known catalog build, so there is "
            "nothing to revert to."
        )
    if evidence.sites and evidence.architecture is not None and profiles is not None:
        other = "php85" if selection == "php84" else "php84"
        other_path = profiles.paths.get(other, "")
        other_build = load().identify(evidence.architecture, other_path) if other_path else None
        if other_build is None or other_build.entry != other:
            refusals.append(
                f"Reverting {selection} needs the other PHP runtime installed so its sites keep "
                "serving during the switch."
            )
        for identifier in evidence.sites:
            state = evidence.states.get(identifier)
            if state is None:
                refusals.append(f"Site {identifier}'s native serving evidence is unavailable.")
                continue
            if state["profiles"].get(selection) != current:
                refusals.append(f"Site {identifier}'s installed runtime changed after discovery.")
                continue
            try:
                missing = missing_php_modules(state, other)
            except ValueError as error:
                refusals.append(str(error))
                continue
            if missing:
                refusals.append(
                    f"Site {identifier} loads modules {other} does not offer: " + ", ".join(missing)
                )
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": update.BODY_SHA256,
        "architecture": str(evidence.architecture or ""),
        "entries": _entries(selection, current_build, previous_build, evidence.sites),
        "states": {
            identifier: state["digest"]
            for identifier, state in evidence.states.items()
            if state is not None
        },
        "details": _details(selection, current_build, previous_build, evidence.sites),
    }
    return ReviewDraft(
        kind=SLUG,
        intent=f"Revert {selection} to its previous build.",
        effects=()
        if refusals
        else (
            DeclaredEffect(
                Scope.SHARED,
                (
                    f"Replace the {selection} profile with its previous catalog build. Each "
                    "listed site moves through its private admission drain and back."
                ),
                evidence.sites,
            ),
        ),
        stages=STAGES,
        postconditions=(
            "The runtime profile selects its previous catalog build.",
            "Every affected site serves again from that runtime without refused requests.",
            "The replaced generation stays installed for a later recovery.",
        ),
        refusals=tuple(refusals),
        boot_id=profiles.boot if profiles is not None else "",
        uptime_centiseconds=profiles.uptime if profiles is not None else None,
        document=document,
        current_sites=evidence.site_names,
        sites_read=SITE_IDENTIFIERS_COMMAND,
    )


def _entries(
    selection: str, current: Build | None, previous: Build | None, sites: tuple[str, ...]
) -> list[dict[str, object]]:
    if current is None or previous is None:
        return []
    return [
        {
            "entry": selection,
            "kind": Kind.PHP.value,
            "from": current.path,
            "to": previous.path,
            "from_version": current.version,
            "to_version": previous.version,
            "sites": list(sites),
        }
    ]


def _details(
    selection: str, current: Build | None, previous: Build | None, sites: tuple[str, ...]
) -> list[dict[str, str]]:
    if current is None or previous is None:
        return []
    return [
        {
            "label": "Runtime",
            "value": f"{selection}: {current.version} to {previous.version}",
        },
        {
            "label": "Exact builds",
            "value": f"{current.path} to {previous.path}",
        },
        {
            "label": "Sites moving",
            "value": ", ".join(sites) or "No site selects this runtime.",
        },
        {
            "label": "Requests",
            "value": (
                "Each listed site keeps serving through its private proxy while its masters switch."
            ),
        },
        {
            "label": "Generations",
            "value": (
                "The replaced generation stays installed; older ones are collected after the "
                "revert verifies."
            ),
        },
    ]


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    return update.body(document, context)


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    return update.verify(shell, stored)


REVERT_RUNTIME: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    refresh_discovery=True,
    input_choices=PHP_ENTRIES,
)
