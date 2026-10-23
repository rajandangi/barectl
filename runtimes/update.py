"""Apply the catalog builds a newer Barectl release ships (Phase B #386).

docs/php-versions.md, docs/runtimes.md, ADR 0028 and ADR 0038. The review names every
installed entry whose profile is an older catalog build, the affected sites, and the
services it restarts. PHP entries move their sites through the same private-admission
drain a site PHP selection uses; the previous generation stays until the new build
verifies, then older generations are collected.
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import re
import shlex
from dataclasses import dataclass, field
from typing import Final

from bootstrap.standing import Standing
from discovery.models import ObservationOutcome, SiteState
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import PreparationInputs
from operations.models import ChangeReview
from sites import php_change
from sites.bodies.php_runtime import PHPState, missing_php_modules
from sites.observation import SITE_IDENTIFIERS_COMMAND

from .catalog import Architecture, Kind, architecture_of, load
from .updates import CatalogUpdate, updates, usage_by_entry

SLUG: Final = "update_catalog"
LABEL: Final = "Update catalog builds"
STAGES: Final = ("preflight", "realise", "sites", "profiles", "verify", "collect")
_PACKAGE: Final = importlib.resources.files("runtimes.bodies")
_UPDATE_RAW: Final = _PACKAGE.joinpath("update.py").read_text()
_START: Final = "# COMPOSED-SITE-PROGRAM:"
_END: Final = "# END-COMPOSED-SITE-PROGRAM"
UPDATE_SOURCE: Final = (
    _UPDATE_RAW[: _UPDATE_RAW.index(_START)] + _UPDATE_RAW[_UPDATE_RAW.index(_END) + len(_END) :]
)
BODY_SOURCE: Final = php_change.SOURCE + "\n" + UPDATE_SOURCE
_PACKED: Final = base64.b64encode(gzip.compress(BODY_SOURCE.encode(), mtime=0)).decode()
_CODE: Final = (
    "import base64,gzip,json,sys\n"
    "exec(gzip.decompress(base64.b64decode(" + repr(_PACKED) + ")))\n"
    "update_catalog(json.loads(gzip.decompress(base64.b64decode(sys.argv[1]))))\n"
)
BODY_BYTES: Final = ("#!/bin/sh\nexec python3 -c " + shlex.quote(_CODE) + ' "$@"').encode()
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()
_DIGEST = re.compile(r"[0-9a-f]{64}")
_BOOT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}")
SITE_FILES: Final = SITE_IDENTIFIERS_COMMAND


@dataclass(frozen=True)
class Profiles:
    boot: str
    uptime: int
    paths: dict[str, str]
    # Each profile's preceding Nix generation, when it names another catalog build.
    previous: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class UpdateEvidence:
    architecture: Architecture | None
    standing: Standing | None
    profiles: Profiles | None
    detected: tuple[CatalogUpdate, ...]
    states: dict[str, PHPState | None]
    site_names: tuple[str, ...]
    site_files: dict[str, str]
    sites_outcome: ObservationOutcome
    incomplete_sites: tuple[str, ...]


def profile_command() -> str:
    entries = sorted({build.entry for build in load().builds})
    steps = [
        "printf 'boot\\t%s\\n' \"$(cat /proc/sys/kernel/random/boot_id)\"",
        "printf 'uptime\\t%s\\n' \"$(cut -d' ' -f1 /proc/uptime | tr -d .)\"",
        (
            "for entry in "
            + " ".join(entries)
            + '; do profile="/nix/var/nix/profiles/barectl/$entry"; '
            + 'link=$(readlink "$profile" 2>/dev/null || true); '
            + "printf '%s\\t%s\\n' \"$entry\" "
            + '"$(readlink -f "$profile" 2>/dev/null || true)"; '
            + "number=${link%-link}; number=${number##*-}; "
            + 'case "$number" in '
            + "'' | *[!0-9]* | 1) printf 'previous:%s\\t\\n' \"$entry\";; "
            + "*) printf 'previous:%s\\t%s\\n' \"$entry\" "
            + '"$(readlink -f "/nix/var/nix/profiles/barectl/$entry-$((number - 1))-link" '
            + '2>/dev/null || true)";; esac; done'
        ),
    ]
    return "sh -c " + shlex.quote("; ".join([*native.read_lock_steps(), *steps]))


def read_profiles(shell: RemoteShell) -> Profiles | None:
    result = run_root(shell, profile_command())
    if result.exit_status or result.truncated:
        return None
    entries = {build.entry for build in load().builds}
    values: dict[str, str] = {}
    previous: dict[str, str] = {}
    boot = ""
    uptime: int | None = None
    for line in result.stdout.splitlines():
        name, separator, value = line.partition("\t")
        if not separator:
            return None
        if name == "boot":
            boot = value
        elif name == "uptime":
            if not value.isdecimal():
                return None
            uptime = int(value)
        elif name.startswith("previous:") and name[9:] in entries and name[9:] not in previous:
            previous[name[9:]] = value
        elif name in entries and name not in values:
            values[name] = value
        else:
            return None
    if not _BOOT.fullmatch(boot) or uptime is None or not values:
        return None
    return Profiles(boot, uptime, values, previous)


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> UpdateEvidence:
    from discovery.observations import collect

    snapshot = collect(shell)
    architecture = architecture_of(snapshot.architecture.value or "")
    profiles = read_profiles(shell) if architecture is not None else None
    usage = usage_by_entry(snapshot.sites.value)
    detected = (
        updates(architecture, profiles.paths, usage)
        if architecture is not None and profiles is not None
        else ()
    )
    states: dict[str, PHPState | None] = {}
    if architecture is not None:
        for update in detected:
            if update.kind is not Kind.PHP:
                continue
            for identifier in update.sites:
                states[identifier] = php_change.read(shell, identifier, architecture)
    site_names = tuple(
        sorted(
            site.identifier
            for site in snapshot.sites.value
            if site.identifier and site.file.startswith("/etc/caddy/sites/")
        )
    )
    return UpdateEvidence(
        architecture,
        snapshot.standing.standing if snapshot.standing else None,
        profiles,
        detected,
        states,
        site_names,
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


def _refusals(evidence: UpdateEvidence) -> list[str]:  # noqa: C901 - one review
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before updating its catalog.")
    if evidence.sites_outcome != ObservationOutcome.OBSERVED:
        refusals.append("The server's site inventory could not be read.")
    if evidence.incomplete_sites and any(update.kind is Kind.PHP for update in evidence.detected):
        refusals.append(
            "A site's PHP transition is incomplete. Finish or reverse it on the site's "
            "Runtime page before updating a PHP runtime."
        )
    if evidence.architecture is None or evidence.profiles is None:
        refusals.append("The installed profile paths could not be read.")
        return refusals
    for update in evidence.detected:
        if update.kind is not Kind.PHP:
            continue
        for identifier in update.sites:
            file = evidence.site_files.get(identifier, "")
            if not file.startswith("/etc/caddy/sites/"):
                refusals.append(
                    f"Site {identifier} selects {update.entry} but is outside supported "
                    "settings. Repair it before updating the runtime."
                )
        if not update.sites:
            continue
        other = "php85" if update.entry == "php84" else "php84"
        other_path = evidence.profiles.paths.get(other, "")
        other_build = load().identify(evidence.architecture, other_path) if other_path else None
        if other_build is None or other_build.entry != other:
            refusals.append(
                f"Updating {update.entry} needs the other PHP runtime installed so its sites "
                "keep serving during the switch. Add runtime "
                + ("php85" if other == "php85" else "php84")
                + " first."
            )
            continue
        for identifier in update.sites:
            state = evidence.states.get(identifier)
            if state is None:
                refusals.append(f"Site {identifier}'s native serving evidence is unavailable.")
                continue
            if state["profiles"].get(update.entry) != update.installed.path:
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
    return refusals


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, UpdateEvidence):
        raise ValueError("A catalog update needs validated native evidence.")
    refusals = _refusals(evidence)
    detected = evidence.detected
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "architecture": str(evidence.architecture or ""),
        "entries": _entries(evidence),
        "states": {
            identifier: state["digest"]
            for identifier, state in evidence.states.items()
            if state is not None
        },
        "details": _details(detected),
    }
    boot_id = evidence.profiles.boot if evidence.profiles else ""
    uptime = evidence.profiles.uptime if evidence.profiles else None
    if not detected:
        document["note"] = "Every installed catalog build is the one this release offers."
        return ReviewDraft(
            kind=SLUG,
            intent="Update the server's catalog builds.",
            stages=STAGES,
            refusals=tuple(refusals),
            boot_id=boot_id,
            uptime_centiseconds=uptime,
            document=document,
            current_sites=evidence.site_names,
            sites_read=SITE_FILES,
        )
    sites = tuple(sorted({site for update in detected for site in update.sites}))
    return ReviewDraft(
        kind=SLUG,
        intent="Update the server's catalog builds.",
        effects=()
        if refusals
        else (
            DeclaredEffect(
                Scope.SHARED,
                (
                    "Replace "
                    + ", ".join(update.entry for update in detected)
                    + " with the builds this Barectl release ships. Each listed PHP site moves "
                    "through its private admission drain; Caddy and HAProxy restart where listed."
                ),
                sites,
            ),
        ),
        stages=STAGES,
        postconditions=(
            "Every updated profile selects this release's exact catalog build.",
            "Every affected site serves from its original runtime on the new build.",
            "Caddy and every site proxy serve their reviewed configuration.",
            "The previous generation stays; older generations are collected afterwards.",
        ),
        refusals=tuple(refusals),
        boot_id=boot_id,
        uptime_centiseconds=uptime,
        document=document,
        current_sites=evidence.site_names,
        sites_read=SITE_FILES,
    )


def _entries(evidence: UpdateEvidence) -> list[dict[str, object]]:
    return [
        {
            "entry": update.entry,
            "kind": update.kind.value,
            "from": update.installed.path,
            "to": update.offered.path,
            "from_version": update.installed.version,
            "to_version": update.offered.version,
            "sites": list(update.sites),
        }
        for update in evidence.detected
    ]


def _details(detected: tuple[CatalogUpdate, ...]) -> list[dict[str, str]]:
    details = [
        {
            "label": entry_label(update.entry),
            "value": (
                f"{update.installed.version} ({update.installed.path}) to "
                f"{update.offered.version} ({update.offered.path})"
            ),
        }
        for update in detected
    ]
    php_sites = tuple(
        sorted({site for update in detected if update.kind is Kind.PHP for site in update.sites})
    )
    details.append(
        {
            "label": "Sites moving",
            "value": ", ".join(php_sites)
            if php_sites
            else "No site selects an updated PHP runtime.",
        }
    )
    services = [update.entry for update in detected if update.restarts_service]
    details.append(
        {
            "label": "Services restarted",
            "value": (
                ", ".join(services) + " and each site's private proxy process"
                if services
                else "No web server or proxy restart."
            ),
        }
    )
    details.append(
        {
            "label": "Requests",
            "value": (
                "Each listed PHP site keeps serving through its private proxy while its masters "
                "switch. A Caddy or HAProxy update restarts that service, as listed above."
            ),
        }
    )
    details.append(
        {
            "label": "Previous generation",
            "value": (
                "Kept until every profile and site verifies. Older generations are then "
                "collected, never the active one or its predecessor. A failure after a "
                "profile changes leaves each site serving on whichever runtime holds it; "
                "its Runtime page finishes or reverses that selection."
            ),
        }
    )
    return details


def entry_label(entry: str) -> str:
    return entry.replace("nodejs_", "Node.js ").replace("php", "PHP ")


@dataclass(frozen=True)
class ReviewedUpdate:
    entry: str
    kind: Kind
    from_path: str
    to_path: str
    sites: tuple[str, ...]


def decode_document(
    document: dict[str, object],
) -> tuple[Architecture, tuple[ReviewedUpdate, ...], dict[str, str]]:
    architecture = document.get("architecture")
    entries = document.get("entries")
    states = document.get("states")
    if (
        type(document.get("version")) is not int
        or document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or not isinstance(architecture, str)
        or architecture not in tuple(Architecture)
        or not isinstance(entries, list)
        or not entries
        or not isinstance(states, dict)
    ):
        raise ValueError("Unsupported catalog update.")
    catalog = load()
    known_entries = {build.entry for build in catalog.builds}
    reviewed: list[ReviewedUpdate] = []
    seen: set[str] = set()
    php_sites: set[str] = set()
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("Unsupported catalog update entry.")
        entry = item.get("entry")
        kind = item.get("kind")
        source, target = item.get("from"), item.get("to")
        sites = item.get("sites")
        if (
            not isinstance(entry, str)
            or entry not in known_entries
            or entry in seen
            or not isinstance(kind, str)
            or not isinstance(source, str)
            or not isinstance(target, str)
            or not isinstance(sites, list)
            or not all(isinstance(site, str) and _IDENTIFIER.fullmatch(site) for site in sites)
            or len(set(sites)) != len(sites)
        ):
            raise ValueError("Unsupported catalog update entry.")
        installed = catalog.identify(Architecture(architecture), source)
        target_build = catalog.identify(Architecture(architecture), target)
        if (
            installed is None
            or target_build is None
            or installed.entry != entry
            or target_build.entry != entry
            or installed.path == target_build.path
            or kind != target_build.kind.value
            or item.get("from_version") != installed.version
            or item.get("to_version") != target_build.version
        ):
            raise ValueError("The catalog update is not the reviewed build.")
        seen.add(entry)
        if kind == Kind.PHP.value:
            php_sites.update(str(site) for site in sites)
        reviewed.append(
            ReviewedUpdate(entry, target_build.kind, source, target, tuple(str(s) for s in sites))
        )
    if reviewed != sorted(reviewed, key=lambda row: row.entry):
        raise ValueError("The catalog update entries are not the reviewed set.")
    if set(states) != php_sites or not all(
        isinstance(value, str) and _DIGEST.fullmatch(value) for value in states.values()
    ):
        raise ValueError("The catalog update has no reviewed site state.")
    return (
        Architecture(architecture),
        tuple(reviewed),
        {str(key): str(value) for key, value in states.items()},
    )


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    _architecture, entries, states = decode_document(document)
    payload = {
        "version": 1,
        "entries": [
            {
                "entry": row.entry,
                "kind": row.kind.value,
                "from": row.from_path,
                "to": row.to_path,
                "sites": list(row.sites),
            }
            for row in entries
        ],
        "states": states,
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES, (encoded,))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    architecture, entries, _states = decode_document(stored.document)
    profiles = read_profiles(shell)
    if profiles is None:
        return None
    for row in entries:
        if profiles.paths.get(row.entry) != row.to_path:
            return False
        if row.kind is not Kind.PHP:
            continue
        for identifier in row.sites:
            state = php_change.read(shell, identifier, architecture)
            if (
                state is None
                or not state["complete"]
                or state["proxy"]["selection"] != row.entry
                or state["profiles"].get(row.entry) != row.to_path
            ):
                return False
    if any(row.entry == "caddy" for row in entries):
        result = run_root(shell, "systemctl is-active --quiet caddy.service")
        if result.exit_status:
            return False
    return True


UPDATE_CATALOG: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    refresh_discovery=True,
)
