"""Edit a WordPress site's extra constants as one reviewed change (Phase B #383).

The review reads constant names and server-computed digests only. Changed values travel
through ADR 0032's confidential channel, and the body rewrites only the changed lines as the
site user at 0600. Barectl-owned names stay fixed in the private configuration.
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

from automation.bodies.source import AUTOMATION_SOURCE
from bootstrap.standing import Standing
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from sites import observation as site_observation
from sites.bodies.common import NativeState, SiteRecord
from sites.change import membership_command
from sites.configuration import PHP_RUNTIMES

from . import convention, observation

SLUG: Final = "edit_wordpress_settings"
LABEL: Final = "Edit WordPress settings"
BODY_SOURCE: Final = (
    AUTOMATION_SOURCE
    + "\n"
    + site_observation.COMMON_SOURCE
    + "\n"
    + importlib.resources.files("wordpress").joinpath("convention.py").read_text()
    + "\n"
    + importlib.resources.files("wordpress.bodies")
    .joinpath("settings.py")
    .read_text()
    .replace("from sites.bodies.common import open_site_lock, result, site_account, stage\n", "")
    .replace(
        "from wordpress.convention import (\n"
        "    apply_constants,\n"
        "    extra_constants,\n"
        "    private_configuration_path,\n"
        "    private_configuration_problem,\n"
        "    valid_constant_key,\n"
        "    write_as_site,\n"
        ")\n",
        "",
    )
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
DIGEST: Final = re.compile(r"[0-9a-f]{64}")
MAX_CHANGES: Final = 64


@dataclass(frozen=True)
class SettingsEvidence:
    standing: Standing | None
    native: NativeState | None
    constants: dict[str, object] | None


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> SettingsEvidence:
    from discovery.observations import collect

    snapshot = collect(shell, sites=False)
    return SettingsEvidence(
        snapshot.standing.standing if snapshot.standing else None,
        site_observation.read(shell, "observed", "", protections=False),
        observation.read(shell),
    )


def _site_of(native: NativeState, identifier: str) -> SiteRecord | None:
    return next((row for row in native["sites"] if row["identifier"] == identifier), None)


def _entries(row: dict[str, object] | None) -> dict[str, dict[str, object]]:
    entries: dict[str, dict[str, object]] = {}
    constants = row.get("constants") if row is not None else None
    if isinstance(constants, list):
        for constant in constants:
            if isinstance(constant, dict) and isinstance(constant.get("key"), str):
                entries[str(constant["key"])] = constant
    return entries


def _refusals(
    evidence: SettingsEvidence, identifier: str
) -> tuple[list[str], SiteRecord | None, dict[str, object] | None]:
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before changing a site.")
    if evidence.native is None:
        refusals.append("The site's native serving configuration could not be read.")
        return refusals, None, None
    site = _site_of(evidence.native, identifier)
    if site is None:
        refusals.append("The site was not observed in the current server configuration.")
        return refusals, None, None
    if site["state"] != "complete":
        refusals.append(site["problem"] or "The site is incomplete or outside supported settings.")
    if site["application"] != "wordpress":
        refusals.append("This site is not a WordPress application.")
    if site["runtime"] not in PHP_RUNTIMES or site["account"] is None:
        refusals.append("The site's PHP runtime or Linux account is not observed.")
    row = observation.site(evidence.constants, identifier) if evidence.constants else None
    if row is None:
        refusals.append("The private WordPress configuration could not be read.")
    return refusals, site, row


def _details(
    row: dict[str, object] | None,
    changes: list[dict[str, object]],
    entries: dict[str, dict[str, object]],
) -> list[dict[str, str]]:
    details = [
        {"label": "Site", "value": str(row["identifier"]) if row is not None else ""},
        {
            "label": "WordPress",
            "value": "WordPress constants live only in the private configuration file.",
        },
    ]
    for change in changes:
        key = str(change["key"])
        exists = key in entries
        details.append(
            {
                "label": key,
                "value": (
                    "Remove (currently hidden, write-only)"
                    if change["action"] == "remove"
                    else ("Set (currently hidden, write-only)" if exists else "Add")
                ),
            }
        )
    return details


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, SettingsEvidence):
        raise ValueError("A WordPress settings change needs native evidence.")
    refusals, site, row = _refusals(evidence, inputs.identifier)
    entries = _entries(row)
    changes: list[dict[str, object]] = [
        {"key": key, "action": action, "digest": ""} for key, action in inputs.settings_changes
    ]
    for key, action in inputs.settings_changes:
        if convention.reserved_constant(key):
            refusals.append(f"{key} is owned by Barectl and cannot be edited.")
        elif action == "remove" and key not in entries:
            refusals.append(f"{key} is not in this site's WordPress settings.")
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": inputs.identifier,
        "details": _details(row, changes, entries),
    }
    secret_fields = [
        {"key": key, "secret": True, "label": f"New value for {key}"}
        for key, action in inputs.settings_changes
        if action == "set" and not convention.reserved_constant(key)
    ]
    if site is not None and row is not None:
        for change in changes:
            entry = entries.get(str(change["key"]))
            change["digest"] = str(entry["digest"]) if entry is not None else ""
        document.update(
            names=list(site["names"]),
            selection=site["runtime"],
            https=bool(site["https"]),
            changes=changes,
            secret_fields=secret_fields,
            configuration_digest=str(row["digest"]),
            precondition_digest=evidence.native["digest"] if evidence.native is not None else "",
        )
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals:
        effects = (
            DeclaredEffect(
                Scope.SITE,
                f"Change {len(changes)} extra constant(s) in {inputs.identifier}'s private "
                "WordPress configuration.",
                (inputs.identifier,),
            ),
        )
    return ReviewDraft(
        SLUG,
        f"Edit the WordPress settings of {inputs.identifier}.",
        effects=effects,
        stages=("preflight", "write", "verify"),
        postconditions=(
            (
                "Only the reviewed constants changed; every fixed and untouched line stays "
                "byte-identical."
            ),
            "The private configuration stays a site-owned file at 0600.",
            "Barectl-owned names remain unchanged.",
        ),
        refusals=tuple(dict.fromkeys(refusals)),
        boot_id=str(evidence.native["boot"]) if evidence.native is not None else "",
        uptime_centiseconds=(
            int(str(evidence.native["uptime"])) if evidence.native is not None else None
        ),
        sites_read=(
            membership_command(str(site["runtime"]))
            if site is not None and site["runtime"] in PHP_RUNTIMES
            else ""
        ),
        current_sites=(inputs.identifier,) if site is not None else None,
        document=document,
        writes_secrets=bool(secret_fields),
    )


def _document(document: dict[str, object]) -> dict[str, object]:
    raw = document.get("changes")
    names = document.get("names")
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or not isinstance(raw, list)
        or not 1 <= len(raw) <= MAX_CHANGES
        or not isinstance(names, list)
        or not names
        or not all(isinstance(name, str) for name in names)
        or document.get("selection") not in PHP_RUNTIMES
        or type(document.get("https")) is not bool
        or not isinstance(document.get("configuration_digest"), str)
        or DIGEST.fullmatch(str(document["configuration_digest"])) is None
    ):
        raise ValueError("The WordPress settings review is not a valid immutable selection.")
    changes: list[dict[str, object]] = []
    for change in raw:
        if not isinstance(change, dict) or set(change) != {"key", "action", "digest"}:
            raise ValueError("The WordPress settings review is not a valid immutable selection.")
        key, action, digest = change["key"], change["action"], change["digest"]
        if (
            not isinstance(key, str)
            or not convention.valid_constant_key(key)
            or action not in ("set", "remove")
            or not isinstance(digest, str)
        ):
            raise ValueError("The WordPress settings review is not a valid immutable selection.")
        changes.append({"key": key, "action": action, "digest": digest})
    fields = document.get("secret_fields")
    if not isinstance(fields, list):
        raise ValueError("The WordPress settings review is not a valid immutable selection.")
    return {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": str(document.get("identifier", "")),
        "changes": changes,
        "secret_fields": fields,
        "configuration_digest": document["configuration_digest"],
    }


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    value = _document(document)
    if value["secret_fields"] and not context.secret_path:
        raise ValueError("The WordPress settings review needs a staged confidential value.")
    payload = {**value, "secret_path": context.secret_path}
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES.rstrip(b"\n"), (encoded,))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    document = stored.document
    identifier = str(document.get("identifier", ""))
    value = observation.read(shell)
    if value is None:
        return None
    row = observation.site(value, identifier)
    if row is None:
        return False
    raw_constants = row.get("constants", [])
    if not isinstance(raw_constants, list):
        return False
    keys = {str(entry["key"]) for entry in raw_constants if isinstance(entry, dict)}
    raw = document.get("changes", [])
    if not isinstance(raw, list):
        return False
    for change in raw:
        if not isinstance(change, dict):
            return False
        if change.get("action") == "remove" and change.get("key") in keys:
            return False
        if change.get("action") == "set" and change.get("key") not in keys:
            return False
    return True


EDIT_SETTINGS: Final = ChangeKind(
    SLUG,
    LABEL,
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    writes_secrets=True,
    input_shape=InputShape.WORDPRESS_SETTINGS,
)
