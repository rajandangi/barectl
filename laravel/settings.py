"""Edit a Laravel site's environment as one reviewed change (Phase B #383).

The review reads key names and server-computed digests only. Changed values travel through
ADR 0032's confidential channel, the body rewrites only the changed lines as the site user
at 0600, and Laravel's cached configuration is rebuilt when one is in use.
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
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from sites import observation as site_observation
from sites.bodies.common import NativeState, SiteRecord
from sites.change import membership_command
from sites.configuration import PHP_RUNTIMES

from . import observation
from .bodies.common import ENVIRONMENT_KEY, NON_SECRET_KEYS

SLUG: Final = "edit_laravel_environment"
LABEL: Final = "Edit Laravel environment"
BODY_SOURCE: Final = (
    observation.LARAVEL_SOURCE
    + "\n"
    + importlib.resources.files("laravel.bodies")
    .joinpath("settings.py")
    .read_text()
    .replace(
        "from laravel.bodies.common import (\n"
        "    ENVIRONMENT_KEY,\n"
        "    _private_file_ok,\n"
        "    apply_environment,\n"
        "    environment_entries_from_text,\n"
        "    environment_path,\n"
        "    read_environment,\n"
        "    user_command,\n"
        ")\n",
        "",
    )
    .replace(
        "from sites.bodies.common import open_site_lock, result, setting, site_account, stage\n",
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
class EnvironmentEvidence:
    standing: Standing | None
    native: NativeState | None
    laravel: dict[str, object] | None


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> EnvironmentEvidence:
    from discovery.observations import collect

    snapshot = collect(shell, sites=False)
    return EnvironmentEvidence(
        snapshot.standing.standing if snapshot.standing else None,
        site_observation.read(shell, "observed", "", protections=False),
        observation.read(shell),
    )


def _site_of(native: NativeState, identifier: str) -> SiteRecord | None:
    return next((row for row in native["sites"] if row["identifier"] == identifier), None)


def _laravel_of(value: dict[str, object] | None, identifier: str) -> dict[str, object] | None:
    if value is None:
        return None
    return observation.site(value, identifier)


def _entries(row: dict[str, object]) -> dict[str, dict[str, object]]:
    details = row.get("environment_details")
    entries: dict[str, dict[str, object]] = {}
    if isinstance(details, list):
        for detail in details:
            if isinstance(detail, dict) and isinstance(detail.get("key"), str):
                entries[str(detail["key"])] = detail
    return entries


def _refusals(
    evidence: EnvironmentEvidence, identifier: str
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
    if site["runtime"] not in PHP_RUNTIMES or site["account"] is None:
        refusals.append("The site's PHP runtime or Linux account is not observed.")
    laravel = _laravel_of(evidence.laravel, identifier)
    if laravel is None:
        refusals.append("The site's environment could not be read.")
    elif laravel["application"] != "laravel":
        refusals.append("This site has no Laravel release to configure.")
    elif not (isinstance(laravel["shared"], dict) and laravel["shared"].get("environment")):
        refusals.append("The site's private environment file is missing or unsafe.")
    return refusals, site, laravel


def _details(
    row: dict[str, object] | None,
    changes: list[dict[str, object]],
    entries: dict[str, dict[str, object]],
) -> list[dict[str, str]]:
    details = [
        {"label": "Site", "value": str(row["identifier"]) if row is not None else ""},
        {
            "label": "Laravel",
            "value": (
                f"Release {row['current']}"
                if row is not None and row.get("current")
                else "Not observed"
            ),
        },
    ]
    for change in changes:
        key = str(change["key"])
        entry = entries.get(key)
        previous = (
            str(entry.get("value", ""))
            if entry is not None and "value" in entry
            else ("Hidden, write-only" if entry is not None else "Not set")
        )
        details.append(
            {
                "label": key,
                "value": (
                    f"Remove (currently {previous})"
                    if change["action"] == "remove"
                    else (
                        f"Set from {previous}"
                        if entry is not None
                        else "Add with the value typed on this confirm screen"
                    )
                ),
            }
        )
    return details


def _change_list(inputs: PreparationInputs) -> list[dict[str, object]]:
    return [{"key": key, "action": action, "digest": ""} for key, action in inputs.settings_changes]


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, EnvironmentEvidence):
        raise ValueError("An environment change needs native evidence.")
    refusals, site, laravel = _refusals(evidence, inputs.identifier)
    entries = _entries(laravel) if laravel is not None else {}
    changes = _change_list(inputs)
    if inputs.settings_changes:
        for key, action in inputs.settings_changes:
            if action == "remove" and key not in entries:
                refusals.append(f"{key} is not in this site's environment.")
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": inputs.identifier,
        "details": _details(laravel, changes, entries),
    }
    secret_fields = [
        {
            "key": key,
            "secret": key not in NON_SECRET_KEYS,
            "label": f"New value for {key}",
        }
        for key, action in inputs.settings_changes
        if action == "set"
    ]
    if site is not None and laravel is not None:
        digest = str(laravel.get("environment_digest", ""))
        for change in changes:
            entry = entries.get(str(change["key"]))
            change["digest"] = str(entry["digest"]) if entry is not None else ""
        document.update(
            names=list(site["names"]),
            selection=site["runtime"],
            https=bool(site["https"]),
            changes=changes,
            secret_fields=secret_fields,
            environment_digest=digest,
            precondition_digest=evidence.native["digest"] if evidence.native is not None else "",
        )
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals:
        effects = (
            DeclaredEffect(
                Scope.SITE,
                f"Change {len(changes)} key(s) in {inputs.identifier}'s private environment.",
                (inputs.identifier,),
            ),
        )
    stages = (
        ("preflight", "write", "config", "verify")
        if secret_fields
        else ("preflight", "write", "verify")
    )
    return ReviewDraft(
        SLUG,
        f"Edit the environment of {inputs.identifier}.",
        effects=effects,
        stages=stages,
        postconditions=(
            "Only the reviewed keys changed; every other line is byte-identical.",
            "The environment stays a site-owned private file at 0600.",
            "Laravel's cached configuration is rebuilt when one is in use.",
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
        or not isinstance(document.get("environment_digest"), str)
        or DIGEST.fullmatch(str(document["environment_digest"])) is None
    ):
        raise ValueError("The environment review is not a valid immutable native selection.")
    changes: list[dict[str, object]] = []
    for change in raw:
        if not isinstance(change, dict) or set(change) != {"key", "action", "digest"}:
            raise ValueError("The environment review is not a valid immutable native selection.")
        key, action, digest = change["key"], change["action"], change["digest"]
        if (
            not isinstance(key, str)
            or ENVIRONMENT_KEY.fullmatch(key) is None
            or action not in ("set", "remove")
            or not isinstance(digest, str)
        ):
            raise ValueError("The environment review is not a valid immutable native selection.")
        changes.append({"key": key, "action": action, "digest": digest})
    fields = document.get("secret_fields")
    if not isinstance(fields, list):
        raise ValueError("The environment review is not a valid immutable native selection.")
    return {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": str(document.get("identifier", "")),
        "names": names,
        "selection": document["selection"],
        "https": document["https"],
        "changes": changes,
        "secret_fields": fields,
        "environment_digest": document["environment_digest"],
    }


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    value = _document(document)
    if value["secret_fields"] and not context.secret_path:
        raise ValueError("The environment review needs a staged confidential value.")
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
    if row is None or row["application"] != "laravel":
        return False
    environment = row.get("environment")
    if not isinstance(environment, list):
        return False
    keys = set(environment)
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


EDIT_ENVIRONMENT: Final = ChangeKind(
    SLUG,
    LABEL,
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    writes_secrets=True,
    input_shape=InputShape.LARAVEL_ENVIRONMENT,
)
