"""Replace the recovery passphrase through one reviewed Shared change (#408).

The review names every repository restic will reopen: each enabled site's onsite repository
and, when offsite storage is set up, its offsite repository. Applying adds the new key,
proves it opens each repository, and only then removes the old key. The old and new
passphrases travel only through the confidential input channel; neither is stored, and no
data is re-encrypted.
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import shlex
from dataclasses import dataclass
from typing import Final

from automation.bodies.source import without_imports
from bootstrap.standing import Standing
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview

from . import convention, observation, offsite

SLUG: Final = "replace_recovery_passphrase"
LABEL: Final = "Replace recovery passphrase"
STAGES: Final = ("preflight", "keys", "verify")
OLD_LABEL: Final = "Current recovery passphrase"
NEW_LABEL: Final = "New recovery passphrase (at least 12 characters)"
NOTE: Final = (
    "restic keeps the data and the server key. Replacing the passphrase adds a new key and "
    "removes the old one; it never re-encrypts a backup. Barectl never stores either "
    "passphrase."
)

NATIVE_SOURCE: Final = importlib.resources.files("backups.bodies").joinpath("native.py").read_text()
KEYS_CORE: Final = without_imports(
    importlib.resources.files("backups.bodies").joinpath("keys.py").read_text(),
    ("backups.bodies.native",),
)
KEYS_SOURCE: Final = NATIVE_SOURCE + "\n" + KEYS_CORE
KEYS_BYTES: Final = (
    (
        "#!/bin/sh\nexec python3 -c "
        + shlex.quote(
            "import base64,gzip; exec(gzip.decompress(base64.b64decode("
            + repr(base64.b64encode(gzip.compress(KEYS_SOURCE.encode(), mtime=0)).decode())
            + ")))"
        )
        + ' "$@"\n'
    )
    .encode()
    .rstrip(b"\n")
)
KEYS_SHA256: Final = hashlib.sha256(KEYS_BYTES).hexdigest()


@dataclass(frozen=True)
class KeysEvidence:
    standing: Standing | None
    restic_path: str
    sites: tuple[str, ...]
    enabled: tuple[str, ...]
    offsite: observation.OffsiteStorage | None
    boot_id: str
    uptime_centiseconds: int | None
    problem: str = ""


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> KeysEvidence:
    storage = offsite.inspect_storage(shell, inputs)
    return KeysEvidence(
        storage.standing,
        storage.restic_path,
        storage.sites,
        storage.enabled,
        storage.offsite,
        storage.boot_id,
        storage.uptime_centiseconds,
        storage.problem,
    )


def _config(storage: observation.OffsiteStorage | None) -> dict[str, str]:
    if storage is None or not storage.configured:
        return {}
    return {
        "provider": storage.provider,
        "bucket": storage.bucket,
        "region": storage.region,
        "endpoint": storage.endpoint,
        "prefix": storage.prefix,
        "prune": "yes" if storage.prune else "no",
    }


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, KeysEvidence):
        raise ValueError("Replacing the recovery passphrase needs native evidence.")
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before changing the passphrase.")
    if not evidence.restic_path:
        refusals.append("Enable backups for at least one site first.")
    if evidence.problem:
        refusals.append(evidence.problem)
    if not evidence.enabled:
        refusals.append("Enable backups for at least one site first.")
    config = _config(evidence.offsite)
    repositories = [f"{convention.repository(site)} (onsite)" for site in evidence.enabled]
    if config:
        repositories.extend(
            f"{convention.offsite_repository(config, site)} (offsite)" for site in evidence.enabled
        )
    details = [
        {"label": "Sites", "value": ", ".join(evidence.enabled)},
        {
            "label": "Repositories",
            "value": "Every enabled site's onsite repository"
            + (
                ", and its offsite repository." if config else ", and no offsite storage is set up."
            ),
        },
        {
            "label": "Data",
            "value": "The backups are not re-encrypted. The server key keeps working.",
        },
    ]
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": KEYS_SHA256,
        "config": config,
        "config_path": convention.OFFSITE_CONFIG,
        "capture_path": convention.OFFSITE_CAPTURE,
        "sites": list(evidence.enabled),
        "repositories": repositories,
        "stages": list(STAGES),
        "details": details,
        "note": NOTE,
        "secret_fields": [
            {"key": "old_passphrase", "label": OLD_LABEL, "secret": True},
            {"key": "new_passphrase", "label": NEW_LABEL, "secret": True},
        ],
    }
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals:
        effects = (
            DeclaredEffect(
                Scope.SHARED,
                (
                    "Replace the recovery passphrase on every enabled site repository "
                    "without re-encrypting any backup."
                ),
                evidence.enabled,
            ),
        )
    return ReviewDraft(
        kind=SLUG,
        intent="Replace the recovery passphrase.",
        effects=effects,
        stages=STAGES if effects else (),
        postconditions=(
            "Every site repository opens with the new recovery passphrase.",
            "The old recovery passphrase no longer opens any of them.",
            "Every server key still opens its repository and no backup was rewritten.",
        )
        if effects
        else (),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        sites_read=offsite.ALL_SITES_READ if effects else "",
        current_sites=evidence.sites if effects else None,
        document=document,
        writes_secrets=True,
    )


def _document(document: dict[str, object]) -> dict[str, str]:
    if document.get("version") != 1 or document.get("body_sha256") != KEYS_SHA256:
        raise ValueError("Unsupported passphrase review.")
    raw = document.get("config")
    if not isinstance(raw, dict):
        raise ValueError("The passphrase review is not a supported change.")
    values = {str(name): str(value) for name, value in raw.items()}
    if values:
        convention.read_config(convention.render_config(values))
    sites = document.get("sites")
    if (
        not isinstance(sites, list)
        or not sites
        or not all(
            isinstance(site, str) and convention.SITE_IDENTIFIER.fullmatch(site) for site in sites
        )
        or len(set(sites)) != len(sites)
        or document.get("config_path") != convention.OFFSITE_CONFIG
        or document.get("capture_path") != convention.OFFSITE_CAPTURE
    ):
        raise ValueError("The passphrase review is not a supported change.")
    return values


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    config = _document(document)
    if not context.secret_path:
        raise ValueError("Replacing the recovery passphrase needs both passphrases.")
    payload = {
        "version": 1,
        "config": config,
        "config_path": convention.OFFSITE_CONFIG,
        "capture_path": convention.OFFSITE_CAPTURE,
        "sites": document["sites"],
        "secret_path": context.secret_path,
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(KEYS_BYTES, (encoded,))


def verify(shell: RemoteShell, review: ChangeReview) -> bool | None:
    config = _document(review.document)
    sites = [str(site) for site in review.document["sites"]]
    # The server key opens every onsite repository; the offsite ones use the same key with
    # the root-only capture environment. No passphrase is needed or stored.
    commands = [
        " ".join(
            [
                "/usr/bin/env",
                f"RESTIC_REPOSITORY={shlex.quote(convention.repository(site))}",
                f"RESTIC_PASSWORD_FILE={shlex.quote(convention.server_key(site))}",
                f"RESTIC_CACHE_DIR={shlex.quote(convention.CACHE_DIR)}",
                shlex.quote(convention.RESTIC_BIN),
                "snapshots",
                "--json",
                "--no-lock",
            ]
        )
        for site in sites
    ]
    if config:
        commands.extend(
            convention.offsite_restic_command(site, config, "snapshots", "--json", "--no-lock")
            for site in sites
        )
    result = run_root(shell, " && ".join(commands))
    return result.exit_status == 0 and not result.truncated


REPLACE: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    refresh_discovery=True,
    input_shape=InputShape.REPLACE_RECOVERY_PASSPHRASE,
    writes_secrets=True,
)
