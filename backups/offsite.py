"""Offsite backup storage on Amazon S3 or Cloudflare R2 (Phase D #403).

Server **Settings > Backup storage** sets one provider and bucket, checks it is writable and
readable, and keeps the access keys only in root-owned environment files on the server. Each
site's offsite repository sits under one fixed server prefix and is initialised from the
onsite repository with copied chunker parameters, so copied snapshots deduplicate. A slow
copy holds a per-repository native lock and runs after a capture has reopened the site.
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import re
import secrets
import shlex
import stat
from dataclasses import dataclass
from typing import Final

from automation.bodies.source import without_imports
from bootstrap.standing import Standing
from databases import observation as database_observation
from discovery.observations import collect
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from runtimes.catalog import Architecture, architecture_of

from . import change, convention, observation

SETUP_SLUG: Final = "set_up_offsite_storage"
SETUP_LABEL: Final = "Set up offsite storage"
REMOVE_SLUG: Final = "remove_offsite_storage"
REMOVE_LABEL: Final = "Remove offsite storage"
COPY_SLUG: Final = "copy_offsite_again"
COPY_LABEL: Final = "Copy offsite again"
SETUP_STAGES: Final = ("preflight", "credentials", "bucket", "repositories", "verify")
REMOVE_STAGES: Final = ("preflight", "remove", "verify")
COPY_STAGES: Final = ("preflight", "lock", "copy", "verify")
OBJECT_LOCK: Final = (
    "Not configured. S3 Object Lock and R2 bucket locks are provider features outside "
    "Barectl, so offsite copies are not immutable and are not protected against deletion."
)
R2_PRUNING: Final = (
    "Not available. On Cloudflare R2 an Object Read & Write token can also delete objects, "
    "so Barectl cannot separate a capture key from a pruning key."
)
S3_PRUNING: Final = (
    "Optional. When you provide a separate pruning key, captures and copies use the other "
    "key, which cannot delete offsite history."
)
REMOVE_KEEPS: Final = (
    "Removing this setting deletes no offsite backup: every copy already in the bucket stays "
    "there. Barectl stops copying and forgets the keys on this server."
)
ALL_SITES_READ: Final = (
    "find /etc/caddy/sites -maxdepth 1 -type f -name '*.caddy' "
    "-printf '%f\\n' | sed 's/\\.caddy$//' | LC_ALL=C sort"
)
PRECONDITION_COMMAND: Final = "; ".join(
    [
        "printf 'boot\\t%s\\n' \"$(cat /proc/sys/kernel/random/boot_id)\"",
        "printf 'uptime\\t%s\\n' \"$(cut -d' ' -f1 /proc/uptime | tr -d .)\"",
        (
            f"printf 'config\\t%s\\n' \"$(stat -c '%u %g %a %f %s' "
            f'{convention.OFFSITE_CONFIG} 2>/dev/null || true)"'
        ),
        (
            f"printf 'root\\t%s\\n' \"$(stat -c '%u %g %a %f %s' "
            f'{convention.OFFSITE_ROOT} 2>/dev/null || true)"'
        ),
    ]
)
_BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_UPTIME = re.compile(r"[0-9]{1,16}")
_METADATA = re.compile(r"([0-9]+) ([0-9]+) ([0-7]{3,4}) ([0-9a-fA-F]+) ([0-9]+)")
_POINT = convention.POINT
STORAGE_UNSAFE = "The storage setting's files have unexpected ownership or permissions."
STORAGE_EMPTY = "The storage setting is empty or incomplete."
STORAGE_ROOT_UNSAFE = "The storage setting's directory has unexpected ownership or permissions."


def storage_metadata(value: str) -> tuple[int, int, int, int, int] | None:
    """Parse GNU stat's ``uid gid mode raw-mode size``: owner, group, mode, type, size."""
    found = _METADATA.fullmatch(value)
    if found is None:
        return None
    try:
        return (
            int(found[1]),
            int(found[2]),
            int(found[3], 8),
            int(found[4], 16),
            int(found[5]),
        )
    except ValueError:
        return None


def safe_storage_metadata(value: str, *, kind: int, mode: int, minimum_size: int = 0) -> bool:
    facts = storage_metadata(value)
    return bool(
        facts is not None
        and facts[0] == 0
        and facts[1] == 0
        and facts[2] == mode
        and stat.S_IFMT(facts[3]) == kind
        and facts[4] >= minimum_size
    )


def _packed(source: str) -> bytes:
    return (
        (
            "#!/bin/sh\nexec python3 -c "
            + shlex.quote(
                "import base64,gzip; exec(gzip.decompress(base64.b64decode("
                + repr(base64.b64encode(gzip.compress(source.encode(), mtime=0)).decode())
                + ")))"
            )
            + ' "$@"\n'
        )
        .encode()
        .rstrip(b"\n")
    )


NATIVE_SOURCE: Final = importlib.resources.files("backups.bodies").joinpath("native.py").read_text()
OFFSITE_CORE: Final = without_imports(
    importlib.resources.files("backups.bodies").joinpath("offsite.py").read_text(),
    ("backups.bodies.native",),
)
SETUP_SOURCE: Final = NATIVE_SOURCE + "\n" + OFFSITE_CORE
SETUP_BYTES: Final = _packed(SETUP_SOURCE)
SETUP_SHA256: Final = hashlib.sha256(SETUP_BYTES).hexdigest()
REMOVE_BYTES: Final = SETUP_BYTES
REMOVE_SHA256: Final = SETUP_SHA256
COPY_CORE: Final = without_imports(
    importlib.resources.files("backups.bodies").joinpath("copy.py").read_text(),
    ("backups.bodies.native",),
)
COPY_SOURCE: Final = NATIVE_SOURCE + "\n" + COPY_CORE
COPY_BYTES: Final = _packed(COPY_SOURCE)
COPY_SHA256: Final = hashlib.sha256(COPY_BYTES).hexdigest()


@dataclass(frozen=True)
class StorageEvidence:
    standing: Standing | None
    architecture: Architecture | None
    boot_id: str
    uptime_centiseconds: int | None
    restic_version: str
    restic_path: str
    sites: tuple[str, ...]
    enabled: tuple[str, ...]
    offsite: observation.OffsiteStorage | None
    problem: str


def _preconditions(shell: RemoteShell) -> tuple[str, int | None, str, str]:
    result = shell.run(PRECONDITION_COMMAND)
    values: dict[str, str] = {}
    if result.exit_status == 0 and not result.truncated:
        for line in result.stdout.splitlines():
            name, separator, value = line.partition("\t")
            if separator:
                values[name] = value
    uptime = values.get("uptime", "")
    return (
        values.get("boot", ""),
        int(uptime) if _UPTIME.fullmatch(uptime) else None,
        values.get("config", ""),
        values.get("root", ""),
    )


def inspect_storage(shell: RemoteShell, inputs: PreparationInputs) -> StorageEvidence:
    observed = collect(shell, sites=False)
    architecture = architecture_of(observed.architecture.value or "")
    path, version = observation.offered_restic(architecture)
    sites_result = shell.run(ALL_SITES_READ)
    sites = (
        tuple(sorted(sites_result.stdout.splitlines()))
        if sites_result.exit_status == 0 and not sites_result.truncated
        else ()
    )
    engines = database_observation.installed_engines(observed)
    engine = engines[0].engine if len(engines) == 1 and engines[0].managed else ""
    problem = ""
    enabled: tuple[str, ...] = ()
    offsite: observation.OffsiteStorage | None = None
    if sites:
        value = observation.read(shell, sites, engine, architecture)
        if value is None:
            problem = "The server's backup settings could not be read."
        else:
            offsite = observation.offsite_of(value)
            rows = value.get("sites")
            if isinstance(rows, list):
                enabled = tuple(
                    str(row["identifier"])
                    for row in rows
                    if isinstance(row, dict)
                    and row.get("repository") is True
                    and row.get("key") is True
                    and not row.get("problems")
                )
    elif sites_result.exit_status != 0 or sites_result.truncated:
        problem = "The server's sites could not be read."
    boot_id, uptime, config_metadata, root_metadata = _preconditions(shell)
    if config_metadata:
        facts = storage_metadata(config_metadata)
        if facts is None or not safe_storage_metadata(
            config_metadata, kind=stat.S_IFREG, mode=0o600
        ):
            problem = STORAGE_UNSAFE
        elif facts[4] == 0:
            problem = STORAGE_EMPTY
    if root_metadata and not safe_storage_metadata(root_metadata, kind=stat.S_IFDIR, mode=0o700):
        problem = STORAGE_ROOT_UNSAFE
    return StorageEvidence(
        observed.standing.standing if observed.standing else None,
        architecture,
        boot_id,
        uptime,
        version,
        path,
        sites,
        enabled,
        offsite,
        problem,
    )


def _storage_refusals(evidence: StorageEvidence) -> list[str]:
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before changing backup storage.")
    if evidence.architecture is None or not evidence.restic_path:
        refusals.append(
            "The pinned backup tool is unavailable for this architecture. Enable backups "
            "for one site first."
        )
    if evidence.problem:
        refusals.append(evidence.problem)
    if evidence.offsite is not None and evidence.offsite.problem:
        refusals.append(evidence.offsite.problem)
    if not _BOOT.fullmatch(evidence.boot_id) or evidence.uptime_centiseconds is None:
        refusals.append("The server's clock could not be read.")
    if not evidence.enabled:
        refusals.append("Enable backups for at least one site before adding offsite storage.")
    return refusals


def _config(
    inputs: PreparationInputs, existing: observation.OffsiteStorage | None
) -> dict[str, str]:
    url = convention.endpoint(inputs.provider, inputs.region, inputs.account)
    same = (
        existing is not None
        and existing.configured
        and existing.provider == inputs.provider
        and existing.bucket == inputs.bucket
        and existing.region == (inputs.region if inputs.provider == "s3" else "auto")
        and existing.endpoint == url
    )
    prefix = existing.prefix if same and existing is not None else "barectl/" + secrets.token_hex(8)
    return {
        "provider": inputs.provider,
        "bucket": inputs.bucket,
        "region": inputs.region if inputs.provider == "s3" else "auto",
        "endpoint": url,
        "prefix": prefix,
        "prune": "yes" if inputs.provider == "s3" else "no",
    }


def _secret_fields(provider: str) -> list[dict[str, object]]:
    fields: list[dict[str, object]] = [
        {"key": "access_key", "label": "Access key ID", "secret": False},
        {"key": "secret_key", "label": "Secret access key", "secret": True},
        {"key": "passphrase", "label": "Recovery passphrase", "secret": True},
    ]
    if provider == "s3":
        fields.extend(
            [
                {
                    "key": "prune_access_key",
                    "label": "Pruning access key ID (optional)",
                    "secret": False,
                    "required": False,
                },
                {
                    "key": "prune_secret_key",
                    "label": "Pruning secret access key (optional)",
                    "secret": True,
                    "required": False,
                },
            ]
        )
    return fields


def review_setup(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, StorageEvidence):
        raise ValueError("Setting up offsite storage needs native evidence.")
    refusals = _storage_refusals(evidence)
    if inputs.provider not in convention.PROVIDERS:
        refusals.append("Choose Amazon S3 or Cloudflare R2.")
    try:
        config = _config(inputs, evidence.offsite)
    except ValueError:
        refusals.append("Choose a supported bucket, region or account.")
        config = {
            "provider": "",
            "bucket": "",
            "region": "",
            "endpoint": "",
            "prefix": "",
            "prune": "no",
        }
    same = (
        not refusals
        and evidence.offsite is not None
        and evidence.offsite.configured
        and evidence.offsite.provider == config["provider"]
        and evidence.offsite.bucket == config["bucket"]
        and evidence.offsite.region == config["region"]
        and evidence.offsite.endpoint == config["endpoint"]
        and evidence.offsite.prefix == config["prefix"]
    )
    already = same
    details = [
        {"label": "Provider", "value": convention.PROVIDER_LABELS.get(inputs.provider, "")},
        {"label": "Bucket", "value": config["bucket"]},
        {
            "label": "Region" if inputs.provider == "s3" else "Account endpoint",
            "value": config["region"] if inputs.provider == "s3" else config["endpoint"],
        },
        {"label": "Prefix", "value": config["prefix"]},
        {
            "label": "Pruning key",
            "value": S3_PRUNING if inputs.provider == "s3" else R2_PRUNING,
        },
        {"label": "Object lock", "value": OBJECT_LOCK},
    ]
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": SETUP_SHA256,
        "config": config,
        "config_path": convention.OFFSITE_CONFIG,
        "capture_path": convention.OFFSITE_CAPTURE,
        "prune_path": convention.OFFSITE_PRUNE,
        "health_repository": convention.health_repository(config) if config["prefix"] else "",
        "health_key": convention.server_key(evidence.enabled[0]) if evidence.enabled else "",
        "sites": list(evidence.enabled),
        "stages": list(SETUP_STAGES),
        "details": details,
        "note": (
            "Barectl writes the access keys only to root-owned files on this server, checks "
            "the bucket can be written and listed, and keeps no key in its database."
        ),
        "secret_fields": _secret_fields(inputs.provider),
    }
    effects: tuple[DeclaredEffect, ...] = ()
    if already:
        document["note"] = "Offsite storage is already set up with these settings."
    elif not refusals:
        effects = (
            DeclaredEffect(
                Scope.SHARED,
                (
                    "Set up offsite backup storage for this server and initialise every "
                    "backed-up site's repository under it."
                ),
                evidence.sites,
            ),
        )
    return ReviewDraft(
        kind=SETUP_SLUG,
        intent="Set up offsite backup storage.",
        effects=effects,
        stages=SETUP_STAGES if effects else (),
        postconditions=(
            "The bucket answers writes and listings with the reviewed keys.",
            "Every backed-up site has an offsite repository initialised from its onsite one.",
            "The offsite keys live only in root-owned files on the server.",
        )
        if effects
        else (),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        sites_read=ALL_SITES_READ if effects else "",
        current_sites=evidence.sites if effects else None,
        document=document,
        writes_secrets=True,
    )


def review_remove(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, StorageEvidence):
        raise ValueError("Removing offsite storage needs native evidence.")
    refusals = _storage_refusals(evidence)
    configured = evidence.offsite is not None and evidence.offsite.configured
    if not configured:
        refusals.append("Offsite storage is not set up on this server.")
    storage = evidence.offsite
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": REMOVE_SHA256,
        "config": {
            "provider": storage.provider if storage else "",
            "bucket": storage.bucket if storage else "",
            "region": storage.region if storage else "",
            "endpoint": storage.endpoint if storage else "",
            "prefix": storage.prefix if storage else "",
            "prune": "yes" if storage is not None and storage.prune else "no",
        },
        "config_path": convention.OFFSITE_CONFIG,
        "capture_path": convention.OFFSITE_CAPTURE,
        "prune_path": convention.OFFSITE_PRUNE,
        "sites": list(evidence.sites),
        "stages": list(REMOVE_STAGES),
        "details": [
            {"label": "Provider", "value": storage.label if storage else ""},
            {"label": "Bucket", "value": storage.bucket if storage else ""},
            {"label": "Existing offsite copies", "value": REMOVE_KEEPS},
        ],
        "acknowledgement": (
            "I understand that removing offsite storage keeps every copy already in the bucket."
        ),
        "secret_fields": [
            {
                "key": "bucket",
                "label": "Type the bucket name to confirm",
                "secret": False,
            }
        ],
        "note": REMOVE_KEEPS,
    }
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals:
        effects = (
            DeclaredEffect(
                Scope.SHARED,
                (
                    "Remove this server's offsite storage setting and its root-only keys; "
                    "copies already in the bucket stay there."
                ),
                evidence.sites,
            ),
        )
    return ReviewDraft(
        kind=REMOVE_SLUG,
        intent="Remove offsite backup storage.",
        effects=effects,
        stages=REMOVE_STAGES if effects else (),
        postconditions=(
            "The offsite setting and its keys are gone from the server.",
            "Every offsite copy already in the bucket is unchanged.",
        )
        if effects
        else (),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        sites_read=ALL_SITES_READ if effects else "",
        current_sites=evidence.sites if effects else None,
        document=document,
        writes_secrets=True,
    )


def capture_plan(
    identifier: str, storage: observation.OffsiteStorage | None
) -> dict[str, object] | None:
    """The reviewed offsite destination a capture copies to, when storage is supported."""
    if storage is None or not storage.configured:
        return None
    config = {
        "provider": storage.provider,
        "bucket": storage.bucket,
        "region": storage.region,
        "endpoint": storage.endpoint,
        "prefix": storage.prefix,
        "prune": "yes" if storage.prune else "no",
    }
    return {
        "repository": convention.offsite_repository(config, identifier),
        "config": convention.OFFSITE_CONFIG,
        "capture_env": convention.OFFSITE_CAPTURE,
        "storage": config,
    }


def validate_capture(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    keys = {"repository", "config", "capture_env", "storage"}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("The offsite copy is not the reviewed one.")
    repository, config, capture_env, storage = (
        value["repository"],
        value["config"],
        value["capture_env"],
        value["storage"],
    )
    if (
        not isinstance(repository, str)
        or not repository.startswith("s3:https://")
        or config != convention.OFFSITE_CONFIG
        or capture_env != convention.OFFSITE_CAPTURE
        or not isinstance(storage, dict)
    ):
        raise ValueError("The offsite copy is not the reviewed one.")
    values = {str(key): str(item) for key, item in storage.items()}
    convention.read_config(convention.render_config(values))
    if not repository.startswith(f"s3:{values['endpoint']}/{values['bucket']}/{values['prefix']}/"):
        raise ValueError("The offsite copy is not the reviewed one.")
    return {
        "repository": repository,
        "config": convention.OFFSITE_CONFIG,
        "capture_env": convention.OFFSITE_CAPTURE,
        "storage": values,
    }


def inspect_copy(shell: RemoteShell, inputs: PreparationInputs) -> change.BackupEvidence:
    return change.inspect(shell, inputs)


def review_copy(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, change.BackupEvidence):
        raise ValueError("Copying a recovery point needs native evidence.")
    refusals = [*change._platform_refusals(evidence), *change._profile_refusals(evidence)]
    if evidence.backup is None or not evidence.backup.enabled:
        refusals.append("Enable backups for this site first.")
    if evidence.offsite is None or not evidence.offsite.configured:
        refusals.append("Set up offsite storage for this server first.")
    point = inputs.point
    if _POINT.fullmatch(point) is None:
        refusals.append("Choose a recovery point that is saved on the server.")
    plan = capture_plan(inputs.identifier, evidence.offsite)
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": COPY_SHA256,
        "identifier": inputs.identifier,
        "point": point,
        "repository": convention.repository(inputs.identifier),
        "server_key": convention.server_key(inputs.identifier),
        "offsite": plan,
        "stages": list(COPY_STAGES),
        "details": [
            {"label": "Recovery point", "value": point},
            {"label": "Site", "value": inputs.identifier},
            {
                "label": "Copied from",
                "value": "This server's encrypted onsite repository.",
            },
            {
                "label": "Offsite storage",
                "value": evidence.offsite.label if evidence.offsite else "",
            },
        ],
        "note": (
            "The copy holds a per-repository lock while it runs, so it never races another "
            "copy. If it fails, the recovery point saved here is unchanged."
        ),
    }
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals:
        effects = (
            DeclaredEffect(
                Scope.SITE,
                f"Copy one existing recovery point of {inputs.identifier} offsite again.",
                (inputs.identifier,),
            ),
        )
    return ReviewDraft(
        kind=COPY_SLUG,
        intent=f"Copy a recovery point of {inputs.identifier} offsite again.",
        effects=effects,
        stages=COPY_STAGES if effects else (),
        postconditions=(
            "The offsite repository holds the same complete recovery point.",
            "The recovery point saved on this server is unchanged.",
        )
        if effects
        else (),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        sites_read=change.sites_read(inputs.identifier) if effects else "",
        current_sites=(inputs.identifier,) if effects else None,
        document=document,
    )


def _document(document: dict[str, object], expected: str) -> None:
    if document.get("version") != 1 or document.get("body_sha256") != expected:
        raise ValueError("Unsupported offsite backup review.")


def _config_document(document: dict[str, object]) -> dict[str, str]:
    raw = document.get("config")
    if not isinstance(raw, dict):
        raise ValueError("The offsite storage review is not a supported setup.")
    values = {str(key): str(value) for key, value in raw.items()}
    if set(values) != {"provider", "bucket", "region", "endpoint", "prefix", "prune"}:
        raise ValueError("The offsite storage review is not a supported setup.")
    convention.read_config(convention.render_config(values))
    return values


def body_setup(document: dict[str, object], context: BodyContext) -> NativeBody:
    _document(document, SETUP_SHA256)
    if not context.secret_path:
        raise ValueError("Setting up offsite storage needs the access keys.")
    config = _config_document(document)
    sites = document.get("sites")
    if (
        not isinstance(sites, list)
        or not all(isinstance(site, str) for site in sites)
        or document.get("config_path") != convention.OFFSITE_CONFIG
        or document.get("capture_path") != convention.OFFSITE_CAPTURE
        or document.get("prune_path") != convention.OFFSITE_PRUNE
        or document.get("health_repository") != convention.health_repository(config)
        or not isinstance(document.get("health_key"), str)
        or not str(document["health_key"]).startswith(convention.KEY_ROOT + "/")
    ):
        raise ValueError("The offsite storage review is not a supported setup.")
    payload = {
        "config": config,
        "config_path": convention.OFFSITE_CONFIG,
        "capture_path": convention.OFFSITE_CAPTURE,
        "prune_path": convention.OFFSITE_PRUNE,
        "health_repository": document["health_repository"],
        "health_key": document["health_key"],
        "sites": sites,
        "secret_path": context.secret_path,
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(SETUP_BYTES, (encoded,))


def body_remove(document: dict[str, object], context: BodyContext) -> NativeBody:
    _document(document, REMOVE_SHA256)
    if not context.secret_path:
        raise ValueError("Removing offsite storage needs its confirmation.")
    config = _config_document(document)
    sites = document.get("sites")
    if (
        not isinstance(sites, list)
        or not all(isinstance(site, str) for site in sites)
        or document.get("config_path") != convention.OFFSITE_CONFIG
        or document.get("capture_path") != convention.OFFSITE_CAPTURE
        or document.get("prune_path") != convention.OFFSITE_PRUNE
    ):
        raise ValueError("The offsite storage review is not a supported removal.")
    payload = {
        "action": "remove",
        "config": config,
        "config_path": convention.OFFSITE_CONFIG,
        "capture_path": convention.OFFSITE_CAPTURE,
        "prune_path": convention.OFFSITE_PRUNE,
        "sites": sites,
        "secret_path": context.secret_path,
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(REMOVE_BYTES, (encoded,))


def body_copy(document: dict[str, object], context: BodyContext) -> NativeBody:
    _document(document, COPY_SHA256)
    identifier = document.get("identifier")
    point = document.get("point")
    offsite = validate_capture(document.get("offsite"))
    storage = offsite.get("storage") if offsite is not None else None
    if (
        not isinstance(identifier, str)
        or convention.SITE_IDENTIFIER.fullmatch(identifier) is None
        or document.get("repository") != convention.repository(identifier)
        or document.get("server_key") != convention.server_key(identifier)
        or not isinstance(point, str)
        or _POINT.fullmatch(point) is None
        or offsite is None
        or not isinstance(storage, dict)
        or offsite["repository"]
        != f"s3:{storage['endpoint']}/{storage['bucket']}/{storage['prefix']}/{identifier}"
    ):
        raise ValueError("The offsite copy is not a supported copy.")
    payload = {
        "identifier": identifier,
        "point": point,
        "repository": document["repository"],
        "server_key": document["server_key"],
        "offsite": offsite,
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(COPY_BYTES, (encoded,))


def _offsite_command(document: dict[str, object], identifier: str, *arguments: str) -> str:
    plan = validate_capture(document.get("offsite"))
    if plan is None:
        raise ValueError("The offsite copy is not the reviewed one.")
    storage = plan.get("storage")
    if not isinstance(storage, dict):
        raise ValueError("The offsite copy is not the reviewed one.")
    return convention.offsite_restic_command(
        identifier,
        {str(key): str(value) for key, value in storage.items()},
        *arguments,
    )


def verify_setup(shell: RemoteShell, review: ChangeReview) -> bool | None:
    body_setup(
        review.document,
        BodyContext("", "", 0, f"{convention.KEY_ROOT}/.staged"),
    )
    document = review.document
    config = _config_document(document)
    health_key = document.get("health_key")
    if not isinstance(health_key, str) or not health_key.startswith(convention.KEY_ROOT + "/"):
        return False
    script = "; ".join(
        [
            "set -a",
            f". {shlex.quote(convention.OFFSITE_CAPTURE)}",
            f"RESTIC_REPOSITORY={shlex.quote(convention.health_repository(config))}",
            f"RESTIC_PASSWORD_FILE={shlex.quote(health_key)}",
            f"RESTIC_CACHE_DIR={shlex.quote(convention.CACHE_DIR)}",
            f"AWS_DEFAULT_REGION={shlex.quote(str(config.get('region', '')))}",
            "set +a",
            shlex.join(
                [
                    convention.RESTIC_BIN,
                    "-o",
                    "s3.bucket-lookup=path",
                    "snapshots",
                    "--json",
                    "--no-lock",
                ]
            ),
        ]
    )
    result = run_root(shell, "sh -c " + shlex.quote(script))
    return not (result.exit_status or result.truncated)


def verify_remove(shell: RemoteShell, review: ChangeReview) -> bool | None:
    body_remove(
        review.document,
        BodyContext("", "", 0, f"{convention.KEY_ROOT}/.staged"),
    )
    checks = " && ".join(
        f"test ! -e {shlex.quote(path)}"
        for path in (
            convention.OFFSITE_CONFIG,
            convention.OFFSITE_CAPTURE,
            convention.OFFSITE_PRUNE,
        )
    )
    result = run_root(shell, f"sh -c {shlex.quote(checks)}")
    return result.exit_status == 0 and not result.truncated


def verify_copy(shell: RemoteShell, review: ChangeReview) -> bool | None:
    body_copy(review.document, BodyContext("", "", 0))
    identifier = str(review.document["identifier"])
    point = str(review.document["point"])
    result = run_root(
        shell,
        _offsite_command(
            review.document,
            identifier,
            "snapshots",
            "--json",
            "--no-lock",
            "--tag",
            "point:" + point,
        ),
    )
    if result.exit_status or result.truncated:
        return None
    try:
        value: object = json.loads(result.stdout)
    except ValueError:
        return None
    if not isinstance(value, list):
        return None
    return any(
        isinstance(row, dict)
        and isinstance(row.get("tags"), list)
        and convention.MARKER in row["tags"]
        and "point:" + point in row["tags"]
        and "complete" in row["tags"]
        for row in value
    )


SET_UP: Final = ChangeKind(
    slug=SETUP_SLUG,
    label=SETUP_LABEL,
    inspect=inspect_storage,
    review=review_setup,
    body=body_setup,
    verify=verify_setup,
    refresh_discovery=True,
    input_shape=InputShape.OFFSITE_STORAGE,
    writes_secrets=True,
)

REMOVE: Final = ChangeKind(
    slug=REMOVE_SLUG,
    label=REMOVE_LABEL,
    inspect=inspect_storage,
    review=review_remove,
    body=body_remove,
    verify=verify_remove,
    refresh_discovery=True,
    input_shape=InputShape.SELECTION,
    writes_secrets=True,
)

COPY: Final = ChangeKind(
    slug=COPY_SLUG,
    label=COPY_LABEL,
    inspect=inspect_copy,
    review=review_copy,
    body=body_copy,
    verify=verify_copy,
    refresh_discovery=True,
    input_shape=InputShape.SITE_BACKUP_POINT,
)
