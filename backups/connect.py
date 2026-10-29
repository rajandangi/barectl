"""Connect existing backup storage from another server (#408).

Server **Settings > Backup storage > Connect existing backup storage** uses the recovery
kit's non-secret facts, the recovery passphrase and the storage keys to open another
server's offsite repositories read-only. It writes only this server's root-only offsite
settings and the source identifiers the kit names; the bounded listing each source answered
with is one safe result line that passive discovery reconstructs. The passphrase and keys
travel only through the confidential input channel and are never stored.
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

from automation.bodies.source import without_imports
from discovery.observations import collect
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview

from . import convention, observation

SLUG: Final = "connect_existing_backup_storage"
LABEL: Final = "Connect existing backup storage"
STAGES: Final = ("preflight", "credentials", "sources", "verify")
SITE: Final = re.compile(r"[a-z][a-z0-9]{2,23}")
READ_SITES: Final = (
    "find /etc/caddy/sites -maxdepth 1 -type f -name '*.caddy' "
    "-printf '%f\\n' | sed 's/\\.caddy$//' | LC_ALL=C sort"
)
NOTE: Final = (
    "Barectl opens the source repositories read-only with the passphrase and the storage "
    "keys, lists their recovery points, and writes only this server's private settings. It "
    "does not copy, initialise or change anything in the bucket."
)

NATIVE_SOURCE: Final = importlib.resources.files("backups.bodies").joinpath("native.py").read_text()
CONNECT_CORE: Final = without_imports(
    importlib.resources.files("backups.bodies").joinpath("connect.py").read_text(),
    ("backups.bodies.native",),
)
CONNECT_SOURCE: Final = NATIVE_SOURCE + "\n" + CONNECT_CORE
CONNECT_BYTES: Final = (
    (
        "#!/bin/sh\nexec python3 -c "
        + shlex.quote(
            "import base64,gzip; exec(gzip.decompress(base64.b64decode("
            + repr(base64.b64encode(gzip.compress(CONNECT_SOURCE.encode(), mtime=0)).decode())
            + ")))"
        )
        + ' "$@"\n'
    )
    .encode()
    .rstrip(b"\n")
)
CONNECT_SHA256: Final = hashlib.sha256(CONNECT_BYTES).hexdigest()


@dataclass(frozen=True)
class ConnectEvidence:
    restic_path: str
    restic_version: str
    sites: tuple[str, ...]
    offsite: observation.OffsiteStorage | None
    boot_id: str
    uptime_centiseconds: int | None
    problem: str = ""


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> ConnectEvidence:
    observed = collect(shell, sites=False)
    from runtimes.catalog import architecture_of

    architecture = architecture_of(observed.architecture.value or "")
    path, version = observation.offered_restic(architecture)
    listing = shell.run(READ_SITES)
    sites = (
        tuple(sorted(listing.stdout.splitlines()))
        if listing.exit_status == 0 and not listing.truncated
        else ()
    )
    offsite: observation.OffsiteStorage | None = None
    problem = ""
    if sites or listing.exit_status == 0:
        value = observation.read(shell, sites, "", architecture)
        if value is None:
            problem = "The server's backup settings could not be read."
        else:
            offsite = observation.offsite_of(value)
    else:
        problem = "The server's sites could not be read."
    result = shell.run(
        "printf 'boot\\t%s\\n' \"$(cat /proc/sys/kernel/random/boot_id)\"; "
        "printf 'uptime\\t%s\\n' \"$(cut -d' ' -f1 /proc/uptime | tr -d .)\""
    )
    boot_id = ""
    uptime: int | None = None
    for line in result.stdout.splitlines() if result.exit_status == 0 else ():
        name, separator, setting = line.partition("\t")
        if not separator:
            continue
        if name == "boot":
            boot_id = setting
        elif name == "uptime" and setting.isdigit():
            uptime = int(setting)
    return ConnectEvidence(path, version, sites, offsite, boot_id, uptime, problem)


def _config(inputs: PreparationInputs) -> dict[str, str]:
    endpoint = convention.endpoint(inputs.provider, inputs.region, inputs.account)
    if (
        convention.BUCKET.fullmatch(inputs.bucket) is None
        or convention.PREFIX.fullmatch(inputs.prefix) is None
    ):
        raise ValueError("Not a supported offsite storage template.")
    return {
        "provider": inputs.provider,
        "bucket": inputs.bucket,
        "region": inputs.region if inputs.provider == "s3" else "auto",
        "endpoint": endpoint,
        "prefix": inputs.prefix,
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


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, ConnectEvidence):
        raise ValueError("Connecting backup storage needs native evidence.")
    refusals: list[str] = []
    if not evidence.restic_path:
        refusals.append("Enable backups for the site you will restore first.")
    if evidence.problem:
        refusals.append(evidence.problem)
    if inputs.provider not in convention.PROVIDERS:
        refusals.append("Choose Amazon S3 or Cloudflare R2.")
    sources = tuple(site for site in inputs.sites if SITE.fullmatch(site))
    if not sources or len(sources) != len(inputs.sites) or len(set(sources)) != len(sources):
        refusals.append("Name each source site exactly as the recovery kit lists it.")
    try:
        config = _config(inputs)
    except ValueError:
        refusals.append("Use the bucket, region or account and prefix from the recovery kit.")
        config = {
            "provider": "",
            "bucket": "",
            "region": "",
            "endpoint": "",
            "prefix": "",
            "prune": "no",
        }
    existing = evidence.offsite
    if existing is not None and existing.configured and config["provider"]:
        same = all(
            getattr(existing, name) == config[name]
            for name in ("provider", "bucket", "region", "endpoint", "prefix")
        )
        if not same:
            refusals.append(
                "Remove the storage connected to this server before connecting another."
            )
    details = [
        {"label": "Provider", "value": convention.PROVIDER_LABELS.get(inputs.provider, "")},
        {"label": "Bucket", "value": config["bucket"]},
        {
            "label": "Region" if inputs.provider == "s3" else "Account endpoint",
            "value": config["region"] if inputs.provider == "s3" else config["endpoint"],
        },
        {"label": "Prefix", "value": config["prefix"]},
        {"label": "Source sites", "value": ", ".join(sources)},
    ]
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": CONNECT_SHA256,
        "config": config,
        "config_path": convention.OFFSITE_CONFIG,
        "capture_path": convention.OFFSITE_CAPTURE,
        "prune_path": convention.OFFSITE_PRUNE,
        "sources_path": convention.OFFSITE_SOURCES,
        "sites": list(sources),
        "stages": list(STAGES),
        "details": details,
        "note": NOTE,
        "secret_fields": _secret_fields(inputs.provider),
    }
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals:
        effects = (
            DeclaredEffect(
                Scope.SHARED,
                (
                    "Connect this server to existing offsite backup storage and read its "
                    "source repositories without changing them."
                ),
                evidence.sites,
            ),
        )
    return ReviewDraft(
        kind=SLUG,
        intent="Connect existing offsite backup storage.",
        effects=effects,
        stages=STAGES if effects else (),
        postconditions=(
            "This server's offsite settings name the reviewed storage and source sites.",
            "The source repositories were opened read-only with the recovery passphrase.",
            "The source recovery points are listed for a restore into a matching site.",
        )
        if effects
        else (),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        sites_read=READ_SITES if effects else "",
        current_sites=evidence.sites if effects else None,
        document=document,
        writes_secrets=True,
    )


def _document(document: dict[str, object]) -> dict[str, str]:
    if document.get("version") != 1 or document.get("body_sha256") != CONNECT_SHA256:
        raise ValueError("Unsupported connected storage review.")
    raw = document.get("config")
    if not isinstance(raw, dict):
        raise ValueError("The connected storage review is not a supported setup.")
    values = {str(name): str(value) for name, value in raw.items()}
    convention.read_config(convention.render_config(values))
    sites = document.get("sites")
    if (
        not isinstance(sites, list)
        or not 1 <= len(sites) <= 64
        or not all(isinstance(site, str) and SITE.fullmatch(site) for site in sites)
        or len(set(sites)) != len(sites)
        or document.get("config_path") != convention.OFFSITE_CONFIG
        or document.get("capture_path") != convention.OFFSITE_CAPTURE
        or document.get("prune_path") != convention.OFFSITE_PRUNE
        or document.get("sources_path") != convention.OFFSITE_SOURCES
    ):
        raise ValueError("The connected storage review is not a supported setup.")
    return values


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    config = _document(document)
    if not context.secret_path:
        raise ValueError("Connecting backup storage needs its access keys and passphrase.")
    payload = {
        "config": config,
        "config_path": convention.OFFSITE_CONFIG,
        "capture_path": convention.OFFSITE_CAPTURE,
        "prune_path": convention.OFFSITE_PRUNE,
        "sources_path": convention.OFFSITE_SOURCES,
        "sites": document["sites"],
        "secret_path": context.secret_path,
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(CONNECT_BYTES, (encoded,))


def verify(shell: RemoteShell, review: ChangeReview) -> bool | None:
    config = _document(review.document)
    sources = review.document["sites"]
    expected = "".join(
        f"{name}={config[name]}\n"
        for name in ("provider", "bucket", "region", "endpoint", "prefix", "prune")
    )
    script = "; ".join(
        [
            f"test -f {shlex.quote(convention.OFFSITE_CONFIG)}",
            f"test -f {shlex.quote(convention.OFFSITE_CAPTURE)}",
            f"test -f {shlex.quote(convention.OFFSITE_SOURCES)}",
            (
                f'test "$(cat {shlex.quote(convention.OFFSITE_CONFIG)})" = '
                f"{shlex.quote(expected.rstrip())}"
            ),
            (
                "python3 -c "
                + shlex.quote(
                    "import json,sys; value=json.load(open(sys.argv[1])); "
                    "assert value == {'version': 1, 'sites': "
                    + repr([str(site) for site in sources])
                    + "}"
                )
                + " "
                + shlex.quote(convention.OFFSITE_SOURCES)
            ),
        ]
    )
    result = run_root(shell, "sh -c " + shlex.quote(script))
    return result.exit_status == 0 and not result.truncated


CONNECT: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    refresh_discovery=True,
    input_shape=InputShape.CONNECT_OFFSITE_STORAGE,
    writes_secrets=True,
)
