"""Host foundation behind the change engine's four-member seam.

docs/bootstrap.md#host-foundation and ADRs 0026 to 0028.
"""

import hashlib
import importlib.resources
import json
import re
import shlex
from dataclasses import dataclass
from typing import Final

from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import EMPTY_INPUTS, PreparationInputs
from operations.models import ChangeReview
from runtimes.catalog import Architecture, architecture_of, load

from .standing import HostJudgment, Standing

SLUG: Final = "host_foundation"
LABEL: Final = "Set up server"
STAGES: Final = ("preflight", "Nix", "catalog", "Caddy", "journald", "verify")
PROFILES: Final = ("caddy", "composer", "wp-cli")
_RESOURCES = importlib.resources.files("bootstrap.bodies")
READ_SOURCE: Final = _RESOURCES.joinpath("foundation_read.sh").read_text()
READ_COMMAND: Final = "sh -c " + shlex.quote(READ_SOURCE + "\nfoundation_read\n")
BODY_BYTES: Final = (
    _RESOURCES.joinpath("foundation.sh")
    .read_text()
    .replace("# FOUNDATION_READ", READ_SOURCE)
    .rstrip("\n")
    .encode()
)
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()
_FIXED_SOURCE: Final = _RESOURCES.joinpath("foundation.sh").read_text()
CADDY_CONFIG: Final = _FIXED_SOURCE.split("<<'CONFIG'\n", 2)[2].split("\nCONFIG", 1)[0]
CADDY_UNIT: Final = _FIXED_SOURCE.split("<<'UNIT'\n", 1)[1].split("\nUNIT", 1)[0]
JOURNAL_CONFIG: Final = (
    "[Journal]" + _FIXED_SOURCE.split("printf '[Journal]", 1)[1].split("' >", 1)[0]
).replace("\\n", "\n")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")


@dataclass(frozen=True)
class FoundationEvidence:
    standing: HostJudgment | None
    architecture: Architecture | None
    boot_id: str
    uptime_centiseconds: int | None
    precondition_digest: str
    complete: bool
    nix_supported: bool = False
    caddy_shape: str = "absent"


def read(shell: RemoteShell) -> dict[str, str] | None:
    result = run_root(shell, READ_COMMAND)
    if result.exit_status != 0 or result.truncated:
        return None
    values: dict[str, str] = {}
    allowed = {
        "digest",
        "boot",
        "uptime",
        "architecture",
        *PROFILES,
        "daemon",
        "caddy_state",
        "socket",
        "runtime",
        "journal",
        "caddy_valid",
        "caddy_json",
        "caddy_version",
        "caddy_executable",
        "caddy_pid",
        "daemon_restricted",
        "caddy_running_json",
        "caddy_shape",
        "caddy_user",
        "caddy_group",
        "caddy_exec",
        "caddy_directory",
        "sites_directory",
        "caddy_file",
        "caddy_unit",
        "nix_config",
        "unknown_host",
    }
    for line in result.stdout.splitlines():
        name, separator, value = line.partition("\t")
        if not separator or name not in allowed or name in values:
            return None
        values[name] = value
    if not _DIGEST.fullmatch(values.get("digest", "")):
        return None
    if not _BOOT.fullmatch(values.get("boot", "")):
        return None
    if not re.fullmatch(r"[0-9]{1,16}", values.get("uptime", "")):
        return None
    return values


def complete(values: dict[str, str], architecture: Architecture) -> bool:
    catalog = load()
    builds = {b.entry: b for b in catalog.offered(architecture) if b.entry in PROFILES}
    if any(values.get(entry) != builds[entry].path for entry in PROFILES):
        return False
    return (
        values.get("nix_config") == "0 0 644"
        and values.get("daemon") == "active"
        and values.get("daemon_restricted") == "yes"
        and caddy_supported(values)
        and values.get("caddy_state") == "active"
        and values.get("unknown_host") == "404"
        and values.get("socket") == "600"
        and values.get("runtime") == "700"
        and values.get("journal") == "persistent"
        and values.get("caddy_valid") == "yes"
        and values.get("caddy_executable") == builds["caddy"].path + "/bin/caddy"
        and supported_caddy(values.get("caddy_json", ""))
        and same_caddy(values.get("caddy_json", ""), values.get("caddy_running_json", ""))
    )


def caddy_supported(values: dict[str, str]) -> bool:
    return (
        values.get("caddy_valid") == "yes"
        and supported_caddy(values.get("caddy_json", ""))
        and values.get("caddy_user") == "caddy"
        and values.get("caddy_group") == "caddy"
        and "path=/nix/var/nix/profiles/barectl/caddy/bin/caddy ;" in values.get("caddy_exec", "")
        and "run --environ --config /etc/caddy/Caddyfile --adapter caddyfile"
        in values.get("caddy_exec", "")
        and values.get("caddy_directory") == "0 0 755"
        and values.get("sites_directory") == "0 0 755"
        and values.get("caddy_file") == "0 0 644"
        and values.get("caddy_unit") == "0 0 644"
    )


def same_caddy(adapted: str, running: str) -> bool:
    try:
        return bool(adapted and running) and json.loads(adapted) == json.loads(running)
    except ValueError:
        return False


def supported_caddy(text: str) -> bool:
    """Interpret Caddy's adapted native JSON, never the Caddyfile syntax."""
    try:
        value: object = json.loads(text)
    except ValueError:
        return False
    if not isinstance(value, dict):
        return False
    admin = value.get("admin")
    apps = value.get("apps")
    if not isinstance(admin, dict) or admin.get("listen") not in {
        "unix//run/caddy/admin.sock",
        "unix//run/caddy/admin.sock|0600",
    }:
        return False
    if not isinstance(apps, dict) or not isinstance(http := apps.get("http"), dict):
        return False
    servers = http.get("servers")
    if not isinstance(servers, dict) or not servers:
        return False
    return all(_supported_server(server) for server in servers.values())


def _host_matched(route: object) -> bool:
    if (
        not isinstance(route, dict)
        or not isinstance(matches := route.get("match"), list)
        or not matches
    ):
        return False
    for match in matches:
        if (
            not isinstance(match, dict)
            or not isinstance(hosts := match.get("host"), list)
            or not hosts
        ):
            return False
        if any(
            not isinstance(host, str) or not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", host)
            for host in hosts
        ):
            return False
    return True


def _supported_server(server: object) -> bool:
    if (
        not isinstance(server, dict)
        or server.get("strict_sni_host") is not True
        or server.get("listen") != [":80"]
    ):
        return False
    routes = server.get("routes")
    if (
        not isinstance(routes, list)
        or not routes
        or not all(_host_matched(route) for route in routes[:-1])
    ):
        return False
    fallback = routes[-1]
    if not isinstance(fallback, dict) or "match" in fallback:
        return False
    handlers = fallback.get("handle")
    if not isinstance(handlers, list) or len(handlers) != 1:
        return False
    handler = handlers[0]
    return (
        isinstance(handler, dict)
        and handler.get("handler") == "static_response"
        and handler.get("status_code") == 404
    )


def inspect(shell: RemoteShell, inputs: PreparationInputs = EMPTY_INPUTS) -> FoundationEvidence:
    from discovery.observations import collect

    observed = collect(shell)
    values = read(shell)
    architecture = architecture_of(observed.architecture.value or "")
    return FoundationEvidence(
        standing=observed.standing,
        architecture=architecture,
        boot_id=values["boot"] if values else "",
        uptime_centiseconds=int(values["uptime"]) if values else None,
        precondition_digest=values["digest"] if values else "",
        complete=bool(values and architecture and complete(values, architecture)),
        nix_supported=bool(
            values
            and values.get("daemon_restricted") == "yes"
            and values.get("nix_config") == "0 0 644"
            and observed.standing
            and ("Nix installation", "supported") in observed.standing.evidence
        ),
        caddy_shape="supported"
        if values and caddy_supported(values)
        else values.get("caddy_shape", "unreadable")
        if values
        else "unreadable",
    )


def review(evidence: object, inputs: PreparationInputs = EMPTY_INPUTS) -> ReviewDraft:
    if not isinstance(evidence, FoundationEvidence):
        raise ValueError("Not foundation evidence.")
    reasons = list(
        evidence.standing.reasons if evidence.standing else ("Host evidence unavailable.",)
    )
    if evidence.architecture is None or evidence.uptime_centiseconds is None:
        reasons.append("The foundation's architecture or native clock could not be read.")
    if not _DIGEST.fullmatch(evidence.precondition_digest) or not _BOOT.fullmatch(evidence.boot_id):
        reasons.append("The foundation preconditions could not be read.")
    document: dict[str, object] = {"version": 1, "body_sha256": BODY_SHA256}
    effects: tuple[DeclaredEffect, ...] = ()
    if not reasons and evidence.architecture:
        catalog = load()
        installer = catalog.installer(evidence.architecture)
        builds = {b.entry: b for b in catalog.offered(evidence.architecture) if b.entry in PROFILES}
        document.update(
            architecture=str(evidence.architecture),
            precondition_digest=evidence.precondition_digest,
            installer_url=installer.url,
            installer_sha256=installer.sha256,
            profiles={entry: builds[entry].path for entry in PROFILES},
            nix_mode="keep" if evidence.nix_supported else "install",
            caddy_mode="keep" if evidence.caddy_shape == "supported" else "install",
            details=[
                {
                    "label": "Main Caddy configuration",
                    "value": "/etc/caddy/Caddyfile (root:root, 0644):\n" + CADDY_CONFIG,
                },
                {
                    "label": "Caddy systemd unit",
                    "value": "/etc/systemd/system/caddy.service (root:root, 0644):\n" + CADDY_UNIT,
                },
                {
                    "label": "Persistent native journal",
                    "value": "/etc/systemd/journald.conf.d/50-barectl.conf (root:root, 0644):\n"
                    + JOURNAL_CONFIG,
                },
                {
                    "label": "Nix installer",
                    "value": f"{installer.version}: {installer.url}; SHA-256 {installer.sha256}",
                },
                {
                    "label": "Catalog profiles",
                    "value": "; ".join(f"{entry}: {builds[entry].path}" for entry in PROFILES),
                },
                {
                    "label": "Network destinations",
                    "value": "releases.nixos.org and cache.nixos.org over HTTPS. "
                    "Only signed official-cache builds; no local builds.",
                },
                {
                    "label": "Estimates",
                    "value": "Catalog download up to "
                    f"{sum(b.download_size for b in builds.values())} "
                    "bytes; unpacked closures up to "
                    f"{sum(b.closure_size for b in builds.values())} "
                    "bytes plus Nix. Shared closure bytes may be counted more than once. "
                    "Admission headroom is 4 GiB disk and 900 MiB memory, unqualified.",
                },
                {
                    "label": "Installer profile edits",
                    "value": "/etc/bash.bashrc, /etc/bashrc, /etc/zshrc, "
                    "/etc/bashrc.backup-before-nix or corresponding backup files where present. "
                    "The official installer adds its daemon shell hook.",
                },
                {
                    "label": "Reserved identities",
                    "value": "nixbld group and nixbld1 to nixbld32, UIDs 30001 to 30032; "
                    "caddy system user/group. Site IDs apply, site, repo and backup are reserved.",
                },
                {
                    "label": "Services",
                    "value": "nix-daemon.socket and nix-daemon.service; Caddy; "
                    "persistent systemd-journald. The Nix daemon stays running after use. "
                    "Caddy starts with a private Unix admin endpoint, directory 0700 and "
                    "socket 0600, and unknown hosts receive HTTP 404.",
                },
            ],
        )
        if evidence.complete:
            document["note"] = "The observed host foundation is complete. No changes needed."
        elif evidence.standing and (
            evidence.standing.standing is Standing.FRESH
            or (evidence.nix_supported and evidence.caddy_shape in {"absent", "supported"})
        ):
            effects = (
                DeclaredEffect(
                    Scope.SERVER,
                    (
                        "Keep the supported Nix daemon and complete the catalog profiles, "
                        if evidence.nix_supported
                        else "Install the pinned multi-user Nix daemon and exact catalog profiles, "
                    )
                    + "start Caddy on HTTP with a private Unix admin socket, and make the "
                    "native journal persistent.",
                ),
            )
        else:
            reasons.append(
                "The foundation has unrecognized partial native configuration. "
                "Resolve the named evidence before preparing again; Barectl will not overwrite it."
            )
    return ReviewDraft(
        kind=SLUG,
        intent="Set up this server's host foundation.",
        effects=effects,
        stages=STAGES,
        postconditions=("Fresh native evidence recognizes the complete Target stack.",),
        refusals=tuple(reasons),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        document=document,
    )


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    if (
        type(document.get("version")) is not int
        or document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
    ):
        raise ValueError("Unsupported foundation review.")
    architecture = document.get("architecture")
    if architecture not in tuple(Architecture):
        raise ValueError("Unsupported foundation architecture.")
    catalog = load()
    installer = catalog.installer(Architecture(str(architecture)))
    if (
        document.get("installer_url") != installer.url
        or document.get("installer_sha256") != installer.sha256
    ):
        raise ValueError("The installer is outside the reviewed catalog.")
    expected_profiles = {
        b.entry: b.path for b in catalog.offered(installer.architecture) if b.entry in PROFILES
    }
    if document.get("profiles") != expected_profiles:
        raise ValueError("The profiles are outside the reviewed catalog.")
    nix_mode = document.get("nix_mode")
    caddy_mode = document.get("caddy_mode")
    if (
        not isinstance(nix_mode, str)
        or nix_mode not in {"keep", "install"}
        or not isinstance(caddy_mode, str)
        or caddy_mode not in {"keep", "install"}
    ):
        raise ValueError("Invalid reviewed foundation stages.")
    digest = document.get("precondition_digest")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise ValueError("The foundation digest is invalid.")
    return NativeBody(
        BODY_BYTES,
        (
            digest,
            installer.url,
            installer.sha256,
            *(expected_profiles[entry] for entry in PROFILES),
            str(nix_mode),
            str(caddy_mode),
        ),
    )


def verify(shell: RemoteShell, review: ChangeReview) -> bool | None:
    body(review.document, BodyContext("", "", 0))
    observed = inspect(shell)
    return (
        None
        if observed.standing is None
        else observed.complete and observed.standing.standing is Standing.TARGET_STACK
    )


HOST_FOUNDATION: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    refresh_discovery=True,
)
