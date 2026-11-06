"""Restart the server and confirm it came back (Phase E #305).

docs/security.md#restart. The review names the packages that asked for a restart and the
services and sites a restart pauses. The engine's shared admission refuses while another
apply or revert unit is active; the body refuses while a site backup or Ubuntu's package
maintenance still has processes, writes its one result line, then asks systemd to restart
the host. The engine treats success as a new boot ID on
a fresh verified connection; no connection within ten minutes leaves the outcome unknown
and nothing is retried.
"""

import hashlib
import importlib.resources
import re
import shlex
import time
from dataclasses import dataclass
from typing import Final

from bootstrap.standing import Standing
from cache import convention as cache_convention
from databases import observation as database_observation
from discovery.models import SiteState
from discovery.root_read import run_root
from discovery.snapshot import CollectedSnapshot
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import PreparationInputs
from operations.models import ChangeReview
from sites.names import canonical_name, readiness_ok, readiness_path

from . import observation
from .bodies.reasons import RESTART_REASONS

SLUG: Final = "restart_server"
LABEL: Final = "Restart server"
STAGES: Final = ("preflight", "restart", "verify")
_BODY_BYTES: Final = (
    importlib.resources.files("security.bodies")
    .joinpath("restart.sh")
    .read_text()
    .rstrip("\n")
    .encode()
)
BODY_SHA256: Final = hashlib.sha256(_BODY_BYTES).hexdigest()
SITES_READ: Final = (
    "find /etc/caddy/sites -maxdepth 1 -type f -name '*.caddy' -printf '%f\\n' "
    "| sed 's/\\.caddy$//' | LC_ALL=C sort"
)
_BOOT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.:-]{0,99}")
_UNIT = re.compile(r"[a-z][a-z0-9@_.:-]{0,119}\.service")
_VERIFY_UNIT: Final = "barectl-apply-" + "0" * 32 + ".service"


@dataclass(frozen=True)
class SiteTarget:
    name: str
    readiness: str
    https: bool


@dataclass(frozen=True)
class RestartEvidence:
    restart: observation.RestartState | None
    restart_warning: str
    standing: str
    machine: str
    boot_id: str
    uptime_centiseconds: int | None
    apt: str
    dpkg: str
    systemd: str
    sites: tuple[str, ...]
    targets: tuple[SiteTarget, ...]
    services: tuple[str, ...]
    active: tuple[tuple[str, str], ...]
    disk_bytes: int | None = None
    memory_kib: int | None = None


def read_command() -> str:
    return "; ".join(
        [
            "printf 'boot\\t%s\\n' \"$(cat /proc/sys/kernel/random/boot_id)\"",
            "printf 'uptime\\t%s\\n' \"$(cut -d' ' -f1 /proc/uptime | tr -d .)\"",
            "printf 'apt\\t%s\\n' \"$(apt --version)\"",
            "printf 'dpkg\\t%s\\n' \"$(dpkg --version | head -1)\"",
            "printf 'systemd\\t%s\\n' \"$(systemctl --version | head -1)\"",
            "printf 'disk\\t%s\\n' \"$(df -B1 --output=avail / | tail -1)\"",
            "printf 'memory\\t%s\\n' \"$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)\"",
        ]
    )


_ALLOWED = {"boot", "uptime", "apt", "dpkg", "systemd", "disk", "memory"}


def _values(shell: RemoteShell) -> dict[str, str]:
    result = run_root(shell, read_command())
    if result.exit_status != 0 or result.truncated:
        return {}
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        name, separator, value = line.partition("\t")
        if not separator or name not in _ALLOWED or name in values:
            return {}
        values[name] = value
    return values


def _sites(observed: CollectedSnapshot) -> tuple[tuple[str, ...], tuple[SiteTarget, ...]]:
    if not observed.sites.observed or observed.sites.value is None:
        return (), ()
    rows = [
        site
        for site in observed.sites.value
        if site.state == SiteState.MANAGED and site.server_names
    ]
    identifiers = tuple(sorted({site.identifier for site in rows}))
    targets = tuple(
        SiteTarget(site.server_names[0], site.readiness, site.https)
        for site in sorted(rows, key=lambda site: site.identifier)
    )
    return identifiers, targets


def _services(observed: CollectedSnapshot) -> tuple[str, ...]:
    units = ["caddy.service"]
    sites = (
        observed.sites.value if observed.sites.observed and observed.sites.value is not None else ()
    )
    cached = observed.cache.value if observed.cache.observed else ()
    cache_sites = {item.identifier for item in cached or () if item.state in {"on", "partial"}}
    for site in sites:
        if site.state != SiteState.MANAGED:
            continue
        units.append(f"haproxy-site@{site.identifier}.service")
        if site.php_version:
            units.append(f"php-fpm-site-{site.php_version}@{site.identifier}.service")
        if site.identifier in cache_sites:
            units.append(cache_convention.instance_paths(site.identifier).unit)
    for engine in database_observation.installed_engines(observed):
        spec = database_observation.specs()[engine.engine]
        units.extend(spec.units)
    return tuple(dict.fromkeys(units))


def _active_states(shell: RemoteShell, units: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    if not units:
        return ()
    command = "systemctl is-active " + " ".join(shlex.quote(unit) for unit in units)
    result = shell.run(command)
    if result.truncated:
        return ()
    states = result.stdout.splitlines()
    if len(states) != len(units):
        return ()
    return tuple(zip(units, states, strict=True))


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> RestartEvidence:
    from discovery.observations import collect

    observed = collect(shell)
    security = observed.security.value if observed.security.observed else None
    restart = security.restart if security is not None else None
    values = _values(shell)
    sites, targets = _sites(observed)
    services = _services(observed)
    return RestartEvidence(
        restart=restart.value if restart is not None and restart.observed else None,
        restart_warning=restart.warning if restart is not None else "",
        standing=observed.standing.standing.value if observed.standing else "",
        machine=observed.architecture.value or "",
        boot_id=values.get("boot", ""),
        uptime_centiseconds=(int(values["uptime"]) if values.get("uptime", "").isdigit() else None),
        apt=values.get("apt", ""),
        dpkg=values.get("dpkg", ""),
        systemd=values.get("systemd", ""),
        sites=sites,
        targets=targets,
        services=services,
        active=_active_states(shell, services),
        disk_bytes=int(values["disk"]) if values.get("disk", "").isdigit() else None,
        memory_kib=int(values["memory"]) if values.get("memory", "").isdigit() else None,
    )


def _platform_reasons(evidence: RestartEvidence) -> list[str]:
    reasons: list[str] = []
    if evidence.standing != Standing.TARGET_STACK.value:
        reasons.append("Set up and verify the host foundation before restarting the server.")
    if evidence.machine not in {"x86_64", "aarch64"}:
        reasons.append("The server's architecture is not one Barectl supports.")
    if evidence.apt and not evidence.apt.startswith("apt 3.2."):
        reasons.append("The server is not the supported Ubuntu 26.04 platform.")
    if evidence.dpkg and "version 1.23." not in evidence.dpkg:
        reasons.append("The server is not the supported Ubuntu 26.04 platform.")
    if evidence.systemd and not evidence.systemd.startswith("systemd 259 "):
        reasons.append("The server is not the supported Ubuntu 26.04 platform.")
    if not evidence.boot_id or evidence.uptime_centiseconds is None:
        reasons.append("The server's boot identity could not be read.")
    if evidence.restart is None:
        reasons.append(
            evidence.restart_warning or "Barectl could not read whether the server needs a restart."
        )
    if not evidence.active:
        reasons.append("Barectl could not read the services a restart would pause.")
    return reasons


def _details(evidence: RestartEvidence) -> list[dict[str, str]]:
    packages = evidence.restart.packages if evidence.restart is not None else ()
    services = [
        f"{_service_name(unit)}: {'running' if state == 'active' else 'not running'}"
        for unit, state in evidence.active
    ]
    return [
        {
            "label": "What happens",
            "value": ("The server stops and starts again. Sites are unavailable until it returns."),
        },
        {
            "label": "Needed by",
            "value": "\n".join(packages) or "No package asked for a restart.",
        },
        {
            "label": "Affected sites",
            "value": ", ".join(evidence.sites) or "None.",
        },
        {
            "label": "Services",
            "value": "\n".join(services) or "None.",
        },
        {
            "label": "Scheduled tasks and queue workers",
            "value": (
                "Scheduled tasks and queue workers stop with the server and start again after "
                "it returns. Work that was running at that moment may be interrupted."
            ),
        },
        {
            "label": "Expected downtime",
            "value": "Usually under a minute; a large or busy server can take longer.",
        },
        {
            "label": "If it does not return",
            "value": (
                "Use your server provider's console. Barectl waits ten minutes, reports that "
                "it does not know, and never tries the restart again."
            ),
        },
        {
            "label": "Services that keep their version",
            "value": "The web server and PHP keep the version Barectl installed.",
        },
    ]


def _service_name(unit: str) -> str:
    if unit == "caddy.service":
        return "Web server"
    if unit.startswith("haproxy-site@"):
        return "Site proxy for " + unit.removeprefix("haproxy-site@").removesuffix(".service")
    if unit.startswith("php-fpm-site-"):
        return "PHP for " + unit.rsplit("@", 1)[-1].removesuffix(".service")
    if unit.startswith("valkey-server@"):
        return "Object cache for " + unit.removeprefix("valkey-server@").removesuffix(".service")
    if unit.startswith(("mariadb", "postgresql")):
        return "Database"
    return "Service"


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, RestartEvidence):
        raise ValueError("A restart needs native evidence.")
    refusals = _platform_reasons(evidence)
    if inputs.selection != "on":
        refusals.append("Choose Restart server to continue.")
    packages = tuple(sorted(evidence.restart.packages)) if evidence.restart is not None else ()
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "boot_id": evidence.boot_id,
        "packages": list(packages),
        "sites": [
            {"name": target.name, "readiness": target.readiness, "https": target.https}
            for target in evidence.targets
        ],
        "services": list(evidence.services),
        "details": _details(evidence),
    }
    effects = (
        (
            DeclaredEffect(
                Scope.SERVER,
                "Restart the server. Sites, scheduled tasks and queue workers stop and start "
                "again.",
                evidence.sites,
            ),
        )
        if not refusals
        else ()
    )
    return ReviewDraft(
        SLUG,
        "Restart the server.",
        effects=effects,
        stages=STAGES,
        postconditions=(
            "The server answers over a new verified connection with a new boot identity.",
            (
                "The web server, each site's proxy and PHP, the database engine and every "
                "enabled object cache are running."
            ),
            "Each site answers its readiness path.",
            (
                "Discovery reads the restart-needed evidence and the services back from the "
                "server alone."
            ),
        ),
        refusals=tuple(dict.fromkeys(refusals)),
        sites_read=SITES_READ,
        current_sites=evidence.sites,
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        document=document,
    )


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    boot_id = document.get("boot_id")
    packages = document.get("packages")
    sites = document.get("sites")
    services = document.get("services")
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or not isinstance(boot_id, str)
        or not _BOOT.fullmatch(boot_id)
        or not isinstance(packages, list)
        or not all(isinstance(name, str) and _PACKAGE.fullmatch(name) for name in packages)
        or not isinstance(sites, list)
        or not isinstance(services, list)
        or not all(isinstance(unit, str) and _UNIT.fullmatch(unit) for unit in services)
        or len(packages) > 500
        or len(sites) > 500
        or len(services) > 1000
    ):
        raise ValueError("The restart review is not a valid immutable selection.")
    return NativeBody(
        _BODY_BYTES,
        (
            boot_id,
            "\n".join(str(name) for name in packages),
            ",".join(str(unit) for unit in services),
        ),
    )


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    document = stored.document
    body(document, BodyContext(_VERIFY_UNIT, "", 0))
    boot = shell.run("cat /proc/sys/kernel/random/boot_id")
    if boot.exit_status != 0 or boot.truncated:
        return None
    if boot.stdout.strip() == document["boot_id"]:
        return False
    services = document.get("services")
    if not isinstance(services, list) or not services:
        return False
    quoted = " ".join(shlex.quote(str(unit)) for unit in services)
    states = shell.run(f"systemctl is-active {quoted}")
    if states.truncated:
        return None
    rows = states.stdout.splitlines()
    if len(rows) != len(services):
        return None
    if any(state != "active" for state in rows):
        return False
    return _readiness(shell, document)


def _readiness(shell: RemoteShell, document: dict[str, object]) -> bool:
    targets = document.get("sites")
    if not isinstance(targets, list) or not targets:
        return True
    deadline = time.monotonic() + 30
    for target in targets:
        if not isinstance(target, dict):
            return False
        name = target.get("name")
        path = target.get("readiness")
        https = target.get("https")
        if not isinstance(name, str) or not isinstance(path, str) or type(https) is not bool:
            return False
        canonical, problem = canonical_name(name)
        if problem:
            return False
        _path, trouble = readiness_path(path)
        if trouble:
            return False
        while True:
            status = _status(shell, canonical, path, https)
            if readiness_ok(path, status):
                break
            if status != 0 or time.monotonic() >= deadline:
                return False
            time.sleep(0.5)
    return True


def _status(shell: RemoteShell, host: str, path: str, https: bool) -> int:
    quoted_host = shlex.quote(host)
    quoted_path = shlex.quote(path)
    if https:
        request = f"https://{quoted_host}{quoted_path}"
        resolve = f"--resolve {quoted_host}:443:127.0.0.1"
        extra = "--insecure"
    else:
        request = f"http://127.0.0.1{quoted_path}"
        resolve = f"-H Host:{quoted_host}"
        extra = ""
    command = (
        "curl --silent --show-error --output /dev/null --write-out '%{http_code}' "
        f"--max-time 10 {extra} {resolve} {request}"
    )
    result = shell.run(command)
    if result.truncated:
        return 0
    try:
        return int(result.stdout.strip() or "0")
    except ValueError:
        return 0


RESTART_SERVER: Final = ChangeKind(
    SLUG,
    LABEL,
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_choices=("on",),
    restarts_host=True,
    reasons=RESTART_REASONS,
    body_sources=("security/bodies/restart.sh",),
)


__all__ = [
    "BODY_SHA256",
    "LABEL",
    "RESTART_SERVER",
    "SLUG",
    "RestartEvidence",
    "SiteTarget",
    "body",
    "inspect",
    "review",
    "verify",
]
