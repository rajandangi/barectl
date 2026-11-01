"""Check for and install exact Ubuntu updates (Phase E #304).

**Check for updates** is one change that refreshes Ubuntu's own package lists under the
shared mutation lock. **Install updates** extends Phase B's exact APT transaction
(docs/adr/0024-admit-exact-reviewed-upgrade-transactions.md): the review names every
selected package at its candidate version with ``--only-upgrade`` and every new dependency,
and the native guard admits only the exact reviewed actions. Removals, downgrades, holds,
pending dpkg states and modified conffiles refuse before dpkg changes anything; the review
also discloses the services Ubuntu may restart and the sites they serve.
"""

import hashlib
import importlib.resources
import shlex
import time
from dataclasses import dataclass
from typing import Final

from bootstrap.standing import Standing
from databases.packages import (
    Simulation,
    UpgradeAction,
    check_package,
    check_version,
    parse_simulation,
    ubuntu_origin,
    upgrade_actions_of,
    upgrade_command,
    upgrade_guard,
    valid_digest,
)
from discovery import observations
from discovery.models import SiteState
from discovery.root_read import run_root
from discovery.snapshot import CollectedSnapshot
from discovery.ssh import CommandResult, RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import PreparationInputs
from operations.models import ChangeReview
from sites.names import readiness_ok, readiness_path

from . import observation
from .change import SITES_READ
from .presentation import UPDATES_DISCLOSURE

CHECK_SLUG: Final = "check_for_ubuntu_updates"
CHECK_LABEL: Final = "Check for updates"
INSTALL_SLUG: Final = "install_ubuntu_updates"
INSTALL_LABEL: Final = "Install updates"
SELECTIONS: Final = ("security", "all")
CHECK_STAGES: Final = ("preflight", "refresh", "verify")
INSTALL_STAGES: Final = ("preflight", "install", "verify")
_DEB_ARCH: Final = {"x86_64": "amd64", "aarch64": "arm64"}
_MIN_DISK_BYTES: Final = 512 * 1024**2
_MIN_MEMORY_KIB: Final = 256 * 1024
SERVICE_STATE_COMMAND: Final = (
    "for unit in mariadb.service postgresql.service valkey-server.service ssh.service "
    "ssh.socket; do printf '%s\\t%s\\n' \"$unit\" "
    '"$(systemctl is-active "$unit" 2>/dev/null || true)"; done'
)
# docs/adr/0024-admit-exact-reviewed-upgrade-transactions.md#revalidation-under-the-lock
PRECONDITION_COMMAND: Final = (
    "{ "
    "sha256sum /var/lib/dpkg/status; "
    "apt-mark showhold; "
    "dpkg --audit 2>&1; "
    "find /var/lib/apt/lists -maxdepth 1 -type f -printf '%f %s %T@\\n' 2>/dev/null "
    "| LC_ALL=C sort; "
    "} | sha256sum | cut -d' ' -f1"
)
CONFFILE_FUNCTIONS: Final = r"""
modified_conffiles() {
  dpkg-query -W -f='P ${Package}\n${Conffiles}\n' 2>/dev/null \
    | while read -r first second; do
      case "$first" in
        P) pkg=$second; continue;;
      esac
      path=$first; hash=$second
      [ -n "$pkg" ] && [ -n "$path" ] || continue
      actual=
      if [ -f "$path" ]; then
        case ${#hash} in
          32) actual=$(md5sum -- "$path" 2>/dev/null | cut -d' ' -f1);;
          64) actual=$(sha256sum -- "$path" 2>/dev/null | cut -d' ' -f1);;
        esac
      fi
      [ "$actual" = "$hash" ] || printf '%s\t%s\n' "$pkg" "$path"
    done
  if [ -r /var/lib/ucf/hashfile ]; then
    while IFS=' ' read -r hash path; do
      [ -n "$path" ] || continue
      actual=
      if [ -f "$path" ]; then
        actual=$(md5sum -- "$path" 2>/dev/null | cut -d' ' -f1)
      fi
      [ "$actual" = "$hash" ] || {
        pkg=$(dpkg-query -S "$path" 2>/dev/null | head -n 1 | cut -d: -f1 | cut -d, -f1)
        printf '%s\t%s\n' "$pkg" "$path"
      }
    done < /var/lib/ucf/hashfile
  fi
}
""".strip()
DIGEST_FUNCTIONS: Final = (
    f"precondition_digest() {{ {PRECONDITION_COMMAND}; }}\n{CONFFILE_FUNCTIONS}"
)
CHECK_BYTES: Final = (
    importlib.resources.files("security.bodies")
    .joinpath("check_updates.sh")
    .read_text()
    .rstrip("\n")
    .encode()
)
CHECK_SHA256: Final = hashlib.sha256(CHECK_BYTES).hexdigest()
INSTALL_BYTES: Final = (
    importlib.resources.files("security.bodies")
    .joinpath("install_updates.sh")
    .read_text()
    .replace("# UPDATES_DIGEST_FUNCTIONS", DIGEST_FUNCTIONS)
    .rstrip("\n")
    .encode()
)
INSTALL_SHA256: Final = hashlib.sha256(INSTALL_BYTES).hexdigest()
_RESTART_SENSITIVE: Final = frozenset(
    {"libssl3t64", "libc6", "libsystemd0", "libsystemd-shared", "libgnutls30t64"}
)


@dataclass(frozen=True)
class _Service:
    unit: str
    label: str
    owners: tuple[str, ...]
    # Which sites the service's restart reaches: every site, or sites with an object cache.
    scope: str = ""


_SERVICES: Final = (
    _Service(
        "mariadb.service",
        "Database",
        ("mariadb-server", "mariadb-server-core", "libmariadb3"),
        "sites",
    ),
    _Service(
        "postgresql.service",
        "Database",
        ("postgresql", "postgresql-18", "postgresql-common"),
        "sites",
    ),
    _Service(
        "valkey-server.service",
        "Object cache",
        ("valkey-server", "valkey-tools"),
        "cache",
    ),
    _Service("ssh.service", "SSH", ("openssh-server",)),
    _Service("ssh.socket", "SSH", ("openssh-server",)),
)
_WAITING: Final = frozenset({"phased", "held", "blocked"})


@dataclass(frozen=True)
class SiteTarget:
    name: str
    readiness: str
    https: bool


@dataclass(frozen=True)
class UpdatesEvidence:
    standing: str
    machine: str
    deb_arch: str
    boot_id: str
    uptime_centiseconds: int | None
    apt: str
    dpkg: str
    systemd: str
    held: tuple[str, ...]
    disk_bytes: int | None
    memory_kib: int | None
    state: observation.UpdatesState | None
    update_warning: str
    sites: tuple[str, ...]
    cache_sites: tuple[str, ...]
    targets: tuple[SiteTarget, ...]
    services: tuple[tuple[str, str], ...]
    conffiles: tuple[tuple[str, str], ...]
    audit: tuple[str, ...]
    downgrades: tuple[str, ...] = ()
    precondition_digest: str = ""
    simulation: Simulation | None = None
    simulation_error: str = ""


def _collect(shell: RemoteShell) -> CollectedSnapshot:
    return observations.collect(shell)


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


def _cache_sites(observed: CollectedSnapshot) -> tuple[str, ...]:
    if not observed.cache.observed or observed.cache.value is None:
        return ()
    return tuple(
        sorted(
            {item.identifier for item in observed.cache.value if item.state in {"on", "partial"}}
        )
    )


def read_command() -> str:
    parts = [
        "printf 'boot\\t%s\\n' \"$(cat /proc/sys/kernel/random/boot_id)\"",
        "printf 'uptime\\t%s\\n' \"$(cut -d' ' -f1 /proc/uptime | tr -d .)\"",
        "printf 'apt\\t%s\\n' \"$(apt --version)\"",
        "printf 'dpkg\\t%s\\n' \"$(dpkg --version | head -1)\"",
        "printf 'systemd\\t%s\\n' \"$(systemctl --version | head -1)\"",
        "printf 'holds\\t%s\\n' \"$(apt-mark showhold | tr '\\n' ',')\"",
        "printf 'disk\\t%s\\n' \"$(df -B1 --output=avail / | tail -1)\"",
        "printf 'memory\\t%s\\n' \"$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)\"",
    ]
    return "; ".join(parts)


def _values(shell: RemoteShell) -> dict[str, str]:
    result = run_root(shell, read_command())
    if result.exit_status != 0 or result.truncated:
        return {}
    allowed = {"boot", "uptime", "apt", "dpkg", "systemd", "holds", "disk", "memory"}
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        name, separator, value = line.partition("\t")
        if not separator or name not in allowed or name in values:
            return {}
        values[name] = value
    return values


def _lines(result: CommandResult) -> tuple[str, ...]:
    if result.exit_status != 0 or result.truncated:
        return ()
    return tuple(line for line in result.stdout.splitlines() if line)


def _rows(text: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    rows: list[tuple[str, str]] = []
    for line in text:
        first, _, second = line.partition("\t")
        if first and second:
            rows.append((first, second))
    return tuple(rows)


def _services(shell: RemoteShell) -> tuple[tuple[str, str], ...]:
    return _rows(_lines(run_root(shell, SERVICE_STATE_COMMAND)))


def _evidence(shell: RemoteShell, inputs: PreparationInputs) -> UpdatesEvidence:
    observed = _collect(shell)
    values = _values(shell)
    security = observed.security.value if observed.security.observed else None
    updates = security.updates if security is not None else None
    sites, targets = _sites(observed)
    machine = observed.architecture.value or ""
    deb_arch = _DEB_ARCH.get(machine, "")
    simulation: Simulation | None = None
    simulation_error = ""
    pending: tuple[observation.PendingUpdate, ...] = ()
    if inputs.selection in SELECTIONS:
        pending = _selected(
            updates.value if updates is not None and updates.observed else None,
            inputs.selection,
        )
        if pending and deb_arch:
            requests = tuple((row.name, row.candidate) for row in pending)
            result = run_root(shell, upgrade_command(requests))
            if result.exit_status == 0 and not result.truncated:
                try:
                    simulation = parse_simulation(result.stdout)
                except ValueError:
                    simulation_error = "APT's simulation is not in a supported form."
            else:
                simulation_error = "APT could not resolve the reviewed updates."
    return UpdatesEvidence(
        standing=observed.standing.standing.value if observed.standing else "",
        machine=machine,
        deb_arch=deb_arch,
        boot_id=values.get("boot", ""),
        uptime_centiseconds=(int(values["uptime"]) if values.get("uptime", "").isdigit() else None),
        apt=values.get("apt", ""),
        dpkg=values.get("dpkg", ""),
        systemd=values.get("systemd", ""),
        held=tuple(part for part in values.get("holds", "").split(",") if part),
        disk_bytes=int(values["disk"]) if values.get("disk", "").isdigit() else None,
        memory_kib=int(values["memory"]) if values.get("memory", "").isdigit() else None,
        state=updates.value if updates is not None and updates.observed else None,
        update_warning=updates.warning if updates is not None else "",
        sites=sites,
        cache_sites=_cache_sites(observed),
        targets=targets,
        services=_services(shell),
        conffiles=_rows(_lines(run_root(shell, CONFFILE_FUNCTIONS + "\nmodified_conffiles"))),
        audit=_lines(run_root(shell, "dpkg --audit 2>&1")),
        downgrades=_downgrades(shell, pending),
        precondition_digest=_first(_lines(run_root(shell, PRECONDITION_COMMAND))),
        simulation=simulation,
        simulation_error=simulation_error,
    )


def _downgrades(
    shell: RemoteShell, pending: tuple[observation.PendingUpdate, ...]
) -> tuple[str, ...]:
    names: list[str] = []
    for row in pending:
        if not row.installed or not row.candidate:
            continue
        result = run_root(
            shell,
            f"dpkg --compare-versions {shlex.quote(row.candidate)} lt {shlex.quote(row.installed)}",
        )
        if result.exit_status == 0:
            names.append(row.name)
    return tuple(names)


def _first(lines: tuple[str, ...]) -> str:
    value = lines[0].strip() if lines else ""
    return value if valid_digest(value) else ""


def _selected(
    state: observation.UpdatesState | None, selection: str
) -> tuple[observation.PendingUpdate, ...]:
    if state is None:
        return ()
    wanted = {"security"} if selection == "security" else {"security", "other"}
    return tuple(row for row in state.pending if row.classification in wanted)


def inspect_check(shell: RemoteShell, inputs: PreparationInputs) -> UpdatesEvidence:
    return _evidence(shell, inputs)


def _platform_reasons(evidence: UpdatesEvidence) -> list[str]:
    reasons: list[str] = []
    if evidence.standing != Standing.TARGET_STACK.value:
        reasons.append("Set up and verify the host foundation before changing Ubuntu updates.")
    if not evidence.deb_arch:
        reasons.append("The server's architecture is not one Barectl supports.")
    if evidence.apt and not evidence.apt.startswith("apt 3.2."):
        reasons.append("The server is not the supported Ubuntu 26.04 platform.")
    if evidence.dpkg and "version 1.23." not in evidence.dpkg:
        reasons.append("The server is not the supported Ubuntu 26.04 platform.")
    if evidence.systemd and not evidence.systemd.startswith("systemd 259 "):
        reasons.append("The server is not the supported Ubuntu 26.04 platform.")
    if evidence.disk_bytes is not None and evidence.disk_bytes < _MIN_DISK_BYTES:
        reasons.append("The server lacks the free disk a reviewed update change needs.")
    if evidence.memory_kib is not None and evidence.memory_kib < _MIN_MEMORY_KIB:
        reasons.append("The server lacks the free memory a reviewed update change needs.")
    if not evidence.boot_id:
        reasons.append("The server's boot identity could not be read.")
    return reasons


def review_check(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, UpdatesEvidence):
        raise ValueError("A Check for updates change needs native evidence.")
    refusals = _platform_reasons(evidence)
    details = _check_details(evidence)
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": CHECK_SHA256,
        "architecture": evidence.machine,
        "details": details,
    }
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals:
        effects = (
            DeclaredEffect(
                Scope.SERVER,
                "Refresh Ubuntu's package lists from the server's configured Ubuntu archive.",
                evidence.sites,
            ),
        )
    return ReviewDraft(
        CHECK_SLUG,
        "Refresh Ubuntu's package lists.",
        effects=effects,
        stages=CHECK_STAGES,
        postconditions=(
            "Ubuntu's package lists are refreshed, so the waiting updates are current.",
            "Discovery reads the list age and waiting updates back from the server alone.",
        ),
        refusals=tuple(dict.fromkeys(refusals)),
        sites_read=SITES_READ,
        current_sites=evidence.sites,
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        document=document,
    )


def _check_details(evidence: UpdatesEvidence) -> list[dict[str, str]]:
    state = evidence.state
    if state is None:
        waiting = "The waiting updates could not be read."
        age = "The age of the package lists could not be read."
    else:
        security = sum(1 for row in state.pending if row.classification == "security")
        other = sum(1 for row in state.pending if row.classification == "other")
        waiting = f"{security} security and {other} other updates are waiting."
        age = (
            f"Package lists last refreshed {_age(state.list_age_seconds)}."
            if state.list_age_seconds is not None
            else "The age of the package lists could not be read."
        )
    return [
        {"label": "Network destinations", "value": "The server's configured Ubuntu archive."},
        {"label": "Before", "value": f"{waiting} {age}"},
        {"label": "Affected sites", "value": ", ".join(evidence.sites) or "None."},
    ]


def check_body(document: dict[str, object], context: BodyContext) -> NativeBody:
    if document.get("version") != 1 or document.get("body_sha256") != CHECK_SHA256:
        raise ValueError("The Check for updates review is not a valid immutable selection.")
    return NativeBody(CHECK_BYTES)


def verify_check(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    check_body(stored.document, BodyContext("", "", 0))
    observed = observation.collect(shell)
    if not observed.observed or observed.value is None:
        return None
    updates = observed.value.updates
    if not updates.observed or updates.value is None:
        return None
    return updates.value.list_age_seconds is not None


def inspect_install(shell: RemoteShell, inputs: PreparationInputs) -> UpdatesEvidence:
    return _evidence(shell, inputs)


def _transaction(  # noqa: C901 - one list of every refusal
    evidence: UpdatesEvidence, selection: str
) -> tuple[tuple[observation.PendingUpdate, ...], tuple[UpgradeAction, ...], str, list[str]]:
    """The selected updates, the reviewed actions, the requested roots and the refusals."""
    refusals: list[str] = []
    state = evidence.state
    if state is None:
        return (), (), "", [evidence.update_warning or "Barectl could not read Ubuntu's updates."]
    selected = _selected(state, selection)
    if not selected:
        return (), (), "", refusals
    # "Kept waiting" updates (held, phased and blocked) never enter the selected set; the
    # review discloses them instead of installing or silently dropping them.
    for row in selected:
        if row.name in evidence.downgrades:
            refusals.append(
                f"{row.name} would be downgraded from {row.installed} to {row.candidate}."
            )
        if not row.candidate or row.candidate in {"kept", "removed"}:
            refusals.append(f"{row.name} has no installable candidate version.")
        if row.archive and not ubuntu_origin(row.archive):
            refusals.append(f"{row.name} comes from {row.archive}, not the Ubuntu 26.04 archive.")
    if refusals:
        return selected, (), "", refusals
    if evidence.simulation_error:
        return selected, (), "", [evidence.simulation_error]
    simulation = evidence.simulation
    if simulation is None:
        return selected, (), "", ["APT could not resolve the reviewed updates."]
    refusals.extend(simulation.problems)
    if refusals:
        return selected, (), "", refusals
    requested = {row.name: row.candidate for row in selected}
    upgrades: dict[str, str] = {}
    for transition in simulation.transitions:
        if transition.action == "Remv" or transition.action == "Purg":
            refusals.append(f"Installing would remove {transition.package} {transition.previous}.")
        elif transition.action == "Inst" and transition.previous:
            upgrades[transition.package] = transition.version
    for name, version in requested.items():
        if upgrades.get(name) != version:
            refusals.append(
                f"APT would not upgrade {name} to {version}; check for updates and prepare again."
            )
    extra = sorted(set(upgrades) - set(requested))
    if extra:
        refusals.append(
            "APT would also upgrade " + ", ".join(extra) + ", which the review did not name. "
            "Check for updates and prepare again."
        )
    try:
        actions = upgrade_actions_of(simulation.transitions, evidence.deb_arch)
    except ValueError as error:
        refusals.append(str(error))
        return selected, (), "", refusals
    packages = {action.package for action in actions}
    held = set(evidence.held)
    refusals.extend(
        f"{name} is held with apt-mark hold. Release the hold first."
        for name in sorted(packages & held)
    )
    for package, path in evidence.conffiles:
        if package in packages:
            refusals.append(
                f"{package} has a configuration file that differs from the package's own: "
                f"{path}. Restore or confirm it through ordinary administration first."
            )
    if evidence.audit:
        refusals.append(
            "The package database has an unfinished package state: " + "; ".join(evidence.audit[:5])
        )
    roots = " ".join(f"{name}={upgrades.get(name, requested[name])}" for name in sorted(requested))
    return selected, actions, roots, refusals


def _install_document(
    evidence: UpdatesEvidence,
    selection: str,
    selected: tuple[observation.PendingUpdate, ...],
    actions: tuple[UpgradeAction, ...],
    roots: str,
) -> tuple[dict[str, object], tuple[DeclaredEffect, ...], list[dict[str, str]]]:
    packages = sorted({action.package for action in actions})
    new = sorted({action.package for action in actions if action.unpack and action.previous == "-"})
    details = _install_details(evidence, selected, actions, new)
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": INSTALL_SHA256,
        "selection": selection,
        "architecture": evidence.machine,
        "deb_arch": evidence.deb_arch,
        "precondition_digest": evidence.precondition_digest,
        "packages": packages,
        "roots": [[name, _version_of(actions, name)] for name in _upgraded(actions)],
        "requested": roots,
        "actions": [
            [action.unpack, action.package, action.previous, action.version, action.architecture]
            for action in actions
        ],
        "sites": [
            {"name": target.name, "readiness": target.readiness, "https": target.https}
            for target in evidence.targets
        ],
        "details": details,
    }
    names = ", ".join(f"{name} {_version_of(actions, name)}" for name in _upgraded(actions))
    text = (
        f"Install {len(_upgraded(actions))} Ubuntu "
        f"{'security ' if selection == 'security' else ''}update"
        f"{'s' if len(_upgraded(actions)) != 1 else ''}: {names}."
    )
    if new:
        text += " New dependencies: " + ", ".join(new) + "."
    text += " " + UPDATES_DISCLOSURE
    return document, (DeclaredEffect(Scope.SERVER, text, evidence.sites),), details


def _upgraded(actions: tuple[UpgradeAction, ...]) -> tuple[str, ...]:
    return tuple(
        sorted({action.package for action in actions if action.unpack and action.previous != "-"})
    )


def _version_of(actions: tuple[UpgradeAction, ...], name: str) -> str:
    return next(
        (
            action.version
            for action in actions
            if action.package == name and action.unpack and action.previous != "-"
        ),
        "",
    )


def _install_details(
    evidence: UpdatesEvidence,
    selected: tuple[observation.PendingUpdate, ...],
    actions: tuple[UpgradeAction, ...],
    new: list[str],
) -> list[dict[str, str]]:
    upgraded = _upgraded(actions)
    waiting = tuple(
        row
        for row in (evidence.state.pending if evidence.state is not None else ())
        if row.classification in _WAITING
    )
    services = _restarted_services(evidence, {action.package for action in actions})
    return [
        {
            "label": "Packages",
            "value": "\n".join(f"{name} {_version_of(actions, name)}" for name in upgraded)
            or "Nothing to install.",
        },
        {
            "label": "New dependencies",
            "value": "\n".join(f"{name} {_version_of_any(actions, name)}" for name in new)
            or "None.",
        },
        {
            "label": "Kept waiting",
            "value": "\n".join(
                f"{row.name} {_waiting_words(row.classification)}" for row in waiting
            )
            or "None.",
        },
        {
            "label": "Download",
            "value": _size(evidence.simulation.download_bytes if evidence.simulation else None),
        },
        {
            "label": "Disk space",
            "value": _size(evidence.simulation.installed_bytes if evidence.simulation else None),
        },
        {"label": "Restarted services", "value": "\n".join(services) or "None."},
        {"label": "Affected sites", "value": ", ".join(evidence.sites) or "None."},
        {
            "label": "Network destinations",
            "value": "The server's configured Ubuntu 26.04 archive only; Barectl adds no source.",
        },
    ]


def _size(value: int | None) -> str:
    if value is None:
        return "Ubuntu's package tool did not report a size."
    if value < 1000:
        return f"{value} B"
    if value < 1000**2:
        return f"{value / 1000:.1f} kB"
    return f"{value / 1000**2:.1f} MB"


def _version_of_any(actions: tuple[UpgradeAction, ...], name: str) -> str:
    return next((action.version for action in actions if action.package == name), "")


def _waiting_words(classification: str) -> str:
    return {
        "phased": "is waiting for Ubuntu's rollout",
        "held": "is held by an administrator",
        "blocked": "would remove a package",
    }.get(classification, "is waiting")


def _restarted_services(evidence: UpdatesEvidence, packages: set[str]) -> list[str]:
    states = dict(evidence.services)
    sensitive = bool(packages & _RESTART_SENSITIVE)
    lines: list[str] = []
    for service in _SERVICES:
        if states.get(service.unit) != "active":
            continue
        if not (sensitive or packages & set(service.owners)):
            continue
        sites = (
            evidence.sites
            if service.scope == "sites"
            else evidence.cache_sites
            if service.scope == "cache"
            else ()
        )
        served = ", ".join(sites) if sites else "no sites"
        lines.append(f"{service.label} ({service.unit}): {served}")
    return lines


def review_install(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, UpdatesEvidence):
        raise ValueError("An Install updates change needs native evidence.")
    refusals = _platform_reasons(evidence)
    if not valid_digest(evidence.precondition_digest):
        refusals.append("The server's package evidence could not be read.")
    if inputs.selection not in SELECTIONS:
        refusals.append("Choose whether to install security updates only or all updates.")
    selected, actions, roots, transaction_refusals = _transaction(evidence, inputs.selection)
    refusals.extend(transaction_refusals)
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": INSTALL_SHA256,
        "selection": inputs.selection,
        "architecture": evidence.machine,
        "deb_arch": evidence.deb_arch,
    }
    effects: tuple[DeclaredEffect, ...] = ()
    details: list[dict[str, str]] = []
    note = ""
    if actions and not refusals:
        document, effects, details = _install_document(
            evidence, inputs.selection, selected, actions, roots
        )
    elif not refusals:
        note = _no_changes_note(evidence, inputs.selection)
    return ReviewDraft(
        INSTALL_SLUG,
        (
            "Install Ubuntu security updates."
            if inputs.selection == "security"
            else "Install all waiting Ubuntu updates."
        ),
        effects=effects,
        stages=INSTALL_STAGES,
        postconditions=(
            (
                "Every reviewed package is installed at its reviewed version and Ubuntu's "
                "package database is clean."
            ),
            (
                "The foundation's profile units are running and each site answers its "
                "readiness path."
            ),
            (
                "Discovery reads the installed versions, the waiting updates and any restart "
                "Ubuntu asks for back from the server alone."
            ),
        ),
        refusals=tuple(dict.fromkeys(refusals)),
        sites_read=SITES_READ,
        current_sites=evidence.sites,
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        document={**document, "details": details, "note": note},
    )


def _no_changes_note(evidence: UpdatesEvidence, selection: str) -> str:
    if evidence.state is None:
        return "Ubuntu's waiting updates could not be read."
    if selection == "security":
        other = sum(1 for row in evidence.state.pending if row.classification == "other")
        return (
            "No security updates are waiting."
            if not other
            else f"No security updates are waiting. {other} other updates are waiting."
        )
    return "No Ubuntu updates are waiting."


def install_body(document: dict[str, object], context: BodyContext) -> NativeBody:
    selection = document.get("selection")
    digest = document.get("precondition_digest")
    roots = document.get("requested")
    packages = document.get("packages")
    actions = document.get("actions")
    if (
        document.get("version") != 1
        or document.get("body_sha256") != INSTALL_SHA256
        or selection not in SELECTIONS
        or not isinstance(digest, str)
        or not valid_digest(digest)
        or not isinstance(roots, str)
        or not roots
        or not isinstance(packages, list)
        or not packages
        or not all(isinstance(name, str) for name in packages)
        or not isinstance(actions, list)
        or not actions
    ):
        raise ValueError("The Install updates review is not a valid immutable selection.")
    for name in packages:
        check_package(name)
    approved: list[UpgradeAction] = []
    for action in actions:
        if (
            not isinstance(action, list)
            or len(action) != 5
            or type(action[0]) is not bool
            or not all(isinstance(value, str) for value in action[1:])
        ):
            raise ValueError("The Install updates review names invalid actions.")
        approved.append(UpgradeAction(action[0], action[1], action[2], action[3], action[4]))
    pairs = _root_pairs(roots)
    for name, version in pairs:
        check_package(name)
        check_version(version)
    upgraded = {action.package for action in approved if action.unpack and action.previous != "-"}
    if (
        set(packages) != {action.package for action in approved}
        or {name for name, _version in pairs} != upgraded
    ):
        raise ValueError("The Install updates review names an invalid transaction.")
    try:
        guard_text = upgrade_guard(tuple(approved))
    except ValueError as error:
        raise ValueError("The Install updates review is not a valid transaction.") from error
    return NativeBody(
        INSTALL_BYTES,
        (str(selection), digest, roots, guard_text, " ".join(packages)),
    )


def _root_pairs(roots: str) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for entry in roots.split():
        name, separator, version = entry.partition("=")
        if not separator or not name or not version:
            raise ValueError("The Install updates review names an invalid root.")
        pairs.append((name, version))
    return tuple(pairs)


def verify_install(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    install_body(stored.document, BodyContext("", "", 0))
    observed = _collect(shell)
    if observed.standing is None:
        return None
    if observed.standing.standing.value != Standing.TARGET_STACK.value:
        return False
    if not _installed(shell, stored.document):
        return False
    audit = run_root(shell, "dpkg --audit 2>&1")
    if audit.exit_status != 0 or audit.truncated or audit.stdout.strip():
        return False
    if not _profile_units(shell, observed):
        return False
    return _readiness(shell, stored.document)


def _installed(shell: RemoteShell, document: dict[str, object]) -> bool:
    actions = document.get("actions")
    if not isinstance(actions, list):
        return False
    pairs: list[tuple[str, str]] = []
    for action in actions:
        if (
            not isinstance(action, list)
            or len(action) != 5
            or type(action[0]) is not bool
            or not all(isinstance(value, str) for value in action[1:])
        ):
            return False
        if action[0]:
            pairs.append((action[1], action[3]))
    if not pairs:
        return True
    names = " ".join(shlex.quote(name) for name, _version in pairs)
    result = run_root(
        shell,
        f"dpkg-query -W -f='${{Package}} ${{Version}} ${{db:Status-Status}}\\n' {names}",
    )
    if result.exit_status != 0 or result.truncated:
        return False
    seen: dict[str, tuple[str, str]] = {}
    for line in result.stdout.splitlines():
        name, _, rest = line.partition(" ")
        version, _, status = rest.partition(" ")
        seen[name] = (version, status)
    return all(seen.get(name) == (version, "installed") for name, version in pairs)


def _profile_units(shell: RemoteShell, observed: CollectedSnapshot) -> bool:
    units = ["caddy.service"]
    sites = observed.sites.value if observed.sites.observed else ()
    runtimes: set[str] = set()
    for site in sites or ():
        if site.state != SiteState.MANAGED:
            continue
        units.append(f"haproxy-site@{site.identifier}.service")
        if site.php_version:
            runtimes.add(site.php_version)
    units.extend(f"php-fpm@{runtime}.service" for runtime in sorted(runtimes))
    quoted = " ".join(shlex.quote(unit) for unit in units)
    result = run_root(shell, f"systemctl is-active {quoted}")
    if result.exit_status != 0 or result.truncated:
        return False
    states = result.stdout.splitlines()
    return len(states) == len(units) and all(state == "active" for state in states)


def _readiness(shell: RemoteShell, document: dict[str, object]) -> bool:
    targets = document.get("sites")
    if not isinstance(targets, list) or not targets:
        return True
    deadline = time.monotonic() + 30
    pending = {
        (target["name"], target["readiness"], target["https"])
        for target in targets
        if isinstance(target, dict)
        and isinstance(target.get("name"), str)
        and isinstance(target.get("readiness"), str)
        and type(target.get("https")) is bool
    }
    if not pending:
        return False
    for name, path, https in pending:
        canonical, problem = _site_target(name, path)
        if problem:
            return False
        while True:
            status = _status(shell, canonical, path, https)
            if readiness_ok(path, status):
                break
            if status != 0 or time.monotonic() >= deadline:
                return False
            time.sleep(0.5)
    return True


def _site_target(name: str, path: str) -> tuple[str, str]:
    from sites.names import canonical_name

    canonical, problem = canonical_name(name)
    if problem:
        return "", problem
    _path, trouble = readiness_path(path)
    return canonical, trouble


def _status(shell: RemoteShell, host: str, path: str, https: bool) -> int:
    host = shlex.quote(host)
    path = shlex.quote(path)
    if https:
        request = f"https://{host}{path}"
        resolve = f"--resolve {host}:443:127.0.0.1"
        extra = "--insecure"
    else:
        request = f"http://127.0.0.1{path}"
        resolve = f"-H Host:{host}"
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


CHECK_FOR_UPDATES: Final = ChangeKind(
    CHECK_SLUG,
    CHECK_LABEL,
    inspect_check,
    review_check,
    check_body,
    verify_check,
    refresh_discovery=True,
)
INSTALL_UPDATES: Final = ChangeKind(
    INSTALL_SLUG,
    INSTALL_LABEL,
    inspect_install,
    review_install,
    install_body,
    verify_install,
    refresh_discovery=True,
    input_choices=SELECTIONS,
)


def _age(seconds: int) -> str:
    if seconds < 60:
        return "less than a minute ago"
    if seconds < 3600:
        return f"{seconds // 60} minutes ago"
    if seconds < 86400:
        return f"{seconds // 3600} hours ago"
    return f"{seconds // 86400} days ago"


__all__ = [
    "CHECK_FOR_UPDATES",
    "CHECK_SHA256",
    "CHECK_SLUG",
    "INSTALL_SHA256",
    "INSTALL_SLUG",
    "INSTALL_UPDATES",
    "SELECTIONS",
    "SiteTarget",
    "UpdatesEvidence",
    "check_body",
    "install_body",
    "review_check",
    "review_install",
    "verify_check",
    "verify_install",
]
