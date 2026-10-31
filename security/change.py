"""Turn Ubuntu's automatic security updates on or off (Phase E #303).

The review reads Ubuntu's own unattended-upgrades evidence, refuses a customized setup for
turning updates on, and names the exact package transaction when the package is missing.
The body sets the package's own debconf answer and runs the distribution's
``dpkg-reconfigure``; it never writes a second scheduler or edits APT's configuration files
by hand. Verification reads the effective values back from the server.
"""

import hashlib
import importlib.resources
from dataclasses import dataclass
from typing import Final

from bootstrap.standing import Standing
from databases.packages import (
    PackageAction,
    Simulation,
    actions_of,
    check_package,
    check_version,
    guard,
    parse_simulation,
    simulate_command,
    valid_digest,
)
from discovery.root_read import run_root
from discovery.snapshot import CollectedSnapshot
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import PreparationInputs
from operations.models import ChangeReview

from . import observation
from .presentation import custom_updates

SLUG: Final = "set_automatic_security_updates"
LABEL: Final = "Change automatic security updates"
STATES: Final = ("on", "off")
ROOTS: Final = ("unattended-upgrades",)
STAGES_ON: Final = ("preflight", "install", "configure", "verify")
STAGES_OFF: Final = ("preflight", "configure", "verify")
_DEB_ARCH: Final = {"x86_64": "amd64", "aarch64": "arm64"}
_MIN_DISK_BYTES: Final = 512 * 1024**2
_MIN_MEMORY_KIB: Final = 256 * 1024
_PERIODIC = "'^APT::Periodic::(Update-Package-Lists|Unattended-Upgrade) '"
_SETTINGS = "'^Unattended-Upgrade::(Allowed-Origins|Package-Blacklist|Automatic-Reboot)'"
PRECONDITION_COMMAND: Final = (
    "{ "
    "dpkg-query -W -f='${db:Status-Status} ${Version}\\n' unattended-upgrades "
    "2>/dev/null || true; "
    "sha256sum /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null || true; "
    f"apt-config dump | grep -E {_PERIODIC} || true; "
    f"apt-config dump | grep -E {_SETTINGS} || true; "
    "} | sha256sum | cut -d' ' -f1"
)
SETTINGS_COMMAND: Final = f"apt-config dump | grep -E {_SETTINGS} | sha256sum | cut -d' ' -f1"
DIGEST_FUNCTIONS: Final = (
    f"precondition_digest() {{ {PRECONDITION_COMMAND}; }}\n"
    f"settings_digest() {{ {SETTINGS_COMMAND}; }}"
)
BODY_BYTES: Final = (
    importlib.resources.files("security.bodies")
    .joinpath("automatic_updates.sh")
    .read_text()
    .replace("# SECURITY_DIGEST_FUNCTIONS", DIGEST_FUNCTIONS)
    .rstrip("\n")
    .encode()
)
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()
SITES_READ: Final = (
    "find /etc/caddy/sites -maxdepth 1 -type f -name '*.caddy' -printf '%f\\n' "
    "| sed 's/\\.caddy$//' | LC_ALL=C sort"
)


@dataclass(frozen=True)
class AutoUpdatesEvidence:
    state: observation.AutoUpdatesState | None
    standing: str
    machine: str
    deb_arch: str
    boot_id: str
    uptime_centiseconds: int | None
    apt: str
    dpkg: str
    systemd: str
    held: tuple[str, ...]
    installed_version: str
    precondition_digest: str
    settings_digest: str
    disk_bytes: int | None = None
    memory_kib: int | None = None
    simulation: Simulation | None = None
    simulation_error: str = ""
    sites: tuple[str, ...] = ()


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
        (
            "printf 'package\\t%s\\n' \"$(dpkg-query -W -f='${db:Status-Status}' "
            'unattended-upgrades 2>/dev/null || true)"'
        ),
        (
            "printf 'version\\t%s\\n' \"$(dpkg-query -W -f='${Version}' "
            'unattended-upgrades 2>/dev/null || true)"'
        ),
        f"printf 'precondition\\t%s\\n' \"$({PRECONDITION_COMMAND})\"",
        f"printf 'settings\\t%s\\n' \"$({SETTINGS_COMMAND})\"",
    ]
    return "; ".join(parts)


def _values(shell: RemoteShell) -> dict[str, str]:
    result = run_root(shell, read_command())
    if result.exit_status != 0 or result.truncated:
        return {}
    allowed = {
        "boot",
        "uptime",
        "apt",
        "dpkg",
        "systemd",
        "holds",
        "disk",
        "memory",
        "package",
        "version",
        "precondition",
        "settings",
    }
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        name, separator, value = line.partition("\t")
        if not separator or name not in allowed or name in values:
            return {}
        values[name] = value
    return values


def _collect(shell: RemoteShell) -> CollectedSnapshot:
    from discovery.observations import collect

    return collect(shell)


def _sites(observed: CollectedSnapshot) -> tuple[str, ...]:
    if not observed.sites.observed or observed.sites.value is None:
        return ()
    return tuple(sorted({site.identifier for site in observed.sites.value}))


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> AutoUpdatesEvidence:
    observed = _collect(shell)
    values = _values(shell)
    state = (
        observed.security.value.auto_updates.value
        if observed.security.observed and observed.security.value is not None
        else None
    )
    machine = observed.architecture.value or ""
    deb_arch = _DEB_ARCH.get(machine, "")
    simulation: Simulation | None = None
    simulation_error = ""
    if inputs.selection == "on" and state is not None and not state.package_installed and deb_arch:
        result = run_root(shell, simulate_command(ROOTS))
        if result.exit_status == 0 and not result.truncated:
            try:
                simulation = parse_simulation(result.stdout)
            except ValueError:
                simulation_error = "APT's simulation is not in a supported form."
        else:
            simulation_error = "APT could not resolve the installation."
    return AutoUpdatesEvidence(
        state=state,
        standing=observed.standing.standing.value if observed.standing else "",
        machine=machine,
        deb_arch=deb_arch,
        boot_id=values.get("boot", ""),
        uptime_centiseconds=(int(values["uptime"]) if values.get("uptime", "").isdigit() else None),
        apt=values.get("apt", ""),
        dpkg=values.get("dpkg", ""),
        systemd=values.get("systemd", ""),
        held=tuple(part for part in values.get("holds", "").split(",") if part),
        installed_version=(
            values.get("version", "") if values.get("package", "") == "installed" else ""
        ),
        precondition_digest=values.get("precondition", ""),
        settings_digest=values.get("settings", ""),
        disk_bytes=int(values["disk"]) if values.get("disk", "").isdigit() else None,
        memory_kib=int(values["memory"]) if values.get("memory", "").isdigit() else None,
        simulation=simulation,
        simulation_error=simulation_error,
        sites=_sites(observed),
    )


def _platform_reasons(evidence: AutoUpdatesEvidence) -> list[str]:
    reasons: list[str] = []
    if evidence.standing != Standing.TARGET_STACK.value:
        reasons.append(
            "Set up and verify the host foundation before changing automatic security updates."
        )
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
    if not valid_digest(evidence.precondition_digest) or not evidence.boot_id:
        reasons.append("The server's automatic-update evidence could not be read.")
    if not valid_digest(evidence.settings_digest):
        reasons.append("The server's allowed update sources could not be read.")
    return reasons


def _transaction(
    evidence: AutoUpdatesEvidence,
) -> tuple[Simulation | None, tuple[PackageAction, ...], str, list[str]]:
    refusals: list[str] = []
    simulation = evidence.simulation
    if evidence.simulation_error:
        return None, (), "", [evidence.simulation_error]
    if simulation is None:
        return None, (), "", ["APT could not resolve the unattended-upgrades installation."]
    refusals.extend(simulation.problems)
    installed = next(
        (
            transition
            for transition in simulation.transitions
            if transition.action == "Inst" and transition.package == ROOTS[0]
        ),
        None,
    )
    if installed is None:
        refusals.append(
            "APT's simulation does not install unattended-upgrades. Check the package "
            "indexes, then prepare again."
        )
    held = {name.split(":", 1)[0] for name in evidence.held}
    refusals.extend(
        f"{transition.package} is held with apt-mark hold. Release the hold through "
        "ordinary administration, then prepare again."
        for transition in simulation.transitions
        if transition.package in held
    )
    try:
        actions = actions_of(simulation.transitions, evidence.deb_arch)
    except ValueError as error:
        refusals.append(f"{error} This reduced transaction only installs missing packages.")
        return simulation, (), installed.version if installed is not None else "", refusals
    return simulation, actions, installed.version if installed is not None else "", refusals


def _expected_settings(
    state: observation.AutoUpdatesState, *, install: bool
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if install:
        return observation.DEFAULT_ALLOWED_ORIGINS, ()
    return state.allowed_origins, state.package_blacklist


def _details(
    evidence: AutoUpdatesEvidence,
    selection: str,
    version: str,
    install: bool,
    origins: tuple[str, ...],
    blacklist: tuple[str, ...],
) -> list[dict[str, str]]:
    state = evidence.state
    last = state.last_upgrade if state is not None else ""
    if state is not None and state.newest_log_age is not None and not last:
        last = f"No result was recorded; the newest log is {state.newest_log_age} seconds old."
    return [
        {"label": "Automatic updates", "value": "On" if selection == "on" else "Off"},
        {
            "label": "Package",
            "value": (
                f"Install unattended-upgrades {version} from the Ubuntu archive."
                if install
                else f"unattended-upgrades {version or 'not installed'}"
            ),
        },
        {
            "label": "Allowed update sources",
            "value": "\n".join(origins) or "Ubuntu's defaults.",
        },
        {
            "label": "Kept out of automatic updates",
            "value": "\n".join(blacklist) or "None.",
        },
        {
            "label": "Ubuntu's own history",
            "value": last or "No run is recorded in the newest log.",
        },
        {
            "label": "Restart",
            "value": (
                "Automatic updates can restart the database engine and Valkey, so sites may "
                "pause briefly. They do not restart the web server or PHP."
                if selection == "on"
                else "Off; nothing is restarted by automatic updates."
            ),
        },
        {
            "label": "Affected sites",
            "value": ", ".join(evidence.sites) or "None.",
        },
    ]


def review(  # noqa: C901 - one list of every refusal
    evidence: object, inputs: PreparationInputs
) -> ReviewDraft:
    if not isinstance(evidence, AutoUpdatesEvidence):
        raise ValueError("An automatic-updates change needs native evidence.")
    state = evidence.state
    refusals = _platform_reasons(evidence)
    if inputs.selection not in STATES:
        refusals.append("Choose whether to turn automatic security updates on or off.")
    elif state is None:
        refusals.append("The automatic-update settings could not be read.")
    if state is not None and inputs.selection == "on":
        refusals.extend(custom_updates(state))
    install = bool(state is not None and inputs.selection == "on" and not state.package_installed)
    actions: tuple[PackageAction, ...] = ()
    version = evidence.installed_version
    if install:
        _simulation, actions, version, transaction_refusals = _transaction(evidence)
        refusals.extend(transaction_refusals)
    elif state is not None and state.package_installed and not version:
        refusals.append("The unattended-upgrades version could not be read. Prepare again.")
    unchanged = (
        state is not None
        and not refusals
        and (
            (inputs.selection == "on" and state.enabled and not install)
            or (inputs.selection == "off" and (not state.package_installed or not state.enabled))
        )
    )
    origins, blacklist = (
        _expected_settings(state, install=install) if state is not None else ((), ())
    )
    automatic_reboot = bool(state.automatic_reboot) if state is not None else False
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "state": inputs.selection,
        "install": install,
        "package_installed": state.package_installed if state is not None else False,
        "package_version": version,
        "architecture": evidence.machine,
        "deb_arch": evidence.deb_arch,
        "precondition_digest": evidence.precondition_digest,
        "settings_digest": "" if install else evidence.settings_digest,
        "origins": list(origins),
        "blacklist": list(blacklist),
        "automatic_reboot": automatic_reboot,
        "roots": [[ROOTS[0], version]] if install else [],
        "actions": [
            [action.unpack, action.package, action.version, action.architecture]
            for action in actions
        ],
        "details": _details(evidence, inputs.selection, version, install, origins, blacklist),
    }
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals and not unchanged:
        if inputs.selection == "on":
            text = (
                "Turn on Ubuntu's automatic security updates: refresh package lists and "
                "install security updates daily."
            )
            if install:
                text += f" Install unattended-upgrades {version} from the Ubuntu archive."
            text += " Updates can restart the database engine and Valkey."
        else:
            text = (
                "Turn off Ubuntu's automatic security updates. Existing allowed update "
                "sources, package blacklists and automatic-reboot settings stay unchanged."
            )
        effects = (DeclaredEffect(Scope.SERVER, text, evidence.sites),)
    note = ""
    if unchanged:
        note = (
            "Ubuntu's automatic security updates are already on with the supported settings."
            if inputs.selection == "on"
            else "Ubuntu's automatic security updates are already off."
        )
    return ReviewDraft(
        SLUG,
        (
            "Turn on Ubuntu's automatic security updates."
            if inputs.selection == "on"
            else "Turn off Ubuntu's automatic security updates."
        ),
        effects=effects,
        stages=STAGES_ON if inputs.selection == "on" else STAGES_OFF,
        postconditions=(
            (
                "Ubuntu refreshes its package lists and installs security updates daily."
                if inputs.selection == "on"
                else "Ubuntu no longer installs security updates by itself."
            ),
            (
                "Allowed update sources, package blacklists and automatic reboot stay as "
                "they were, and the server never restarts itself after updates."
                if inputs.selection == "on"
                else (
                    "Allowed update sources, package blacklists and automatic reboot stay as "
                    "they were."
                )
            ),
            (
                "Both apt-daily timers are enabled."
                if inputs.selection == "on"
                else "The timers are left as they were."
            ),
            "Discovery reads the effective setting back from the server alone.",
        ),
        refusals=tuple(dict.fromkeys(refusals)),
        sites_read=SITES_READ,
        current_sites=evidence.sites,
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        document={**document, "note": note} if note else document,
    )


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    state = document.get("state")
    install = document.get("install")
    version = document.get("package_version")
    digest = document.get("precondition_digest")
    settings = document.get("settings_digest")
    origins = document.get("origins")
    blacklist = document.get("blacklist")
    automatic_reboot = document.get("automatic_reboot")
    roots = document.get("roots")
    actions = document.get("actions")
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or state not in STATES
        or type(install) is not bool
        or not isinstance(version, str)
        or not version
        or not isinstance(digest, str)
        or not valid_digest(digest)
        or not isinstance(settings, str)
        or (settings and not valid_digest(settings))
        or not isinstance(origins, list)
        or not all(isinstance(origin, str) for origin in origins)
        or not isinstance(blacklist, list)
        or not all(isinstance(item, str) for item in blacklist)
        or type(automatic_reboot) is not bool
        or not isinstance(roots, list)
        or not isinstance(actions, list)
    ):
        raise ValueError("The automatic-updates review is not a valid immutable selection.")
    check_version(version)
    approved: list[PackageAction] = []
    if install:
        if (
            len(roots) != 1
            or not isinstance(roots[0], list)
            or len(roots[0]) != 2
            or roots[0][0] != ROOTS[0]
            or roots[0][1] != version
            or not actions
        ):
            raise ValueError("The automatic-updates review names an invalid transaction.")
        check_package(str(roots[0][0]))
        for action in actions:
            if not isinstance(action, list) or len(action) != 4 or type(action[0]) is not bool:
                raise ValueError("The automatic-updates review names invalid actions.")
            approved.append(
                PackageAction(action[0], str(action[1]), str(action[2]), str(action[3]))
            )
        try:
            guard_text = guard(tuple(approved))
        except ValueError as error:
            raise ValueError("The automatic-updates review is not a valid transaction.") from error
        requested = f"{ROOTS[0]}={version}"
    else:
        if roots or actions:
            raise ValueError("The automatic-updates review names a transaction without install.")
        guard_text = ""
        requested = ""
    return NativeBody(
        BODY_BYTES,
        (str(state), digest, requested, guard_text, ROOTS[0], version, settings),
    )


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    document = stored.document
    body(document, BodyContext("", "", 0))
    observed = observation.collect(shell)
    if not observed.observed or observed.value is None:
        return None
    check = observed.value.auto_updates
    if not check.observed or check.value is None:
        return None
    state = check.value
    version = str(document["package_version"])
    origins = tuple(str(origin) for origin in document["origins"])
    blacklist = tuple(str(item) for item in document["blacklist"])
    reboot = bool(document["automatic_reboot"])
    if document["state"] == "off":
        if not state.package_installed:
            return True
        return (
            not state.enabled
            and state.allowed_origins == origins
            and state.package_blacklist == blacklist
            and bool(state.automatic_reboot) == reboot
        )
    return (
        state.package_installed
        and state.enabled
        and state.allowed_origins == origins
        and state.package_blacklist == blacklist
        and bool(state.automatic_reboot) == reboot
        and state.conffile_matches_package is not False
        and state.list_update_timer == "enabled"
        and state.upgrade_timer == "enabled"
        and _installed_version(shell) == version
    )


def _installed_version(shell: RemoteShell) -> str:
    result = run_root(
        shell,
        "dpkg-query -W -f='${db:Status-Status} ${Version}' unattended-upgrades 2>/dev/null",
    )
    if result.exit_status != 0 or result.truncated:
        return ""
    status, _, version = result.stdout.strip().partition(" ")
    return version if status == "installed" else ""


SET_AUTOMATIC_SECURITY_UPDATES: Final = ChangeKind(
    SLUG,
    LABEL,
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_choices=STATES,
)
