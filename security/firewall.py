"""Turn on the standard UFW firewall and manage one operator port (Phase E #306).

docs/security.md#firewall, docs/security-native-design.md#firewall-standard and
docs/adr/0023-change-server-access-with-native-confirm-or-revert.md. The review adopts
UFW's own state, names the exact package transaction when UFW is missing, and refuses
anything outside the supported grammar. The body saves a recovery preimage, arms the
five-minute revert timer, then changes the firewall only through ``ufw`` commands.
"""

import hashlib
import importlib.resources
import ipaddress
import re
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
from operations import revert
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview

from . import observation

SLUG: Final = "manage_firewall"
LABEL: Final = "Manage the firewall"
ACTIONS: Final = ("on", "add", "remove")
PROTOCOLS: Final = ("tcp", "udp")
ROOTS: Final = ("ufw",)
STAGES: Final = ("preflight", "install", "preimage", "apply", "verify")
STANDARD_TCP_PORTS: Final = ("80", "443")
STANDARD_UDP_PORTS: Final = ("443",)
PREIMAGE_FILES: Final = (
    "/etc/ufw/user.rules",
    "/etc/ufw/user6.rules",
    "/etc/ufw/ufw.conf",
    "/etc/default/ufw",
)
_DEB_ARCH: Final = {"x86_64": "amd64", "aarch64": "arm64"}
_MIN_DISK_BYTES: Final = 512 * 1024**2
_MIN_MEMORY_KIB: Final = 256 * 1024
_PORT = re.compile(r"([1-9][0-9]{0,4})(?::([1-9][0-9]{0,4}))?")
_AUTHORIZED_RULE = re.compile(
    r"allow (?:proto (tcp|udp) )?from ([0-9a-fA-F:.]+/[0-9]{1,3}) "
    r"to any port ([1-9][0-9]{0,4}(?::[1-9][0-9]{0,4})?)(?: proto (tcp|udp))?"
)
_SITES_READ: Final = (
    "find /etc/caddy/sites -maxdepth 1 -type f -name '*.caddy' -printf '%f\\n' "
    "| sed 's/\\.caddy$//' | LC_ALL=C sort"
)
DOCKER_PACKAGES: Final = "docker.io docker-ce docker-ce-cli containerd.io"
PRESTATE_READ: Final = (
    "{ "
    "ufw status verbose 2>&1 || true; "
    "ufw show added 2>&1 || true; "
    "cat /etc/ufw/ufw.conf 2>/dev/null || true; "
    "cat /etc/default/ufw 2>/dev/null || true; "
    "sshd -T 2>/dev/null | sed -n 's/^port //p' | LC_ALL=C sort -n; "
    "systemctl show ssh.socket -p ListenStream 2>/dev/null || true; "
    "dpkg-query -W -f='${Status} ${Version}\\n' ufw 2>/dev/null || true; "
    "}"
)
PRESTATE_COMMAND: Final = f"{PRESTATE_READ} | sha256sum | cut -d' ' -f1"
DIGEST_FUNCTIONS: Final = (
    f"firewall_pread() {{ {PRESTATE_READ}; }}\n"
    f"firewall_prestate() {{ firewall_pread | sha256sum | cut -d' ' -f1; }}"
)
BODY_BYTES: Final = (
    importlib.resources.files("security.bodies")
    .joinpath("firewall.sh")
    .read_text()
    .replace("# FIREWALL_DIGEST_FUNCTIONS", DIGEST_FUNCTIONS)
    .replace("# FIREWALL_SAVE", revert.save_steps(PREIMAGE_FILES, revert.reload_ufw_steps()))
    .replace("# FIREWALL_ARM", revert.arm_step())
    .rstrip("\n")
    .encode()
)
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()
# Verification re-validates the stored document through ``body``; a syntactically valid
# unit name is enough there because verification runs on the controller's own connection.
_VERIFY_UNIT: Final = "barectl-apply-" + "0" * 32 + ".service"


@dataclass(frozen=True)
class FirewallEvidence:
    firewall: observation.FirewallState | None
    ssh: observation.SshState | None
    listeners: tuple[observation.Listener, ...]
    standing: str
    machine: str
    deb_arch: str
    boot_id: str
    uptime_centiseconds: int | None
    apt: str
    dpkg: str
    systemd: str
    held: tuple[str, ...]
    ufw_version: str
    precondition_digest: str
    dry_run_digest: str
    dry_run_error: str
    docker_installed: bool
    connection_port: int
    disk_bytes: int | None = None
    memory_kib: int | None = None
    simulation: Simulation | None = None
    simulation_error: str = ""
    sites: tuple[str, ...] = ()


def read_command() -> str:
    return "; ".join(
        [
            "printf 'boot\\t%s\\n' \"$(cat /proc/sys/kernel/random/boot_id)\"",
            "printf 'uptime\\t%s\\n' \"$(cut -d' ' -f1 /proc/uptime | tr -d .)\"",
            "printf 'apt\\t%s\\n' \"$(apt --version)\"",
            "printf 'dpkg\\t%s\\n' \"$(dpkg --version | head -1)\"",
            "printf 'systemd\\t%s\\n' \"$(systemctl --version | head -1)\"",
            "printf 'holds\\t%s\\n' \"$(apt-mark showhold | tr '\\n' ',')\"",
            "printf 'disk\\t%s\\n' \"$(df -B1 --output=avail / | tail -1)\"",
            "printf 'memory\\t%s\\n' \"$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)\"",
            (
                "printf 'ufwstatus\\t%s\\n' \"$(dpkg-query -W -f='${db:Status-Status}' "
                'ufw 2>/dev/null || true)"'
            ),
            (
                "printf 'ufwversion\\t%s\\n' \"$(dpkg-query -W -f='${Version}' "
                'ufw 2>/dev/null || true)"'
            ),
            (
                "printf 'docker\\t%s\\n' \"$(dpkg-query -W -f='${db:Status-Status} ${Package}\\n' "
                f"{DOCKER_PACKAGES} 2>/dev/null | tr '\\n' ',' || true)\""
            ),
            f"printf 'precondition\\t%s\\n' \"$({PRESTATE_COMMAND})\"",
        ]
    )


_ALLOWED = {
    "boot",
    "uptime",
    "apt",
    "dpkg",
    "systemd",
    "holds",
    "disk",
    "memory",
    "ufwstatus",
    "ufwversion",
    "docker",
    "precondition",
}


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


def _collect(shell: RemoteShell) -> CollectedSnapshot:
    from discovery.observations import collect

    return collect(shell)


def _sites(observed: CollectedSnapshot) -> tuple[str, ...]:
    if not observed.sites.observed or observed.sites.value is None:
        return ()
    return tuple(sorted({site.identifier for site in observed.sites.value}))


def standard_ports(ssh_ports: tuple[int, ...]) -> tuple[tuple[str, str], ...]:
    """Every standard rule: the effective SSH ports, then the web rules."""
    rules = {("tcp", str(port)) for port in ssh_ports}
    rules.update(("tcp", port) for port in STANDARD_TCP_PORTS)
    rules.update(("udp", port) for port in STANDARD_UDP_PORTS)
    return tuple(sorted(rules, key=lambda item: (item[0], int(item[1]))))


def _rule(
    state: observation.FirewallState, protocol: str, ports: str, network: str = ""
) -> observation.FirewallRule | None:
    return next(
        (
            row
            for row in state.rules
            if row.kind in {"standard", "operator"}
            and row.action == "allow"
            and row.protocol == protocol
            and row.ports == ports
            and row.network == network
        ),
        None,
    )


def _standard_missing(
    state: observation.FirewallState, ssh_ports: tuple[int, ...]
) -> tuple[tuple[str, str], ...]:
    return tuple(
        sorted(
            (protocol, ports)
            for protocol, ports in standard_ports(ssh_ports)
            if _rule(state, protocol, ports) is None
        )
    )


def standard_holds(state: observation.FirewallState, ssh_ports: tuple[int, ...]) -> bool:
    """The fixed standard: on at boot, IPv6, safe defaults, low logging and public rules."""
    if (
        not state.ufw_installed
        or state.ufw_enabled is not True
        or state.ipv6 is not True
        or state.default_incoming != "deny"
        or state.default_outgoing != "allow"
        or state.default_routed != "deny"
        or not state.logging.lower().startswith("on (low)")
        or state.outside
        or state.conffiles_intact is False
    ):
        return False
    return not _standard_missing(state, ssh_ports)


def _ssh_ports_problem(
    ssh: observation.SshState,
    listeners: tuple[observation.Listener, ...],
    connection_port: int,
) -> str:
    configured = set(ssh.sshd_ports)
    listeners_ports = {
        row.port for row in listeners if row.protocol == "tcp" and observation.is_ssh_listener(row)
    }
    if not configured:
        return (
            "The server's SSH configuration did not name a port, so Barectl will not "
            "change the firewall."
        )
    if ssh.socket_ports and set(ssh.socket_ports) != configured:
        return (
            "The server's SSH socket and its SSH configuration name different ports, so "
            "Barectl will not change the firewall until they agree."
        )
    if listeners_ports != configured:
        return (
            "The SSH listeners do not agree with the server's SSH configuration, so Barectl "
            "will not change the firewall until they agree."
        )
    if connection_port not in configured:
        return (
            "The port this connection uses is not one the server's SSH configuration allows, "
            "so changing the firewall could cut off access."
        )
    return ""


def _rule_spec(
    inputs: PreparationInputs,
) -> tuple[tuple[str, str, str] | None, list[str]]:
    refusals: list[str] = []
    port = inputs.port.strip()
    protocol = inputs.protocol.strip().lower()
    network = inputs.network.strip()
    if protocol not in PROTOCOLS:
        refusals.append("Choose TCP or UDP for this port.")
    match = _PORT.fullmatch(port)
    if match is None or int(match[1]) > 65535 or (match[2] is not None and int(match[2]) > 65535):
        refusals.append("Enter one port from 1 to 65535, or a range such as 8000:8010.")
    elif match[2] is not None and int(match[1]) > int(match[2]):
        refusals.append("The first port in the range must not be higher than the last.")
    if network:
        try:
            parsed = ipaddress.ip_network(network, strict=True)
        except ValueError:
            refusals.append("Enter one IPv4 or IPv6 network in CIDR form, such as 203.0.113.0/24.")
        else:
            network = str(parsed)
    if refusals:
        return None, refusals
    return (protocol, port, network), []


def _command(protocol: str, port: str, network: str, *, delete: bool = False) -> list[str]:
    words = ["delete", "allow"] if delete else ["allow"]
    if network:
        return [*words, "from", network, "to", "any", "port", port, "proto", protocol]
    return [*words, f"{port}/{protocol}"]


def _planned_commands(
    state: observation.FirewallState,
    inputs: PreparationInputs,
    ssh_ports: tuple[int, ...],
) -> tuple[list[list[str]], str]:
    """The exact UFW commands the review proposes; preparation dry-runs each one."""
    spec, problem = _rule_spec(inputs) if inputs.selection != "on" else (None, [])
    if problem:
        return [], problem[0]
    if inputs.selection == "on":
        commands: list[list[str]] = []
        if not state.ufw_installed:
            return commands, ""
        commands.extend(
            [
                ["default", "deny", "incoming"],
                ["default", "allow", "outgoing"],
                ["default", "deny", "routed"],
                ["logging", "low"],
            ]
        )
        commands.extend(
            ["allow", f"{port}/{protocol}"]
            for protocol, port in _standard_missing(state, ssh_ports)
        )
        commands.append(["--force", "enable"])
        return commands, ""
    if spec is None:
        return [], ""
    protocol, port, network = spec
    return [_command(protocol, port, network, delete=inputs.selection == "remove")], ""


def _dry_run_digest(shell: RemoteShell, commands: list[list[str]]) -> tuple[str, str]:
    if not commands:
        return "", ""
    parts: list[str] = []
    for command in commands:
        # docs/security.md#firewall: ufw 0.36.2 persists the dry-run enable, so it is not
        # a read and preparation skips it.
        if command == ["--force", "enable"]:
            continue
        result = run_root(shell, "ufw --dry-run " + " ".join(_quoted(part) for part in command))
        if result.exit_status != 0 or result.truncated:
            return (
                "",
                (
                    "UFW could not simulate this change. Check the firewall's state, then "
                    "prepare again."
                ),
            )
        parts.append(result.stdout)
    return hashlib.sha256("\0".join(parts).encode()).hexdigest(), ""


def _quoted(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> FirewallEvidence:
    observed = _collect(shell)
    values = _values(shell)
    state = (
        observed.security.value.firewall.value
        if observed.security.observed
        and observed.security.value is not None
        and observed.security.value.firewall.observed
        else None
    )
    ssh = (
        observed.security.value.ssh.value
        if observed.security.observed
        and observed.security.value is not None
        and observed.security.value.ssh.observed
        else None
    )
    listeners = (
        observed.security.value.listeners.value
        if observed.security.observed
        and observed.security.value is not None
        and observed.security.value.listeners.observed
        and observed.security.value.listeners.value is not None
        else ()
    )
    machine = observed.architecture.value or ""
    deb_arch = _DEB_ARCH.get(machine, "")
    ssh_ports = ssh.sshd_ports if ssh is not None else ()
    commands = _planned_commands(state, inputs, ssh_ports) if state is not None else ([], "")
    dry_digest, dry_error = (
        _dry_run_digest(shell, commands[0]) if not commands[1] else ("", commands[1])
    )
    simulation: Simulation | None = None
    simulation_error = ""
    if inputs.selection == "on" and state is not None and not state.ufw_installed and deb_arch:
        result = run_root(shell, simulate_command(ROOTS))
        if result.exit_status == 0 and not result.truncated:
            try:
                simulation = parse_simulation(result.stdout)
            except ValueError:
                simulation_error = "APT's simulation is not in a supported form."
        else:
            simulation_error = "APT could not resolve the firewall's installation."
    docker = values.get("docker", "")
    docker_installed = any(
        entry.partition(" ")[0] in {"installed", "half-installed", "unpacked"}
        and entry.rpartition(" ")[2] in {"docker.io", "docker-ce", "docker-ce-cli", "containerd.io"}
        for entry in docker.split(",")
        if entry.strip()
    )
    return FirewallEvidence(
        state,
        ssh,
        listeners,
        observed.standing.standing.value if observed.standing else "",
        machine,
        deb_arch,
        values.get("boot", ""),
        int(values["uptime"]) if values.get("uptime", "").isdigit() else None,
        values.get("apt", ""),
        values.get("dpkg", ""),
        values.get("systemd", ""),
        tuple(part for part in values.get("holds", "").split(",") if part),
        values.get("ufwversion", "") if values.get("ufwstatus", "") == "installed" else "",
        values.get("precondition", ""),
        dry_digest,
        dry_error,
        docker_installed,
        _connection_port(shell),
        int(values["disk"]) if values.get("disk", "").isdigit() else None,
        int(values["memory"]) if values.get("memory", "").isdigit() else None,
        simulation,
        simulation_error,
        _sites(observed),
    )


def _connection_port(shell: RemoteShell) -> int:
    """The port the server's SSH daemon sees this connection on.

    A saved connection or the native harness may reach the server through a forwarder, so
    the controller's TCP port is not the server's. OpenSSH publishes the server-side port in
    ``SSH_CONNECTION``; the fallback keeps a direct connection usable when it is absent.
    """
    session = shell.run("printenv SSH_CONNECTION")
    if session.exit_status == 0 and not session.truncated:
        fields = session.stdout.split()
        if len(fields) >= 4 and fields[3].isdigit():
            value = int(fields[3])
            if 0 < value < 65536:
                return value
    value = getattr(shell, "port", 22)
    return value if type(value) is int and 0 < value < 65536 else 22


def _platform_reasons(evidence: FirewallEvidence) -> list[str]:
    reasons: list[str] = []
    if evidence.standing != Standing.TARGET_STACK.value:
        reasons.append("Set up and verify the host foundation before changing the firewall.")
    if not evidence.deb_arch:
        reasons.append("The server's architecture is not one Barectl supports.")
    if evidence.apt and not evidence.apt.startswith("apt 3.2."):
        reasons.append("The server is not the supported Ubuntu 26.04 platform.")
    if evidence.dpkg and "version 1.23." not in evidence.dpkg:
        reasons.append("The server is not the supported Ubuntu 26.04 platform.")
    if evidence.systemd and not evidence.systemd.startswith("systemd 259 "):
        reasons.append("The server is not the supported Ubuntu 26.04 platform.")
    if evidence.disk_bytes is not None and evidence.disk_bytes < _MIN_DISK_BYTES:
        reasons.append("The server lacks the free disk a reviewed firewall change needs.")
    if evidence.memory_kib is not None and evidence.memory_kib < _MIN_MEMORY_KIB:
        reasons.append("The server lacks the free memory a reviewed firewall change needs.")
    if not valid_digest(evidence.precondition_digest) or not evidence.boot_id:
        reasons.append("The server's firewall evidence could not be read.")
    return reasons


def _transaction(evidence: FirewallEvidence) -> tuple[tuple[PackageAction, ...], str, list[str]]:
    simulation = evidence.simulation
    if evidence.simulation_error:
        return (), "", [evidence.simulation_error]
    if simulation is None:
        return (), "", ["APT could not resolve the firewall's installation."]
    refusals = list(simulation.problems)
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
            "APT's simulation does not install the firewall. Check the package indexes, "
            "then prepare again."
        )
        return (), "", refusals
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
        return (), installed.version, refusals
    return actions, installed.version, refusals


def _rule_description(protocol: str, port: str, network: str) -> str:
    allowed = f"{port}/{protocol}"
    return f"{allowed} from {network}" if network else f"{allowed} from anywhere"


def _details(
    evidence: FirewallEvidence,
    inputs: PreparationInputs,
    ssh_ports: tuple[int, ...],
    version: str,
    install: bool,
) -> list[dict[str, str]]:
    state = evidence.firewall
    standard = ", ".join([f"{port}/tcp" for port in ssh_ports] + ["80/tcp", "443/tcp", "443/udp"])
    described = _rule_description(inputs.protocol, inputs.port.strip(), inputs.network.strip())
    action = {
        "on": "Turn on the standard firewall.",
        "add": f"Allow {described}.",
        "remove": f"Remove the allowance for {described}.",
    }[inputs.selection]
    details = [
        {"label": "What happens", "value": action},
        {"label": "Kept open", "value": standard},
        {
            "label": "80/tcp",
            "value": "Serves certificate challenges and redirects visitors to HTTPS.",
        },
        {"label": "443/udp", "value": "Serves HTTP/3."},
        {
            "label": f"{revert.WINDOW_MINUTES}-minute window",
            "value": (
                f"Barectl keeps the previous firewall settings for "
                f"{revert.WINDOW_MINUTES} minutes and opens a new connection to confirm "
                "access. If that fails, the server puts the previous settings back."
            ),
        },
        {
            "label": "If your connection drops",
            "value": (
                "Nothing needs doing: the server restores the previous firewall on its own "
                "and the change does not stay."
            ),
        },
        {
            "label": "If the server restarts",
            "value": (
                f"A restart inside the {revert.WINDOW_MINUTES}-minute window keeps the new "
                "rules. Only the automatic put-back is lost."
            ),
        },
        {
            "label": "Cloud firewall",
            "value": "A firewall at your cloud provider is outside what Barectl can see.",
        },
    ]
    if state is not None and state.ufw_installed and state.ufw_enabled is not True:
        details.append(
            {
                "label": "Before",
                "value": (
                    "The firewall was not both on and enabled at start-up, so its "
                    "protection did not hold."
                ),
            }
        )
    if install:
        details.append(
            {
                "label": "Package",
                "value": f"Install ufw {version} from the Ubuntu archive.",
            }
        )
    elif version:
        details.append({"label": "Package", "value": f"ufw {version}"})
    details.append({"label": "Affected sites", "value": ", ".join(evidence.sites) or "None."})
    return details


def review(  # noqa: C901 - one list of every refusal
    evidence: object, inputs: PreparationInputs
) -> ReviewDraft:
    if not isinstance(evidence, FirewallEvidence):
        raise ValueError("A firewall change needs native evidence.")
    state = evidence.firewall
    ssh = evidence.ssh
    refusals = _platform_reasons(evidence)
    if inputs.selection not in ACTIONS:
        refusals.append("Choose whether to turn on the firewall, allow a port or remove a port.")
    if state is None:
        refusals.append("The firewall settings could not be read.")
    if ssh is None:
        refusals.append("The SSH settings could not be read.")
    if evidence.docker_installed:
        refusals.append(
            "Docker is installed and publishes ports ahead of a host firewall, so Barectl "
            "does not manage the firewall on this server."
        )
    if state is not None and state.outside:
        refusals.append(
            "Some firewall settings are outside what Barectl supports, so it leaves them "
            "alone and will not change the firewall: " + "; ".join(state.outside)
        )
    ssh_ports = ssh.sshd_ports if ssh is not None else ()
    if ssh is not None:
        problem = _ssh_ports_problem(ssh, evidence.listeners, evidence.connection_port)
        if problem:
            refusals.append(problem)
    install = False
    actions: tuple[PackageAction, ...] = ()
    version = evidence.ufw_version
    if inputs.selection == "on" and state is not None and not state.ufw_installed:
        install = True
        actions, version, transaction_refusals = _transaction(evidence)
        refusals.extend(transaction_refusals)
    elif state is not None and state.ufw_installed and not version:
        refusals.append("The firewall's package version could not be read. Prepare again.")
    if state is not None and state.ufw_installed and state.ipv6 is False:
        refusals.append(
            "IPv6 is turned off in the firewall's settings, which is outside the standard "
            "Barectl manages."
        )
    no_changes = False
    note = ""
    spec: tuple[str, str, str] | None = None
    if inputs.selection in {"add", "remove"} and state is not None:
        if not state.ufw_installed:
            refusals.append("Turn on the standard firewall before changing its ports.")
        elif not standard_holds(state, ssh_ports):
            refusals.append(
                "The firewall is on but does not follow the standard Barectl manages. Turn "
                "the standard firewall on again before adding or removing ports."
            )
        else:
            spec, rule_refusals = _rule_spec(inputs)
            refusals.extend(rule_refusals)
            if spec is not None:
                protocol, port, network = spec
                if inputs.selection == "remove":
                    standard_rule = _rule(state, protocol, port)
                    if (
                        network == ""
                        and standard_rule is not None
                        and standard_rule.kind == "standard"
                    ):
                        refusals.append(
                            "Barectl does not remove the standard web and SSH allowances."
                        )
                    elif _rule(state, protocol, port, network) is None:
                        no_changes = True
                        note = "That port is already not allowed by an operator rule."
                elif _rule(state, protocol, port, network) is not None:
                    no_changes = True
                    note = "That port is already allowed by an operator rule."
    if (
        inputs.selection == "on"
        and state is not None
        and state.ufw_installed
        and standard_holds(state, ssh_ports)
    ):
        no_changes = True
        note = "The firewall already follows the standard Barectl manages."
    if evidence.dry_run_error and not refusals:
        refusals.append(evidence.dry_run_error)
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals and not no_changes:
        if inputs.selection == "on":
            text = (
                "Turn on the server's firewall and allow SSH and web traffic: every SSH "
                "port on TCP, 80/tcp, 443/tcp and 443/udp, with everything else refused."
            )
        elif inputs.selection == "add":
            if spec is None:
                raise ValueError("A firewall allowance needs a validated port.")
            text = f"Allow {_rule_description(spec[0], spec[1], spec[2])} through the firewall."
        else:
            if spec is None:
                raise ValueError("A firewall removal needs a validated port.")
            text = f"Remove the allowance for {_rule_description(spec[0], spec[1], spec[2])}."
        effects = (DeclaredEffect(Scope.SERVER, text, evidence.sites),)
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "action": inputs.selection,
        "install": install,
        "package_installed": state.ufw_installed if state is not None else False,
        "package_version": version,
        "architecture": evidence.machine,
        "deb_arch": evidence.deb_arch,
        "precondition_digest": evidence.precondition_digest,
        "dry_run_digest": evidence.dry_run_digest,
        "ssh_ports": list(ssh_ports),
        "connection_port": evidence.connection_port,
        "port": inputs.port.strip(),
        "protocol": inputs.protocol.strip().lower(),
        "network": inputs.network.strip(),
        "roots": [[ROOTS[0], version]] if install else [],
        "actions": [
            [action.unpack, action.package, action.version, action.architecture]
            for action in actions
        ],
        "details": _details(evidence, inputs, ssh_ports, version, install),
    }
    if note:
        document["note"] = note
    if inputs.selection == "on":
        intent = "Turn on the standard firewall."
    elif inputs.selection == "add":
        intent = "Allow a port through the firewall."
    else:
        intent = "Remove a port allowance from the firewall."
    described = _rule_description(inputs.protocol, inputs.port.strip(), inputs.network.strip())
    return ReviewDraft(
        SLUG,
        intent,
        effects=effects,
        stages=STAGES,
        postconditions=(
            (
                "The firewall is active at boot, covers IPv6, refuses incoming and routed "
                "traffic, allows outgoing traffic and logs at the low level."
                if inputs.selection == "on"
                else "The firewall still follows the standard Barectl manages."
            ),
            (
                "Every SSH port on TCP, 80/tcp, 443/tcp and 443/udp are allowed from anywhere."
                if inputs.selection == "on"
                else (
                    f"{described} is allowed."
                    if inputs.selection == "add"
                    else f"{described} is no longer allowed."
                )
            ),
            (
                f"Barectl confirms access over a new connection inside "
                f"{revert.WINDOW_MINUTES} minutes."
            ),
            "Discovery reads the effective rules back from the server alone.",
        ),
        refusals=tuple(dict.fromkeys(refusals)),
        sites_read=_SITES_READ,
        current_sites=evidence.sites,
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        document=document,
    )


def body(  # noqa: C901 - one validation of every reviewed field
    document: dict[str, object], context: BodyContext
) -> NativeBody:
    action = document.get("action")
    install = document.get("install")
    version = document.get("package_version")
    digest = document.get("precondition_digest")
    ports = document.get("ssh_ports")
    connection_port = document.get("connection_port")
    port = document.get("port")
    protocol = document.get("protocol")
    network = document.get("network")
    roots = document.get("roots")
    actions = document.get("actions")
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or action not in ACTIONS
        or type(install) is not bool
        or not isinstance(version, str)
        or not isinstance(digest, str)
        or not valid_digest(digest)
        or not isinstance(ports, list)
        or not all(type(item) is int and 0 < item < 65536 for item in ports)
        or type(connection_port) is not int
        or not 0 < connection_port < 65536
        or not isinstance(port, str)
        or not isinstance(protocol, str)
        or not isinstance(network, str)
        or not isinstance(roots, list)
        or not isinstance(actions, list)
    ):
        raise ValueError("The firewall review is not a valid immutable selection.")
    if action == "on":
        if port or protocol or network:
            raise ValueError("Turning on the firewall names an operator rule.")
    else:
        spec, refusals = _rule_spec(
            PreparationInputs(action, firewall=True, port=port, protocol=protocol, network=network)
        )
        if refusals or spec is None:
            raise ValueError("The firewall review names an invalid rule.")
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
            raise ValueError("The firewall review names an invalid package transaction.")
        check_package(str(roots[0][0]))
        for entry in actions:
            if not isinstance(entry, list) or len(entry) != 4 or type(entry[0]) is not bool:
                raise ValueError("The firewall review names invalid package actions.")
            approved.append(PackageAction(entry[0], str(entry[1]), str(entry[2]), str(entry[3])))
        try:
            guard_text = guard(tuple(approved))
        except ValueError as error:
            raise ValueError("The firewall review is not a valid package transaction.") from error
        requested = f"{ROOTS[0]}={version}"
    else:
        if roots or actions:
            raise ValueError("The firewall review names a package transaction without install.")
        guard_text = ""
        requested = ""
    check_version(version)
    window = revert.names(context.unit)
    return NativeBody(
        BODY_BYTES,
        (
            action,
            digest,
            requested,
            guard_text,
            ROOTS[0],
            version,
            ",".join(str(item) for item in sorted(set(ports))),
            ",".join(f"{protocol}:{item}" for protocol, item in standard_ports(tuple(ports))),
            port,
            protocol,
            network,
            str(connection_port),
            window.identifier,
        ),
    )


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    document = stored.document
    body(document, BodyContext(_VERIFY_UNIT, "", 0))
    observed = observation.collect(shell)
    if not observed.observed or observed.value is None:
        return None
    state = observed.value.firewall.value if observed.value.firewall.observed else None
    ssh = observed.value.ssh.value if observed.value.ssh.observed else None
    if state is None or ssh is None:
        return None
    ports = tuple(int(item) for item in document["ssh_ports"] if isinstance(item, int))
    if document["action"] == "on":
        return (
            observed.value.firewall.observed
            and standard_holds(state, ports)
            and _installed_version(shell) == document["package_version"]
        )
    if not standard_holds(state, ports):
        return False
    protocol = str(document["protocol"])
    port = str(document["port"])
    network = str(document["network"])
    found = _rule(state, protocol, port, network)
    return found is None if document["action"] == "remove" else found is not None


def _installed_version(shell: RemoteShell) -> str:
    result = run_root(
        shell,
        "dpkg-query -W -f='${db:Status-Status} ${Version}' ufw 2>/dev/null",
    )
    if result.exit_status != 0 or result.truncated:
        return ""
    status, _, version = result.stdout.strip().partition(" ")
    return version if status == "installed" else ""


MANAGE_FIREWALL: Final = ChangeKind(
    SLUG,
    LABEL,
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_choices=ACTIONS,
    input_shape=InputShape.FIREWALL,
    access_changing=True,
)
