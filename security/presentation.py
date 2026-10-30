"""Plain-language Security checks from stored observations (Phase E #302, #179).

The default view states tasks, not native detail: what Barectl saw, why it matters, when it
was read and the one next action. Engine detail stays under Advanced.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from discovery.snapshot import CollectedSnapshot
from runtimes.catalog import architecture_of
from runtimes.presentation import shown_runtimes, shown_updates

from .observation import (
    STANDARD_PUBLIC_PORTS,
    AutoUpdatesState,
    Check,
    FirewallState,
    Listener,
    RestartState,
    SecurityState,
    SshState,
    UpdatesState,
)


class CheckState(StrEnum):
    OK = "ok"
    ATTENTION = "attention"
    UNKNOWN = "unknown"
    OUTSIDE = "outside"


OK = CheckState.OK
ATTENTION = CheckState.ATTENTION
UNKNOWN = CheckState.UNKNOWN
OUTSIDE = CheckState.OUTSIDE
_NOT_AVAILABLE = "Not available yet"
_RUNTIME_CHECK_SETTING = "Web runtime fixes arrive through Barectl releases, not Ubuntu updates."
_CLOUD_FIREWALL = "A firewall at your cloud provider is outside what Barectl can see."


@dataclass(frozen=True)
class ShownCheck:
    name: str
    state: CheckState
    what: str
    why: str
    read_at: datetime
    action: str
    action_url: str = ""
    details: tuple[str, ...] = ()
    note: str = ""


def present(
    collected: CollectedSnapshot, read_at: datetime, *, advanced_url: str = ""
) -> tuple[ShownCheck, ...]:
    """The checks, in the section's fixed order."""
    state = collected.security.value if collected.security.observed else None
    if state is None:
        names = (
            "Firewall",
            "SSH sign-in",
            "Automatic security updates",
            "Ubuntu updates",
            "Restart needed",
        )
        return (
            *(_unknown(name, read_at) for name in names),
            _runtimes(collected, read_at, advanced_url),
        )
    return (
        _firewall(state.firewall, state.listeners, state.ssh, read_at),
        _ssh(state.ssh, read_at),
        _auto_updates(state.auto_updates, read_at),
        _updates(state.updates, read_at),
        _restart(state.restart, read_at),
        _runtimes(collected, read_at, advanced_url),
    )


def check_reads(
    state: SecurityState | None,
) -> tuple[tuple[str, Check[object]], ...]:
    """The named check evidence, for the Advanced reads behind the section."""
    if state is None:
        return ()
    return (
        ("Firewall", state.firewall),
        ("Public ports", state.listeners),
        ("SSH sign-in", state.ssh),
        ("Automatic security updates", state.auto_updates),
        ("Ubuntu updates", state.updates),
        ("Restart needed", state.restart),
    )


def _unknown(name: str, read_at: datetime) -> ShownCheck:
    return ShownCheck(
        name,
        UNKNOWN,
        "Could not check. Run a connection check to read this.",
        "",
        read_at,
        _NOT_AVAILABLE,
    )


def _could_not(name: str, check: Check[object], why: str, read_at: datetime) -> ShownCheck:
    reason = check.warning or f"Could not check ({check.status.label.lower()})."
    return ShownCheck(name, UNKNOWN, reason, why, read_at, _NOT_AVAILABLE)


def _firewall(
    check: Check[FirewallState],
    listeners: Check[tuple[Listener, ...]],
    ssh: Check[SshState],
    read_at: datetime,
) -> ShownCheck:
    firewall = _firewall_state(check, read_at)
    exposure = _listeners(listeners, ssh, read_at)
    states = {firewall.state, exposure.state}
    if OUTSIDE in states:
        state = OUTSIDE
    elif ATTENTION in states:
        state = ATTENTION
    elif UNKNOWN in states:
        state = UNKNOWN
    else:
        state = OK
    details = (*firewall.details, *exposure.details)
    note = firewall.note or exposure.note
    if state == UNKNOWN:
        what = firewall.what if firewall.state == UNKNOWN else exposure.what
    else:
        what = " ".join(part for part in (firewall.what, exposure.what) if part)
    return ShownCheck(
        "Firewall",
        state,
        what,
        firewall.why,
        read_at,
        _NOT_AVAILABLE,
        details=details,
        note=note,
    )


def _firewall_state(check: Check[FirewallState], read_at: datetime) -> ShownCheck:
    why = "Only the ports you intend to expose should accept connections from the internet."
    if not check.observed or check.value is None:
        return _could_not("Firewall", check, why, read_at)
    state = check.value
    if state.outside:
        return ShownCheck(
            "Firewall",
            OUTSIDE,
            "Some firewall settings are outside what Barectl supports, so it leaves them "
            "alone and will not change the firewall.",
            why,
            read_at,
            _NOT_AVAILABLE,
            details=state.outside,
            note=_CLOUD_FIREWALL,
        )
    if not state.ufw_installed:
        return ShownCheck(
            "Firewall",
            ATTENTION,
            "No firewall is set up on the server, so every port it listens on is reachable.",
            why,
            read_at,
            _NOT_AVAILABLE,
            note=_CLOUD_FIREWALL,
        )
    if state.ufw_enabled is not True:
        return ShownCheck(
            "Firewall",
            ATTENTION,
            "The firewall is off, so every port the server listens on is reachable.",
            why,
            read_at,
            _NOT_AVAILABLE,
            note=_CLOUD_FIREWALL,
        )
    allowed = _firewall_allowed(state)
    defaults = (
        f"Defaults: incoming {state.default_incoming or 'unknown'}, "
        f"outgoing {state.default_outgoing or 'unknown'}, "
        f"routed {state.default_routed or 'unknown'}."
    )
    details = [defaults]
    if state.ipv6 is False:
        details.append("IPv6 is not covered by the firewall.")
    details.extend(row.line for row in state.rules if row.kind == "operator")
    return ShownCheck(
        "Firewall",
        ATTENTION if state.ipv6 is False else OK,
        f"The firewall is on. It allows {allowed}.",
        why,
        read_at,
        _NOT_AVAILABLE,
        details=tuple(details),
        note=_CLOUD_FIREWALL,
    )


def _firewall_allowed(state: FirewallState) -> str:
    ports = sorted(
        {
            f"{row.ports}/{row.protocol}"
            for row in state.rules
            if row.kind in {"standard", "operator"} and row.ports
        }
    )
    return ", ".join(ports) if ports else "nothing yet"


def _listeners(
    check: Check[tuple[Listener, ...]],
    ssh: Check[SshState],
    read_at: datetime,
) -> ShownCheck:
    why = "A public database, cache or management port can be reached by anyone."
    if not check.observed or check.value is None:
        return _could_not("", check, why, read_at)
    ssh_ports = ssh.value.ports if ssh.observed and ssh.value else (22,)
    expected = set(STANDARD_PUBLIC_PORTS) | {("tcp", port) for port in ssh_ports}
    public = [row for row in check.value if row.public]
    unexpected = [row for row in public if (row.protocol, row.port) not in expected]
    if not public:
        return ShownCheck(
            "",
            OK,
            "Nothing listens for connections from the internet.",
            why,
            read_at,
            _NOT_AVAILABLE,
        )
    if unexpected:
        named = ", ".join(
            f"{_plain_process(row.process) or 'Another program'} on {row.port}/{row.protocol}"
            for row in unexpected
        )
        return ShownCheck(
            "",
            ATTENTION,
            f"Programs outside the standard web and SSH ports accept connections: {named}.",
            why,
            read_at,
            _NOT_AVAILABLE,
            details=tuple(
                f"{_plain_process(row.process) or 'Unknown program'}: "
                f"{row.address}:{row.port}/{row.protocol}"
                for row in unexpected
            ),
        )
    return ShownCheck(
        "",
        OK,
        "Only SSH and web traffic accept connections from the internet.",
        why,
        read_at,
        _NOT_AVAILABLE,
        details=tuple(f"{row.process or 'A program'}: {row.port}/{row.protocol}" for row in public),
    )


def _ssh(check: Check[SshState], read_at: datetime) -> ShownCheck:
    why = "A guessed password can sign in; a key cannot be guessed."
    if not check.observed or check.value is None:
        return _could_not("SSH sign-in", check, why, read_at)
    state = check.value
    passwords = (
        state.password_authentication == "yes"  # noqa: S105 - a setting name, not a secret
        or state.keyboard_interactive == "yes"
    )
    root_password = state.permit_root_login == "yes"
    if passwords or root_password:
        parts = []
        if passwords:
            parts.append("passwords can sign in")
        if root_password:
            parts.append("the root account can sign in with a password")
        what = "Sign-in settings are weak: " + " and ".join(parts) + "."
        return ShownCheck(
            "SSH sign-in",
            ATTENTION,
            what,
            why,
            read_at,
            _NOT_AVAILABLE,
            details=tuple(
                f"{name} can sign in but has no authorized key."
                for name in state.accounts_without_keys
            )
            if state.accounts_without_keys
            else (),
        )
    details = []
    if state.accounts_without_keys:
        details.append(
            "These accounts can sign in but have no authorized key: "
            + ", ".join(state.accounts_without_keys)
            + "."
        )
    if state.per_source_penalties == "yes":
        details.append("Repeated failed attempts are slowed down.")
    if state.socket_ports and set(state.socket_ports) != set(state.ports):
        details.append(
            "The SSH listener and its configuration name different ports; Barectl will not "
            "change the firewall until they agree."
        )
    return ShownCheck(
        "SSH sign-in",
        OK,
        "Only key sign-in is allowed; passwords cannot sign in.",
        why,
        read_at,
        _NOT_AVAILABLE,
        details=tuple(details),
    )


def _auto_updates(check: Check[AutoUpdatesState], read_at: datetime) -> ShownCheck:
    why = "Ubuntu can install security fixes without waiting for someone to sign in."
    if not check.observed or check.value is None:
        return _could_not("Automatic security updates", check, why, read_at)
    state = check.value
    custom = _custom_origins(state)
    if custom:
        return ShownCheck(
            "Automatic security updates",
            OUTSIDE,
            "Ubuntu's automatic updates are set up in a way Barectl does not change.",
            why,
            read_at,
            _NOT_AVAILABLE,
            details=custom,
        )
    if not state.enabled:
        return ShownCheck(
            "Automatic security updates",
            ATTENTION,
            "Ubuntu does not install security updates by itself.",
            why,
            read_at,
            _NOT_AVAILABLE,
        )
    details = []
    if state.newest_log_age is not None:
        details.append(f"The last automatic run was {_age(state.newest_log_age)}.")
    return ShownCheck(
        "Automatic security updates",
        ATTENTION if state.list_update_timer == "" or state.upgrade_timer == "" else OK,
        "Ubuntu refreshes its package lists and installs security updates by itself, "
        "without restarting the server.",
        why,
        read_at,
        _NOT_AVAILABLE,
        details=tuple(details),
    )


def _custom_origins(state: AutoUpdatesState) -> tuple[str, ...]:
    reasons = []
    origins = state.allowed_origins
    if origins and not any("-security" in origin for origin in origins):
        reasons.append("The allowed update sources do not include Ubuntu security updates.")
    if state.conffile_matches_package is False:
        reasons.append("The automatic-update settings file was edited.")
    if state.automatic_reboot:
        reasons.append("The server is set to restart itself after updates.")
    return tuple(reasons)


def _updates(check: Check[UpdatesState], read_at: datetime) -> ShownCheck:
    why = "Security updates fix known vulnerabilities; installing them closes the window."
    if not check.observed or check.value is None:
        return _could_not("Ubuntu updates", check, why, read_at)
    state = check.value
    counts = _counts(state)
    security = counts.get("security", 0)
    blocked = sum(counts.get(name, 0) for name in ("phased", "held", "blocked"))
    details = [_classification_line(name, count) for name, count in counts.items() if count]
    if state.list_age_seconds is None:
        details.append("The age of the package lists could not be read.")
    else:
        details.append(f"Package lists last refreshed {_age(state.list_age_seconds)}.")
    if security:
        what = f"{security} security update{'s' if security != 1 else ''} waiting."
    elif blocked:
        what = (
            "Ubuntu is holding updates back for its rollout or for another reason; Barectl "
            "will not install them until they are ready."
        )
    else:
        what = "No Ubuntu updates are waiting."
    return ShownCheck(
        "Ubuntu updates",
        ATTENTION if security or counts.get("blocked", 0) else OK,
        what,
        why,
        read_at,
        _NOT_AVAILABLE,
        details=tuple(details),
    )


def _counts(state: UpdatesState) -> dict[str, int]:
    counts = {"security": 0, "other": 0, "phased": 0, "held": 0, "blocked": 0}
    for update in state.pending:
        counts[update.classification] = counts.get(update.classification, 0) + 1
    return counts


def _classification_line(name: str, count: int) -> str:
    label = {
        "security": "security",
        "other": "other",
        "phased": "waiting for Ubuntu's rollout",
        "held": "held by an administrator",
        "blocked": "blocked because they would remove a package",
    }[name]
    return f"{count} {label} update{'s' if count != 1 else ''}."


def _restart(check: Check[RestartState], read_at: datetime) -> ShownCheck:
    why = "A kernel or library fix is not active until the server starts again."
    if not check.observed or check.value is None:
        return _could_not("Restart needed", check, why, read_at)
    state = check.value
    if not state.required:
        return ShownCheck(
            "Restart needed",
            OK,
            "The server does not need a restart.",
            why,
            read_at,
            _NOT_AVAILABLE,
        )
    return ShownCheck(
        "Restart needed",
        ATTENTION,
        "The server needs a restart before some fixes take effect.",
        why,
        read_at,
        _NOT_AVAILABLE,
        details=tuple(f"{name} needs the restart." for name in state.packages),
    )


def _runtimes(collected: CollectedSnapshot, read_at: datetime, advanced_url: str) -> ShownCheck:
    why = _RUNTIME_CHECK_SETTING
    if not collected.runtimes:
        return ShownCheck(
            "Web runtimes",
            UNKNOWN,
            "Could not check. The web runtimes could not be read.",
            why,
            read_at,
            _NOT_AVAILABLE,
        )
    if architecture_of(collected.architecture.value or "") is None:
        return ShownCheck(
            "Web runtimes",
            UNKNOWN,
            "Could not check. The server's architecture was not read, so Barectl cannot "
            "compare the web runtimes with this release.",
            why,
            read_at,
            _NOT_AVAILABLE,
        )
    rows = shown_runtimes(collected)
    pending = shown_updates(collected, rows)
    problems = tuple(row.entry for row in rows if row.problem)
    details = (
        *(f"{_runtime_name(row.entry)}: build {row.generation or 'unknown'}" for row in rows),
        *(
            f"{_runtime_name(entry)}: its live settings do not match what Barectl installed."
            for entry in problems
        ),
        (
            "Advanced shows the web server's private admin endpoint, the absence of a "
            "public admin port and the build service's account limits."
        ),
    )
    if problems:
        return ShownCheck(
            "Web runtimes",
            ATTENTION,
            "A web runtime's live settings do not match what Barectl installed.",
            why,
            read_at,
            _NOT_AVAILABLE,
            details=details,
        )
    update_url = f"{advanced_url}?tab=catalog#catalog-updates-heading" if advanced_url else ""
    if pending:
        return ShownCheck(
            "Web runtimes",
            ATTENTION,
            "A newer build of the web runtimes is available in this Barectl release.",
            why,
            read_at,
            "See the update in Advanced" if update_url else _NOT_AVAILABLE,
            action_url=update_url,
            details=details,
        )
    return ShownCheck(
        "Web runtimes",
        OK,
        "Every web runtime matches this Barectl release.",
        why,
        read_at,
        _NOT_AVAILABLE,
        details=details,
    )


def _plain_process(name: str) -> str:
    if name == "caddy":
        return "Web server"
    if name == "haproxy":
        return "Site proxy"
    if name in {"sshd", "ssh"}:
        return "SSH"
    if name.startswith("php-fpm") or name == "php":
        return "PHP"
    if name in {"postgres", "mariadbd", "mysqld"}:
        return "Database"
    if name in {"valkey-server", "redis-server"}:
        return "Object cache"
    if name == "dockerd":
        return "Docker"
    return name


def _runtime_name(entry: str) -> str:
    if entry.startswith("php") and len(entry) == 5 and entry[3:].isdigit():
        return f"PHP {entry[3]}.{entry[4]}"
    if entry.startswith("nodejs_"):
        return "Node.js " + entry.removeprefix("nodejs_").replace("_", ".")
    if entry in {"caddy", "haproxy"}:
        return "Web server"
    return "Tool"


def _age(seconds: int) -> str:
    if seconds < 0:
        return "in the future"
    if seconds < 3600:
        return f"{max(1, seconds // 60)} minutes ago"
    if seconds < 86400:
        return f"{seconds // 3600} hours ago"
    return f"{seconds // 86400} days ago"
