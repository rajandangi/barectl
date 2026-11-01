"""Plain-language Security checks from stored observations (Phase E #302, #179).

The default view states tasks, not native detail: what Barectl saw, why it matters, when it
was read and the one next action. Engine detail stays under Advanced.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from discovery.snapshot import CollectedSnapshot
from operations import revert
from runtimes.catalog import architecture_of
from runtimes.presentation import ShownRuntime, shown_runtimes, shown_updates

from .observation import (
    DEFAULT_ALLOWED_ORIGINS,
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
class ShownAction:
    """One POST control a check offers, such as the updates' check and install choices."""

    label: str
    form: str
    value: str = ""
    name: str = "selection"


@dataclass(frozen=True)
class ShownCheck:
    name: str
    state: CheckState
    what: str
    why: str
    read_at: datetime
    action: str
    action_url: str = ""
    action_form: str = ""
    action_value: str = ""
    action_name: str = "state"
    details: tuple[str, ...] = ()
    note: str = ""
    actions: tuple[ShownAction, ...] = ()


@dataclass(frozen=True)
class ShownFirewallRule:
    """One operator allowance the panel can remove."""

    label: str
    port: str
    protocol: str
    network: str = ""


@dataclass(frozen=True)
class FirewallPanel:
    """The extra-port panel under the Firewall check, when the standard holds."""

    prepare_url: str
    can_change: bool
    rules: tuple[ShownFirewallRule, ...]
    window_minutes: int


def present(
    collected: CollectedSnapshot,
    read_at: datetime,
    *,
    advanced_url: str = "",
    auto_updates_url: str = "",
    updates_check_url: str = "",
    updates_install_url: str = "",
    firewall_url: str = "",
    can_change: bool = False,
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
        _firewall(state.firewall, state.listeners, state.ssh, read_at, firewall_url, can_change),
        _ssh(state.ssh, read_at),
        _auto_updates(state.auto_updates, read_at, auto_updates_url, can_change),
        _updates(
            state.updates,
            read_at,
            updates_check_url,
            updates_install_url,
            can_change,
        ),
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
    action_url: str,
    can_change: bool,
) -> ShownCheck:
    firewall = _firewall_state(check, ssh, read_at, action_url, can_change)
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
        firewall.action,
        action_form=firewall.action_form,
        action_value=firewall.action_value,
        action_name=firewall.action_name,
        details=details,
        note=note,
    )


def _firewall_action(
    state: FirewallState, ssh: Check[SshState], action_url: str, can_change: bool
) -> tuple[str, str]:
    """The one next action the Firewall check offers, or no action when the panel does."""
    if not can_change or not action_url or state.outside:
        return _NOT_AVAILABLE, ""
    if not state.ufw_installed or state.ufw_enabled is not True:
        return "Turn on firewall", "on"
    ports = ssh.value.sshd_ports or ssh.value.ports if ssh.observed and ssh.value else ()
    from .firewall import standard_holds

    if standard_holds(state, ports):
        return "", ""
    return "Set up the standard firewall", "on"


def _firewall_state(
    check: Check[FirewallState],
    ssh: Check[SshState],
    read_at: datetime,
    action_url: str,
    can_change: bool,
) -> ShownCheck:
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
    action, value = _firewall_action(state, ssh, action_url, can_change)
    if not state.ufw_installed:
        return ShownCheck(
            "Firewall",
            ATTENTION,
            "No firewall is set up on the server, so every port it listens on is reachable.",
            why,
            read_at,
            action,
            action_form=action_url if action and action != _NOT_AVAILABLE else "",
            action_value=value,
            action_name="selection",
            note=_CLOUD_FIREWALL,
        )
    if state.ufw_enabled is not True:
        return ShownCheck(
            "Firewall",
            ATTENTION,
            "The firewall is off or not enabled at start-up, so its protection does not hold.",
            why,
            read_at,
            action,
            action_form=action_url if action and action != _NOT_AVAILABLE else "",
            action_value=value,
            action_name="selection",
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
        ATTENTION if action else (ATTENTION if state.ipv6 is False else OK),
        (
            f"The firewall is on. It allows {allowed}."
            if not action
            else "The firewall is on but does not follow the standard Barectl manages."
        ),
        why,
        read_at,
        action,
        action_form=action_url if action and action != _NOT_AVAILABLE else "",
        action_value=value,
        action_name="selection",
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


def firewall_panel(
    state: SecurityState | None, *, prepare_url: str, can_change: bool
) -> FirewallPanel | None:
    """The extra-port controls, only when the standard firewall holds and can be changed."""
    if state is None or not state.firewall.observed or state.firewall.value is None:
        return None
    firewall = state.firewall.value
    ssh_ports = (
        state.ssh.value.sshd_ports or state.ssh.value.ports
        if state.ssh.observed and state.ssh.value
        else ()
    )
    from .firewall import standard_holds

    if not standard_holds(firewall, ssh_ports):
        return None
    rules = tuple(
        ShownFirewallRule(
            (
                f"{row.ports}/{row.protocol} from {row.network}"
                if row.network
                else f"{row.ports}/{row.protocol} from anywhere"
            ),
            row.ports,
            row.protocol,
            row.network,
        )
        for row in firewall.rules
        if row.kind == "operator" and row.action == "allow" and row.ports
    )
    return FirewallPanel(
        prepare_url=prepare_url,
        can_change=can_change,
        rules=rules,
        window_minutes=revert.WINDOW_MINUTES,
    )


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


RESTART_DISCLOSURE = (
    "These updates can restart the database engine and Valkey, so sites may pause briefly. "
    "They do not restart the web server or PHP."
)
UPDATES_DISCLOSURE = (
    "Ubuntu may restart the database engine, the object cache and SSH, so sites may pause "
    "briefly. Web serving and PHP are not restarted by Ubuntu updates."
)
UPDATES_CHECK_LABEL = "Check for updates"
UPDATES_SECURITY_LABEL = "Install security updates"
UPDATES_ALL_LABEL = "Install all updates"


def _auto_updates(
    check: Check[AutoUpdatesState],
    read_at: datetime,
    action_url: str,
    can_change: bool,
) -> ShownCheck:
    why = "Ubuntu can install security fixes without waiting for someone to sign in."
    if not check.observed or check.value is None:
        return _could_not("Automatic security updates", check, why, read_at)
    state = check.value
    history = _history(state)
    custom = custom_updates(state)
    if custom:
        form = action_url if can_change and state.enabled else ""
        return ShownCheck(
            "Automatic security updates",
            OUTSIDE,
            "Ubuntu's automatic updates are set up in a way Barectl does not change.",
            why,
            read_at,
            "Turn off" if form else _NOT_AVAILABLE,
            action_form=form,
            action_value="off",
            details=(*custom, *history),
            note=RESTART_DISCLOSURE,
        )
    action, value = _auto_updates_action(state)
    form = action_url if can_change and action and value else ""
    label = action if form else _NOT_AVAILABLE
    if not state.package_installed:
        return ShownCheck(
            "Automatic security updates",
            ATTENTION,
            "Ubuntu's automatic security updates are not installed, so it does not install "
            "security fixes by itself.",
            why,
            read_at,
            label,
            action_form=form,
            action_value=value,
            details=history,
            note=RESTART_DISCLOSURE,
        )
    if not state.enabled:
        return ShownCheck(
            "Automatic security updates",
            ATTENTION,
            "Ubuntu does not install security updates by itself.",
            why,
            read_at,
            label,
            action_form=form,
            action_value=value,
            details=history,
            note=RESTART_DISCLOSURE,
        )
    return ShownCheck(
        "Automatic security updates",
        OK,
        "Ubuntu refreshes its package lists and installs security updates by itself, "
        "without restarting the server.",
        why,
        read_at,
        label,
        action_form=form,
        action_value=value,
        details=history,
        note=RESTART_DISCLOSURE,
    )


def _auto_updates_action(state: AutoUpdatesState) -> tuple[str, str]:
    return ("Turn off", "off") if state.enabled else ("Turn on", "on")


def _history(state: AutoUpdatesState) -> tuple[str, ...]:
    if state.last_upgrade:
        age = f" ({_age(state.newest_log_age)})" if state.newest_log_age is not None else ""
        return (f"Ubuntu's own history: {state.last_upgrade}{age}.",)
    if state.newest_log_age is not None:
        return (f"Ubuntu's own history last ran {_age(state.newest_log_age)}.",)
    return ("Ubuntu's own history could not be read.",)


def custom_updates(state: AutoUpdatesState) -> tuple[str, ...]:
    """Why this setup is outside the supported one, or nothing when it follows it."""
    reasons = []
    origins = state.allowed_origins
    if (state.package_installed or origins) and origins != DEFAULT_ALLOWED_ORIGINS:
        reasons.append("The allowed update sources are customized.")
    if state.package_blacklist:
        reasons.append("Some packages are kept out of automatic updates.")
    if state.automatic_reboot:
        reasons.append("The server is set to restart itself after updates.")
    if state.package_installed and state.conffile_matches_package is False:
        reasons.append("The automatic-update settings file was edited.")
    if state.list_update_timer != "enabled" or state.upgrade_timer != "enabled":
        reasons.append("One of Ubuntu's update timers is disabled.")
    return tuple(reasons)


def _updates(
    check: Check[UpdatesState],
    read_at: datetime,
    check_url: str,
    install_url: str,
    can_change: bool,
) -> ShownCheck:
    why = "Security updates fix known vulnerabilities; installing them closes the window."
    if not check.observed or check.value is None:
        return _could_not("Ubuntu updates", check, why, read_at)
    state = check.value
    counts = _counts(state)
    security = counts.get("security", 0)
    other = counts.get("other", 0)
    blocked = sum(counts.get(name, 0) for name in ("phased", "held", "blocked"))
    details = [_classification_line(name, count) for name, count in counts.items() if count]
    if state.list_age_seconds is None:
        details.append("The age of the package lists could not be read.")
    else:
        details.append(f"Package lists last refreshed {_age(state.list_age_seconds)}.")
        if state.list_age_seconds >= 86400 and not security:
            details.append(
                "The package lists are more than a day old. Check for updates before "
                "installing anything."
            )
    if security:
        what = f"{security} security update{'s' if security != 1 else ''} waiting."
    elif blocked:
        what = (
            "Ubuntu is holding updates back for its rollout or for another reason; Barectl "
            "will not install them until they are ready."
        )
    else:
        what = "No Ubuntu updates are waiting."
    actions: list[ShownAction] = []
    if can_change and check_url:
        actions.append(ShownAction(UPDATES_CHECK_LABEL, check_url))
    if can_change and install_url:
        if security:
            actions.append(ShownAction(UPDATES_SECURITY_LABEL, install_url, "security"))
        if other:
            actions.append(ShownAction(UPDATES_ALL_LABEL, install_url, "all"))
    return ShownCheck(
        "Ubuntu updates",
        ATTENTION if security or counts.get("blocked", 0) else OK,
        what,
        why,
        read_at,
        _NOT_AVAILABLE if not actions else actions[0].label,
        details=tuple(details),
        actions=tuple(actions),
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
        *(_runtime_line(row, read_at) for row in rows),
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


def _runtime_line(row: ShownRuntime, read_at: datetime) -> str:
    build = row.generation or "unknown"
    if not row.installed_at:
        return f"{_runtime_name(row.entry)}: build {build}, age not recorded"
    age = _age(int(read_at.timestamp()) - row.installed_at)
    return f"{_runtime_name(row.entry)}: build {build}, installed {age}"


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
