"""Fixed root reads of a server's security checks (Phase E #302, ADR 0026, ADR 0033).

The reads are ordinary discovery through ``discovery.root_read``; nothing here changes
the server, and every unreadable part stays an explicit "Could not check".
"""

import re
import time
from dataclasses import dataclass
from typing import Final

from discovery.models import ObservationOutcome
from discovery.root_read import run_root
from discovery.snapshot import Observation
from discovery.ssh import RemoteShell

ID_COMMAND = "id -u"
LISTENERS_COMMAND = "ss -Hlnptu"
UFW_PACKAGE_COMMAND = "dpkg-query -W -f='${Status}\\t${Version}\\n' ufw"
UFW_STATUS_COMMAND = "ufw status verbose"
UFW_ADDED_COMMAND = "ufw show added"
UFW_CONFIG_COMMAND = "cat /etc/ufw/ufw.conf"
UFW_DEFAULT_COMMAND = "cat /etc/default/ufw"
UFW_RULES_DIGEST_COMMAND = "sha256sum /etc/ufw/before.rules /etc/ufw/after.rules"
UFW_CONFFILES_COMMAND = "dpkg-query -W -f='${Conffiles}\\n' ufw"
FIREWALLD_COMMAND = "systemctl is-active firewalld"
DOCKER_COMMAND = "systemctl is-active docker"
NFT_COMMAND = "nft list ruleset"
IPTABLES_COMMAND = "iptables-save"
SSHD_COMMAND = "sshd -T"
SSH_SOCKET_COMMAND = "systemctl show ssh.socket -p ListenStream"
ACCOUNTS_COMMAND = "getent passwd"
AUTHORIZED_KEYS_COMMAND = (
    "find /home /root -maxdepth 4 -type f -path '*/.ssh/authorized_keys' -print"
)
APT_CONFIG_COMMAND = "apt-config dump"
APT_TIMERS_COMMAND = (
    "systemctl show apt-daily.timer apt-daily-upgrade.timer -p Id -p UnitFileState -p ActiveState"
)
UNATTENDED_DIGEST_COMMAND = "sha256sum /etc/apt/apt.conf.d/50unattended-upgrades"
UNATTENDED_CONFFILES_COMMAND = "dpkg-query -W -f='${Conffiles}\\n' unattended-upgrades"
UNATTENDED_LOG_COMMAND = (
    "find /var/log/unattended-upgrades -maxdepth 1 -type f "
    "-printf '%T@ %p\\n' 2>/dev/null | sort -nr | head -n 1"
)
APT_SIMULATE_COMMAND = "apt-get -s -o APT::Get::Show-Versions=1 upgrade --with-new-pkgs"
APT_HOLDS_COMMAND = "apt-mark showhold"
LISTS_AGE_COMMAND = (
    "find /var/lib/apt/lists -name '*InRelease' -printf '%T@\\n' 2>/dev/null | sort -n | tail -n 1"
)
REBOOT_COMMAND = "cat /run/reboot-required"
REBOOT_PACKAGES_COMMAND = "cat /run/reboot-required.pkgs"

_ROOT_WARNING = (
    "Barectl needs root or the authorized passwordless sudo to read the security checks."
)
_PUBLIC_PROCESSES = re.compile(r'users:\(\("(?P<process>[^"]+)"')
_LOGIN_SHELLS = frozenset({"/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/usr/bin/sh"})
_MAX_LISTENERS = 500
_MAX_UPDATES = 500
_MAX_PACKAGES = 200
STANDARD_PUBLIC_PORTS = frozenset({("tcp", 80), ("tcp", 443), ("udp", 443)})


@dataclass(frozen=True)
class Check[T]:
    """One check's evidence, and why it could not be read."""

    status: ObservationOutcome
    source: tuple[str, ...]
    warning: str
    value: T | None

    @property
    def observed(self) -> bool:
        return self.status == ObservationOutcome.OBSERVED and self.value is not None


@dataclass(frozen=True)
class Listener:
    address: str
    port: int
    protocol: str
    process: str
    public: bool


@dataclass(frozen=True)
class FirewallRule:
    """A rule in the supported grammar, or the line that is outside it."""

    kind: str
    line: str
    action: str = ""
    protocol: str = ""
    ports: str = ""
    network: str = ""


@dataclass(frozen=True)
class FirewallState:
    ufw_installed: bool
    ufw_enabled: bool | None
    default_incoming: str
    default_outgoing: str
    default_routed: str
    ipv6: bool | None
    logging: str
    rules: tuple[FirewallRule, ...]
    outside: tuple[str, ...]
    conffiles_intact: bool | None


@dataclass(frozen=True)
class SshState:
    password_authentication: str
    keyboard_interactive: str
    permit_root_login: str
    # ``ports`` is the effective set: ``sshd -T`` plus the sockets sshd actually listens on.
    ports: tuple[int, ...]
    socket_ports: tuple[int, ...]
    accounts_without_keys: tuple[str, ...]
    per_source_penalties: str
    # The ``sshd -T`` port lines alone, kept so a firewall change can prove every source of
    # truth agrees before it could close the controller's own access.
    sshd_ports: tuple[int, ...] = ()


# The allowed origins Ubuntu's package ships, read from its own
# /etc/apt/apt.conf.d/50unattended-upgrades (Ubuntu automatic updates).
DEFAULT_ALLOWED_ORIGINS: Final = (
    "${distro_id}:${distro_codename}",
    "${distro_id}:${distro_codename}-security",
    "${distro_id}ESMApps:${distro_codename}-apps-security",
    "${distro_id}ESM:${distro_codename}-infra-security",
)


@dataclass(frozen=True)
class AutoUpdatesState:
    enabled: bool
    list_update_timer: str
    upgrade_timer: str
    automatic_reboot: bool | None
    allowed_origins: tuple[str, ...]
    conffile_matches_package: bool | None
    last_upgrade: str
    newest_log_age: int | None
    package_installed: bool = False
    package_blacklist: tuple[str, ...] = ()


@dataclass(frozen=True)
class PendingUpdate:
    name: str
    installed: str
    candidate: str
    archive: str
    classification: str


@dataclass(frozen=True)
class UpdatesState:
    list_age_seconds: int | None
    pending: tuple[PendingUpdate, ...]


@dataclass(frozen=True)
class RestartState:
    required: bool
    packages: tuple[str, ...]


@dataclass(frozen=True)
class SecurityState:
    firewall: Check[FirewallState]
    listeners: Check[tuple[Listener, ...]]
    ssh: Check[SshState]
    auto_updates: Check[AutoUpdatesState]
    updates: Check[UpdatesState]
    restart: Check[RestartState]


@dataclass(frozen=True)
class _Failure:
    status: ObservationOutcome
    command: str
    warning: str


@dataclass(frozen=True)
class SshSettings:
    password_authentication: str
    keyboard_interactive: str
    permit_root_login: str
    per_source_penalties: str
    ports: tuple[int, ...]


def collect(shell: RemoteShell) -> Observation[SecurityState]:
    """Read every security check, keeping each check's own outcome."""
    if _privileged(shell):
        return Observation(ObservationOutcome.OBSERVED, (ID_COMMAND,), "", _read(shell))
    failure = _Failure(ObservationOutcome.INACCESSIBLE, ID_COMMAND, _ROOT_WARNING)
    return Observation(
        ObservationOutcome.OBSERVED,
        (ID_COMMAND,),
        "",
        SecurityState(
            firewall=_unreadable(failure),
            listeners=_unreadable(failure),
            ssh=_unreadable(failure),
            auto_updates=_unreadable(failure),
            updates=_unreadable(failure),
            restart=_unreadable(failure),
        ),
    )


def _privileged(shell: RemoteShell) -> bool:
    result = run_root(shell, ID_COMMAND)
    return result.exit_status == 0 and result.stdout.strip() == "0"


def _unreadable[T](failure: _Failure) -> Check[T]:
    return Check(failure.status, (failure.command,), failure.warning, None)


def _read(shell: RemoteShell) -> SecurityState:
    listeners = _read_listeners(shell)
    ssh = _read_ssh(shell, listeners)
    return SecurityState(
        firewall=_read_firewall(shell, ssh),
        listeners=listeners,
        ssh=ssh,
        auto_updates=_read_auto_updates(shell),
        updates=_read_updates(shell),
        restart=_read_restart(shell),
    )


def _read_listeners(shell: RemoteShell) -> Check[tuple[Listener, ...]]:
    text = _run(shell, LISTENERS_COMMAND)
    if isinstance(text, _Failure):
        return _unreadable(text)
    listeners = parse_listeners(text)
    if listeners is None:
        return _unreadable(
            _Failure(
                ObservationOutcome.UNSUPPORTED,
                LISTENERS_COMMAND,
                "The server did not report its listeners in a supported format.",
            )
        )
    return Check(ObservationOutcome.OBSERVED, (LISTENERS_COMMAND,), "", listeners)


def _read_ssh(shell: RemoteShell, listeners: Check[tuple[Listener, ...]]) -> Check[SshState]:
    text = _run(shell, SSHD_COMMAND)
    if isinstance(text, _Failure):
        return _unreadable(text)
    settings = parse_sshd(text)
    if settings is None:
        return _unreadable(
            _Failure(
                ObservationOutcome.UNSUPPORTED,
                SSHD_COMMAND,
                "The server did not report its SSH settings in a supported format.",
            )
        )
    socket_text = _run(shell, SSH_SOCKET_COMMAND, accepted=(0, 1))
    socket_ports = () if isinstance(socket_text, _Failure) else parse_socket_ports(socket_text)
    passwd = _run(shell, ACCOUNTS_COMMAND)
    keys = _run(shell, AUTHORIZED_KEYS_COMMAND, accepted=(0, 1))
    accounts: tuple[str, ...] = ()
    warning = ""
    if isinstance(passwd, _Failure) or isinstance(keys, _Failure):
        warning = "Barectl could not read the accounts that sign in without a key."
    else:
        accounts = parse_accounts_without_keys(passwd, keys)
    source = (SSHD_COMMAND, SSH_SOCKET_COMMAND, ACCOUNTS_COMMAND, AUTHORIZED_KEYS_COMMAND)
    ports = settings.ports
    if listeners.observed and listeners.value:
        ports = tuple(
            sorted(set(ports) | {row.port for row in listeners.value if is_ssh_listener(row)})
        )
    return Check(
        ObservationOutcome.OBSERVED,
        source,
        warning,
        SshState(
            settings.password_authentication,
            settings.keyboard_interactive,
            settings.permit_root_login,
            ports,
            socket_ports,
            accounts,
            settings.per_source_penalties,
            settings.ports,
        ),
    )


def enabled_for_standard(active: bool | None, boot: bool | None) -> bool | None:
    """The standard needs UFW active now *and* enabled at boot."""
    return None if active is None or boot is None else active is True and boot is True


def is_ssh_listener(listener: Listener) -> bool:
    return listener.protocol == "tcp" and listener.process == "sshd"


def _read_firewall(shell: RemoteShell, ssh: Check[SshState]) -> Check[FirewallState]:
    package = _run(shell, UFW_PACKAGE_COMMAND, accepted=(0, 1))
    installed = not isinstance(package, _Failure) and "install ok installed" in package.lower()
    status_text = ""
    added_text = ""
    enabled: bool | None = None
    defaults = ("", "", "")
    logging = ""
    if installed:
        status = _run(shell, UFW_STATUS_COMMAND, accepted=(0, 1))
        if isinstance(status, _Failure):
            return _unreadable(status)
        status_text = status
        active, defaults, logging = parse_ufw_status(status_text)
        added = _run(shell, UFW_ADDED_COMMAND, accepted=(0, 1))
        if isinstance(added, _Failure):
            return _unreadable(added)
        added_text = added
    config = _run(shell, UFW_CONFIG_COMMAND, accepted=(0, 1))
    default_file = _run(shell, UFW_DEFAULT_COMMAND, accepted=(0, 1))
    ipv6 = (
        parse_ipv6(default_file) if installed and not isinstance(default_file, _Failure) else None
    )
    if installed:
        boot = None if isinstance(config, _Failure) else parse_ufw_config(config)
        enabled = None if active is None or boot is None else (active is True and boot is True)
    rules = parse_ufw_added(added_text, _ssh_ports(ssh))
    outside = list(_outside_managers(shell, installed, enabled))
    outside.extend(rule.line for rule in rules if rule.kind == "outside")
    conffiles = _run(shell, UFW_RULES_DIGEST_COMMAND, accepted=(0, 1))
    conffile_rows = _run(shell, UFW_CONFFILES_COMMAND, accepted=(0, 1))
    intact = None
    if not isinstance(conffiles, _Failure) and not isinstance(conffile_rows, _Failure):
        intact = digests_match(conffiles, conffile_rows, ("before.rules", "after.rules"))
        if intact is False:
            outside.append(
                "The firewall's own rule files were edited outside what Barectl supports."
            )
    return Check(
        ObservationOutcome.OBSERVED,
        (
            UFW_PACKAGE_COMMAND,
            UFW_STATUS_COMMAND,
            UFW_ADDED_COMMAND,
            FIREWALLD_COMMAND,
            DOCKER_COMMAND,
            NFT_COMMAND,
            IPTABLES_COMMAND,
        ),
        "",
        FirewallState(
            installed,
            enabled,
            defaults[0],
            defaults[1],
            defaults[2],
            ipv6,
            logging,
            tuple(rules),
            tuple(dict.fromkeys(outside)),
            intact,
        ),
    )


def _ssh_ports(ssh: Check[SshState]) -> tuple[int, ...]:
    return ssh.value.ports if ssh.observed and ssh.value else ()


def _outside_managers(shell: RemoteShell, installed: bool, enabled: bool | None) -> tuple[str, ...]:
    found: list[str] = []
    if _active(shell, FIREWALLD_COMMAND):
        found.append("firewalld is active, so two firewalls would manage the same server.")
    if _active(shell, DOCKER_COMMAND):
        found.append(
            "Docker is active and publishes ports ahead of a host firewall, so Barectl "
            "does not manage its rules."
        )
    if not installed or enabled is not True:
        nft = _run(shell, NFT_COMMAND, accepted=(0, 1))
        if not isinstance(nft, _Failure) and _nft_has_foreign_rules(nft):
            found.append("An nftables ruleset outside UFW is active.")
        iptables = _run(shell, IPTABLES_COMMAND, accepted=(0, 1))
        if not isinstance(iptables, _Failure) and _iptables_has_rules(iptables):
            found.append("An iptables ruleset outside UFW is active.")
    return tuple(found)


def _active(shell: RemoteShell, command: str) -> bool:
    text = _run(shell, command, accepted=(0, 1, 3))
    return not isinstance(text, _Failure) and text.strip() == "active"


def _read_auto_updates(shell: RemoteShell) -> Check[AutoUpdatesState]:
    config = _run(shell, APT_CONFIG_COMMAND)
    if isinstance(config, _Failure):
        return _unreadable(config)
    values = parse_apt_config(config)
    timers_text = _run(shell, APT_TIMERS_COMMAND, accepted=(0, 1))
    if isinstance(timers_text, _Failure):
        return _unreadable(timers_text)
    timers = parse_timers(timers_text)
    digest_text = _run(shell, UNATTENDED_DIGEST_COMMAND, accepted=(0, 1))
    conffiles_text = _run(shell, UNATTENDED_CONFFILES_COMMAND, accepted=(0, 1))
    installed = not isinstance(conffiles_text, _Failure)
    matches = None
    if not isinstance(digest_text, _Failure) and not isinstance(conffiles_text, _Failure):
        matches = conffile_matches(
            digest_text, conffiles_text, "/etc/apt/apt.conf.d/50unattended-upgrades"
        )
    log_text = _run(shell, UNATTENDED_LOG_COMMAND, accepted=(0, 1))
    last_upgrade = ""
    newest_age: int | None = None
    if not isinstance(log_text, _Failure) and log_text.strip():
        path, age = parse_newest_log(log_text)
        if path:
            newest_age = age
            body = _run(shell, f"tail -n 60 {_quoted(path)}", accepted=(0, 1))
            if not isinstance(body, _Failure):
                last_upgrade = summarize_unattended_log(body)
    enabled = (
        values.get("APT::Periodic::Update-Package-Lists") == "1"
        and values.get("APT::Periodic::Unattended-Upgrade") == "1"
    )
    reboot = values.get("Unattended-Upgrade::Automatic-Reboot")
    return Check(
        ObservationOutcome.OBSERVED,
        (
            APT_CONFIG_COMMAND,
            APT_TIMERS_COMMAND,
            UNATTENDED_DIGEST_COMMAND,
            UNATTENDED_LOG_COMMAND,
        ),
        "",
        AutoUpdatesState(
            enabled,
            timers.get("apt-daily.timer", ""),
            timers.get("apt-daily-upgrade.timer", ""),
            None if reboot is None else reboot.lower() == "true",
            parse_allowed_origins(config),
            matches,
            last_upgrade,
            newest_age,
            installed,
            parse_package_blacklist(config),
        ),
    )


def _read_updates(shell: RemoteShell) -> Check[UpdatesState]:
    simulation = _run(shell, APT_SIMULATE_COMMAND, accepted=(0, 1))
    if isinstance(simulation, _Failure):
        return _unreadable(simulation)
    held_text = _run(shell, APT_HOLDS_COMMAND, accepted=(0, 1))
    if isinstance(held_text, _Failure):
        return _unreadable(held_text)
    parsed = parse_upgrades(simulation)
    if parsed is None:
        return _unreadable(
            _Failure(
                ObservationOutcome.UNSUPPORTED,
                APT_SIMULATE_COMMAND,
                "The server did not report waiting updates in a supported format.",
            )
        )
    names = tuple(sorted({row[0] for row in parsed}))[:_MAX_PACKAGES]
    archives = _candidate_archives(shell, names)
    age_text = _run(shell, LISTS_AGE_COMMAND, accepted=(0, 1))
    held = set(held_text.split())
    pending = _pending_updates(parsed, held, archives)
    if isinstance(age_text, _Failure):
        return Check(
            ObservationOutcome.OBSERVED,
            (APT_SIMULATE_COMMAND, APT_HOLDS_COMMAND),
            "Barectl could not read the age of the package lists.",
            UpdatesState(None, pending),
        )
    return Check(
        ObservationOutcome.OBSERVED,
        (
            APT_SIMULATE_COMMAND,
            APT_HOLDS_COMMAND,
            "apt-cache policy",
            LISTS_AGE_COMMAND,
        ),
        "",
        UpdatesState(parse_list_age(age_text), pending),
    )


def _candidate_archives(shell: RemoteShell, names: tuple[str, ...]) -> dict[str, str]:
    if not names:
        return {}
    text = _run(shell, "apt-cache policy " + " ".join(names), accepted=(0, 1))
    if isinstance(text, _Failure):
        return {}
    return parse_apt_policy(text)


def _pending_updates(
    parsed: tuple[tuple[str, str, str], ...],
    held: set[str],
    archives: dict[str, str],
) -> tuple[PendingUpdate, ...]:
    rows = []
    for name, installed, candidate in parsed[:_MAX_UPDATES]:
        archive = archives.get(name, "")
        if name in held:
            classification = "held"
        elif candidate == "kept":
            classification = "phased"
        elif "-security" in archive:
            classification = "security"
        elif candidate == "removed":
            classification = "blocked"
        else:
            classification = "other"
        rows.append(PendingUpdate(name, installed, candidate, archive, classification))
    return tuple(rows)


def _read_restart(shell: RemoteShell) -> Check[RestartState]:
    required = _run(shell, REBOOT_COMMAND, accepted=(0, 1))
    packages = _run(shell, REBOOT_PACKAGES_COMMAND, accepted=(0, 1))
    if isinstance(required, _Failure) or isinstance(packages, _Failure):
        return _unreadable(
            _Failure(
                ObservationOutcome.INACCESSIBLE,
                REBOOT_COMMAND,
                "Barectl could not read whether the server needs a restart.",
            )
        )
    return Check(
        ObservationOutcome.OBSERVED,
        (REBOOT_COMMAND, REBOOT_PACKAGES_COMMAND),
        "",
        RestartState(
            bool(required.strip()),
            tuple(line.strip() for line in packages.splitlines() if line.strip()),
        ),
    )


def _run(
    shell: RemoteShell, command: str, *, accepted: frozenset[int] | tuple[int, ...] = (0,)
) -> str | _Failure:
    result = run_root(shell, command)
    if result.truncated:
        return _Failure(
            ObservationOutcome.UNSUPPORTED,
            command,
            f"{command} wrote more output than expected. It was not read.",
        )
    if result.exit_status != 0:
        if result.exit_status in accepted:
            return result.stdout
        return _Failure(
            ObservationOutcome.INACCESSIBLE,
            command,
            "Barectl could not read this setting from the server.",
        )
    return result.stdout


def _quoted(path: str) -> str:
    return "'" + path.replace("'", "'\\''") + "'"


# Parsers are pure and tested over recorded Ubuntu 26.04 output.


def parse_listeners(text: str) -> tuple[Listener, ...] | None:
    rows: list[Listener] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split(None, 6)
        protocol = ""
        if fields[0].lower() in {"tcp", "udp"}:
            if len(fields) < 6:
                return None
            protocol = fields[0].lower()
            state = fields[1]
            local = fields[4]
            process = fields[6] if len(fields) > 6 else ""
        else:
            if len(fields) < 5:
                return None
            state = fields[0]
            local = fields[3]
            process = fields[5] if len(fields) > 5 else ""
        parsed = _split_address(local)
        if parsed is None:
            continue
        address, port = parsed
        protocol = protocol or ("tcp" if state.upper() == "LISTEN" else "udp")
        match = _PUBLIC_PROCESSES.search(process)
        rows.append(
            Listener(
                address,
                port,
                protocol,
                match["process"] if match else "",
                _is_public(address),
            )
        )
        if len(rows) > _MAX_LISTENERS:
            return None
    return tuple(rows)


def _split_address(local: str) -> tuple[str, int] | None:
    address, separator, port = local.rpartition(":")
    if not separator or not port.isdigit():
        return None
    return address.strip("[]") or "*", int(port)


def _is_public(address: str) -> bool:
    return address not in {"127.0.0.1", "::1", ""} and not address.startswith("127.")


def parse_sshd(text: str) -> SshSettings | None:
    settings: dict[str, object] = {}
    ports: list[int] = []
    for line in text.splitlines():
        name, _, value = line.strip().partition(" ")
        key = name.lower()
        if key == "port" and value.isdigit():
            ports.append(int(value))
        elif key in {
            "passwordauthentication",
            "kbdinteractiveauthentication",
            "permitrootlogin",
            "persourcepenalties",
        }:
            settings[key] = value
    if "passwordauthentication" not in settings:
        return None
    return SshSettings(
        password_authentication=str(settings.get("passwordauthentication", "")),
        keyboard_interactive=str(settings.get("kbdinteractiveauthentication", "")),
        permit_root_login=str(settings.get("permitrootlogin", "")),
        per_source_penalties=str(settings.get("persourcepenalties", "")),
        ports=tuple(sorted(set(ports))) or (22,),
    )


def parse_socket_ports(text: str) -> tuple[int, ...]:
    ports: set[int] = set()
    for line in text.splitlines():
        _, _, value = line.partition("=")
        for entry in value.split():
            parsed = _split_address(entry)
            if parsed is not None:
                ports.add(parsed[1])
    return tuple(sorted(ports))


def parse_accounts_without_keys(passwd: str, keys: str) -> tuple[str, ...]:
    authorized = set(keys.split())
    accounts = []
    for line in passwd.splitlines():
        fields = line.split(":")
        if len(fields) != 7:
            continue
        name, home, shell = fields[0], fields[5], fields[6]
        if shell not in _LOGIN_SHELLS:
            continue
        if f"{home.rstrip('/')}/.ssh/authorized_keys" not in authorized:
            accounts.append(name)
    return tuple(sorted(accounts))


def parse_ufw_status(text: str) -> tuple[bool | None, tuple[str, str, str], str]:
    enabled: bool | None = None
    defaults = ["", "", ""]
    logging = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Status:"):
            enabled = stripped.partition(":")[2].strip() == "active"
        elif stripped.startswith("Logging:"):
            logging = stripped.partition(":")[2].strip()
        elif stripped.startswith("Default:"):
            values = re.findall(r"(allow|deny|reject)\s+\((\w+)\)", stripped)
            for verb, direction in values:
                index = {"incoming": 0, "outgoing": 1, "routed": 2}.get(direction)
                if index is not None:
                    defaults[index] = verb
    return enabled, (defaults[0], defaults[1], defaults[2]), logging


def parse_ufw_config(text: str) -> bool | None:
    for line in text.splitlines():
        name, _, value = line.partition("=")
        if name.strip() == "ENABLED":
            return value.strip().lower() == "yes"
    return None


def parse_ipv6(text: str) -> bool | None:
    for line in text.splitlines():
        name, _, value = line.partition("=")
        if name.strip() == "IPV6":
            return value.strip().lower() == "yes"
    return None


_SIMPLE_RULE = re.compile(r"^allow (?P<ports>[0-9]{1,5}(?::[0-9]{1,5})?)/(?P<protocol>tcp|udp)$")
_NETWORK_RULE = re.compile(
    r"^allow (?:proto (?P<protocol>tcp|udp) )?from (?P<network>[0-9a-fA-F:.]+/[0-9]{1,3}) "
    r"to any port (?P<ports>[0-9]{1,5}(?::[0-9]{1,5})?)(?: proto (?P<trailing>tcp|udp))?$"
)


def parse_ufw_added(text: str, ssh_ports: tuple[int, ...]) -> tuple[FirewallRule, ...]:
    standard = {
        *(f"{port}/tcp" for port in ssh_ports),
        *(f"{port}/{protocol}" for protocol, port in STANDARD_PUBLIC_PORTS),
    }
    rules: list[FirewallRule] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("Added user rules") or line == "(None)":
            continue
        if line.startswith("ufw "):
            line = line.removeprefix("ufw ")
        simple = _SIMPLE_RULE.fullmatch(line)
        network = _NETWORK_RULE.fullmatch(line)
        if simple:
            kind = (
                "standard" if simple["ports"] + "/" + simple["protocol"] in standard else "operator"
            )
            rules.append(FirewallRule(kind, line, "allow", simple["protocol"], simple["ports"], ""))
        elif network:
            rules.append(
                FirewallRule(
                    "operator",
                    line,
                    "allow",
                    network["protocol"] or network["trailing"] or "",
                    network["ports"],
                    network["network"],
                )
            )
        else:
            rules.append(FirewallRule("outside", line))
    return tuple(rules)


def digests_match(digests: str, conffiles: str, names: tuple[str, ...]) -> bool | None:
    expected: dict[str, str] = {}
    for line in conffiles.splitlines():
        fields = line.split()
        if len(fields) == 2:
            expected[fields[0].rsplit("/", 1)[-1]] = fields[1]
    observed: dict[str, str] = {}
    for line in digests.splitlines():
        fields = line.split()
        if len(fields) == 2:
            observed[fields[1].rsplit("/", 1)[-1]] = fields[0]
    compared = [name for name in names if name in expected and name in observed]
    if not compared:
        return None
    return all(observed[name] == expected[name] for name in compared)


def conffile_matches(digests: str, conffiles: str, path: str) -> bool | None:
    observed = ""
    for line in digests.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1] == path:
            observed = fields[0]
    expected = ""
    for line in conffiles.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == path:
            expected = fields[1]
    if not observed or not expected:
        return None
    return observed == expected


def _iptables_has_rules(text: str) -> bool:
    """A rule outside UFW's own chains, which a firewall change must leave alone."""
    table = ""
    for line in text.splitlines():
        if line.startswith("*"):
            table = line[1:].strip()
            continue
        if table != "filter" or not line.startswith(("-A ", "-I ")):
            continue
        fields = line.split()
        chain = fields[1] if len(fields) > 1 else ""
        if chain.startswith("ufw") or " -j ufw" in line:
            continue
        return True
    return False


def _nft_has_foreign_rules(text: str) -> bool:
    """A rule in a chain UFW does not own; UFW's own chains are adopted."""
    chain = ""
    for line in text.splitlines():
        stripped = line.strip()
        match = re.match(r"chain ([^ ]+) \{", stripped)
        if match:
            chain = match[1]
            continue
        if not chain or chain.startswith("ufw") or not stripped:
            continue
        if stripped in {"}", "{"} or stripped.startswith(("type ", "policy ", "comment ")):
            continue
        return True
    return False


def parse_apt_config(text: str) -> dict[str, str]:
    """The effective scalar values; APT applies the last file's value."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r'(?P<name>[^ ]+) "(?P<value>[^"]*)";', line.strip())
        if match:
            values[match["name"]] = match["value"]
    return values


def parse_allowed_origins(text: str) -> tuple[str, ...]:
    """Every allowed origin, which APT repeats under one key."""
    origins = []
    for line in text.splitlines():
        match = re.fullmatch(
            r'Unattended-Upgrade::Allowed-Origins:: "(?P<value>[^"]*)";', line.strip()
        )
        if match:
            origins.append(match["value"])
    return tuple(origins)


def parse_package_blacklist(text: str) -> tuple[str, ...]:
    """Every package pattern Ubuntu's automatic updates are told to skip."""
    entries = []
    for line in text.splitlines():
        match = re.fullmatch(
            r'Unattended-Upgrade::Package-Blacklist:: "(?P<value>[^"]*)";', line.strip()
        )
        if match:
            entries.append(match["value"])
    return tuple(entries)


def parse_timers(text: str) -> dict[str, str]:
    """Each timer's enablement at boot; a disabled timer does not follow the standard."""
    timers: dict[str, dict[str, str]] = {}
    current = ""
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        if not separator:
            continue
        if name == "Id":
            current = value.strip()
            timers[current] = {}
        elif current:
            timers[current][name] = value.strip()
    return {name: values.get("UnitFileState", "") for name, values in timers.items()}


def parse_newest_log(text: str) -> tuple[str, int | None]:
    fields = text.strip().split(None, 1)
    if len(fields) != 2:
        return "", None
    try:
        stamp = int(float(fields[0]))
    except ValueError:
        return "", None
    return fields[1], stamp


def summarize_unattended_log(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in reversed(lines):
        if line.startswith("Packages that were upgraded"):
            return line
        if line.startswith("No packages found"):
            return "No updates were installed."
        if line.startswith("Packages that will be upgraded"):
            return line
    return lines[-1] if lines else ""


def parse_upgrades(text: str) -> tuple[tuple[str, str, str], ...] | None:
    """Every simulated upgrade as (name, installed, candidate), and removals.

    "kept back" candidates are reported by APT without an ``Inst`` line, so the section
    heading and its package names are read too. A held package is reported separately.
    """
    rows: list[tuple[str, str, str]] = []
    section = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("The following packages will be REMOVED"):
            section = "removed"
            continue
        if stripped.startswith("The following packages have been kept back"):
            section = "kept"
            continue
        if stripped.startswith("Inst "):
            fields = stripped.split()
            if len(fields) < 4:
                return None
            name = fields[1]
            installed = fields[2].strip("[]")
            candidate = next((part.strip("()") for part in fields[3:] if part.startswith("(")), "")
            rows.append((name, installed, candidate.split(" ", 1)[0] if candidate else ""))
            continue
        if section and re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", stripped):
            rows.append((stripped, "", section))
            continue
        if not line.startswith(" "):
            section = ""
    return tuple(rows)


def parse_apt_policy(text: str) -> dict[str, str]:
    """The archive that offers each package's candidate, or ``removed``/``kept back``.

    A candidate published to both ``-updates`` and ``-security`` is a security update;
    Ubuntu copies security fixes into the updates suite too (docs/security.md#ubuntu-updates).
    """
    archives: dict[str, str] = {}
    suites: dict[str, list[str]] = {}
    candidate: dict[str, str] = {}
    offering = ""
    current = ""
    for line in text.splitlines():
        if line and not line.startswith(" "):
            current = line.strip().rstrip(":")
            offering = ""
            continue
        if not current:
            continue
        stripped = line.strip()
        if stripped.startswith("Candidate:"):
            version = stripped.partition(":")[2].strip()
            candidate[current] = version
            if version == "(none)":
                archives[current] = "removed"
            continue
        offered = re.fullmatch(r"(?:\*\*\* )?(\S+) \d+", stripped)
        if offered:
            offering = offered[1]
            continue
        match = re.match(r"^[0-9]+ (?:https?|file):\S+ (\S+) ", stripped)
        if match and offering and offering == candidate.get(current):
            suites.setdefault(current, []).append(match[1])
    for name, values in suites.items():
        if name in archives:
            continue
        archives[name] = next((value for value in values if "-security" in value), values[0])
    return archives


def parse_list_age(text: str, *, now: float | None = None) -> int | None:
    """The age of the newest package index from its modification time."""
    value = text.strip()
    try:
        modified = float(value)
    except ValueError:
        return None
    return max(0, int((time.time() if now is None else now) - modified))
