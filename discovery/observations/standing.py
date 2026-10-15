"""Fixed native evidence used by the shared host-standing judgment."""

import json
import re
from dataclasses import replace

from bootstrap.standing import HostEvidence, HostJudgment, judge
from operations.apt import PROCESS_COMMAND

from ..root_read import run_root
from ..snapshot import (
    FilesystemSize,
    Observation,
    OsRelease,
)
from ..ssh import RemoteShell
from .probes import COMMAND_NOT_FOUND, _Failed, _path_missing, _read_file, _run, _test

_VERSIONS = (
    ("apt", "apt --version", re.compile(r"apt ([0-9]+\.[0-9]+)\.[0-9]+")),
    (
        "dpkg",
        "dpkg --version",
        re.compile(r"Debian 'dpkg' package management program version ([0-9]+\.[0-9]+)\.[0-9]+"),
    ),
    ("systemd", "systemctl --version", re.compile(r"systemd ([0-9]+)(?:\.| \()")),
)
_PANEL_PATHS = (
    "/usr/local/cpanel",
    "/usr/local/psa",
    "/usr/local/directadmin",
    "/usr/local/hestia",
    "/usr/local/vesta",
    "/usr/local/CyberCP",
    "/usr/local/ispconfig",
    "/etc/webmin",
    "/www/server",
    "/etc/runcloud",
    "/home/clp",
)
_LISTENERS = "ss -Hlnpt '( sport = :80 or sport = :443 )'"
_TOOLS = (
    "apt-get",
    "dpkg-query",
    "df",
    "systemctl",
    "ss",
    "timedatectl",
    "getent",
    "id",
    "curl",
    "sha256sum",
    "tar",
    "xz",
    "flock",
    "journalctl",
    "systemd-analyze",
    "readlink",
    "stat",
    "awk",
    "sed",
    "grep",
    "/usr/sbin/useradd",
    "/usr/sbin/groupadd",
    "/usr/sbin/runuser",
)
_FOUNDATION_PATHS = (
    ("Nix", ("/nix/var/nix/profiles/default/bin/nix", "/etc/nix/nix.conf")),
    ("Catalog realisation", ("/nix/var/nix/profiles/per-user/root/profile/bin/caddy",)),
    ("Caddy", ("/etc/caddy/Caddyfile", "/etc/systemd/system/caddy.service")),
    ("journald", ("/etc/systemd/journald.conf.d/50-barectl.conf",)),
    ("Verify", ("/etc/caddy/sites",)),
)


def collect(
    shell: RemoteShell,
    os_release: Observation[OsRelease | None],
    architecture: Observation[str | None],
    filesystem: Observation[FilesystemSize | None],
    installed_packages: frozenset[str] | None,
) -> HostJudgment:
    """Judge the current host from fixed observations; failed reads remain unknown."""
    series = {name: _series(shell, command, pattern) for name, command, pattern in _VERSIONS}
    user_id = _integer(shell, "id -u")
    privileged = user_id == 0 if user_id is not None else None
    if privileged is False:
        checked = run_root(shell, "id -u")
        privileged = checked.exit_status == 0 and checked.stdout.strip() == "0"
    free_disk = filesystem.value.avail_bytes if filesystem.observed and filesystem.value else None
    available_memory = _available_memory(shell)
    proxy_stacks = _haproxy_stacks(shell)
    stacks = (*_foreign_stacks(installed_packages), *(proxy_stacks or ()))
    listeners = _listeners(shell)
    panel_states = tuple((path, _path_state(shell, path)) for path in _PANEL_PATHS)
    panels = tuple(path for path, state in panel_states if state is True)
    nix_shape = _nix_shape(shell)
    nix_ids_free = _nix_ids_free(shell)
    tool_status = tuple((tool, _command_exists(shell, tool)) for tool in _TOOLS)
    missing_tools = tuple(tool for tool, available in tool_status if available is False)
    clock = _boolean_command(shell, "timedatectl show -p NTPSynchronized --value", "yes", "no")
    apt_active = _apt_active(shell)
    foundation = tuple(_stage(shell, paths) for _, paths in _FOUNDATION_PATHS)
    release = (
        os_release.value.version_id
        if os_release.observed and os_release.value and os_release.value.id == "ubuntu"
        else None
    )
    machine = architecture.value if architecture.observed else None
    architecture_name = {"x86_64": "amd64", "aarch64": "arm64"}.get(machine or "", machine)
    judgment = judge(
        HostEvidence(
            release=release,
            architecture=architecture_name,
            apt_series=series["apt"],
            dpkg_series=series["dpkg"],
            systemd_series=series["systemd"],
            privileged=privileged,
            free_disk_bytes=free_disk,
            available_memory_bytes=available_memory,
            foreign_web_stacks=stacks,
            foreign_stacks_readable=installed_packages is not None and proxy_stacks is not None,
            privileged_listeners=listeners or (),
            panel_paths=panels,
            nix_shape=nix_shape,
            nix_build_uid_range_free=nix_ids_free,
            required_tools_missing=missing_tools,
            required_tools_readable=all(available is not None for _, available in tool_status),
            clock_synchronized=clock,
            apt_daily_active=apt_active,
            foundation=foundation,
            panel_paths_readable=all(state is not None for _, state in panel_states),
            listeners_readable=listeners is not None,
        )
    )
    if nix_shape == "supported":
        from bootstrap import foundation as host_foundation
        from runtimes.catalog import architecture_of, load

        values = host_foundation.read(shell)
        catalog_architecture = architecture_of(machine or "")
        if values and catalog_architecture:
            exact = host_foundation.complete(values, catalog_architecture)
            observed_stages = (
                "present" if values.get("daemon") == "active" else "incomplete",
                "present"
                if all(
                    values.get(entry, "").startswith("/nix/store/")
                    for entry in host_foundation.PROFILES
                )
                else "incomplete",
                "present"
                if values.get("caddy_valid") == "yes" and values.get("caddy_state") == "active"
                else "incomplete",
                "present" if values.get("journal") == "persistent" else "incomplete",
                "present" if exact else "incomplete",
            )
            own_pid = values.get("caddy_pid", "")
            own_executable = values.get("caddy_executable", "")
            known = load().identify(catalog_architecture, own_executable.removesuffix("/bin/caddy"))
            foreign = tuple(
                line
                for line in (listeners or ())
                if not (known and own_pid and f"pid={own_pid}," in line)
            )
            judgment = judge(
                HostEvidence(
                    release=release,
                    architecture=architecture_name,
                    apt_series=series["apt"],
                    dpkg_series=series["dpkg"],
                    systemd_series=series["systemd"],
                    privileged=privileged,
                    free_disk_bytes=free_disk,
                    available_memory_bytes=available_memory,
                    foreign_web_stacks=stacks,
                    foreign_stacks_readable=installed_packages is not None
                    and proxy_stacks is not None,
                    privileged_listeners=foreign,
                    panel_paths=panels,
                    nix_shape=nix_shape,
                    nix_build_uid_range_free=nix_ids_free,
                    required_tools_missing=missing_tools,
                    required_tools_readable=all(
                        available is not None for _, available in tool_status
                    ),
                    clock_synchronized=clock,
                    apt_daily_active=apt_active,
                    foundation=observed_stages,
                    panel_paths_readable=all(state is not None for _, state in panel_states),
                    listeners_readable=listeners is not None,
                )
            )
            judgment = replace(
                judgment,
                evidence=(
                    *judgment.evidence,
                    ("Caddy version", values.get("caddy_version", "Could not be read")),
                    ("Caddy state", values.get("caddy_state", "Could not be read")),
                    ("Caddy configuration", values.get("caddy_valid", "Could not be read")),
                    ("Nix daemon", values.get("daemon", "Could not be read")),
                    ("Journal storage", values.get("journal", "Could not be read")),
                ),
            )
    return judgment


def _series(shell: RemoteShell, command: str, pattern: re.Pattern[str]) -> str | None:
    result = _run(shell, command)
    if isinstance(result, _Failed):
        return None
    match = pattern.search(result)
    return match.group(1) if match else None


def _integer(shell: RemoteShell, command: str) -> int | None:
    result = _run(shell, command)
    if isinstance(result, _Failed):
        return None
    value = result.strip()
    return int(value) if re.fullmatch(r"[0-9]{1,10}", value) else None


def _available_memory(shell: RemoteShell) -> int | None:
    result = _read_file(shell, "/proc/meminfo")
    if isinstance(result, _Failed):
        return None
    for line in result.splitlines():
        match = re.fullmatch(r"MemAvailable:\s+([0-9]+) kB", line)
        if match:
            return int(match[1]) * 1024
    return None


def _foreign_stacks(installed_packages: frozenset[str] | None) -> tuple[str, ...]:
    installed: list[str] = []
    if installed_packages is not None:
        families = (
            ("Apache", {"apache2", "apache2-bin"}),
            ("Nginx", {"nginx", "nginx-core", "nginx-full", "nginx-light", "nginx-extras"}),
            ("Lighttpd", {"lighttpd"}),
            ("Caddy", {"caddy"}),
            ("HAProxy", {"haproxy"}),
            ("OpenLiteSpeed", {"openlitespeed"}),
        )
        for label, known in families:
            packages = sorted(installed_packages & known)
            if packages:
                installed.append(f"{label} packages: {', '.join(packages)}")
        php = sorted(name for name in installed_packages if name.startswith("php"))
        if php:
            installed.append(f"APT PHP packages: {', '.join(php)}")
    return tuple(dict.fromkeys(installed))


def _haproxy_stacks(shell: RemoteShell) -> tuple[str, ...] | None:
    from sites.observation import PROXY_INVENTORY_COMMAND

    result = run_root(shell, PROXY_INVENTORY_COMMAND)
    if result.exit_status or result.truncated:
        return None
    try:
        value: object = json.loads(result.stdout)
    except ValueError:
        return None
    if not isinstance(value, list) or any(not isinstance(row, str) for row in value):
        return None
    return tuple(value)


def _listeners(shell: RemoteShell) -> tuple[str, ...] | None:
    result = run_root(shell, _LISTENERS)
    if result.exit_status != 0 or result.truncated:
        return None
    return tuple(line[:300] for line in result.stdout.splitlines()[:20])


def _nix_shape(shell: RemoteShell) -> str | None:
    binary_path = "/nix/var/nix/profiles/default/bin/nix"
    binary = _path_state(shell, binary_path)
    store = _path_state(shell, "/nix/store")
    config = _path_state(shell, "/etc/nix/nix.conf")
    if None in (binary, store, config):
        return None
    if not binary and not store and not config:
        return "absent"
    if binary and store and config and _test(shell, "-x", binary_path) and _supported_nix(shell):
        return "supported"
    return "partial"


def _path_state(shell: RemoteShell, path: str) -> bool | None:
    if _test(shell, "-e", path):
        return True
    return False if _path_missing(shell, path) else None


def _supported_nix(shell: RemoteShell) -> bool:
    version = _run(shell, "/nix/var/nix/profiles/default/bin/nix --version")
    config = _read_file(shell, "/etc/nix/nix.conf")
    if isinstance(version, _Failed) or isinstance(config, _Failed):
        return False
    expected = {
        "allowed-users": "root",
        "trusted-users": "root",
        "substituters": "https://cache.nixos.org",
        "trusted-public-keys": "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=",
        "max-jobs": "0",
        "fallback": "false",
    }
    observed = {
        name.strip(): value.strip()
        for line in config.splitlines()
        if "=" in line
        for name, _, value in (line.partition("="),)
    }
    return version.strip() == "nix (Nix) 2.35.2" and observed == expected


def _nix_ids_free(shell: RemoteShell) -> bool | None:
    result = _run(shell, "getent passwd")
    if isinstance(result, _Failed):
        return None
    reserved: list[list[str]] = []
    for line in result.splitlines():
        fields = line.split(":")
        if len(fields) != 7 or not fields[2].isdigit():
            return None
        if 30001 <= int(fields[2]) <= 30032:
            reserved.append(fields)
    if not reserved:
        reserved_group = shell.run("getent group 30000")
        return (
            reserved_group.exit_status == 2
            and not reserved_group.stdout
            and not reserved_group.truncated
        )

    if len(reserved) != 32 or not _supported_nix(shell):
        return False
    group = _run(shell, "getent group nixbld")
    if isinstance(group, _Failed):
        return None
    fields = group.strip().split(":")
    if len(fields) != 4 or fields[2] != "30000":
        return False
    members = set(fields[3].split(","))
    expected = {f"nixbld{index}" for index in range(1, 33)}
    return members == expected and all(
        account[0] == f"nixbld{int(account[2]) - 30000}"
        and account[3] == fields[2]
        and account[5] == "/var/empty"
        and account[6] in {"/sbin/nologin", "/usr/sbin/nologin"}
        for account in reserved
    )


def _command_exists(shell: RemoteShell, name: str) -> bool | None:
    result = shell.run(f"command -v {name}")
    if result.exit_status == 0:
        return bool(result.stdout.strip())
    if result.exit_status == COMMAND_NOT_FOUND:
        return False
    return None


def _boolean_command(shell: RemoteShell, command: str, yes: str, no: str) -> bool | None:
    result = _run(shell, command)
    if isinstance(result, _Failed):
        return None
    value = result.strip().lower()
    return True if value == yes else False if value == no else None


def _apt_active(shell: RemoteShell) -> bool | None:
    result = shell.run(PROCESS_COMMAND)
    if result.truncated or result.exit_status not in {0, 1}:
        return None
    return result.exit_status == 1


def _stage(shell: RemoteShell, paths: tuple[str, ...]) -> str:
    present = tuple(_path_state(shell, path) for path in paths)
    if None in present:
        return "unreadable"
    if not any(present):
        return "absent"
    return "present" if all(present) else "incomplete"
