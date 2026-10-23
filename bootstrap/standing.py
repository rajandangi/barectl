"""Pure judgment of host standing from fixed native evidence.

docs/target-architecture.md#host-standing and ADR 0026.
"""

from dataclasses import dataclass
from enum import StrEnum


class Standing(StrEnum):
    FRESH = "Fresh host"
    INCOMPLETE_FOUNDATION = "Incomplete foundation"
    TARGET_STACK = "Target stack"
    NOT_MANAGEABLE = "Not manageable"


@dataclass(frozen=True)
class HostEvidence:
    release: str | None
    architecture: str | None
    apt_series: str | None
    dpkg_series: str | None
    systemd_series: str | None
    privileged: bool | None
    free_disk_bytes: int | None
    available_memory_bytes: int | None
    foreign_web_stacks: tuple[str, ...]
    privileged_listeners: tuple[str, ...]
    panel_paths: tuple[str, ...]
    nix_shape: str | None
    nix_build_uid_range_free: bool | None
    required_tools_missing: tuple[str, ...]
    clock_synchronized: bool | None
    apt_daily_active: bool | None
    foundation: tuple[str, ...]
    foreign_stacks_readable: bool = True
    required_tools_readable: bool = True
    panel_paths_readable: bool = True
    listeners_readable: bool = True


@dataclass(frozen=True)
class HostJudgment:
    standing: Standing
    reasons: tuple[str, ...]
    warnings: tuple[str, ...]
    foundation: tuple[tuple[str, str], ...]
    evidence: tuple[tuple[str, str], ...] = ()
    # The installed catalog profile each tool entry resolves to, from native evidence.
    profiles: tuple[tuple[str, str], ...] = ()


FOUNDATION_STAGES = ("Nix", "Catalog realisation", "Caddy", "journald", "Verify")
SUPPORTED_ARCHITECTURES = frozenset({"amd64", "arm64"})
_PROVISIONAL_MINIMUM_DISK = 4 * 1024**3
_PROVISIONAL_MINIMUM_MEMORY = 900 * 1024**2


def judge(evidence: HostEvidence) -> HostJudgment:
    """Return a reproducible standing without consulting controller or server markers."""
    reasons: list[str] = []
    warnings: list[str] = []
    checks = (
        _platform_reasons(evidence),
        _foreign_reasons(evidence),
        _privilege_reasons(evidence),
        _capacity_reasons(evidence),
        _nix_reasons(evidence),
        _tool_reasons(evidence),
        _activity_reasons(evidence),
    )
    reasons.extend(reason for group in checks for reason in group)
    warnings.extend(_clock_warnings(evidence))
    foundation, foundation_reasons = _foundation(evidence)
    reasons.extend(foundation_reasons)

    if reasons:
        standing = Standing.NOT_MANAGEABLE
    elif all(state == "present" for _, state in foundation):
        standing = Standing.TARGET_STACK
    elif any(state in {"present", "incomplete"} for _, state in foundation):
        standing = Standing.INCOMPLETE_FOUNDATION
    else:
        standing = Standing.FRESH
    return HostJudgment(
        standing,
        tuple(reasons),
        tuple(warnings),
        foundation,
        _evidence_lines(evidence),
    )


def _evidence_lines(evidence: HostEvidence) -> tuple[tuple[str, str], ...]:
    return (
        ("Ubuntu release", evidence.release or "Could not be read"),
        ("Architecture", evidence.architecture or "Could not be read"),
        ("APT series", evidence.apt_series or "Could not be read"),
        ("dpkg series", evidence.dpkg_series or "Could not be read"),
        ("systemd series", evidence.systemd_series or "Could not be read"),
        ("Privilege", _boolean(evidence.privileged, "Available", "Unavailable")),
        ("Free disk (4 GiB provisional threshold, unqualified)", _bytes(evidence.free_disk_bytes)),
        (
            "Available memory (900 MiB provisional threshold, unqualified)",
            _bytes(evidence.available_memory_bytes),
        ),
        (
            "Foreign web stacks",
            ", ".join(evidence.foreign_web_stacks)
            if evidence.foreign_web_stacks
            else "None found"
            if evidence.foreign_stacks_readable
            else "Could not be read",
        ),
        (
            "Ports 80/443 listeners",
            ", ".join(evidence.privileged_listeners)
            if evidence.privileged_listeners
            else "None found"
            if evidence.listeners_readable
            else "Could not be read",
        ),
        (
            "Hosting panel paths",
            ", ".join(evidence.panel_paths)
            if evidence.panel_paths
            else "None found"
            if evidence.panel_paths_readable
            else "Could not be read",
        ),
        ("Nix installation", evidence.nix_shape or "Could not be read"),
        (
            "Nix build-user ID range",
            _boolean(evidence.nix_build_uid_range_free, "Free", "Occupied"),
        ),
        (
            "Required tools",
            ", ".join(evidence.required_tools_missing)
            if evidence.required_tools_missing
            else "Could not be read"
            if not evidence.required_tools_readable
            else "Present",
        ),
        (
            "Clock synchronization",
            _boolean(evidence.clock_synchronized, "Synchronized", "Not synchronized"),
        ),
        (
            "APT background activity",
            "Active"
            if evidence.apt_daily_active is True
            else "Inactive"
            if evidence.apt_daily_active is False
            else "Could not be read",
        ),
    )


def _boolean(value: bool | None, positive: str, negative: str) -> str:
    return positive if value is True else negative if value is False else "Could not be read"


def _bytes(value: int | None) -> str:
    return f"{value / 1024**3:.1f} GiB" if value is not None else "Could not be read"


def _platform_reasons(evidence: HostEvidence) -> tuple[str, ...]:
    reasons: list[str] = []
    if evidence.release is None:
        reasons.append("The operating system could not be read.")
    elif evidence.release != "26.04":
        reasons.append(f"Ubuntu {evidence.release} is outside supported settings.")
    if evidence.architecture is None:
        reasons.append("The server architecture could not be read.")
    elif evidence.architecture not in SUPPORTED_ARCHITECTURES:
        reasons.append(f"The {evidence.architecture} architecture is not qualified.")
    for name, series, expected in (
        ("apt", evidence.apt_series, "3.2"),
        ("dpkg", evidence.dpkg_series, "1.23"),
        ("systemd", evidence.systemd_series, "259"),
    ):
        if series is None:
            reasons.append(f"The {name} series could not be read.")
        elif series != expected:
            reasons.append(f"The {name} {series} series is outside supported settings.")
    return tuple(reasons)


def _foreign_reasons(evidence: HostEvidence) -> tuple[str, ...]:
    reasons: list[str] = []
    if evidence.foreign_web_stacks:
        items = ", ".join(evidence.foreign_web_stacks)
        reasons.append(f"Another web stack is installed: {items}.")
        installed = tuple(item.lower() for item in evidence.foreign_web_stacks)
        nginx = any(item.startswith("nginx") for item in installed)
        apt_php = any(item.startswith("apt php") for item in installed)
        if nginx and apt_php:
            reasons.append("Earlier Barectl layouts are not managed.")
    elif not evidence.foreign_stacks_readable:
        reasons.append("Installed web-stack and PHP packages could not be inspected.")
    if evidence.privileged_listeners:
        reasons.append(
            "Ports 80 or 443 have foreign privileged listeners: "
            f"{', '.join(evidence.privileged_listeners)}."
        )
    elif not evidence.listeners_readable:
        reasons.append("Listeners on ports 80 and 443 could not be inspected.")
    if evidence.panel_paths:
        reasons.append(f"Hosting panel paths are present: {', '.join(evidence.panel_paths)}.")
    elif not evidence.panel_paths_readable:
        reasons.append("Hosting panel paths could not be inspected.")
    return tuple(reasons)


def _foundation(
    evidence: HostEvidence,
) -> tuple[tuple[tuple[str, str], ...], tuple[str, ...]]:
    reasons: list[str] = []
    foundation = tuple(zip(FOUNDATION_STAGES, evidence.foundation, strict=False))
    if len(evidence.foundation) != len(FOUNDATION_STAGES):
        reasons.append("Foundation stage evidence is incomplete.")
    if any(state == "unreadable" for _, state in foundation):
        reasons.append("One or more foundation stages could not be read.")
    return foundation, tuple(reasons)


def _capacity_reasons(evidence: HostEvidence) -> tuple[str, ...]:
    reasons: list[str] = []
    if evidence.free_disk_bytes is None:
        reasons.append("Free disk space could not be read.")
    elif evidence.free_disk_bytes < _PROVISIONAL_MINIMUM_DISK:
        reasons.append(
            "Free disk space is below the provisional 4 GiB headroom threshold (unqualified)."
        )
    if evidence.available_memory_bytes is None:
        reasons.append("Available memory could not be read.")
    elif evidence.available_memory_bytes < _PROVISIONAL_MINIMUM_MEMORY:
        reasons.append(
            "Available memory is below the provisional 900 MiB headroom threshold (unqualified)."
        )
    return tuple(reasons)


def _privilege_reasons(evidence: HostEvidence) -> tuple[str, ...]:
    if evidence.privileged is True:
        return ()
    if evidence.privileged is None:
        return ("The discovery connection's privilege could not be read.",)
    return ("The discovery connection has neither root nor authorized passwordless sudo.",)


def _nix_reasons(evidence: HostEvidence) -> tuple[str, ...]:
    reasons: list[str] = []
    if evidence.nix_shape is None:
        reasons.append("Nix could not be inspected.")
    elif evidence.nix_shape not in {"absent", "supported", "partial"}:
        reasons.append("An unrecognized Nix installation is present.")
    elif evidence.nix_shape == "partial":
        reasons.append(
            "Nix installation incomplete. Follow the official uninstall instructions before "
            "preparing again: https://nix.dev/manual/nix/2.35/installation/uninstall.html"
        )
    if evidence.nix_build_uid_range_free is not True:
        reasons.append("The Nix build-user ID range is occupied or could not be checked.")
    return tuple(reasons)


def _tool_reasons(evidence: HostEvidence) -> tuple[str, ...]:
    reasons: list[str] = []
    if evidence.required_tools_missing:
        reasons.append(f"Required tools are missing: {', '.join(evidence.required_tools_missing)}.")
    if not evidence.required_tools_readable:
        reasons.append("Required tools could not be checked.")
    return tuple(reasons)


def _activity_reasons(evidence: HostEvidence) -> tuple[str, ...]:
    if evidence.apt_daily_active is False:
        return ()
    return ("APT background package activity is running or could not be checked.",)


def _clock_warnings(evidence: HostEvidence) -> tuple[str, ...]:
    if evidence.clock_synchronized is False:
        return ("The server clock is not synchronized.",)
    if evidence.clock_synchronized is None:
        return ("Clock synchronization could not be checked.",)
    return ()
