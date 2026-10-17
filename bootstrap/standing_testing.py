"""Shared observed-host evidence for pure standing and foundation review tests."""

from .standing import HostEvidence


def fresh_evidence() -> HostEvidence:
    return HostEvidence(
        release="26.04",
        architecture="amd64",
        apt_series="3.2",
        dpkg_series="1.23",
        systemd_series="259",
        privileged=True,
        free_disk_bytes=20 * 1024**3,
        available_memory_bytes=4 * 1024**3,
        foreign_web_stacks=(),
        privileged_listeners=(),
        panel_paths=(),
        nix_shape="absent",
        nix_build_uid_range_free=True,
        required_tools_missing=(),
        clock_synchronized=True,
        apt_daily_active=False,
        foundation=("absent",) * 5,
    )
