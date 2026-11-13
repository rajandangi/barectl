"""The journal retention policy Barectl can own, reconstructed from fixed native facts (#549).

docs/adr/0044-own-journald-log-retention-in-a-separate-drop-in.md. Barectl writes one
drop-in as ``root:root 0644`` and reads the merged journald configuration back. This module
stays pure: discovery imports it to store the observation, and the change kind imports it to
render and compare a candidate.
"""

import hashlib
import re
from dataclasses import dataclass
from typing import Final

JOURNAL_DIRECTORY: Final = "/etc/systemd/journald.conf.d"
RETENTION_PATH: Final = f"{JOURNAL_DIRECTORY}/60-barectl-log-retention.conf"
MISSING: Final = "missing"

DISK_CAP_CHOICES: Final = ("250M", "500M", "1G", "2G", "4G")
DISK_CAP_LABELS: Final[dict[str, str]] = {
    "250M": "250 MiB",
    "500M": "500 MiB",
    "1G": "1 GiB",
    "2G": "2 GiB",
    "4G": "4 GiB",
}
MAX_AGE_CHOICES: Final = ("1week", "1month", "3months", "6months", "1year")
MAX_AGE_LABELS: Final[dict[str, str]] = {
    "1week": "1 week",
    "1month": "1 month",
    "3months": "3 months",
    "6months": "6 months",
    "1year": "12 months",
}

NOT_CONFIGURED: Final = "not_configured"
MANAGED: Final = "managed"
OUTSIDE: Final = "outside"
NOT_CHECKED: Final = "not_checked"

SHAPE: Final = "[Journal]\nSystemMaxUse=<disk-cap>\nMaxRetentionSec=<max-age>\n"

_FILE_FACT = re.compile(
    r"([0-9]+) ([0-9]+) ([0-7]{3,4}) ([0-9]+) (file ([0-9a-f]{64})|directory|symlink|other)"
)
_OWNED = ("0", "0", "644", "1")


@dataclass(frozen=True)
class RetentionObservation:
    """One reconstructed state, with the values the card shows or the plain reason it is outside."""

    state: str
    reason: str = ""
    disk_cap: str = ""
    max_age: str = ""


def render(disk_cap: str, max_age: str) -> str:
    """The exact native file Barectl writes for one supported pair."""
    if disk_cap not in DISK_CAP_CHOICES:
        raise ValueError("The disk cap is not one of the supported choices.")
    if max_age not in MAX_AGE_CHOICES:
        raise ValueError("The maximum age is not one of the supported choices.")
    return f"[Journal]\nSystemMaxUse={disk_cap}\nMaxRetentionSec={max_age}\n"


def _rendered_pair(digest: str) -> tuple[str, str] | None:
    for disk_cap in DISK_CAP_CHOICES:
        for max_age in MAX_AGE_CHOICES:
            content = render(disk_cap, max_age).encode()
            if hashlib.sha256(content).hexdigest() == digest:
                return disk_cap, max_age
    return None


def reconstruct(
    file_fact: str, effective_disk_cap: str, effective_max_age: str
) -> RetentionObservation:
    """Turn the fixed read's three facts into exactly one state.

    ``file_fact`` is ``missing`` or the path's owner, group, mode, link count, one type
    token (``file``, ``directory``, ``symlink`` or ``other``) and, for a regular file, its
    SHA-256. The effective values come from the merged journald configuration, so a later
    drop-in is visible. Anything the read cannot establish is outside supported settings,
    never managed.
    """
    if file_fact == MISSING:
        return RetentionObservation(NOT_CONFIGURED)
    match = _FILE_FACT.fullmatch(file_fact)
    if match is None:
        return RetentionObservation(OUTSIDE, "The retention configuration could not be read.")
    if match[6] is None:
        return RetentionObservation(
            OUTSIDE, "The retention configuration path is not a regular file."
        )
    if match.groups()[:4] != _OWNED:
        return RetentionObservation(
            OUTSIDE,
            "The retention configuration is not a root-owned 0644 regular file with one link.",
        )
    pair = _rendered_pair(match[6])
    if pair is None:
        return RetentionObservation(
            OUTSIDE, "The retention configuration is not the exact content Barectl writes."
        )
    if not effective_disk_cap or not effective_max_age:
        return RetentionObservation(OUTSIDE, "The effective retention values could not be read.")
    if (effective_disk_cap, effective_max_age) != pair:
        return RetentionObservation(
            OUTSIDE, "A later configuration overrides the retention setting."
        )
    return RetentionObservation(MANAGED, "", pair[0], pair[1])
