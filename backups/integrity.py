"""The weekly integrity finding and its fixed native units (Phase D #405).

**Enable backups** installs one weekly unit per repository, onsite and offsite. Each run
holds the per-repository lock, runs ``restic check`` with a rotating ``--read-data-subset``,
and reads the newest complete recovery point back through ``restic dump`` into a private
stage. The run writes one safe ``barectl-result`` line with its class, counts, bytes, short
point identifier, subset and location.

Passive discovery reads those lines from the native journal and stores the finding as a typed
``BackupIntegrity`` row per site and location. This module never runs restic on a page.
"""

import json
from typing import Final

from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from servers.models import Server

from . import convention
from .bodies import integrity as integrity_body
from .observation import IntegrityFinding, finding_of

MAX_BYTES: Final = 262144
JOURNAL: Final = (
    "/usr/bin/journalctl --no-pager --reverse -o cat -n 500 --grep '^barectl-result '"
    f" | /usr/bin/head -c {MAX_BYTES + 1}"
)


def enable_document(identifier: str) -> dict[str, object]:
    """The unit files and run payload Enable backups installs for this site."""
    return {
        "check": {
            "version": 1,
            "payload": {
                "version": 1,
                "identifier": identifier,
                "repository": convention.repository(identifier),
                "server_key": convention.server_key(identifier),
                "filename": convention.dump_filename(identifier),
            },
            "units": integrity_body.unit_texts(identifier),
        }
    }


def validate_enable(document: dict[str, object]) -> dict[str, object] | None:
    """The reviewed check setup, or ``None`` when this review installs nothing."""
    raw = document.get("check")
    if raw is None:
        return None
    identifier = document.get("identifier")
    if not isinstance(raw, dict) or set(raw) != {"version", "payload", "units"}:
        raise ValueError("The integrity check is not the reviewed one.")
    if (
        raw.get("version") != 1
        or not isinstance(identifier, str)
        or convention.SITE_IDENTIFIER.fullmatch(identifier) is None
    ):
        raise ValueError("The integrity check is not the reviewed one.")
    units = raw.get("units")
    payload = raw.get("payload")
    if not isinstance(units, dict) or not isinstance(payload, dict):
        raise ValueError("The integrity check is not the reviewed one.")
    if set(units) != set(integrity_body.UNIT_KEYS):
        raise ValueError("The integrity check is not the reviewed one.")
    for key, expected in integrity_body.unit_texts(identifier).items():
        if units.get(key) != expected:
            raise ValueError("The integrity check is not the reviewed one.")
    if (
        set(payload) != {"version", "identifier", "repository", "server_key", "filename"}
        or payload.get("version") != 1
        or payload.get("identifier") != identifier
        or payload.get("repository") != convention.repository(identifier)
        or payload.get("server_key") != convention.server_key(identifier)
        or payload.get("filename") != convention.dump_filename(identifier)
    ):
        raise ValueError("The integrity check is not the reviewed one.")
    return raw


def journal_command() -> str:
    return JOURNAL


def read_results(shell: RemoteShell, identifier: str) -> tuple[IntegrityFinding, ...] | None:
    """Every location's newest integrity finding for one site, or ``None`` when unreadable."""
    result = run_root(shell, journal_command())
    if result.exit_status or result.truncated or len(result.stdout) > MAX_BYTES:
        return None
    return parse_results(result.stdout, identifier)


def parse_results(text: str, identifier: str) -> tuple[IntegrityFinding, ...]:
    found: dict[str, IntegrityFinding] = {}
    for line in text.splitlines():
        if not line.startswith("barectl-result "):
            continue
        try:
            value = json.loads(line[len("barectl-result ") :])
        except ValueError:
            continue
        if not isinstance(value, dict):
            continue
        if value.get("kind") != "integrity" or value.get("site") != identifier:
            continue
        location = value.get("location")
        if location not in ("onsite", "offsite") or location in found:
            continue
        row = {
            key: value.get(key)
            for key in (
                "location",
                "class",
                "reason",
                "at",
                "point",
                "checked",
                "snapshots",
                "bytes",
                "subset",
            )
        }
        finding = finding_of(row, str(location))
        if finding is not None:
            found[str(location)] = finding
    return tuple(found[location] for location in ("onsite", "offsite") if location in found)


def record(server: Server, identifier: str, findings: tuple[IntegrityFinding, ...]) -> None:
    from django.utils import timezone

    from .models import BackupIntegrity

    now = timezone.now()
    by_location = {finding.location: finding for finding in findings}
    for location in ("onsite", "offsite"):
        finding = by_location.get(location)
        if finding is None:
            BackupIntegrity.objects.filter(
                server=server, identifier=identifier, location=location
            ).delete()
            continue
        BackupIntegrity.objects.update_or_create(
            server=server,
            identifier=identifier,
            location=location,
            defaults={
                "result_class": finding.result_class,
                "reason": finding.reason,
                "at": finding.at,
                "point": finding.point,
                "checked": finding.checked,
                "snapshots": finding.snapshots,
                "bytes": finding.size,
                "subset": finding.subset,
                "checked_at": now,
            },
        )


def stored(server: Server, identifier: str) -> tuple[IntegrityFinding, ...]:
    from .models import BackupIntegrity

    return tuple(
        IntegrityFinding(
            row.location,
            row.result_class,
            row.reason,
            row.at,
            row.point,
            row.checked,
            row.snapshots,
            row.bytes,
            row.subset,
        )
        for row in BackupIntegrity.objects.filter(server=server, identifier=identifier).order_by(
            "location"
        )
    )
