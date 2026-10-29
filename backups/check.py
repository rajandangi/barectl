"""Check backups: an explicit read-only listing of one site's recovery points (#396).

The read runs through the worker and ``RemoteShell`` as root with the site's server key and
``--no-lock``, so it never changes the repository. The bounded result lives on the request
row with the time it was read; opening the Backups section runs nothing.
"""

import json
import shlex
from datetime import timedelta
from typing import Final

from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone

from databases import observation as database_observation
from discovery.presentation import VIEW_SITES
from discovery.root_read import run_root
from discovery.snapshot import current_snapshot
from discovery.ssh import connect_operation
from operations import lifecycle
from operations.lifecycle import OperationRefused, recovers_first
from operations.models import RemoteOperation
from servers.models import Server
from sites.names import valid_identifier

from . import convention, integrity, observation
from .models import BackupCheck

READ_PERMISSIONS: Final = ("servers.view_server", VIEW_SITES)
INTERRUPTED_FAILURE: Final = (
    "The backup check worker stopped before finishing this request. Check backups again."
)
UNEXPECTED_FAILURE: Final = (
    "The backup check stopped because of an unexpected error. Barectl did not record the "
    "error details, which could include remote output. Check backups again."
)
STALE_AFTER: Final = timedelta(minutes=5)
LISTING_FRESH: Final = timedelta(minutes=15)
MAX_BYTES: Final = 262144
MAX_POINTS: Final = 500
POINT: Final = convention.POINT
SCOPES: Final = convention.SCOPES
ORIGINS: Final = convention.ORIGINS


def listing_command(identifier: str) -> str:
    argv = [
        "/usr/bin/env",
        f"RESTIC_REPOSITORY={convention.repository(identifier)}",
        f"RESTIC_PASSWORD_FILE={convention.server_key(identifier)}",
        f"RESTIC_CACHE_DIR={convention.CACHE_DIR}",
        convention.RESTIC_BIN,
        "snapshots",
        "--json",
        "--no-lock",
        "--tag",
        convention.MARKER,
        "--tag",
        f"site:{identifier}",
    ]
    return shlex.join(argv) + f" | /usr/bin/head -c {MAX_BYTES + 1}"


def parse_listing(text: str) -> list[dict[str, object]] | None:
    """The Barectl-tagged recovery points in restic's snapshots answer."""
    try:
        value: object = json.loads(text)
    except ValueError:
        return None
    if not isinstance(value, list) or len(value) > MAX_POINTS:
        return None
    return [row for row in value if _barectl_point(row)]


def _barectl_point(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    tags = value.get("tags")
    if (
        not isinstance(tags, list)
        or len(tags) > 16
        or not all(isinstance(tag, str) and convention.TAG.fullmatch(tag) for tag in tags)
    ):
        return False
    return convention.MARKER in tags


def points(value: list[dict[str, object]]) -> list[dict[str, object]]:
    groups: dict[str, list[dict[str, object]]] = {}
    for snapshot in value:
        tags = snapshot.get("tags")
        if not isinstance(tags, list):
            continue
        row = _point_row(snapshot, tags)
        if row is not None:
            groups.setdefault(str(row["point"]), []).append(row)
    rows = [_combined(group) for group in groups.values()]
    return sorted(rows, key=lambda row: str(row["time"]), reverse=True)


def _point_row(snapshot: dict[str, object], tags: list[object]) -> dict[str, object] | None:
    lookup = {tag: True for tag in tags if isinstance(tag, str)}
    point = _tag(tags, convention.POINT_TAG)
    identifier = snapshot.get("id")
    when = snapshot.get("time")
    if (
        not isinstance(identifier, str)
        or len(identifier) != 64
        or not isinstance(when, str)
        or len(when) > 40
        or (point and POINT.fullmatch(point) is None)
    ):
        return None
    scope = _tag(tags, "scope:")
    part = _tag(tags, "part:") or (scope if scope in convention.PARTS else "")
    application = _tag(tags, "application:")
    return {
        "id": identifier,
        "short": identifier[:8],
        "time": when,
        "point": point or identifier,
        "scope": scope,
        "part": part,
        "origin": _tag(tags, "origin:"),
        "application": application if application in convention.APPLICATIONS else "",
        "live": lookup.get("capture:live", False),
        "keep": lookup.get("keep", False),
        "complete_part": lookup.get("complete", False),
        "size": _processed_bytes(snapshot),
    }


def _combined(parts: list[dict[str, object]]) -> dict[str, object]:
    """One recovery point from its snapshots, restorable only when every part is complete."""
    scopes = {str(part["scope"]) for part in parts}
    scope = scopes.pop() if len(scopes) == 1 else ""
    present = {str(part["part"]) for part in parts if str(part["part"])}
    expected = set(convention.expected_parts(scope)) if scope else present
    missing = sorted(expected - present)
    incomplete = sorted(
        part
        for part in expected
        if not any(str(item["part"]) == part and item["complete_part"] is True for item in parts)
    )
    restorable = bool(expected) and not missing and not incomplete
    first = parts[0]
    application = next(
        (str(part["application"]) for part in parts if str(part.get("application", ""))),
        "",
    )
    return {
        "id": str(first["id"]),
        "short": str(first["short"]),
        "time": min(str(part["time"]) for part in parts),
        "point": str(first["point"]),
        "scope": scope,
        "parts": sorted(present),
        "snapshots": {
            str(part["part"]): str(part["id"])
            for part in parts
            if str(part["part"]) and part["complete_part"] is True
        },
        "application": application,
        "missing": missing,
        "incomplete": incomplete,
        "origin": str(first["origin"]),
        "live": all(part["live"] is True for part in parts),
        "keep": any(part["keep"] is True for part in parts),
        "size": sum(int(str(part.get("size", 0))) for part in parts),
        "complete": restorable,
    }


def _processed_bytes(snapshot: dict[str, object]) -> int:
    summary = snapshot.get("summary")
    if not isinstance(summary, dict):
        return 0
    value = summary.get("total_bytes_processed", summary.get("data_added", 0))
    return value if type(value) is int and value >= 0 else 0


def _tag(tags: list[object], prefix: str) -> str:
    return next(
        (
            tag.removeprefix(prefix)
            for tag in tags
            if isinstance(tag, str) and tag.startswith(prefix)
        ),
        "",
    )


def _engine(server: Server) -> str:
    snapshot = current_snapshot(server)
    if snapshot is None:
        return ""
    engines = database_observation.installed_engines(snapshot.collected)
    return engines[0].engine if len(engines) == 1 and engines[0].managed else ""


def _authorized(check: BackupCheck) -> None:
    user = User.objects.filter(pk=check.requested_by_id).first() if check.requested_by_id else None
    if user is None or not user.is_active or not user.has_perms(READ_PERMISSIONS):
        raise OperationRefused("Permission to check this site's backups is no longer available.")


def _read(check: BackupCheck) -> None:
    _authorized(check)
    snapshot = current_snapshot(check.server)
    if snapshot is None:
        value: dict[str, object] = {
            "version": 1,
            "identifier": check.identifier,
            "outcome": "unreadable",
            "problem": "The site has not been observed yet.",
            "points": [],
            "schedule": {},
        }
    else:
        from runtimes.catalog import architecture_of

        architecture = (
            architecture_of(snapshot.collected.architecture.value or "")
            if snapshot.collected.architecture.value
            else None
        )
        engine = _engine(check.server)
        with connect_operation(check) as shell:
            native = observation.read(shell, (check.identifier,), engine, architecture)
            from . import retention

            retention.record(
                check.server, check.identifier, retention.read_policy(shell, check.identifier)
            )
            findings = integrity.read_results(shell, check.identifier)
            if findings is not None:
                integrity.record(check.server, check.identifier, findings)
            row = _row(native, check.identifier)
            if row is None or not _enabled(row):
                value = {
                    "version": 1,
                    "identifier": check.identifier,
                    "outcome": "missing",
                    "problem": "Backups are not enabled for this site.",
                    "points": [],
                    "schedule": {},
                }
            else:
                result = run_root(shell, listing_command(check.identifier))
                text = result.stdout
                parsed = (
                    None
                    if result.exit_status or result.truncated or len(text) > MAX_BYTES
                    else parse_listing(text)
                )
                from . import schedule

                observed_schedule = schedule.read(shell, (check.identifier,))
                if observed_schedule is not None:
                    for observed_row in observed_schedule:
                        schedule.record(check.server, observed_row)
                value = (
                    {
                        "version": 1,
                        "identifier": check.identifier,
                        "outcome": "unreadable",
                        "problem": "The recovery points could not be read.",
                        "points": [],
                        "schedule": {},
                    }
                    if parsed is None
                    else {
                        "version": 1,
                        "identifier": check.identifier,
                        "outcome": "observed",
                        "problem": "",
                        "points": points(parsed),
                        "schedule": schedule.listing(
                            observed_schedule[0] if observed_schedule else None
                        ),
                    }
                )
    now = timezone.now()
    with transaction.atomic():
        if not lifecycle.succeed(check.pk, now):
            return
        BackupCheck.objects.filter(pk=check.pk).update(listing=value, checked_at=now)


def _enabled(row: dict[str, object]) -> bool:
    problems = row.get("problems")
    return (
        bool(row.get("profile"))
        and row.get("repository") is True
        and row.get("key") is True
        and not problems
    )


def _row(value: dict[str, object] | None, identifier: str) -> dict[str, object] | None:
    if value is None:
        return None
    rows = value.get("sites")
    if not isinstance(rows, list):
        return None
    item = next(
        (row for row in rows if isinstance(row, dict) and row.get("identifier") == identifier),
        None,
    )
    return item if isinstance(item, dict) else None


lifecycle.register(
    BackupCheck,
    _read,
    interrupted=INTERRUPTED_FAILURE,
    unexpected=UNEXPECTED_FAILURE,
    stale_after=STALE_AFTER,
)


def forget_checks(server: Server) -> None:
    """Delete a removed server's finished checks; active checks protect it."""
    lifecycle.forget(
        RemoteOperation.objects.filter(server=server, kind=RemoteOperation.Kind.BACKUP_CHECK)
    )


def latest_check(server: Server, identifier: str) -> BackupCheck | None:
    return (
        BackupCheck.objects.filter(
            server=server,
            identifier=identifier,
            status=RemoteOperation.Status.SUCCEEDED,
        )
        .exclude(listing={})
        .order_by("-finished_at", "-pk")
        .first()
    )


def active(server: Server, identifier: str) -> BackupCheck | None:
    return (
        BackupCheck.objects.filter(
            server=server, identifier=identifier, status__in=RemoteOperation.ACTIVE
        )
        .order_by("-queued_at", "-pk")
        .first()
    )


@recovers_first
def request_check(server: Server, user: User, identifier: str) -> BackupCheck | None:
    """Queue one explicit listing; ``None`` when another operation holds the server."""
    if not valid_identifier(identifier):
        raise ValueError("Not a supported site.")
    if not user.has_perms(READ_PERMISSIONS):
        raise OperationRefused("Your account may not check this site's backups.")
    BackupCheck.objects.filter(server=server, identifier=identifier).exclude(
        status__in=RemoteOperation.ACTIVE
    ).delete()
    try:
        return lifecycle.queue(BackupCheck, server, identifier=identifier, requested_by=user)
    except lifecycle.OperationBusy:
        return None


def stale(check: BackupCheck) -> bool:
    return check.checked_at is None or timezone.now() - check.checked_at > LISTING_FRESH
