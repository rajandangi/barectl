"""Restore a recovery point into a site (#400, #401).

The review binds the exact snapshot identifiers, target site, what is replaced, compatibility,
disk and expected downtime. Applying re-lists the point under the site's deploy lock, takes
and verifies a safety backup in the restore's own scope when the target holds data, restores
the files into private staging and admits them there, then pauses and drains the site exactly
as a full capture does. Files become a new site-owned release, the database is streamed into
the site's own engine client as ``s<id>``, and the native configuration is re-rendered from
the convention. Import, data checks and the site's readiness answer are verified separately
before the gate opens (docs/adr/0022, Phases D #358, #400 and #401).
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import secrets
import shlex
from dataclasses import dataclass
from typing import Final

from automation.bodies.source import AUTOMATION_SOURCE, without_imports
from automation.fence import checked
from bootstrap.standing import Standing
from databases import observation as database_observation
from discovery.observations import collect
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from runtimes.catalog import Architecture, architecture_of
from sites import observation as site_observation
from sites.configuration import (
    SiteSettings,
    render_caddy,
    render_laravel_caddy,
    render_maintenance,
    render_wordpress_caddy,
)
from sites.names import valid_identifier

from . import change, check, convention, observation
from .bodies import restore as restore_body

SLUG: Final = "restore_database"
LABEL: Final = "Restore"
SCOPES: Final = ("database", "files", "full")
DATABASE_STAGES: Final = (
    "preflight",
    "check",
    "safety",
    "gate",
    "drain",
    "import",
    "checks",
    "readiness",
    "open",
)
FILES_STAGES: Final = (
    "preflight",
    "check",
    "safety",
    "stage",
    "gate",
    "drain",
    "files",
    "config",
    "checks",
    "readiness",
    "open",
)
FULL_STAGES: Final = (
    "preflight",
    "check",
    "safety",
    "stage",
    "gate",
    "drain",
    "import",
    "files",
    "config",
    "checks",
    "readiness",
    "open",
)
STAGES: Final = {
    "database": DATABASE_STAGES,
    "files": FILES_STAGES,
    "full": FULL_STAGES,
}
APPLICATION_LABELS: Final = {
    "plain": "plain PHP",
    "wordpress": "WordPress",
    "laravel": "Laravel",
}
# The private state a restore replaces as a whole, beside the release (file scope, #358).
SHARED_FILES: Final = {
    "plain": (),
    "wordpress": ("private/wp-config.php",),
    "laravel": ("private/laravel.env", "private/storage", "private/cache"),
}
RELEASE: Final = restore_body.RELEASE
EXPECTED_DOWNTIME: Final = (
    "Visitors see a maintenance page while the site is replaced and checked. A small site "
    "usually takes a few minutes; a large one can take longer."
)
RESTORE_CORE: Final = without_imports(
    importlib.resources.files("backups.bodies").joinpath("restore.py").read_text(),
    (
        "automation.bodies.units",
        "sites.bodies.admission",
        "sites.bodies.common",
        "sites.bodies.site_fpm",
        "sites.names",
        "sites.serving",
        "backups.bodies.native",
        "backups.bodies.paused",
    ),
)
RESTORE_SOURCE: Final = (
    AUTOMATION_SOURCE
    + "\n"
    + site_observation.COMMON_SOURCE
    + "\n"
    + change.NATIVE_SOURCE
    + "\n"
    + change.PAUSED_SOURCE
    + "\n"
    + RESTORE_CORE
)
RESTORE_BYTES: Final = change._packed(RESTORE_SOURCE)
RESTORE_SHA256: Final = hashlib.sha256(RESTORE_BYTES).hexdigest()


@dataclass(frozen=True)
class RestoreEvidence:
    architecture: Architecture | None
    standing: Standing | None
    engine: str
    engine_label: str
    engine_version: str
    site: dict[str, object] | None
    backup: observation.ObservedBackup | None
    point: dict[str, object] | None
    snapshot: str
    files_snapshot: str
    point_parts: tuple[str, ...]
    point_version: str
    target_empty: bool
    target_problem: str
    disk_available: int
    current_sites: tuple[str, ...]
    boot_id: str
    uptime_centiseconds: int | None
    # The source site: a removed site's kept repository (#407) or a connected offsite
    # source (#408). Empty means this site's own recovery point.
    source: str = ""
    # The kind of site a removed site's point shows, when its files can prove it (#407).
    source_kind: str = ""
    # A connected source's last point listing and repository, for a cross-server restore.
    source_points: tuple[dict[str, object], ...] = ()
    source_repository: str = ""
    # The connected offsite configuration; empty for a removed site's kept onsite repository.
    source_storage: dict[str, str] | None = None


def point_listing_command(identifier: str) -> str:
    return check.listing_command(identifier)


# A removed site's kind is provable from the files its recovery point holds (#407).
KIND_MARKERS: Final = (("laravel", "private/laravel.env"), ("wordpress", "private/wp-config.php"))


def kind_command(source: str, snapshot: str, path: str) -> str:
    argv = [
        "/usr/bin/env",
        f"RESTIC_REPOSITORY={convention.repository(source)}",
        f"RESTIC_PASSWORD_FILE={convention.server_key(source)}",
        f"RESTIC_CACHE_DIR={convention.CACHE_DIR}",
        convention.RESTIC_BIN,
        "ls",
        "--json",
        "--no-lock",
        snapshot,
        "/" + path.lstrip("/"),
    ]
    return shlex.join(argv)


def point_kind(shell: RemoteShell, source: str, snapshot: str) -> str:
    """Which kind of site a removed site's files point came from, or "" when unproven."""
    if not snapshot or not source:
        return ""
    missing = 0
    for application, path in KIND_MARKERS:
        result = run_root(shell, kind_command(source, snapshot, f"/var/www/{source}/{path}"))
        if result.exit_status == 0 and not result.truncated:
            return application
        if result.exit_status == 1:
            missing += 1
            continue
        return ""
    return "plain" if missing == len(KIND_MARKERS) else ""


def header_command(identifier: str, snapshot: str, filename: str) -> str:
    argv = [
        "/usr/bin/env",
        f"RESTIC_REPOSITORY={convention.repository(identifier)}",
        f"RESTIC_PASSWORD_FILE={convention.server_key(identifier)}",
        f"RESTIC_CACHE_DIR={convention.CACHE_DIR}",
        convention.RESTIC_BIN,
        "dump",
        "--no-lock",
        snapshot,
        "/" + filename.lstrip("/"),
    ]
    return shlex.join(argv) + f" | /usr/bin/head -c {restore_body.HEADER_BYTES}"


def _point_snapshots(rows: list[dict[str, object]], point: str) -> dict[str, str]:
    """One complete snapshot per part of the reviewed point."""
    found: dict[str, str] = {}
    for row in rows:
        tags = row.get("tags")
        identifier = row.get("id")
        if (
            not isinstance(tags, list)
            or not isinstance(identifier, str)
            or convention.POINT_TAG + point not in tags
            or "complete" not in tags
        ):
            continue
        part = next(
            (
                tag.removeprefix("part:")
                for tag in tags
                if isinstance(tag, str) and tag.startswith("part:")
            ),
            "",
        )
        if part in convention.PARTS:
            found[part] = identifier
    return found


def _point_snapshot(rows: list[dict[str, object]], point: str, part: str = "database") -> str:
    return _point_snapshots(rows, point).get(part, "")


def _point_size(rows: list[dict[str, object]], snapshot: str) -> int:
    for row in rows:
        if row.get("id") != snapshot:
            continue
        summary = row.get("summary")
        if not isinstance(summary, dict):
            return 0
        value = summary.get("total_bytes_processed", summary.get("data_added", 0))
        return value if type(value) is int and value >= 0 else 0
    return 0


def _site(record: dict[str, object] | None) -> tuple[SiteSettings | None, str]:
    if record is None:
        return None, ""
    application = str(record.get("application", "plain"))
    names = record.get("names")
    if application not in change.FULL_APPLICATIONS or not isinstance(names, list):
        return None, application
    if not all(isinstance(name, str) for name in names):
        return None, application
    try:
        settings = SiteSettings(
            str(record["identifier"]),
            tuple(str(name) for name in names),
            str(record.get("runtime", "")),
            https=bool(record.get("https", True)),
            readiness=str(record.get("readiness", "/")),
        )
    except ValueError:
        return None, application
    return settings, application


def _open_file(settings: SiteSettings, application: str) -> str:
    if application == "wordpress":
        return render_wordpress_caddy(settings)
    if application == "laravel":
        return render_laravel_caddy(settings)
    return render_caddy(settings)


def _read_point(
    shell: RemoteShell, identifier: str, point: str
) -> tuple[dict[str, object] | None, dict[str, str], int]:
    result = run_root(shell, point_listing_command(identifier))
    if result.exit_status or result.truncated:
        return None, {}, 0
    parsed = check.parse_listing(result.stdout)
    if parsed is None:
        return None, {}, 0
    rows = check.points(parsed)
    found = next((row for row in rows if row.get("point") == point), None)
    snapshots = _point_snapshots(parsed, point)
    size = sum(_point_size(parsed, snapshot) for snapshot in snapshots.values())
    return found, snapshots, size


def _point_version(
    shell: RemoteShell, identifier: str, snapshot: str, filename: str, engine: str
) -> str:
    if not snapshot:
        return ""
    result = run_root(shell, header_command(identifier, snapshot, filename))
    if result.exit_status or result.truncated:
        return ""
    return restore_body.dump_version(engine, result.stdout)


def _target_empty(shell: RemoteShell, engine: str, identifier: str) -> tuple[bool, str]:
    if engine not in ("mariadb", "postgresql"):
        return False, "This server has no managed database engine."
    result = run_root(shell, restore_body.count_command(engine, identifier))
    text = result.stdout.strip()
    if result.exit_status or result.truncated or not text.isdigit():
        return False, "The site's database could not be read."
    return int(text) == 0, ""


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> RestoreEvidence:
    observed = collect(shell, sites=False)
    architecture = architecture_of(observed.architecture.value or "")
    engines = database_observation.installed_engines(observed)
    engine = engines[0].engine if len(engines) == 1 and engines[0].managed else ""
    label = engines[0].label if len(engines) == 1 else ""
    version = engines[0].version if len(engines) == 1 else ""
    record, current_sites, boot_id, uptime = change._site_record(shell, inputs.identifier)
    listing = shell.run(change.ALL_SITES_READ)
    if listing.exit_status == 0 and not listing.truncated:
        current_sites = tuple(listing.stdout.splitlines())
    backup: observation.ObservedBackup | None = None
    value = observation.read(shell, (inputs.identifier,), engine, architecture)
    if value is not None:
        backup = change._observed(value, inputs.identifier)
    source = inputs.source
    source_points: tuple[dict[str, object], ...] = ()
    source_repository = ""
    source_storage: dict[str, str] | None = None
    source_kind = ""
    evidence_source = ""
    offsite = observation.offsite_of(value)
    config = (
        {
            "provider": offsite.provider,
            "bucket": offsite.bucket,
            "region": offsite.region,
            "endpoint": offsite.endpoint,
            "prefix": offsite.prefix,
            "prune": "yes" if offsite.prune else "no",
        }
        if offsite is not None and offsite.configured
        else None
    )
    connected = (
        next((row for row in offsite.sources if row.identifier == source), None)
        if source and offsite is not None
        else None
    )
    if source and connected is not None:
        # A connected offsite source on another server (#408).
        source_points = connected.points()
        if config:
            try:
                source_repository = convention.offsite_repository(config, source)
            except ValueError:
                source_repository = ""
            source_storage = config
        point = next((row for row in source_points if row.get("point") == inputs.point), None)
        raw_snapshots = point.get("snapshots") if isinstance(point, dict) else None
        snapshots = (
            {str(part): str(identifier) for part, identifier in raw_snapshots.items()}
            if isinstance(raw_snapshots, dict)
            else {}
        )
        size = _point_bytes(point)
        point_version = ""
        source_kind = str(point.get("application", "")) if isinstance(point, dict) else ""
        evidence_source = source
    else:
        # This site's own point, or a removed site's kept repository on this server (#407).
        taken_from = source or inputs.identifier
        point, snapshots, size = _read_point(shell, taken_from, inputs.point)
        if point is not None:
            point = {**point, "size": size}
        point_version = _point_version(
            shell,
            taken_from,
            snapshots.get("database", ""),
            convention.dump_filename(taken_from),
            engine,
        )
        if taken_from == inputs.identifier:
            source_kind = str(record.get("application", "plain")) if record is not None else ""
        else:
            source_kind = point_kind(shell, taken_from, snapshots.get("files", ""))
            evidence_source = taken_from
    empty, target_problem = _target_empty(shell, engine, inputs.identifier)
    disk = observed.filesystem.value.avail_bytes if observed.filesystem.value else 0
    return RestoreEvidence(
        architecture,
        observed.standing.standing if observed.standing else None,
        engine,
        label,
        version,
        record,
        backup,
        point,
        snapshots.get("database", ""),
        snapshots.get("files", ""),
        tuple(sorted(snapshots)),
        point_version,
        empty,
        target_problem,
        disk,
        current_sites,
        boot_id,
        uptime,
        evidence_source,
        source_kind,
        source_points,
        source_repository,
        source_storage,
    )


def _scope(inputs: PreparationInputs) -> str:
    return inputs.scope or "database"


def _refusals(  # noqa: C901 - one closed set of refusal checks
    evidence: RestoreEvidence, settings: SiteSettings | None, scope: str, application: str
) -> list[str]:
    refusals: list[str] = []
    connected = bool(evidence.source_storage)
    if evidence.source and not connected:
        if evidence.source in evidence.current_sites:
            refusals.append(
                f"Site {evidence.source} still exists, so restore from its own Backups section "
                "instead of the kept backups of a removed site."
            )
        if scope == "database":
            refusals.append(
                "A removed site's database-only point cannot prove which kind of site it came "
                "from. Restore a full recovery point instead."
            )
        elif not evidence.source_kind:
            refusals.append(
                "Barectl could not read the removed site's files, so it cannot confirm which "
                "kind of site the recovery point came from."
            )
        elif evidence.source_kind != application:
            refusals.append(
                "That recovery point was taken from a different kind of site, so it cannot be "
                "restored into this one."
            )
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before restoring a site.")
    if settings is None or evidence.site is None:
        refusals.append("The site's configuration could not be read.")
    elif str(evidence.site.get("state", "")) != "complete":
        refusals.append("The site is not complete, so it cannot be restored.")
    if evidence.architecture is None:
        refusals.append("The server's architecture is not supported.")
    if evidence.backup is None or not evidence.backup.enabled:
        refusals.append("Enable backups for this site first.")
    if connected and not evidence.source_repository:
        refusals.append("That connected source storage is not available on this server.")
    if connected and not evidence.source_points:
        refusals.append("Connect the existing backup storage again to read its recovery points.")
    if evidence.point is None:
        refusals.append(
            "That recovery point is not in the connected source's last listing."
            if connected
            else "That recovery point is no longer listed. Check backups and choose again."
        )
    elif evidence.point.get("complete") is not True and scope == "database":
        refusals.append("That recovery point has no complete database copy to restore.")
    elif evidence.point.get("complete") is not True and scope == "files":
        refusals.append("That recovery point has no complete files copy to restore.")
    elif evidence.point.get("complete") is not True:
        refusals.append("That recovery point is not complete, so it cannot be restored.")
    parts = set(evidence.point_parts)
    if scope in ("database", "full") and evidence.point is not None:
        if "database" in parts:
            if not evidence.engine:
                refusals.append("This server has no managed database engine to restore into.")
            if not evidence.backup or not evidence.backup.database:
                refusals.append(
                    evidence.backup.database_problem
                    if evidence.backup is not None
                    else "This site has no site database."
                )
            if not evidence.point_version and not connected:
                refusals.append("The recovery point's database copy could not be read.")
        elif scope == "database":
            refusals.append("That recovery point has no complete database copy to restore.")
    if scope in ("files", "full") and evidence.point is not None and "files" not in parts:
        refusals.append("That recovery point has no complete files copy to restore.")
    if scope == "database" and evidence.target_problem:
        refusals.append(evidence.target_problem)
    if (
        scope in ("database", "full")
        and evidence.engine
        and evidence.point_version
        and not connected
    ):
        current = restore_body.engine_major(evidence.engine, evidence.engine_version)
        found = restore_body.engine_major(evidence.engine, evidence.point_version)
        if current and found and current != found:
            refusals.append(
                f"That recovery point was made by {evidence.engine_label} {found}, but this "
                f"site now uses {evidence.engine_label} {current}. Restore needs the same "
                "database version."
            )
    if connected and evidence.point is not None:
        application = str((evidence.site or {}).get("application", ""))
        source_application = evidence.point.get("application")
        if source_application not in change.FULL_APPLICATIONS:
            refusals.append(
                "The source recovery point does not record its application kind, so Barectl "
                "cannot prove it matches this site. Capture a new point on the source server."
            )
        elif source_application != application:
            source_label = APPLICATION_LABELS.get(str(source_application), str(source_application))
            target_label = APPLICATION_LABELS.get(application, application)
            refusals.append(
                f"That recovery point is a {source_label} site, but this site is "
                f"{target_label}. Restore needs the same kind of site."
            )
    size = _point_bytes(evidence.point)
    if evidence.disk_available and evidence.disk_available < convention.HEADROOM_BYTES + size:
        refusals.append("The server lacks the free space a restore keeps in reserve.")
    return refusals


def _point_bytes(point: dict[str, object] | None) -> int:
    if point is None:
        return 0
    value = point.get("size")
    return value if type(value) is int and value >= 0 else 0


def _time_label(value: object) -> str:
    if not isinstance(value, str):
        return "time not recorded"
    try:
        from datetime import datetime

        from django.utils import timezone

        parsed = datetime.fromisoformat(value)
        return timezone.localtime(parsed).strftime("%-d %b %Y, %H:%M")
    except ValueError:
        return "time not recorded"


def _safety_scope(scope: str, parts: set[str]) -> str:
    if scope == "database":
        return "database"
    if scope == "full" and "database" in parts:
        return "full"
    return "files"


def _safety_tags(
    identifier: str, scope: str, point: str, application: str = ""
) -> dict[str, list[str]]:
    """The reviewed safety capture's tags, one entry per part it writes."""
    if scope == "database":
        return {
            "database": list(
                convention.tags(
                    identifier,
                    "database",
                    origin="safety",
                    live=True,
                    point=point,
                    application=application,
                )
            )
        }
    if scope == "files":
        return {
            "files": list(
                convention.tags(
                    identifier,
                    "files",
                    origin="safety",
                    live=False,
                    point=point,
                    application=application,
                )
            )
        }
    return {
        "database": list(
            convention.tags(
                identifier,
                "full",
                part="database",
                origin="safety",
                live=False,
                point=point,
                application=application,
            )
        ),
        "files": list(
            convention.tags(
                identifier,
                "full",
                part="files",
                origin="safety",
                live=False,
                point=point,
                application=application,
            )
        ),
    }


def _scope_label(scope: str) -> str:
    return {"database": "Database only", "files": "Files only", "full": "Full site"}[scope]


def _safety_label(scope: str) -> str:
    return {"database": "database-only", "files": "files-only", "full": "full site"}[scope]


def _replacement(scope: str, has_database: bool) -> str:
    if scope == "database":
        return (
            "This site's database. Any table or view the recovery point does not contain is "
            "removed. Other sites' databases are not touched."
        )
    if scope == "files":
        return (
            "This site's application files. The file the site serves now becomes a retained "
            "release and is not deleted."
        )
    if has_database:
        return (
            "This site's application files and its database. The file the site serves now "
            "becomes a retained release; any table or view the point does not contain is "
            "removed. Other sites' databases are not touched."
        )
    return (
        "This site's application files. The point has no database copy, so the database stays "
        "as it is now. The file the site serves now becomes a retained release."
    )


def _details(
    evidence: RestoreEvidence,
    inputs: PreparationInputs,
    settings: SiteSettings | None,
    application: str,
    scope: str,
    names: tuple[str, ...],
    point: dict[str, object],
    safety_scope: str,
    skipped: bool,
    needed: int,
    size: int,
) -> list[dict[str, str]]:
    parts = set(evidence.point_parts)
    point_major = restore_body.engine_major(evidence.engine, evidence.point_version)
    current_major = restore_body.engine_major(evidence.engine, evidence.engine_version)
    point_scope = {
        "database": "database-only",
        "files": "files-only",
        "full": "full site",
    }.get(str(point.get("scope", "")), "database-only")
    if evidence.source_storage:
        location = f"From connected backup storage, source site {evidence.source}."
    elif evidence.source:
        location = f"From the kept backups of removed site {evidence.source}."
    else:
        location = "Saved on this server."
    rows = [
        {
            "label": "Recovery point",
            "value": (
                f"{_scope_label(scope)} from a {point_scope} recovery point taken "
                f"{_time_label(point.get('time'))}. {location}"
            ),
        },
        {
            "label": "Target site",
            "value": f"{inputs.identifier} ({', '.join(names)})" if names else inputs.identifier,
        },
        {"label": "Will be replaced", "value": _replacement(scope, "database" in parts)},
        {
            "label": "Compatibility",
            "value": (
                (
                    f"Same site kind ({APPLICATION_LABELS.get(application, application)}) and "
                    f"{evidence.engine_label} {point_major or 'unknown'} as this site "
                    f"({evidence.engine_label} {current_major or 'unknown'})."
                )
                if scope in ("database", "full") and evidence.engine and "database" in parts
                else f"Same site kind ({APPLICATION_LABELS.get(application, application)})."
            )
            + (
                " Barectl checks the source's database version when it opens the repository, "
                "before it changes the site."
                if evidence.source_storage and scope in ("database", "full")
                else ""
            ),
        },
        {
            "label": "Disk needed",
            "value": (
                f"At least {needed // (1024 * 1024)} MiB free before it starts. The recovery "
                f"point holds about {size // (1024 * 1024)} MiB."
            ),
        },
        {"label": "Expected downtime", "value": EXPECTED_DOWNTIME},
        {
            "label": "Safety backup",
            "value": (
                "The site's database is empty, so no safety backup is taken."
                if skipped
                else f"Barectl takes and checks a {_safety_label(safety_scope)} safety "
                "backup first."
            ),
        },
        {
            "label": "Server configuration",
            "value": (
                "The web server, proxy and PHP configuration are re-created from Barectl's "
                "convention, never from the backup. Restore never runs application code, "
                "migrations, key generation or dependency downloads."
            ),
        },
    ]
    if evidence.source and not evidence.source_storage:
        rows.insert(
            1,
            {
                "label": "Source",
                "value": (
                    f"The kept backups of removed site {evidence.source}. Barectl keeps that "
                    "repository and restores from it into this site; the removed site is not "
                    "recreated and nothing of it is served."
                ),
            },
        )
    if scope == "files":
        rows.insert(
            3,
            {
                "label": "Database",
                "value": (
                    "The database is left as it is now, so the files and the database may come "
                    "from different points."
                ),
            },
        )
    if application == "wordpress":
        rows.insert(
            3,
            {
                "label": "Private configuration",
                "value": (
                    "The site's private configuration is replaced from the recovery point, and "
                    "the target's database settings are kept because this site's database is "
                    f"always {convention.database_name(str(inputs.identifier))}."
                ),
            },
        )
    if application == "laravel":
        rows.insert(
            3,
            {
                "label": "Shared state",
                "value": (
                    "Laravel's .env, storage and bootstrap cache are replaced as a whole from "
                    "the recovery point, never overlaid on what the site holds now."
                ),
            },
        )
    if point.get("live") is True:
        rows.insert(
            3,
            {
                "label": "Captured while the site ran",
                "value": (
                    "This recovery point was captured live, so its files and database may "
                    "differ by the capture window."
                ),
            },
        )
    if evidence.source_storage and evidence.source != inputs.identifier:
        rows.insert(
            3,
            {
                "label": "Source site and domain",
                "value": (
                    f"The recovery point came from source site {evidence.source}, which may "
                    f"have served a different domain. This target keeps its own domain "
                    f"({', '.join(names)}). Barectl never rewrites application data, so check "
                    "the application's own domain setting after the restore."
                ),
            },
        )
    return rows


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, RestoreEvidence):
        raise ValueError("A restore needs native evidence.")
    scope = _scope(inputs)
    if scope not in SCOPES:
        return ReviewDraft(
            kind=SLUG,
            intent="Restore a site.",
            refusals=("This restore choice is not supported.",),
            document={"version": 1},
        )
    settings, application = _site(evidence.site)
    refusals = _refusals(evidence, settings, scope, application)
    point = evidence.point or {}
    parts = set(evidence.point_parts)
    point_major = restore_body.engine_major(evidence.engine, evidence.point_version)
    current_major = restore_body.engine_major(evidence.engine, evidence.engine_version)
    size = _point_bytes(evidence.point)
    needed = convention.HEADROOM_BYTES + size
    names = settings.names if settings is not None else ()
    primary = names[0] if names else inputs.identifier
    at = change.schedule_time()
    skipped = scope == "database" and evidence.target_empty
    safety_scope = "database" if skipped else _safety_scope(scope, parts)
    safety_point = "" if skipped else secrets.token_hex(8)
    safety_at = "" if skipped else at
    safety_tags = (
        {} if skipped else _safety_tags(inputs.identifier, safety_scope, safety_point, application)
    )
    release = f"restore-{inputs.point}-{secrets.token_hex(4)}"
    shared = list(SHARED_FILES[application])
    files = [
        f"/var/www/{inputs.identifier}/current",
        *(f"/var/www/{inputs.identifier}/{path}" for path in shared),
    ]
    snapshot = evidence.snapshot if scope != "files" else ""
    files_snapshot = evidence.files_snapshot if scope in ("files", "full") else ""
    details = _details(
        evidence,
        inputs,
        settings,
        application,
        scope,
        names,
        point,
        safety_scope,
        skipped,
        needed,
        size,
    )
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": RESTORE_SHA256,
        "identifier": inputs.identifier,
        "application": application,
        "names": list(names),
        "runtime": settings.runtime if settings is not None else "",
        "https": bool(settings.https) if settings is not None else True,
        "readiness": settings.readiness if settings is not None else "/",
        "engine": evidence.engine if evidence.engine in ("mariadb", "postgresql") else "",
        "engine_label": evidence.engine_label,
        "engine_version": evidence.engine_version,
        "engine_major": current_major,
        "point_engine_version": evidence.point_version,
        "point_major": point_major,
        "source": evidence.source,
        "source_kind": evidence.source_kind,
        "repository": convention.repository(
            inputs.identifier if evidence.source_storage else (evidence.source or inputs.identifier)
        ),
        "server_key": convention.server_key(
            inputs.identifier if evidence.source_storage else (evidence.source or inputs.identifier)
        ),
        "safety_repository": convention.repository(inputs.identifier),
        "safety_key": convention.server_key(inputs.identifier),
        "point": inputs.point,
        "scope": scope,
        "point_scope": str(point.get("scope", "")),
        "snapshot": snapshot,
        "files_snapshot": files_snapshot,
        "source_application": str(point.get("application", "")),
        "source_repository": evidence.source_repository,
        "source_storage": evidence.source_storage or {},
        "source_snapshots": {
            "database": snapshot,
            "files": files_snapshot,
        },
        "secret_label": "Recovery passphrase for the connected source repository",
        "filename": convention.dump_filename(
            inputs.identifier if evidence.source_storage else (evidence.source or inputs.identifier)
        ),
        "point_time": str(point.get("time", "")),
        "point_live": point.get("live") is True,
        "point_size": size,
        "release": release,
        "shared": shared,
        "files": files,
        "caddy": _open_file(settings, application) if settings is not None else "",
        "gate": render_maintenance(settings) if settings is not None else "",
        "target_empty": evidence.target_empty if scope == "database" else False,
        "safety_scope": safety_scope,
        "safety_point": safety_point,
        "safety_at": safety_at,
        "safety_restic_time": change.restic_time(safety_at) if safety_at else "",
        "safety_tags": safety_tags,
        "dump": convention.dump_argv(inputs.identifier, evidence.engine)
        if scope != "files" and evidence.engine in ("mariadb", "postgresql") and "database" in parts
        else [],
        "origin": "",
        "at": at,
        "restic_time": change.restic_time(at),
        "stages": list(STAGES[scope]),
        "details": details,
        "confirmation": primary,
        "confirmation_label": f"Type {primary} to confirm this restore.",
        "note": (
            "If the restore stops after pausing the site, the site stays paused until you "
            "reopen it. Barectl never retries a restore automatically."
        ),
    }
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals:
        replaced = {
            "database": "the database",
            "files": "the files",
            "full": "the files" + (" and database" if "database" in parts else ""),
        }[scope]
        effects = (
            DeclaredEffect(
                Scope.SITE,
                (
                    f"Replace {replaced} of {inputs.identifier} with the recovery point taken "
                    f"{_time_label(point.get('time'))}."
                ),
                (inputs.identifier,),
                destroys_data=True,
            ),
            *(
                (
                    DeclaredEffect(
                        Scope.SHARED,
                        (
                            "Reload Caddy for every site when the maintenance page goes up and "
                            "comes down; other sites keep serving."
                        ),
                        evidence.current_sites,
                    ),
                )
                if any(site != inputs.identifier for site in evidence.current_sites)
                else ()
            ),
        )
    return ReviewDraft(
        kind=SLUG,
        intent=f"Restore site {inputs.identifier}.",
        effects=effects,
        stages=STAGES[scope] if effects else (),
        postconditions=(
            (
                "The recovery point's files are the site's current release and its restored "
                "database holds the point's data."
            )
            if scope == "full" and "database" in parts
            else (
                "The recovery point's files are the site's current release."
                if scope in ("files", "full")
                else "The recovery point's data is in the site's own database."
            ),
            "The site's permissions and native configuration follow the convention.",
            (
                "The import finished, the data checks passed and the site answered its "
                "readiness check."
            ),
            "The site serves visitors again and its background work is back.",
        )
        if effects
        else (),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        sites_read=change.ALL_SITES_READ if effects else "",
        current_sites=evidence.current_sites if effects else None,
        document=document,
        writes_secrets=bool(evidence.source_storage),
    )


def _base_document(document: dict[str, object]) -> None:
    if document.get("version") != 1 or document.get("body_sha256") != RESTORE_SHA256:
        raise ValueError("Unsupported restore review.")
    identifier = document.get("identifier")
    application = document.get("application")
    names = document.get("names")
    point = document.get("point")
    source = str(document.get("source") or identifier)
    snapshot = document.get("snapshot")
    files_snapshot = document.get("files_snapshot")
    if (
        not isinstance(identifier, str)
        or application not in change.FULL_APPLICATIONS
        or not isinstance(names, list)
        or not all(isinstance(name, str) for name in names)
        or not isinstance(point, str)
        or convention.POINT.fullmatch(point) is None
        or not valid_identifier(source)
        or not isinstance(snapshot, str)
        or not isinstance(files_snapshot, str)
        or (snapshot and restore_body.SNAPSHOT.fullmatch(snapshot) is None)
        or (files_snapshot and restore_body.SNAPSHOT.fullmatch(files_snapshot) is None)
    ):
        raise ValueError("The restore review is not a supported site.")
    settings = SiteSettings(
        identifier,
        tuple(str(name) for name in names),
        str(document.get("runtime", "")),
        https=document.get("https", True) is not False,
        readiness=str(document.get("readiness", "/")),
    )
    if _open_file(settings, str(application)) != document.get("caddy"):
        raise ValueError("The restore review changed the site's configuration.")
    if render_maintenance(settings) != document.get("gate"):
        raise ValueError("The restore review changed the maintenance page.")


def _restore_document(document: dict[str, object]) -> None:  # noqa: C901 - one closed document
    _base_document(document)
    identifier = str(document["identifier"])
    engine = document.get("engine")
    scope = document.get("scope")
    target_empty = document.get("target_empty")
    tags = document.get("safety_tags")
    safety_scope = document.get("safety_scope")
    safety_point = document.get("safety_point")
    safety_at = document.get("safety_at")
    release = document.get("release")
    shared = document.get("shared")
    files = document.get("files")
    snapshot = document.get("snapshot")
    files_snapshot = document.get("files_snapshot")
    parts = set()
    if snapshot:
        parts.add("database")
    if files_snapshot:
        parts.add("files")
    source = document.get("source")
    source_storage = document.get("source_storage")
    source_snapshots = document.get("source_snapshots")
    source_repository = document.get("source_repository")
    if (
        not isinstance(source, str)
        or (source and convention.SITE_IDENTIFIER.fullmatch(source) is None)
        or not isinstance(source_storage, dict)
        or not isinstance(source_repository, str)
        or not isinstance(source_snapshots, dict)
    ):
        raise ValueError("The restore review has no supported source.")
    connected = bool(source_storage)
    if connected:
        if not source:
            raise ValueError("A connected source names its site.")
        values = {str(name): str(value) for name, value in source_storage.items()}
        convention.read_config(convention.render_config(values))
        if source_repository != convention.offsite_repository(values, source):
            raise ValueError("The restore review changed its connected source repository.")
        if document.get("source_application") != document.get("application"):
            raise ValueError("The restore review changed the source application.")
        if source_snapshots != {"database": snapshot, "files": files_snapshot}:
            raise ValueError("The restore review changed the source snapshots.")
    elif source_repository or source_snapshots != {
        "database": snapshot,
        "files": files_snapshot,
    }:
        raise ValueError("A same-server restore names no connected source.")
    expected = identifier if connected else str(source or identifier)
    if (
        engine not in ("", "mariadb", "postgresql")
        or scope not in SCOPES
        or safety_scope not in SCOPES
        or document.get("point_scope") not in convention.SCOPES
        or document.get("repository") != convention.repository(expected)
        or document.get("server_key") != convention.server_key(expected)
        or (document.get("safety_repository") or convention.repository(identifier))
        != convention.repository(identifier)
        or (document.get("safety_key") or convention.server_key(identifier))
        != convention.server_key(identifier)
        or document.get("filename") != convention.dump_filename(expected)
        or type(target_empty) is not bool
        or type(document.get("point_size")) is not int
        or not isinstance(release, str)
        or RELEASE.fullmatch(release) is None
        or not isinstance(shared, list)
        or not all(isinstance(path, str) for path in shared)
        or not isinstance(files, list)
        or not all(isinstance(path, str) for path in files)
        or not isinstance(tags, dict)
    ):
        raise ValueError("The restore review is not a supported restore.")
    if scope == "database" and "database" not in parts:
        raise ValueError("The restore review has no database copy.")
    if scope in ("files", "full") and "files" not in parts:
        raise ValueError("The restore review has no files copy.")
    if scope == "files" and "database" in parts:
        raise ValueError("A files-only restore never restores the database.")
    if document.get("shared") != list(SHARED_FILES[str(document["application"])]):
        raise ValueError("The restore review changed the site's private files.")
    if files != [
        f"/var/www/{identifier}/current",
        *(f"/var/www/{identifier}/{path}" for path in SHARED_FILES[str(document["application"])]),
    ]:
        raise ValueError("The restore review changed the file scope.")
    dump = document.get("dump")
    if "database" in parts:
        if engine not in ("mariadb", "postgresql") or dump != convention.dump_argv(
            identifier, str(engine)
        ):
            raise ValueError("The restore dump command is not the reviewed one.")
        if document.get("point_major") != restore_body.engine_major(
            str(engine), str(document.get("point_engine_version", ""))
        ) or document.get("engine_major") != restore_body.engine_major(
            str(engine), str(document.get("engine_version", ""))
        ):
            raise ValueError("The restore review changed its database version.")
    elif dump != []:
        raise ValueError("A files-only restore has no database command.")
    if target_empty and scope != "database":
        raise ValueError("Only a database restore can skip its safety backup.")
    if not tags:
        if scope != "database" or not target_empty:
            raise ValueError("The restore review has no safety backup.")
        if safety_scope != "database" or safety_point != "" or safety_at != "":
            raise ValueError("An empty database never takes a safety backup.")
    else:
        if (
            not isinstance(safety_point, str)
            or convention.POINT.fullmatch(safety_point) is None
            or not isinstance(safety_at, str)
            or change.restic_time(safety_at) != document.get("safety_restic_time")
            or tags
            != _safety_tags(
                identifier,
                str(safety_scope),
                safety_point,
                str(document.get("application", "")),
            )
        ):
            raise ValueError("The restore safety backup is not the reviewed one.")
    if document.get("stages") != list(STAGES[str(scope)]):
        raise ValueError("The restore review stages are not the reviewed ones.")


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    _restore_document(document)
    value = {
        key: document[key]
        for key in (
            "identifier",
            "application",
            "names",
            "runtime",
            "https",
            "readiness",
            "engine",
            "engine_major",
            "source",
            "repository",
            "server_key",
            "safety_repository",
            "safety_key",
            "point",
            "scope",
            "snapshot",
            "files_snapshot",
            "source",
            "source_application",
            "source_repository",
            "source_storage",
            "filename",
            "release",
            "shared",
            "files",
            "target_empty",
            "safety_scope",
            "safety_point",
            "safety_at",
            "safety_restic_time",
            "safety_tags",
            "dump",
            "origin",
            "at",
            "restic_time",
            "caddy",
            "gate",
            "point_size",
        )
    }
    value["automation_fence"] = checked(document)
    if document.get("source_storage"):
        if not context.secret_path:
            raise ValueError("A cross-server restore needs the source repository passphrase.")
        value["secret_path"] = context.secret_path
    encoded = base64.b64encode(gzip.compress(json.dumps(value).encode(), mtime=0)).decode()
    return NativeBody(RESTORE_BYTES, (encoded,))


def verify(shell: RemoteShell, review: ChangeReview) -> bool | None:
    _restore_document(review.document)
    listing = site_observation.read(shell, "observed", "", protections=False)
    if listing is None:
        return None
    record = next(
        (site for site in listing["sites"] if site["identifier"] == review.document["identifier"]),
        None,
    )
    return bool(
        record is not None
        and record.get("state") == "complete"
        and record.get("serving_form") != "maintenance"
    )


RESTORE: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    refresh_discovery=True,
    input_shape=InputShape.SITE_RECOVERY_POINT,
)
