"""Restore one database recovery point into a site's own database (#400).

The review binds the exact snapshot identifiers, target site, overwrite effect,
compatibility, disk and expected downtime. Applying re-lists the point under the site's
deploy lock, takes and verifies a database-only safety backup when the target holds data,
pauses and drains the site exactly as a full capture does, streams ``restic dump`` into the
site's own engine client as ``s<id>``, and verifies the import, the data checks and the
site's readiness answer before lifting the gate (docs/adr/0022, Phases D #358 and #400).
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

from . import change, check, convention, observation
from .bodies import restore as restore_body

SLUG: Final = "restore_database"
LABEL: Final = "Restore database only"
STAGES: Final = (
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
APPLICATION_LABELS: Final = {
    "plain": "plain PHP",
    "wordpress": "WordPress",
    "laravel": "Laravel",
}
EXPECTED_DOWNTIME: Final = (
    "Visitors see a maintenance page while the database is replaced and checked. A small "
    "site usually takes a few minutes; a large database can take longer."
)
RESTORE_CORE: Final = without_imports(
    importlib.resources.files("backups.bodies").joinpath("restore.py").read_text(),
    (
        "automation.bodies.units",
        "sites.bodies.admission",
        "sites.bodies.common",
        "sites.bodies.site_fpm",
        "sites.names",
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
    point_version: str
    target_empty: bool
    target_problem: str
    disk_available: int
    current_sites: tuple[str, ...]
    boot_id: str
    uptime_centiseconds: int | None


def point_listing_command(identifier: str) -> str:
    return check.listing_command(identifier)


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


def _point_snapshot(rows: list[dict[str, object]], point: str, part: str = "database") -> str:
    for row in rows:
        tags = row.get("tags")
        identifier = row.get("id")
        if (
            isinstance(tags, list)
            and isinstance(identifier, str)
            and convention.POINT_TAG + point in tags
            and f"part:{part}" in tags
            and "complete" in tags
        ):
            return identifier
    return ""


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
) -> tuple[dict[str, object] | None, str, int]:
    result = run_root(shell, point_listing_command(identifier))
    if result.exit_status or result.truncated:
        return None, "", 0
    parsed = check.parse_listing(result.stdout)
    if parsed is None:
        return None, "", 0
    rows = check.points(parsed)
    found = next((row for row in rows if row.get("point") == point), None)
    snapshot = _point_snapshot(parsed, point)
    return found, snapshot, _point_size(parsed, snapshot)


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
    point, snapshot, size = _read_point(shell, inputs.identifier, inputs.point)
    if point is not None:
        point = {**point, "size": size}
    point_version = _point_version(
        shell,
        inputs.identifier,
        snapshot,
        convention.dump_filename(inputs.identifier),
        engine,
    )
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
        snapshot,
        point_version,
        empty,
        target_problem,
        disk,
        current_sites,
        boot_id,
        uptime,
    )


def _refusals(  # noqa: C901 - one closed set of refusal checks
    evidence: RestoreEvidence, settings: SiteSettings | None
) -> list[str]:
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before restoring a site.")
    if settings is None or evidence.site is None:
        refusals.append("The site's configuration could not be read.")
    elif str(evidence.site.get("state", "")) != "complete":
        refusals.append("The site is not complete, so its database cannot be restored.")
    if evidence.architecture is None:
        refusals.append("The server's architecture is not supported.")
    if evidence.backup is None or not evidence.backup.enabled:
        refusals.append("Enable backups for this site first.")
    if not evidence.engine:
        refusals.append("This server has no managed database engine to restore into.")
    if not evidence.backup or not evidence.backup.database:
        refusals.append(
            evidence.backup.database_problem
            if evidence.backup is not None
            else "This site has no site database."
        )
    if evidence.point is None:
        refusals.append("That recovery point is no longer listed. Check backups and choose again.")
    elif evidence.point.get("complete") is not True or "database" not in str(
        evidence.point.get("parts")
    ):
        refusals.append("That recovery point has no complete database copy to restore.")
    if evidence.point is not None and not evidence.point_version:
        refusals.append("The recovery point's database copy could not be read.")
    if evidence.target_problem:
        refusals.append(evidence.target_problem)
    if evidence.engine and evidence.point_version:
        current = restore_body.engine_major(evidence.engine, evidence.engine_version)
        found = restore_body.engine_major(evidence.engine, evidence.point_version)
        if current and found and current != found:
            refusals.append(
                f"That recovery point was made by {evidence.engine_label} {found}, but this "
                f"site now uses {evidence.engine_label} {current}. Restore needs the same "
                "database version."
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


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, RestoreEvidence):
        raise ValueError("A restore needs native evidence.")
    settings, application = _site(evidence.site)
    refusals = _refusals(evidence, settings)
    point = evidence.point or {}
    point_major = restore_body.engine_major(evidence.engine, evidence.point_version)
    current_major = restore_body.engine_major(evidence.engine, evidence.engine_version)
    size = _point_bytes(evidence.point)
    needed = convention.HEADROOM_BYTES + size
    names = settings.names if settings is not None else ()
    primary = names[0] if names else inputs.identifier
    at = change.schedule_time()
    safety_point = "" if evidence.target_empty else secrets.token_hex(8)
    safety_at = "" if evidence.target_empty else at
    safety_tags = (
        []
        if evidence.target_empty
        else list(
            convention.tags(
                inputs.identifier,
                "database",
                origin="safety",
                live=True,
                point=safety_point,
            )
        )
    )
    scope_label = "Database only" if point.get("scope") == "database" else "Full site"
    details = [
        {
            "label": "Recovery point",
            "value": (
                f"{scope_label}, taken {_time_label(point.get('time'))}. Saved on this server."
                if evidence.point is not None
                else "Not found."
            ),
        },
        {
            "label": "Target site",
            "value": f"{inputs.identifier} ({', '.join(names)})" if names else inputs.identifier,
        },
        {
            "label": "Will be replaced",
            "value": (
                "This site's database. Any table or view the recovery point does not contain "
                "is removed. Other sites' databases are not touched."
            ),
        },
        {
            "label": "Compatibility",
            "value": (
                f"Same site kind ({APPLICATION_LABELS.get(application, application)}) and "
                f"{evidence.engine_label} {point_major or 'unknown'} as this site "
                f"({evidence.engine_label} {current_major or 'unknown'})."
                if evidence.engine
                else "No managed database engine."
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
                if evidence.target_empty
                else "Barectl takes and checks a database-only safety backup first."
            ),
        },
    ]
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
        "repository": convention.repository(inputs.identifier),
        "server_key": convention.server_key(inputs.identifier),
        "point": inputs.point,
        "snapshot": evidence.snapshot,
        "filename": convention.dump_filename(inputs.identifier),
        "point_time": str(point.get("time", "")),
        "point_scope": str(point.get("scope", "")),
        "point_live": point.get("live") is True,
        "point_size": size,
        "caddy": _open_file(settings, application) if settings is not None else "",
        "gate": render_maintenance(settings) if settings is not None else "",
        "target_empty": evidence.target_empty,
        "safety_point": safety_point,
        "safety_at": safety_at,
        "safety_restic_time": change.restic_time(safety_at) if safety_at else "",
        "safety_tags": safety_tags,
        "dump": convention.dump_argv(inputs.identifier, evidence.engine)
        if evidence.engine in ("mariadb", "postgresql")
        else [],
        "scope": "database",
        "origin": "",
        "at": at,
        "restic_time": change.restic_time(at),
        "stages": list(STAGES),
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
        effects = (
            DeclaredEffect(
                Scope.SITE,
                (
                    f"Replace the database of {inputs.identifier} with the recovery point taken "
                    f"{_time_label(point.get('time'))}. Any table or view it does not contain is "
                    "removed; other sites' databases are unchanged."
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
        intent=f"Restore the database of site {inputs.identifier}.",
        effects=effects,
        stages=STAGES if effects else (),
        postconditions=(
            "The recovery point's data is in the site's own database.",
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
    )


def _base_document(document: dict[str, object]) -> None:
    if document.get("version") != 1 or document.get("body_sha256") != RESTORE_SHA256:
        raise ValueError("Unsupported restore review.")
    identifier = document.get("identifier")
    application = document.get("application")
    names = document.get("names")
    point = document.get("point")
    snapshot = document.get("snapshot")
    if (
        not isinstance(identifier, str)
        or application not in change.FULL_APPLICATIONS
        or not isinstance(names, list)
        or not all(isinstance(name, str) for name in names)
        or not isinstance(point, str)
        or convention.POINT.fullmatch(point) is None
        or not isinstance(snapshot, str)
        or restore_body.SNAPSHOT.fullmatch(snapshot) is None
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


def _restore_document(document: dict[str, object]) -> None:
    _base_document(document)
    identifier = str(document["identifier"])
    engine = document.get("engine")
    target_empty = document.get("target_empty")
    tags = document.get("safety_tags")
    safety_point = document.get("safety_point")
    safety_at = document.get("safety_at")
    if (
        engine not in ("mariadb", "postgresql")
        or document.get("repository") != convention.repository(identifier)
        or document.get("server_key") != convention.server_key(identifier)
        or document.get("filename") != convention.dump_filename(identifier)
        or document.get("scope") != "database"
        or type(target_empty) is not bool
        or type(document.get("point_size")) is not int
        or not isinstance(tags, list)
        or not all(isinstance(tag, str) for tag in tags)
    ):
        raise ValueError("The restore review is not a supported restore.")
    if document.get("point_major") != restore_body.engine_major(
        str(engine), str(document.get("point_engine_version", ""))
    ) or document.get("engine_major") != restore_body.engine_major(
        str(engine), str(document.get("engine_version", ""))
    ):
        raise ValueError("The restore review changed its database version.")
    if document.get("dump") != convention.dump_argv(identifier, str(engine)):
        raise ValueError("The restore dump command is not the reviewed one.")
    if target_empty:
        if tags or safety_point != "" or safety_at != "":
            raise ValueError("An empty database never takes a safety backup.")
    else:
        if (
            not isinstance(safety_point, str)
            or convention.POINT.fullmatch(safety_point) is None
            or not isinstance(safety_at, str)
            or change.restic_time(safety_at) != document.get("safety_restic_time")
            or tags
            != list(
                convention.tags(
                    identifier,
                    "database",
                    origin="safety",
                    live=True,
                    point=safety_point,
                )
            )
        ):
            raise ValueError("The restore safety backup is not the reviewed one.")
    if document.get("stages") != list(STAGES):
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
            "repository",
            "server_key",
            "point",
            "snapshot",
            "filename",
            "target_empty",
            "safety_point",
            "safety_at",
            "safety_restic_time",
            "safety_tags",
            "dump",
            "scope",
            "origin",
            "at",
            "restic_time",
            "caddy",
            "gate",
            "point_size",
        )
    }
    value["automation_fence"] = checked(document)
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
