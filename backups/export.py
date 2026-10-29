"""Export one recovery point to this computer (Phase D #358, #409).

Export restores a point into a bounded, root-only stage on the server and builds the site's
files as one tar archive plus its database as one dump. It leaves the site's private
configuration out. The controller transfers both through the existing ``RemoteShell``
boundary in bounded reads, then serves them from private controller staging as an
authenticated, no-store, expiring download. There is no public URL and no database blob.

Applying the review declares the new **site data leaves the server** effect, so consent is
derived as Shared even though the effect names one site (docs/adr/0035).
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import secrets
from dataclasses import dataclass
from typing import Final

from automation.bodies.source import without_imports
from bootstrap.standing import Standing
from databases import observation as database_observation
from discovery.observations import collect
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from runtimes.catalog import Architecture, architecture_of
from sites.configuration import SiteSettings

from . import change, convention, observation, restore
from .bodies import export as export_body
from .bodies import restore as restore_body

SLUG: Final = "export_recovery_point"
LABEL: Final = "Export"
STAGES: Final = ("preflight", "stage", "files", "database", "verify")
APPLICATIONS: Final = ("plain", "wordpress", "laravel")
EXPIRES: Final = "30 minutes"
EXPORT_CORE: Final = without_imports(
    importlib.resources.files("backups.bodies").joinpath("export.py").read_text(),
    (
        "backups.bodies.native",
        "backups.bodies.restore",
        "automation.bodies.units",
        "sites.bodies.admission",
        "sites.bodies.common",
        "sites.bodies.site_fpm",
        "sites.names",
        "sites.serving",
    ),
)
# The restore admission rules are shared with export; its own entry point must not run.
RESTORE_CORE: Final = restore.RESTORE_CORE.split('if __name__ == "__main__":')[0]
EXPORT_SOURCE: Final = (
    change.NATIVE_SOURCE
    + "\n"
    + RESTORE_CORE
    + "\n"
    + EXPORT_CORE
    + '\nif __name__ == "__main__":\n    main()\n'
)
EXPORT_BYTES: Final = change._packed(EXPORT_SOURCE)
EXPORT_SHA256: Final = hashlib.sha256(EXPORT_BYTES).hexdigest()


@dataclass(frozen=True)
class ExportEvidence:
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
    disk_available: int
    current_sites: tuple[str, ...]
    boot_id: str
    uptime_centiseconds: int | None


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> ExportEvidence:
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
    point, snapshots, size = restore._read_point(shell, inputs.identifier, inputs.point)
    if point is not None:
        point = {**point, "size": size}
    disk = observed.filesystem.value.avail_bytes if observed.filesystem.value else 0
    return ExportEvidence(
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
        disk,
        current_sites,
        boot_id,
        uptime,
    )


def _site(record: dict[str, object] | None) -> tuple[SiteSettings | None, str]:
    return restore._site(record)


def _size(point: dict[str, object] | None) -> int:
    return restore._point_bytes(point)


def _time_label(value: object) -> str:
    return restore._time_label(value)


def _scope_label(value: object) -> str:
    return {
        "database": "database-only",
        "files": "files-only",
        "full": "full site",
    }.get(str(value), "database-only")


def _refusals(  # noqa: C901 - one closed set of refusal checks
    evidence: ExportEvidence, settings: SiteSettings | None, application: str
) -> list[str]:
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before exporting a point.")
    if settings is None or evidence.site is None:
        refusals.append("The site's configuration could not be read.")
    elif str(evidence.site.get("state", "")) != "complete":
        refusals.append("The site is not complete, so its recovery point cannot be exported.")
    if application not in APPLICATIONS:
        refusals.append("This site's kind is not supported for export.")
    if evidence.architecture is None:
        refusals.append("The server's architecture is not supported.")
    if evidence.backup is None or not evidence.backup.enabled:
        refusals.append("Enable backups for this site first.")
    if evidence.point is None:
        refusals.append("That recovery point is no longer listed. Check backups and choose again.")
    elif evidence.point.get("complete") is not True:
        refusals.append("That recovery point is not complete, so it cannot be exported.")
    elif not evidence.point_parts:
        refusals.append("That recovery point has nothing to export.")
    parts = set(evidence.point_parts)
    if "database" in parts:
        if not evidence.engine:
            refusals.append("This server has no managed database engine to export from.")
        if evidence.backup is None or not evidence.backup.database:
            refusals.append(
                evidence.backup.database_problem
                if evidence.backup is not None
                else "This site has no site database."
            )
    size = _size(evidence.point)
    if size > export_body.MAX_EXPORT_BYTES:
        refusals.append(
            "That recovery point is larger than the largest export Barectl can move safely "
            f"({export_body.MAX_EXPORT_BYTES // (1024 * 1024)} MiB)."
        )
    if evidence.disk_available and evidence.disk_available < (convention.HEADROOM_BYTES + 2 * size):
        refusals.append("The server lacks the free space an export keeps in reserve.")
    return refusals


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, ExportEvidence):
        raise ValueError("An export needs native evidence.")
    settings, application = _site(evidence.site)
    refusals = _refusals(evidence, settings, application)
    point = evidence.point or {}
    parts = set(evidence.point_parts)
    size = _size(evidence.point)
    names = settings.names if settings is not None else ()
    at = change.schedule_time()
    token = secrets.token_hex(16)
    engine_major = restore_body.engine_major(evidence.engine, evidence.engine_version)
    details = [
        {
            "label": "Recovery point",
            "value": (
                f"{_scope_label(point.get('scope'))} recovery point taken "
                f"{_time_label(point.get('time'))}. Saved on this server."
            ),
        },
        {
            "label": "Target",
            "value": "This Barectl computer. The copy is kept in private staging and is never "
            "served from a public address.",
        },
        {
            "label": "Included",
            "value": (
                "The site's application files as one tar archive"
                + (" and its database as one dump." if "database" in parts else ".")
            ),
        },
        {
            "label": "Left out",
            "value": (
                "The site's private configuration: WordPress's private configuration file, "
                "Laravel's .env and its cached configuration. Production secrets are not "
                "exported."
                if application in ("wordpress", "laravel")
                else "No private configuration is included for this site kind."
            ),
        },
        {
            "label": "Size bound",
            "value": (
                f"Up to {export_body.MAX_EXPORT_BYTES // (1024 * 1024)} MiB in total. A "
                "larger recovery point is refused rather than moved."
            ),
        },
        {
            "label": "Download",
            "value": (
                f"The download needs your account and expires after {EXPIRES}. Barectl "
                "removes the copy from both the server and this computer afterwards."
            ),
        },
    ]
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": EXPORT_SHA256,
        "identifier": inputs.identifier,
        "application": application,
        "names": list(names),
        "runtime": settings.runtime if settings is not None else "",
        "https": bool(settings.https) if settings is not None else True,
        "readiness": settings.readiness if settings is not None else "/",
        "engine": evidence.engine if evidence.engine in ("mariadb", "postgresql") else "",
        "engine_label": evidence.engine_label,
        "engine_version": evidence.engine_version,
        "engine_major": engine_major,
        "repository": convention.repository(inputs.identifier),
        "server_key": convention.server_key(inputs.identifier),
        "point": inputs.point,
        "point_scope": str(point.get("scope", "")),
        "point_time": str(point.get("time", "")),
        "point_live": point.get("live") is True,
        "point_size": size,
        "snapshot": evidence.snapshot if "database" in parts else "",
        "files_snapshot": evidence.files_snapshot if "files" in parts else "",
        "filename": convention.dump_filename(inputs.identifier),
        "token": token,
        "at": at,
        "stages": list(STAGES),
        "details": details,
    }
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals:
        effects = (
            DeclaredEffect(
                Scope.SITE,
                (
                    f"Copy the recovery point of {inputs.identifier} taken "
                    f"{_time_label(point.get('time'))} to this computer, without the site's "
                    "private configuration."
                ),
                (inputs.identifier,),
                leaves_server=True,
            ),
        )
    return ReviewDraft(
        kind=SLUG,
        intent=f"Export a recovery point of {inputs.identifier}.",
        effects=effects,
        stages=STAGES if effects else (),
        postconditions=(
            (
                "The point's files and database are in this computer's private staging, "
                "without the site's private configuration."
            ),
            "The download needs your account, expires, and leaves no stage on either side.",
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


def _document(document: dict[str, object]) -> None:
    if document.get("version") != 1 or document.get("body_sha256") != EXPORT_SHA256:
        raise ValueError("Unsupported export review.")
    identifier = document.get("identifier")
    application = document.get("application")
    point = document.get("point")
    token = document.get("token")
    snapshot = document.get("snapshot")
    files_snapshot = document.get("files_snapshot")
    names = document.get("names")
    if (
        not isinstance(identifier, str)
        or application not in APPLICATIONS
        or not isinstance(point, str)
        or convention.POINT.fullmatch(point) is None
        or not isinstance(token, str)
        or export_body.TOKEN.fullmatch(token) is None
        or not isinstance(names, list)
        or not all(isinstance(name, str) for name in names)
        or not isinstance(snapshot, str)
        or not isinstance(files_snapshot, str)
        or (snapshot and restore_body.SNAPSHOT.fullmatch(snapshot) is None)
        or (files_snapshot and restore_body.SNAPSHOT.fullmatch(files_snapshot) is None)
        or (not snapshot and not files_snapshot)
        or document.get("repository") != convention.repository(identifier)
        or document.get("server_key") != convention.server_key(identifier)
        or document.get("filename") != convention.dump_filename(identifier)
        or document.get("stages") != list(STAGES)
        or type(document.get("point_size")) is not int
    ):
        raise ValueError("The export review is not a supported export.")
    if not snapshot and document.get("engine") != "":
        raise ValueError("A files-only export has no database engine.")
    if snapshot and document.get("engine") not in ("mariadb", "postgresql"):
        raise ValueError("The export database engine is not supported.")


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    _document(document)
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
            "files_snapshot",
            "filename",
            "token",
            "at",
            "point_size",
        )
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(value).encode(), mtime=0)).decode()
    return NativeBody(EXPORT_BYTES, (encoded,))


def verify(shell: RemoteShell, review: ChangeReview) -> bool | None:
    _document(review.document)
    from . import downloads

    try:
        transfer = downloads.transfer(
            shell,
            str(review.document["identifier"]),
            str(review.document["point"]),
            str(review.document["token"]),
        )
        downloads.record(review, transfer)
    except Exception:
        return False
    return True


EXPORT: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    input_shape=InputShape.SITE_BACKUP_POINT,
)
