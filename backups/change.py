"""Enable backups and take a database-only recovery point (Phase D #396).

Both kinds use the engine's four-member seam. Enable backups realises restic from the pinned
catalog, creates the site's root-only repository and adds the operator's passphrase key plus
a random server key; the passphrase arrives only through the confidential input channel.
Back up now streams the site's database dump through ``--stdin-from-command`` as the site
user (ADR 0031, ADR 0032, ADR 0037, #358).
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import re
import secrets
import shlex
from dataclasses import dataclass
from datetime import UTC
from typing import Final

from django.utils import timezone as django_timezone

from automation.bodies.source import AUTOMATION_SOURCE, without_imports
from bootstrap.standing import Standing
from databases import observation as database_observation
from discovery.observations import collect
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from runtimes.catalog import Architecture, architecture_of, load
from sites import observation as site_observation
from sites.configuration import (
    SiteSettings,
    render_caddy,
    render_laravel_caddy,
    render_maintenance,
    render_wordpress_caddy,
)
from sites.names import valid_identifier

from . import convention, kit, observation

ENABLE_SLUG: Final = "enable_backups"
ENABLE_LABEL: Final = "Enable backups"
BACKUP_SLUG: Final = "back_up_now"
BACKUP_LABEL: Final = "Back up now"
FULL_SLUG: Final = "back_up_full_site"
FULL_LABEL: Final = "Back up full site"
FULL_APPLICATIONS: Final = ("plain", "wordpress", "laravel")
ESCROW: Final = (
    "I stored the recovery passphrase and the printed recovery kit somewhere other than "
    "this server and Barectl."
)
PASSPHRASE_LABEL: Final = "Recovery passphrase (at least 12 characters)"  # noqa: S105
AT: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\+00:00")
RESTIC_TIME: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}")
BUILD: Final = re.compile(r"/nix/store/[0-9a-z]{32}-restic-[0-9.]+")


def _packed(source: str) -> bytes:
    return (
        (
            "#!/bin/sh\nexec python3 -c "
            + shlex.quote(
                "import base64,gzip; exec(gzip.decompress(base64.b64decode("
                + repr(base64.b64encode(gzip.compress(source.encode(), mtime=0)).decode())
                + ")))"
            )
            + ' "$@"\n'
        )
        .encode()
        .rstrip(b"\n")
    )


ENABLE_SOURCE: Final = importlib.resources.files("backups.bodies").joinpath("enable.py").read_text()
ENABLE_BYTES: Final = _packed(ENABLE_SOURCE)
ENABLE_SHA256: Final = hashlib.sha256(ENABLE_BYTES).hexdigest()
NATIVE_SOURCE: Final = importlib.resources.files("backups.bodies").joinpath("native.py").read_text()
PAUSED_SOURCE: Final = without_imports(
    importlib.resources.files("backups.bodies").joinpath("paused.py").read_text(),
    (
        "backups.bodies.native",
        "sites.bodies.admission",
        "sites.bodies.common",
        "sites.bodies.site_fpm",
    ),
)
BACKUP_SOURCE: Final = (
    NATIVE_SOURCE
    + "\n"
    + without_imports(
        importlib.resources.files("backups.bodies").joinpath("backup.py").read_text(),
        ("backups.bodies.native",),
    )
)
BACKUP_BYTES: Final = _packed(BACKUP_SOURCE)
BACKUP_SHA256: Final = hashlib.sha256(BACKUP_BYTES).hexdigest()
FULL_CORE: Final = without_imports(
    importlib.resources.files("backups.bodies").joinpath("full.py").read_text(),
    (
        "automation.bodies.units",
        "sites.bodies.admission",
        "sites.bodies.common",
        "sites.bodies.site_fpm",
        "backups.bodies.native",
        "backups.bodies.paused",
    ),
)
FULL_SOURCE: Final = (
    AUTOMATION_SOURCE
    + "\n"
    + site_observation.COMMON_SOURCE
    + "\n"
    + NATIVE_SOURCE
    + "\n"
    + PAUSED_SOURCE
    + "\n"
    + FULL_CORE
)
FULL_BYTES: Final = _packed(FULL_SOURCE)
FULL_SHA256: Final = hashlib.sha256(FULL_BYTES).hexdigest()
ENABLE_STAGES: Final = ("preflight", "restic", "repository", "keys", "verify")
BACKUP_STAGES: Final = ("preflight", "backup", "verify")
FULL_STAGES: Final = (
    "preflight",
    "gate",
    "drain",
    "backup-database",
    "backup-files",
    "verify",
    "open",
)


@dataclass(frozen=True)
class BackupEvidence:
    architecture: Architecture | None
    standing: Standing | None
    engine: str
    site: dict[str, object] | None
    database: bool
    database_problem: str
    backup: observation.ObservedBackup | None
    problem: str
    boot_id: str
    uptime_centiseconds: int | None
    restic_path: str
    restic_version: str
    disk_available: int = 0
    current_sites: tuple[str, ...] = ()
    offsite: observation.OffsiteStorage | None = None


def _site_record(
    shell: RemoteShell, identifier: str
) -> tuple[dict[str, object] | None, tuple[str, ...], str, int | None]:
    listing = site_observation.read(shell, "observed", "", protections=False)
    if listing is None:
        return None, (), "", None
    record = next(
        (site for site in listing["sites"] if site["identifier"] == identifier),
        None,
    )
    current = tuple(sorted(str(site) for site in listing["current_sites"]))
    if record is None:
        return None, current, str(listing["boot"]), int(str(listing["uptime"]))
    return dict(record), current, str(listing["boot"]), int(str(listing["uptime"]))


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> BackupEvidence:
    observed = collect(shell, sites=False)
    architecture = architecture_of(observed.architecture.value or "")
    engines = database_observation.installed_engines(observed)
    engine = engines[0].engine if len(engines) == 1 and engines[0].managed else ""
    record, current_sites, boot_id, uptime = _site_record(shell, inputs.identifier)
    listing = shell.run(ALL_SITES_READ)
    if listing.exit_status == 0 and not listing.truncated:
        current_sites = tuple(listing.stdout.splitlines())
    restic_path, restic_version = observation.offered_restic(architecture)
    problem = ""
    backup: observation.ObservedBackup | None = None
    value = observation.read(shell, (inputs.identifier,), engine, architecture)
    if value is None:
        problem = "Backups could not be read from the server."
    else:
        backup = _observed(value, inputs.identifier)
    disk = observed.filesystem.value.avail_bytes if observed.filesystem.value else 0
    return BackupEvidence(
        architecture,
        observed.standing.standing if observed.standing else None,
        engine,
        record,
        bool(backup.database) if backup is not None else False,
        backup.database_problem if backup is not None else "",
        backup,
        problem,
        boot_id,
        uptime,
        restic_path,
        restic_version,
        disk,
        current_sites,
        observation.offsite_of(value),
    )


def _offsite_plan(identifier: str, evidence: BackupEvidence) -> dict[str, object] | None:
    from . import offsite

    return offsite.capture_plan(identifier, evidence.offsite)


def _platform_refusals(evidence: BackupEvidence) -> list[str]:
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before enabling backups.")
    if evidence.site is None or str(evidence.site.get("state", "")) != "complete":
        refusals.append("The site is not complete, so its backups cannot be enabled.")
    if evidence.architecture is None:
        refusals.append("The server's architecture is not supported.")
    elif not evidence.restic_path:
        refusals.append("The pinned backup tool is unavailable for this architecture.")
    if evidence.problem:
        refusals.append(evidence.problem)
    elif evidence.backup is None:
        refusals.append("The site's backups could not be read from the server.")
    if evidence.offsite is not None and evidence.offsite.problem:
        refusals.append(evidence.offsite.problem)
    if evidence.backup is not None:
        refusals.extend(evidence.backup.problems)
    return refusals


def _profile_refusals(evidence: BackupEvidence) -> list[str]:
    if evidence.backup is None:
        return []
    profile = evidence.backup.profile
    if profile and not evidence.restic_path:
        return ["The backup tool is outside supported settings."]
    if profile and profile not in observation.known_profiles(evidence.architecture):
        return ["The backup tool is outside supported settings."]
    return []


def _details(evidence: BackupEvidence) -> list[dict[str, str]]:
    values = [
        {
            "label": "Backup tool",
            "value": f"restic {evidence.restic_version}" if evidence.restic_version else "restic",
        },
        {
            "label": "Free space kept",
            "value": (
                f"At least {convention.HEADROOM_BYTES // (1024 * 1024)} MiB before it starts"
            ),
        },
    ]
    if evidence.database:
        values.append({"label": "Database only", "value": "Available for this site."})
    else:
        values.append(
            {
                "label": "Database only",
                "value": evidence.database_problem or "This site has no site database.",
            }
        )
    return values


def review_enable(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, BackupEvidence):
        raise ValueError("Enabling backups needs native evidence.")
    refusals = [*_platform_refusals(evidence), *_profile_refusals(evidence)]
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": ENABLE_SHA256,
        "identifier": inputs.identifier,
        "stages": list(ENABLE_STAGES),
        "details": _details(evidence),
        "note": (
            "Barectl keeps the recovery passphrase only long enough to add it to the "
            "repository. Store the printed kit and the passphrase away from this server."
        ),
        "acknowledgement": ESCROW,
        "secret_label": PASSPHRASE_LABEL,
        "kit_lines": kit.lines(
            server_name="{server}",
            identifier=inputs.identifier,
            restic_version=evidence.restic_version,
        ),
    }
    postconditions = (
        f"restic {evidence.restic_version} is installed from the pinned catalog."
        if evidence.restic_version
        else "restic is installed from the pinned catalog.",
        "The site's encrypted repository exists in a root-only directory.",
        "The operator's passphrase and a server key both open the repository.",
        "The recovery passphrase is not stored and the kit holds no secret.",
    )
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals and evidence.backup is not None and evidence.backup.enabled:
        document["note"] = "Backups are already enabled for this site. Nothing will change."
    elif not refusals:
        document.update(
            {
                "restic_path": evidence.restic_path,
                "restic_version": evidence.restic_version,
                "profile_path": evidence.backup.profile if evidence.backup else "",
                "repository": convention.repository(inputs.identifier),
                "server_key": convention.server_key(inputs.identifier),
                "repository_existed": "yes"
                if evidence.backup is not None and evidence.backup.repository
                else "no",
                "at": schedule_time(),
            }
        )
        effects = (
            DeclaredEffect(
                Scope.SHARED,
                (
                    "Install the pinned backup tool and create this site's encrypted onsite "
                    f"repository for {inputs.identifier}, carrying the recovery passphrase."
                ),
                (inputs.identifier,),
            ),
        )
    return ReviewDraft(
        kind=ENABLE_SLUG,
        intent=f"Enable backups for site {inputs.identifier}.",
        effects=effects,
        stages=ENABLE_STAGES if effects else (),
        postconditions=postconditions if effects else (),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        sites_read=sites_read(inputs.identifier) if effects else "",
        current_sites=(inputs.identifier,) if effects else None,
        document=document,
        writes_secrets=True,
    )


def review_backup(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, BackupEvidence):
        raise ValueError("A backup needs native evidence.")
    refusals = [*_platform_refusals(evidence), *_profile_refusals(evidence)]
    if evidence.site is None or str(evidence.site.get("state", "")) != "complete":
        refusals.append("The site is not complete, so Barectl will not back it up.")
    if evidence.backup is None or not evidence.backup.enabled:
        refusals.append("Enable backups for this site first.")
    if not evidence.database:
        refusals.append(evidence.database_problem or "This site has no site database.")
    if not evidence.engine:
        refusals.append("This server has no managed database engine to dump.")
    point = secrets.token_hex(8)
    at = schedule_time()
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BACKUP_SHA256,
        "identifier": inputs.identifier,
        "engine": evidence.engine,
        "repository": convention.repository(inputs.identifier),
        "server_key": convention.server_key(inputs.identifier),
        "point": point,
        "at": at,
        "restic_time": restic_time(at),
        "tags": list(
            convention.tags(inputs.identifier, "database", origin="manual", live=True, point=point)
        ),
        "dump": convention.dump_argv(inputs.identifier, evidence.engine)
        if evidence.engine in ("mariadb", "postgresql")
        else [],
        "filename": convention.dump_filename(inputs.identifier),
        "stages": list(BACKUP_STAGES),
        "details": [
            {"label": "Scope", "value": "Database only"},
            {"label": "Site is paused", "value": "No. The dump runs without pausing the site."},
            {
                "label": "Free space kept",
                "value": f"{convention.HEADROOM_BYTES // (1024 * 1024)} MiB",
            },
        ],
        "note": (
            "Barectl streams the dump straight into the encrypted repository. A failed dump "
            "creates no recovery point."
        ),
        "offsite": _offsite_plan(inputs.identifier, evidence),
    }
    postconditions = (
        "One complete Barectl-tagged database recovery point exists in the repository.",
        "No plain-text database dump remains on disk.",
    )
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals:
        effects = (
            DeclaredEffect(
                Scope.SITE,
                f"Take one database-only recovery point for {inputs.identifier}.",
                (inputs.identifier,),
            ),
        )
    return ReviewDraft(
        kind=BACKUP_SLUG,
        intent=f"Back up the database of site {inputs.identifier}.",
        effects=effects,
        stages=BACKUP_STAGES if effects else (),
        postconditions=postconditions if effects else (),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        sites_read=sites_read(inputs.identifier) if effects else "",
        current_sites=(inputs.identifier,) if effects else None,
        document=document,
    )


ALL_SITES_READ: Final = (
    "find /etc/caddy/sites -maxdepth 1 -type f -name '*.caddy' "
    "-printf '%f\\n' | sed 's/\\.caddy$//' | LC_ALL=C sort"
)
FULL_EXCLUDED: Final = (
    "The object cache's data, logs, sessions, temporary files, other retained releases, "
    "runtime builds, the deploy key and known-hosts, and web server, proxy and TLS settings."
)


def _full_site(evidence: BackupEvidence) -> tuple[SiteSettings | None, str, str]:
    site = evidence.site
    if site is None:
        return None, "", ""
    application = str(site.get("application", "plain"))
    if application not in ("plain", "wordpress", "laravel"):
        return None, application, ""
    names = site.get("names")
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        return None, application, ""
    try:
        settings = SiteSettings(
            str(site["identifier"]),
            tuple(names),
            str(site.get("runtime", "")),
            https=bool(site.get("https", True)),
            readiness=str(site.get("readiness", "/")),
        )
    except ValueError:
        return None, application, ""
    return settings, application, str(site.get("state", ""))


def _full_open_file(settings: SiteSettings, application: str) -> str:
    if application == "wordpress":
        return render_wordpress_caddy(settings)
    if application == "laravel":
        return render_laravel_caddy(settings)
    return render_caddy(settings)


def _full_files(identifier: str, application: str) -> list[str]:
    directory = f"/var/www/{identifier}"
    shared = {
        "laravel": ["private/laravel.env", "private/storage", "private/cache"],
        "wordpress": ["private/wp-config.php"],
        "plain": [],
    }[application]
    return [f"{directory}/current", *(f"{directory}/{path}" for path in shared)]


def _full_refusals(
    evidence: BackupEvidence, settings: SiteSettings | None, application: str, state: str
) -> list[str]:
    refusals = [*_platform_refusals(evidence), *_profile_refusals(evidence)]
    if settings is None or state != "complete":
        refusals.append("The site is not complete, so Barectl will not pause it.")
    if application == "wordpress_partial" or application not in (
        "plain",
        "wordpress",
        "laravel",
    ):
        refusals.append("The site's application is incomplete, so its files cannot be copied.")
    if evidence.backup is None or not evidence.backup.enabled:
        refusals.append("Enable backups for this site first.")
    if evidence.database and not evidence.engine:
        refusals.append("This server has no managed database engine to dump.")
    if evidence.disk_available and evidence.disk_available < convention.HEADROOM_BYTES:
        refusals.append("The server lacks the free space this full backup keeps in reserve.")
    return refusals


def review_full(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, BackupEvidence):
        raise ValueError("A full backup needs native evidence.")
    settings, application, state = _full_site(evidence)
    refusals = _full_refusals(evidence, settings, application, state)
    scope = "full" if evidence.database and evidence.engine else "files"
    point = secrets.token_hex(8)
    at = schedule_time()
    files = _full_files(inputs.identifier, application) if settings is not None else []
    dump = (
        convention.dump_argv(inputs.identifier, evidence.engine)
        if evidence.database and evidence.engine
        else []
    )
    tags: dict[str, list[str]] = {
        "files": list(
            convention.tags(
                inputs.identifier,
                scope,
                part="files",
                origin="manual",
                live=False,
                point=point,
                complete=False,
            )
        )
    }
    if dump:
        tags["database"] = list(
            convention.tags(
                inputs.identifier,
                scope,
                part="database",
                origin="manual",
                live=False,
                point=point,
                complete=False,
            )
        )
    caddy = _full_open_file(settings, application) if settings is not None else ""
    gate = render_maintenance(settings) if settings is not None else ""
    other = tuple(site for site in evidence.current_sites if site != inputs.identifier)
    paused = (
        "Visitors see a maintenance page, their in-flight requests finish, and the site's "
        "background work is stopped while the copy is taken."
    )
    details = [
        {"label": "Scope", "value": "Full site" if scope == "full" else "Full site (files only)"},
        {"label": "Site is paused", "value": "Yes. " + paused},
        {
            "label": "Copied",
            "value": (
                "The database and the site's files."
                if scope == "full"
                else "The site's files. It has no site database."
            ),
        },
        {"label": "Excluded", "value": FULL_EXCLUDED},
        {
            "label": "Free space kept",
            "value": f"At least {convention.HEADROOM_BYTES // (1024 * 1024)} MiB before it starts",
        },
    ]
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": FULL_SHA256,
        "identifier": inputs.identifier,
        "application": application,
        "scope": scope,
        "engine": evidence.engine if dump else "",
        "names": list(settings.names) if settings is not None else [],
        "runtime": settings.runtime if settings is not None else "",
        "https": bool(settings.https) if settings is not None else True,
        "readiness": settings.readiness if settings is not None else "/",
        "repository": convention.repository(inputs.identifier),
        "server_key": convention.server_key(inputs.identifier),
        "point": point,
        "at": at,
        "restic_time": restic_time(at),
        "caddy": caddy,
        "gate": gate,
        "files": files,
        "dump": dump,
        "filename": convention.dump_filename(inputs.identifier),
        "tags": tags,
        "stages": list(FULL_STAGES),
        "details": details,
        "note": (
            "A full copy pauses the site briefly. If it stops partway, the site stays paused "
            "until you reopen it."
        ),
        "offsite": _offsite_plan(inputs.identifier, evidence),
    }
    postconditions = (
        "One complete Barectl-tagged full recovery point exists in the repository.",
        "The site serves visitors again.",
        "The site's background work is exactly as it was before the copy.",
    )
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals:
        effects = (
            DeclaredEffect(
                Scope.SITE,
                (
                    f"Pause {inputs.identifier}, copy its "
                    + ("database and files" if scope == "full" else "files")
                    + " into one recovery point, and reopen it."
                ),
                (inputs.identifier,),
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
                if other
                else ()
            ),
        )
    return ReviewDraft(
        kind=FULL_SLUG,
        intent=f"Back up site {inputs.identifier} completely.",
        effects=effects,
        stages=FULL_STAGES if effects else (),
        postconditions=postconditions if effects else (),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        sites_read=ALL_SITES_READ if effects else "",
        current_sites=evidence.current_sites if effects else None,
        document=document,
    )


def _full_document(document: dict[str, object]) -> None:
    _document(document, FULL_SHA256)
    from . import offsite

    offsite.validate_capture(document.get("offsite"))
    identifier = document.get("identifier")
    settings_values = document.get("names")
    application = document.get("application")
    scope = document.get("scope")
    if (
        not isinstance(identifier, str)
        or not valid_identifier(identifier)
        or application not in ("plain", "wordpress", "laravel")
        or scope not in ("full", "files")
        or not isinstance(settings_values, list)
        or not all(isinstance(name, str) for name in settings_values)
    ):
        raise ValueError("The full backup review is not a supported capture.")
    settings = SiteSettings(
        identifier,
        tuple(str(name) for name in settings_values),
        str(document.get("runtime", "")),
        https=document.get("https", True) is not False,
        readiness=str(document.get("readiness", "/")),
    )
    if _full_open_file(settings, str(application)) != document.get("caddy"):
        raise ValueError("The full backup site configuration is not the reviewed one.")
    if render_maintenance(settings) != document.get("gate"):
        raise ValueError("The full backup gate is not the reviewed one.")
    if document.get("files") != _full_files(identifier, str(application)):
        raise ValueError("The full backup file set is not the reviewed one.")
    tags = document.get("tags")
    point = str(document.get("point", ""))
    at = str(document.get("at", ""))
    if (
        not isinstance(tags, dict)
        or not isinstance(document.get("restic_time"), str)
        or RESTIC_TIME.fullmatch(str(document["restic_time"])) is None
        or document.get("restic_time") != restic_time(at)
        or AT.fullmatch(at) is None
        or convention.POINT.fullmatch(point) is None
        or document.get("repository") != convention.repository(identifier)
        or document.get("server_key") != convention.server_key(identifier)
        or document.get("filename") != convention.dump_filename(identifier)
    ):
        raise ValueError("The full backup review is not a supported capture.")
    expected = {
        "files": list(
            convention.tags(
                identifier,
                str(scope),
                part="files",
                origin="manual",
                live=False,
                point=point,
                complete=False,
            )
        )
    }
    dump = document.get("dump")
    if isinstance(dump, list) and dump:
        if not isinstance(document.get("engine"), str) or document.get("engine") not in (
            "mariadb",
            "postgresql",
        ):
            raise ValueError("The full backup review has no supported engine.")
        if dump != convention.dump_argv(identifier, str(document["engine"])):
            raise ValueError("The full backup dump is not the reviewed one.")
        expected["database"] = list(
            convention.tags(
                identifier,
                str(scope),
                part="database",
                origin="manual",
                live=False,
                point=point,
                complete=False,
            )
        )
    if tags != expected or (scope == "files") != (not dump):
        raise ValueError("The full backup review is not a supported capture.")


def body_full(document: dict[str, object], context: BodyContext) -> NativeBody:
    _full_document(document)
    value = {
        key: document[key]
        for key in (
            "identifier",
            "application",
            "scope",
            "engine",
            "names",
            "runtime",
            "https",
            "readiness",
            "repository",
            "server_key",
            "point",
            "at",
            "restic_time",
            "caddy",
            "gate",
            "files",
            "dump",
            "filename",
            "tags",
            "offsite",
        )
    }
    from automation import fence as automation_fence

    value["automation_fence"] = automation_fence.checked(document)
    encoded = base64.b64encode(gzip.compress(json.dumps(value).encode(), mtime=0)).decode()
    return NativeBody(FULL_BYTES, (encoded,))


def verify_full(shell: RemoteShell, review: ChangeReview) -> bool | None:
    body_full(review.document, BodyContext("", "", 0))
    point = str(review.document["point"])
    identifier = str(review.document["identifier"])
    command = shlex.join(
        [
            "/usr/bin/env",
            f"RESTIC_REPOSITORY={convention.repository(identifier)}",
            f"RESTIC_PASSWORD_FILE={convention.server_key(identifier)}",
            f"RESTIC_CACHE_DIR={convention.CACHE_DIR}",
            convention.RESTIC_BIN,
            "snapshots",
            "--json",
            "--no-lock",
            "--tag",
            "point:" + point,
        ]
    )
    result = run_root(shell, command)
    if result.exit_status or result.truncated:
        return None
    try:
        value: object = json.loads(result.stdout)
    except ValueError:
        return None
    if not isinstance(value, list):
        return None
    parts: dict[str, bool] = {}
    for row in value:
        if not isinstance(row, dict) or not isinstance(row.get("tags"), list):
            continue
        tags = [tag for tag in row["tags"] if isinstance(tag, str)]
        part = next(
            (tag.removeprefix("part:") for tag in tags if tag.startswith("part:")),
            "",
        )
        if part in convention.PARTS and part not in parts:
            parts[part] = "complete" in tags
    expected = convention.expected_parts(str(review.document.get("scope", "full")))
    return all(parts.get(part) is True for part in expected) and set(parts) == set(expected)


def sites_read(identifier: str) -> str:
    """The fixed read that proves the reviewed site still exists."""
    path = shlex.quote(f"/etc/caddy/sites/{identifier}.caddy")
    return f"test -f {path} && printf '%s\\n' {shlex.quote(identifier)}"


def restic_time(at: str) -> str:
    """restic's ``--time`` takes ``YYYY-MM-DD HH:MM:SS``; the result keeps RFC 3339."""
    return at.replace("T", " ").removesuffix("+00:00")


def schedule_time() -> str:
    value = django_timezone.now().astimezone(UTC).replace(microsecond=0)
    return value.isoformat()


def _document(document: dict[str, object], expected: str) -> None:
    if document.get("version") != 1 or document.get("body_sha256") != expected:
        raise ValueError("Unsupported backup review.")


def _known_build(path: object, version: object) -> None:
    if not isinstance(path, str) or BUILD.fullmatch(path) is None:
        raise ValueError("The backup tool is not a catalog build.")
    build = load().identify(Architecture.X86_64, path) or load().identify(
        Architecture.AARCH64, path
    )
    if build is None or build.entry != convention.RESTIC_ENTRY or build.version != version:
        raise ValueError("The backup tool is not a reviewed catalog build.")


def body_enable(document: dict[str, object], context: BodyContext) -> NativeBody:
    _document(document, ENABLE_SHA256)
    if not context.secret_path:
        raise ValueError("Enabling backups needs a staged recovery passphrase.")
    identifier = document.get("identifier")
    repository = document.get("repository")
    key = document.get("server_key")
    at = document.get("at")
    if (
        not isinstance(identifier, str)
        or not valid_identifier(identifier)
        or repository != convention.repository(identifier)
        or key != convention.server_key(identifier)
        or not isinstance(at, str)
        or AT.fullmatch(at) is None
        or not isinstance(document.get("profile_path"), str)
    ):
        raise ValueError("The backup review is not a supported setup.")
    _known_build(document.get("restic_path"), document.get("restic_version"))
    payload = {
        "identifier": identifier,
        "restic_path": document["restic_path"],
        "profile_path": document["profile_path"],
        "repository": repository,
        "server_key": key,
        "repository_existed": document.get("repository_existed"),
        "at": at,
        "secret_path": context.secret_path,
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(ENABLE_BYTES, (encoded,))


def body_backup(document: dict[str, object], context: BodyContext) -> NativeBody:
    _document(document, BACKUP_SHA256)
    from . import offsite

    offsite.validate_capture(document.get("offsite"))
    identifier = document.get("identifier")
    engine = document.get("engine")
    point = document.get("point")
    at = document.get("at")
    tags = document.get("tags")
    dump = document.get("dump")
    if (
        not isinstance(identifier, str)
        or not valid_identifier(identifier)
        or engine not in ("mariadb", "postgresql")
        or not isinstance(point, str)
        or convention.POINT.fullmatch(point) is None
        or not isinstance(at, str)
        or AT.fullmatch(at) is None
        or not isinstance(document.get("restic_time"), str)
        or RESTIC_TIME.fullmatch(str(document.get("restic_time"))) is None
        or document.get("restic_time") != restic_time(at)
        or not isinstance(tags, list)
        or tags
        != list(convention.tags(identifier, "database", origin="manual", live=True, point=point))
        or not isinstance(dump, list)
        or dump != convention.dump_argv(identifier, str(engine))
        or document.get("filename") != convention.dump_filename(identifier)
        or document.get("repository") != convention.repository(identifier)
        or document.get("server_key") != convention.server_key(identifier)
    ):
        raise ValueError("The backup review is not a supported capture.")
    payload = {
        key: document[key]
        for key in (
            "identifier",
            "engine",
            "repository",
            "server_key",
            "point",
            "at",
            "restic_time",
            "tags",
            "dump",
            "filename",
            "offsite",
        )
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(BACKUP_BYTES, (encoded,))


def _current(shell: RemoteShell, document: dict[str, object]) -> observation.ObservedBackup | None:
    identifier = str(document["identifier"])
    observed = collect(shell, sites=False)
    architecture = architecture_of(observed.architecture.value or "")
    engines = database_observation.installed_engines(observed)
    engine = engines[0].engine if len(engines) == 1 and engines[0].managed else ""
    value = observation.read(shell, (identifier,), engine, architecture)
    return _observed(value, identifier) if value is not None else None


def _observed(value: dict[str, object], identifier: str) -> observation.ObservedBackup | None:
    rows = value.get("sites")
    if not isinstance(rows, list):
        return None
    item = next(
        (row for row in rows if isinstance(row, dict) and row.get("identifier") == identifier),
        None,
    )
    if item is None:
        return None
    last = item.get("last")
    return observation.ObservedBackup(
        identifier,
        str(item["profile"]),
        bool(item["repository"]),
        bool(item["key"]),
        tuple(str(problem) for problem in item["problems"]),
        bool(item["database"]),
        str(item["database_problem"]),
        observation.BackupResult(
            str(last["class"]),
            str(last["reason"]),
            str(last["scope"]),
            str(last["origin"]),
            str(last["at"]),
            str(last["point"]),
            int(str(last["snapshots"])),
            int(str(last["bytes"])),
            str(last.get("offsite", "")),
        )
        if isinstance(last, dict)
        else None,
        observation.offsite_of(value),
        _copy(item.get("copy")),
    )


def _copy(value: object) -> observation.OffsiteCopy | None:
    if not isinstance(value, dict):
        return None
    return observation.OffsiteCopy(
        str(value["class"]),
        str(value["reason"]),
        str(value["point"]),
        str(value["at"]),
    )


def verify_enable(shell: RemoteShell, review: ChangeReview) -> bool | None:
    body_enable(
        review.document, BodyContext("", "", 0, f"{native.CONFIDENTIAL_DIRECTORY}/{'0' * 32}")
    )
    row = _current(shell, review.document)
    return None if row is None else row.enabled


def verify_backup(shell: RemoteShell, review: ChangeReview) -> bool | None:
    body_backup(review.document, BodyContext("", "", 0))
    point = str(review.document["point"])
    identifier = str(review.document["identifier"])
    command = shlex.join(
        [
            "/usr/bin/env",
            f"RESTIC_REPOSITORY={convention.repository(identifier)}",
            f"RESTIC_PASSWORD_FILE={convention.server_key(identifier)}",
            f"RESTIC_CACHE_DIR={convention.CACHE_DIR}",
            convention.RESTIC_BIN,
            "snapshots",
            "--json",
            "--no-lock",
            "--tag",
            "point:" + point,
        ]
    )
    result = run_root(shell, command)
    if result.exit_status or result.truncated:
        return None
    try:
        value: object = json.loads(result.stdout)
    except ValueError:
        return None
    if not isinstance(value, list):
        return None
    return any(
        isinstance(row, dict)
        and isinstance(row.get("tags"), list)
        and convention.MARKER in row["tags"]
        and "point:" + point in row["tags"]
        and "complete" in row["tags"]
        for row in value
    )


ENABLE: Final = ChangeKind(
    slug=ENABLE_SLUG,
    label=ENABLE_LABEL,
    inspect=inspect,
    review=review_enable,
    body=body_enable,
    verify=verify_enable,
    refresh_discovery=True,
    input_shape=InputShape.SITE,
    writes_secrets=True,
)

BACK_UP_NOW: Final = ChangeKind(
    slug=BACKUP_SLUG,
    label=BACKUP_LABEL,
    inspect=inspect,
    review=review_backup,
    body=body_backup,
    verify=verify_backup,
    refresh_discovery=True,
    input_shape=InputShape.SITE,
)

BACK_UP_FULL: Final = ChangeKind(
    slug=FULL_SLUG,
    label=FULL_LABEL,
    inspect=inspect,
    review=review_full,
    body=body_full,
    verify=verify_full,
    refresh_discovery=True,
    input_shape=InputShape.SITE,
)
