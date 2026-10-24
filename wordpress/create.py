"""Create a WordPress site as one reviewed change (Phase B #380, ADR 0017).

The change builds the site and its MariaDB binding, downloads the pinned core archive whose
size and SHA-256 are checked in here, installs it as the site user, writes server-generated
salts to a private configuration outside the public root, keeps visitors behind the
maintenance gate until the home and login pages answer, and verifies the site over HTTPS.
The administrator password arrives only through the confidential input channel and is
never stored (ADR 0032).
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import re
import shlex
from dataclasses import dataclass
from typing import Final

from databases import binding, provision
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from operations.models import ChangeReview
from runtimes import observation as runtime_observation
from runtimes.catalog import Architecture, architecture_of
from sites import change as site_change
from sites import observation
from sites.bodies.common import SITE_GATED, NativeState, SiteRecord
from sites.configuration import (
    PHP_RUNTIMES,
    SiteSettings,
    render_maintenance,
    render_pool,
    render_wordpress_caddy,
)

from . import convention

SLUG: Final = "create_wordpress_site"
LABEL: Final = "Create WordPress site"
STAGES: Final = (
    "preflight",
    "site",
    "gate",
    "database",
    "download",
    "configure",
    "install",
    "publish",
    "verify",
)

_DATABASE_SOURCE: Final = (
    importlib.resources.files("databases.bodies").joinpath("site.py").read_text()
)
BODY_SOURCE: Final = (
    observation.COMMON_SOURCE.replace(
        'RUNTIME_READ_SOURCE = ""',
        "RUNTIME_READ_SOURCE = " + repr(runtime_observation.READ_SOURCE),
    )
    + "\n"
    + importlib.resources.files("wordpress").joinpath("convention.py").read_text()
    + "\n"
    + importlib.resources.files("wordpress.bodies")
    .joinpath("install.py")
    .read_text()
    .replace(
        "from sites.bodies.common import (\n"
        "    configure_pool,\n"
        "    create_account,\n"
        "    create_layout,\n"
        "    current_bytes,\n"
        "    identity_name_exists,\n"
        "    maintenance_file,\n"
        "    pool_file,\n"
        "    publish_caddy,\n"
        "    result,\n"
        "    runtime_admission,\n"
        "    setting,\n"
        "    stage,\n"
        "    validate_candidate,\n"
        "    validate_pool_candidate,\n"
        "    wordpress_caddy_file,\n"
        ")\n",
        "",
    )
    .replace(
        "from wordpress.convention import (\n"
        "    CORE_ARCHIVE_SHA256,\n"
        "    CORE_ARCHIVE_SIZE,\n"
        "    CORE_ARCHIVE_URL,\n"
        "    CORE_MARKERS,\n"
        "    CORE_VERSION,\n"
        "    loader_problem,\n"
        "    new_salts,\n"
        "    private_configuration_path,\n"
        "    private_configuration_problem,\n"
        "    public_root,\n"
        "    render_loader,\n"
        "    render_private_configuration,\n"
        "    version_of,\n"
        ")\n",
        "",
    )
    .replace('DATABASE_BODY = ""', "DATABASE_BODY = " + repr(_DATABASE_SOURCE))
)
BODY_BYTES: Final = (
    (
        "#!/bin/sh\nexec python3 -c "
        + shlex.quote(
            "import base64,gzip; exec(gzip.decompress(base64.b64decode("
            + repr(base64.b64encode(gzip.compress(BODY_SOURCE.encode(), mtime=0)).decode())
            + ")))"
        )
        + ' "$@"\n'
    )
    .encode()
    .rstrip(b"\n")
)
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()


@dataclass(frozen=True)
class WordPressEvidence:
    site: site_change.SiteEvidence
    database: provision.DatabaseEvidence


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> WordPressEvidence:
    from discovery.observations import collect

    site = site_change.inspect(shell, inputs)
    snapshot = collect(shell, sites=False)
    architecture = architecture_of(snapshot.architecture.value or "")
    return WordPressEvidence(
        site, provision.evidence(shell, snapshot, architecture, inputs.identifier)
    )


def _site_row(evidence: WordPressEvidence, identifier: str) -> SiteRecord | None:
    native = evidence.site.native
    if native is None:
        return None
    return next((site for site in native["sites"] if site["identifier"] == identifier), None)


def _account_identity(row: SiteRecord | None) -> int:
    account = row.get("account") if row is not None else None
    if isinstance(account, list) and len(account) == 5 and type(account[0]) is int:
        return int(account[0])
    return 0


def _database_refusals(evidence: WordPressEvidence, identifier: str) -> list[str]:
    database = evidence.database
    if database.engine == binding.POSTGRESQL:
        return ["WordPress needs MariaDB. This server runs PostgreSQL."]
    if not database.engine:
        return [
            (
                "This server has no database engine. Install MariaDB from Server Settings "
                "or as Step 1 of Create site before creating a WordPress site."
            )
        ]
    if database.engine != binding.MARIADB:
        return [f"WordPress needs MariaDB, not {database.label}."]
    return provision.refusals(database, identifier, subject="a WordPress site")


def _new_site_refusals(native: NativeState, inputs: PreparationInputs) -> list[str]:
    refusals: list[str] = []
    directory = f"/var/www/{inputs.identifier}"
    if native["evidence"].get(directory) is not None:
        refusals.append("The site directory is already occupied. Review its native state first.")
    refusals.extend(
        "A requested DNS name already belongs to another site."
        for site in native["sites"]
        if site["identifier"] != inputs.identifier and set(site["names"]).intersection(inputs.names)
    )
    return refusals


def _existing_refusals(row: SiteRecord, inputs: PreparationInputs) -> tuple[bool, bool, list[str]]:
    """Whether the site already exists, whether it is gated, and any refusal."""
    refusals: list[str] = []
    if row["names"] != list(inputs.names):
        refusals.append("This identifier already names a site with other DNS names.")
    if row["runtime"] not in ("", inputs.selection):
        refusals.append("This identifier already names a site on another PHP runtime.")
    if row["https"] != inputs.https:
        refusals.append("This identifier already names a site with another HTTPS setting.")
    state = str(row["state"])
    problem = str(row["problem"])
    if state == "unsupported":
        refusals.append(problem or "The existing site is outside supported settings.")
    elif state == "partial" and problem != SITE_GATED:
        refusals.append(problem or "The existing site is incomplete.")
    return state in ("complete", "partial"), problem == SITE_GATED, refusals


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:  # noqa: C901 - one reviewed shape
    if not isinstance(evidence, WordPressEvidence):
        raise ValueError("WordPress creation needs native evidence.")
    settings = SiteSettings(inputs.identifier, inputs.names, inputs.selection, https=inputs.https)
    refusals: list[str] = list(site_change.runtime_refusals(evidence.site, settings))
    refusals.extend(_database_refusals(evidence, inputs.identifier))
    native = evidence.site.native
    if native is None:
        refusals.append(
            "Site files, accounts or Caddy's running configuration are unreadable or unsupported."
        )
    row = _site_row(evidence, inputs.identifier)
    existing = False
    gated = False
    if row is None and native is not None:
        refusals.extend(_new_site_refusals(native, inputs))
    elif row is not None:
        existing, gated, existing_refusals = _existing_refusals(row, inputs)
        refusals.extend(existing_refusals)
    application = row["application"] if row else "plain"
    version = row["application_version"] if row else ""
    application_problem = row["application_problem"] if row else ""
    installed = application == "wordpress" and not application_problem
    completed, statements = (
        ([], []) if refusals else provision.statements(evidence.database, inputs.identifier)
    )
    current: tuple[str, ...] = ()
    identity = _account_identity(row)
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": inputs.identifier,
        "names": list(inputs.names),
        "selection": inputs.selection,
        "https": inputs.https,
        "title": inputs.title,
        "admin_username": inputs.admin_username,
        "admin_email": inputs.admin_email,
        "existing": existing,
        "gated": gated,
        "installed": installed,
        "locale": evidence.database.locale,
        "engine": evidence.database.engine,
        "principal": binding.name_of(inputs.identifier),
        "archive_url": convention.CORE_ARCHIVE_URL,
        "archive_size": convention.CORE_ARCHIVE_SIZE,
        "archive_sha256": convention.CORE_ARCHIVE_SHA256,
        "core_version": convention.CORE_VERSION,
        "completed": completed,
        "statements": statements,
        "secret_label": "WordPress administrator password",
        "secret_generate": True,
    }
    document.update(site_change.runtime_document(evidence.site, inputs))
    if native is not None:
        current = tuple(str(site) for site in native["current_sites"])
        identity = _account_identity(row) or site_change.review_identity(native, inputs.identifier)
        document.update(
            identity=identity,
            caddy=render_wordpress_caddy(settings),
            gate=render_maintenance(settings),
            pool=render_pool(settings),
        )
        if not existing:
            document.update(
                precondition_digest=native["digest"],
                disk_digest=native["disk_digest"],
                proxy_identity=native["next_proxy_id"],
                membership={settings.runtime: list(current)},
            )
        document.update(
            provision.document(
                evidence.database,
                inputs.identifier,
                inputs.selection,
                identity,
                if_ready=not refusals,
            )
        )
        if row is not None and row["state"] == "partial" and not gated:
            refusals.append("The site's native layout is incomplete; finish it first.")
    if installed and statements:
        refusals.append("The WordPress site exists but its database binding is incomplete.")
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals and not (installed and not gated):
        effects = (
            DeclaredEffect(
                Scope.SITE,
                f"{'Finish' if existing else 'Create'} WordPress site {inputs.identifier}, its "
                "database and pinned core release.",
                (inputs.identifier,),
            ),
            *(
                (
                    DeclaredEffect(
                        Scope.SHARED,
                        "Publish the shared Caddy route without restarting other sites.",
                        current,
                    ),
                )
                if current
                else ()
            ),
        )
    document["details"] = _details(evidence, inputs, row, installed, version, statements, completed)
    if inputs.https:
        warnings = site_change.dns_warnings(evidence.site, inputs.names)
        if warnings:
            document["acknowledgement"] = " ".join(warnings)
    stages = tuple(stage for stage in STAGES if stage != "site") if existing else STAGES
    if installed and gated:
        stages = ("preflight", "publish", "verify")
    return ReviewDraft(
        SLUG,
        f"Create WordPress site {inputs.identifier}.",
        effects=effects,
        stages=stages,
        postconditions=(
            "The site, its MariaDB binding and the pinned WordPress core exist.",
            "The home and login pages answer over the site's own HTTPS address.",
            "WordPress runs as the site user and its salts stay on the server.",
        ),
        refusals=tuple(dict.fromkeys(refusals)),
        boot_id=str(native["boot"]) if native else "",
        uptime_centiseconds=int(str(native["uptime"])) if native else None,
        sites_read=site_change.membership_command(inputs.selection)
        if native and native["master_present"]
        else "",
        current_sites=current if native and native["master_present"] else None,
        document=document,
    )


def _details(
    evidence: WordPressEvidence,
    inputs: PreparationInputs,
    row: SiteRecord | None,
    installed: bool,
    version: str,
    statements: list[list[str]],
    completed: list[str],
) -> list[dict[str, str]]:
    identity = _account_identity(row) or (
        site_change.review_identity(evidence.site.native, inputs.identifier)
        if evidence.site.native is not None
        else 0
    )
    return [
        {"label": "Site title", "value": inputs.title},
        {"label": "Administrator username", "value": inputs.admin_username},
        {"label": "Administrator email", "value": inputs.admin_email},
        {
            "label": "Administrator password",
            "value": (
                "Typed on this confirm screen and sent only over the confidential channel. "
                "It is never stored."
            ),
        },
        {
            "label": "Core release",
            "value": (
                f"WordPress {convention.CORE_VERSION} from {convention.CORE_ARCHIVE_URL} "
                f"({convention.CORE_ARCHIVE_SIZE} bytes, SHA-256 "
                f"{convention.CORE_ARCHIVE_SHA256})"
            ),
        },
        {
            "label": "Installed core",
            "value": (
                f"WordPress {version} is already installed; this review changes nothing."
                if installed
                else "The pinned release is installed as the site user."
            ),
        },
        {
            "label": "Database",
            "value": (
                f"{evidence.database.label}; {binding.name_of(inputs.identifier)} over the "
                "local socket; MariaDB unix_socket; no password."
                if evidence.database.engine
                else "No database engine is installed."
            ),
        },
        {
            "label": "Database statements",
            "value": "\n".join(f"{step} ({database or '—'})" for step, database, _t in statements)
            or "The convention's binding already exists.",
        },
        {"label": "Database steps present", "value": ", ".join(completed) or "None."},
        {"label": "Linux account", "value": f"s{inputs.identifier}"},
        {"label": "Numeric UID/GID", "value": str(identity)},
        {"label": "Site directory", "value": f"/var/www/{inputs.identifier}"},
        {
            "label": "Private configuration",
            "value": f"/var/www/{inputs.identifier}/private/wp-config.php (0600, site user)",
        },
        {
            "label": "HTTPS",
            "value": (
                "Caddy serves bare host names with automatic HTTPS (issuance and renewal)"
                if inputs.https
                else "HTTP only: the site file uses explicit http:// addresses"
            ),
        },
        {
            "label": "Gate",
            "value": ("The maintenance gate stays in place until the home and login pages answer."),
        },
    ]


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    inputs = decode_inputs(
        {
            key: document.get(key)
            for key in (
                "version",
                "selection",
                "identifier",
                "names",
                "https",
                "title",
                "admin_username",
                "admin_email",
            )
        },
        PHP_RUNTIMES,
        InputShape.WORDPRESS_CREATE,
    )
    settings = SiteSettings(inputs.identifier, inputs.names, inputs.selection, https=inputs.https)
    try:
        architecture = Architecture(str(document.get("architecture", "")))
    except ValueError:
        raise ValueError("The review has no supported catalog architecture.") from None
    engine = document.get("engine")
    if engine != binding.MARIADB:
        raise ValueError("The WordPress review names no MariaDB engine.")
    identity = document.get("identity")
    if type(identity) is not int or not 1000 <= identity < 30000:
        raise ValueError("The WordPress review has no reviewed identity.")
    completed = document.get("completed")
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or document.get("caddy") != render_wordpress_caddy(settings)
        or document.get("gate") != render_maintenance(settings)
        or document.get("pool") != render_pool(settings)
        or document.get("archive_url") != convention.CORE_ARCHIVE_URL
        or document.get("archive_size") != convention.CORE_ARCHIVE_SIZE
        or document.get("archive_sha256") != convention.CORE_ARCHIVE_SHA256
        or document.get("core_version") != convention.CORE_VERSION
        or document.get("runtime_arguments")
        != list(runtime_observation.read_arguments(inputs.selection, architecture))
        or not isinstance(completed, list)
        or not all(isinstance(step, str) for step in completed)
        or list(completed) != list(binding.steps_of(engine)[: len(completed)])
    ):
        raise ValueError("The WordPress review is not a valid immutable native selection.")
    expected = binding.statements(engine, binding.name_of(inputs.identifier))[len(completed) :]
    if document.get("statements") != [[s.step, s.database, s.text] for s in expected]:
        raise ValueError("The WordPress review is not the convention's statements.")
    provision.reviewed_probe(document, engine, inputs.identifier, identity)
    if document.get("existing") and (
        document.get("precondition_digest") is not None
        or document.get("proxy_identity") is not None
    ):
        raise ValueError("An existing site review names creation-only evidence.")
    if not document.get("existing"):
        proxy_identity = document.get("proxy_identity")
        if (
            type(proxy_identity) is not int
            or not 1000 <= proxy_identity < 30000
            or proxy_identity == identity
            or not isinstance(document.get("precondition_digest"), str)
            or not isinstance(document.get("disk_digest"), str)
        ):
            raise ValueError("The WordPress review has no valid creation evidence.")
    if (
        not context.secret_path
        or re.fullmatch(r"/run/barectl/secrets/[0-9a-f]{32}", context.secret_path) is None
    ):
        raise ValueError("The WordPress review needs a staged confidential value.")
    payload = {**document, "secret_path": context.secret_path}
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES.rstrip(b"\n"), (encoded,))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    from sites import observation as site_observation

    document = stored.document
    identifier = str(document.get("identifier", ""))
    selection = str(document.get("selection", ""))
    value = site_observation.read(shell, identifier, selection, site_only=True)
    if value is None:
        return None
    row = next((site for site in value["sites"] if site["identifier"] == identifier), None)
    if row is None or row["state"] != "complete" or row["application"] != "wordpress":
        return False
    if row["names"] != list(document.get("names", [])) or row["runtime"] != selection:
        return False
    engine = str(document.get("engine", ""))
    result = run_root(shell, binding.read_command(engine, binding.name_of(identifier)))
    if result.exit_status != 0 or result.truncated:
        return None
    try:
        facts = binding.parse_facts(engine, result.stdout)
    except ValueError:
        return False
    locale = binding.read_locale(result.stdout) if engine == binding.POSTGRESQL else ""
    return binding.recognize(engine, binding.name_of(identifier), facts, locale=locale).state == (
        "satisfied"
    )


CREATE_WORDPRESS: Final = ChangeKind(
    SLUG,
    LABEL,
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    writes_secrets=True,
    input_choices=PHP_RUNTIMES,
    input_shape=InputShape.WORDPRESS_CREATE,
)
