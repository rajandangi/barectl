"""Create a Laravel site as one reviewed change (Phase B #382, ADR 0019 amended).

The change builds the site and its database (composed from #379's site-database convention),
writes a private ``.env`` from Laravel's production defaults with a server-generated
``APP_KEY``, and — for an SSH repository — generates an ed25519 deploy key as the site user
and trusts the repository host key only by an exact fingerprint match (ADR 0034). No private
key and no ``.env`` value ever reaches the controller.
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import os
import re
import secrets
import shlex
from dataclasses import dataclass
from typing import Final

from databases import binding
from databases import observation as database_observation
from discovery.root_read import run_root
from discovery.snapshot import CollectedSnapshot
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import (
    InputShape,
    PreparationInputs,
    decode_inputs,
    valid_release_name,
)
from operations.models import ChangeReview
from runtimes import observation as runtime_observation
from runtimes.catalog import Architecture, architecture_of, load
from sites import change as site_change
from sites.configuration import PHP_RUNTIMES, SiteSettings, render_caddy, render_pool

from . import observation
from .configuration import (
    APP_KEY_PLACEHOLDER,
    render_environment,
    repository_locator,
    repository_ref,
)

SLUG: Final = "create_laravel_site"
LABEL: Final = "Create Laravel site"

_DATABASE_SOURCE: Final = (
    importlib.resources.files("databases.bodies").joinpath("site.py").read_text()
)
BODY_SOURCE: Final = (
    observation.LARAVEL_SOURCE.replace(
        'RUNTIME_READ_SOURCE = ""', "RUNTIME_READ_SOURCE = " + repr(runtime_observation.READ_SOURCE)
    )
    + "\n"
    + importlib.resources.files("laravel.bodies")
    .joinpath("create.py")
    .read_text()
    .replace(
        "from laravel.bodies.common import (\n"
        "    classify,\n"
        "    laravel_paths,\n"
        "    link_shared,\n"
        "    switch_current,\n"
        "    user_command,\n"
        ")\n",
        "",
    )
    .replace(
        "from sites.bodies.common import (\n"
        "    caddy_file,\n"
        "    configure_pool,\n"
        "    create_account,\n"
        "    create_layout,\n"
        "    identity_name_exists,\n"
        "    pool_file,\n"
        "    publish_caddy,\n"
        "    result,\n"
        "    runtime_admission,\n"
        "    setting,\n"
        "    stage,\n"
        "    validate_candidate,\n"
        "    validate_pool_candidate,\n"
        "    verify_http,\n"
        "    write_new,\n"
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

STAGES: Final = (
    "preflight",
    "account",
    "layout",
    "pool",
    "caddy",
    "laravel",
    "principal",
    "database",
    "privileges",
    "schema",
    "verify",
)

_SSH_HOST: Final = re.compile(r"[A-Za-z0-9._-]{1,64}@(?P<host>[A-Za-z0-9.-]+):(?P<path>.+)\Z")


@dataclass(frozen=True)
class DatabaseEvidence:
    engine: str
    label: str
    managed: bool
    outside: tuple[str, ...]
    current: binding.Binding | None
    locale: str
    catalog_text: str
    catalog_error: str
    fcgi_path: str


@dataclass(frozen=True)
class LaravelEvidence:
    site: site_change.SiteEvidence
    database: DatabaseEvidence
    host_keys: tuple[str, ...]
    host_problem: str


def _host_of(locator: str) -> str:
    match = _SSH_HOST.fullmatch(locator)
    return match.group("host") if match is not None else ""


def _host_keys(shell: RemoteShell, locator: str, fingerprint: str) -> tuple[tuple[str, ...], str]:
    """The repository host key lines whose fingerprint matches the operator's exactly."""
    if locator.startswith("https://"):
        return (), ""
    host = _host_of(locator)
    if not host or not fingerprint:
        return (), "The repository host or its fingerprint is missing."
    command = (
        "ssh-keyscan -T 5 "
        + shlex.quote(host)
        + " | while IFS= read -r line; do "
        + "printf '%s\\t%s\\n' \"$(printf '%s\\n' \"$line\" | ssh-keygen -lf - | cut -d' ' -f2)\" "
        + '"$line"; done'
    )
    result = run_root(shell, command)
    if result.exit_status != 0 or result.truncated:
        return (), "The repository host key could not be read."
    matched = [
        line.partition("\t")[2]
        for line in result.stdout.splitlines()
        if line.partition("\t")[0] == fingerprint
    ]
    if not matched:
        return (), (
            "The repository host key does not match the fingerprint you pasted. Barectl "
            "trusts only a key whose fingerprint matches exactly; check the fingerprint "
            "and prepare this review again."
        )
    return tuple(sorted(matched)), ""


def _database_evidence(
    shell: RemoteShell, observed: CollectedSnapshot, architecture: Architecture | None, name: str
) -> DatabaseEvidence:
    installed = database_observation.installed_engines(observed)
    outside = database_observation.outside_supported_engines(observed)
    engine = installed[0].engine if len(installed) == 1 else ""
    managed = installed[0].managed if len(installed) == 1 else False
    label = database_observation.specs()[engine].label if engine else "the database engine"
    fcgi = ""
    if architecture is not None:
        build = next(
            (candidate for candidate in load().offered(architecture) if candidate.entry == "fcgi"),
            None,
        )
        fcgi = build.path if build is not None else ""
    catalog_text = ""
    catalog_error = ""
    current: binding.Binding | None = None
    locale = ""
    if engine:
        result = run_root(shell, binding.read_command(engine, name))
        if result.exit_status == 0 and not result.truncated:
            catalog_text = result.stdout
            try:
                facts = binding.parse_facts(engine, catalog_text)
            except ValueError as error:
                catalog_error = str(error)
            else:
                locale = binding.read_locale(catalog_text) if engine == binding.POSTGRESQL else ""
                current = binding.recognize(engine, name, facts, locale=locale)
        else:
            catalog_error = "The database engine's catalog could not be read."
    return DatabaseEvidence(
        engine, label, managed, outside, current, locale, catalog_text, catalog_error, fcgi
    )


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> LaravelEvidence:
    from discovery.observations import collect

    site = site_change.inspect(shell, inputs)
    snapshot = collect(shell, sites=False)
    architecture = architecture_of(snapshot.architecture.value or "")
    name = binding.name_of(inputs.identifier)
    database = _database_evidence(shell, snapshot, architecture, name)
    host_keys: tuple[str, ...] = ()
    host_problem = ""
    if inputs.repository and not inputs.repository.startswith("https://"):
        host_keys, host_problem = _host_keys(shell, inputs.repository, inputs.fingerprint)
    return LaravelEvidence(site, database, host_keys, host_problem)


def _environment_fields(database: DatabaseEvidence, inputs: PreparationInputs) -> dict[str, str]:
    if database.engine == binding.POSTGRESQL:
        connection, host, port = "pgsql", binding.POSTGRESQL_SOCKET_DIRECTORY, "5432"
        socket = ""
    else:
        connection, host, port = "mariadb", "localhost", "3306"
        socket = binding.MARIADB_SOCKET
    return {
        "connection": connection,
        "host": host,
        "port": port,
        "database": binding.name_of(inputs.identifier),
        "username": binding.name_of(inputs.identifier),
        "socket": socket,
    }


def _app_url(inputs: PreparationInputs) -> str:
    scheme = "https" if inputs.https else "http"
    return f"{scheme}://{inputs.names[0]}" if inputs.names else ""


def _reviewed_environment(evidence: LaravelEvidence, inputs: PreparationInputs) -> str:
    return render_environment(
        app_url=_app_url(inputs),
        app_key=APP_KEY_PLACEHOLDER,
        **_environment_fields(evidence.database, inputs),
    )


def _statements(evidence: DatabaseEvidence, identifier: str) -> tuple[list[str], list[list[str]]]:
    """The convention's remaining statements and the steps already present, or a refusal."""
    name = binding.name_of(identifier)
    current = evidence.current
    if current is None:
        completed: tuple[str, ...] = ()
    elif current.state == "satisfied":
        return [], []
    else:
        completed = current.completed
    remaining = binding.statements(evidence.engine, name, evidence.locale)[len(completed) :]
    return [str(step) for step in completed], [[s.step, s.database, s.text] for s in remaining]


def _database_refusals(evidence: DatabaseEvidence, identifier: str) -> list[str]:
    refusals: list[str] = []
    if not evidence.engine:
        refusals.append(
            "This server has no database engine. Install MariaDB or PostgreSQL from Server "
            "Settings before creating a Laravel site."
        )
        return refusals
    if not evidence.managed:
        refusals.append(f"{evidence.label} is Outside supported settings.")
    refusals.extend(evidence.outside)
    if evidence.catalog_error:
        refusals.append(evidence.catalog_error)
        return refusals
    if not evidence.fcgi_path:
        refusals.append("The FastCGI client's native profile is unavailable.")
    current = evidence.current
    if current is not None and current.state == "custom":
        refusals.append(
            f"The engine holds a binding for {binding.name_of(identifier)} that does not "
            "follow the convention. Complete or remove it through ordinary administration first."
        )
        return refusals
    if evidence.engine == binding.POSTGRESQL and current is not None and not evidence.locale:
        refusals.append(
            "The engine's template database has no supported UTF-8 libc locale, so a new "
            "database cannot be created with the convention."
        )
    return refusals


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, LaravelEvidence):
        raise ValueError("Laravel creation needs native evidence.")
    settings = SiteSettings(inputs.identifier, inputs.names, inputs.selection, https=inputs.https)
    refusals: list[str] = list(site_change.runtime_refusals(evidence.site, settings))
    try:
        locator = repository_locator(inputs.repository)
        ref = repository_ref(inputs.branch)
        fingerprint = inputs.fingerprint
    except ValueError as error:
        raise ValueError(str(error)) from None
    refusals.extend(_database_refusals(evidence.database, inputs.identifier))
    if evidence.host_problem:
        refusals.append(evidence.host_problem)
    native = evidence.site.native
    if native is None:
        refusals.append(
            "Site files, accounts or Caddy's running configuration are unreadable or unsupported."
        )
    completed, statements = _statements(evidence.database, inputs.identifier)
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": inputs.identifier,
        "names": list(inputs.names),
        "selection": inputs.selection,
        "https": inputs.https,
        "repository": locator,
        "branch": ref,
        "fingerprint": fingerprint,
        "ssh": not locator.startswith("https://"),
        "host_keys": list(evidence.host_keys),
        "app_url": _app_url(inputs),
        "environment": _reviewed_environment(evidence, inputs),
        "engine": evidence.database.engine,
        "principal": binding.name_of(inputs.identifier),
        "release": "bootstrap-" + secrets.token_hex(8),
        "completed": completed,
        "statements": statements,
    }
    document.update(site_change.runtime_document(evidence.site, inputs))
    current: tuple[str, ...] = ()
    existing = False
    if native is not None:
        current = tuple(str(site) for site in native["current_sites"])
        existing, collisions = site_change.existing_site(native, inputs)
        refusals.extend(collisions)
        identity = site_change.review_identity(native, inputs.identifier)
        document.update(
            precondition_digest=native["digest"],
            disk_digest=native["disk_digest"],
            identity=identity,
            proxy_identity=native["next_proxy_id"],
            caddy=render_caddy(settings),
            pool=render_pool(settings),
            membership={settings.runtime: list(current)},
        )
        document.update(_database_document(evidence.database, inputs, identity, refusals))
        document["details"] = _details(evidence, inputs, statements, completed, locator, ref)
    effects = (
        ()
        if refusals or existing
        else (
            DeclaredEffect(
                Scope.SITE,
                f"Create Laravel site {inputs.identifier}, its database and its private "
                "environment.",
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
    )
    return ReviewDraft(
        SLUG,
        f"Create Laravel site {inputs.identifier} from {locator}.",
        effects=effects,
        stages=STAGES,
        postconditions=(
            "The site, its database and its private environment exist.",
            f"The site's first release carries {locator} on {ref}.",
            "The site answers its placeholder over its own address.",
        ),
        refusals=tuple(refusals),
        boot_id=str(native["boot"]) if native else "",
        uptime_centiseconds=int(str(native["uptime"])) if native else None,
        sites_read=site_change.membership_command(inputs.selection)
        if native and native["master_present"]
        else "",
        current_sites=current if native and native["master_present"] else None,
        document=document,
    )


def _database_document(
    evidence: DatabaseEvidence,
    inputs: PreparationInputs,
    identity: int,
    refusals: list[str],
) -> dict[str, object]:
    if refusals or not evidence.engine:
        return {}
    name = binding.name_of(inputs.identifier)
    token = os.urandom(16).hex()
    probe_source = binding.render_probe(evidence.engine, name, token)
    pre, full = binding.expected_probe(evidence.engine, name, token, identity, identity)
    return {
        "token": token,
        "locale": evidence.locale,
        "fcgi_path": evidence.fcgi_path,
        "app_socket": binding.app_socket(inputs.identifier, inputs.selection),
        "read_command": binding.read_command(evidence.engine, name),
        "catalog_digest": binding.digest(evidence.catalog_text),
        "probe_path": binding.probe_path(inputs.identifier, token),
        "probe_source": probe_source,
        "probe_sha256": binding.probe_digest(probe_source),
        "expected_pre": pre,
        "expected_full": full,
        **_environment_fields(evidence, inputs),
    }


def _details(
    evidence: LaravelEvidence,
    inputs: PreparationInputs,
    statements: list[list[str]],
    completed: list[str],
    locator: str,
    ref: str,
) -> list[dict[str, str]]:
    identity = (
        site_change.review_identity(evidence.site.native, inputs.identifier)
        if evidence.site.native is not None
        else 0
    )
    details = [
        {"label": "Repository", "value": locator},
        {"label": "Branch or tag", "value": ref},
        {
            "label": "Deploy key",
            "value": (
                "An ed25519 key pair is generated on the server as the site user; only its "
                "public half is shown."
                if not locator.startswith("https://")
                else "Not needed: a public https:// repository authenticates its host with TLS."
            ),
        },
        {
            "label": "Repository host key",
            "value": "\n".join(evidence.host_keys) or "Trusted through TLS.",
        },
        {"label": "Application URL", "value": _app_url(inputs)},
        {
            "label": "Database",
            "value": (
                f"{evidence.database.label}; {binding.name_of(inputs.identifier)} over the "
                "local socket; no password."
                if evidence.database.engine
                else "No database engine is installed."
            ),
        },
        {
            "label": "Database statements",
            "value": "\n".join(f"{step} ({database or '—'})" for step, database, _t in statements)
            or "The convention's binding already exists.",
        },
        {
            "label": "Database steps present",
            "value": ", ".join(completed) or "None.",
        },
        {"label": "Linux account", "value": f"s{inputs.identifier}"},
        {"label": "Numeric UID/GID", "value": str(identity)},
        {"label": "Site directory", "value": f"/var/www/{inputs.identifier}"},
    ]
    if evidence.site.native is not None:
        details += [
            {
                "label": "First release",
                "value": "releases/initial with the reviewed Git metadata; current symlink",
            },
            {"label": "Caddy validation", "value": evidence.site.native["validation"]},
            {
                "label": "PHP pool scratch validation",
                "value": evidence.site.native["pool_validation"],
            },
        ]
    return details


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
                "repository",
                "branch",
                "fingerprint",
            )
        },
        PHP_RUNTIMES,
        InputShape.LARAVEL_CREATE,
    )
    settings = SiteSettings(inputs.identifier, inputs.names, inputs.selection, https=inputs.https)
    try:
        architecture = Architecture(str(document.get("architecture", "")))
    except ValueError:
        raise ValueError("The review has no supported catalog architecture.") from None
    engine = document.get("engine")
    if not isinstance(engine, str) or engine not in binding.ENGINES:
        raise ValueError("The Laravel review names no supported database engine.")
    name = binding.name_of(inputs.identifier)
    identity = document.get("identity")
    proxy_identity = document.get("proxy_identity")
    completed = document.get("completed")
    locale = str(document.get("locale", ""))
    if locale not in ("", *binding.POSTGRESQL_LOCALES):
        raise ValueError("The Laravel review has no reviewed locale.")
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or document.get("repository") != repository_locator(inputs.repository)
        or document.get("branch") != repository_ref(inputs.branch)
        or document.get("caddy") != render_caddy(settings)
        or document.get("pool") != render_pool(settings)
        or document.get("runtime_arguments")
        != list(runtime_observation.read_arguments(inputs.selection, architecture))
        or not isinstance(document.get("release"), str)
        or not valid_release_name(str(document.get("release")))
        or document.get("read_command") != binding.read_command(engine, name)
        or document.get("app_socket") != binding.app_socket(inputs.identifier, inputs.selection)
        or type(identity) is not int
        or not 1000 <= identity < 30000
        or type(proxy_identity) is not int
        or not 1000 <= proxy_identity < 30000
        or proxy_identity == identity
        or not isinstance(completed, list)
        or not all(isinstance(step, str) for step in completed)
        or list(completed) != list(binding.steps_of(engine)[: len(completed)])
    ):
        raise ValueError("The Laravel review is not a valid immutable native selection.")
    expected = binding.statements(engine, name, locale)[len(completed) :]
    statements = document.get("statements")
    if statements != [[s.step, s.database, s.text] for s in expected]:
        raise ValueError("The Laravel review is not the convention's statements.")
    if document.get("environment") != render_environment(
        app_url=str(document.get("app_url", "")),
        app_key=APP_KEY_PLACEHOLDER,
        connection=str(document.get("connection", "")),
        host=str(document.get("host", "")),
        port=str(document.get("port", "")),
        database=str(document.get("database", "")),
        username=str(document.get("username", "")),
        socket=str(document.get("socket", "")),
    ):
        raise ValueError("The reviewed Laravel environment changed.")
    _reviewed_probe(document, engine, name, identity)
    for key in ("catalog_digest",):
        digest = document.get(key)
        if not isinstance(digest, str) or not binding.DIGEST.fullmatch(digest):
            raise ValueError("The Laravel review has no valid database digest.")
    encoded = base64.b64encode(gzip.compress(json.dumps(document).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES.rstrip(b"\n"), (encoded,))


def _reviewed_probe(document: dict[str, object], engine: str, name: str, identity: int) -> None:
    token = document.get("token")
    if not isinstance(token, str) or binding.TOKEN.fullmatch(token) is None:
        raise ValueError("The Laravel review has no probe token.")
    probe = binding.render_probe(engine, name, token)
    if document.get("probe_source") != probe or document.get(
        "probe_sha256"
    ) != binding.probe_digest(probe):
        raise ValueError("The Laravel review's database probe changed.")
    pre, full = binding.expected_probe(engine, name, token, identity, identity)
    if document.get("expected_pre") != pre or document.get("expected_full") != full:
        raise ValueError("The Laravel review's database probe expectation changed.")


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    document = stored.document
    engine = str(document.get("engine", ""))
    identifier = str(document.get("identifier", ""))
    name = binding.name_of(identifier)
    result = run_root(shell, binding.read_command(engine, name))
    if result.exit_status != 0 or result.truncated:
        return None
    try:
        facts = binding.parse_facts(engine, result.stdout)
    except ValueError:
        return False
    locale = binding.read_locale(result.stdout) if engine == binding.POSTGRESQL else ""
    if binding.recognize(engine, name, facts, locale=locale).state != "satisfied":
        return False
    laravel = observation.read(shell)
    if laravel is None:
        return None
    row = observation.site(laravel, identifier)
    if row is None or row["application"] != "laravel":
        return False
    if row["repository"] != document.get("repository") or row["branch"] != document.get("branch"):
        return False
    shared = row["shared"]
    return isinstance(shared, dict) and all(bool(flag) for flag in shared.values())


CREATE_LARAVEL: Final = ChangeKind(
    SLUG,
    LABEL,
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_choices=PHP_RUNTIMES,
    input_shape=InputShape.LARAVEL_CREATE,
)
