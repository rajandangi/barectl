"""Give one site its database binding through the engine's four-member seam.

docs/databases.md, the phase specification's site-database bullet, ADR 0010
and ADR 0013. The database and principal are both named ``s<identifier>`` and authenticate
as the site's Linux user over the local socket, so no password exists. This kind creates the
binding for a plain PHP site from Site Settings > Database; a Laravel site consumes the same
convention from its own Create site change (#382).
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import os
import shlex
from dataclasses import dataclass
from typing import Final

from bootstrap.standing import Standing
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from runtimes.catalog import Architecture, architecture_of, load

from . import binding, observation

SLUG: Final = "add_site_database"
LABEL: Final = "Add site database"

BODY_SOURCE: Final = importlib.resources.files("databases.bodies").joinpath("site.py").read_text()
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
class SiteBindingEvidence:
    architecture: Architecture | None
    standing: Standing | None
    engine: str
    engine_managed: bool
    outside: tuple[str, ...]
    site: dict[str, object] | None
    runtime: str
    site_digest: str
    boot_id: str
    uptime_centiseconds: int | None
    catalog_text: str
    catalog_error: str


def _site_record(
    shell: RemoteShell, identifier: str
) -> tuple[dict[str, object] | None, str, str, int | None]:
    from sites import observation as site_observation

    listing = site_observation.read(shell, "observed", "", protections=False)
    if listing is None:
        return None, "", "", None
    record = next(
        (site for site in listing["sites"] if site["identifier"] == identifier),
        None,
    )
    if record is None:
        return None, "", "", None
    uptime = int(str(listing["uptime"]))
    return dict(record), str(record["runtime"]), str(listing["boot"]), uptime


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> SiteBindingEvidence:
    from discovery.observations import collect

    observed = collect(shell, sites=False)
    engine = ""
    engine_managed = False
    outside = observation.outside_supported_engines(observed)
    installed = observation.installed_engines(observed)
    if len(installed) == 1:
        engine = installed[0].engine
        engine_managed = installed[0].managed
    record, runtime, boot_id, uptime = _site_record(shell, inputs.identifier)
    site_digest = ""
    if record is not None and runtime:
        read = run_root(shell, binding.site_read_command(inputs.identifier, runtime))
        if read.exit_status == 0 and not read.truncated:
            site_digest = binding.digest(read.stdout)
    catalog_text = ""
    catalog_error = ""
    if engine:
        result = run_root(shell, binding.read_command(engine, binding.name_of(inputs.identifier)))
        if result.exit_status == 0 and not result.truncated:
            catalog_text = result.stdout
        else:
            catalog_error = "The database engine's catalog could not be read."
    return SiteBindingEvidence(
        architecture_of(observed.architecture.value or ""),
        observed.standing.standing if observed.standing else None,
        engine,
        engine_managed,
        outside,
        record,
        runtime,
        site_digest,
        boot_id,
        uptime,
        catalog_text,
        catalog_error,
    )


def _identity(record: dict[str, object] | None) -> tuple[int, int] | None:
    if record is None:
        return None
    account = record.get("account")
    if (
        isinstance(account, list)
        and len(account) == 5
        and type(account[0]) is int
        and type(account[1]) is int
    ):
        return account[0], account[1]
    return None


def _fcgi_path(architecture: Architecture) -> str:
    build = next(
        (candidate for candidate in load().offered(architecture) if candidate.entry == "fcgi"),
        None,
    )
    return build.path if build is not None else ""


def _binding(evidence: SiteBindingEvidence, identifier: str) -> tuple[binding.Binding | None, str]:
    if not evidence.catalog_text:
        return None, evidence.catalog_error
    try:
        facts = binding.parse_facts(evidence.engine, evidence.catalog_text)
    except ValueError as error:
        return None, str(error)
    locale = (
        binding.read_locale(evidence.catalog_text) if evidence.engine == binding.POSTGRESQL else ""
    )
    return binding.recognize(evidence.engine, identifier, facts, locale=locale), ""


def _platform_refusals(
    evidence: SiteBindingEvidence, identity: tuple[int, int] | None
) -> tuple[list[str], str]:
    engine = evidence.engine
    label = observation.specs()[engine].label if engine else "the database engine"
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before adding a site database.")
    if not engine:
        refusals.append(
            "This server has no database engine. Install MariaDB or PostgreSQL in Server "
            "Settings > Database first."
        )
    elif not evidence.engine_managed:
        refusals.append(f"{label} is Outside supported settings.")
    refusals.extend(evidence.outside)
    record = evidence.site
    if record is None or str(record.get("state", "")) != "complete":
        refusals.append("The site is not complete, so its database cannot be added.")
    if not evidence.runtime:
        refusals.append("The site's PHP master could not be read.")
    if identity is None:
        refusals.append("The site's Linux account could not be read.")
    if evidence.architecture is None or not _fcgi_path(evidence.architecture):
        refusals.append("The FastCGI client's native profile is unavailable.")
    return refusals, label


def _selection(
    engine: str, name: str, current: binding.Binding | None
) -> tuple[tuple[binding.Statement, ...], str, list[str]]:
    if current is None:
        return (), "", []
    if current.state == "custom":
        return (
            (),
            "",
            [
                (
                    f"The engine holds a binding for {name} that does not follow the "
                    "convention. Complete or remove it through ordinary administration first."
                )
            ],
        )
    if current.state == "satisfied":
        return (), f"{name} already exists and follows the convention.", []
    if engine == binding.POSTGRESQL and not current.locale:
        return (
            (),
            "",
            [
                (
                    "The engine's template database has no supported UTF-8 libc locale, so a "
                    "new database cannot be created with the convention."
                )
            ],
        )
    statements = binding.statements(engine, name, current.locale)[len(current.completed) :]
    return statements, "", []


def _document(
    evidence: SiteBindingEvidence,
    identifier: str,
    name: str,
    label: str,
    current: binding.Binding | None,
) -> dict[str, object]:
    architecture = evidence.architecture
    runtime = evidence.runtime
    return {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "engine": evidence.engine,
        "identifier": identifier,
        "principal": name,
        "architecture": str(architecture) if architecture is not None else "",
        "runtime": runtime,
        "app_socket": binding.app_socket(identifier, runtime) if runtime else "",
        "unit": binding.master_unit(identifier, runtime) if runtime else "",
        "fcgi_path": _fcgi_path(architecture) if architecture is not None else "",
        "locale": current.locale if current is not None else "",
        "site_read_command": binding.site_read_command(identifier, runtime) if runtime else "",
        "read_command": binding.read_command(evidence.engine, name) if evidence.engine else "",
        "completed": list(current.completed) if current is not None else [],
        "details": _details(identifier, name, evidence.engine, label, current),
    }


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, SiteBindingEvidence):
        raise ValueError("A site database needs native evidence.")
    identifier = inputs.identifier
    name = binding.name_of(identifier)
    identity = _identity(evidence.site)
    refusals, label = _platform_refusals(evidence, identity)
    current: binding.Binding | None = None
    catalog_error = ""
    if evidence.engine and identity is not None:
        current, catalog_error = _binding(evidence, identifier)
    statements: tuple[binding.Statement, ...] = ()
    note = ""
    if not refusals and catalog_error:
        refusals.append(catalog_error)
    elif not refusals:
        statements, note, extra = _selection(evidence.engine, name, current)
        refusals.extend(extra)
    document = _document(evidence, identifier, name, label, current)
    document["statements"] = [[s.step, s.database, s.text] for s in statements]
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals and statements:
        document["identity"] = list(identity) if identity else []
        document["catalog_digest"] = binding.digest(evidence.catalog_text)
        document["site_digest"] = evidence.site_digest
        document.update(_token_documents(evidence.engine, name, identity))
        effects = (
            DeclaredEffect(
                Scope.SITE,
                f"Create the {name} database and principal over the site's local socket; "
                "no password exists.",
                (identifier,),
            ),
        )
    stages = ("preflight", "probe", *[s.step for s in statements], "verify") if statements else ()
    return ReviewDraft(
        kind=SLUG,
        intent=f"Add the database for site {identifier}.",
        effects=effects,
        stages=stages,
        postconditions=(
            f"The {name} database and principal exist, authenticated as the site's Linux user.",
            "PHP under the site's own master connects through its driver.",
            "The principal holds all privileges on its own database and no other.",
        ),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        sites_read=binding.presence_command(identifier) if not refusals else "",
        current_sites=(identifier,) if not refusals else None,
        document={**document, "note": note},
    )


def _details(
    identifier: str,
    name: str,
    engine: str,
    label: str,
    current: binding.Binding | None,
) -> list[dict[str, str]]:
    details = [
        {"label": "Engine", "value": label},
        {"label": "Database", "value": name},
        {"label": "Principal", "value": f"{name} (via {_authentication(engine)})"},
        {"label": "Connection", "value": connection_string(engine, identifier)},
    ]
    if current is not None:
        details.append({"label": "Current state", "value": _state_text(current)})
    return details


def _state_text(current: binding.Binding) -> str:
    if current.state == "satisfied":
        return "The convention's database, principal and privileges exist."
    if current.state == "partial":
        created = ", ".join(current.completed) or "nothing"
        return f"Partly applied: {created} already exist."
    return "No convention binding exists."


def _authentication(engine: str) -> str:
    return "MariaDB unix_socket" if engine == binding.MARIADB else "PostgreSQL peer"


def connection_string(engine: str, identifier: str) -> str:
    name = binding.name_of(identifier)
    if engine == binding.MARIADB:
        return (
            f"DB_NAME={name} DB_USER={name} DB_PASSWORD= (empty) "
            f"DB_HOST=localhost:{binding.MARIADB_SOCKET}"
        )
    return (
        f"host={binding.POSTGRESQL_SOCKET_DIRECTORY} port={binding.POSTGRESQL_PORT} "
        f"dbname={name} user={name}"
    )


def _token_documents(engine: str, name: str, identity: tuple[int, int] | None) -> dict[str, object]:
    token = os.urandom(16).hex()
    probe = binding.render_probe(engine, name, token)
    uid, gid = identity or (0, 0)
    pre, full = binding.expected_probe(engine, name, token, uid, gid)
    return {
        "token": token,
        "probe_path": binding.probe_path(name.removeprefix("s"), token),
        "probe_source": probe,
        "probe_sha256": binding.probe_digest(probe),
        "expected_pre": pre,
        "expected_full": full,
    }


def _reviewed_fields(
    document: dict[str, object],
) -> tuple[str, str, str, str, int, int, str, Architecture]:
    from sites.names import valid_identifier

    engine = document.get("engine")
    identifier = document.get("identifier")
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or not isinstance(engine, str)
        or engine not in binding.ENGINES
        or not isinstance(identifier, str)
        or not valid_identifier(identifier)
    ):
        raise ValueError("Unsupported site database review.")
    name = binding.name_of(identifier)
    runtime = document.get("runtime")
    if runtime not in ("php84", "php85"):
        raise ValueError("The site database review has no supported PHP master.")
    identity = document.get("identity")
    if (
        not isinstance(identity, list)
        or len(identity) != 2
        or not all(type(value) is int and 1000 <= value < 30000 for value in identity)
    ):
        raise ValueError("The site database review has no reviewed identity.")
    try:
        catalog_architecture = Architecture(str(document.get("architecture")))
    except ValueError:
        raise ValueError("The site database review has no supported architecture.") from None
    fcgi = document.get("fcgi_path")
    if not isinstance(fcgi, str):
        raise ValueError("The site database review names no reviewed FastCGI client.")
    build = load().identify(catalog_architecture, fcgi)
    if build is None or build.entry != "fcgi":
        raise ValueError("The site database review names no reviewed FastCGI client.")
    return (
        engine,
        identifier,
        name,
        str(runtime),
        int(identity[0]),
        int(identity[1]),
        fcgi,
        catalog_architecture,
    )


def _reviewed_statements(
    document: dict[str, object], engine: str, name: str
) -> tuple[list[str], list[list[str]]]:
    review_locale = document.get("locale", "")
    if review_locale not in ("", *binding.POSTGRESQL_LOCALES):
        raise ValueError("The site database review has no reviewed locale.")
    expected = binding.statements(engine, name, str(review_locale))
    completed = document.get("completed")
    if (
        not isinstance(completed, list)
        or not all(isinstance(step, str) for step in completed)
        or list(completed) != list(binding.steps_of(engine)[: len(completed)])
    ):
        raise ValueError("The site database review is not a convention prefix.")
    rest = expected[len(completed) :]
    statements = document.get("statements")
    if not isinstance(statements, list) or statements != [
        [s.step, s.database, s.text] for s in rest
    ]:
        raise ValueError("The site database review is not the convention's statements.")
    return [str(step) for step in completed], statements


def _reviewed_probe(
    document: dict[str, object], engine: str, name: str, identifier: str, uid: int, gid: int
) -> tuple[str, str]:
    token = document.get("token")
    if not isinstance(token, str) or binding.TOKEN.fullmatch(token) is None:
        raise ValueError("The site database review has no probe token.")
    probe = binding.render_probe(engine, name, token)
    if (
        document.get("probe_source") != probe
        or document.get("probe_sha256") != binding.probe_digest(probe)
        or document.get("probe_path") != binding.probe_path(identifier, token)
    ):
        raise ValueError("The site database probe changed.")
    pre, full = binding.expected_probe(engine, name, token, uid, gid)
    if document.get("expected_pre") != pre or document.get("expected_full") != full:
        raise ValueError("The site database probe expectation changed.")
    return pre, full


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    engine, identifier, name, runtime, uid, gid, fcgi, _architecture = _reviewed_fields(document)
    _completed, statements = _reviewed_statements(document, engine, name)
    if document.get("read_command") != binding.read_command(engine, name):
        raise ValueError("The site database catalog read changed.")
    if document.get("site_read_command") != binding.site_read_command(identifier, runtime):
        raise ValueError("The site database identity read changed.")
    app_socket = binding.app_socket(identifier, runtime)
    if document.get("app_socket") != app_socket or document.get("unit") != binding.master_unit(
        identifier, runtime
    ):
        raise ValueError("The site database review names no reviewed site master.")
    _reviewed_probe(document, engine, name, identifier, uid, gid)
    for key in ("site_digest", "catalog_digest"):
        value = document.get(key)
        if not isinstance(value, str) or not binding.DIGEST.fullmatch(value):
            raise ValueError("The site database review has no valid digest.")
    payload = {
        "engine": engine,
        "identifier": identifier,
        "principal": name,
        "fcgi_path": fcgi,
        "app_socket": app_socket,
        "site_read_command": document["site_read_command"],
        "site_digest": document["site_digest"],
        "read_command": document["read_command"],
        "catalog_digest": document["catalog_digest"],
        "statements": statements,
        "probe_path": document["probe_path"],
        "probe_source": document["probe_source"],
        "probe_sha256": document["probe_sha256"],
        "expected_pre": document["expected_pre"],
        "expected_full": document["expected_full"],
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES.rstrip(b"\n"), (encoded,))


def verify(shell: RemoteShell, review: ChangeReview) -> bool | None:
    body(review.document, BodyContext("", "", 0))
    engine = str(review.document["engine"])
    identifier = str(review.document["identifier"])
    name = binding.name_of(identifier)
    result = run_root(shell, binding.read_command(engine, name))
    if result.exit_status != 0 or result.truncated:
        return None
    bind = _recognize(engine, identifier, result.stdout)
    return bind is not None and bind.state == "satisfied"


def _recognize(engine: str, identifier: str, text: str) -> binding.Binding | None:
    try:
        facts = binding.parse_facts(engine, text)
    except ValueError:
        return None
    locale = binding.read_locale(text) if engine == binding.POSTGRESQL else ""
    return binding.recognize(engine, identifier, facts, locale=locale)


ADD_SITE_DATABASE: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    refresh_discovery=True,
    input_shape=InputShape.SITE_DATABASE,
)
