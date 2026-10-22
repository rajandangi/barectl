"""A site's database binding, reviewed and applied as part of creating an application.

The extension of ``documents/site.py`` to the create kinds of #382 and #380: they compose
the same #379 convention, so the database, principal, probe and reviewed statements live in
one place. Nothing here imports Django.
"""

import os
from dataclasses import dataclass

from discovery.root_read import run_root
from discovery.snapshot import CollectedSnapshot
from discovery.ssh import RemoteShell
from runtimes.catalog import Architecture, load

from . import binding
from . import observation as database_observation


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


def evidence(
    shell: RemoteShell,
    observed: CollectedSnapshot,
    architecture: Architecture | None,
    identifier: str,
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
    name = binding.name_of(identifier)
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


def environment_fields(evidence: DatabaseEvidence, identifier: str) -> dict[str, str]:
    if evidence.engine == binding.POSTGRESQL:
        connection, host, port = "pgsql", binding.POSTGRESQL_SOCKET_DIRECTORY, "5432"
        socket = ""
    else:
        connection, host, port = "mariadb", "localhost", "3306"
        socket = binding.MARIADB_SOCKET
    return {
        "connection": connection,
        "host": host,
        "port": port,
        "database": binding.name_of(identifier),
        "username": binding.name_of(identifier),
        "socket": socket,
    }


def statements(evidence: DatabaseEvidence, identifier: str) -> tuple[list[str], list[list[str]]]:
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


def refusals(
    evidence: DatabaseEvidence, identifier: str, *, subject: str = "a Laravel site"
) -> list[str]:
    refusals: list[str] = []
    if not evidence.engine:
        refusals.append(
            f"This server has no database engine. Install MariaDB or PostgreSQL from Server "
            f"Settings before creating {subject}."
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


def document(
    evidence: DatabaseEvidence,
    identifier: str,
    runtime: str,
    identity: int,
    *,
    if_ready: bool,
) -> dict[str, object]:
    """The reviewed binding fields; empty when a refusal already blocks the change."""
    if not evidence.engine or not if_ready:
        return {}
    name = binding.name_of(identifier)
    token = os.urandom(16).hex()
    probe_source = binding.render_probe(evidence.engine, name, token)
    pre, full = binding.expected_probe(evidence.engine, name, token, identity, identity)
    return {
        "token": token,
        "locale": evidence.locale,
        "fcgi_path": evidence.fcgi_path,
        "app_socket": binding.app_socket(identifier, runtime),
        "read_command": binding.read_command(evidence.engine, name),
        "catalog_digest": binding.digest(evidence.catalog_text),
        "probe_path": binding.probe_path(identifier, token),
        "probe_source": probe_source,
        "probe_sha256": binding.probe_digest(probe_source),
        "expected_pre": pre,
        "expected_full": full,
        **environment_fields(evidence, identifier),
    }


def reviewed_probe(
    document: dict[str, object], engine: str, identifier: str, identity: int
) -> None:
    """Refuse a review whose probe, digest or expectation changed."""
    name = binding.name_of(identifier)
    token = document.get("token")
    if not isinstance(token, str) or binding.TOKEN.fullmatch(token) is None:
        raise ValueError("The review has no database probe token.")
    probe = binding.render_probe(engine, name, token)
    if document.get("probe_source") != probe or document.get(
        "probe_sha256"
    ) != binding.probe_digest(probe):
        raise ValueError("The review's database probe changed.")
    pre, full = binding.expected_probe(engine, name, token, identity, identity)
    if document.get("expected_pre") != pre or document.get("expected_full") != full:
        raise ValueError("The review's database probe expectation changed.")
    if document.get("probe_path") != binding.probe_path(identifier, token):
        raise ValueError("The review's database probe path changed.")
    for key in ("catalog_digest",):
        digest = document.get(key)
        if not isinstance(digest, str) or not binding.DIGEST.fullmatch(digest):
            raise ValueError("The review has no valid database digest.")
    if document.get("read_command") != binding.read_command(engine, name):
        raise ValueError("The review's database catalog read changed.")
