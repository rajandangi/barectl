"""Remove a site and every resource of its convention through the engine's four members.

docs/sites.md, the Phase B removal bullet and ADR 0035. The review lists the Caddy file,
services, FPM and HAProxy configuration, database and principal, stored certificate,
directory and accounts, states that no backup exists before Phase D, and needs Destructive
consent. The native body gates the site, removes exactly those resources in the reviewed
order and proves that nothing of it remains while the other sites keep serving. A failure
reports partly applied; a fresh review proposes only what remains.
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import re
import shlex
from dataclasses import dataclass
from typing import Final, cast

from bootstrap.standing import Standing
from databases import binding, provision
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from runtimes.catalog import Architecture, architecture_of

from . import observation
from .configuration import PHP_RUNTIMES
from .names import canonical_name, valid_identifier

SLUG: Final = "remove_site"
LABEL: Final = "Remove site"
STAGES: Final = (
    "preflight",
    "gate",
    "caddy",
    "services",
    "configuration",
    "database",
    "certificate",
    "files",
    "accounts",
    "verify",
)

_BINDING_SOURCE: Final = importlib.resources.files("databases").joinpath("binding.py").read_text()
_REMOVE_TEXT: Final = importlib.resources.files("sites.bodies").joinpath("remove.py").read_text()
_CORE_SOURCE: Final = re.sub(
    r"from sites\.bodies\.common import \([^)]*\)\n", "", _REMOVE_TEXT, count=1
).replace("from sites.bodies.admission import haproxy_state\n", "")
REMOVAL_SOURCE: Final = observation.COMMON_SOURCE + "\n" + _CORE_SOURCE
READ_SOURCE: Final = REMOVAL_SOURCE + "\nprint(canonical(inventory(sys.argv[1])))\n"
BODY_SOURCE: Final = (
    REMOVAL_SOURCE.replace('BINDING_SOURCE = ""', "BINDING_SOURCE = " + repr(_BINDING_SOURCE))
    + "\nraise SystemExit(main(sys.argv))\n"
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

NO_BACKUP: Final = (
    "No backup exists. Phase D adds backups; this removal deletes files, the database and "
    "its data, and the certificate, and none of it can be recovered."
)


@dataclass(frozen=True)
class RemovalEvidence:
    architecture: Architecture | None
    standing: Standing | None
    inventory: dict[str, object] | None
    inventory_problem: str
    database: provision.DatabaseEvidence


def read_command(identifier: str) -> str:
    if not valid_identifier(identifier):
        raise ValueError("Not a site identifier.")
    command = observation.python_command(READ_SOURCE, (identifier,))
    return "sh -c " + shlex.quote("; ".join([*native.read_lock_steps(), "exec " + command]))


def _account(value: object, *, expected_home: str, expected_shell: str) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 5
        and type(value[0]) is int
        and type(value[1]) is int
        and 1000 <= value[0] < 30000
        and value[0] == value[1]
        and value[2] == expected_home
        and value[3] == expected_shell
        and isinstance(value[4], list)
        and value[4] == [value[1]]
    )


def _group(value: object) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 2
        and type(value[0]) is int
        and 1000 <= value[0] < 30000
        and isinstance(value[1], list)
        and value[1] == []
    )


def _digest(value: object, *, empty: bool = False) -> bool:
    if not isinstance(value, str):
        return False
    return (empty and value == "") or re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _identifier_list(value: object) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= 64
        and all(isinstance(item, str) and valid_identifier(item) for item in value)
        and list(value) == sorted(set(value))
    )


def valid_inventory(value: object, identifier: str) -> bool:  # noqa: C901 - a closed shape
    if not isinstance(value, dict) or set(value) != {
        "version",
        "identifier",
        "boot",
        "uptime",
        "paths",
        "names",
        "https",
        "runtime",
        "problem",
        "site_file_digest",
        "account",
        "proxy_account",
        "account_group",
        "proxy_group",
        "certificates",
        "services",
        "other_sites",
        "caddy_matches",
        "caddy_data_directory",
        "digest",
    }:
        return False
    if value["version"] != 1 or value["identifier"] != identifier:
        return False
    if (
        not isinstance(value["boot"], str)
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value["boot"]
        )
        is None
        or type(value["uptime"]) is not int
        or value["uptime"] < 0
    ):
        return False
    paths = value["paths"]
    if (
        not isinstance(paths, dict)
        or len(paths) != 12
        or not all(
            isinstance(path, str) and type(present) is bool for path, present in paths.items()
        )
    ):
        return False
    names = value["names"]
    if (
        not isinstance(names, list)
        or len(names) > 10
        or not all(isinstance(name, str) and canonical_name(name)[1] == "" for name in names)
        or len(set(names)) != len(names)
    ):
        return False
    if type(value["https"]) is not bool or value["runtime"] not in ("", *PHP_RUNTIMES):
        return False
    if not isinstance(value["problem"], str) or len(value["problem"]) > 500:
        return False
    if not _digest(value["site_file_digest"], empty=True):
        return False
    if value["account"] is not None and not isinstance(value["account"], list):
        return False
    if value["proxy_account"] is not None and not isinstance(value["proxy_account"], list):
        return False
    if value["account_group"] is not None and not isinstance(value["account_group"], list):
        return False
    if value["proxy_group"] is not None and not isinstance(value["proxy_group"], list):
        return False
    certificates = value["certificates"]
    if not isinstance(certificates, list) or len(certificates) > 64:
        return False
    if not isinstance(value["caddy_data_directory"], str) or not value[
        "caddy_data_directory"
    ].startswith("/"):
        return False
    if not all(
        isinstance(path, str) and path.startswith(value["caddy_data_directory"] + "/certificates/")
        for path in certificates
    ):
        return False
    services = value["services"]
    if (
        not isinstance(services, dict)
        or len(services) != 4
        or not all(
            isinstance(unit, str)
            and unit.endswith(".service")
            and isinstance(state, list)
            and len(state) == 3
            and all(isinstance(item, str) for item in state)
            for unit, state in services.items()
        )
    ):
        return False
    if not _identifier_list(value["other_sites"]):
        return False
    if type(value["caddy_matches"]) is not bool or not isinstance(
        value["caddy_data_directory"], str
    ):
        return False
    return _digest(value["digest"])


def _read_inventory(shell: RemoteShell, identifier: str) -> tuple[dict[str, object] | None, str]:
    result = run_root(shell, read_command(identifier))
    if result.exit_status != 0 or result.truncated:
        return None, "The site's native artifacts could not be read."
    try:
        value: object = json.loads(result.stdout)
    except ValueError:
        return None, "The site's native artifacts are not in the supported form."
    if not valid_inventory(value, identifier):
        return None, "The site's native artifacts are not in the supported form."
    return cast("dict[str, object]", value), ""


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> RemovalEvidence:
    from discovery.observations import collect

    snapshot = collect(shell, sites=False)
    architecture = architecture_of(snapshot.architecture.value or "")
    inventory, problem = _read_inventory(shell, inputs.identifier)
    database = provision.evidence(shell, snapshot, architecture, inputs.identifier)
    return RemovalEvidence(
        architecture,
        snapshot.standing.standing if snapshot.standing else None,
        inventory,
        problem,
        database,
    )


def presence_command(identifier: str) -> str:
    if not valid_identifier(identifier):
        raise ValueError("Not a site identifier.")
    return (
        f"if [ -e /etc/caddy/sites/{identifier}.caddy ] || [ -d /var/www/{identifier} ] "
        f"|| getent passwd s{identifier} >/dev/null 2>&1 "
        f"|| getent passwd p{identifier} >/dev/null 2>&1 "
        f"|| getent group s{identifier} >/dev/null 2>&1 "
        f"|| getent group p{identifier} >/dev/null 2>&1 "
        f"|| [ -e /etc/haproxy/sites/{identifier}.cfg ] "
        f"|| [ -d /etc/php-fpm/sites/{identifier} ]; "
        f"then printf '%s\\n' {identifier}; fi"
    )


def _names(inventory: dict[str, object], inputs: PreparationInputs) -> tuple[str, ...]:
    names = inventory["names"]
    if not isinstance(names, list):
        names = []
    observed = tuple(str(name) for name in names)
    if observed:
        return observed
    return (inputs.primary,) if inputs.primary else ()


def _database_refusals(evidence: RemovalEvidence, identifier: str) -> tuple[list[str], bool]:
    database = evidence.database
    if not database.engine:
        return [], False
    refusals: list[str] = []
    if not database.managed:
        refusals.append(f"{database.label} is Outside supported settings.")
    refusals.extend(database.outside)
    if database.catalog_error:
        refusals.append(database.catalog_error)
    current = database.current
    if current is not None and current.state == "custom":
        refusals.append(
            f"The engine holds a binding for {binding.name_of(identifier)} that does not "
            "follow the convention. Remove it through ordinary administration first."
        )
    return refusals, current is not None and current.state in ("partial", "satisfied")


def _database_document(
    evidence: RemovalEvidence, identifier: str, exists: bool
) -> dict[str, object]:
    database = evidence.database
    name = binding.name_of(identifier)
    value: dict[str, object] = {
        "engine": database.engine,
        "label": database.label,
        "name": name,
        "exists": exists,
        "state": database.current.state if database.current is not None else "absent",
        "read_command": binding.read_command(database.engine, name) if database.engine else "",
        "catalog_digest": binding.digest(database.catalog_text),
        "statements": [
            [statement.step, statement.database, statement.text]
            for statement in (binding.drop_statements(database.engine, name) if exists else ())
        ],
    }
    return value


def _deleted_paths(inventory: dict[str, object]) -> list[str]:
    paths = inventory["paths"]
    if not isinstance(paths, dict):
        return []
    return [f"{path} (already absent)" if not present else path for path, present in paths.items()]


def _effects(identifier: str, primary: str) -> tuple[DeclaredEffect, ...]:
    return (
        DeclaredEffect(
            Scope.SITE,
            (
                f"Delete site {primary}: its Caddy file, services, PHP-FPM, HAProxy and object "
                "cache configuration, database and principal, stored certificate, directory "
                "and accounts. The database and every site file are destroyed."
            ),
            (identifier,),
            destroys_data=True,
        ),
        DeclaredEffect(
            Scope.SHARED,
            (
                "Caddy reloads its configuration for every site; the other sites keep "
                "serving and no other site's PHP master or HAProxy process restarts."
            ),
        ),
    )


def _details(
    inventory: dict[str, object], database: dict[str, object], primary: str
) -> list[dict[str, str]]:
    raw_names = inventory["names"]
    names = ", ".join(str(name) for name in raw_names) if isinstance(raw_names, list) else primary
    account = inventory.get("account")
    proxy = inventory.get("proxy_account")
    database_value = (
        f"{database.get('label', 'the engine')}: {database.get('name', '')} database and "
        f"principal (state: {database.get('state', 'absent')})"
        if database.get("exists")
        else "No site database exists."
    )
    raw_certificates = inventory["certificates"]
    certificates = raw_certificates if isinstance(raw_certificates, list) else []
    certificate = (
        "\n".join(str(path) for path in certificates) if certificates else "No stored certificate."
    )
    raw_other = inventory["other_sites"]
    other = raw_other if isinstance(raw_other, list) else []
    raw_services = inventory["services"]
    services = raw_services if isinstance(raw_services, dict) else {}
    return [
        {"label": "Site", "value": names},
        {"label": "Deleted files and configuration", "value": "\n".join(_deleted_paths(inventory))},
        {
            "label": "Services stopped and disabled",
            "value": "\n".join(
                f"{unit} ({state[1] or 'not loaded'})" for unit, state in services.items()
            ),
        },
        {"label": "Database", "value": database_value},
        {"label": "Certificate", "value": certificate},
        {
            "label": "Accounts",
            "value": "\n".join(
                [
                    (
                        f"s{inventory['identifier']}: UID {account[0]}, GID {account[1]}"
                        if isinstance(account, list)
                        else f"s{inventory['identifier']}: absent"
                    ),
                    (
                        f"p{inventory['identifier']}: UID {proxy[0]}, GID {proxy[1]}"
                        if isinstance(proxy, list)
                        else f"p{inventory['identifier']}: absent"
                    ),
                ]
            ),
        },
        {
            "label": "Other sites",
            "value": (
                f"{len(other)} other site(s) keep serving; Caddy reloads the whole tree."
                if other
                else "This is the server's only site."
            ),
        },
        {"label": "Backups", "value": NO_BACKUP},
    ]


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:  # noqa: C901 - one review
    if not isinstance(evidence, RemovalEvidence):
        raise ValueError("A site removal needs native evidence.")
    identifier = inputs.identifier
    inventory = evidence.inventory
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before removing a site.")
    if inventory is None:
        refusals.append(evidence.inventory_problem)
        inventory = {}
    boot_id = str(inventory.get("boot", ""))
    uptime = inventory.get("uptime")
    if not boot_id or type(uptime) is not int:
        refusals.append("The server's clock could not be read.")
    names = _names(inventory, inputs)
    for name in names:
        canonical, problem = canonical_name(name)
        if problem or canonical != name:
            refusals.append(problem or "The site's primary domain is not canonical.")
    account = inventory.get("account")
    proxy = inventory.get("proxy_account")
    if account is not None and not _account(
        account, expected_home=f"/var/www/{identifier}", expected_shell="/usr/sbin/nologin"
    ):
        refusals.append("The site's Linux account is outside supported settings.")
    if proxy is not None and not _account(
        proxy, expected_home="/nonexistent", expected_shell="/usr/sbin/nologin"
    ):
        refusals.append("The site's proxy account is outside supported settings.")
    for key in ("account_group", "proxy_group"):
        value = inventory.get(key)
        if value is not None and not _group(value):
            refusals.append("A site group holds members or is outside supported settings.")
    database_refusals, database_exists = _database_refusals(evidence, identifier)
    refusals.extend(database_refusals)
    database = _database_document(evidence, identifier, database_exists)
    paths = inventory.get("paths")
    present_paths = isinstance(paths, dict) and any(paths.values())
    artifacts = (
        present_paths
        or account is not None
        or proxy is not None
        or inventory.get("account_group") is not None
        or inventory.get("proxy_group") is not None
        or bool(inventory.get("certificates"))
        or database_exists
    )
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": identifier,
        "names": list(names),
        "primary": names[0] if names else "",
        "runtime": inventory.get("runtime", ""),
        "https": inventory.get("https", True),
        "site_digest": inventory.get("digest", ""),
        "site_file_digest": inventory.get("site_file_digest", ""),
        "account": account,
        "proxy_account": proxy,
        "account_group": inventory.get("account_group"),
        "proxy_group": inventory.get("proxy_group"),
        "certificates": inventory.get("certificates", []),
        "other_sites": inventory.get("other_sites", []),
        "caddy_data_directory": inventory.get("caddy_data_directory", ""),
        "database": database,
        "confirmation": names[0] if names else "",
        "confirmation_label": (f"Type {names[0]} to confirm this removal." if names else ""),
        "details": _details(inventory, database, names[0] if names else identifier)
        if inventory
        else [],
        "note": "",
    }
    if not refusals and not artifacts:
        document["note"] = f"Nothing of site {identifier} remains on this server."
        return ReviewDraft(
            kind=SLUG,
            intent=f"Remove site {identifier}.",
            stages=STAGES,
            refusals=(),
            boot_id=boot_id,
            uptime_centiseconds=uptime if type(uptime) is int else None,
            document=document,
        )
    if not refusals and not names:
        refusals.append("The site's primary domain cannot be read from the server.")
    effects = _effects(identifier, names[0]) if not refusals else ()
    return ReviewDraft(
        kind=SLUG,
        intent=f"Remove site {identifier}.",
        effects=effects,
        stages=STAGES,
        postconditions=(
            (
                "The site's Caddy file, services, configuration, database and principal, "
                "certificate, directory and accounts are gone."
            ),
            "The remaining Caddy configuration validates and Caddy serves it.",
            "Every other site keeps its own Caddy file, services and data.",
        ),
        refusals=tuple(refusals),
        boot_id=boot_id,
        uptime_centiseconds=uptime if type(uptime) is int else None,
        sites_read=presence_command(identifier) if not refusals and artifacts else "",
        current_sites=(identifier,) if not refusals and artifacts else None,
        document=document,
    )


def _reviewed_account(value: object) -> bool:
    if value is None:
        return True
    return (
        isinstance(value, list)
        and len(value) == 5
        and type(value[0]) is int
        and type(value[1]) is int
        and 1000 <= value[0] < 30000
        and value[0] == value[1]
        and isinstance(value[2], str)
        and isinstance(value[3], str)
        and isinstance(value[4], list)
        and all(type(group) is int for group in value[4])
    )


def _reviewed_group(value: object) -> bool:
    return value is None or (
        isinstance(value, list)
        and len(value) == 2
        and type(value[0]) is int
        and 1000 <= value[0] < 30000
        and isinstance(value[1], list)
        and not value[1]
    )


def _reviewed_statements(document: dict[str, object], engine: str, name: str) -> list[list[str]]:
    statements = document.get("statements")
    expected = [
        [statement.step, statement.database, statement.text]
        for statement in binding.drop_statements(engine, name)
    ]
    if statements != expected:
        raise ValueError("The site removal is not the convention's database removal.")
    return expected


def body(document: dict[str, object], context: BodyContext) -> NativeBody:  # noqa: C901 - one reviewed shape
    identifier = document.get("identifier")
    names = document.get("names")
    primary = document.get("primary")
    database = document.get("database")
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or not isinstance(identifier, str)
        or not valid_identifier(identifier)
        or not isinstance(names, list)
        or not all(isinstance(name, str) and canonical_name(name)[1] == "" for name in names)
        or not names
        or len(set(names)) != len(names)
        or names[0] != primary
        or not isinstance(primary, str)
        or canonical_name(primary)[1]
        or document.get("runtime") not in ("", *PHP_RUNTIMES)
        or type(document.get("https")) is not bool
        or not _digest(document.get("site_digest"))
        or not _digest(document.get("site_file_digest"), empty=True)
        or not isinstance(database, dict)
        or not isinstance(document.get("certificates"), list)
        or not isinstance(document.get("other_sites"), list)
    ):
        raise ValueError("Unsupported site removal.")
    if not _reviewed_account(document.get("account")):
        raise ValueError("The site removal has no reviewed account.")
    if not _reviewed_account(document.get("proxy_account")):
        raise ValueError("The site removal has no reviewed proxy account.")
    if not _reviewed_group(document.get("account_group")) or not _reviewed_group(
        document.get("proxy_group")
    ):
        raise ValueError("The site removal has no reviewed group.")
    certificates = document["certificates"]
    other_sites = document["other_sites"]
    caddy_data = document.get("caddy_data_directory")
    if (
        not isinstance(certificates, list)
        or not isinstance(caddy_data, str)
        or not caddy_data.startswith("/")
        or not all(
            isinstance(item, str) and item.startswith(caddy_data + "/certificates/")
            for item in certificates
        )
    ):
        raise ValueError("The site removal names an invalid certificate.")
    if not isinstance(other_sites, list) or not _identifier_list(other_sites):
        raise ValueError("The site removal names invalid other sites.")
    engine = database.get("engine")
    name = database.get("name")
    catalog_digest = database.get("catalog_digest")
    if (
        not isinstance(catalog_digest, str)
        or binding.DIGEST.fullmatch(catalog_digest) is None
        or not isinstance(engine, str)
        or not isinstance(name, str)
    ):
        raise ValueError("The site removal has no reviewed database state.")
    if database.get("exists") is True:
        if (
            engine not in (binding.MARIADB, binding.POSTGRESQL)
            or name != binding.name_of(identifier)
            or database.get("read_command") != binding.read_command(engine, name)
        ):
            raise ValueError("The site removal has no reviewed database.")
        _reviewed_statements(database, engine, name)
    elif database.get("exists") is not False:
        raise ValueError("The site removal has no reviewed database state.")
    reviewed = {
        key: document.get(key)
        for key in (
            "identifier",
            "names",
            "primary",
            "runtime",
            "https",
            "site_digest",
            "site_file_digest",
            "account",
            "proxy_account",
            "account_group",
            "proxy_group",
            "certificates",
            "other_sites",
            "caddy_data_directory",
            "database",
        )
    }
    payload = {
        **reviewed,
        "database": {
            **database,
            "statements": (
                _reviewed_statements(database, engine, name)
                if database.get("exists") is True and engine and name
                else []
            ),
        },
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES.rstrip(b"\n"), (encoded,))


def verify(shell: RemoteShell, review: ChangeReview) -> bool | None:
    body(review.document, BodyContext("", "", 0))
    identifier = str(review.document["identifier"])
    inventory, _problem = _read_inventory(shell, identifier)
    if inventory is None:
        return None
    paths = inventory["paths"]
    if isinstance(paths, dict) and any(paths.values()):
        return False
    if (
        inventory["account"] is not None
        or inventory["proxy_account"] is not None
        or inventory["account_group"] is not None
        or inventory["proxy_group"] is not None
        or inventory["certificates"]
    ):
        return False
    if not inventory["caddy_matches"]:
        return False
    database = review.document.get("database")
    if isinstance(database, dict) and database.get("engine"):
        result = run_root(
            shell, binding.read_command(str(database["engine"]), str(database["name"]))
        )
        if result.exit_status != 0 or result.truncated:
            return None
        try:
            facts = binding.parse_facts(str(database["engine"]), result.stdout)
        except ValueError:
            return None
        return facts.get("database") == "0" and facts.get("principal") == "0"
    return True


REMOVE: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    refresh_discovery=True,
    input_shape=InputShape.SITE_REMOVE,
)
