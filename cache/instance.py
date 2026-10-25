"""One site's own Valkey instance, its application wiring, and the change that sets it.

docs/adr/0030-give-each-site-its-own-valkey-instance.md. The instance is the packaged
``valkey-server@<identifier>.service`` template with a root-owned drop-in and
configuration, running as the site account on a private Unix socket. For WordPress the
pinned Redis Object Cache plugin is installed and its drop-in enabled after the
``WP_REDIS_*`` constants are written into the private configuration file.

Recognition reads the same native files a fresh controller can: the configuration, the
drop-in, the unit's own properties and the application's files. Nothing here keeps a cache
value or a Barectl marker on the server.
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

from discovery.root_read import run_root
from discovery.snapshot import CollectedSnapshot, ObservedCache, ObservedSite
from discovery.ssh import RemoteShell
from operations import native
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from sites import observation as site_observation

from . import convention, observation
from .laravel import laravel_managed_digests, laravel_wiring_digests

SLUG: Final = "set_site_object_cache"
LABEL: Final = "Object cache"
STAGES: Final = ("preflight", "instance", "wiring", "plugin", "verify")
STAGES_OFF: Final = ("preflight", "disconnect", "stop", "verify")
STAGES_LARAVEL: Final = ("preflight", "instance", "environment", "config", "workers", "verify")
STAGES_LARAVEL_OFF: Final = (
    "preflight",
    "disconnect",
    "config",
    "workers",
    "stop",
    "verify",
)
SOCKET_MODE: Final = 0o600
DIGEST: Final = re.compile(r"[0-9a-f]{64}")
_BODY_RESOURCE: Final = importlib.resources.files("cache.bodies").joinpath("instance.py")
LARAVEL_COMMON_SOURCE: Final = (
    importlib.resources.files("laravel.bodies")
    .joinpath("common.py")
    .read_text()
    .replace(
        "from sites.bodies.common import (\n"
        "    canonical,\n"
        "    current_bytes,\n"
        "    open_site_lock,\n"
        "    reload_caddy,\n"
        "    reload_site_fpm,\n"
        "    replace_caddy,\n"
        "    result,\n"
        "    safe,\n"
        "    same_site_lock,\n"
        "    setting,\n"
        "    site_account,\n"
        "    site_address,\n"
        "    stage,\n"
        ")\n",
        "",
    )
)
BODY_SOURCE: Final = (
    site_observation.COMMON_SOURCE
    + "\n"
    + importlib.resources.files("cache").joinpath("convention.py").read_text()
    + "\n"
    + importlib.resources.files("cache")
    .joinpath("laravel.py")
    .read_text()
    .replace("from .convention import instance_paths\n", "")
    + "\n"
    + importlib.resources.files("wordpress").joinpath("convention.py").read_text()
    + "\n"
    + importlib.resources.files("automation").joinpath("convention.py").read_text()
    + "\n"
    + importlib.resources.files("automation")
    .joinpath("workers.py")
    .read_text()
    .replace(
        "from automation.convention import (\n"
        "    KILL_MODE,\n"
        "    WORKER_ROLES,\n"
        "    account,\n"
        "    digest,\n"
        "    directives_map,\n"
        "    parse_unit,\n"
        "    render_slice,\n"
        "    role_of,\n"
        "    service_name,\n"
        "    site_directory,\n"
        "    slice_name,\n"
        ")\n",
        "",
    )
    + "\n"
    + importlib.resources.files("automation.bodies")
    .joinpath("worker_env.py")
    .read_text()
    .replace("from automation.convention import service_name\n", "")
    .replace("from automation.workers import WORKER_ROLES\n", "")
    + "\n"
    + LARAVEL_COMMON_SOURCE
    + "\n"
    + _BODY_RESOURCE.read_text()
    .replace(
        "from automation.bodies.worker_env import restart_workers\n",
        "",
    )
    .replace(
        "from cache.convention import (\n"
        "    MAXMEMORY_MIB,\n"
        "    config_shape,\n"
        "    instance_paths,\n"
        "    laravel_managed,\n"
        "    laravel_values,\n"
        "    laravel_wiring,\n"
        "    render_config,\n"
        "    render_drop_in,\n"
        ")\n",
        "",
    )
    .replace(
        "from laravel.bodies.common import (\n"
        "    _private_file_ok,\n"
        "    apply_environment,\n"
        "    environment_entries_from_text,\n"
        "    environment_path,\n"
        "    read_environment,\n"
        "    user_command,\n"
        ")\n",
        "",
    )
    .replace(
        "from sites.bodies.common import (\n"
        "    native_state,\n"
        "    open_site_lock,\n"
        "    result,\n"
        "    stage,\n"
        ")\n",
        "",
    )
    .replace(
        "from wordpress.convention import (\n"
        "    cache_wiring,\n"
        "    private_configuration_path,\n"
        "    private_configuration_problem,\n"
        "    set_cache_constants,\n"
        "    write_as_site,\n"
        ")\n",
        "",
    )
)
BODY_BYTES: Final = (
    "#!/bin/sh\nexec python3 -c "
    + shlex.quote(
        "import base64,gzip; exec(gzip.decompress(base64.b64decode("
        + repr(base64.b64encode(gzip.compress(BODY_SOURCE.encode(), mtime=0)).decode())
        + ")))"
    )
    + ' "$@"'
).encode()
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()

SOURCE: Final = (
    importlib.resources.files("cache").joinpath("convention.py").read_text()
    + "\n"
    + importlib.resources.files("wordpress").joinpath("convention.py").read_text()
    + "\n"
    + """
import hashlib
import json
import pathlib
import stat
import subprocess
import sys


def _regular(path, limit=65536):
    try:
        info = pathlib.Path(path).lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > limit:
        return None
    try:
        return pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _unit(name):
    try:
        completed = subprocess.run(
            [
                "/usr/bin/systemctl",
                "show",
                "--no-pager",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--property=UnitFileState",
                "--property=User",
                "--property=Group",
                "--property=ExecStart",
                name,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if completed.returncode:
        return {}
    values = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key not in values:
            values[key] = value
    return values


def _plugin(identifier):
    path = (
        pathlib.Path("/var/www")
        / identifier
        / "current"
        / "public"
        / "wp-content"
        / "plugins"
        / "redis-cache"
        / "redis-cache.php"
    )
    text = _regular(path)
    if text is None:
        return ""
    for line in text.splitlines()[:40]:
        if line.startswith(" * Version: "):
            return line.removeprefix(" * Version: ").strip()[:40]
    return ""


def _wordpress(identifier):
    text = _regular(
        pathlib.Path("/var/www") / identifier / "private" / "wp-config.php"
    )
    dropin = (
        pathlib.Path("/var/www")
        / identifier
        / "current"
        / "public"
        / "wp-content"
        / "object-cache.php"
    )
    try:
        info = dropin.lstat()
        present = stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)
    except OSError:
        present = False
    if text is None:
        return {
            "present": False,
            "wiring": "",
            "configuration_digest": "",
            "dropin": present,
            "plugin": _plugin(identifier),
        }
    problem = private_configuration_problem(text, identifier)
    return {
        "present": not problem,
        "wiring": "" if problem else cache_wiring(text, identifier),
        "configuration_digest": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "dropin": present,
        "plugin": _plugin(identifier),
    }


def _identifiers():
    found = set()
    for path in pathlib.Path("/etc/valkey").glob("*.conf"):
        if path.name == "valkey.conf":
            continue
        if IDENTIFIER.fullmatch(path.stem):
            found.add(path.stem)
    for path in pathlib.Path("/etc/systemd/system").glob("valkey-server@*.service.d"):
        name = path.name.removeprefix("valkey-server@").removesuffix(".service.d")
        if IDENTIFIER.fullmatch(name):
            found.add(name)
    root = pathlib.Path("/var/www")
    try:
        entries = sorted(root.iterdir())
    except OSError:
        entries = []
    for entry in entries:
        if IDENTIFIER.fullmatch(entry.name) and not entry.is_symlink():
            found.add(entry.name)
    return sorted(found)[:64]


def _instance(identifier, with_text):
    paths = instance_paths(identifier)
    config = _regular(paths.config)
    shape = config_shape(identifier, config) if config is not None else None
    drop_in = _regular(paths.drop_in)
    try:
        info = pathlib.Path(paths.socket).lstat()
        socket = {
            "present": stat.S_ISSOCK(info.st_mode),
            "uid": info.st_uid,
            "mode": stat.S_IMODE(info.st_mode),
        }
    except OSError:
        socket = {"present": False, "uid": -1, "mode": -1}
    return {
        "identifier": identifier,
        "config_present": config is not None,
        "config_digest": (
            hashlib.sha256(config.encode("utf-8")).hexdigest() if config is not None else ""
        ),
        "config": config if with_text and config is not None else "",
        "memory_mib": shape.memory_mib if shape is not None else None,
        "config_problem": shape.problem if shape is not None else "",
        "outside": shape.outside if shape is not None else "",
        "drop_in_present": drop_in is not None,
        "drop_in_supported": drop_in == render_drop_in(identifier),
        "drop_in_digest": (
            hashlib.sha256(drop_in.encode("utf-8")).hexdigest() if drop_in is not None else ""
        ),
        "unit": _unit(paths.unit),
        "socket": socket,
        "data": pathlib.Path(paths.data_directory).is_dir(),
        "wordpress": _wordpress(identifier),
    }


def cache_read():
    options = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
    wanted = options.get("identifier", "")
    identifiers = [wanted] if wanted else _identifiers()
    instances = [_instance(identifier, bool(wanted)) for identifier in identifiers]
    payload = {
        "instances": instances,
        "sites": sorted(
            entry.name
            for entry in pathlib.Path("/var/www").iterdir()
            if IDENTIFIER.fullmatch(entry.name)
        )[:64]
        if pathlib.Path("/var/www").is_dir()
        else [],
    }
    value = {
        "version": 1,
        "boot": pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "uptime": int(float(pathlib.Path("/proc/uptime").read_text().split()[0]) * 100),
        "digest": hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        **payload,
    }
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\\n")


cache_read()
"""
)
READ_SOURCE: Final = SOURCE
_BOOT: Final = re.compile(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")


def read_command(identifier: str = "") -> str:
    if identifier:
        convention.instance_paths(identifier)
    options = json.dumps({"identifier": identifier}, separators=(",", ":"))
    command = site_observation.python_command(READ_SOURCE, (options,))
    return "sh -c " + shlex.quote("; ".join([*native.read_lock_steps(), "exec " + command]))


def read(shell: RemoteShell, identifier: str = "") -> dict[str, object] | None:
    """The cache instances and application wiring, or ``None`` when unreadable."""
    result = run_root(shell, read_command(identifier))
    if result.exit_status or result.truncated:
        return None
    try:
        value: object = json.loads(result.stdout)
    except ValueError:
        return None
    return cast("dict[str, object]", value) if valid_read(value) else None


def valid_read(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "version",
        "boot",
        "uptime",
        "digest",
        "instances",
        "sites",
    }:
        return False
    if (
        value["version"] != 1
        or not isinstance(value["boot"], str)
        or _BOOT.fullmatch(value["boot"]) is None
        or type(value["uptime"]) is not int
        or value["uptime"] < 0
        or not isinstance(value["digest"], str)
        or DIGEST.fullmatch(value["digest"]) is None
        or not _identifier_list(value["sites"])
        or not isinstance(value["instances"], list)
        or len(value["instances"]) > 64
    ):
        return False
    return all(valid_instance(row) for row in value["instances"])


def _identifier_list(value: object) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= 64
        and all(
            isinstance(item, str) and re.fullmatch(r"[a-z][a-z0-9]{2,23}", item) is not None
            for item in value
        )
    )


def _unit_state(value: object) -> bool:
    return isinstance(value, dict) and all(
        isinstance(value.get(key), str)
        for key in (
            "LoadState",
            "ActiveState",
            "SubState",
            "UnitFileState",
            "User",
            "Group",
            "ExecStart",
        )
    )


def _wordpress_state(value: object) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value)
        == {
            "present",
            "wiring",
            "configuration_digest",
            "dropin",
            "plugin",
        }
        and (
            type(value["present"]) is bool
            and value["wiring"] in ("", "partial", "complete")
            and isinstance(value["configuration_digest"], str)
            and (
                value["configuration_digest"] == ""
                or DIGEST.fullmatch(value["configuration_digest"])
            )
            and type(value["dropin"]) is bool
            and isinstance(value["plugin"], str)
            and len(value["plugin"]) <= 40
        )
    )


def valid_instance(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "identifier",
        "config_present",
        "config_digest",
        "config",
        "memory_mib",
        "config_problem",
        "outside",
        "drop_in_present",
        "drop_in_supported",
        "drop_in_digest",
        "unit",
        "socket",
        "data",
        "wordpress",
    }:
        return False
    identifier = value["identifier"]
    if not isinstance(identifier, str):
        return False
    try:
        convention.instance_paths(identifier)
    except ValueError:
        return False
    if (
        type(value["config_present"]) is not bool
        or not isinstance(value["config_digest"], str)
        or (value["config_digest"] and DIGEST.fullmatch(str(value["config_digest"])) is None)
        or not isinstance(value["config"], str)
        or len(value["config"]) > 65536
        or (value["memory_mib"] is not None and type(value["memory_mib"]) is not int)
        or not isinstance(value["config_problem"], str)
        or len(value["config_problem"]) > 400
        or not isinstance(value["outside"], str)
        or len(value["outside"]) > 400
        or type(value["drop_in_present"]) is not bool
        or type(value["drop_in_supported"]) is not bool
        or not isinstance(value["drop_in_digest"], str)
        or type(value["data"]) is not bool
        or not _unit_state(value["unit"])
        or not _wordpress_state(value["wordpress"])
    ):
        return False
    socket = value["socket"]
    return (
        isinstance(socket, dict)
        and set(socket) == {"present", "uid", "mode"}
        and type(socket["present"]) is bool
        and type(socket["uid"]) is int
        and type(socket["mode"]) is int
    )


def instances(value: dict[str, object] | None) -> dict[str, dict[str, object]]:
    if value is None:
        return {}
    rows = value.get("instances")
    if not isinstance(rows, list):
        return {}
    return {
        str(row["identifier"]): cast("dict[str, object]", row)
        for row in rows
        if isinstance(row, dict)
    }


def instance(value: dict[str, object] | None, identifier: str) -> dict[str, object] | None:
    return instances(value).get(identifier)


def site_ids(account: object) -> tuple[int, int] | None:
    """The site account's ids, for the socket's ownership check."""
    if isinstance(account, ObservedSite):
        account = account.account
    if isinstance(account, list) and len(account) >= 2:
        return (account[0], account[1]) if all(type(item) is int for item in account[:2]) else None
    uid = getattr(account, "uid", None)
    gid = getattr(account, "gid", None)
    if type(uid) is int and type(gid) is int:
        return uid, gid
    return None


def unit_of(row: dict[str, object] | None) -> dict[str, str]:
    unit = row.get("unit") if row is not None else None
    return cast("dict[str, str]", unit) if isinstance(unit, dict) else {}


def wordpress_of(row: dict[str, object] | None) -> dict[str, object]:
    value = row.get("wordpress") if row is not None else None
    return cast("dict[str, object]", value) if isinstance(value, dict) else {}


def _running(row: dict[str, object]) -> bool:
    unit = unit_of(row)
    return unit.get("ActiveState") == "active" and unit.get("SubState") in ("running", "start")


def state_of(  # noqa: C901 - one recognized state table
    row: dict[str, object] | None,
    *,
    application: str = "",
    client: str = "",
    account: object = None,
    wiring: str = "",
) -> tuple[str, str]:
    """One site's object cache state and the reason it is not simply on or off.

    ``wiring`` is the application's own cache wiring, recognized by the caller from native
    evidence: the WordPress constants, or Laravel's `.env` keys. An application's wiring
    participates in the off state, so a leftover environment never reads as "off".
    """
    if row is None:
        if wiring:
            return "partial", "The cache instance is not installed."
        return "off", ""
    wordpress = wordpress_of(row)
    wordpress_wiring = str(wordpress.get("wiring", ""))
    dropin = bool(wordpress.get("dropin"))
    if application != "laravel" and not wiring:
        wiring = wordpress_wiring
    if not row["config_present"] and not row["drop_in_present"] and not wiring and not dropin:
        return "off", ""
    if row["outside"]:
        return "unsupported", str(row["outside"])
    if row["config_problem"]:
        return "unsupported", str(row["config_problem"])
    if not row["drop_in_supported"]:
        return "unsupported", (
            "The cache instance's unit settings are outside the supported convention."
        )
    if application == "laravel":
        if not row["config_present"] or not row["drop_in_present"]:
            return "partial", "The cache instance is not installed."
    elif not row["drop_in_present"]:
        return "unsupported", (
            "The cache instance's unit settings are outside the supported convention."
        )
    identifier = str(row["identifier"])
    unit = unit_of(row)
    if (
        unit.get("User") != "s" + identifier
        or unit.get("Group") != "s" + identifier
        or f"/etc/valkey/{identifier}.conf" not in unit.get("ExecStart", "")
    ):
        return "unsupported", "The cache instance runs outside the site's own account."
    if not _running(row):
        return "partial", "The cache instance is not running."
    socket = row.get("socket")
    if not isinstance(socket, dict) or not socket.get("present"):
        return "partial", "The cache's private connection is not available."
    identifiers = site_ids(account)
    if identifiers is not None and (
        socket.get("uid") != identifiers[0] or socket.get("mode") != SOCKET_MODE
    ):
        return "partial", "The cache's private connection is outside the site's own account."
    if application == "wordpress":
        if wiring != "complete":
            return "partial", "The WordPress cache connection is not fully configured."
        if not dropin:
            return "partial", "The WordPress object cache is not enabled."
        if client != "phpredis":
            return "partial", "The site does not load the object cache's PHP client."
        if wordpress.get("plugin") != plugin_version():
            return "partial", "The WordPress object cache plugin is not the pinned version."
    if application == "laravel":
        if wiring != "complete":
            return "partial", "The site does not use its own cache."
        if client != "phpredis":
            return "partial", "The site does not load the object cache's PHP client."
    return "on", ""


def observed(
    value: dict[str, object] | None,
    sites: tuple[ObservedSite, ...],
    laravel: dict[str, str] | None = None,
) -> tuple[ObservedCache, ...]:
    """One observation row per site, plus any instance whose site is not configured.

    ``laravel`` maps a Laravel site's identifier to its recognized `.env` wiring, which the
    caller derives from the server-computed setting digests, never from the values.
    """
    rows = instances(value)
    known = {site.identifier for site in sites}
    records: list[ObservedCache] = []
    for site in sites:
        row = rows.get(site.identifier)
        is_laravel = laravel is not None and site.identifier in laravel
        state, problem = state_of(
            row,
            application="laravel" if is_laravel else site.application,
            client=site.client,
            account=site.account,
            wiring=(laravel or {}).get(site.identifier, "") if is_laravel else "",
        )
        records.append(
            ObservedCache(
                site.identifier,
                state,
                int(str(row["memory_mib"]))
                if row is not None and row["memory_mib"] is not None
                else None,
                problem,
                str(wordpress_of(row).get("plugin", "")),
                site.client,
                unit_of(row).get("ActiveState", ""),
            )
        )
    for identifier, row in rows.items():
        if identifier in known:
            continue
        state, problem = state_of(row)
        records.append(
            ObservedCache(
                identifier,
                state,
                int(str(row["memory_mib"])) if row["memory_mib"] is not None else None,
                problem or "The site this cache belongs to is not configured.",
                str(wordpress_of(row).get("plugin", "")),
                "",
                unit_of(row).get("ActiveState", ""),
            )
        )
    return tuple(sorted(records, key=lambda record: record.identifier))


def plugin_version() -> str:
    from .plugin import PLUGIN_VERSION

    return PLUGIN_VERSION


def plugin_name() -> str:
    from .plugin import PLUGIN_NAME

    return PLUGIN_NAME


@dataclass(frozen=True)
class InstanceEvidence:
    collected: CollectedSnapshot
    value: dict[str, object] | None
    site: ObservedSite | None
    site_digest: str = ""
    # A Laravel site's own release and environment inventory (#393). ``None`` for another
    # application or when the inventory is unreadable.
    laravel: dict[str, object] | None = None


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> InstanceEvidence:
    from discovery.observations import collect

    snapshot = collect(shell, sites=False)
    site, digest = _site_snapshot(shell, snapshot, inputs.identifier)
    laravel: dict[str, object] | None = None
    if site is not None and site.application != "wordpress":
        from laravel import observation as laravel_observation

        # A Laravel site's passive site record reads as plain (its application is known
        # from its release layout), so the release inventory is the native proof.
        inventory = laravel_observation.read(shell)
        row = (
            laravel_observation.site(inventory, inputs.identifier)
            if inventory is not None
            else None
        )
        if row is not None and row["application"] == "laravel":
            laravel = inventory
    return InstanceEvidence(snapshot, read(shell, inputs.identifier), site, digest, laravel)


def _site_snapshot(
    shell: RemoteShell, snapshot: CollectedSnapshot, identifier: str
) -> tuple[ObservedSite | None, str]:
    from sites import observation as sites_observation

    if snapshot.standing is None:
        return None, ""
    native_state = sites_observation.read(shell, "observed", "", protections=False)
    if native_state is None:
        return None, ""
    row = next((site for site in native_state["sites"] if site["identifier"] == identifier), None)
    digest = str(native_state["digest"])
    if row is None:
        return None, digest
    return sites_observation.observed_site(cast("dict[str, object]", row)), digest


ACCOUNT_LABEL: Final = "The site's Linux account is not observed."
LARAVEL_PREIMAGE_ON = (
    "Barectl does not know which cache store this site used before its object cache was "
    "turned on, so it will not overwrite the current store. Turn the object cache off and "
    "prepare again only after the site's cache store is known."
)
LARAVEL_PREIMAGE_OFF = (
    "Barectl does not know which cache store this site used before its object cache was "
    "turned on, so it will not guess. This device has no record of turning it on; restore "
    "the site's cache store through ordinary administration, then prepare this review again."
)
LARAVEL_UNREADABLE = "The site's release and environment could not be read."


@dataclass(frozen=True)
class LaravelCacheState:
    """One Laravel site's environment wiring, recognized from digests and the release."""

    row: dict[str, object] | None
    wiring: str
    managed: frozenset[str]
    store: str
    store_present: bool
    release_complete: bool


def laravel_site(evidence: InstanceEvidence, identifier: str) -> dict[str, object] | None:
    if evidence.laravel is None:
        return None
    from laravel import observation as laravel_observation

    return laravel_observation.site(evidence.laravel, identifier)


def _environment_details(row: dict[str, object] | None) -> list[dict[str, object]]:
    details = row.get("environment_details") if row is not None else None
    return (
        [detail for detail in details if isinstance(detail, dict)]
        if isinstance(details, list)
        else []
    )


def laravel_wiring(identifier: str, row: dict[str, object] | None) -> str:
    digests = {
        str(detail["key"]): str(detail["digest"])
        for detail in _environment_details(row)
        if isinstance(detail.get("key"), str) and isinstance(detail.get("digest"), str)
    }
    return laravel_wiring_digests(identifier, digests)


def laravel_managed(identifier: str, row: dict[str, object] | None) -> frozenset[str]:
    digests = {
        str(detail["key"]): str(detail["digest"])
        for detail in _environment_details(row)
        if isinstance(detail.get("key"), str) and isinstance(detail.get("digest"), str)
    }
    return laravel_managed_digests(identifier, digests)


def _laravel_state(identifier: str, row: dict[str, object] | None) -> LaravelCacheState:
    entries = {
        str(detail["key"]): str(detail["value"])
        for detail in _environment_details(row)
        if isinstance(detail.get("key"), str) and isinstance(detail.get("value"), str)
    }
    current = str(row.get("current", "")) if row is not None else ""
    releases = row.get("releases") if row is not None else None
    complete = bool(current) and any(
        isinstance(entry, dict)
        and entry.get("name") == current
        and entry.get("state") == "complete"
        for entry in (releases if isinstance(releases, list) else [])
    )
    return LaravelCacheState(
        row,
        laravel_wiring(identifier, row),
        laravel_managed(identifier, row),
        entries.get("CACHE_STORE", ""),
        "CACHE_STORE" in entries,
        complete,
    )


def _refusals(  # noqa: C901 - every refusal reason
    evidence: InstanceEvidence, inputs: PreparationInputs, identifier: str
) -> tuple[list[str], dict[str, object] | None]:
    from bootstrap.standing import Standing

    enabled = inputs.object_cache is True
    refusals: list[str] = []
    snapshot = evidence.collected
    if snapshot.standing is None or snapshot.standing.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before changing a site.")
    current = observation.installed(snapshot)
    if current is None:
        refusals.append(
            "This server has no object cache yet. Install Valkey in Server Settings first."
        )
    elif not current.masked or not current.inactive:
        refusals.append(
            "The server's shared Valkey service is still running. Stop and mask it in Server "
            "Settings, then prepare again."
        )
    if evidence.value is None:
        refusals.append("The site's object cache could not be read.")
    site = evidence.site
    if site is None:
        refusals.append("The site was not observed in the current server configuration.")
        return refusals, None
    row = instance(evidence.value, identifier)
    laravel_row = laravel_site(evidence, identifier)
    if laravel_row is None:
        if site.application != "wordpress":
            refusals.append("This site is not a verified WordPress or Laravel installation.")
        else:
            value = wordpress_of(row)
            if value and value.get("present") is False:
                refusals.append(
                    "The private WordPress configuration is outside the supported settings."
                )
        if not enabled:
            return refusals, row
    if laravel_row is not None:
        laravel = _laravel_state(identifier, laravel_row)
        if not enabled:
            return refusals, row
        if laravel.row is None:
            refusals.append(LARAVEL_UNREADABLE)
        elif not laravel.release_complete:
            refusals.append(
                "The site's last deploy is not complete, so its object cache cannot be turned "
                "on. Deploy the site again first."
            )
        if (
            laravel.wiring != "complete"
            and laravel.store == "redis"
            and not inputs.cache_store_known
        ):
            refusals.append(LARAVEL_PREIMAGE_ON)
    if not enabled:
        return refusals, row
    from discovery.models import SiteState

    if site.state != SiteState.MANAGED:
        refusals.append(
            "The site is not fully managed, so its object cache cannot be turned on. Finish "
            "its last deploy or take it out of maintenance first."
        )
    if site.account is None:
        refusals.append(ACCOUNT_LABEL)
    if site.client != "phpredis":
        refusals.append(
            "This site does not load the object cache's PHP client. Load it for this site "
            "first, then prepare the object cache again."
        )
    artifacts = row is not None and (row["config_present"] or row["drop_in_present"])
    if (
        artifacts
        and row is not None
        and (row["outside"] or row["config_problem"] or not row["drop_in_supported"])
    ):
        refusals.append(
            "The site's cache instance is outside supported settings. Correct it through "
            "ordinary administration, then prepare again."
        )
    return refusals, row


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:  # noqa: C901
    if not isinstance(evidence, InstanceEvidence):
        raise ValueError("An object cache change needs native evidence.")
    identifier = inputs.identifier
    enabled = inputs.object_cache is True
    refusals, row = _refusals(evidence, inputs, identifier)
    site = evidence.site
    laravel_row = laravel_site(evidence, identifier)
    application = (
        "laravel" if laravel_row is not None else (site.application if site is not None else "")
    )
    laravel = _laravel_state(identifier, laravel_row) if laravel_row is not None else None
    account = site.account if site is not None else None
    state, problem = state_of(
        row,
        application=application,
        client=site.client if site is not None else "",
        account=account,
        wiring=laravel.wiring if laravel is not None else "",
    )
    memory = inputs.cache_mib if enabled else 0
    previous_present, previous_store = False, ""
    write_environment = False
    restore_store = False
    if laravel is not None:
        if enabled:
            write_environment = laravel.wiring != "complete"
            if write_environment:
                if laravel.store_present and laravel.store != "redis":
                    previous_present, previous_store = True, laravel.store
                elif not laravel.store_present:
                    previous_present, previous_store = False, ""
                elif inputs.cache_store_known:
                    previous_present = inputs.cache_store_present
                    previous_store = inputs.cache_store
                elif LARAVEL_PREIMAGE_ON not in refusals:
                    refusals.append(LARAVEL_PREIMAGE_ON)
        else:
            restore_store = "CACHE_STORE" in laravel.managed
            write_environment = bool(laravel.managed)
            if restore_store:
                if inputs.cache_store_known:
                    previous_present = inputs.cache_store_present
                    previous_store = inputs.cache_store
                else:
                    refusals.append(LARAVEL_PREIMAGE_OFF)
    unchanged = enabled and state == "on" and row is not None and row["memory_mib"] == memory
    artifacts = row is not None and (row["config_present"] or row["drop_in_present"])
    if not enabled and not artifacts and not write_environment:
        unchanged = True
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": identifier,
        "application": application,
        "enabled": enabled,
        "maxmemory_mib": memory,
        "socket": convention.instance_paths(identifier).socket,
    }
    current: dict[str, object] = {
        "state": state,
        "memory_mib": row["memory_mib"] if row is not None else None,
        "problem": problem,
        "wiring": (
            laravel.wiring if laravel is not None else str(wordpress_of(row).get("wiring", ""))
        ),
        "plugin": str(wordpress_of(row).get("plugin", "")),
    }
    effects: tuple[DeclaredEffect, ...] = ()
    if site is not None and evidence.value is not None:
        if application == "wordpress":
            from .plugin import (
                PLUGIN_ARCHIVE_SHA256,
                PLUGIN_ARCHIVE_SIZE,
                PLUGIN_ARCHIVE_URL,
                PLUGIN_VERSION,
            )

            document.update(
                prefix=_prefix(identifier),
                plugin_version=PLUGIN_VERSION,
                plugin_url=PLUGIN_ARCHIVE_URL,
                plugin_size=PLUGIN_ARCHIVE_SIZE,
                plugin_sha256=PLUGIN_ARCHIVE_SHA256,
                configuration_digest=wordpress_of(row).get("configuration_digest", ""),
            )
            effect_on = (
                "Turn on this site's own object cache: its private Valkey instance, the "
                "pinned Redis Object Cache plugin and the WordPress connection, limited to "
                f"{_size_label(memory)}."
            )
            effect_off = (
                "Turn off this site's object cache: disable the WordPress cache first, then "
                "stop and remove the site's private instance."
            )
        else:
            if laravel is not None and laravel.row is not None:
                document.update(
                    environment_digest=laravel.row.get("environment_digest", ""),
                    write_environment=write_environment,
                    restore_store=restore_store,
                    previous_store_present=previous_present,
                    previous_store=previous_store,
                )
            effect_on = (
                "Turn on this site's own object cache: its private cache, the site's cache "
                f"settings, limited to {_size_label(memory)}, and restart its workers. Its "
                "cached configuration is rebuilt."
            )
            effect_off = (
                "Turn off this site's object cache: restore the site's previous cache store "
                "and rebuild its configuration first, restart its workers, then stop and "
                "remove the site's private instance."
            )
        document.update(
            precondition_digest=evidence.site_digest,
            cache_digest=evidence.value["digest"],
            current=current,
            details=_details(identifier, application, enabled, memory, state, problem, row),
        )
        if not refusals and not unchanged:
            effects = (
                DeclaredEffect(Scope.SITE, effect_on if enabled else effect_off, (identifier,)),
            )
    note = ""
    if unchanged and not refusals:
        if enabled:
            note = "This site's object cache is already on with the chosen limit."
        elif laravel is not None and laravel.wiring:
            note = (
                "Barectl has no cache to turn off for this site; its environment points at "
                "another cache."
            )
        else:
            note = "This site has no object cache."
    stages: tuple[str, ...]
    postconditions: tuple[str, ...]
    if laravel is not None:
        stages = STAGES_LARAVEL if enabled else STAGES_LARAVEL_OFF
        postconditions = (
            (
                "The site's cache settings use its own private cache, its cached configuration "
                "was rebuilt, and any running workers restarted."
            )
            if enabled
            else (
                "The site is back on its previous cache store with its configuration rebuilt, "
                "and no cache instance runs."
            ),
            "No other site's cache or serving changes.",
            "Discovery reconstructs the cache state from the server alone.",
        )
    else:
        stages = STAGES if enabled else STAGES_OFF
        postconditions = (
            (
                "The site has its own running cache instance on a private connection, with "
                "the pinned plugin enabled."
            )
            if enabled
            else ("The site keeps no cache instance, no plugin drop-in and no cache settings."),
            "No other site's cache or serving changes.",
            "Discovery reconstructs the cache state from the server alone.",
        )
    return ReviewDraft(
        SLUG,
        (
            f"Turn on the object cache for {identifier}."
            if enabled
            else f"Turn off the object cache for {identifier}."
        ),
        effects=effects,
        stages=stages,
        postconditions=postconditions,
        refusals=tuple(dict.fromkeys(refusals)),
        boot_id=str(evidence.value["boot"]) if evidence.value is not None else "",
        uptime_centiseconds=(
            int(str(evidence.value["uptime"])) if evidence.value is not None else None
        ),
        sites_read=(
            "find /etc/caddy/sites -maxdepth 1 -type f -name "
            + shlex.quote(identifier + ".caddy")
            + " -printf '%f\\n' | sed 's/\\.caddy$//'"
        )
        if site is not None
        else "",
        current_sites=(identifier,) if site is not None else None,
        document={**document, "note": note},
    )


def _prefix(identifier: str) -> str:
    from wordpress.convention import cache_prefix

    return cache_prefix(identifier)


def _size_label(memory_mib: int) -> str:
    if memory_mib % 1024 == 0:
        return f"{memory_mib // 1024} GiB"
    return f"{memory_mib} MiB"


def _details(
    identifier: str,
    application: str,
    enabled: bool,
    memory: int,
    state: str,
    problem: str,
    row: dict[str, object] | None,
) -> list[dict[str, str]]:
    details = [
        {"label": "Site", "value": identifier},
        {"label": "Current state", "value": _state_label(state, problem)},
        {"label": "PHP client", "value": "phpredis (loaded for this site)"},
    ]
    if enabled:
        details.append({"label": "Memory limit", "value": _size_label(memory)})
        if application == "laravel":
            details.extend(
                [
                    {
                        "label": "Cache store",
                        "value": "Redis through this site's own private connection.",
                    },
                    {
                        "label": "Cached configuration",
                        "value": "Rebuilt after the cache setting changes.",
                    },
                    {
                        "label": "Workers",
                        "value": "Any running workers restart gracefully and finish current jobs.",
                    },
                    {
                        "label": "Private connection",
                        "value": "This site's own cache connection; no network port, no password.",
                    },
                ]
            )
        else:
            details.extend(
                [
                    {
                        "label": "WordPress plugin",
                        "value": f"{plugin_name()} {plugin_version()} (pinned)",
                    },
                    {
                        "label": "Private connection",
                        "value": "This site's own cache connection; no network port, no password.",
                    },
                ]
            )
    elif application == "laravel":
        details.append(
            {
                "label": "Disconnected first",
                "value": (
                    "The site's previous cache store is restored, its configuration rebuilt "
                    "and its workers restarted; then its private instance and connection are "
                    "removed."
                ),
            }
        )
    else:
        details.append(
            {
                "label": "Stopped and removed",
                "value": (
                    "The WordPress cache is disconnected first; then the site's instance, "
                    "its configuration and its private connection are removed."
                ),
            }
        )
    if row is not None and wordpress_of(row).get("plugin"):
        plugin = wordpress_of(row)["plugin"]
        details.append({"label": "Plugin observed", "value": f"Redis Object Cache {plugin}"})
    return details


def _state_label(state: str, problem: str) -> str:
    label = {
        "on": "On",
        "off": "Off",
        "partial": "Partly on",
        "unsupported": "Outside supported settings",
    }.get(state, state)
    return f"{label}: {problem}" if problem else label


def _document(document: dict[str, object]) -> dict[str, object]:
    from .plugin import (
        PLUGIN_ARCHIVE_SHA256,
        PLUGIN_ARCHIVE_SIZE,
        PLUGIN_ARCHIVE_URL,
        PLUGIN_VERSION,
    )

    identifier = document.get("identifier")
    application = document.get("application")
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or not isinstance(identifier, str)
        or application not in ("wordpress", "laravel")
        or type(document.get("enabled")) is not bool
        or type(document.get("maxmemory_mib")) is not int
    ):
        raise ValueError("The object cache review is not a valid immutable selection.")
    paths = convention.instance_paths(identifier)
    enabled = document["enabled"] is True
    memory = int(str(document["maxmemory_mib"]))
    if enabled and memory not in convention.MAXMEMORY_MIB:
        raise ValueError("The object cache review names an unreviewed memory size.")
    if not enabled and memory:
        raise ValueError("A disabled object cache must not name a memory size.")
    digest = document.get("precondition_digest")
    cache = document.get("cache_digest")
    if (
        not isinstance(digest, str)
        or DIGEST.fullmatch(digest) is None
        or not isinstance(cache, str)
        or DIGEST.fullmatch(cache) is None
        or document.get("socket") != paths.socket
    ):
        raise ValueError("The object cache review's evidence is invalid.")
    if application == "wordpress":
        configuration = document.get("configuration_digest")
        if (
            document.get("plugin_version") != PLUGIN_VERSION
            or document.get("plugin_url") != PLUGIN_ARCHIVE_URL
            or document.get("plugin_size") != PLUGIN_ARCHIVE_SIZE
            or document.get("plugin_sha256") != PLUGIN_ARCHIVE_SHA256
            or not isinstance(configuration, str)
            or DIGEST.fullmatch(configuration) is None
            or not isinstance(document.get("prefix"), str)
        ):
            raise ValueError("The object cache review does not name the pinned plugin.")
        return document
    environment = document.get("environment_digest")
    previous = document.get("previous_store")
    if (
        not isinstance(environment, str)
        or not environment
        or DIGEST.fullmatch(environment) is None
        or type(document.get("write_environment")) is not bool
        or type(document.get("restore_store")) is not bool
        or type(document.get("previous_store_present")) is not bool
        or not isinstance(previous, str)
        or len(previous) > 2048
        or any(character in "\x00\r\n" for character in previous)
        or (document.get("previous_store_present") is False and previous)
    ):
        raise ValueError("The object cache review's Laravel environment is invalid.")
    return document


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    value = _document(document)
    payload = {
        key: value.get(key)
        for key in (
            "version",
            "identifier",
            "application",
            "enabled",
            "maxmemory_mib",
            "socket",
            "prefix",
            "plugin_version",
            "plugin_url",
            "plugin_size",
            "plugin_sha256",
            "precondition_digest",
            "configuration_digest",
            "cache_digest",
            "environment_digest",
            "write_environment",
            "restore_store",
            "previous_store_present",
            "previous_store",
        )
    }
    from base64 import b64encode
    from gzip import compress

    encoded = b64encode(compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES, (encoded,))


def verify(shell: RemoteShell, review_value: ChangeReview) -> bool | None:
    body(review_value.document, BodyContext("", "", 0))
    identifier = str(review_value.document["identifier"])
    value = read(shell, identifier)
    if value is None:
        return None
    row = instance(value, identifier)
    enabled = review_value.document.get("enabled") is True
    site, _digest = _site_snapshot(shell, _collect(shell), identifier)
    wiring = ""
    laravel_row: dict[str, object] | None = None
    if site is not None and site.application != "wordpress":
        from laravel import observation as laravel_observation

        inventory = laravel_observation.read(shell)
        laravel_row = (
            laravel_observation.site(inventory, identifier) if inventory is not None else None
        )
        if laravel_row is not None and laravel_row["application"] != "laravel":
            laravel_row = None
        wiring = laravel_wiring(identifier, laravel_row)
    state, _problem = state_of(
        row,
        application=site.application if site is not None else "",
        client=site.client if site is not None else "",
        account=site.account if site is not None else None,
        wiring=wiring,
    )
    if enabled:
        return (
            state == "on"
            and row is not None
            and row["memory_mib"] == review_value.document.get("maxmemory_mib")
        )
    if laravel_row is not None:
        artifacts = row is not None and (row["config_present"] or row["drop_in_present"])
        return not artifacts and not laravel_managed(identifier, laravel_row)
    return state == "off"


def _collect(shell: RemoteShell) -> CollectedSnapshot:
    from discovery.observations import collect

    return collect(shell, sites=False)


SET_SITE_OBJECT_CACHE: Final = ChangeKind(
    slug=SLUG,
    label="Change the object cache",
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    refresh_discovery=True,
    input_shape=InputShape.SITE_OBJECT_CACHE,
)
