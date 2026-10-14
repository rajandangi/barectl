"""Read target sites through native configuration and the upstream Caddy adapter."""

import importlib.resources
import json
import re
import shlex
from typing import TYPE_CHECKING, Final, cast

from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native
from runtimes.catalog import Architecture, load
from runtimes.configuration import MANDATORY

from .bodies.common import NativeState
from .configuration import CADDY_TEMPLATE, POOL_TEMPLATE

POOL_SOURCE: Final = (
    importlib.resources.files("sites.bodies").joinpath("pool_boundary.py").read_text()
    + "\n"
    + importlib.resources.files("sites.bodies")
    .joinpath("pool.py")
    .read_text()
    .replace("from sites.bodies.pool_boundary import ini_pool\n", "")
    .replace('SITE_POOL_TEMPLATE = ""', "SITE_POOL_TEMPLATE = " + repr(POOL_TEMPLATE))
)
NAMES_SOURCE: Final = (
    importlib.resources.files("sites")
    .joinpath("names.py")
    .read_text()
    .replace(
        "from discovery.observations.sites import RESERVED as DISCOVERY_RESERVED",
        'DISCOVERY_RESERVED = frozenset({"www", "html"})',
    )
)
LIVE_SOURCE: Final = (
    importlib.resources.files("runtimes")
    .joinpath("live.py")
    .read_text()
    .replace("from .configuration import MANDATORY", "MANDATORY = " + repr(MANDATORY))
)
if TYPE_CHECKING:
    from discovery.snapshot import Observation, ObservedSite


COMMON_SOURCE: Final = (
    LIVE_SOURCE
    + "\n"
    + NAMES_SOURCE
    + "\n"
    + POOL_SOURCE
    + "\n"
    + importlib.resources.files("sites.bodies")
    .joinpath("common.py")
    .read_text()
    .replace("from sites.bodies.pool import supported_pool\n", "")
    .replace("from sites.bodies.pool_boundary import safe_pool_boundary\n", "")
    .replace("from sites.names import request\n", "")
    .replace("from runtimes.live import live_values, master_identity, protected\n", "")
    .replace('CADDY_TEMPLATE = ""', "CADDY_TEMPLATE = " + repr(CADDY_TEMPLATE))
    .replace('POOL_TEMPLATE = ""', "POOL_TEMPLATE = " + repr(POOL_TEMPLATE))
    .replace(
        "KNOWN_CADDY: dict[str, tuple[str, ...]] = {}",
        "KNOWN_CADDY: dict[str, tuple[str, ...]] = "
        + repr(
            {
                machine: tuple(
                    build.path
                    for build in load().builds
                    if build.entry == "caddy" and build.architecture == architecture
                )
                for machine, architecture in (
                    ("x86_64", Architecture.X86_64),
                    ("aarch64", Architecture.AARCH64),
                )
            }
        ),
    )
)
READ_SOURCE: Final = (
    COMMON_SOURCE + "\nimport sys\n"
    "print(canonical(native_state(sys.argv[1], sys.argv[2], json.loads(sys.argv[3]))))\n"
)


def read_command(identifier: str, runtime: str, names: tuple[str, ...] = ()) -> str:
    from .configuration import SiteSettings

    SiteSettings(identifier, names or ("example.com",), runtime)
    command = shlex.join(
        ["python3", "-c", READ_SOURCE, identifier, runtime, json.dumps(list(names))]
    )
    return "sh -c " + shlex.quote(
        "; ".join([*native.lock_steps("exit 11", "exit 10"), "exec " + command])
    )


def read(
    shell: RemoteShell, identifier: str, runtime: str, names: tuple[str, ...] = ()
) -> NativeState | None:
    result = run_root(shell, read_command(identifier, runtime, names))
    if result.exit_status or result.truncated:
        return None
    try:
        value: object = json.loads(result.stdout)
    except ValueError:
        return None
    if not isinstance(value, dict) or value.get("version") != 1:
        return None
    if not valid_state(value):
        return None
    return cast(NativeState, value)


def valid_state(value: dict[str, object]) -> bool:
    if set(value) != {
        "version",
        "uptime",
        "next_id",
        "boot",
        "digest",
        "disk_digest",
        "validation",
        "current_sites",
        "sites",
        "evidence",
        "master_present",
    }:
        return False
    if not all(type(value.get(key)) is int for key in ("version", "uptime", "next_id")):
        return False
    if type(value.get("master_present")) is not bool:
        return False
    if not all(
        isinstance(value.get(key), str) and re.fullmatch(r"[0-9a-f]{64}", str(value[key]))
        for key in ("digest", "disk_digest")
    ):
        return False
    if (
        not isinstance(value.get("boot"), str)
        or re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", str(value["boot"])) is None
    ):
        return False
    if value.get("validation") not in ("valid", "unavailable", "not_requested"):
        return False
    current, sites, evidence = value.get("current_sites"), value.get("sites"), value.get("evidence")
    if (
        not isinstance(current, list)
        or len(current) > 64
        or not all(
            isinstance(site, str) and re.fullmatch(r"[a-z][a-z0-9]{2,23}", site) for site in current
        )
    ):
        return False
    if not isinstance(sites, list) or len(sites) > 64 or not isinstance(evidence, dict):
        return False
    return all(valid_site(site) for site in sites)


def valid_site(site: object) -> bool:
    if not isinstance(site, dict) or set(site) != {
        "identifier",
        "runtime",
        "file",
        "state",
        "problem",
        "names",
        "account",
    }:
        return False
    identifier, names, account = site["identifier"], site["names"], site["account"]
    if not isinstance(identifier, str) or re.fullmatch(r"[a-z][a-z0-9]{2,23}", identifier) is None:
        return False
    if site["file"] != f"/etc/caddy/sites/{identifier}.caddy":
        return False
    if site["runtime"] not in ("", "php84", "php85") or site["state"] not in (
        "complete",
        "partial",
        "unsupported",
    ):
        return False
    if not isinstance(site["problem"], str) or len(site["problem"]) > 1000:
        return False
    if (
        not isinstance(names, list)
        or len(names) > 32
        or not all(isinstance(name, str) and len(name) <= 253 for name in names)
    ):
        return False
    return account is None or (
        isinstance(account, list)
        and len(account) == 5
        and type(account[0]) is int
        and type(account[1]) is int
        and isinstance(account[2], str)
        and isinstance(account[3], str)
        and isinstance(account[4], list)
        and all(type(group) is int for group in account[4])
    )


def observed_sites(shell: RemoteShell) -> Observation[tuple[ObservedSite, ...]]:
    from discovery.models import ObservationOutcome, SiteRouting, SiteState
    from discovery.snapshot import Observation, ObservedSite, SiteAccount

    value = read(shell, "observed", "php84")
    source = ("/etc/caddy/sites", "/etc/php-fpm", "/var/www")
    if value is None:
        return Observation(
            ObservationOutcome.INACCESSIBLE,
            source,
            "The native site configuration could not be reconstructed.",
            (),
        )
    rows = []
    for site in value["sites"]:
        account = site["account"]
        identity = None
        if (
            account is not None
            and len(account) == 5
            and type(account[0]) is int
            and type(account[1]) is int
            and isinstance(account[2], str)
            and isinstance(account[3], str)
        ):
            identity = SiteAccount(account[0], account[1], account[2], account[3])
        state = {"complete": SiteState.MANAGED, "partial": SiteState.PARTLY_APPLIED}.get(
            site["state"], SiteState.NOT_FOLLOWING
        )
        rows.append(
            ObservedSite(
                site["identifier"],
                tuple(site["names"]),
                site["runtime"],
                identity,
                state,
                ObservationOutcome.OBSERVED,
                file=site["file"],
                missing=(site["problem"],) if site["problem"] else (),
                convention_revision=5,
                routing=SiteRouting.PHP,
            )
        )
    return Observation(ObservationOutcome.OBSERVED, source, "", tuple(rows))
