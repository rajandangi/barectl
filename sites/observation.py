"""Read target sites through native configuration and the upstream Caddy adapter."""

import importlib.resources
import json
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
    if not all(type(value.get(key)) is int for key in ("version", "uptime", "next_id")):
        return False
    if not all(
        isinstance(value.get(key), str) for key in ("boot", "digest", "disk_digest", "validation")
    ):
        return False
    current, sites, evidence = value.get("current_sites"), value.get("sites"), value.get("evidence")
    if not isinstance(current, list) or not all(isinstance(site, str) for site in current):
        return False
    if not isinstance(sites, list) or len(sites) > 64 or not isinstance(evidence, dict):
        return False
    return all(
        isinstance(site, dict)
        and isinstance(site.get("identifier"), str)
        and isinstance(site.get("runtime"), str)
        and isinstance(site.get("file"), str)
        and isinstance(site.get("state"), str)
        and isinstance(site.get("problem"), str)
        and isinstance(site.get("names"), list)
        and all(isinstance(name, str) for name in site["names"])
        and (site.get("account") is None or isinstance(site["account"], list))
        for site in sites
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
