"""Read target sites through native configuration and the upstream Caddy adapter."""

import base64
import gzip
import importlib.resources
import json
import re
import shlex
from typing import TYPE_CHECKING, Final, cast

from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native
from runtimes.catalog import Architecture, load
from runtimes.configuration import MANDATORY, PROBE
from runtimes.configuration import render as render_master
from runtimes.observation import with_bounded

from .bodies.common import PHP_TRANSITION_INCOMPLETE as PHP_TRANSITION_INCOMPLETE
from .bodies.common import NativeState
from .configuration import (
    CADDY_TEMPLATE,
    MAINTENANCE_TEMPLATE,
    POOL_TEMPLATE,
    WORDPRESS_TEMPLATE,
)
from .names import readiness_path

POOL_SOURCE: Final = (
    importlib.resources.files("sites.bodies").joinpath("pool_boundary.py").read_text()
    + "\n"
    + importlib.resources.files("sites.bodies")
    .joinpath("pool.py")
    .read_text()
    .replace("from sites.bodies.pool_boundary import ini_pool\n", "")
    .replace('SITE_POOL_TEMPLATE = ""', "SITE_POOL_TEMPLATE = " + repr(POOL_TEMPLATE))
)
NAMES_SOURCE: Final = importlib.resources.files("sites").joinpath("names.py").read_text()
LIVE_SOURCE: Final = (
    importlib.resources.files("runtimes")
    .joinpath("live.py")
    .read_text()
    .replace("from .configuration import MANDATORY", "MANDATORY = " + repr(MANDATORY))
)
SERVING_SOURCE: Final = (
    importlib.resources.files("sites")
    .joinpath("serving.py")
    .read_text()
    .replace(
        "from .configuration import SiteSettings",
        "from types import SimpleNamespace\nSiteSettings = SimpleNamespace",
    )
)
FPM_SOURCE: Final = (
    importlib.resources.files("sites.bodies")
    .joinpath("site_fpm.py")
    .read_text()
    .replace("from runtimes.live import live_values, master_identity, protected\n", "")
)
ADMISSION_SOURCE: Final = (
    importlib.resources.files("sites.bodies")
    .joinpath("admission.py")
    .read_text()
    .replace("from sites.configuration import SiteSettings\n", "")
    .replace("from sites.serving import HAPROXY_UNIT, haproxy_config\n", "")
    .replace(
        "KNOWN_HAPROXY: dict[str, tuple[str, ...]] = {}",
        "KNOWN_HAPROXY = "
        + repr(
            {
                machine: tuple(
                    build.path
                    for build in load().builds
                    if build.entry == "haproxy" and build.architecture == architecture
                )
                for machine, architecture in (
                    ("x86_64", Architecture.X86_64),
                    ("aarch64", Architecture.AARCH64),
                )
            }
        ),
    )
)
if TYPE_CHECKING:
    from discovery.snapshot import Observation, ObservedSite, SiteCertificate


COMMON_SOURCE: Final = with_bounded(
    LIVE_SOURCE,
    NAMES_SOURCE,
    POOL_SOURCE,
    SERVING_SOURCE,
    ADMISSION_SOURCE,
    FPM_SOURCE,
    importlib.resources.files("sites.bodies")
    .joinpath("common.py")
    .read_text()
    .replace("from sites.bodies.pool import supported_pool\n", "")
    .replace("from sites.bodies.pool_boundary import safe_pool_boundary\n", "")
    .replace(
        "from sites.names import readiness_directive, readiness_ok, readiness_path, request\n",
        "",
    )
    .replace(
        "from sites.serving import (\n    diagnostic_pool,\n    fpm_unit,\n    haproxy_config,\n"
        "    master_config,\n    php_directory,\n    site_pool_path,\n)\n",
        "",
    )
    .replace(
        "from sites.bodies.admission import (\n"
        "    hap_api,\n    hap_inventory,\n    hap_validate,\n    hap_wait,\n"
        "    haproxy_state,\n    persist_proxy_state,\n)\n",
        "",
    )
    .replace("from runtimes.live import live_values, master_identity, protected\n", "")
    .replace(
        "from sites.bodies.site_fpm import"
        " RetainedEntry, sfp_file, sfp_retained_shape, site_fpm_evidence\n",
        "",
    )
    .replace('NATIVE_PROBE = ""', "NATIVE_PROBE = " + repr(PROBE))
    .replace('CADDY_TEMPLATE = ""', "CADDY_TEMPLATE = " + repr(CADDY_TEMPLATE))
    .replace(
        'CADDY_MAINTENANCE_TEMPLATE = ""',
        "CADDY_MAINTENANCE_TEMPLATE = " + repr(MAINTENANCE_TEMPLATE),
    )
    .replace(
        'CADDY_WORDPRESS_TEMPLATE = ""',
        "CADDY_WORDPRESS_TEMPLATE = " + repr(WORDPRESS_TEMPLATE),
    )
    .replace('POOL_TEMPLATE = ""', "POOL_TEMPLATE = " + repr(POOL_TEMPLATE))
    .replace(
        "KNOWN_FCGI: dict[str, tuple[str, ...]] = {}",
        "KNOWN_FCGI = "
        + repr(
            {
                machine: tuple(
                    build.path
                    for build in load().builds
                    if build.entry == "fcgi" and build.architecture == architecture
                )
                for machine, architecture in (
                    ("x86_64", Architecture.X86_64),
                    ("aarch64", Architecture.AARCH64),
                )
            }
        ),
    )
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
    .replace(
        "KNOWN_PHP: dict[str, dict[str, tuple[str, ...]]] = {}",
        "KNOWN_PHP: dict[str, dict[str, tuple[str, ...]]] = "
        + repr(
            {
                machine: {
                    entry: tuple(
                        build.path
                        for build in load().builds
                        if build.entry == entry and build.architecture == architecture
                    )
                    for entry in ("php84", "php85")
                }
                for machine, architecture in (
                    ("x86_64", Architecture.X86_64),
                    ("aarch64", Architecture.AARCH64),
                )
            }
        ),
    )
    .replace(
        "KNOWN_NODE: dict[str, dict[str, tuple[str, ...]]] = {}",
        "KNOWN_NODE: dict[str, dict[str, tuple[str, ...]]] = "
        + repr(
            {
                machine: {
                    entry: tuple(
                        build.path
                        for build in load().builds
                        if build.entry == entry and build.architecture == architecture
                    )
                    for entry in ("nodejs_22", "nodejs_24")
                }
                for machine, architecture in (
                    ("x86_64", Architecture.X86_64),
                    ("aarch64", Architecture.AARCH64),
                )
            }
        ),
    )
    .replace(
        "NATIVE_MASTER_FILES: dict[str, dict[str, str]] = {}",
        "NATIVE_MASTER_FILES: dict[str, dict[str, str]] = "
        + repr(
            {
                entry: {
                    "php.ini": render_master(entry).ini,
                    "php-fpm.conf": render_master(entry).master,
                }
                for entry in ("php84", "php85")
            }
        ),
    ),
)
READ_SOURCE: Final = (
    COMMON_SOURCE + "\nimport sys\n"
    "options = json.loads(sys.argv[4])\n"
    "print(canonical(native_state(sys.argv[1], sys.argv[2], json.loads(sys.argv[3]), "
    "site_only=options['site_only'], protections=options['protections'], "
    "https=options['https'])))\n"
)


def python_command(source: str, arguments: tuple[str, ...]) -> str:
    packed = base64.b64encode(gzip.compress(source.encode(), mtime=0)).decode()
    code = "import base64,gzip; exec(gzip.decompress(base64.b64decode(" + repr(packed) + ")))"
    return shlex.join(["python3", "-c", code, *arguments])


PROXY_INVENTORY_COMMAND: Final = python_command(
    with_bounded(SERVING_SOURCE, ADMISSION_SOURCE + "\nprint(json.dumps(hap_inventory()))\n"),
    (),
)


def read_command(
    identifier: str,
    runtime: str,
    names: tuple[str, ...] = (),
    *,
    site_only: bool = False,
    protections: bool = True,
    https: bool = True,
) -> str:
    from .configuration import SiteSettings

    if runtime or identifier != "observed" or names:
        SiteSettings(identifier, names or ("example.com",), runtime, https)
    options = json.dumps({"site_only": site_only, "protections": protections, "https": https})
    command = python_command(READ_SOURCE, (identifier, runtime, json.dumps(list(names)), options))
    return "sh -c " + shlex.quote("; ".join([*native.read_lock_steps(), "exec " + command]))


def read(
    shell: RemoteShell,
    identifier: str,
    runtime: str,
    names: tuple[str, ...] = (),
    *,
    site_only: bool = False,
    protections: bool = True,
    https: bool = True,
) -> NativeState | None:
    result = run_root(
        shell,
        read_command(
            identifier, runtime, names, site_only=site_only, protections=protections, https=https
        ),
    )
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
        "next_proxy_id",
        "boot",
        "digest",
        "disk_digest",
        "validation",
        "current_sites",
        "sites",
        "evidence",
        "master_present",
        "pool_validation",
    }:
        return False
    if not all(
        type(value.get(key)) is int for key in ("version", "uptime", "next_id", "next_proxy_id")
    ):
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
    if any(
        value.get(key) not in ("valid", "unavailable", "not_requested")
        for key in ("validation", "pool_validation")
    ):
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


def _valid_application(site: dict[str, object]) -> bool:
    application = site.get("application", "plain")
    version = site.get("application_version", "")
    problem = site.get("application_problem", "")
    return (
        application in ("plain", "wordpress", "wordpress_partial")
        and isinstance(version, str)
        and len(version) <= 40
        and isinstance(problem, str)
        and len(problem) <= 500
    )


def valid_site(site: object) -> bool:
    required = {
        "identifier",
        "runtime",
        "node_runtime",
        "https",
        "readiness",
        "certificate",
        "file",
        "state",
        "problem",
        "names",
        "account",
    }
    optional = {"application", "application_version", "application_problem"}
    if not isinstance(site, dict) or not required <= set(site) <= required | optional:
        return False
    if not _valid_application(site) or not _valid_site_scalars(site):
        return False
    return _valid_names(site["names"]) and _valid_account(site["account"])


def _valid_site_scalars(site: dict[str, object]) -> bool:
    identifier = site["identifier"]
    if not isinstance(identifier, str) or re.fullmatch(r"[a-z][a-z0-9]{2,23}", identifier) is None:
        return False
    if type(site["https"]) is not bool or not valid_certificate(site["certificate"]):
        return False
    readiness = site["readiness"]
    if not isinstance(readiness, str) or readiness_path(readiness)[1]:
        return False
    if site["node_runtime"] not in ("", "nodejs_22", "nodejs_24"):
        return False
    if site["file"] != f"/etc/caddy/sites/{identifier}.caddy":
        return False
    if site["runtime"] not in ("", "php84", "php85") or site["state"] not in (
        "complete",
        "partial",
        "unsupported",
    ):
        return False
    return isinstance(site["problem"], str) and len(site["problem"]) <= 1000


def _valid_names(value: object) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= 32
        and all(isinstance(name, str) and len(name) <= 253 for name in value)
    )


def _valid_account(account: object) -> bool:
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


def valid_certificate(value: object) -> bool:
    if value is None:
        return True
    if not isinstance(value, dict):
        return False
    state = value.get("state")
    if state in ("http", "waiting"):
        return set(value) == {"state"}
    if state == "failing":
        error = value.get("error")
        return set(value) == {"state", "error"} and isinstance(error, str) and len(error) <= 400
    if state in ("issued", "renewal_due"):
        issuer, not_after, names = value.get("issuer"), value.get("not_after"), value.get("names")
        return (
            set(value) == {"state", "issuer", "not_after", "names"}
            and isinstance(issuer, str)
            and len(issuer) <= 200
            and type(not_after) is int
            and not_after >= 0
            and isinstance(names, list)
            and 0 < len(names) <= 64
            and all(isinstance(name, str) and 0 < len(name) <= 253 for name in names)
        )
    return False


def observed_certificate(value: object) -> SiteCertificate | None:
    from discovery.snapshot import SiteCertificate

    if not isinstance(value, dict):
        return None
    state = str(value["state"])
    names = value.get("names")
    return SiteCertificate(
        state=state,
        issuer=str(value.get("issuer", "")),
        not_after=int(str(value.get("not_after", 0))),
        error=str(value.get("error", "")),
        names=tuple(str(name) for name in names) if isinstance(names, list) else (),
    )


def observed_site(site: dict[str, object]) -> ObservedSite:
    from discovery.models import ObservationOutcome, SiteState
    from discovery.snapshot import ObservedSite, SiteAccount

    account = site["account"]
    identity = None
    if (
        isinstance(account, list)
        and len(account) == 5
        and type(account[0]) is int
        and type(account[1]) is int
        and isinstance(account[2], str)
        and isinstance(account[3], str)
    ):
        identity = SiteAccount(account[0], account[1], account[2], account[3])
    state = {"complete": SiteState.MANAGED, "partial": SiteState.PARTLY_APPLIED}.get(
        str(site["state"]), SiteState.NOT_FOLLOWING
    )
    problem = str(site["problem"])
    return ObservedSite(
        str(site["identifier"]),
        tuple(str(name) for name in cast(list[object], site["names"])),
        str(site["runtime"]),
        identity,
        state,
        ObservationOutcome.OBSERVED,
        file=str(site["file"]),
        missing=(problem,) if problem else (),
        node_runtime=str(site["node_runtime"]),
        https=bool(site["https"]),
        readiness=str(site["readiness"]),
        certificate=observed_certificate(site["certificate"]),
        application=str(site.get("application", "plain")),
        application_version=str(site.get("application_version", "")),
        application_problem=str(site.get("application_problem", "")),
    )


UNREADABLE_SITE: Final = "The site's live PHP protection evidence could not be read."


def observed_sites(shell: RemoteShell) -> Observation[tuple[ObservedSite, ...]]:
    from discovery.models import ObservationOutcome
    from discovery.snapshot import Observation

    source = ("/etc/caddy/sites", "/etc/php-fpm", "/var/www")
    value = read(shell, "observed", "", protections=False)
    if value is None:
        return Observation(
            ObservationOutcome.INACCESSIBLE,
            source,
            "The native site configuration could not be reconstructed.",
            (),
        )
    records: list[dict[str, object]] = [dict(site) for site in value["sites"]]
    for index, site in enumerate(value["sites"]):
        if not site["runtime"]:
            continue
        # One bounded read per site: no single command bundles several sites' live
        # PHP protection evidence (docs/ssh-connections.md#bounds-and-read-only-commands).
        deep = read(shell, str(site["identifier"]), str(site["runtime"]), site_only=True)
        matching = (
            next(
                (
                    candidate
                    for candidate in deep["sites"]
                    if candidate["identifier"] == site["identifier"]
                ),
                None,
            )
            if deep is not None
            else None
        )
        records[index] = (
            {**dict(site), "state": "unsupported", "problem": UNREADABLE_SITE}
            if matching is None
            else dict(matching)
        )
    return Observation(
        ObservationOutcome.OBSERVED, source, "", tuple(observed_site(row) for row in records)
    )
