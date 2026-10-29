import base64
import contextlib
import fcntl
import grp
import hashlib
import json
import os
import pathlib
import pwd
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from typing import TYPE_CHECKING, Final, NotRequired, TypedDict

from runtimes.live import live_values, master_identity, protected
from sites.bodies.admission import (
    hap_api,
    hap_inventory,
    hap_validate,
    hap_wait,
    haproxy_state,
    persist_proxy_state,
)
from sites.bodies.logrotate import logrotate_state
from sites.bodies.pool import (
    SitePool,
    extension_line,
    parse_pool,
    pool_extension,
    render_pool_settings,
    supported_pool,
    without_extension,
)
from sites.bodies.pool_boundary import safe_pool_boundary
from sites.bodies.site_fpm import RetainedEntry, sfp_file, sfp_retained_shape, site_fpm_evidence
from sites.names import readiness_directive, readiness_ok, readiness_path, request
from sites.serving import (
    diagnostic_pool,
    fpm_unit,
    haproxy_config,
    master_config,
    php_directory,
    site_pool_path,
)

PHP_TRANSITION_INCOMPLETE: Final[str] = "The PHP runtime transition is incomplete."
CADDY_OUTSIDE: Final[str] = "The site has Caddy settings outside the supported configuration."
POOL_OUTSIDE: Final[str] = "The site pool has settings outside the supported bounds."
ROUTE_ABSENT: Final[str] = (
    "Native account, group, directory or pool evidence exists, but its Caddy route is absent."
)
NODE_INTERRUPTED: Final[str] = "The site's Node command links have an interrupted selection."
SITE_GATED: Final[str] = (
    "The site's maintenance gate is in place until the change that published it verifies."
)


if TYPE_CHECKING:
    from automation.bodies.units import fence, restore
    from sites.configuration import SiteSettings


class SiteRecord(TypedDict):
    identifier: str
    names: list[str]
    runtime: str
    node_runtime: str
    https: bool
    readiness: str
    certificate: dict[str, object] | None
    pool: dict[str, object] | None
    account: list[object] | None
    file: str
    state: str
    problem: str
    application: str
    application_version: str
    application_problem: str
    serving_form: str
    client: NotRequired[str]
    # The supported state of the site's root-owned logrotate file (Phase C #389).
    log_rotation: NotRequired[str]


class NativeState(TypedDict):
    version: int
    boot: str
    uptime: int
    sites: list[SiteRecord]
    current_sites: list[str]
    disk_digest: str
    digest: str
    evidence: dict[str, dict[str, object] | None]
    next_id: int
    next_proxy_id: int
    validation: str
    pool_validation: str
    master_present: bool


class SiteNodeState(TypedDict):
    native: NativeState
    selection: str
    problem: str
    profiles: dict[str, str]
    links: dict[str, str | None]
    digest: str


CADDY_TEMPLATE = ""
CADDY_MAINTENANCE_TEMPLATE = ""
CADDY_WORDPRESS_TEMPLATE = ""
CADDY_LARAVEL_TEMPLATE = ""
POOL_TEMPLATE = ""
KNOWN_CADDY: dict[str, tuple[str, ...]] = {}
KNOWN_PHP: dict[str, dict[str, tuple[str, ...]]] = {}
KNOWN_NODE: dict[str, dict[str, tuple[str, ...]]] = {}
# The locked phpredis shared object per machine and PHP runtime (#390), baked into the
# native source from the catalog lock so recognition never guesses a store path.
KNOWN_REDIS: dict[str, dict[str, str]] = {}
NATIVE_MASTER_FILES: dict[str, dict[str, str]] = {}
ADMIN = "unix//run/caddy/admin.sock"
RUNTIME_READ_SOURCE = ""
NATIVE_PROBE = ""
KNOWN_FCGI: dict[str, tuple[str, ...]] = {}


def run(args: list[str], text: str | None = None, *, check: bool = True) -> str:
    process = subprocess.Popen(  # noqa: S603 - fixed native argv and validated convention values
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(text, timeout=20)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise
    if len(stdout) > 1048576 or len(stderr) > 1048576 or (check and process.returncode):
        raise ValueError("The native command failed or exceeded its bound.")
    return stdout


def setting(
    identifier: str,
    names: list[str],
    entry: str,
    https: bool = True,
    readiness: str = "/",
) -> SimpleNamespace:
    if entry not in ("php84", "php85"):
        raise ValueError("Invalid PHP runtime.")
    canonical_identifier, canonical_names = request(identifier, " ".join(names))
    canonical_readiness, problem = readiness_path(readiness)
    if (
        canonical_identifier != identifier
        or list(canonical_names) != names
        or problem
        or canonical_readiness != readiness
    ):
        raise ValueError("The native site selection is not canonical.")
    return SimpleNamespace(
        identifier=identifier,
        names=names,
        runtime=entry,
        https=https,
        readiness=readiness,
        account="s" + identifier,
        directory="/var/www/" + identifier,
        socket=f"/run/php-fpm/sites/{identifier}/{entry}/app.sock",
        proxy_socket=f"/run/haproxy/{identifier}/http.sock",
        proxy="p" + identifier,
    )


def site_address(settings: SimpleNamespace, name: str) -> str:
    """A bare host for HTTPS, an explicit ``http://`` host for an HTTP-only site."""
    return ("" if settings.https else "http://") + name


def caddy_file(settings: SimpleNamespace) -> str:
    return CADDY_TEMPLATE.format(
        settings=settings,
        addresses=", ".join(site_address(settings, n) for n in settings.names),
        readiness=readiness_directive(settings.readiness),
    )


def alias_directives(settings: SimpleNamespace, *, enabled: bool = True) -> tuple[str, str]:
    """The alias redirect lines, or empty strings for a single-name site."""
    if not enabled or len(settings.names) < 2:
        return "", ""
    primary = settings.names[0]
    scheme = "https" if settings.https else "http"
    return (
        f'    @alias expression {{http.request.host}} != "{primary}"\n',
        f"        redir @alias {scheme}://{primary}{{uri}} permanent\n",
    )


def wordpress_caddy_file(settings: SimpleNamespace, *, aliases: bool = True) -> str:
    alias_matcher, alias_redirect = alias_directives(settings, enabled=aliases)
    return CADDY_WORDPRESS_TEMPLATE.format(
        settings=settings,
        addresses=", ".join(site_address(settings, n) for n in settings.names),
        alias_matcher=alias_matcher,
        alias_redirect=alias_redirect,
    )


def laravel_caddy_file(settings: SimpleNamespace, *, aliases: bool = True) -> str:
    alias_matcher, alias_redirect = alias_directives(settings, enabled=aliases)
    return CADDY_LARAVEL_TEMPLATE.format(
        settings=settings,
        addresses=", ".join(site_address(settings, n) for n in settings.names),
        alias_matcher=alias_matcher,
        alias_redirect=alias_redirect,
    )


def maintenance_file(settings: SimpleNamespace) -> str:
    return CADDY_MAINTENANCE_TEMPLATE.format(
        settings=settings,
        addresses=", ".join(site_address(settings, n) for n in settings.names),
    )


CADDY_UNIT = "caddy.service"
CERTIFICATE_LIMIT = 64
RENEWAL_WINDOW_SECONDS = 30 * 86400
NOT_AFTER_FORMAT = "%b %d %H:%M:%S %Y %Z"


def process_environment(pid: str) -> dict[str, str]:
    try:
        raw = pathlib.Path(f"/proc/{pid}/environ").read_bytes()
    except OSError:
        return {}
    values: dict[str, str] = {}
    for item in raw.split(b"\0"):
        key, separator, value = item.partition(b"=")
        if separator:
            values[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")
    return values


def caddy_data_directory() -> str:
    """Caddy's own app data directory, from the running unit's environment (docs/tls.md)."""
    try:
        pid = run(["systemctl", "show", "--value", "-p", "MainPID", CADDY_UNIT]).strip()
    except ValueError:
        pid = ""
    environment = process_environment(pid) if pid.isdigit() and pid != "0" else {}
    home = environment.get("HOME") or "/var/lib/caddy"
    data = environment.get("XDG_DATA_HOME") or home.rstrip("/") + "/.local/share"
    return data.rstrip("/") + "/caddy"


def certificate_names(path: str) -> list[str]:
    try:
        text = run(["/usr/bin/openssl", "x509", "-in", path, "-noout", "-ext", "subjectAltName"])
    except ValueError, OSError, subprocess.TimeoutExpired:
        return []
    return [match.group(1) for match in re.finditer(r"DNS:([^,/\s]+)", text)]


def certificate_metadata(path: str) -> tuple[str, int]:
    import calendar

    try:
        text = run(["/usr/bin/openssl", "x509", "-in", path, "-noout", "-issuer", "-enddate"])
    except ValueError, OSError, subprocess.TimeoutExpired:
        return "", 0
    issuer, not_after = "", 0
    for line in text.splitlines():
        if line.startswith("issuer="):
            issuer = line[len("issuer=") :].strip()[:200]
        elif line.startswith("notAfter="):
            try:
                not_after = calendar.timegm(
                    time.strptime(line[len("notAfter=") :].strip(), NOT_AFTER_FORMAT)
                )
            except ValueError:
                not_after = 0
    return issuer, not_after


def issuance_error(names: list[str]) -> str:
    """The last bounded Caddy issuance error naming one of the site's hosts, or empty."""
    try:
        text = run(
            [
                "/usr/bin/journalctl",
                "-u",
                CADDY_UNIT,
                "--no-pager",
                "-n",
                "200",
                "-o",
                "cat",
                "--grep",
                "error|obtain|challenge",
                "-i",
            ]
        )
    except ValueError, OSError, subprocess.TimeoutExpired:
        return ""
    wanted = set(names)
    error = ""
    for line in text.splitlines():
        lowered = line.lower()
        if not any(word in lowered for word in ("error", "obtain", "challenge")):
            continue
        if any(name in line for name in wanted):
            error = line.strip()[:200]
    return error


def certificate_state(names: list[str], https: bool) -> dict[str, object]:
    """The site's certificate state from Caddy's stored certificate files (docs/tls.md)."""
    if not https:
        return {"state": "http"}
    base = pathlib.Path(caddy_data_directory()) / "certificates"
    wanted = set(names)
    found: list[dict[str, object]] = []
    with contextlib.suppress(OSError):
        for directory in sorted(base.glob("*/*"))[:CERTIFICATE_LIMIT]:
            for path in sorted(directory.glob("*.crt"))[:8]:
                with contextlib.suppress(OSError):
                    if path.stat().st_size > 65536:
                        continue
                    cert_names = certificate_names(str(path))
                    if not wanted.intersection(cert_names):
                        continue
                    issuer, not_after = certificate_metadata(str(path))
                    found.append({"names": cert_names, "issuer": issuer, "not_after": not_after})
    if found:
        best = max(found, key=lambda item: int(str(item["not_after"])))
        remaining = int(str(best["not_after"])) - int(time.time())
        return {
            "state": "renewal_due" if 0 < remaining < RENEWAL_WINDOW_SECONDS else "issued",
            "issuer": best["issuer"],
            "not_after": best["not_after"],
            "names": best["names"],
        }
    error = issuance_error(names)
    return {"state": "failing", "error": error} if error else {"state": "waiting"}


def pool_file(settings: SiteSettings | SimpleNamespace, extension: str = "") -> str:
    pool = POOL_TEMPLATE.format(settings=settings)
    return pool + (extension_line(extension) if extension else "")


def known_redis(runtime: str) -> str:
    """The locked phpredis shared object for ``runtime`` on this machine, or ``""``."""
    return KNOWN_REDIS.get(os.uname().machine, {}).get(runtime, "")


def caddy_binary() -> str:
    target = os.path.realpath("/nix/var/nix/profiles/barectl/caddy")
    if target not in KNOWN_CADDY.get(os.uname().machine, ()):
        raise ValueError("Caddy's native profile is not a known catalog build.")
    return target + "/bin/caddy"


def adapt(text: str | None = None, path: str = "/etc/caddy/Caddyfile") -> object:
    return json.loads(
        run(
            [
                caddy_binary(),
                "adapt",
                "--config",
                "-" if text is not None else path,
                "--adapter",
                "caddyfile",
            ],
            text,
        )
    )


def running() -> object:
    return json.loads(
        run(
            [
                "/usr/bin/curl",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "5",
                "--unix-socket",
                "/run/caddy/admin.sock",
                "http://localhost/config/",
            ]
        )
    )


def safe(path: str, *, directory: bool = False) -> bool:
    p = pathlib.Path(path)
    try:
        metadata = p.lstat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022 or stat.S_ISLNK(metadata.st_mode):
            return False
        if directory and not stat.S_ISDIR(metadata.st_mode):
            return False
        if not directory and (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1):
            return False
        return all(safe(str(parent), directory=True) for parent in p.parents)
    except OSError:
        return False


def fingerprint(path: str) -> dict[str, object] | None:
    try:
        p = pathlib.Path(path)
        info = p.lstat()
        value: dict[str, object] = {
            "uid": info.st_uid,
            "gid": info.st_gid,
            "mode": stat.S_IMODE(info.st_mode),
            "type": stat.S_IFMT(info.st_mode),
            "inode": info.st_ino,
            "ctime": info.st_ctime_ns,
        }
        if stat.S_ISLNK(info.st_mode):
            value["link"] = os.readlink(p)
        elif stat.S_ISREG(info.st_mode):
            if info.st_size > 65536:
                raise ValueError("A native file exceeds its bound.")
            value["sha256"] = hashlib.sha256(p.read_bytes()).hexdigest()
        return value
    except FileNotFoundError:
        return None


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def walk_routes(node: object, hosts: list[list[str]], roots: set[str], dials: set[str]) -> None:
    if isinstance(node, dict):
        for key, child in node.items():
            if key == "host" and isinstance(child, list) and all(isinstance(x, str) for x in child):
                hosts.append(child)
            elif key == "root" and isinstance(child, str):
                roots.add(child)
            elif key == "dial" and isinstance(child, str):
                dials.add(child)
            walk_routes(child, hosts, roots, dials)
    elif isinstance(node, list):
        for child in node:
            walk_routes(child, hosts, roots, dials)


def readiness_handlers(node: object, found: list[object]) -> None:
    if isinstance(node, dict):
        if node.get("handler") == "vars" and "readiness_path" in node:
            found.append(node["readiness_path"])
        for child in node.values():
            readiness_handlers(child, found)
    elif isinstance(node, list):
        for child in node:
            readiness_handlers(child, found)


def site_readiness(server: object) -> str:
    """The readiness path a site's adapted Caddy configuration holds, or its default.

    A non-default path is one ``vars readiness_path`` handler. Caddy applies it to every
    request, so it is ordinary native configuration and a fresh controller reads it without
    a Barectl marker. Any other use of ``vars`` is outside the convention.
    """
    found: list[object] = []
    readiness_handlers(server, found)
    if len(found) > 1:
        raise ValueError("A site has more than one readiness path.")
    if not found:
        return "/"
    value = found[0]
    if not isinstance(value, str):
        raise ValueError("A site has an unsupported readiness path.")
    path, problem = readiness_path(value)
    if problem or path != value:
        raise ValueError("A site has an unsupported readiness path.")
    return path


def extract(identifier: str, value: object) -> SimpleNamespace:
    """The site selection an adapted file describes.

    Caddy merges every site into one server per listener, so an HTTPS site's own route
    lives in the ``:443`` server while its automatic HTTP-to-HTTPS redirect lives in the
    ``:80`` server beside the catch-all. This finds the one server that carries the site's
    private admission socket, reads the site's names and root there, and takes the HTTPS
    setting from that server's listener.
    """
    http = value.get("apps", {}) if isinstance(value, dict) else None
    http = http.get("http", {}) if isinstance(http, dict) else None
    servers = http.get("servers", {}) if isinstance(http, dict) else None
    if not isinstance(servers, dict):
        raise ValueError("A site has unsupported private routing.")
    socket = f"unix//run/haproxy/{identifier}/http.sock"
    root = f"/var/www/{identifier}/current/public"
    matches: list[tuple[dict[str, object], list[list[str]], set[str], set[str]]] = []
    for server in servers.values():
        if not isinstance(server, dict):
            continue
        hosts: list[list[str]] = []
        roots: set[str] = set()
        dials: set[str] = set()
        walk_routes(server, hosts, roots, dials)
        if socket in dials:
            matches.append((server, hosts, roots, dials))
    if len(matches) != 1:
        raise ValueError("A site has unsupported private routing.")
    server, hosts, roots, dials = matches[0]
    if len(hosts) != 1 or dials != {socket}:
        raise ValueError("A site has unsupported private routing.")
    listen = server.get("listen")
    if not isinstance(listen, list) or not all(isinstance(item, str) for item in listen):
        raise ValueError("A site has an unsupported listener.")
    if roots == {root}:
        return setting(
            identifier,
            hosts[0],
            "php84",
            https=":443" in listen,
            readiness=site_readiness(server),
        )
    if not roots:
        # A maintenance gate keeps the site's names and private socket but serves 503
        # until the change that published it verifies (docs/target-architecture.md).
        return setting(
            identifier,
            hosts[0],
            "php84",
            https=":443" in listen,
            readiness="/",
        )
    raise ValueError("A site has unsupported private routing.")


def membership(entry: str) -> list[str]:
    directory = pathlib.Path(f"/etc/php-fpm/{entry}/pools")
    if not directory.exists() and not directory.is_symlink():
        return []
    if not safe(str(directory), directory=True):
        raise ValueError("Unsafe pool directory.")
    identifiers = []
    for path in sorted(directory.glob("*.conf")):
        if path.name == "diagnostic.conf":
            continue
        identifier = path.stem
        if not safe(str(path)):
            raise ValueError("Unsafe pool file.")
        if not safe_pool_boundary(identifier, entry, path.read_text()):
            raise ValueError("An unsupported pool blocks this master's change.")
        identifiers.append(identifier)
    return identifiers


def metadata_matches(path: str, uid: int, gid: int, mode: int, kind: int) -> bool:
    value = fingerprint(path)
    return (
        value is not None
        and value.get("uid") == uid
        and value.get("gid") == gid
        and value.get("mode") == mode
        and value.get("type") == kind
    )


def wrapper(settings: SiteSettings | SimpleNamespace, name: str, extension: str = "") -> str:
    executable = {
        "php": f"/nix/var/nix/profiles/barectl/{settings.runtime}/bin/php",
        "composer": "/nix/var/nix/profiles/barectl/composer/share/php/composer/bin/composer",
        "wp": "/nix/var/nix/profiles/barectl/wp-cli/share/wp-cli/wp-cli.phar",
    }[name]
    # The build's own ini is loaded before the command line, so phpredis must be named on the
    # command line: the extension needs session, which the build's ini loads after a ``-c``
    # ini would have requested redis (#390). CLI commands get the same client as the master.
    client = f" -dextension={extension}" if extension else ""
    command = (
        f'"{executable}"{client}'
        if name == "php"
        else f'"/nix/var/nix/profiles/barectl/{settings.runtime}/bin/php"{client} "{executable}"'
    )
    return "#!/bin/sh\nexec " + command + ' "$@"\n'


def known_node_profile(entry: str) -> str:
    if entry not in ("nodejs_22", "nodejs_24"):
        raise ValueError("Invalid Node runtime.")
    profile = pathlib.Path("/nix/var/nix/profiles/barectl") / entry
    if not safe(str(profile.parent), directory=True):
        return ""
    try:
        if profile.lstat().st_uid != 0 or not profile.is_symlink():
            return ""
        target = os.path.realpath(profile)
        if target not in KNOWN_NODE.get(os.uname().machine, {}).get(entry, ()):
            return ""
        if any(
            not (pathlib.Path(target) / "bin" / name).is_file() for name in ("node", "npm", "npx")
        ):
            return ""
        return target
    except OSError:
        return ""


def node_command_links(identifier: str) -> tuple[str, str, dict[str, str | None]]:
    links: dict[str, str | None] = {}
    selections = set()
    for name in ("node", "npm", "npx"):
        path = pathlib.Path("/var/www") / identifier / "bin" / name
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            links[name] = None
            continue
        if not stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0:
            return "", "A site Node command is set by the administrator.", links
        target = os.readlink(path)
        links[name] = target
        entry = next(
            (
                entry
                for entry in ("nodejs_22", "nodejs_24")
                if target == f"/nix/var/nix/profiles/barectl/{entry}/bin/{name}"
            ),
            "",
        )
        if not entry or not known_node_profile(entry):
            return "", "A site Node command does not select a known installed runtime.", links
        selections.add(entry)
    if not selections:
        return "", "", links
    if len(selections) != 1 or any(value is None for value in links.values()):
        return "", NODE_INTERRUPTED, links
    return next(iter(selections)), "", links


def site_node_state(identifier: str) -> SiteNodeState:
    value = native_state(identifier, "")
    site = next((site for site in value["sites"] if site["identifier"] == identifier), None)
    if site is None:
        raise ValueError("The site was not observed.")
    value = native_state(identifier, site["runtime"])
    selected, problem, links = node_command_links(identifier)
    profiles = {entry: known_node_profile(entry) for entry in ("nodejs_22", "nodejs_24")}
    metadata = {
        str(path): fingerprint(str(path))
        for path in [
            *(
                pathlib.Path("/var/www") / identifier / "bin" / name
                for name in ("node", "npm", "npx")
            ),
            *(pathlib.Path("/nix/var/nix/profiles/barectl") / entry for entry in profiles),
            pathlib.Path("/var/www") / identifier / "bin",
            pathlib.Path("/var/www") / identifier / ".deploy.lock",
        ]
    }
    digest = hashlib.sha256(
        canonical({"native": value["digest"], "metadata": metadata, "profiles": profiles}).encode()
    ).hexdigest()
    return {
        "native": value,
        "selection": selected,
        "problem": problem,
        "profiles": profiles,
        "links": links,
        "digest": digest,
    }


def same_site_lock(descriptor: int, identifier: str) -> bool:
    path = pathlib.Path("/var/www") / identifier / ".deploy.lock"
    if not safe(str(path)):
        return False
    opened, current = os.fstat(descriptor), path.lstat()
    account = site_account(identifier)
    return (
        (opened.st_dev, opened.st_ino) == (current.st_dev, current.st_ino)
        and account is not None
        and opened.st_uid == 0
        and opened.st_gid == account[1]
        and stat.S_IMODE(opened.st_mode) == 0o640
        and opened.st_nlink == 1
    )


def open_site_lock(identifier: str) -> int:
    path = pathlib.Path("/var/www") / identifier / ".deploy.lock"
    if not safe(str(path)):
        raise ValueError("Unsafe site deployment lock.")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not same_site_lock(descriptor, identifier):
            raise ValueError("The site deployment lock changed.")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not same_site_lock(descriptor, identifier):
            raise ValueError("The site deployment lock changed.")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def set_site_node(document: dict[str, object]) -> None:
    try:
        descriptor = open_site_lock(str(document["identifier"]))
    except BlockingIOError:
        result("lock_busy")
        return
    except OSError, ValueError:
        result("refused", "unsafe_lock")
        return
    try:
        node_locked_change(document, descriptor)
    finally:
        os.close(descriptor)


def node_locked_change(  # noqa: C901 - reviewed stages
    document: dict[str, object], descriptor: int
) -> None:
    changed = False
    identifier, selection = str(document["identifier"]), str(document["selection"])
    try:
        state = site_node_state(identifier)
        if state["digest"] != document["precondition_digest"]:
            result("refused", "precondition")
            return
        if not known_node_profile(selection) or known_node_profile(selection) != document["path"]:
            result("refused", "runtime_cache")
            return
        site = next(site for site in state["native"]["sites"] if site["identifier"] == identifier)
        if site["state"] != "complete" and site["problem"] != NODE_INTERRUPTED:
            result("refused", "evidence")
            return
        directory = pathlib.Path("/var/www") / identifier / "bin"
        if not safe(str(directory), directory=True) or not same_site_lock(descriptor, identifier):
            result("refused", "evidence")
            return
        if not fence(document, identifier):
            result("refused", "automation_fence")
            return
        stage("links")
        with tempfile.TemporaryDirectory(prefix=".node-", dir=directory) as temporary:
            for name in ("node", "npm", "npx"):
                candidate = pathlib.Path(temporary) / name
                candidate.symlink_to(f"/nix/var/nix/profiles/barectl/{selection}/bin/{name}")
            for name in ("node", "npm", "npx"):
                os.replace(pathlib.Path(temporary) / name, directory / name)
                changed = True
        stage("verify")
        selected, problem, _ = node_command_links(identifier)
        if selected != selection or problem or not same_site_lock(descriptor, identifier):
            raise ValueError("The selected native command links could not be verified.")
        if not restore(document, identifier):
            result("partial", "automation_restore")
            return
        result("succeeded")
    except OSError, ValueError, KeyError, StopIteration, subprocess.TimeoutExpired:
        result("partial", "runtime_config") if changed else result("refused", "evidence")


def account_ids(settings: SimpleNamespace, attributes: list[object]) -> tuple[int, int]:
    uid, gid = attributes[:2]
    if (
        not isinstance(uid, int)
        or not isinstance(gid, int)
        or not 1000 <= uid < 30000
        or not 1000 <= gid < 30000
    ):
        raise ValueError("The site's IDs are outside the supported allocation range.")
    account_group = grp.getgrnam(settings.account)
    if account_group.gr_gid != gid or attributes[2:] != [
        settings.directory,
        "/usr/sbin/nologin",
        [gid],
    ]:
        raise ValueError("The account or supplementary groups differ from the convention.")
    shadow = next(
        (
            line.split(":")[1]
            for line in pathlib.Path("/etc/shadow").read_text().splitlines()
            if line.startswith(settings.account + ":")
        ),
        "",
    )
    if not shadow.startswith(("!", "*")):
        raise ValueError("The site account's password is not locked.")
    return uid, gid


def laravel_release(directory: str) -> bool:
    """Whether a release has the Laravel shape, recognized by shape and never by a marker.

    Phase B's recognition: ``artisan`` plus the shared ``.env`` and storage links in
    ``current``. A release published by another controller's CI is recognized exactly like
    Barectl's own.
    """
    base = pathlib.Path(directory)
    artisan = base / "artisan"
    return (
        artisan.is_file()
        and not artisan.is_symlink()
        and (base / ".env").is_symlink()
        and (base / "storage").is_symlink()
    )


def directory_shape(  # noqa: C901 - one recognition of the whole release layout
    settings: SimpleNamespace, uid: int, gid: int
) -> tuple[str, str]:
    current = pathlib.Path(settings.directory) / "current"
    try:
        target = os.readlink(current)
    except FileNotFoundError:
        return "partial", "The current release link is absent."
    except OSError:
        return "unsupported", "The current release entry is not a supported link."
    if (
        re.fullmatch(r"releases/[A-Za-z0-9][A-Za-z0-9._-]{0,63}", target) is None
        or current.lstat().st_uid != 0
    ):
        return "unsupported", "The current release link leaves the root-controlled release layout."
    caddy_gid = grp.getgrnam("caddy").gr_gid
    release = settings.directory + "/" + target
    # A Laravel release belongs to the site user and is classified so that Caddy reads
    # only ``public``: every other directory is traversal-only and PHP source is the site
    # user's (Phase B; docs/adr/0040-classify-laravel-release-permissions.md).
    classified = laravel_release(release)
    # Every release Barectl creates or restores belongs to the site user (Phase D #401).
    # A root-owned release is the earlier form and stays recognizable on existing sites.
    release_forms = ((uid, gid, 0o711), (0, 0, 0o755))
    directories = (
        (settings.directory, 0, 0, 0o755),
        (settings.directory + "/releases", 0, 0, 0o755),
        (release + "/public", uid, caddy_gid, 0o2750),
        (settings.directory + "/private", uid, gid, 0o700),
        (settings.directory + "/private/sessions", uid, gid, 0o700),
        (settings.directory + "/private/tmp", uid, gid, 0o700),
        (settings.directory + "/logs", pwd.getpwnam("caddy").pw_uid, gid, 0o750),
        (settings.directory + "/bin", 0, 0, 0o755),
    )
    for path, owner, group, mode in directories:
        if fingerprint(path) is None:
            return "partial", "A required site directory is absent."
        if not metadata_matches(path, owner, group, mode, stat.S_IFDIR):
            return "unsupported", "A site directory has unsupported ownership or permissions."
    if fingerprint(release) is None:
        return "partial", "A required site directory is absent."
    if not any(
        metadata_matches(release, owner, group, mode, stat.S_IFDIR)
        for owner, group, mode in release_forms
    ):
        return "unsupported", "A site directory has unsupported ownership or permissions."
    for path in laravel_sources(release) if classified else ():
        if fingerprint(path) is None:
            return "partial", "A required site file is absent."
        if not metadata_matches(path, uid, gid, 0o600, stat.S_IFREG):
            return "unsupported", "A site file has unsupported ownership or permissions."
    return "complete", ""


def laravel_sources(release: str) -> tuple[str, ...]:
    """The Laravel source files a release must keep site-only (0600)."""
    return (release + "/artisan", release + "/public/index.php")


def php_wrapper_variant(settings: SimpleNamespace) -> tuple[str, str] | None:
    """The runtime and cache client every site PHP command agrees on, or ``None``."""
    chosen: tuple[str, str] | None = None
    for name in ("php", "composer", "wp"):
        path = settings.directory + "/bin/" + name
        if not safe(path) or not metadata_matches(path, 0, 0, 0o755, stat.S_IFREG):
            return None
        contents = pathlib.Path(path).read_text()
        matches = list(
            dict.fromkeys(
                (entry, extension)
                for entry in ("php84", "php85")
                for extension in ("", known_redis(entry))
                if contents
                == wrapper(setting(settings.identifier, settings.names, entry), name, extension)
            )
        )
        if len(matches) != 1 or (chosen is not None and matches[0] != chosen):
            return None
        chosen = matches[0]
    return chosen


def php_wrapper_selections(settings: SimpleNamespace) -> dict[str, str] | None:
    variant = php_wrapper_variant(settings)
    return None if variant is None else dict.fromkeys(("php", "composer", "wp"), variant[0])


def php_wrapper_runtime(settings: SimpleNamespace) -> str:
    variant = php_wrapper_variant(settings)
    return "" if variant is None else variant[0]


def configuration_shape(
    settings: SimpleNamespace, uid: int, gid: int, *, protections: bool = True
) -> tuple[str, str]:
    lock = settings.directory + "/.deploy.lock"
    if fingerprint(lock) is None:
        return "partial", "The stable per-site deploy lock is absent."
    if not metadata_matches(lock, 0, gid, 0o640, stat.S_IFREG) or not safe(lock):
        return "unsupported", "The deploy lock is outside the root-controlled convention."
    selected = php_wrapper_runtime(settings)
    if not selected:
        if php_wrapper_selections(settings) is not None:
            return "partial", PHP_TRANSITION_INCOMPLETE
        return "unsupported", "The site's PHP commands are administrator-owned or inconsistent."
    if selected != settings.runtime:
        return "partial", PHP_TRANSITION_INCOMPLETE
    return serving_shape(settings, protections=protections)


def php_site_unit(identifier: str, runtime: str) -> str:
    return f"php-fpm-site-{runtime}@{identifier}.service"


def unit_properties(report: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in report.splitlines() if "=" in line)


def php_service_inactive(values: dict[str, str]) -> bool:
    """A runtime's site service is proven stopped; every unresolved state reads as running."""
    return values.get("ActiveState") in ("inactive", "failed") and values.get("MainPID") == "0"


def php_runtime_entries(settings: SimpleNamespace) -> dict[str, RetainedEntry] | None:
    """Owner, mode, kind and bytes of every entry under one runtime's configuration directory."""
    base = php_directory(settings.identifier, settings.runtime)
    observed: dict[str, RetainedEntry] = {}
    for directory in (base, base + "/pools"):
        paths = [directory]
        try:
            paths += [str(entry) for entry in pathlib.Path(directory).iterdir()]
        except FileNotFoundError:
            pass
        except OSError:
            return None
        for path in paths:
            meta = sfp_file(path)
            if meta is None:
                continue
            uid, mode = meta.get("uid"), meta.get("mode")
            if "unreadable" in meta or type(uid) is not int or type(mode) is not int:
                return None
            kinds: dict[object, str] = {stat.S_IFDIR: "dir", stat.S_IFREG: "file"}
            raw = meta.get("bytes")
            observed[path] = (
                uid,
                int(mode),
                kinds.get(meta.get("type"), "other"),
                base64.b64decode(raw) if isinstance(raw, str) else b"",
            )
    return observed


def retained_php_shape(settings: SimpleNamespace, *, active: bool) -> str:
    observed = php_runtime_entries(settings)
    if observed is None:
        return "unsupported"
    expected = site_fpm_files(settings)
    pool = site_pool_path(settings.identifier, settings.runtime)
    try:
        tuned = pathlib.Path(pool).read_text()
    except OSError:
        pass
    else:
        if parse_pool(settings.identifier, settings.runtime, tuned) is None:
            return "unsupported"
        expected[pool] = tuned
    return sfp_retained_shape(expected, observed, active)


def serving_shape(  # noqa: C901 - one recognition path for the whole serving convention
    settings: SimpleNamespace, *, protections: bool = True
) -> tuple[str, str]:
    pool = pathlib.Path(site_pool_path(settings.identifier, settings.runtime))
    if not pool.exists() or not pathlib.Path(settings.socket).exists():
        return "partial", "The site's independent PHP service or socket is absent."
    try:
        tuned = pool.read_text()
    except OSError:
        return "unsupported", POOL_OUTSIDE
    extension = pool_extension(tuned, settings.identifier)
    if extension and extension != known_redis(settings.runtime):
        return "unsupported", POOL_OUTSIDE
    if not safe(str(pool)) or not supported_pool(
        settings.identifier, settings.runtime, tuned, extension
    ):
        return "unsupported", POOL_OUTSIDE
    variant = php_wrapper_variant(settings)
    if variant is None or variant[1] != extension:
        return "unsupported", "The site's PHP commands and pool disagree on the cache client."
    proxy = pwd.getpwnam(settings.proxy)
    if not metadata_matches(settings.socket, 0, proxy.pw_gid, 0o660, stat.S_IFSOCK):
        return "unsupported", "The application's private admission socket is unsafe."
    if protections and site_fpm_read(settings) is None:
        return "unsupported", "The site PHP service has unavailable native protection evidence."
    observed = haproxy_state(settings)
    if observed["selection"] != settings.runtime or observed["persistent"] != settings.runtime:
        return "partial", PHP_TRANSITION_INCOMPLETE
    other = "php85" if settings.runtime == "php84" else "php84"
    retained = pathlib.Path(php_directory(settings.identifier, other))
    if retained.exists() or retained.is_symlink():
        active = not php_service_inactive(
            unit_properties(
                run(
                    [
                        "systemctl",
                        "show",
                        php_site_unit(settings.identifier, other),
                        "--property=ActiveState,MainPID",
                    ],
                    check=False,
                )
            )
        )
        if (
            retained_php_shape(setting(settings.identifier, settings.names, other), active=active)
            == "unsupported"
        ):
            return "unsupported", "Retained PHP configuration is administrator-owned."
        return "partial", PHP_TRANSITION_INCOMPLETE
    _, node_problem, _ = node_command_links(settings.identifier)
    return ("unsupported", node_problem) if node_problem else ("complete", "")


def site_shape(
    settings: SimpleNamespace, attributes: list[object] | None, *, protections: bool = True
) -> tuple[str, str]:
    if attributes is None:
        return "partial", "The site's Linux account is absent."
    try:
        uid, gid = account_ids(settings, attributes)
        state, problem = directory_shape(settings, uid, gid)
        if state != "complete":
            return state, problem
        return configuration_shape(settings, uid, gid, protections=protections)
    except ValueError, KeyError, OSError:
        return (
            "unsupported",
            "The site's native account or configuration is outside supported settings.",
        )


def site_account(identifier: str) -> list[object] | None:
    try:
        account = pwd.getpwnam("s" + identifier)
    except KeyError:
        return None
    return [
        account.pw_uid,
        account.pw_gid,
        account.pw_dir,
        account.pw_shell,
        sorted(os.getgrouplist(account.pw_name, account.pw_gid)),
    ]


def identity_name_exists(identifier: str) -> bool:
    if site_account(identifier) is not None:
        return True
    try:
        grp.getgrnam("s" + identifier)
        return True
    except KeyError:
        return False


def partial_candidates(requested: str) -> set[str]:
    candidates: set[str] = set()
    if requested and identity_name_exists(requested):
        candidates.add(requested)
    for entry in ("php84", "php85"):
        candidates.update(
            path.stem
            for path in pathlib.Path(f"/etc/php-fpm/{entry}/pools").glob("*.conf")
            if path.name != "diagnostic.conf"
        )
    directory = pathlib.Path("/var/www")
    if directory.is_dir():
        candidates.update(path.name for path in directory.iterdir())
    candidates.update(
        account.pw_name[1:]
        for account in pwd.getpwall()
        if account.pw_name.startswith("s")
        and account.pw_dir == "/var/www/" + account.pw_name[1:]
        and account.pw_shell == "/usr/sbin/nologin"
        and 1000 <= account.pw_uid < 30000
    )
    return candidates


def partial_sites(
    known: set[str], requested: str = "", *, target: str = "", protections: bool = True
) -> list[SiteRecord]:
    candidates = partial_candidates(requested)
    if target:
        candidates &= {target}
    if len(candidates - known) > 64:
        raise ValueError("Too many partial site candidates.")
    rows: list[SiteRecord] = []
    for identifier in sorted(candidates - known):
        if not re.fullmatch(r"[a-z][a-z0-9]{2,23}", identifier):
            continue
        try:
            request(identifier, "example.com")
        except ValueError:
            continue
        masters = [
            entry
            for entry in ("php84", "php85")
            if pathlib.Path(f"/etc/php-fpm/{entry}/pools/{identifier}.conf").exists()
        ]
        runtime = masters[0] if len(masters) == 1 else ""
        attributes = site_account(identifier)
        state = "partial"
        if runtime:
            settings = setting(identifier, ["example.com"], runtime)
            observed_state, _ = site_shape(settings, attributes, protections=protections)
            if observed_state == "unsupported":
                state = "unsupported"
        if len(masters) > 1:
            state = "unsupported"
        application, application_version, application_problem = wordpress_application(identifier)
        rows.append(
            {
                "identifier": identifier,
                "names": [],
                "runtime": runtime,
                "node_runtime": "",
                "https": False,
                "readiness": "/",
                "certificate": None,
                "pool": None,
                "account": attributes,
                "file": f"/etc/caddy/sites/{identifier}.caddy",
                "state": state,
                "problem": ROUTE_ABSENT,
                "application": application,
                "application_version": application_version,
                "application_problem": application_problem,
                "serving_form": "maintenance" if runtime else "partial",
                "client": "",
                "log_rotation": logrotate_state(identifier)[0],
            }
        )
    return rows


def site_runtime_state(
    settings: SimpleNamespace, attributes: list[object] | None, *, protections: bool = True
) -> tuple[str, str]:
    return site_shape(settings, attributes, protections=protections)


def site_pool_record(settings: SimpleNamespace) -> SitePool | None:
    path = pathlib.Path(site_pool_path(settings.identifier, settings.runtime))
    if not settings.runtime or not safe(str(path)):
        return None
    try:
        text = path.read_text()
    except OSError:
        return None
    extension = pool_extension(text, settings.identifier)
    if extension and extension != known_redis(settings.runtime):
        return None
    return parse_pool(settings.identifier, settings.runtime, text, extension)


def native_directories(entry: str) -> list[str]:
    directories = ["/etc/caddy", "/etc/caddy/sites", "/var/www"]
    if entry:
        directories.extend(("/etc/haproxy/sites", "/var/lib/haproxy/sites"))
    return directories


def _small_file(path: pathlib.Path) -> str | None:
    """A bounded, non-followed regular file read for passive discovery."""
    try:
        descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            return None
        data = os.read(descriptor, 65537)
    except OSError:
        return None
    finally:
        os.close(descriptor)
    return data.decode("utf-8", "replace") if len(data) <= 65536 else None


def _entry_kind(path: pathlib.Path) -> str:
    try:
        info = path.lstat()
    except OSError:
        return ""
    if stat.S_ISLNK(info.st_mode):
        return "symlink"
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    return "file" if stat.S_ISREG(info.st_mode) else "other"


def wordpress_application(identifier: str) -> tuple[str, str, str]:
    """The site's application, its core version and any partial-install problem.

    This reads bounded native files only: the pinned core's version literal and the fixed
    loader, never application PHP (docs/wordpress.md#discovery-and-execution).
    """
    if re.fullmatch(r"[a-z][a-z0-9]{2,23}", identifier) is None:
        return "plain", "", ""
    base = pathlib.Path("/var/www") / identifier / "current" / "public"
    markers = {
        name: _entry_kind(base / name)
        for name in (
            "wp-load.php",
            "wp-settings.php",
            "wp-admin",
            "wp-includes",
            "wp-includes/version.php",
            "wp-content",
        )
    }
    if not any(markers.values()):
        return "plain", "", ""
    version_text = _small_file(base / "wp-includes" / "version.php")
    found = re.findall(
        r"^\$wp_version = '([0-9A-Za-z.-]{1,40})';$", version_text or "", re.MULTILINE
    )
    version = found[0] if len(found) == 1 else ""
    expected_loader = (
        "<?php\n"
        f"require '/var/www/{identifier}/private/wp-config.php';\n"
        "require_once ABSPATH . 'wp-settings.php';\n"
    )
    loader = _small_file(base / "wp-config.php")
    private = pathlib.Path("/var/www") / identifier / "private" / "wp-config.php"
    try:
        private_info = private.lstat()
    except OSError:
        private_info = None
    problem = ""
    if not version:
        problem = "The WordPress core version file is missing or unreadable."
    elif loader != expected_loader:
        problem = "The public WordPress loader is missing or outside the supported layout."
    elif (
        private_info is None
        or not stat.S_ISREG(private_info.st_mode)
        or stat.S_IMODE(private_info.st_mode) & 0o077
    ):
        problem = "The private WordPress configuration is missing or not private."
    elif not (
        markers["wp-load.php"] == "file"
        and markers["wp-settings.php"] == "file"
        and markers["wp-admin"] == "directory"
        and markers["wp-includes"] == "directory"
        and markers["wp-includes/version.php"] == "file"
        and markers["wp-content"] == "directory"
    ):
        problem = "WordPress core files are only partly present."
    return ("wordpress" if not problem else "wordpress_partial"), version, problem


def native_site_record(  # noqa: C901 - one record per recognized serving form
    path: pathlib.Path, *, protections: bool = True
) -> SiteRecord:
    original = adapt(path.read_text())
    settings = extract(path.stem, original)
    https = bool(settings.https)
    form = "plain"
    supported = original == adapt(caddy_file(settings))
    if not supported:
        supported = original == adapt(wordpress_caddy_file(settings))
        form = "wordpress"
    if not supported:
        supported = original == adapt(laravel_caddy_file(settings))
        form = "laravel"
    if not supported:
        supported = original == adapt(wordpress_caddy_file(settings, aliases=False)) or (
            original == adapt(laravel_caddy_file(settings, aliases=False))
        )
        if supported:
            form = (
                "wordpress"
                if original == adapt(wordpress_caddy_file(settings, aliases=False))
                else "laravel"
            )
    gated = not supported and original == adapt(maintenance_file(settings))
    if gated:
        form = "maintenance"
    elif not supported:
        form = "unsupported"
    attributes = site_account(settings.identifier)
    try:
        proxy = haproxy_state(settings)
        selected = proxy["selection"]
        if selected:
            settings = setting(
                settings.identifier,
                settings.names,
                selected,
                https=https,
                readiness=settings.readiness,
            )
            state, problem = site_runtime_state(settings, attributes, protections=protections)
        else:
            settings.runtime = ""
            state, problem = "partial", PHP_TRANSITION_INCOMPLETE
    except (ValueError, OSError, KeyError, subprocess.TimeoutExpired) as error:
        sys.stderr.write("Site serving evidence stopped: " + str(error)[:500] + "\n")
        settings.runtime = ""
        state, problem = "unsupported", "The private PHP admission evidence is unavailable."
    node_runtime, _, _ = node_command_links(settings.identifier)
    application, application_version, application_problem = wordpress_application(
        settings.identifier
    )
    if gated:
        state, problem = "partial", SITE_GATED
    elif not supported:
        state = "unsupported"
        problem = CADDY_OUTSIDE
    pool = site_pool_record(settings) if state == "complete" else None
    return {
        "identifier": settings.identifier,
        "names": settings.names,
        "runtime": settings.runtime,
        "node_runtime": node_runtime,
        "https": https,
        "readiness": settings.readiness,
        "certificate": certificate_state(list(settings.names), https),
        "pool": pool.document() if pool is not None else None,
        "account": attributes,
        "file": str(path),
        "state": state,
        "problem": problem,
        "application": application,
        "application_version": application_version,
        "application_problem": application_problem,
        "serving_form": form,
        "client": site_client(settings) if state == "complete" else "",
        "log_rotation": logrotate_state(settings.identifier)[0],
    }


def site_records(
    files: list[pathlib.Path], identifier: str, *, site_only: bool, protections: bool = True
) -> list[SiteRecord]:
    """One record per supported site file, or only ``identifier`` when ``site_only``."""
    for path in files:
        if path.suffix != ".caddy" or not safe(str(path)):
            raise ValueError("Unsupported Caddy file.")
    records: list[SiteRecord] = []
    seen: set[str] = set()
    for path in files:
        if site_only and path.stem != identifier:
            continue
        record = native_site_record(path, protections=protections)
        if seen.intersection(record["names"]):
            raise ValueError("A host is already claimed.")
        seen.update(record["names"])
        records.append(record)
    return records


def publish_wrapper(path: pathlib.Path, contents: str) -> None:
    """Atomically publish one of a site's PHP command wrappers, fsynced."""
    before = fingerprint(str(path))
    if before is None or not safe(str(path)):
        raise ValueError("A PHP command preimage is unavailable.")
    descriptor, staged_name = tempfile.mkstemp(prefix=".php-runtime-", dir=path.parent)
    staged = pathlib.Path(staged_name)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(contents)
            stream.flush()
            os.fchmod(stream.fileno(), 0o755)
            os.fsync(stream.fileno())
        if fingerprint(str(path)) != before:
            raise ValueError("A PHP command changed during staging.")
        os.replace(staged, path)
        parent = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        staged.unlink(missing_ok=True)


def realise_locked(path: str) -> None:
    """Realise one reviewed store path the way every Barectl body does: no builds."""
    process = subprocess.Popen(  # noqa: S603 - fixed native argv and a validated store path
        [
            "/nix/var/nix/profiles/default/bin/nix-store",
            "--realise",
            path,
            "--option",
            "max-jobs",
            "0",
            "--option",
            "fallback",
            "false",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        _, stderr = process.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise ValueError("The locked extension closure did not realise in time.") from None
    if process.returncode:
        raise ValueError("The locked extension closure is unavailable: " + stderr[:500])


def restart_site_fpm(settings: SimpleNamespace) -> dict[str, object]:
    """Restart one site's own master and wait for its completed load and protection read."""
    unit = php_site_unit(settings.identifier, settings.runtime)
    command = ["systemctl", "show", unit, "--property=MainPID,InvocationID"]
    before = unit_properties(run(command, check=False))
    run(["systemctl", "restart", unit])
    evidence = wait_site_fpm(settings)
    after = unit_properties(run(command, check=False))
    if after.get("MainPID") == before.get("MainPID") and after.get("InvocationID") == before.get(
        "InvocationID"
    ):
        raise ValueError("The site's own PHP master was not restarted.")
    return evidence


def set_site_client(document: dict[str, object]) -> None:
    """Enable or disable one site's object-cache PHP client and restart only its master."""
    try:
        descriptor = open_site_lock(str(document.get("identifier", "")))
    except BlockingIOError:
        result("lock_busy")
        return
    except OSError, ValueError:
        result("refused", "unsafe_lock")
        return
    try:
        client_locked_change(document, descriptor)
    finally:
        os.close(descriptor)


def client_locked_change(document: dict[str, object], descriptor: int) -> None:  # noqa: C901
    identifier = str(document.get("identifier", ""))
    enabled = document.get("enabled") is True
    extension = str(document.get("extension", ""))
    stage("preflight")
    changed = False
    try:
        before = native_state("observed", "", protections=False)
        if before["digest"] != document.get("precondition_digest"):
            result("refused", "evidence")
            return
        site = next((row for row in before["sites"] if row["identifier"] == identifier), None)
        if site is None or site["state"] != "complete" or not site["runtime"]:
            result("refused", "evidence")
            return
        settings = setting(
            identifier,
            site["names"],
            site["runtime"],
            https=site["https"],
            readiness=site["readiness"],
        )
        if site_client(settings) != document.get("current"):
            result("refused", "evidence")
            return
        wanted = extension if enabled else ""
        if enabled and (not extension or extension != known_redis(settings.runtime)):
            result("refused", "evidence")
            return
        if not enabled and extension:
            result("refused", "evidence")
            return
        if site_client(settings) == ("phpredis" if wanted else ""):
            result("refused", "evidence")
            return
        build = str(document.get("build", ""))
        if enabled and not build.startswith("/nix/store/"):
            result("refused", "evidence")
            return
        if not same_site_lock(descriptor, identifier):
            result("refused", "evidence")
            return
        stage("realise")
        if enabled:
            try:
                realise_locked(build)
            except ValueError:
                result("refused", "runtime_cache")
                return
        if native_state("observed", "", protections=False)["digest"] != before["digest"]:
            result("refused", "evidence")
            return
        root = php_directory(identifier, settings.runtime)
        pool_path = pathlib.Path(site_pool_path(identifier, settings.runtime))
        pool_preimage = current_bytes(pool_path)
        diagnostic_path = pathlib.Path(root + "/pools/diagnostic.conf")
        diagnostic_preimage = current_bytes(diagnostic_path)
        if pool_preimage is None or diagnostic_preimage is None:
            result("refused", "evidence")
            return
        candidate = without_extension(pool_preimage) + (extension_line(wanted) if wanted else "")
        expected = site_fpm_files(settings, wanted)
        account = pwd.getpwnam(settings.account)
        validate_pool_candidate(settings, account.pw_uid, candidate)
        stage("pool")
        replace_site_file(pool_path, candidate, pool_preimage)
        changed = True
        replace_site_file(diagnostic_path, expected[str(diagnostic_path)], diagnostic_preimage)
        stage("commands")
        for name in ("php", "composer", "wp"):
            publish_wrapper(
                pathlib.Path(settings.directory) / "bin" / name,
                wrapper(settings, name, wanted),
            )
        stage("restart")
        restart_site_fpm(settings)
        stage("verify")
        after = native_state("observed", "", protections=False)
        current = next((item for item in after["sites"] if item["identifier"] == identifier), None)
        evidence = site_fpm_read(settings)
        extension_names = evidence.get("extensions") if evidence is not None else None
        if (
            current is None
            or current["state"] != "complete"
            or site_client(settings) != ("phpredis" if wanted else "")
            or evidence is None
            or evidence.get("client") != ("phpredis" if wanted else "")
            or not isinstance(extension_names, list)
            or (("redis" in extension_names) != bool(wanted))
        ):
            raise ValueError("The restarted site master did not report the reviewed client.")
        result("succeeded")
    except ValueError, OSError, KeyError, subprocess.TimeoutExpired:
        result("partial" if changed else "refused", "site_client" if changed else "evidence")


def native_state(
    identifier: str,
    entry: str,
    requested_names: list[str] | None = None,
    *,
    site_only: bool = False,
    protections: bool = True,
    https: bool = True,
) -> NativeState:
    """One server's native state.

    ``site_only`` keeps the record of only ``identifier``. The PHP change manages one site,
    and every record's protection read is expensive, so reading each site's would exceed the
    command bound as sites accumulate. The whole site directory is still fingerprinted in
    ``evidence``, so another site joining or leaving changes the digest (ADR 0038).

    ``protections`` reads each record's live PHP protections. The all-sites discovery read
    turns it off and follows with one bounded per-site read, so no single command bundles
    several sites' protection evidence (docs/ssh-connections.md#bounds-and-read-only-commands).
    """
    if hap_inventory():
        raise ValueError("A foreign HAProxy process is outside the supported serving convention.")
    directories = native_directories(entry)
    if (
        any(
            not safe(p, directory=True)
            for p in directories
            if p.startswith("/etc/caddy")
            or pathlib.Path(p).exists()
            or pathlib.Path(p).is_symlink()
        )
        or (
            (pathlib.Path("/var/www").exists() or pathlib.Path("/var/www").is_symlink())
            and not safe("/var/www", directory=True)
        )
        or not safe("/var", directory=True)
    ):
        raise ValueError("Unsafe configuration ancestors.")
    if not safe("/etc/caddy/Caddyfile"):
        raise ValueError("Unsafe main configuration.")
    disk = adapt()
    if disk != running():
        raise ValueError("Caddy's disk and running configurations differ.")
    files = sorted(pathlib.Path("/etc/caddy/sites").iterdir())
    if len(files) > 64:
        raise ValueError("Too many site files.")
    for path in files:
        if path.suffix != ".caddy" or not safe(str(path)):
            raise ValueError("Unsupported Caddy file.")
    known = {path.stem for path in files}
    sites = site_records(files, identifier, site_only=site_only, protections=protections)
    sites += partial_sites(
        known,
        identifier if entry else "",
        target=identifier if site_only else "",
        protections=protections,
    )
    current = [site["identifier"] for site in sites] if entry else []
    paths = evidence_paths(identifier, entry, directories, [str(p) for p in files])
    evidence = {path: fingerprint(path) for path in paths}
    value: NativeState = {
        "version": 1,
        "boot": pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "uptime": int(float(pathlib.Path("/proc/uptime").read_text().split()[0]) * 100),
        "sites": sites,
        "current_sites": current,
        "disk_digest": hashlib.sha256(canonical(disk).encode()).hexdigest(),
        "digest": hashlib.sha256(canonical(evidence).encode()).hexdigest(),
        "evidence": evidence,
        "next_id": free_identity() if entry else 0,
        "next_proxy_id": free_identity((free_identity(),)) if entry else 0,
        "validation": "not_requested",
        "pool_validation": "not_requested",
        "master_present": bool(entry),
    }
    value["validation"] = validation_status(identifier, entry, requested_names, https)
    if requested_names:
        value["pool_validation"] = pool_validation_status(identifier, entry, value["next_id"])
    return value


def evidence_paths(
    identifier: str, entry: str, directories: list[str], files: list[str]
) -> list[str]:
    paths = [
        "/etc/caddy/Caddyfile",
        *files,
        *directories,
        "/etc/passwd",
        "/etc/login.defs",
        "/nix/var/nix/profiles/barectl/caddy",
        "/etc/systemd/system/php-fpm@.service",
        "/etc/group",
        "/etc/shadow",
        f"/var/www/{identifier}",
    ]
    if entry:
        paths += [
            f"/nix/var/nix/profiles/barectl/{entry}",
            f"/etc/php-fpm/{entry}/php-fpm.conf",
            f"/etc/php-fpm/{entry}/php.ini",
            *[str(path) for path in pathlib.Path(f"/etc/php-fpm/{entry}/pools").glob("*.conf")],
            f"/etc/php-fpm/{entry}/pools/{identifier}.conf",
        ]
    return paths


def validation_status(
    identifier: str, entry: str, names: list[str] | None, https: bool = True
) -> str:
    if not names:
        return "not_requested"
    try:
        validate_candidate(identifier, caddy_file(setting(identifier, names, entry, https=https)))
        return "valid"
    except ValueError, OSError, subprocess.TimeoutExpired:
        return "unavailable"


def pool_validation_status(identifier: str, entry: str, identity: int) -> str:
    settings = setting(identifier, ["example.com"], entry)
    try:
        validate_pool_candidate(settings, identity, pool_file(settings))
        return "valid"
    except ValueError, OSError, subprocess.TimeoutExpired:
        return "unavailable"


def free_identity(excluded: tuple[int, ...] = ()) -> int:
    used = {row.pw_uid for row in pwd.getpwall()}
    import grp

    used.update(row.gr_gid for row in grp.getgrall())
    return next(
        value for value in range(1000, 30000) if value not in used and value not in excluded
    )


def result(outcome: str, reason: str = "") -> None:
    value = {"class": outcome}
    if reason:
        value["reason"] = reason
    sys.stdout.write("barectl-result " + canonical(value) + "\n")
    sys.stdout.flush()


def stage(value: str) -> None:
    sys.stdout.write("barectl-stage " + value + "\n")
    sys.stdout.flush()


def write_new(
    path: str, contents: str, mode: int, owner: str = "root", group: str = "root"
) -> None:
    p = pathlib.Path(path)
    if not safe(str(p.parent), directory=True):
        raise ValueError("Unsafe publication directory.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as output:
        output.write(contents)
        output.flush()
        os.fsync(output.fileno())
        import grp

        os.fchown(output.fileno(), pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid)
        os.fchmod(output.fileno(), mode)


def install_file(
    path: str, contents: str, mode: int, owner: str, group: str, boundary: str
) -> None:
    temporary = pathlib.Path(boundary) / (".stage-" + pathlib.Path(path).name)
    write_new(str(temporary), contents, mode, owner, group)
    try:
        os.link(temporary, path, follow_symlinks=False)
    finally:
        temporary.unlink()


def copied_directory(root: pathlib.Path, relative: str, owner: int, group: int, mode: int) -> None:
    target = root / relative
    target.mkdir(parents=True, exist_ok=True)
    original = pathlib.Path("/var") / relative
    if original.exists() or original.is_symlink():
        metadata = original.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("Validation refuses an unsupported live directory entry.")
        owner, group, mode = metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)
    os.chown(target, owner, group)
    target.chmod(mode)


def candidate_tree(root: pathlib.Path, identifier: str, candidate: str) -> None:
    main = pathlib.Path("/etc/caddy/Caddyfile").read_text()
    if "import sites/*.caddy" not in main or "import /" in main:
        raise ValueError("The main configuration does not use the supported relative tree.")
    (root / "sites").mkdir(mode=0o750)
    os.chown(root / "sites", 0, grp.getgrnam("caddy").gr_gid)
    for source in [
        pathlib.Path("/etc/caddy/Caddyfile"),
        *pathlib.Path("/etc/caddy/sites").iterdir(),
    ]:
        if not safe(str(source)) or (source.name != "Caddyfile" and source.suffix != ".caddy"):
            raise ValueError("Unsupported candidate tree member.")
        target = root / ("Caddyfile" if source.name == "Caddyfile" else "sites/" + source.name)
        target.write_bytes(source.read_bytes())
        metadata = source.stat()
        os.chown(target, metadata.st_uid, metadata.st_gid)
        target.chmod(stat.S_IMODE(metadata.st_mode))
    target = root / "sites" / (identifier + ".caddy")
    target.write_text(candidate)
    target.chmod(0o644)


def validate_candidate(identifier: str, candidate: str) -> None:
    with tempfile.TemporaryDirectory(prefix="site-candidate-", dir="/run") as directory:
        root = pathlib.Path(directory)
        os.chown(root, 0, grp.getgrnam("caddy").gr_gid)
        root.chmod(0o750)
        candidate_tree(root, identifier, candidate)
        scratch = root / "var"
        scratch.mkdir(mode=0o755)
        copied_directory(scratch, "www", 0, 0, 0o755)
        copied_directory(scratch, "lib", 0, 0, 0o755)
        caddy = pwd.getpwnam("caddy")
        copied_directory(scratch, "lib/caddy", caddy.pw_uid, caddy.pw_gid, 0o700)
        for path in (root / "sites").iterdir():
            settings = extract(path.stem, adapt(path.read_text()))
            copied_directory(scratch, "www/" + settings.identifier, 0, 0, 0o755)
            copied_directory(
                scratch, "www/" + settings.identifier + "/logs", caddy.pw_uid, caddy.pw_gid, 0o750
            )
            original = pathlib.Path(settings.directory) / "logs/access.json"
            if original.exists() or original.is_symlink():
                metadata = original.lstat()
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ValueError("Validation refuses an unsafe access-log entry.")
                copied = scratch / "www" / settings.identifier / "logs/access.json"
                copied.touch()
                os.chown(copied, metadata.st_uid, metadata.st_gid)
                copied.chmod(stat.S_IMODE(metadata.st_mode))
        run(
            [
                "/usr/bin/unshare",
                "--mount",
                "--propagation",
                "private",
                "/bin/sh",
                "-c",
                (
                    '/usr/bin/mount --bind "$1" /var && exec /usr/sbin/runuser '
                    '-u caddy -- "$3" validate '
                    '--config "$2" --adapter caddyfile'
                ),
                "validator",
                str(scratch),
                str(root / "Caddyfile"),
                caddy_binary(),
            ]
        )


def php_binary(entry: str) -> str:
    selected = os.path.realpath(f"/nix/var/nix/profiles/barectl/{entry}")
    if selected not in KNOWN_PHP.get(os.uname().machine, {}).get(entry, ()):
        raise ValueError("The selected PHP executable has no known native identity.")
    return selected + "/bin/php-fpm"


def numeric_pool_candidate(settings: SimpleNamespace, identity: int, candidate: str) -> str:
    if not 1000 <= identity < 30000:
        raise ValueError("Invalid future identity.")
    for field in ("user", "group"):
        before = f"{field} = {settings.account}\n"
        if candidate.count(before) != 1:
            raise ValueError("The pool identity differs from review.")
        candidate = candidate.replace(before, f"{field} = {identity}\n")
    return candidate.replace(f"listen.group = {settings.proxy}\n", "listen.group = root\n")


def validate_pool_candidate(settings: SimpleNamespace, identity: int, candidate: str) -> None:
    with tempfile.TemporaryDirectory(prefix="site-pool-candidate-", dir="/run") as directory:
        root = pathlib.Path(directory)
        copied = root / "php-fpm"
        selected = copied / "sites" / settings.identifier / settings.runtime
        (selected / "pools").mkdir(parents=True, mode=0o755)
        (selected / "php.ini").write_text(NATIVE_MASTER_FILES[settings.runtime]["php.ini"])
        (selected / "php-fpm.conf").write_text(master_config(settings))
        (selected / "pools" / f"{settings.identifier}.conf").write_text(
            numeric_pool_candidate(settings, identity, candidate)
        )
        scratch = root / "var"
        scratch.mkdir(mode=0o755)
        for relative in ("www", f"www/{settings.identifier}", f"www/{settings.identifier}/logs"):
            copied_directory(scratch, relative, 0, 0, 0o755)
        run(
            [
                "/usr/bin/unshare",
                "--mount",
                "--propagation",
                "private",
                "/bin/sh",
                "-c",
                (
                    '/usr/bin/mount --bind "$1" /etc/php-fpm && /usr/bin/mount --bind "$2" /var '
                    '&& exec "$3" -t -y "$4/php-fpm.conf" -c "$4/php.ini"'
                ),
                "validator",
                str(copied),
                str(scratch),
                php_binary(settings.runtime),
                php_directory(settings.identifier, settings.runtime),
            ]
        )


def current_bytes(path: pathlib.Path) -> str | None:
    if path.is_symlink() or (path.exists() and not safe(str(path))):
        raise ValueError("The live Caddy file is outside the root-controlled convention.")
    return path.read_text() if path.exists() else None


def replace_site_file(path: pathlib.Path, value: str, expected: str | None) -> None:
    if current_bytes(path) != expected or not safe(str(path.parent), directory=True):
        raise ValueError("The reviewed preimage changed before publication.")
    if expected is None:
        write_new(str(path), value, 0o644)
        return
    descriptor, temporary = tempfile.mkstemp(
        prefix="." + path.stem + "-", suffix=".stage", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o644)
        if current_bytes(path) != expected or not safe(str(path.parent), directory=True):
            raise ValueError("The reviewed preimage changed during staging.")
        os.replace(temporary, path)
    finally:
        pathlib.Path(temporary).unlink(missing_ok=True)


def replace_caddy(path: pathlib.Path, value: str, expected: str | None) -> None:
    replace_site_file(path, value, expected)


def reload_caddy() -> None:
    run(
        [
            caddy_binary(),
            "reload",
            "--config",
            "/etc/caddy/Caddyfile",
            "--adapter",
            "caddyfile",
            "--address",
            ADMIN,
        ]
    )


def restore_caddy(path: pathlib.Path, candidate: str, preimage: str | None, old: object) -> bool:
    unchanged = running() == old
    if current_bytes(path) != candidate:
        raise ValueError("Caddy restoration cannot prove its publication identity.")
    if preimage is None:
        path.unlink()
    else:
        replace_caddy(path, preimage, candidate)
    if running() != old:
        reload_caddy()
    if adapt() != old or running() != old or current_bytes(path) != preimage:
        raise ValueError("Caddy's old serving configuration could not be proven.")
    if not unchanged:
        raise ValueError("The candidate may have served before restoration.")
    return False


def publish_caddy(identifier: str, candidate: str, preimage: str | None) -> bool:
    live = pathlib.Path(f"/etc/caddy/sites/{identifier}.caddy")
    old = running()
    if adapt() != old or current_bytes(live) != preimage:
        raise ValueError("The reviewed Caddy preimage or running configuration changed.")
    validate_candidate(identifier, candidate)
    replace_caddy(live, candidate, preimage)
    try:
        reload_caddy()
        if running() != adapt():
            raise ValueError("Caddy's loaded configuration differs from disk.")
        return True
    except ValueError, OSError, subprocess.TimeoutExpired:
        return restore_caddy(live, candidate, preimage, old)


def create_account(settings: SimpleNamespace, identity: int) -> pwd.struct_passwd:
    identity_argument = str(identity)
    run(["/usr/sbin/groupadd", "--gid", identity_argument, settings.account])
    run(
        [
            "/usr/sbin/useradd",
            "--uid",
            identity_argument,
            "--gid",
            identity_argument,
            "--no-create-home",
            "--home-dir",
            settings.directory,
            "--shell",
            "/usr/sbin/nologin",
            settings.account,
        ]
    )
    account = pwd.getpwnam(settings.account)
    if (
        account.pw_uid != int(identity)
        or account.pw_gid != int(identity)
        or os.getgrouplist(settings.account, account.pw_gid) != [account.pw_gid]
    ):
        raise ValueError("Created identity differs from review.")
    return account


def create_layout(settings: SimpleNamespace) -> int:
    for path, owner, group, mode in (
        ("/var/www", "root", "root", "755"),
        (settings.directory, "root", "root", "755"),
        (settings.directory + "/releases", "root", "root", "755"),
        (settings.directory + "/releases/initial", settings.account, settings.account, "711"),
        (settings.directory + "/releases/initial/public", settings.account, "caddy", "2750"),
        (settings.directory + "/private", settings.account, settings.account, "700"),
        (settings.directory + "/private/sessions", settings.account, settings.account, "700"),
        (settings.directory + "/private/tmp", settings.account, settings.account, "700"),
        (settings.directory + "/logs", "caddy", settings.account, "750"),
        (settings.directory + "/bin", "root", "root", "755"),
    ):
        run(["/usr/bin/install", "-d", "-o", owner, "-g", group, "-m", mode, path])
    os.symlink("releases/initial", settings.directory + "/current")
    write_new(settings.directory + "/.deploy.lock", "", 0o640, "root", settings.account)
    descriptor = os.open(settings.directory + "/.deploy.lock", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        populate_layout(settings)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def populate_layout(settings: SimpleNamespace) -> None:
    placeholder = (
        '<?php header("Content-Type: application/json"); echo json_encode(["site"=>"'
        + settings.identifier
        + '","uid"=>posix_geteuid(),"runtime"=>PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION]);\n'
    )
    install_file(
        settings.directory + "/current/public/index.php",
        placeholder,
        0o600,
        settings.account,
        settings.account,
        settings.directory,
    )
    install_file(
        settings.directory + "/current/public/hello.txt",
        "Welcome to your PHP site.\n",
        0o640,
        settings.account,
        "caddy",
        settings.directory,
    )
    for filename in ("php-error.log", "php-slow.log"):
        install_file(
            settings.directory + "/logs/" + filename,
            "",
            0o640,
            settings.account,
            settings.account,
            settings.directory,
        )
    for name in ("php", "composer", "wp"):
        write_new(settings.directory + "/bin/" + name, wrapper(settings, name), 0o755)


def serving_directory(path: str, mode: int = 0o755) -> None:
    target = pathlib.Path(path)
    if target.exists() or target.is_symlink():
        if not safe(path, directory=True) or stat.S_IMODE(target.stat().st_mode) != mode:
            raise ValueError("Unsafe serving directory.")
        return
    if not target.parent.is_dir():
        serving_directory(str(target.parent))
    if not safe(str(target.parent), directory=True):
        raise ValueError("Unsafe serving directory ancestor.")
    target.mkdir(mode=mode)


def site_fpm_files(
    settings: SiteSettings | SimpleNamespace, extension: str | None = None
) -> dict[str, str]:
    if extension is None:
        extension = getattr(settings, "client", "")
    root = php_directory(settings.identifier, settings.runtime)
    return {
        root + "/php.ini": NATIVE_MASTER_FILES[settings.runtime]["php.ini"],
        root + "/php-fpm.conf": master_config(settings),
        site_pool_path(settings.identifier, settings.runtime): pool_file(settings, extension),
        root + "/pools/diagnostic.conf": diagnostic_pool(settings, extension),
    }


def site_fpm_read(settings: SimpleNamespace) -> dict[str, object] | None:
    pool = site_pool_path(settings.identifier, settings.runtime)
    try:
        tuned = pathlib.Path(pool).read_text()
    except OSError:
        return None
    # The object cache's client is site-local native state: the site pool and its diagnostic
    # pool name the same locked phpredis build, or neither names one. A known path enables the
    # client; any other value is outside the convention and recognition refuses it.
    extension = pool_extension(tuned, settings.identifier)
    if extension and extension != known_redis(settings.runtime):
        return None
    expected = {
        **site_fpm_files(settings, extension),
        f"/etc/systemd/system/php-fpm-site-{settings.runtime}@.service": fpm_unit(settings.runtime),
        "/etc/php-fpm/diagnostics/probe.php": NATIVE_PROBE,
    }
    # A site pool's bounded operator-tunable settings are supported, so the evidence attests
    # the pool's actual bytes once ``supported_pool`` accepts them rather than the template's
    # (docs/site-conventions.md#supported-configuration-grammar). Every other key must equal
    # the convention, so a bounded tuning stays supported and anything else is refused.
    selected = parse_pool(settings.identifier, settings.runtime, tuned, extension)
    if selected is None:
        return None
    expected[pool] = tuned
    fcgi = os.path.realpath("/nix/var/nix/profiles/barectl/fcgi")
    if fcgi not in KNOWN_FCGI.get(os.uname().machine, ()):
        return None
    minimum, maximum = pool_child_range(selected)
    evidence = site_fpm_evidence(
        settings.identifier,
        settings.runtime,
        expected,
        KNOWN_PHP.get(os.uname().machine, {}).get(settings.runtime, ()),
        fcgi,
        minimum,
        maximum,
    )
    if evidence is not None:
        evidence["client"] = "phpredis" if extension else ""
    return evidence


def site_client(settings: SimpleNamespace) -> str:
    """The site's recognized PHP cache client, ``""`` when none is enabled."""
    try:
        tuned = pathlib.Path(site_pool_path(settings.identifier, settings.runtime)).read_text()
    except OSError:
        return ""
    return (
        "phpredis"
        if pool_extension(tuned, settings.identifier) == known_redis(settings.runtime)
        and known_redis(settings.runtime)
        else ""
    )


def pool_child_range(pool: SitePool) -> tuple[int, int]:
    if pool.process_manager == "static":
        return pool.max_children, pool.max_children
    if pool.process_manager == "dynamic" and pool.min_spare_servers is not None:
        return pool.min_spare_servers, pool.max_children
    return 0, pool.max_children


def wait_site_fpm(settings: SimpleNamespace) -> dict[str, object]:
    deadline = time.monotonic() + 10
    while True:
        evidence = site_fpm_read(settings)
        if evidence is not None:
            return evidence
        if time.monotonic() >= deadline:
            raise ValueError("Independent PHP did not establish complete native readiness.")
        time.sleep(0.05)


def start_site_fpm(settings: SimpleNamespace) -> None:
    root = php_directory(settings.identifier, settings.runtime)
    serving_directory(root + "/pools")
    for path, content in site_fpm_files(settings).items():
        if pathlib.Path(path).exists():
            if not safe(path) or pathlib.Path(path).read_text() != content:
                raise ValueError("Foreign independent PHP configuration.")
        else:
            write_new(path, content, 0o644)
    diagnostic = f"/var/lib/php-fpm/sites/{settings.identifier}/{settings.runtime}/diagnostic"
    serving_directory(diagnostic)
    probe = pwd.getpwnam("php-probe")
    for relative in ("session", "upload", "tmp"):
        private_path = pathlib.Path(diagnostic) / relative
        if not private_path.exists():
            private_path.mkdir(mode=0o700)
            os.chown(private_path, probe.pw_uid, probe.pw_gid)
        value = private_path.lstat()
        if (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) != (
            probe.pw_uid,
            probe.pw_gid,
            0o700,
        ):
            raise ValueError("Unsafe site diagnostic private directory.")
    run([php_binary(settings.runtime), "-t", "-y", root + "/php-fpm.conf", "-c", root + "/php.ini"])
    run(
        [
            "systemctl",
            "--no-reload",
            "enable",
            "--now",
            f"php-fpm-site-{settings.runtime}@{settings.identifier}.service",
        ]
    )


def configure_pool(
    settings: SimpleNamespace, account: pwd.struct_passwd, proxy_identity: int
) -> None:
    if free_identity() != proxy_identity:
        raise ValueError("The proxy's reviewed numeric identity changed.")
    run(["groupadd", "--gid", str(proxy_identity), settings.proxy])
    run(
        [
            "useradd",
            "--uid",
            str(proxy_identity),
            "--gid",
            str(proxy_identity),
            "--no-create-home",
            "--home-dir",
            "/nonexistent",
            "--shell",
            "/usr/sbin/nologin",
            settings.proxy,
        ]
    )
    start_site_fpm(settings)
    wait_site_fpm(settings)
    serving_directory("/etc/haproxy/sites")
    serving_directory("/var/lib/haproxy/sites")
    write_new(f"/etc/haproxy/sites/{settings.identifier}.cfg", haproxy_config(settings), 0o600)
    hap_validate(settings.identifier)
    run(
        [
            "systemctl",
            "--no-reload",
            "enable",
            "--now",
            f"haproxy-site@{settings.identifier}.service",
        ]
    )
    hap_wait(settings.identifier)
    if hap_api(settings.identifier, f"set server php/{settings.runtime} state ready"):
        raise ValueError("The native selection command did not succeed.")
    if persist_proxy_state(settings) != settings.runtime:
        raise ValueError("Native restart selection differs from creation.")
    if haproxy_state(settings)["selection"] != settings.runtime:
        raise ValueError("Private admission did not select the created runtime.")


def runtime_admission(document: dict[str, object], settings: SimpleNamespace) -> NativeState:
    before = native_state(settings.identifier, settings.runtime)
    arguments = document.get("runtime_arguments")
    if not isinstance(arguments, list) or not all(isinstance(arg, str) for arg in arguments):
        raise ValueError("Invalid native runtime arguments.")
    runtime = json.loads(run(["python3", "-c", RUNTIME_READ_SOURCE, *arguments]))
    if runtime.get("digest") != document["runtime_digest"]:
        raise ValueError("The runtime evidence changed.")
    row = next((row for row in runtime["runtimes"] if row.get("entry") == settings.runtime), None)
    if not isinstance(row, dict) or not master_identity(row):
        raise ValueError("The selected master no longer has a safe native load identity.")
    values = live_values(row, str(document["runtime_version"]))
    if values is None or not protected(values[0], values[1], tuple(values[2])):
        raise ValueError("The selected master's live protections changed.")
    return before


def create(document: dict[str, object]) -> None:
    names = document.get("names")
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        result("refused", "evidence")
        return
    https = document.get("https", True) is not False
    settings = setting(str(document["identifier"]), names, str(document["selection"]), https=https)
    stage("preflight")
    try:
        before = runtime_admission(document, settings)
    except ValueError, OSError, subprocess.TimeoutExpired:
        result("refused", "evidence")
        return
    if (
        before["digest"] != document["precondition_digest"]
        or before["disk_digest"] != document["disk_digest"]
        or before["next_id"] != document["identity"]
        or before["next_proxy_id"] != document["proxy_identity"]
    ):
        result("refused", "evidence")
        return
    if (
        settings.identifier in before["current_sites"]
        or pathlib.Path(settings.directory).exists()
        or identity_name_exists(settings.identifier)
    ):
        result("refused", "evidence")
        return
    try:
        validate_candidate(settings.identifier, caddy_file(settings))
        validate_pool_candidate(settings, int(str(document["identity"])), pool_file(settings))
    except ValueError, OSError, subprocess.TimeoutExpired:
        result("refused", "evidence")
        return
    changed = False
    deployment_lock: int | None = None
    try:
        stage("account")
        identity = document.get("identity")
        if type(identity) is not int:
            raise ValueError("Invalid reviewed identity.")
        changed = True
        account = create_account(settings, identity)
        stage("layout")
        deployment_lock = create_layout(settings)
        stage("pool")
        configure_pool(settings, account, int(str(document["proxy_identity"])))
        stage("caddy")
        if not publish_caddy(settings.identifier, caddy_file(settings), None):
            result("partial", "site_caddy")
            return
        stage("verify")
        verify_http(settings, account.pw_uid)
        result("succeeded")
    except ValueError, OSError, subprocess.TimeoutExpired:
        result("partial" if changed else "refused", "site_create" if changed else "evidence")

    finally:
        if deployment_lock is not None:
            os.close(deployment_lock)


def verify_http(settings: SimpleNamespace, uid: int, *, readiness: bool = True) -> None:
    """The site serves its placeholder as its own account and answers its readiness path.

    The identity probe makes PHP answer as the site's reviewed account through the site's
    own private admission path. The readiness request then asks the primary name for the
    configured path. An HTTPS site answers on ``:443`` after Caddy has obtained its
    certificate, which may take a moment on first handshake, so both probes are retried
    within a bounded window. An HTTP-only site is probed on ``:80``.

    Laravel creation passes ``readiness=False``: its own readiness check is ``/up`` during
    Deploy, and the application is not expected to answer a plain PHP readiness path yet.
    """
    deadline = time.monotonic() + 30
    while True:
        try:
            for hostname in settings.names:
                response = json.loads(run(verify_argv(settings, hostname)))
                if response.get("uid") != uid or response.get("site") != settings.identifier:
                    raise ValueError("PHP is not serving as the site's reviewed account.")
            if readiness:
                verify_readiness(settings)
            return
        except ValueError, OSError, subprocess.TimeoutExpired:
            if not settings.https or time.monotonic() >= deadline:
                raise
            time.sleep(0.5)


def verify_readiness(settings: SimpleNamespace) -> None:
    """A GET of the site's readiness path with its primary Host answers acceptably."""
    status = readiness_status(settings)
    if not readiness_ok(settings.readiness, status):
        shown = str(status) if status > 0 else "no response"
        raise ValueError(f"The site answered {shown} at its readiness path {settings.readiness}.")


def readiness_status(settings: SimpleNamespace) -> int:
    """The HTTP status of a GET for the readiness path, or 0 when the request failed."""
    try:
        return int(run(readiness_argv(settings)).strip())
    except OSError, ValueError, subprocess.TimeoutExpired:
        return 0


def readiness_argv(settings: SimpleNamespace) -> list[str]:
    hostname = settings.names[0]
    argv = [
        "/usr/bin/curl",
        "--silent",
        "--show-error",
        "--insecure",
        "--output",
        "/dev/null",
        "--write-out",
        "%{http_code}",
        "--max-time",
        "10",
    ]
    if settings.https:
        argv += [
            "--resolve",
            f"{hostname}:443:127.0.0.1",
            f"https://{hostname}{settings.readiness}",
        ]
    else:
        argv += ["-H", "Host: " + hostname, f"http://127.0.0.1{settings.readiness}"]
    return argv


def verify_argv(settings: SimpleNamespace, hostname: str) -> list[str]:
    if settings.https:
        return [
            "/usr/bin/curl",
            "--silent",
            "--show-error",
            "--fail",
            "--insecure",
            "--max-time",
            "10",
            "--resolve",
            f"{hostname}:443:127.0.0.1",
            f"https://{hostname}/index.php",
        ]
    return [
        "/usr/bin/curl",
        "--silent",
        "--show-error",
        "--fail",
        "--max-time",
        "5",
        "-H",
        "Host: " + hostname,
        "http://127.0.0.1/index.php",
    ]


def domains_caddy_file(settings: SimpleNamespace, form: str) -> str:
    """The site's Caddy file in the recognized form a domains change republishes."""
    if form == "plain":
        return caddy_file(settings)
    if form == "wordpress":
        return wordpress_caddy_file(settings)
    if form == "laravel":
        return laravel_caddy_file(settings)
    raise ValueError("The site's serving form cannot be republished.")


def domain_probe(settings: SimpleNamespace, name: str, path: str = "/") -> tuple[int, str]:
    """The status and redirect target for one of the site's names, or ``(0, "")``."""
    argv = [
        "/usr/bin/curl",
        "--silent",
        "--show-error",
        "--insecure",
        "--max-time",
        "10",
        "--output",
        "/dev/null",
        "--write-out",
        "%{http_code}\t%{redirect_url}",
    ]
    if settings.https:
        argv += ["--resolve", f"{name}:443:127.0.0.1", f"https://{name}{path}"]
    else:
        argv += ["-H", "Host: " + name, f"http://127.0.0.1{path}"]
    try:
        output = run(argv, check=False).strip()
    except OSError, ValueError, subprocess.TimeoutExpired:
        return (0, "")
    status, _, target = output.partition("\t")
    return (int(status) if status.isdigit() else 0, target)


def verify_domains(settings: SimpleNamespace, form: str) -> None:
    """The primary name serves and every alias redirects to it where the form requires it.

    An HTTPS name may wait for Caddy to issue its certificate, so failures are retried in
    the same bounded window a create uses. A plain PHP site serves every name directly;
    WordPress and Laravel aliases redirect to the primary domain (Phase B #442).
    """
    aliases_redirect = form in ("wordpress", "laravel") and len(settings.names) > 1
    prefix = ("https://" if settings.https else "http://") + settings.names[0]
    path = "/up" if form == "laravel" else settings.readiness if form == "plain" else "/"
    deadline = time.monotonic() + 30
    while True:
        try:
            for index, name in enumerate(settings.names):
                status, target = domain_probe(settings, name, path)
                if index and aliases_redirect:
                    if status not in (301, 302, 307, 308) or not target.startswith(prefix):
                        raise ValueError("A site alias did not redirect to the primary domain.")
                elif (status >= 500 or status == 0) if form == "plain" else status != 200:
                    raise ValueError("The site did not answer its own address.")
            return
        except ValueError, OSError, subprocess.TimeoutExpired:
            if not settings.https or time.monotonic() >= deadline:
                raise
            time.sleep(0.5)


def set_site_domains(document: dict[str, object]) -> None:  # noqa: C901 - reviewed stages
    """Publish a site's new names and HTTPS setting, then prove every name answers."""
    identifier = str(document.get("identifier", ""))
    names = document.get("names")
    https = document.get("https")
    form = document.get("form")
    try:
        descriptor = open_site_lock(identifier)
    except BlockingIOError:
        result("lock_busy")
        return
    except OSError, ValueError:
        result("refused", "unsafe_lock")
        return
    changed = False
    try:
        if (
            not isinstance(names, list)
            or not names
            or not all(isinstance(name, str) for name in names)
            or type(https) is not bool
            or form not in ("plain", "wordpress", "laravel")
        ):
            result("refused", "evidence")
            return
        stage("preflight")
        before = native_state("observed", "", protections=False)
        if before["digest"] != document.get("precondition_digest"):
            result("refused", "evidence")
            return
        site = next(
            (candidate for candidate in before["sites"] if candidate["identifier"] == identifier),
            None,
        )
        if (
            site is None
            or site["state"] != "complete"
            or site["serving_form"] != form
            or site["names"] != document.get("previous_names")
            or site["https"] is not document.get("previous_https")
        ):
            result("refused", "evidence")
            return
        settings = setting(
            identifier,
            names,
            site["runtime"],
            https=https,
            readiness=site["readiness"],
        )
        candidate = domains_caddy_file(settings, form)
        if candidate != document.get("caddy"):
            result("refused", "evidence")
            return
        live = pathlib.Path(f"/etc/caddy/sites/{identifier}.caddy")
        preimage = current_bytes(live)
        if preimage is None:
            result("refused", "evidence")
            return
        stage("caddy")
        if not publish_caddy(identifier, candidate, preimage):
            result("refused", "site_domains")
            return
        changed = True
        stage("verify")
        after = native_state("observed", "", protections=False)
        current = next(
            (row for row in after["sites"] if row["identifier"] == identifier),
            None,
        )
        if (
            current is None
            or current["state"] != "complete"
            or current["serving_form"] != form
            or current["names"] != names
            or current["https"] is not https
        ):
            raise ValueError("The published names and HTTPS setting did not verify.")
        verify_domains(settings, form)
        result("succeeded")
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        sys.stderr.write(
            "Domains change stopped (" + type(error).__name__ + "): " + str(error)[:500] + "\n"
        )
        result("partial" if changed else "refused", "site_domains" if changed else "evidence")
    finally:
        os.close(descriptor)


def set_site_readiness(document: dict[str, object]) -> None:
    """Publish one site's readiness path in its Caddy file and prove it answers."""
    identifier = str(document.get("identifier", ""))
    value = document.get("readiness")
    stage("preflight")
    changed = False
    try:
        if not isinstance(value, str):
            result("refused", "evidence")
            return
        path, problem = readiness_path(value)
        if problem or path != value:
            result("refused", "evidence")
            return
        before = native_state("observed", "", protections=False)
        if before["digest"] != document.get("precondition_digest"):
            result("refused", "evidence")
            return
        site = next(
            (candidate for candidate in before["sites"] if candidate["identifier"] == identifier),
            None,
        )
        if site is None or site["state"] != "complete":
            result("refused", "evidence")
            return
        live = pathlib.Path(f"/etc/caddy/sites/{identifier}.caddy")
        preimage = current_bytes(live)
        if preimage is None:
            result("refused", "evidence")
            return
        settings = setting(
            identifier,
            site["names"],
            site["runtime"],
            https=site["https"],
            readiness=path,
        )
        stage("caddy")
        if not publish_caddy(identifier, caddy_file(settings), preimage):
            result("refused", "readiness_publish")
            return
        changed = True
        stage("verify")
        after = native_state("observed", "", protections=False)
        current = next(
            (candidate for candidate in after["sites"] if candidate["identifier"] == identifier),
            None,
        )
        if current is None or current["state"] != "complete" or current["readiness"] != path:
            raise ValueError("The published readiness path did not verify.")
        verify_readiness(settings)
        result("succeeded")
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        sys.stderr.write(
            "Readiness change stopped (" + type(error).__name__ + "): " + str(error)[:500] + "\n"
        )
        result(
            "partial" if changed else "refused",
            "site_readiness" if changed else "evidence",
        )


def reload_site_fpm(settings: SimpleNamespace) -> None:
    """Ask one site's own master to reload its pool and wait for the completed load."""
    unit = php_site_unit(settings.identifier, settings.runtime)
    command = ["systemctl", "show", unit, "--property=ActiveState,MainPID,InvocationID"]
    before = unit_properties(run(command, check=False))
    pid = before.get("MainPID", "")
    if before.get("ActiveState") != "active" or not pid.isdecimal() or int(pid) <= 0:
        raise ValueError("The site's own PHP master is not running.")
    os.kill(int(pid), signal.SIGUSR2)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if site_fpm_read(settings) is not None:
            after = unit_properties(run(command, check=False))
            if after.get("MainPID") != pid or after.get("InvocationID") != before.get(
                "InvocationID"
            ):
                raise ValueError("The site's PHP master was replaced instead of reloaded.")
            return
        time.sleep(0.5)
    raise ValueError("The site's PHP master did not complete its reload.")


def set_site_pool(document: dict[str, object]) -> None:
    """Rewrite one site's bounded pool settings and reload only its own master."""
    try:
        descriptor = open_site_lock(str(document.get("identifier", "")))
    except BlockingIOError:
        result("lock_busy")
        return
    except OSError, ValueError:
        result("refused", "unsafe_lock")
        return
    try:
        pool_locked_change(document, descriptor)
    finally:
        os.close(descriptor)


def pool_locked_change(document: dict[str, object], descriptor: int) -> None:  # noqa: C901 - reviewed stages
    identifier = str(document.get("identifier", ""))
    pool = SitePool.from_document(document.get("pool"))
    stage("preflight")
    changed = False
    path: pathlib.Path | None = None
    preimage: str | None = None
    candidate: str | None = None
    settings: SimpleNamespace | None = None
    try:
        if pool is None:
            result("refused", "evidence")
            return
        before = native_state("observed", "", protections=False)
        if before["digest"] != document.get("precondition_digest"):
            result("refused", "evidence")
            return
        site = next(
            (row for row in before["sites"] if row["identifier"] == identifier),
            None,
        )
        if site is None or site["state"] != "complete" or site["pool"] is None:
            result("refused", "evidence")
            return
        settings = setting(
            identifier,
            site["names"],
            site["runtime"],
            https=site["https"],
            readiness=site["readiness"],
        )
        path = pathlib.Path(site_pool_path(settings.identifier, settings.runtime))
        preimage = current_bytes(path)
        if preimage is None:
            result("refused", "evidence")
            return
        candidate = render_pool_settings(preimage, pool)
        account = pwd.getpwnam(settings.account)
        validate_pool_candidate(settings, account.pw_uid, candidate)
        if not same_site_lock(descriptor, identifier):
            result("refused", "evidence")
            return
        if native_state("observed", "", protections=False)["digest"] != before["digest"]:
            result("refused", "evidence")
            return
        if not fence(document, identifier):
            result("refused", "automation_fence")
            return
        stage("pool")
        replace_site_file(path, candidate, preimage)
        changed = True
        stage("reload")
        reload_site_fpm(settings)
        stage("verify")
        after = native_state("observed", "", protections=False)
        current = next(
            (item for item in after["sites"] if item["identifier"] == identifier),
            None,
        )
        if (
            current is None
            or current["state"] != "complete"
            or SitePool.from_document(current["pool"]) != pool
        ):
            raise ValueError("The reloaded pool did not verify.")
        if not restore(document, identifier):
            result("partial", "automation_restore")
            return
        result("succeeded")
    except ValueError, OSError, KeyError, subprocess.TimeoutExpired:
        if (
            changed
            and path is not None
            and preimage is not None
            and candidate is not None
            and settings is not None
        ):
            try:
                replace_site_file(path, preimage, candidate)
                reload_site_fpm(settings)
            except ValueError, OSError, KeyError, subprocess.TimeoutExpired:
                pass
        result("partial" if changed else "refused", "site_pool" if changed else "evidence")
