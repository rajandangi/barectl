import base64
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
from typing import Final, TypedDict

from runtimes.live import live_values, master_identity, protected
from sites.bodies.admission import (
    hap_api,
    hap_inventory,
    hap_validate,
    haproxy_state,
    persist_proxy_state,
)
from sites.bodies.pool import supported_pool
from sites.bodies.pool_boundary import safe_pool_boundary
from sites.bodies.site_fpm import sfp_file, sfp_retained_shape, site_fpm_evidence
from sites.names import request
from sites.serving import diagnostic_pool, fpm_unit, haproxy_config, master_config

PHP_TRANSITION_INCOMPLETE: Final[str] = "The PHP runtime transition is incomplete."


class SiteRecord(TypedDict):
    identifier: str
    names: list[str]
    runtime: str
    node_runtime: str
    account: list[object] | None
    file: str
    state: str
    problem: str


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
POOL_TEMPLATE = ""
KNOWN_CADDY: dict[str, tuple[str, ...]] = {}
KNOWN_PHP: dict[str, dict[str, tuple[str, ...]]] = {}
KNOWN_NODE: dict[str, dict[str, tuple[str, ...]]] = {}
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


def setting(identifier: str, names: list[str], entry: str) -> SimpleNamespace:
    if entry not in ("php84", "php85"):
        raise ValueError("Invalid PHP runtime.")
    canonical_identifier, canonical_names = request(
        identifier, " ".join(names), max_name_octets=253
    )
    if canonical_identifier != identifier or list(canonical_names) != names:
        raise ValueError("The native site selection is not canonical.")
    return SimpleNamespace(
        identifier=identifier,
        names=names,
        runtime=entry,
        account="s" + identifier,
        directory="/var/www/" + identifier,
        socket=f"/run/php-fpm/sites/{identifier}/{entry}/app.sock",
        proxy_socket=f"/run/haproxy/{identifier}/http.sock",
        proxy="p" + identifier,
    )


def caddy_file(settings: SimpleNamespace) -> str:
    return CADDY_TEMPLATE.format(
        settings=settings, addresses=", ".join("http://" + n for n in settings.names)
    )


def pool_file(settings: SimpleNamespace) -> str:
    return POOL_TEMPLATE.format(settings=settings)


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


def extract(identifier: str, value: object) -> SimpleNamespace:
    hosts: list[list[str]] = []
    roots: set[str] = set()
    sockets: set[str] = set()

    def visit(node: object) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                if (
                    key == "host"
                    and isinstance(child, list)
                    and all(isinstance(x, str) for x in child)
                ):
                    hosts.append(child)
                elif key == "root" and isinstance(child, str):
                    roots.add(child)
                elif key == "dial" and isinstance(child, str):
                    sockets.add(child)
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(value)
    if (
        len(hosts) != 1
        or roots != {f"/var/www/{identifier}/current/public"}
        or sockets != {f"unix//run/haproxy/{identifier}/http.sock"}
    ):
        raise ValueError("A site has unsupported private routing.")
    return setting(identifier, hosts[0], "php84")


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


def wrapper(settings: SimpleNamespace, name: str) -> str:
    executable = {
        "php": f"/nix/var/nix/profiles/barectl/{settings.runtime}/bin/php",
        "composer": "/nix/var/nix/profiles/barectl/composer/share/php/composer/bin/composer",
        "wp": "/nix/var/nix/profiles/barectl/wp-cli/share/wp-cli/wp-cli.phar",
    }[name]
    command = (
        f'"{executable}"'
        if name == "php"
        else f'"/nix/var/nix/profiles/barectl/{settings.runtime}/bin/php" "{executable}"'
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
        return "", "The site's Node command links have an interrupted selection.", links
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


def node_locked_change(document: dict[str, object], descriptor: int) -> None:
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
        if (
            site["state"] != "complete"
            and site["problem"] != "The site's Node command links have an interrupted selection."
        ):
            result("refused", "evidence")
            return
        directory = pathlib.Path("/var/www") / identifier / "bin"
        if not safe(str(directory), directory=True) or not same_site_lock(descriptor, identifier):
            result("refused", "evidence")
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


def directory_shape(settings: SimpleNamespace, uid: int, gid: int) -> tuple[str, str]:
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
    directories = (
        (settings.directory, 0, 0, 0o755),
        (settings.directory + "/releases", 0, 0, 0o755),
        (settings.directory + "/" + target, 0, 0, 0o755),
        (settings.directory + "/" + target + "/public", uid, caddy_gid, 0o2750),
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
    return "complete", ""


def php_wrapper_selections(settings: SimpleNamespace) -> dict[str, str] | None:
    selections: dict[str, str] = {}
    for name in ("php", "composer", "wp"):
        path = settings.directory + "/bin/" + name
        if not safe(path) or not metadata_matches(path, 0, 0, 0o755, stat.S_IFREG):
            return None
        contents = pathlib.Path(path).read_text()
        matches = [
            entry
            for entry in ("php84", "php85")
            if contents == wrapper(setting(settings.identifier, settings.names, entry), name)
        ]
        if len(matches) != 1:
            return None
        selections[name] = matches[0]
    return selections


def php_wrapper_runtime(settings: SimpleNamespace) -> str:
    selections = php_wrapper_selections(settings)
    versions = set(selections.values()) if selections is not None else set()
    return next(iter(versions)) if len(versions) == 1 else ""


def configuration_shape(settings: SimpleNamespace, uid: int, gid: int) -> tuple[str, str]:
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
    return serving_shape(settings)


def php_survivors(
    settings: SimpleNamespace,
) -> dict[str, tuple[int, int, str, bytes]] | None:
    """Native owner, mode, kind and bytes of every entry under a runtime's directory."""
    base = f"/etc/php-fpm/sites/{settings.identifier}/{settings.runtime}"
    observed: dict[str, tuple[int, int, str, bytes]] = {}
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
    """Whether the runtime's surviving configuration is complete, a canonical subset or foreign."""
    observed = php_survivors(settings)
    if observed is None:
        return "unsupported"
    return sfp_retained_shape(site_fpm_files(settings), observed, active)


def serving_shape(settings: SimpleNamespace) -> tuple[str, str]:
    pool = pathlib.Path(
        f"/etc/php-fpm/sites/{settings.identifier}/{settings.runtime}/pools/{settings.identifier}.conf"
    )
    if not pool.exists() or not pathlib.Path(settings.socket).exists():
        return "partial", "The site's independent PHP service or socket is absent."
    if not safe(str(pool)) or not supported_pool(
        settings.identifier, settings.runtime, pool.read_text()
    ):
        return "unsupported", "The site pool has settings outside the supported bounds."
    proxy = pwd.getpwnam(settings.proxy)
    if not metadata_matches(settings.socket, 0, proxy.pw_gid, 0o660, stat.S_IFSOCK):
        return "unsupported", "The application's private admission socket is unsafe."
    if site_fpm_read(settings) is None:
        return "unsupported", "The site PHP service has unavailable native protection evidence."
    observed = haproxy_state(settings)
    if observed["selection"] != settings.runtime or observed["persistent"] != settings.runtime:
        return "partial", PHP_TRANSITION_INCOMPLETE
    other = "php85" if settings.runtime == "php84" else "php84"
    retained = pathlib.Path(f"/etc/php-fpm/sites/{settings.identifier}/{other}")
    if retained.exists() or retained.is_symlink():
        if (
            retained_php_shape(
                setting(settings.identifier, settings.names, other),
                active=php_service_active(settings.identifier, other),
            )
            == "unsupported"
        ):
            return "unsupported", "Retained PHP configuration is administrator-owned."
        return "partial", PHP_TRANSITION_INCOMPLETE
    _, node_problem, _ = node_command_links(settings.identifier)
    return ("unsupported", node_problem) if node_problem else ("complete", "")


def php_service_active(identifier: str, entry: str) -> bool:
    """Whether another runtime's site service runs or is in an unresolved native state."""
    report = run(
        [
            "systemctl",
            "show",
            f"php-fpm-site-{entry}@{identifier}.service",
            "--property=ActiveState,MainPID",
        ],
        check=False,
    )
    values = dict(line.split("=", 1) for line in report.splitlines())
    return not (
        values.get("ActiveState") in ("inactive", "failed") and values.get("MainPID") == "0"
    )


def site_shape(settings: SimpleNamespace, attributes: list[object] | None) -> tuple[str, str]:
    if attributes is None:
        return "partial", "The site's Linux account is absent."
    try:
        uid, gid = account_ids(settings, attributes)
        state, problem = directory_shape(settings, uid, gid)
        if state != "complete":
            return state, problem
        return configuration_shape(settings, uid, gid)
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


def partial_sites(known: set[str], requested: str = "") -> list[SiteRecord]:
    candidates = partial_candidates(requested)
    if len(candidates - known) > 64:
        raise ValueError("Too many partial site candidates.")
    rows: list[SiteRecord] = []
    for identifier in sorted(candidates - known):
        if not re.fullmatch(r"[a-z][a-z0-9]{2,23}", identifier):
            continue
        try:
            request(identifier, "example.com", max_name_octets=253)
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
            observed_state, _ = site_shape(settings, attributes)
            if observed_state == "unsupported":
                state = "unsupported"
        if len(masters) > 1:
            state = "unsupported"
        rows.append(
            {
                "identifier": identifier,
                "names": [],
                "runtime": runtime,
                "node_runtime": "",
                "account": attributes,
                "file": f"/etc/caddy/sites/{identifier}.caddy",
                "state": state,
                "problem": (
                    "Native account, group, directory or pool evidence exists, "
                    "but its Caddy route is absent."
                ),
            }
        )
    return rows


def site_runtime_state(
    settings: SimpleNamespace, attributes: list[object] | None
) -> tuple[str, str]:
    return site_shape(settings, attributes)


def native_directories(entry: str) -> list[str]:
    directories = ["/etc/caddy", "/etc/caddy/sites", "/var/www"]
    if entry:
        directories.extend(("/etc/haproxy/sites", "/var/lib/haproxy/sites"))
    return directories


def native_site_record(path: pathlib.Path) -> SiteRecord:
    original = adapt(path.read_text())
    settings = extract(path.stem, original)
    supported = original == adapt(caddy_file(settings))
    attributes = site_account(settings.identifier)
    try:
        proxy = haproxy_state(settings)
        selected = proxy["selection"]
        if selected:
            settings = setting(settings.identifier, settings.names, selected)
            state, problem = site_runtime_state(settings, attributes)
        else:
            settings.runtime = ""
            state, problem = "partial", PHP_TRANSITION_INCOMPLETE
    except (ValueError, OSError, KeyError, subprocess.TimeoutExpired) as error:
        sys.stderr.write("Site serving evidence stopped: " + str(error)[:500] + "\n")
        settings.runtime = ""
        state, problem = "unsupported", "The private PHP admission evidence is unavailable."
    node_runtime, _, _ = node_command_links(settings.identifier)
    if not supported:
        state = "unsupported"
        problem = "The site has Caddy settings outside the supported configuration."
    return {
        "identifier": settings.identifier,
        "names": settings.names,
        "runtime": settings.runtime,
        "node_runtime": node_runtime,
        "account": attributes,
        "file": str(path),
        "state": state,
        "problem": problem,
    }


def native_state(
    identifier: str, entry: str, requested_names: list[str] | None = None
) -> NativeState:
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
    sites: list[SiteRecord] = []
    seen: set[str] = set()
    for path in files:
        if path.suffix != ".caddy" or not safe(str(path)):
            raise ValueError("Unsupported Caddy file.")
        record = native_site_record(path)
        if seen.intersection(record["names"]):
            raise ValueError("A host is already claimed.")
        seen.update(record["names"])
        sites.append(record)
    sites += partial_sites({site["identifier"] for site in sites}, identifier if entry else "")
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
    value["validation"] = validation_status(identifier, entry, requested_names)
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


def validation_status(identifier: str, entry: str, names: list[str] | None) -> str:
    if not names:
        return "not_requested"
    try:
        validate_candidate(identifier, caddy_file(setting(identifier, names, entry)))
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
                f"/etc/php-fpm/sites/{settings.identifier}/{settings.runtime}",
            ]
        )


def current_bytes(path: pathlib.Path) -> str | None:
    if path.is_symlink() or (path.exists() and not safe(str(path))):
        raise ValueError("The live Caddy file is outside the root-controlled convention.")
    return path.read_text() if path.exists() else None


def replace_caddy(path: pathlib.Path, value: str, expected: str | None) -> None:
    if current_bytes(path) != expected or not safe(str(path.parent), directory=True):
        raise ValueError("The Caddy preimage changed before publication.")
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
            raise ValueError("The Caddy preimage changed during staging.")
        os.replace(temporary, path)
    finally:
        pathlib.Path(temporary).unlink(missing_ok=True)


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
        (settings.directory + "/releases/initial", "root", "root", "755"),
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


def site_fpm_files(settings: SimpleNamespace) -> dict[str, str]:
    root = f"/etc/php-fpm/sites/{settings.identifier}/{settings.runtime}"
    return {
        root + "/php.ini": NATIVE_MASTER_FILES[settings.runtime]["php.ini"],
        root + "/php-fpm.conf": master_config(settings),
        root + f"/pools/{settings.identifier}.conf": pool_file(settings),
        root + "/pools/diagnostic.conf": diagnostic_pool(settings),
    }


def site_fpm_read(settings: SimpleNamespace) -> dict[str, object] | None:
    expected = {
        **site_fpm_files(settings),
        f"/etc/systemd/system/php-fpm-site-{settings.runtime}@.service": fpm_unit(settings.runtime),
        "/etc/php-fpm/diagnostics/probe.php": NATIVE_PROBE,
    }
    fcgi = os.path.realpath("/nix/var/nix/profiles/barectl/fcgi")
    if fcgi not in KNOWN_FCGI.get(os.uname().machine, ()):
        return None
    return site_fpm_evidence(
        settings.identifier,
        settings.runtime,
        expected,
        KNOWN_PHP.get(os.uname().machine, {}).get(settings.runtime, ()),
        fcgi,
    )


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
    root = f"/etc/php-fpm/sites/{settings.identifier}/{settings.runtime}"
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
    settings = setting(str(document["identifier"]), names, str(document["selection"]))
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


def verify_http(settings: SimpleNamespace, uid: int) -> None:
    for hostname in settings.names:
        response = json.loads(
            run(
                [
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
            )
        )
        if response.get("uid") != uid or response.get("site") != settings.identifier:
            raise ValueError("PHP is not serving as the site's reviewed account.")
