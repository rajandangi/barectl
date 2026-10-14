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
from typing import TypedDict

from runtimes.live import live_values, master_identity, protected
from sites.bodies.pool import supported_pool
from sites.bodies.pool_boundary import ini_pool, safe_pool_boundary
from sites.names import request


class SiteRecord(TypedDict):
    identifier: str
    names: list[str]
    runtime: str
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
    validation: str
    pool_validation: str
    master_present: bool


CADDY_TEMPLATE = ""
POOL_TEMPLATE = ""
KNOWN_CADDY: dict[str, tuple[str, ...]] = {}
KNOWN_PHP: dict[str, dict[str, tuple[str, ...]]] = {}
NATIVE_MASTER_FILES: dict[str, dict[str, str]] = {}
ADMIN = "unix//run/caddy/admin.sock"
RUNTIME_READ_SOURCE = ""


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
        socket=f"/run/php-fpm/{entry}/{identifier}.sock",
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
    if len(hosts) != 1 or roots != {f"/var/www/{identifier}/current/public"} or len(sockets) != 1:
        raise ValueError("A site has unsupported routing.")
    socket = sockets.pop()
    entry = next(
        (
            entry
            for entry in ("php84", "php85")
            if socket == f"unix//run/php-fpm/{entry}/{identifier}.sock"
        ),
        "",
    )
    return setting(identifier, hosts[0], entry)


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


def configuration_shape(settings: SimpleNamespace, uid: int, gid: int) -> tuple[str, str]:
    caddy_gid = grp.getgrnam("caddy").gr_gid
    lock = settings.directory + "/.deploy.lock"
    if fingerprint(lock) is None:
        return "partial", "The stable per-site deploy lock is absent."
    if not metadata_matches(lock, 0, gid, 0o640, stat.S_IFREG) or not safe(lock):
        return "unsupported", "The deploy lock is outside the root-controlled convention."
    for name in ("php", "composer", "wp"):
        path = settings.directory + "/bin/" + name
        if fingerprint(path) is None:
            return "partial", "A site runtime wrapper is absent."
        if (
            not safe(path)
            or not metadata_matches(path, 0, 0, 0o755, stat.S_IFREG)
            or pathlib.Path(path).read_text() != wrapper(settings, name)
        ):
            return "unsupported", "A site runtime wrapper differs from its observed runtime."
    pool = pathlib.Path(f"/etc/php-fpm/{settings.runtime}/pools/{settings.identifier}.conf")
    if not pool.exists() or not pathlib.Path(settings.socket).exists():
        return "partial", "The site pool or runtime-keyed socket is absent."
    if not safe(str(pool)) or not supported_pool(
        settings.identifier, settings.runtime, pool.read_text()
    ):
        return "unsupported", "The site pool has settings outside the supported bounds."
    if not metadata_matches(settings.socket, uid, caddy_gid, 0o660, stat.S_IFSOCK):
        return "unsupported", "The site's socket has unsupported ownership or permissions."
    return "complete", ""


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


def native_directories(entry: str) -> list[str]:
    directories = ["/etc/caddy", "/etc/caddy/sites", "/var/www"]
    if entry:
        directories.append(f"/etc/php-fpm/{entry}/pools")
    return directories


def native_state(
    identifier: str, entry: str, requested_names: list[str] | None = None
) -> NativeState:
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
        original = adapt(path.read_text())
        settings = extract(path.stem, original)
        supported = original == adapt(caddy_file(settings))
        if seen.intersection(settings.names):
            raise ValueError("A host is already claimed.")
        seen.update(settings.names)
        attributes = site_account(settings.identifier)
        state, problem = site_shape(settings, attributes)
        if not supported:
            state = "unsupported"
            problem = "The site has Caddy settings outside the supported configuration."
        sites.append(
            {
                "identifier": settings.identifier,
                "names": settings.names,
                "runtime": settings.runtime,
                "account": attributes,
                "file": str(path),
                "state": state,
                "problem": problem,
            }
        )
    sites += partial_sites({site["identifier"] for site in sites}, identifier if entry else "")
    current = membership(entry) if entry else []
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
        "validation": "not_requested",
        "pool_validation": "not_requested",
        "master_present": bool(entry and pathlib.Path(f"/etc/php-fpm/{entry}/pools").is_dir()),
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


def free_identity() -> int:
    used = {row.pw_uid for row in pwd.getpwall()}
    import grp

    used.update(row.gr_gid for row in grp.getgrall())
    return next(value for value in range(1000, 30000) if value not in used)


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
    for field in ("user", "group", "listen.owner"):
        before = f"{field} = {settings.account}\n"
        if candidate.count(before) != 1:
            raise ValueError("The pool's symbolic identity differs from review.")
        candidate = candidate.replace(before, f"{field} = {identity}\n")
    return candidate


def pool_validation_directories(scratch: pathlib.Path, pools: pathlib.Path, identity: int) -> None:
    for path in pools.glob("*.conf"):
        if path.name == "diagnostic.conf":
            continue
        identifier = path.stem
        if re.fullmatch(r"[a-z][a-z0-9]{2,23}", identifier) is None:
            raise ValueError("Unsupported pool identity in validation tree.")
        values = ini_pool(path.read_text(), identifier)
        if values is None or values.get("slowlog") != f"/var/www/{identifier}/logs/php-slow.log":
            raise ValueError("An existing pool has an unsupported validation log path.")
        if "access.log" in values:
            raise ValueError("An existing pool has an unsupported access log path.")
        group = site_account(identifier)
        group_id = int(str(group[1])) if group else identity
        copied_directory(scratch, f"www/{identifier}", 0, 0, 0o755)
        copied_directory(scratch, f"www/{identifier}/logs", 0, group_id, 0o750)


def validate_pool_candidate(settings: SimpleNamespace, identity: int, candidate: str) -> None:
    source = pathlib.Path(f"/etc/php-fpm/{settings.runtime}")
    with tempfile.TemporaryDirectory(prefix="site-pool-candidate-", dir="/run") as directory:
        root = pathlib.Path(directory)
        copied = root / "master"
        copied.mkdir(mode=0o755)
        (copied / "pools").mkdir(mode=0o755)
        for original, destination in ((source, copied), (source / "pools", copied / "pools")):
            if not safe(str(original), directory=True):
                raise ValueError("Unsafe master tree directory.")
            metadata = original.stat()
            os.chown(destination, metadata.st_uid, metadata.st_gid)
            destination.chmod(stat.S_IMODE(metadata.st_mode))
        for path in [
            source / "php.ini",
            source / "php-fpm.conf",
            *sorted((source / "pools").glob("*.conf")),
        ]:
            if not safe(str(path)):
                raise ValueError("Unsafe master tree member.")
            if path.name in (
                "php.ini",
                "php-fpm.conf",
            ) and path.read_text() != NATIVE_MASTER_FILES.get(settings.runtime, {}).get(path.name):
                raise ValueError("The master configuration is not the supported safe input.")
            destination = copied / path.relative_to(source)
            destination.write_bytes(path.read_bytes())
            metadata = path.stat()
            os.chown(destination, metadata.st_uid, metadata.st_gid)
            destination.chmod(stat.S_IMODE(metadata.st_mode))
        (copied / "pools" / f"{settings.identifier}.conf").write_text(
            numeric_pool_candidate(settings, identity, candidate)
        )
        scratch = root / "var"
        scratch.mkdir(mode=0o755)
        for relative in ("log", "log/php-fpm", "www", f"www/{settings.identifier}"):
            copied_directory(scratch, relative, 0, 0, 0o755)
        pool_validation_directories(scratch, copied / "pools", identity)
        binary = php_binary(settings.runtime)
        run(
            [
                "/usr/bin/unshare",
                "--mount",
                "--propagation",
                "private",
                "/bin/sh",
                "-c",
                (
                    '/usr/bin/mount --bind "$1" "$2" && /usr/bin/mount --bind "$3" /var '
                    '&& exec "$4" -t -y "$2/php-fpm.conf" -c "$2/php.ini"'
                ),
                "validator",
                str(copied),
                str(source),
                str(scratch),
                binary,
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


def configure_pool(settings: SimpleNamespace, account: pwd.struct_passwd) -> None:
    pool_path = f"/etc/php-fpm/{settings.runtime}/pools/{settings.identifier}.conf"
    write_new(pool_path, pool_file(settings), 0o644)
    run(
        [
            php_binary(settings.runtime),
            "-t",
            "-y",
            f"/etc/php-fpm/{settings.runtime}/php-fpm.conf",
            "-c",
            f"/etc/php-fpm/{settings.runtime}/php.ini",
        ]
    )
    run(["/usr/bin/systemctl", "reload", f"php-fpm@{settings.runtime}.service"])
    deadline = time.monotonic() + 10
    while not pathlib.Path(settings.socket).exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    socket = pathlib.Path(settings.socket).stat()
    import grp

    if (
        not stat.S_ISSOCK(socket.st_mode)
        or socket.st_uid != account.pw_uid
        or socket.st_gid != grp.getgrnam("caddy").gr_gid
        or stat.S_IMODE(socket.st_mode) != 0o660
    ):
        raise ValueError("Pool socket differs from the reviewed identity.")


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
        configure_pool(settings, account)
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
