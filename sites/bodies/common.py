import base64
import hashlib
import json
import os
import pathlib
import pwd
import re
import stat
import subprocess
import tempfile
import time
from types import SimpleNamespace

CADDY_TEMPLATE = ""
POOL_TEMPLATE = ""
CADDY = "/nix/var/nix/profiles/barectl/caddy/bin/caddy"
ADMIN = "unix//run/caddy/admin.sock"


def run(args: list[str], text: str | None = None, *, check: bool = True) -> str:
    result = subprocess.run(
        args, input=text, text=True, capture_output=True, timeout=20, check=False
    )
    if len(result.stdout) > 1048576 or len(result.stderr) > 1048576 or check and result.returncode:
        raise ValueError("The native command failed or exceeded its bound.")
    return result.stdout


def setting(identifier: str, names: list[str], entry: str) -> SimpleNamespace:
    if not re.fullmatch(r"[a-z][a-z0-9]{2,23}", identifier) or entry not in ("php84", "php85"):
        raise ValueError("Invalid site identity.")
    if not 1 <= len(names) <= 10 or len(set(names)) != len(names):
        raise ValueError("Invalid DNS name list.")
    for name in names:
        if len(name) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in name.split(".")
        ):
            raise ValueError("Invalid DNS name.")
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


def adapt(text: str | None = None, path: str = "/etc/caddy/Caddyfile") -> object:
    return json.loads(
        run(
            [
                CADDY,
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
    if not safe(str(directory), directory=True):
        raise ValueError("Unsafe pool directory.")
    identifiers = []
    for path in sorted(directory.glob("*.conf")):
        if path.name == "diagnostic.conf":
            continue
        identifier = path.stem
        if not safe(str(path)):
            raise ValueError("Unsafe pool file.")
        settings = setting(identifier, ["example.com"], entry)
        if path.read_text() != pool_file(settings):
            raise ValueError("An unsupported pool blocks this master's change.")
        identifiers.append(identifier)
    return identifiers


def native_state(identifier: str, entry: str) -> dict[str, object]:
    directories = ["/etc/caddy", "/etc/caddy/sites", "/var/www", f"/etc/php-fpm/{entry}/pools"]
    if (
        any(not safe(p, directory=True) for p in directories if p != "/var/www")
        or (pathlib.Path("/var/www").exists() and not safe("/var/www", directory=True))
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
    sites: list[dict[str, object]] = []
    seen: set[str] = set()
    for path in files:
        if path.suffix != ".caddy" or not safe(str(path)):
            raise ValueError("Unsupported Caddy file.")
        original = adapt(path.read_text())
        settings = extract(path.stem, original)
        if original != adapt(caddy_file(settings)):
            raise ValueError("A site does not round trip through Caddy's adapter.")
        if seen.intersection(settings.names):
            raise ValueError("A host is already claimed.")
        seen.update(settings.names)
        try:
            account = pwd.getpwnam(settings.account)
            attributes = [
                account.pw_uid,
                account.pw_gid,
                account.pw_dir,
                account.pw_shell,
                sorted(os.getgrouplist(account.pw_name, account.pw_gid)),
            ]
        except KeyError:
            attributes = None
        sites.append(
            {
                "identifier": settings.identifier,
                "names": settings.names,
                "runtime": settings.runtime,
                "account": attributes,
                "file": str(path),
            }
        )
    current = membership(entry)
    paths = [
        "/etc/caddy/Caddyfile",
        *[str(p) for p in files],
        *directories,
        "/etc/passwd",
        "/etc/login.defs",
        "/etc/group",
        "/etc/shadow",
        f"/var/www/{identifier}",
        f"/etc/php-fpm/{entry}/pools/{identifier}.conf",
    ]
    evidence = {path: fingerprint(path) for path in paths}
    return {
        "version": 1,
        "boot": pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "uptime": int(float(pathlib.Path("/proc/uptime").read_text().split()[0]) * 100),
        "sites": sites,
        "current_sites": current,
        "disk_digest": hashlib.sha256(canonical(disk).encode()).hexdigest(),
        "digest": hashlib.sha256(canonical(evidence).encode()).hexdigest(),
        "evidence": evidence,
        "next_id": free_identity(),
    }


def free_identity() -> int:
    used = {row.pw_uid for row in pwd.getpwall()}
    import grp

    used.update(row.gr_gid for row in grp.getgrall())
    return next(value for value in range(1000, 30000) if value not in used)


def result(outcome: str, reason: str = "") -> None:
    value = {"class": outcome}
    if reason:
        value["reason"] = reason
    print("barectl-result " + canonical(value), flush=True)


def stage(value: str) -> None:
    print("barectl-stage " + value, flush=True)


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


def publish_caddy(identifier: str, candidate: str, preimage: str | None) -> bool:
    live = pathlib.Path(f"/etc/caddy/sites/{identifier}.caddy")
    old = running()
    main = pathlib.Path("/etc/caddy/Caddyfile").read_text()
    if "import sites/*.caddy" not in main or "import /" in main:
        raise ValueError("The main configuration does not use the supported relative tree.")
    if (live.read_text() if live.exists() else None) != preimage:
        raise ValueError("The reviewed preimage changed.")
    with tempfile.TemporaryDirectory(prefix="site-candidate-", dir="/run") as directory:
        import grp

        root = pathlib.Path(directory)
        os.chown(root, 0, grp.getgrnam("caddy").gr_gid)
        root.chmod(0o750)
        (root / "sites").mkdir(mode=0o750)
        os.chown(root / "sites", 0, grp.getgrnam("caddy").gr_gid)
        for source in pathlib.Path("/etc/caddy/sites").iterdir():
            if source.suffix != ".caddy" or not safe(str(source)):
                raise ValueError("Unsupported candidate tree member.")
            target = root / "sites" / source.name
            target.write_bytes(source.read_bytes())
            os.chown(target, 0, grp.getgrnam("caddy").gr_gid)
            target.chmod(0o640)
        (root / "Caddyfile").write_text(main)
        target = root / "sites" / live.name
        target.write_text(candidate)
        for target in (root / "Caddyfile", target):
            os.chown(target, 0, grp.getgrnam("caddy").gr_gid)
            target.chmod(0o640)
        run(
            [
                "/usr/sbin/runuser",
                "-u",
                "caddy",
                "--",
                CADDY,
                "validate",
                "--config",
                str(root / "Caddyfile"),
                "--adapter",
                "caddyfile",
            ]
        )
        if (live.read_text() if live.exists() else None) != preimage or not safe(
            str(live.parent), directory=True
        ):
            raise ValueError("The preimage changed during validation.")
        if preimage is None:
            write_new(str(live), candidate, 0o644)
        else:
            replacement = root / "replacement"
            replacement.write_text(candidate)
            replacement.chmod(0o644)
            os.replace(replacement, live)
        try:
            run(
                [
                    CADDY,
                    "reload",
                    "--config",
                    "/etc/caddy/Caddyfile",
                    "--adapter",
                    "caddyfile",
                    "--address",
                    ADMIN,
                ]
            )
            if running() != adapt():
                raise ValueError("Caddy's loaded configuration differs from disk.")
            return True
        except ValueError, OSError, subprocess.TimeoutExpired:
            if live.read_text() != candidate or not safe(str(live)):
                raise ValueError(
                    "Caddy restoration cannot prove its publication identity."
                ) from None
            if preimage is None:
                live.unlink()
            else:
                replacement = root / "restore"
                replacement.write_text(preimage)
                replacement.chmod(0o644)
                os.replace(replacement, live)
            if running() != old:
                run(
                    [
                        CADDY,
                        "reload",
                        "--config",
                        "/etc/caddy/Caddyfile",
                        "--adapter",
                        "caddyfile",
                        "--address",
                        ADMIN,
                    ]
                )
            if (
                adapt() != old
                or running() != old
                or (live.read_text() if live.exists() else None) != preimage
            ):
                raise ValueError("Caddy's old serving configuration could not be proven.") from None
            return False


def create(document: dict[str, object]) -> None:
    settings = setting(str(document["identifier"]), document["names"], str(document["selection"]))
    stage("preflight")
    before = native_state(settings.identifier, settings.runtime)
    if (
        before["digest"] != document["precondition_digest"]
        or before["disk_digest"] != document["disk_digest"]
        or before["next_id"] != document["identity"]
    ):
        result("refused", "evidence")
        return
    if settings.identifier in before["current_sites"] or pathlib.Path(settings.directory).exists():
        result("refused", "evidence")
        return
    changed = False
    try:
        stage("account")
        identity = str(document["identity"])
        run(["/usr/sbin/groupadd", "--gid", identity, settings.account])
        changed = True
        run(
            [
                "/usr/sbin/useradd",
                "--uid",
                identity,
                "--gid",
                identity,
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
        stage("layout")
        for path, owner, group, mode in (
            ("/var/www", "root", "root", "755"),
            (settings.directory, "root", "root", "755"),
            (settings.directory + "/releases", "root", settings.account, "750"),
            (settings.directory + "/releases/initial", "root", "caddy", "750"),
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
        for name, executable in (
            ("php", f"/nix/var/nix/profiles/barectl/{settings.runtime}/bin/php"),
            ("composer", "/nix/var/nix/profiles/barectl/composer/bin/composer"),
            ("wp", "/nix/var/nix/profiles/barectl/wp-cli/bin/wp"),
        ):
            command = (
                f'"{executable}"'
                if name == "php"
                else f'"/nix/var/nix/profiles/barectl/{settings.runtime}/bin/php" "{executable}"'
            )
            write_new(
                settings.directory + "/bin/" + name, "#!/bin/sh\nexec " + command + ' "$@"\n', 0o755
            )
        stage("pool")
        pool_path = f"/etc/php-fpm/{settings.runtime}/pools/{settings.identifier}.conf"
        write_new(pool_path, pool_file(settings), 0o644)
        run(
            [
                f"/nix/var/nix/profiles/barectl/{settings.runtime}/bin/php-fpm",
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
        stage("caddy")
        if not publish_caddy(settings.identifier, caddy_file(settings), None):
            result("partial", "site_caddy")
            return
        stage("verify")
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
            if response.get("uid") != account.pw_uid or response.get("site") != settings.identifier:
                raise ValueError("PHP is not serving as the site's reviewed account.")
        result("succeeded")
    except ValueError, OSError, subprocess.TimeoutExpired:
        result("partial" if changed else "refused", "site_create" if changed else "evidence")
