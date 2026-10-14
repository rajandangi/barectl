import base64
import hashlib
import json
import os
import pathlib
import pwd
import stat
import subprocess
import sys
from contextlib import suppress

selection, fcgi_path, expected_probe, expected_unit = sys.argv[1:]
root = pathlib.Path("/nix/var/nix/profiles/barectl")
entries = ("php84", "php85", "nodejs_22", "nodejs_24")


def run(arguments: list[str]) -> str | None:
    try:
        result = subprocess.run(  # noqa: S603 - fixed commands and catalog-validated executable
            arguments, capture_output=True, timeout=8, check=False
        )
        if len(result.stdout) > 32768 or result.returncode:
            return None
        return result.stdout.decode("utf-8")
    except OSError, ValueError, subprocess.TimeoutExpired:
        return None


def file(path: str | pathlib.Path) -> dict[str, object] | None:
    try:
        p = pathlib.Path(path)
        meta = p.lstat()
        value: dict[str, object] = {
            "uid": meta.st_uid,
            "gid": meta.st_gid,
            "mode": stat.S_IMODE(meta.st_mode),
            "type": stat.S_IFMT(meta.st_mode),
        }
        if stat.S_ISLNK(meta.st_mode):
            value["link"] = os.readlink(p)
        elif stat.S_ISREG(meta.st_mode):
            if meta.st_size > 65536:
                return {"unreadable": True}
            value["bytes"] = base64.b64encode(p.read_bytes()).decode()
        return value
    except FileNotFoundError:
        return None
    except OSError:
        return {"unreadable": True}


def identity() -> list[object] | None:
    try:
        user = pwd.getpwnam("php-probe")
        return [
            user.pw_uid,
            user.pw_gid,
            user.pw_dir,
            user.pw_shell,
            sorted(os.getgrouplist("php-probe", user.pw_gid)),
        ]
    except KeyError:
        return None


def paths(entry: str) -> list[str]:
    values = [
        f"/nix/var/nix/profiles/barectl/{entry}",
        "/nix/var/nix/profiles/barectl/fcgi",
        "/etc/systemd/system/php-fpm@.service",
        "/etc/php-fpm",
        "/etc/php-fpm/diagnostics",
        "/etc/php-fpm/diagnostics/probe.php",
    ]
    if entry.startswith("php"):
        values += [
            f"/etc/php-fpm/{entry}",
            f"/etc/php-fpm/{entry}/php.ini",
            f"/etc/php-fpm/{entry}/php-fpm.conf",
            f"/etc/php-fpm/{entry}/pools",
            f"/etc/php-fpm/{entry}/pools/diagnostic.conf",
        ]
        with suppress(FileNotFoundError):
            values += sorted(str(p) for p in pathlib.Path(f"/etc/php-fpm/{entry}/pools").iterdir())[
                :64
            ]
    return sorted(set(values))


def digest(entry: str) -> str:
    values: dict[str, object] = {path: file(path) for path in paths(entry)}
    values["identity"] = identity()
    return hashlib.sha256(
        json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def admissible(entry: str) -> bool:
    profile = file(root / entry)
    target = file(f"/etc/php-fpm/{entry}")
    if profile is None and entry.startswith("php") and target is not None:
        return False
    for path in (
        "/nix",
        "/nix/var",
        "/nix/var/nix",
        "/nix/var/nix/profiles",
        str(root),
        "/etc",
        "/etc/php-fpm",
        "/etc/php-fpm/diagnostics",
        "/etc/systemd",
        "/etc/systemd/system",
    ):
        metadata = file(path)
        if metadata is not None and (
            metadata.get("uid") != 0
            or metadata.get("type") != stat.S_IFDIR
            or not isinstance(metadata.get("mode"), int)
            or int(str(metadata["mode"])) & 0o022
        ):
            return False
    for path, expected in (
        ("/etc/systemd/system/php-fpm@.service", expected_unit),
        ("/etc/php-fpm/diagnostics/probe.php", expected_probe),
    ):
        metadata = file(path)
        if metadata is not None and (
            metadata.get("uid") != 0
            or metadata.get("type") != stat.S_IFREG
            or metadata.get("bytes") != expected
            or not isinstance(metadata.get("mode"), int)
            or int(str(metadata["mode"])) & 0o022
        ):
            return False
    user = identity()
    if user is not None and (
        user[0] == 0 or user[2:4] != ["/nonexistent", "/usr/sbin/nologin"] or user[4] != [user[1]]
    ):
        return False
    tool = file(root / "fcgi")
    return tool is None or os.path.realpath(root / "fcgi") == fcgi_path


rows = []
names = (
    sorted(set(entries) | {p.name for p in root.iterdir() if "-link" not in p.name})
    if root.is_dir()
    else entries
)
if len(names) > 64:
    raise ValueError("too many profiles")
for entry in names:
    if entry in ("caddy", "composer", "wp-cli", "restic", "fcgi"):
        continue
    p = root / entry
    if not p.is_symlink() and not p.exists():
        continue
    path = os.path.realpath(p)
    generation = os.readlink(p) if p.is_symlink() else ""
    row: dict[str, object] = {"entry": entry, "path": path, "generation": generation, "files": {}}
    if entry in ("php84", "php85"):
        row["files"] = {path: file(path) for path in paths(entry)}
        row["identity"] = identity()
        report = run(
            [
                "systemctl",
                "show",
                f"php-fpm@{entry}.service",
                "-p",
                "LoadState",
                "-p",
                "ActiveState",
                "-p",
                "SubState",
                "-p",
                "InvocationID",
                "-p",
                "MainPID",
                "-p",
                "ExecStart",
                "-p",
                "Environment",
            ]
        )
        row["unit"] = report or ""
        socket = pathlib.Path(f"/run/php-fpm/{entry}/diagnostic.sock")
        row["socket"] = file(socket)
        ancestors = [file(p) for p in ("/etc", "/etc/php-fpm", "/etc/php-fpm/diagnostics")]
        probe = file("/etc/php-fpm/diagnostics/probe.php")

        def controlled_directory(metadata: dict[str, object] | None) -> bool:
            return bool(
                metadata
                and metadata.get("uid") == 0
                and metadata.get("type") == stat.S_IFDIR
                and isinstance(metadata.get("mode"), int)
                and int(str(metadata["mode"])) & 0o022 == 0
            )

        safe = all(controlled_directory(v) for v in ancestors)
        safe = safe and bool(
            probe
            and probe.get("uid") == 0
            and probe.get("type") == stat.S_IFREG
            and isinstance(probe.get("mode"), int)
            and int(str(probe["mode"])) & 0o022 == 0
            and probe.get("bytes") == expected_probe
        )
        sock = file(socket)
        safe = safe and bool(
            sock
            and sock.get("type") == stat.S_IFSOCK
            and sock.get("uid") == 0
            and sock.get("gid") == 0
            and sock.get("mode") == 0o600
        )
        safe = safe and os.path.realpath(root / "fcgi") == fcgi_path
        response = None
        if safe:
            response = run(
                [
                    "timeout",
                    "6",
                    "env",
                    "-i",
                    "SCRIPT_FILENAME=/etc/php-fpm/diagnostics/probe.php",
                    "SCRIPT_NAME=/probe.php",
                    "REQUEST_METHOD=GET",
                    "QUERY_STRING=",
                    fcgi_path + "/bin/cgi-fcgi",
                    "-bind",
                    "-connect",
                    str(socket),
                ]
            )
        row["response"] = response or ""
    rows.append(row)
sys.stdout.write(
    json.dumps(
        {
            "version": 1,
            "architecture": os.uname().machine,
            "boot": pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "uptime": int(float(pathlib.Path("/proc/uptime").read_text().split()[0]) * 100),
            "digest": digest(selection),
            "admissible": admissible(selection),
            "runtimes": rows,
        },
        separators=(",", ":"),
    )
)
