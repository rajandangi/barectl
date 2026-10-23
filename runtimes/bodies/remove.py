"""Remove one unused runtime profile and the convention's native configuration.

Staged as the second half of a two-stage body: the first stage prints the default-command
state this script reads on standard input. Invoked with the reviewed entry, kind, path,
generation, expected PHP configuration and known catalog paths.
"""

import base64
import json
import os
import pathlib
import stat
import subprocess
import sys

NIX_BIN = "/nix/var/nix/profiles/default/bin"
NIX_ENV = {"HOME": "/root", "USER": "root"}
SYSTEMCTL = "/usr/bin/systemctl"
PROFILE_ROOT = "/nix/var/nix/profiles/barectl"


def emit(text: str) -> None:
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def native(argv: list[str], *, timeout: int = 600) -> str:
    environment = {**os.environ, **NIX_ENV}
    process = subprocess.run(  # noqa: S603 - fixed native argv from the reviewed convention
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=environment,
    )
    if process.returncode:
        raise ValueError("A native command failed.")
    return process.stdout


def report(outcome: str, reason: str = "") -> None:
    value = {"class": outcome}
    if reason:
        value["reason"] = reason
    emit("barectl-result " + json.dumps(value))


def progress(value: str) -> None:
    emit("barectl-stage " + value)


def default_usage(entry: str, kind: str, current: dict[str, object]) -> str:
    family = "php" if kind == "php" else "node"
    if current.get(family) == entry:
        return f"the server default {family.upper()} commands"
    problem = current.get(family + "_problem")
    if isinstance(problem, str) and problem:
        return f"the server default {family.upper()} commands ({problem})"
    return ""


def node_usage(entry: str) -> str:
    for path in pathlib.Path("/var/www").glob("*/bin/node"):
        try:
            if os.readlink(path) == f"{PROFILE_ROOT}/{entry}/bin/node":
                return f"site {path.parent.parent.name}"
        except OSError:
            continue
    return ""


def php_usage(entry: str) -> str:
    for path in pathlib.Path("/var/www").glob("*/bin/php"):
        try:
            contents = path.read_text(encoding="utf-8", errors="strict")
        except OSError, UnicodeError:
            continue
        if f"{PROFILE_ROOT}/{entry}/bin/php" in contents:
            return f"site {path.parent.parent.name}"
    for directory in pathlib.Path("/etc/php-fpm/sites").glob(f"*/{entry}"):
        return f"site {directory.parent.name}"
    for pool in pathlib.Path(f"/etc/php-fpm/{entry}/pools").glob("*.conf"):
        if pool.name != "diagnostic.conf":
            return f"site {pool.stem}"
    units = native(
        [
            "systemctl",
            "list-unit-files",
            f"php-fpm-site-{entry}@*.service",
            "--no-legend",
            "--plain",
        ]
    )
    for line in units.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1].startswith("enabled"):
            return "a site PHP service"
    return ""


def owned_directory(path: pathlib.Path) -> bool:
    try:
        value = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(value.st_mode)
        and value.st_uid == 0
        and stat.S_IMODE(value.st_mode) & 0o022 == 0
    )


def matches(path: pathlib.Path, expected: bytes) -> bool:
    try:
        value = path.lstat()
        return stat.S_ISREG(value.st_mode) and value.st_uid == 0 and path.read_bytes() == expected
    except OSError:
        return False


def checked_configuration(entry: str, ini: bytes, master: bytes, pool: bytes) -> pathlib.Path:
    base = pathlib.Path(f"/etc/php-fpm/{entry}")
    if not owned_directory(base):
        raise ValueError("The runtime configuration is not the supported root-owned directory.")
    if sorted(path.name for path in base.iterdir()) != ["php-fpm.conf", "php.ini", "pools"]:
        raise ValueError("The runtime configuration holds an unexpected entry.")
    pools = base / "pools"
    if not owned_directory(pools) or sorted(path.name for path in pools.iterdir()) != [
        "diagnostic.conf"
    ]:
        raise ValueError("The runtime's pools hold an unexpected entry.")
    for path, expected in (
        (base / "php.ini", ini),
        (base / "php-fpm.conf", master),
        (pools / "diagnostic.conf", pool),
    ):
        if not matches(path, expected):
            raise ValueError("The runtime configuration differs from the reviewed build.")
    return base


def stop_service(entry: str) -> None:
    unit = f"php-fpm@{entry}.service"
    shown = subprocess.run(  # noqa: S603 - a fixed unit query
        [SYSTEMCTL, "show", unit, "-p", "LoadState", "-p", "ActiveState"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    values = dict(line.split("=", 1) for line in shown.stdout.splitlines() if "=" in line)
    if values.get("LoadState") in ("", "not-found"):
        return
    if values.get("ActiveState") in ("active", "activating", "deactivating"):
        native([SYSTEMCTL, "stop", unit], timeout=340)
    subprocess.run(  # noqa: S603 - disabling a not-found instance exits nonzero harmlessly
        [SYSTEMCTL, "--no-reload", "disable", unit],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )


def remove_files(base: pathlib.Path) -> None:
    (base / "pools" / "diagnostic.conf").unlink(missing_ok=True)
    (base / "php.ini").unlink(missing_ok=True)
    (base / "php-fpm.conf").unlink(missing_ok=True)
    (base / "pools").rmdir()
    base.rmdir()


def remove_profile(entry: str) -> None:
    profile = pathlib.Path(f"{PROFILE_ROOT}/{entry}")
    for link in pathlib.Path(PROFILE_ROOT).glob(f"{entry}-*-link"):
        if link.is_symlink():
            link.unlink()
    if profile.is_symlink():
        profile.unlink()
    elif profile.exists():
        raise ValueError("The runtime profile is not a link Barectl owns.")


def service_active(entry: str) -> bool:
    active = subprocess.run(  # noqa: S603 - a fixed unit query
        [SYSTEMCTL, "is-active", f"php-fpm@{entry}.service"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    ).stdout.strip()
    return active == "active"


def collect_store() -> None:
    subprocess.run(  # noqa: S603 - the fixed Nix garbage collector
        [NIX_BIN + "/nix-store", "--gc"],
        stdin=subprocess.DEVNULL,
        env={**os.environ, **NIX_ENV},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=900,
        check=True,
    )


def main(argv: list[str]) -> None:  # noqa: C901 - one reviewed removal
    if len(argv) != 8:
        sys.stderr.write("Runtime removal received an invalid argument set.\n")
        report("refused", "evidence")
        return
    entry, kind, path, generation, _digest, ini64, master64, pool64 = argv
    ini = base64.b64decode(ini64) if ini64 else b""
    master = base64.b64decode(master64) if master64 else b""
    pool = base64.b64decode(pool64) if pool64 else b""
    try:
        current = json.load(sys.stdin)
    except ValueError:
        report("refused", "defaults_unreadable")
        return
    if not isinstance(current, dict):
        report("refused", "defaults_unreadable")
        return
    progress("preflight")
    profile = pathlib.Path(f"{PROFILE_ROOT}/{entry}")
    if os.path.realpath(profile) != path:
        sys.stderr.write("The runtime profile no longer resolves to the reviewed build.\n")
        report("refused", "evidence")
        return
    if (os.readlink(profile) if profile.is_symlink() else "") != generation:
        sys.stderr.write("The runtime profile generation changed before removal.\n")
        report("refused", "evidence")
        return
    try:
        usage = default_usage(entry, kind, current) or (
            php_usage(entry) if kind == "php" else node_usage(entry)
        )
        base = checked_configuration(entry, ini, master, pool) if kind == "php" else None
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        sys.stderr.write(
            "Runtime removal preflight stopped ("
            + type(error).__name__
            + "): "
            + str(error)[:500]
            + "\n"
        )
        report("refused", "evidence")
        return
    if usage:
        sys.stderr.write("The runtime is still in use: " + usage + "\n")
        report("refused", "runtime_in_use")
        return
    changed = False
    try:
        progress("services")
        changed = True
        if kind == "php":
            stop_service(entry)
        progress("configuration")
        if base is not None:
            remove_files(base)
        progress("profile")
        remove_profile(entry)
        progress("collect")
        try:
            collect_store()
        except OSError, subprocess.SubprocessError:
            sys.stderr.write(
                "Garbage collection did not finish; removed paths stay until it runs.\n"
            )
        progress("verify")
        if os.path.lexists(profile) or (base is not None and os.path.lexists(base)):
            raise ValueError("The runtime's native artifacts remain.")
        if kind == "php" and service_active(entry):
            raise ValueError("The runtime's master is still active.")
        report("succeeded")
    except ValueError, OSError, subprocess.SubprocessError:
        report("partial" if changed else "refused", "runtime_config")


main(sys.argv[1:])
