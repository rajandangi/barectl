"""Publish the reviewed per-site logrotate file, after logrotate itself accepts it.

A standalone body: it shares no code with the site observation read, so a change to it never
invalidates a recorded transcript. The reviewed text is re-rendered here before publication
and ``logrotate --debug`` must accept it.
"""

import json
import os
import pathlib
import re
import stat
import subprocess
import sys

LOGROTATE_DIRECTORY = "/etc/logrotate.d"
LOGROTATE_PHP_FILES = ("php-error.log", "php-slow.log")
LOGROTATE_KNOWN_FILES = (*LOGROTATE_PHP_FILES, "wp-debug.log")
LOGROTATE_HEADER = (
    "# Barectl rotates this site's own log files. Do not edit: anything outside this\n"
    "# file's supported shape is reported, and the reviewed Log rotation action restores it.\n"
    "# The log directory is caddy:site 0750, so root renames and recreates the files with\n"
    "# the site's ownership; the site account cannot rename inside its own log directory.\n"
)


def logrotate_directory(identifier: str) -> str:
    return f"/var/www/{identifier}/logs"


def logrotate_file(identifier: str) -> str:
    return f"{LOGROTATE_DIRECTORY}/barectl-site-{identifier}"


def logrotate_render(identifier: str, names: tuple[str, ...]) -> str:
    if not names or any(name not in LOGROTATE_KNOWN_FILES for name in names):
        raise ValueError("Not a supported set of site log files.")
    ordered = tuple(name for name in LOGROTATE_KNOWN_FILES if name in names)
    account = "s" + identifier
    rotated = " ".join(f"{logrotate_directory(identifier)}/{name}" for name in ordered)
    return (
        LOGROTATE_HEADER
        + rotated
        + " {\n"
        + "    daily\n"
        + "    maxsize 20M\n"
        + "    rotate 5\n"
        + "    maxage 14\n"
        + "    compress\n"
        + "    delaycompress\n"
        + "    missingok\n"
        + "    notifempty\n"
        + f"    create 0640 {account} {account}\n"
        + "}\n"
    )


def result(outcome: str, reason: str = "") -> None:
    value = {"class": outcome}
    if reason:
        value["reason"] = reason
    sys.stdout.write("barectl-result " + json.dumps(value) + "\n")
    sys.stdout.flush()


def stage(value: str) -> None:
    sys.stdout.write("barectl-stage " + value + "\n")
    sys.stdout.flush()


def run(argv: list[str]) -> None:
    process = subprocess.run(  # noqa: S603 - fixed native argv
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if process.returncode:
        raise ValueError("logrotate refused the file.")


def write_new(path: str, contents: str, mode: int) -> None:
    parent = pathlib.Path(path).parent
    if parent.stat().st_uid != 0 or stat.S_IMODE(parent.stat().st_mode) & 0o022:
        raise ValueError("Unsafe publication directory.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "w") as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(path, mode)
    except BaseException:
        pathlib.Path(path).unlink(missing_ok=True)
        raise


def install_rotation(document: dict[str, object]) -> None:
    """Publish exactly the reviewed file, validated by ``logrotate --debug`` first."""
    identifier = document.get("identifier")
    names = document.get("files")
    expected = document.get("rotation")
    if (
        not isinstance(identifier, str)
        or re.fullmatch(r"[a-z][a-z0-9]{2,23}", identifier) is None
        or not isinstance(names, list)
        or not all(isinstance(name, str) for name in names)
        or not isinstance(expected, str)
        or expected != logrotate_render(identifier, tuple(names))
    ):
        result("refused", "evidence")
        return
    stage("preflight")
    binary = next(
        (
            path
            for path in ("/usr/sbin/logrotate", "/usr/bin/logrotate")
            if pathlib.Path(path).is_file()
        ),
        "",
    )
    if not binary or not pathlib.Path(LOGROTATE_DIRECTORY).is_dir():
        result("refused", "logrotate_missing")
        return
    path = logrotate_file(identifier)
    try:
        previous = pathlib.Path(path).read_text() if pathlib.Path(path).is_file() else None
    except OSError:
        previous = None
    candidate = f"/run/barectl-logrotate-{identifier}.conf"
    try:
        pathlib.Path(candidate).unlink(missing_ok=True)
        write_new(candidate, expected, 0o600)
        run([binary, "--debug", candidate])
    except ValueError, OSError:
        pathlib.Path(candidate).unlink(missing_ok=True)
        result("refused", "rotation_invalid")
        return
    pathlib.Path(candidate).unlink(missing_ok=True)
    stage("publish")
    temporary = f"{LOGROTATE_DIRECTORY}/.barectl-site-{identifier}"
    try:
        pathlib.Path(temporary).unlink(missing_ok=True)
        write_new(temporary, expected, 0o644)
        os.replace(temporary, path)
    except ValueError, OSError:
        pathlib.Path(temporary).unlink(missing_ok=True)
        result("refused", "evidence")
        return
    stage("verify")
    try:
        run([binary, "--debug", path])
    except ValueError, OSError:
        if previous is None:
            pathlib.Path(path).unlink(missing_ok=True)
        else:
            pathlib.Path(temporary).unlink(missing_ok=True)
            write_new(temporary, previous, 0o644)
            os.replace(temporary, path)
        result("refused", "rotation_invalid")
        return
    result("succeeded")


if __name__ == "__main__":
    install_rotation(json.loads(sys.argv[1]))
