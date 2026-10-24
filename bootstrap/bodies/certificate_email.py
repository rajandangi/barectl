"""Publish Caddy's main configuration with the reviewed certificate contact email (#444).

docs/tls.md#certificate-contact-email. The reviewed document carries the whole previous
and candidate files; this body proves the preimage, validates the candidate with the
pinned Caddy binary, replaces it atomically, reloads Caddy and proves the running
configuration equals the file. A failed reload or verification restores the previous file.
"""

import base64
import gzip
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
from contextlib import suppress
from typing import Final

MAIN: Final = pathlib.Path("/etc/caddy/Caddyfile")
ADMIN: Final = "unix//run/caddy/admin.sock"
CADDY: Final = pathlib.Path("/nix/var/nix/profiles/barectl/caddy/bin/caddy")
MAX_TEXT: Final = 8192
EMAIL: Final = re.compile(
    r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
)


def result(kind: str, reason: str = "") -> None:
    line = {"class": kind}
    if reason:
        line["reason"] = reason
    sys.stdout.write("barectl-result " + json.dumps(line) + "\n")
    sys.stdout.flush()


def stage(name: str) -> None:
    sys.stdout.write("barectl-stage " + name + "\n")
    sys.stdout.flush()


def run(argv: list[str], *, check: bool = True) -> str:
    process = subprocess.Popen(  # noqa: S603 - fixed native argv
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise ValueError("The native command timed out.") from None
    if len(stdout) > 1048576 or len(stderr) > 1048576 or (check and process.returncode):
        raise ValueError("The native command failed or exceeded its bound.")
    return stdout


def binary() -> str:
    target = os.path.realpath(CADDY)
    if not target.startswith("/nix/store/") or not target.endswith("/bin/caddy"):
        raise ValueError("Caddy's profile is not the pinned catalog build.")
    return target


def safe(path: pathlib.Path) -> bool:
    try:
        info, parent = path.lstat(), path.parent.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == 0
        and stat.S_IMODE(info.st_mode) == 0o644
        and info.st_nlink == 1
        and stat.S_ISDIR(parent.st_mode)
        and parent.st_uid == 0
        and not parent.st_mode & 0o022
    )


def adapt(path: pathlib.Path = MAIN) -> object:
    return json.loads(run([binary(), "adapt", "--config", str(path), "--adapter", "caddyfile"]))


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


def reload() -> None:
    run(
        [
            binary(),
            "reload",
            "--config",
            str(MAIN),
            "--adapter",
            "caddyfile",
            "--address",
            ADMIN,
        ]
    )


def candidate_file(text: str) -> pathlib.Path:
    descriptor, name = tempfile.mkstemp(prefix=".Caddyfile-", suffix=".stage", dir=str(MAIN.parent))
    try:
        with os.fdopen(descriptor, "w") as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o644)
    except BaseException:
        pathlib.Path(name).unlink(missing_ok=True)
        raise
    return pathlib.Path(name)


def write_atomic(path: pathlib.Path, text: str) -> None:
    staged = candidate_file(text)
    try:
        os.replace(staged, path)
    finally:
        staged.unlink(missing_ok=True)


def restore(previous: str, old: object) -> bool:
    with suppress(ValueError, OSError):
        write_atomic(MAIN, previous)
        reload()
    with suppress(ValueError, OSError):
        return adapt() == old and running() == old and MAIN.read_text() == previous
    return False


def decode(argv: list[str]) -> tuple[str, str, str] | None:
    """The reviewed email, preimage and candidate from the one native argument."""
    if len(argv) != 1:
        return None
    try:
        value = json.loads(gzip.decompress(base64.b64decode(argv[0])))
    except ValueError, OSError:
        return None
    if not isinstance(value, dict) or set(value) != {"email", "previous", "caddy"}:
        return None
    email, previous, candidate = value["email"], value["previous"], value["caddy"]
    if (
        not isinstance(email, str)
        or (email and EMAIL.fullmatch(email) is None)
        or not isinstance(previous, str)
        or not isinstance(candidate, str)
        or len(previous.encode()) > MAX_TEXT
        or len(candidate.encode()) > MAX_TEXT
    ):
        return None
    return email, previous, candidate


def main(argv: list[str]) -> int:
    reviewed = decode(argv)
    if reviewed is None:
        result("refused", "evidence")
        return 0
    _email, previous, candidate = reviewed
    if not safe(MAIN):
        result("refused", "evidence")
        return 0
    stage("preflight")
    try:
        if MAIN.read_text() != previous:
            result("refused", "precondition")
            return 0
        old = running()
        if adapt() != old:
            result("refused", "evidence")
            return 0
        staged = candidate_file(candidate)
        try:
            run([binary(), "validate", "--config", str(staged), "--adapter", "caddyfile"])
        finally:
            staged.unlink(missing_ok=True)
        stage("caddy")
        if not safe(MAIN) or MAIN.read_text() != previous:
            result("refused", "precondition")
            return 0
        write_atomic(MAIN, candidate)
    except ValueError, OSError, subprocess.TimeoutExpired:
        result("refused", "certificate_email")
        return 0
    try:
        reload()
        stage("verify")
        if MAIN.read_text() != candidate or running() != adapt():
            raise ValueError("Caddy's running configuration differs from the file.")
    except ValueError, OSError, subprocess.TimeoutExpired:
        restore(previous, old)
        result("partial", "certificate_email")
        return 0
    result("succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
