"""Publish the reviewed journald log retention policy (#551).

docs/adr/0044-own-journald-log-retention-in-a-separate-drop-in.md. The reviewed document
carries the chosen pair, the rendered file and the previous file or its absence. This body
proves the preimage, writes the drop-in atomically as root:root 0644, refuses a later
drop-in override, restarts journald and reads both effective values back. A failure after
the write restores the previous file or removes the new one. It never deletes a journal
file and never runs a vacuum command.
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
from typing import Final

DIRECTORY: Final = pathlib.Path("/etc/systemd/journald.conf.d")
PATH: Final = DIRECTORY / "60-barectl-log-retention.conf"
SYSTEMD_ANALYZE: Final = "/usr/bin/systemd-analyze"
SYSTEMCTL: Final = "/usr/bin/systemctl"
SERVICE: Final = "systemd-journald.service"
MAX_TEXT: Final = 4096
ROOT_UID: Final = 0
ROOT_GID: Final = 0
DISK_CAP_CHOICES: Final = ("250M", "500M", "1G", "2G", "4G")
MAX_AGE_CHOICES: Final = ("1week", "1month", "3months", "6months", "1year")
_VALUE = re.compile(r"[A-Za-z0-9.%:+-]{0,32}")


def render(disk_cap: str, max_age: str) -> str:
    if disk_cap not in DISK_CAP_CHOICES:
        raise ValueError("The disk cap is not one of the supported choices.")
    if max_age not in MAX_AGE_CHOICES:
        raise ValueError("The maximum age is not one of the supported choices.")
    return f"[Journal]\nSystemMaxUse={disk_cap}\nMaxRetentionSec={max_age}\n"


def result(kind: str, reason: str = "") -> None:
    line = {"class": kind}
    if reason:
        line["reason"] = reason
    sys.stdout.write("barectl-result " + json.dumps(line) + "\n")
    sys.stdout.flush()


def stage(name: str) -> None:
    sys.stdout.write("barectl-stage " + name + "\n")
    sys.stdout.flush()


def run(argv: list[str]) -> str:
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
    if process.returncode or len(stdout) > 1048576 or len(stderr) > 1048576:
        raise ValueError("The native command failed or exceeded its bound.")
    return stdout


def merged() -> tuple[str, str]:
    """Both effective values from the merged journald configuration, last assignment wins."""
    text = run([SYSTEMD_ANALYZE, "cat-config", "systemd/journald.conf"])
    found = {"SystemMaxUse": "", "MaxRetentionSec": ""}
    for line in text.splitlines():
        for key in found:
            if line.startswith(key + "="):
                found[key] = line[len(key) + 1 :]
    return found["SystemMaxUse"], found["MaxRetentionSec"]


def restart() -> None:
    run([SYSTEMCTL, "restart", SERVICE])
    if run([SYSTEMCTL, "is-active", SERVICE]).strip() != "active":
        raise ValueError("The journal service is not active.")


def safe_directory(*, create: bool = True) -> None:
    """Require a root-owned private drop-in directory, creating it when asked."""
    try:
        info = DIRECTORY.lstat()
    except FileNotFoundError:
        if not create:
            return
        os.mkdir(DIRECTORY, 0o755)
        info = DIRECTORY.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != ROOT_UID
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise ValueError("The journald drop-in directory is not safe to use.")


def read_previous() -> str | None:
    """The current file's exact content, ``None`` when it is absent."""
    try:
        info = PATH.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != ROOT_UID
        or stat.S_IMODE(info.st_mode) != 0o644
        or info.st_nlink != 1
    ):
        raise ValueError("The retention file is not a root-owned 0644 regular file.")
    text = PATH.read_text()
    if len(text.encode()) > MAX_TEXT:
        raise ValueError("The retention file exceeds its bound.")
    return text


def write_atomic(text: str) -> None:
    descriptor, name = tempfile.mkstemp(prefix=".barectl-retention-", dir=str(DIRECTORY))
    try:
        with os.fdopen(descriptor, "w") as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o644)
            os.fchown(output.fileno(), ROOT_UID, ROOT_GID)
        os.replace(name, PATH)
    except BaseException:
        pathlib.Path(name).unlink(missing_ok=True)
        raise


def restore(previous: str | None) -> bool:
    """Put the previous file back, or remove a file this run created, then restart."""
    try:
        if previous is None:
            PATH.unlink(missing_ok=True)
        else:
            write_atomic(previous)
        restart()
        return read_previous() == previous
    except ValueError, OSError, subprocess.TimeoutExpired:
        return False


def decode(argv: list[str]) -> tuple[str, str, str, str | None, tuple[str, str]] | None:
    """The reviewed pair, its rendered file, the previous file and its effective values."""
    if len(argv) != 1:
        return None
    try:
        value = json.loads(gzip.decompress(base64.b64decode(argv[0])))
    except ValueError, OSError:
        return None
    expected = {
        "disk_cap",
        "max_age",
        "retention",
        "previous",
        "previous_disk_cap",
        "previous_max_age",
    }
    if not isinstance(value, dict) or set(value) != expected:
        return None
    disk_cap, max_age = value.get("disk_cap"), value.get("max_age")
    retention, previous = value.get("retention"), value.get("previous")
    previous_disk_cap, previous_max_age = (
        value.get("previous_disk_cap"),
        value.get("previous_max_age"),
    )
    if (
        disk_cap not in DISK_CAP_CHOICES
        or max_age not in MAX_AGE_CHOICES
        or not isinstance(retention, str)
        or retention != render(str(disk_cap), str(max_age))
        or (
            previous is not None
            and (
                not isinstance(previous, str)
                or len(previous.encode()) > MAX_TEXT
                or not any(
                    previous == render(cap, age)
                    for cap in DISK_CAP_CHOICES
                    for age in MAX_AGE_CHOICES
                )
            )
        )
        or not isinstance(previous_disk_cap, str)
        or not isinstance(previous_max_age, str)
        or _VALUE.fullmatch(previous_disk_cap) is None
        or _VALUE.fullmatch(previous_max_age) is None
    ):
        return None
    return (
        str(disk_cap),
        str(max_age),
        retention,
        previous,
        (previous_disk_cap, previous_max_age),
    )


def main(argv: list[str]) -> int:
    reviewed = decode(argv)
    if reviewed is None:
        result("refused", "evidence")
        return 0
    disk_cap, max_age, retention, previous, previous_effective = reviewed
    stage("preflight")
    try:
        safe_directory(create=False)
        if read_previous() != previous or merged() != previous_effective:
            result("refused", "precondition")
            return 0
    except ValueError, OSError, subprocess.TimeoutExpired:
        result("refused", "evidence")
        return 0
    stage("publish")
    try:
        safe_directory()
        write_atomic(retention)
        if merged() != (disk_cap, max_age):
            raise ValueError("A later drop-in overrides the reviewed pair.")
        stage("verify")
        restart()
        if merged() != (disk_cap, max_age):
            raise ValueError("The effective values do not match the review.")
    except ValueError, OSError, subprocess.TimeoutExpired:
        if restore(previous):
            result("refused", "journal_retention")
        else:
            result("partial", "journal_retention")
        return 0
    result("succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
