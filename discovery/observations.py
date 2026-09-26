"""Read-only observations collected over a verified connection.

Every command here is a fixed string that only reads. None uses sudo, installs packages or
writes files. Only the fields Barectl displays are kept; raw remote output is discarded.
"""

import re
import shlex
from dataclasses import dataclass

from .models import ObservationStatus
from .ssh import RemoteShell

# The os-release specification: read /etc/os-release, falling back to /usr/lib/os-release.
# https://www.freedesktop.org/software/systemd/man/latest/os-release.html
OS_RELEASE_FILES = ("/etc/os-release", "/usr/lib/os-release")
OS_RELEASE_FIELDS = {"PRETTY_NAME": 200, "NAME": 200, "ID": 100, "VERSION_ID": 100}

# Capacity observations use only fixed read-only commands with the SSH user's own
# permissions. No sudo, no package installation, no writes. Maintainer sources, not
# Django endorsements:
# - uname -m: https://www.gnu.org/software/coreutils/manual/html_node/uname-invocation.html
# - nproc: https://www.gnu.org/software/coreutils/manual/html_node/nproc-invocation.html
# - /proc/meminfo MemTotal in kB: https://docs.kernel.org/filesystems/proc.html
# - df -B1 --output: https://www.gnu.org/software/coreutils/manual/html_node/df-invocation.html
ARCH_COMMAND = "uname -m"
CPU_COMMAND = "nproc"
MEMINFO_PATH = "/proc/meminfo"
FILESYSTEM_COMMAND = "df -B1 --output=size,avail,target /"
ARCH_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,100}")
# ASCII only: str.isdigit accepts characters such as "²" that int() rejects.
DIGITS = re.compile(r"[0-9]+")
MAX_CPU_COUNT = 1_000_000
# A POSIX shell exits 127 when a command is not found and 126 when it cannot run it.
# https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html#tag_19_08_02
COMMAND_NOT_FOUND = 127
COMMAND_NOT_EXECUTABLE = 126


@dataclass(frozen=True)
class _Failed:
    status: ObservationStatus
    warning: str


def _read_file(shell: RemoteShell, path: str) -> str | _Failed:
    """Return a remote file's contents, or why it could not be observed."""
    result = shell.run(f"cat {path}")
    if result.truncated:
        return _Failed(
            ObservationStatus.UNSUPPORTED, f"{path} is larger than expected. It was not read."
        )
    if result.exit_status == 0:
        return result.stdout
    # Error text depends on the server's locale, so ask the shell instead.
    if shell.run(f"test -e {path}").exit_status != 0:
        return _Failed(ObservationStatus.ABSENT, f"The server has no {path}.")
    if shell.run(f"test -r {path}").exit_status != 0:
        return _Failed(
            ObservationStatus.INACCESSIBLE,
            f"The SSH user cannot read {path}. Barectl does not use sudo.",
        )
    return _Failed(ObservationStatus.UNSUPPORTED, f"{path} could not be read.")


@dataclass(frozen=True)
class OsRelease:
    status: ObservationStatus
    source: str = ""
    fields: tuple[tuple[str, str], ...] = ()
    warning: str = ""

    def get(self, name: str) -> str:
        return dict(self.fields).get(name, "")


def collect_os_release(shell: RemoteShell) -> OsRelease:
    for path in OS_RELEASE_FILES:
        text = _read_file(shell, path)
        if not isinstance(text, _Failed):
            return _parse_os_release(path, text)
        if text.status != ObservationStatus.ABSENT:
            return OsRelease(text.status, source=path, warning=text.warning)
    return OsRelease(
        ObservationStatus.ABSENT,
        warning="The server has neither /etc/os-release nor /usr/lib/os-release.",
    )


def _parse_os_release(path: str, text: str) -> OsRelease:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        name, separator, raw = line.strip().partition("=")
        if not separator or name not in OS_RELEASE_FIELDS:
            continue
        try:
            # Values use shell quoting; shlex parses it without executing anything.
            words = shlex.split(raw, comments=False)
        except ValueError:
            continue
        value = " ".join(words).strip()
        if value and value.isprintable():
            fields[name] = value[: OS_RELEASE_FIELDS[name]]
    if not fields.keys() & {"PRETTY_NAME", "NAME", "ID"}:
        return OsRelease(
            ObservationStatus.UNSUPPORTED,
            source=path,
            warning=f"{path} does not identify the operating system in a supported format.",
        )
    return OsRelease(ObservationStatus.OBSERVED, source=path, fields=tuple(fields.items()))


@dataclass(frozen=True)
class Architecture:
    status: ObservationStatus
    value: str = ""
    source: str = ARCH_COMMAND
    warning: str = ""


@dataclass(frozen=True)
class CpuCount:
    status: ObservationStatus
    count: int | None = None
    source: str = CPU_COMMAND
    warning: str = ""


@dataclass(frozen=True)
class Memory:
    status: ObservationStatus
    total_bytes: int | None = None
    source: str = MEMINFO_PATH
    warning: str = ""


@dataclass(frozen=True)
class Filesystem:
    status: ObservationStatus
    size_bytes: int | None = None
    avail_bytes: int | None = None
    source: str = FILESYSTEM_COMMAND
    warning: str = ""


def _run(shell: RemoteShell, command: str) -> str | _Failed:
    """Return a fixed command's output, or why it could not be observed."""
    result = shell.run(command)
    if result.truncated:
        return _Failed(
            ObservationStatus.UNSUPPORTED,
            f"{command} wrote more output than expected. It was not read.",
        )
    program = command.split()[0]
    if result.exit_status == COMMAND_NOT_FOUND:
        return _Failed(ObservationStatus.ABSENT, f"The server has no {program} command.")
    if result.exit_status == COMMAND_NOT_EXECUTABLE:
        return _Failed(
            ObservationStatus.INACCESSIBLE,
            f"The SSH user cannot run {program}. Barectl does not use sudo.",
        )
    if result.exit_status != 0:
        return _Failed(ObservationStatus.UNSUPPORTED, f"{command} failed.")
    return result.stdout


def collect_architecture(shell: RemoteShell) -> Architecture:
    output = _run(shell, ARCH_COMMAND)
    if isinstance(output, _Failed):
        return Architecture(output.status, warning=output.warning)
    value = output.strip()
    if ARCH_PATTERN.fullmatch(value) is None:
        return Architecture(
            ObservationStatus.UNSUPPORTED,
            warning=f"{ARCH_COMMAND} did not report the architecture in a supported format.",
        )
    return Architecture(ObservationStatus.OBSERVED, value=value)


def collect_cpu_count(shell: RemoteShell) -> CpuCount:
    output = _run(shell, CPU_COMMAND)
    if isinstance(output, _Failed):
        return CpuCount(output.status, warning=output.warning)
    text = output.strip()
    count = int(text) if DIGITS.fullmatch(text) else 0
    if not 1 <= count <= MAX_CPU_COUNT:
        return CpuCount(
            ObservationStatus.UNSUPPORTED,
            warning=f"{CPU_COMMAND} did not report the CPU count in a supported format.",
        )
    return CpuCount(ObservationStatus.OBSERVED, count=count)


def collect_memory(shell: RemoteShell) -> Memory:
    text = _read_file(shell, MEMINFO_PATH)
    if isinstance(text, _Failed):
        return Memory(text.status, warning=text.warning)
    for line in text.splitlines():
        name, _, rest = line.strip().partition(":")
        if name != "MemTotal":
            continue
        parts = rest.split()
        if len(parts) == 2 and parts[1] == "kB" and DIGITS.fullmatch(parts[0]):
            kilobytes = int(parts[0])
            if kilobytes > 0:
                return Memory(ObservationStatus.OBSERVED, total_bytes=kilobytes * 1024)
        break
    return Memory(
        ObservationStatus.UNSUPPORTED,
        warning=f"{MEMINFO_PATH} did not report memory in a supported format.",
    )


def collect_filesystem(shell: RemoteShell) -> Filesystem:
    output = _run(shell, FILESYSTEM_COMMAND)
    if isinstance(output, _Failed):
        return Filesystem(output.status, warning=output.warning)
    lines = [line.split() for line in output.splitlines() if line.strip()]
    # The first line is a header; the second describes the root filesystem.
    if len(lines) >= 2 and len(lines[1]) == 3 and lines[1][2] == "/":
        size, avail, _ = lines[1]
        if DIGITS.fullmatch(size) and DIGITS.fullmatch(avail):
            size_bytes, avail_bytes = int(size), int(avail)
            # A full filesystem has no available space, but it always has a size.
            if size_bytes > 0 and avail_bytes <= size_bytes:
                return Filesystem(
                    ObservationStatus.OBSERVED, size_bytes=size_bytes, avail_bytes=avail_bytes
                )
    return Filesystem(
        ObservationStatus.UNSUPPORTED,
        warning="The root filesystem capacity was not reported in a supported format.",
    )
