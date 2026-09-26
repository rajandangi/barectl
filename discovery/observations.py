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
FILESYSTEM_PATH = "/"
ARCH_PATTERN = re.compile(r"[A-Za-z0-9_.-]+")
MAX_ARCH_LENGTH = 100
MAX_CPU_COUNT = 1_000_000


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
        result = shell.run(f"cat {path}")
        if result.truncated:
            return OsRelease(
                ObservationStatus.UNSUPPORTED,
                source=path,
                warning=f"{path} is larger than an os-release file should be. It was not read.",
            )
        if result.exit_status == 0:
            return _parse_os_release(path, result.stdout)
        # Error text depends on the server's locale, so ask the shell instead.
        if shell.run(f"test -e {path}").exit_status != 0:
            continue
        if shell.run(f"test -r {path}").exit_status != 0:
            return OsRelease(
                ObservationStatus.INACCESSIBLE,
                source=path,
                warning=f"The SSH user cannot read {path}. Barectl does not use sudo.",
            )
        return OsRelease(
            ObservationStatus.UNSUPPORTED, source=path, warning=f"{path} could not be read."
        )
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
    path: str = ""
    size_bytes: int | None = None
    avail_bytes: int | None = None
    source: str = FILESYSTEM_COMMAND
    warning: str = ""


def collect_architecture(shell: RemoteShell) -> Architecture:
    result = shell.run(ARCH_COMMAND)
    if result.truncated:
        return Architecture(
            ObservationStatus.UNSUPPORTED,
            warning=f"{ARCH_COMMAND} wrote more output than expected. It was not read.",
        )
    if result.exit_status != 0:
        return Architecture(
            ObservationStatus.UNSUPPORTED,
            warning=f"{ARCH_COMMAND} could not be read.",
        )
    value = result.stdout.strip()
    if (
        not value
        or "\n" in value
        or " " in value
        or len(value) > MAX_ARCH_LENGTH
        or not value.isprintable()
        or ARCH_PATTERN.fullmatch(value) is None
    ):
        return Architecture(
            ObservationStatus.UNSUPPORTED,
            warning=f"{ARCH_COMMAND} did not report the architecture in a supported format.",
        )
    return Architecture(ObservationStatus.OBSERVED, value=value)


def collect_cpu_count(shell: RemoteShell) -> CpuCount:
    result = shell.run(CPU_COMMAND)
    if result.truncated:
        return CpuCount(
            ObservationStatus.UNSUPPORTED,
            warning=f"{CPU_COMMAND} wrote more output than expected. It was not read.",
        )
    if result.exit_status != 0:
        return CpuCount(
            ObservationStatus.UNSUPPORTED,
            warning=f"{CPU_COMMAND} could not be read.",
        )
    text = result.stdout.strip()
    if not text.isascii() or not text.isdigit():
        return CpuCount(
            ObservationStatus.UNSUPPORTED,
            warning=f"{CPU_COMMAND} did not report the CPU count in a supported format.",
        )
    try:
        count = int(text)
    except ValueError:
        return CpuCount(
            ObservationStatus.UNSUPPORTED,
            warning=f"{CPU_COMMAND} did not report the CPU count in a supported format.",
        )
    if count < 1 or count > MAX_CPU_COUNT:
        return CpuCount(
            ObservationStatus.UNSUPPORTED,
            warning=f"{CPU_COMMAND} did not report the CPU count in a supported format.",
        )
    return CpuCount(ObservationStatus.OBSERVED, count=count)


def collect_memory(shell: RemoteShell) -> Memory:
    result = shell.run(f"cat {MEMINFO_PATH}")
    if result.truncated:
        return Memory(
            ObservationStatus.UNSUPPORTED,
            warning=f"{MEMINFO_PATH} is larger than expected. It was not read.",
        )
    if result.exit_status == 0:
        return _parse_meminfo(result.stdout)
    # Error text depends on the server's locale, so ask the shell instead.
    if shell.run(f"test -e {MEMINFO_PATH}").exit_status != 0:
        return Memory(
            ObservationStatus.ABSENT,
            warning=f"The server has no {MEMINFO_PATH}.",
        )
    if shell.run(f"test -r {MEMINFO_PATH}").exit_status != 0:
        return Memory(
            ObservationStatus.INACCESSIBLE,
            warning=f"The SSH user cannot read {MEMINFO_PATH}. Barectl does not use sudo.",
        )
    return Memory(
        ObservationStatus.UNSUPPORTED,
        warning=f"{MEMINFO_PATH} could not be read.",
    )


def _parse_meminfo(text: str) -> Memory:
    for line in text.splitlines():
        name, _, rest = line.strip().partition(":")
        if name != "MemTotal":
            continue
        parts = rest.split()
        if len(parts) != 2 or parts[1] != "kB" or not parts[0].isdigit():
            return Memory(
                ObservationStatus.UNSUPPORTED,
                warning=f"{MEMINFO_PATH} did not report memory in a supported format.",
            )
        kilobytes = int(parts[0])
        if kilobytes < 1:
            return Memory(
                ObservationStatus.UNSUPPORTED,
                warning=f"{MEMINFO_PATH} did not report memory in a supported format.",
            )
        return Memory(ObservationStatus.OBSERVED, total_bytes=kilobytes * 1024)
    return Memory(
        ObservationStatus.UNSUPPORTED,
        warning=f"{MEMINFO_PATH} did not report memory in a supported format.",
    )


def collect_filesystem(shell: RemoteShell) -> Filesystem:
    result = shell.run(FILESYSTEM_COMMAND)
    if result.truncated:
        return Filesystem(
            ObservationStatus.UNSUPPORTED,
            warning=f"{FILESYSTEM_COMMAND} wrote more output than expected. It was not read.",
        )
    if result.exit_status != 0:
        return Filesystem(
            ObservationStatus.UNSUPPORTED,
            warning=f"{FILESYSTEM_COMMAND} could not be read.",
        )
    return _parse_filesystem(result.stdout)


def _unsupported_filesystem() -> Filesystem:
    return Filesystem(
        ObservationStatus.UNSUPPORTED,
        warning="The root filesystem capacity was not reported in a supported format.",
    )


def _parse_filesystem(text: str) -> Filesystem:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) < 2:
        return _unsupported_filesystem()
    # The first line is a header; the first data line describes the root filesystem.
    parts = lines[1].split()
    if len(parts) != 3 or parts[2] != FILESYSTEM_PATH:
        return _unsupported_filesystem()
    if not parts[0].isdigit() or not parts[1].isdigit():
        return _unsupported_filesystem()
    size_bytes = int(parts[0])
    avail_bytes = int(parts[1])
    if size_bytes < 1 or avail_bytes < 0 or avail_bytes > size_bytes:
        return _unsupported_filesystem()
    return Filesystem(
        ObservationStatus.OBSERVED,
        path=FILESYSTEM_PATH,
        size_bytes=size_bytes,
        avail_bytes=avail_bytes,
    )
