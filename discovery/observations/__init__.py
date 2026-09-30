"""Read-only observations (docs/ssh-connections.md#bounds-and-read-only-commands)."""

import re
import shlex

from ..models import ObservationOutcome, WebStackComponent
from ..snapshot import CollectedSnapshot, FilesystemSize, Observation, OsRelease
from ..ssh import RemoteShell
from .components import _collect_web_stack
from .configuration import _collect_nginx_sites, _collect_php_pools
from .databases import collect_databases
from .probes import _Failed, _read_file, _run
from .sites import _collect_sites

__all__ = ["collect"]

OS_RELEASE_FILES = ("/etc/os-release", "/usr/lib/os-release")
OS_RELEASE_FIELDS = {"PRETTY_NAME": 200, "NAME": 200, "ID": 100, "VERSION_ID": 100}

ARCH_COMMAND = "uname -m"
CPU_COMMAND = "nproc"
MEMINFO_PATH = "/proc/meminfo"
FILESYSTEM_COMMAND = "df -B1 --output=size,avail,target /"
ARCH_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,100}")
# ASCII only: str.isdigit accepts characters such as "²" that int() rejects.
DIGITS = re.compile(r"[0-9]+")
MAX_CPU_COUNT = 1_000_000


def collect(shell: RemoteShell) -> CollectedSnapshot:
    """docs/adr/0001-configuration-observations-depend-on-package-observation.md"""
    os_release = _collect_os_release(shell)
    architecture = _collect_architecture(shell)
    cpu_count = _collect_cpu_count(shell)
    memory_bytes = _collect_memory(shell)
    filesystem = _collect_filesystem(shell)
    components = _collect_web_stack(shell)
    by_component = {observed.component: observed for observed in components}
    nginx = by_component[WebStackComponent.NGINX]
    php = by_component[WebStackComponent.PHP_FPM]
    enabled = _collect_nginx_sites(shell, nginx)
    pools = _collect_php_pools(shell, php)
    return CollectedSnapshot(
        os=os_release,
        architecture=architecture,
        cpu_count=cpu_count,
        memory_bytes=memory_bytes,
        filesystem=filesystem,
        components=components,
        nginx_site_files=enabled.observation,
        php_fpm_pools=pools.observation,
        sites=collect_databases(
            shell,
            os_release,
            components,
            _collect_sites(shell, os_release, nginx, php, enabled, pools),
        ),
    )


def _collect_os_release(shell: RemoteShell) -> Observation[OsRelease | None]:
    for path in OS_RELEASE_FILES:
        text = _read_file(shell, path)
        if not isinstance(text, _Failed):
            return _parse_os_release(path, text)
        if not text.missing:
            return Observation(text.status, (path,), text.warning, None)
    return Observation(
        ObservationOutcome.UNSUPPORTED,
        (),
        "The server has neither /etc/os-release nor /usr/lib/os-release, so Barectl "
        "cannot identify the operating system.",
        None,
    )


def _parse_os_release(path: str, text: str) -> Observation[OsRelease | None]:
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
        return Observation(
            ObservationOutcome.UNSUPPORTED,
            (path,),
            f"{path} does not identify the operating system in a supported format.",
            None,
        )
    release = OsRelease(
        fields.get("PRETTY_NAME", ""),
        fields.get("NAME", ""),
        fields.get("ID", ""),
        fields.get("VERSION_ID", ""),
    )
    return Observation(ObservationOutcome.OBSERVED, (path,), "", release)


def _collect_architecture(shell: RemoteShell) -> Observation[str | None]:
    output = _run(shell, ARCH_COMMAND)
    if isinstance(output, _Failed):
        return Observation(output.status, (ARCH_COMMAND,), output.warning, None)
    value = output.strip()
    if ARCH_PATTERN.fullmatch(value) is None:
        return Observation(
            ObservationOutcome.UNSUPPORTED,
            (ARCH_COMMAND,),
            f"{ARCH_COMMAND} did not report the architecture in a supported format.",
            None,
        )
    return Observation(ObservationOutcome.OBSERVED, (ARCH_COMMAND,), "", value)


def _collect_cpu_count(shell: RemoteShell) -> Observation[int | None]:
    output = _run(shell, CPU_COMMAND)
    if isinstance(output, _Failed):
        return Observation(output.status, (CPU_COMMAND,), output.warning, None)
    text = output.strip()
    count = int(text) if DIGITS.fullmatch(text) else 0
    if not 1 <= count <= MAX_CPU_COUNT:
        return Observation(
            ObservationOutcome.UNSUPPORTED,
            (CPU_COMMAND,),
            f"{CPU_COMMAND} did not report the CPU count in a supported format.",
            None,
        )
    return Observation(ObservationOutcome.OBSERVED, (CPU_COMMAND,), "", count)


def _collect_memory(shell: RemoteShell) -> Observation[int | None]:
    text = _read_file(shell, MEMINFO_PATH)
    if isinstance(text, _Failed) and text.missing:
        return Observation(
            text.status,
            (MEMINFO_PATH,),
            f"The server has no {MEMINFO_PATH}, so Barectl cannot report memory.",
            None,
        )
    if isinstance(text, _Failed):
        return Observation(text.status, (MEMINFO_PATH,), text.warning, None)
    for line in text.splitlines():
        name, _, rest = line.strip().partition(":")
        if name != "MemTotal":
            continue
        parts = rest.split()
        if len(parts) == 2 and parts[1] == "kB" and DIGITS.fullmatch(parts[0]):
            kilobytes = int(parts[0])
            if kilobytes > 0:
                return Observation(
                    ObservationOutcome.OBSERVED, (MEMINFO_PATH,), "", kilobytes * 1024
                )
        break
    return Observation(
        ObservationOutcome.UNSUPPORTED,
        (MEMINFO_PATH,),
        f"{MEMINFO_PATH} did not report memory in a supported format.",
        None,
    )


def _collect_filesystem(shell: RemoteShell) -> Observation[FilesystemSize | None]:
    output = _run(shell, FILESYSTEM_COMMAND)
    if isinstance(output, _Failed):
        return Observation(output.status, (FILESYSTEM_COMMAND,), output.warning, None)
    lines = [line.split() for line in output.splitlines() if line.strip()]
    # The first line is a header; the second describes the root filesystem.
    if len(lines) >= 2 and len(lines[1]) == 3 and lines[1][2] == "/":
        size, avail, _ = lines[1]
        if DIGITS.fullmatch(size) and DIGITS.fullmatch(avail):
            size_bytes, avail_bytes = int(size), int(avail)
            # A full filesystem has no available space, but it always has a size.
            if size_bytes > 0 and avail_bytes <= size_bytes:
                return Observation(
                    ObservationOutcome.OBSERVED,
                    (FILESYSTEM_COMMAND,),
                    "",
                    FilesystemSize(size_bytes, avail_bytes),
                )
    return Observation(
        ObservationOutcome.UNSUPPORTED,
        (FILESYSTEM_COMMAND,),
        "The root filesystem capacity was not reported in a supported format.",
        None,
    )
