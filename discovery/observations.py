"""Read-only observations collected over a verified connection.

Every command here is a fixed string that only reads. None uses sudo, installs packages or
writes files. Only the fields Barectl displays are kept; raw remote output is discarded.
"""

import shlex
from dataclasses import dataclass

from .models import ObservationStatus
from .ssh import RemoteShell

# The os-release specification: read /etc/os-release, falling back to /usr/lib/os-release.
# https://www.freedesktop.org/software/systemd/man/latest/os-release.html
OS_RELEASE_FILES = ("/etc/os-release", "/usr/lib/os-release")
OS_RELEASE_FIELDS = {"PRETTY_NAME": 200, "NAME": 200, "ID": 100, "VERSION_ID": 100}


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
