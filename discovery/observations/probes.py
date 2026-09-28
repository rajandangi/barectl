"""Probe reads over ``RemoteShell.run`` and how their failures are classified.

The collectors decide observation outcomes from the exit status and output of these fixed
read-only commands (docs/adr/0002-keep-the-remote-shell-seam.md).
"""

import shlex
from collections.abc import Iterable
from dataclasses import dataclass, replace

from ..models import ObservationOutcome
from ..ssh import RemoteShell

# A POSIX shell exits 127 when a command is not found and 126 when it cannot run it.
# https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html#tag_19_08_02
COMMAND_NOT_FOUND = 127
COMMAND_NOT_EXECUTABLE = 126
# Bounds on what one listing or one observation's warning may hold.
MAX_LISTING_ENTRIES = 1000
MAX_OBSERVATION_WARNINGS = 20
MAX_WARNING = 500


@dataclass(frozen=True)
class _Failed:
    """Why a command, file or directory could not be read.

    Helpers never decide that something is absent: only a collector knows whether the
    thing it looked for may legitimately not exist. A missing command or path is reported
    as unsupported with ``missing`` set, and the collector decides what that means.
    """

    status: ObservationOutcome
    warning: str
    # The command or path whose result this is.
    source: str
    missing: bool = False


def _test(shell: RemoteShell, flag: str, path: str) -> bool:
    return shell.run(f"test {flag} {shlex.quote(path)}").exit_status == 0


def _path_missing(shell: RemoteShell, path: str) -> bool:
    """Whether a path ``test -e`` cannot see does not exist, rather than being hidden.

    ``test -e`` also fails when a parent directory cannot be searched, so the nearest
    existing ancestor decides: a searchable one means the path does not exist.
    """
    parent = path.rpartition("/")[0] or "/"
    if path == "/" or _test(shell, "-x", parent):
        return True
    if _test(shell, "-e", parent):
        return False
    return _path_missing(shell, parent)


def _unreadable(shell: RemoteShell, path: str) -> _Failed:
    """Why a remote file or directory could not be read."""
    # Error text depends on the server's locale, so ask the shell instead.
    if not _test(shell, "-e", path):
        if _path_missing(shell, path):
            return _Failed(
                ObservationOutcome.UNSUPPORTED, f"The server has no {path}.", path, missing=True
            )
    elif _test(shell, "-r", path):
        return _Failed(ObservationOutcome.UNSUPPORTED, f"{path} could not be read.", path)
    return _Failed(
        ObservationOutcome.INACCESSIBLE,
        f"The SSH user cannot read {path}. Barectl does not use sudo.",
        path,
    )


def _read_file(shell: RemoteShell, path: str) -> str | _Failed:
    """Return a remote file's contents, or why it could not be observed."""
    result = shell.run(f"cat {shlex.quote(path)}")
    if result.truncated:
        return _Failed(
            ObservationOutcome.UNSUPPORTED,
            f"{path} is larger than expected. It was not read.",
            path,
        )
    if result.exit_status == 0:
        return result.stdout
    return _unreadable(shell, path)


def _run(
    shell: RemoteShell,
    command: str,
    *,
    accepted: frozenset[int] = frozenset({0}),
    missing: str | None = None,
    failed: str | None = None,
) -> str | _Failed:
    """Return a fixed command's output, or why it could not be observed.

    ``accepted`` names the exit statuses that still produce parseable output. A missing
    command leaves the observation uninspectable, never absent; ``missing`` replaces its
    warning, and ``failed`` replaces the warning for any other exit status.
    """
    result = shell.run(command)
    if result.truncated:
        return _Failed(
            ObservationOutcome.UNSUPPORTED,
            f"{command} wrote more output than expected. It was not read.",
            command,
        )
    program = command.split()[0]
    if result.exit_status == COMMAND_NOT_FOUND:
        return _Failed(
            ObservationOutcome.UNSUPPORTED,
            missing or f"The server has no {program} command, so Barectl cannot inspect this.",
            command,
            missing=True,
        )
    if result.exit_status == COMMAND_NOT_EXECUTABLE:
        return _Failed(
            ObservationOutcome.INACCESSIBLE,
            f"The SSH user cannot run {program}. Barectl does not use sudo.",
            command,
        )
    if result.exit_status not in accepted:
        return _Failed(ObservationOutcome.UNSUPPORTED, failed or f"{command} failed.", command)
    return result.stdout


def _listing_command(path: str, *, hidden: bool = False) -> str:
    """The command that lists a directory, with names starting with "." when ``hidden``."""
    return f"ls -1b{'A' if hidden else ''} {shlex.quote(path)}"


def _list_directory(shell: RemoteShell, path: str, *, hidden: bool = False) -> list[str] | _Failed:
    """A directory's entry names, or why they could not be listed.

    ``-b`` escapes newlines and other nongraphic characters in names, so each entry is
    one line; escaped names fail the entry patterns and are skipped, never split.
    """
    result = shell.run(_listing_command(path, hidden=hidden))
    if result.exit_status != 0 and not result.truncated:
        return _unreadable(shell, path)
    entries = result.stdout.splitlines()
    if result.truncated or len(entries) > MAX_LISTING_ENTRIES:
        return _Failed(
            ObservationOutcome.UNSUPPORTED,
            f"{path} holds more than {MAX_LISTING_ENTRIES} entries. It was not read.",
            path,
        )
    return entries


_OUTSIDE_LAYOUT = "Barectl reads only the Debian layout."


def _outside_layout(failure: _Failed) -> _Failed:
    """A read failure in the Debian layout, noting the layout when the path is missing.

    A missing main configuration file or configuration directory of an installed
    component is no finding about configuration kept elsewhere.
    """
    if not failure.missing:
        return failure
    return replace(failure, warning=f"{failure.warning} {_OUTSIDE_LAYOUT}")


def _bounded(warnings: list[str], message: str) -> None:
    """Append a bounded warning once, stopping at the observation warning cap."""
    message = message[:MAX_WARNING]
    if len(warnings) < MAX_OBSERVATION_WARNINGS and message not in warnings:
        warnings.append(message)


def _overall(outcomes: Iterable[ObservationOutcome], *, listed_empty: bool) -> ObservationOutcome:
    """A collection's outcome from the outcomes of the entries it inspected.

    Anything observed makes the collection observed; the other entries remain partial
    results. Otherwise entries Barectl could not inspect leave no finding: inaccessible
    when permissions refused all of them, unsupported otherwise. When nothing was found,
    a listed location that held nothing to read is an observed empty collection;
    otherwise everything Barectl looked for is absent.
    """
    found = set(outcomes)
    if ObservationOutcome.OBSERVED in found:
        return ObservationOutcome.OBSERVED
    uninspected = found - {ObservationOutcome.ABSENT}
    if uninspected == {ObservationOutcome.INACCESSIBLE}:
        return ObservationOutcome.INACCESSIBLE
    if uninspected:
        return ObservationOutcome.UNSUPPORTED
    return ObservationOutcome.OBSERVED if listed_empty else ObservationOutcome.ABSENT
