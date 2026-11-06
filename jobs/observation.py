"""Bounded native reads for Barectl's own change runs (Phase E #285).

Running work reuses the change engine's retained-unit read. Finished work is one bounded
journal read of the transient apply units, restricted to the engine's stage and result
markers and reduced to the message, unit and invocation fields. The result line is parsed
by the engine's one parser, so Jobs never invents an outcome
(docs/adr/0035-one-change-engine-with-effect-derived-consent.md).

Access follows the change engine's exact ``sudo -n`` authorization check: a read the SSH
user may not perform is reported as denied coverage, and nothing escalates. The controller
never keeps journal messages, only the unit, invocation, timestamps and parsed outcome.
"""

import json
import shlex
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from discovery.ssh import CommandResult, RemoteShell
from operations import engine, native

PROVIDER: Final = "barectl_changes"

# The widest range Recent results offers today (#291 owns the filters and the viewer zone).
HISTORY_DAYS: Final = 30
# Literal line cap. journald prints several fixed metadata fields beside the requested
# ones, so a worst-case stage and result pair measured on the 1 GiB Ubuntu 26.04 lane is
# about 1.3 KiB; 90 lines stay inside the 64 KiB SSH answer bound with room for a 91st
# line, which is how the read tells a full answer from a capped one.
HISTORY_LINES: Final = 90
_FIELDS: Final = "MESSAGE,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID"
_JOURNAL: Final = (
    "/usr/bin/journalctl",
    "--no-pager",
    "--quiet",
    "--output=json",
    f"--output-fields={_FIELDS}",
    "--grep",
    "^barectl-(stage |result )",
    "-u",
    "barectl-apply-*",
)
HISTORY_COMMAND: Final = shlex.join(
    (
        *_JOURNAL,
        "--reverse",
        "-n",
        str(HISTORY_LINES + 1),
        "--since",
        f"{HISTORY_DAYS} days ago",
    )
)
OLDEST_COMMAND: Final = (
    shlex.join(
        (
            *_JOURNAL[:4],
            "--output-fields=__REALTIME_TIMESTAMP",
            "-u",
            "barectl-apply-*",
        )
    )
    + " | /usr/bin/head -n 1"
)
# One authorized command returns the oldest retained time and the bounded history, so a
# discovery pays one exact-sudo authorization and one SSH execution instead of two.
OLDEST_MARK: Final = "--barectl-jobs-oldest--"
HISTORY_MARK: Final = "--barectl-jobs-history--"
JOURNAL_COMMAND: Final = (
    f"printf '%s\\n' '{OLDEST_MARK}'; {OLDEST_COMMAND}; "
    f"printf '%s\\n' '{HISTORY_MARK}'; {HISTORY_COMMAND}"
)

RUNNING_NOT_READ = "Barectl could not read the change runs the server still holds."
JOURNAL_NOT_READ = "Barectl could not read the server's record of finished changes."
JOURNAL_DENIED = (
    "The SSH user may not read the server's journal, so finished changes are not shown. "
    "Barectl did not use sudo."
)
JOURNAL_TRUNCATED = (
    "The server keeps more finished changes than Barectl reads at once, so older results "
    "are not shown."
)
JOURNAL_UNREADABLE = "Some finished changes could not be read, so their results are unknown."
NO_EVIDENCE = (
    "The server has no available Barectl change results for the last "
    f"{HISTORY_DAYS} days. This does not mean no change ran."
)


@dataclass(frozen=True)
class ObservedChange:
    """One observed change run, from its retained unit or its journal lines.

    ``result_class`` is empty when the row has no readable result. ``result_evidence``
    keeps a result line Barectl could not read distinct from the run printing none.
    ``started_at`` is the first stage line's time and ``finished_at`` the result line's
    time, both server UTC.
    """

    unit: str
    invocation_id: str = ""
    kind_slug: str = ""
    sites: tuple[str, ...] = ()
    result_class: str = ""
    reason: str = ""
    started_at: datetime | None = None
    finished_at: datetime | None = None
    running: bool = False
    active_state: str = ""
    sub_state: str = ""
    exec_main_status: int | None = None
    result_evidence: engine.ResultEvidence = engine.ResultEvidence.ABSENT


def stored_result_evidence(
    result_class: str, finished_at: datetime | None
) -> engine.ResultEvidence:
    """The result evidence a stored row keeps without a column of its own.

    A stored class means the line parsed. A result-line time without a class means a line
    was present but unreadable. Neither means the run reported no result line.
    """
    if result_class:
        return engine.ResultEvidence.PRESENT
    if finished_at is not None:
        return engine.ResultEvidence.UNREADABLE
    return engine.ResultEvidence.ABSENT


@dataclass(frozen=True)
class ProviderCoverage:
    provider: str
    state: str
    warning: str = ""
    oldest_at: datetime | None = None


@dataclass(frozen=True)
class JobReading:
    changes: tuple[ObservedChange, ...] = ()
    coverage: tuple[ProviderCoverage, ...] = ()


def read(shell: RemoteShell) -> JobReading:
    """Read the server's Barectl change runs and how much of them it could establish."""
    running, running_state, running_warning = _running(shell)
    finished, finished_state, finished_warning, oldest_at = _finished(shell)
    changes = _merge(running, finished)
    state = _state(changes, running_state, finished_state)
    warning = " ".join(
        text for text in (running_warning, finished_warning) if text and state != "complete"
    )
    if state == "no_evidence" and not warning:
        warning = NO_EVIDENCE
    return JobReading(
        changes=changes,
        coverage=(ProviderCoverage(PROVIDER, state, warning, oldest_at),),
    )


def _merge(
    running: tuple[ObservedChange, ...], finished: tuple[ObservedChange, ...]
) -> tuple[ObservedChange, ...]:
    """One row per run, preferring a finished result over a still-retained unit."""
    by_key = {(row.unit, row.invocation_id): row for row in finished}
    rows = list(finished)
    for row in running:
        key = (row.unit, row.invocation_id)
        if key in by_key:
            continue
        rows.append(row)
        by_key[key] = row
    rows.sort(key=_order)
    return tuple(rows)


def _order(row: ObservedChange) -> tuple[int, float, str]:
    # Newest evidence first; a row with no time sorts after timed rows.
    when = row.finished_at or row.started_at
    return (0 if row.running else 1, -(when.timestamp() if when else 0), row.unit)


def _state(changes: tuple[ObservedChange, ...], running_state: str, finished_state: str) -> str:
    # A failed or partial read outranks a complete one; an empty complete read is
    # explicitly no evidence, never a claim that nothing ran.
    for state in ("read_failed", "access_denied", "unreadable", "truncated"):
        if running_state == state or finished_state == state:
            return state
    return "complete" if changes else "no_evidence"


def _running(shell: RemoteShell) -> tuple[tuple[ObservedChange, ...], str, str]:
    result = shell.run(native.RUNNING_STATES)
    if result.exit_status != 0:
        return (), "read_failed", RUNNING_NOT_READ
    if result.truncated:
        return (), "truncated", RUNNING_NOT_READ
    try:
        _, units = native.parse_retained_states(result.stdout)
    except native.Unreadable:
        return (), "unreadable", RUNNING_NOT_READ
    rows = tuple(
        ObservedChange(
            unit=unit.unit,
            invocation_id=unit.invocation_id,
            running=True,
            active_state=unit.active_state,
            sub_state=unit.sub_state,
            exec_main_status=unit.exec_main_status,
        )
        for unit in units
        if unit.found and not unit.terminal
    )
    # A finished run's evidence is its journal line; the retained-unit read is filtered to
    # active units so a host that keeps many finished units pays nothing for them.
    return rows, "complete", ""


def _finished(
    shell: RemoteShell,
) -> tuple[tuple[ObservedChange, ...], str, str, datetime | None]:
    result, denied = _journal(shell, JOURNAL_COMMAND)
    if denied:
        return (), "access_denied", JOURNAL_DENIED, None
    if result.exit_status != 0:
        return (), "read_failed", JOURNAL_NOT_READ, None
    split = _split(result.stdout)
    if split is None:
        return (), "unreadable", JOURNAL_UNREADABLE, None
    oldest_text, history_text = split
    rows, unreadable, counted = _parse(history_text)
    truncated = result.truncated or counted > HISTORY_LINES
    oldest = _oldest(oldest_text)
    if truncated:
        return tuple(rows), "truncated", JOURNAL_TRUNCATED, oldest
    if unreadable:
        return tuple(rows), "unreadable", JOURNAL_UNREADABLE, oldest
    return tuple(rows), "complete", "", oldest


def _journal(shell: RemoteShell, command: str) -> tuple[CommandResult, bool]:
    """Run one fixed journal read, or report the SSH user's exact-sudo refusal."""
    root = native.is_root(shell)
    if root is None:
        return CommandResult(1, ""), False
    if root is True:
        return shell.run(command), False
    argv = ["/usr/bin/sh", "-c", command]
    if shell.run(native.authorization(argv)).exit_status != 0:
        return CommandResult(1, ""), True
    return shell.run(native.privileged(argv, root=False)), False


def _split(text: str) -> tuple[str, str] | None:
    """The oldest line and the history lines from the one combined read."""
    lines = text.splitlines()
    try:
        oldest = lines.index(OLDEST_MARK)
        history = lines.index(HISTORY_MARK)
    except ValueError:
        return None
    if not oldest < history:
        return None
    return "\n".join(lines[oldest + 1 : history]), "\n".join(lines[history + 1 :])


def _oldest(text: str) -> datetime | None:
    """The oldest journal time the server still holds, from the combined read."""
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except ValueError:
            return None
        return _timestamp(value.get("__REALTIME_TIMESTAMP")) if isinstance(value, dict) else None
    return None


@dataclass
class _Group:
    unit: str
    invocation_id: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result_class: str = ""
    reason: str = ""
    kind_slug: str = ""
    sites: tuple[str, ...] = ()
    result_seen: bool = False
    result_evidence: engine.ResultEvidence = engine.ResultEvidence.ABSENT


@dataclass(frozen=True)
class _Entry:
    unit: str
    invocation: str
    message: str
    when: datetime


def _parse(text: str) -> tuple[list[ObservedChange], bool, int]:
    """Parse the journal answer into one row per invocation.

    Returns the rows, whether any line was unreadable, and how many journal lines the
    answer held, so the caller can tell a full read from a capped one.
    """
    groups: dict[tuple[str, str], _Group] = {}
    unreadable = False
    lines = [line for line in text.splitlines() if line.strip()]
    for line in lines[:HISTORY_LINES]:
        try:
            entry = _entry(line)
        except ValueError:
            unreadable = True
            continue
        group = groups.setdefault(
            (entry.unit, entry.invocation), _Group(entry.unit, entry.invocation)
        )
        unreadable = _apply(group, entry) or unreadable
    rows = [
        ObservedChange(
            unit=group.unit,
            invocation_id=group.invocation_id,
            kind_slug=group.kind_slug,
            sites=group.sites,
            result_class=group.result_class,
            reason=group.reason,
            started_at=group.started_at,
            finished_at=group.finished_at,
            result_evidence=group.result_evidence,
        )
        for group in groups.values()
    ]
    return rows, unreadable, len(lines)


def _entry(line: str) -> _Entry:
    """One journal JSON line, or ``ValueError`` when it is not the form we asked for."""
    try:
        value = json.loads(line)
    except ValueError as error:
        raise ValueError("Not a journal line.") from error
    if not isinstance(value, dict):
        raise ValueError("Not a journal line.")
    message = value.get("MESSAGE")
    unit = value.get("_SYSTEMD_UNIT")
    invocation = value.get("_SYSTEMD_INVOCATION_ID")
    when = _timestamp(value.get("__REALTIME_TIMESTAMP"))
    if (
        not isinstance(message, str)
        or not isinstance(unit, str)
        or not isinstance(invocation, str)
        or when is None
    ):
        raise ValueError("Not the journal fields Barectl requested.")
    try:
        native.check_unit(unit)
    except native.Unreadable as error:
        raise ValueError("Not a Barectl unit.") from error
    if invocation and not _invocation(invocation):
        raise ValueError("Not an invocation ID.")
    return _Entry(unit, invocation, message, when)


def _apply(group: _Group, entry: _Entry) -> bool:
    """Apply one entry to its run; return whether a result line was unreadable."""
    if entry.message.startswith("barectl-stage "):
        if group.started_at is None or entry.when < group.started_at:
            group.started_at = entry.when
        return False
    if not entry.message.startswith("barectl-result "):
        return False
    if group.result_seen:
        # The newest result line wins; an older one never replaces it.
        return False
    group.result_seen = True
    group.finished_at = entry.when
    try:
        parsed = engine.parse_result_line(entry.message)
    except native.Unreadable:
        group.result_evidence = engine.ResultEvidence.UNREADABLE
        return True
    if parsed is None:
        group.result_evidence = engine.ResultEvidence.UNREADABLE
        return True
    group.result_evidence = engine.ResultEvidence.PRESENT
    group.result_class = parsed.result_class
    group.reason = parsed.reason
    group.kind_slug = parsed.change_kind
    group.sites = parsed.sites
    return False


def _invocation(value: str) -> bool:
    try:
        native.check_invocation(value)
    except native.Unreadable:
        return False
    return True


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.isdigit():
        return None
    # journald reports microseconds since the Unix epoch in __REALTIME_TIMESTAMP.
    try:
        return datetime.fromtimestamp(int(value) / 1_000_000, tz=UTC)
    except OverflowError, OSError, ValueError:
        return None
