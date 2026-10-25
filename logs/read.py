"""The fixed log-read command and its typed page (Phase C #389, docs/logs.md#reading).

A read is one bounded, root-only command through ``RemoteShell``: the newest lines of one
named log, scrubbed on the server, at most ``MAX_LINES`` lines and ``MAX_PAGE_BYTES`` bytes.
No page GET issues a command; only an explicit operator request queues one.
"""

import base64
import binascii
import gzip
import importlib.resources
import json
import shlex
from dataclasses import dataclass, replace
from typing import Final

from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native
from operations.confidential import scrub

from .models import LogOutcome


def _without_imports(text: str) -> str:
    """Drop the imports the assembled server program provides by concatenation."""
    lines: list[str] = []
    skipping = False
    for line in text.splitlines():
        if line.startswith(("from automation.convention import", "from cache.convention import")):
            skipping = line.rstrip().endswith("(")
            continue
        if skipping:
            skipping = not line.strip().endswith(")")
            continue
        lines.append(line)
    return "\n".join(lines)


READ_SOURCE: Final = (
    importlib.resources.files("sites.bodies").joinpath("logrotate.py").read_text()
    + "\n"
    + importlib.resources.files("automation").joinpath("convention.py").read_text()
    + "\n"
    + importlib.resources.files("cache").joinpath("convention.py").read_text()
    + "\n"
    + _without_imports(
        importlib.resources.files("logs.bodies")
        .joinpath("read.py")
        .read_text()
        .replace("from sites.bodies.logrotate import logrotate_present, logrotate_state\n", "")
    )
)
PAGE_PREFIX: Final = "barectl-log-page "


@dataclass(frozen=True)
class LogLine:
    """One rendered line: parsed access fields, the raw line, and whether it was cut."""

    time: str = ""
    method: str = ""
    path: str = ""
    status: int | None = None
    duration: str = ""
    raw: str = ""
    truncated: bool = False

    def document(self) -> dict[str, object]:
        return {
            "time": self.time,
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "duration": self.duration,
            "raw": self.raw,
            "truncated": self.truncated,
        }

    @classmethod
    def from_document(cls, value: object) -> LogLine | None:
        if not isinstance(value, dict):
            return None
        status = value.get("status")
        if status is not None and not isinstance(status, int):
            return None
        return cls(
            time=str(value.get("time", ""))[:40],
            method=str(value.get("method", ""))[:10],
            path=str(value.get("path", ""))[:2000],
            status=status,
            duration=str(value.get("duration", ""))[:20],
            raw=str(value.get("raw", ""))[: 8 * 1024],
            truncated=value.get("truncated") is True,
        )


@dataclass(frozen=True)
class LogPage:
    """The typed evidence of one log read."""

    state: str
    lines: tuple[LogLine, ...] = ()
    cursor: str = ""
    at_end: bool = True
    files: tuple[str, ...] = ()
    note: str = ""
    bytes: int = 0
    # A journal page continues toward older lines with ``cursor`` and toward new lines with
    # ``newest``; ``live`` marks a page a live view asked for (Phase C #397).
    newest: str = ""
    live: bool = False
    # The site's own log rotation, read in the same bounded command (Phase C #389).
    rotation: str = ""
    rotation_problem: str = ""
    rotation_files: tuple[str, ...] = ()
    log_files: tuple[str, ...] = ()

    @property
    def wording(self) -> str:
        return state_wording(self.state, self.note)

    def document(self) -> dict[str, object]:
        return {
            "version": 1,
            "state": self.state,
            "lines": [line.document() for line in self.lines],
            "cursor": self.cursor,
            "at_end": self.at_end,
            "files": list(self.files),
            "note": self.note,
            "bytes": self.bytes,
            "newest": self.newest,
            "live": self.live,
            "rotation": self.rotation,
            "rotation_problem": self.rotation_problem,
            "rotation_files": list(self.rotation_files),
            "log_files": list(self.log_files),
        }

    @classmethod
    def from_document(cls, value: object) -> LogPage | None:
        if not isinstance(value, dict) or value.get("version") != 1:
            return None
        state = value.get("state")
        if state not in tuple(LogOutcome.values):
            return None
        raw_lines = value.get("lines")
        if not isinstance(raw_lines, list) or len(raw_lines) > 500:
            return None
        lines = tuple(
            line for item in raw_lines if (line := LogLine.from_document(item)) is not None
        )
        if len(lines) != len(raw_lines):
            return None
        files = value.get("files")
        return cls(
            state=str(state),
            lines=lines,
            cursor=str(value.get("cursor", ""))[:200],
            at_end=value.get("at_end") is True,
            files=tuple(str(name) for name in files) if isinstance(files, list) else (),
            note=str(value.get("note", ""))[:200],
            bytes=value["bytes"] if isinstance(value.get("bytes"), int) else 0,
            newest=str(value.get("newest", ""))[:200],
            live=value.get("live") is True,
            rotation=str(value.get("rotation", ""))[:20],
            rotation_problem=str(value.get("rotation_problem", ""))[:200],
            rotation_files=_strings(value.get("rotation_files")),
            log_files=_strings(value.get("log_files")),
        )


def _strings(value: object) -> tuple[str, ...]:
    return tuple(str(item) for item in value[:8]) if isinstance(value, list) else ()


def state_wording(state: str, note: str) -> str:
    """Exactly what an operator should understand about a log that has no lines."""
    if state == LogOutcome.OBSERVED:
        return ""
    if state == LogOutcome.MISSING:
        return note or "This log does not exist yet."
    if state == LogOutcome.EMPTY:
        return note or "This log is empty."
    if state == LogOutcome.UNREADABLE:
        return note or "Barectl could not read this log."
    if state == LogOutcome.ROTATED:
        return "This log rotated since the last page. Read the newest lines again to continue."
    if state == LogOutcome.NOT_CONFIGURED:
        return note or "This log is not configured for this site."
    return "Barectl has not read this log yet."


def command(
    identifier: str,
    source: str,
    *,
    term: str = "",
    since: str = "",
    until: str = "",
    cursor: str = "",
) -> str:
    """The one fixed command for a read; every argument is validated and quoted."""
    options = json.dumps({"term": term, "since": since, "until": until, "cursor": cursor})
    packed = base64.b64encode(gzip.compress(READ_SOURCE.encode(), mtime=0)).decode()
    code = "import base64,gzip; exec(gzip.decompress(base64.b64decode(" + repr(packed) + ")))"
    inner = shlex.join(["python3", "-c", code, identifier, source, options])
    return "sh -c " + shlex.quote("; ".join([*native.read_lock_steps(), "exec " + inner]))


def read(
    shell: RemoteShell,
    identifier: str,
    source: str,
    *,
    term: str = "",
    since: str = "",
    until: str = "",
    cursor: str = "",
) -> LogPage:
    """Run the bounded read and return its typed page, or an unreadable page."""
    result = run_root(
        shell,
        command(identifier, source, term=term, since=since, until=until, cursor=cursor),
    )
    if result.exit_status or result.truncated:
        return LogPage(
            LogOutcome.UNREADABLE,
            note="This log could not be read inside the command limit.",
        )
    try:
        page = decode(result.stdout)
    except ValueError:
        return LogPage(LogOutcome.UNREADABLE, note="This log's answer could not be read.")
    return page


def decode(answer: str) -> LogPage:
    """Decode the command's compressed answer into a typed page."""
    text = answer.strip()
    if not text.startswith(PAGE_PREFIX):
        raise ValueError("Not a log page.")
    try:
        raw = gzip.decompress(base64.b64decode(text[len(PAGE_PREFIX) :], validate=True))
        value = json.loads(raw)
    except (binascii.Error, OSError, ValueError) as error:
        raise ValueError("Not a log page.") from error
    page = LogPage.from_document(value)
    if page is None:
        raise ValueError("Not a log page.")
    return page


def scrubbed(page: LogPage, values: tuple[str, ...] = ()) -> LogPage:
    """The controller-side second pass over every stored line.

    A read carries no submitted secret, so ``values`` is empty for a worker's own read; the
    server-side pass is the guarantee. The same chokepoint keeps a future caller from
    storing a known value, and the fast tests exercise it with canaries.
    """
    if not values:
        return page
    return replace(
        page,
        lines=tuple(replace(line, raw=scrub(line.raw, values)) for line in page.lines),
    )
