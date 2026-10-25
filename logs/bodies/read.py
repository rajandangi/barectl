"""A bounded, scrubbed log page, read on the server inside one fixed command.

Compiled into the log-read worker command and imported directly by tests. It never loads a
whole file: the newest window is read, filtered, and cut to ``MAX_LINES`` lines and
``MAX_PAGE_BYTES`` bytes, and older pages continue from a cursor that names the file, its
identity and the byte offset. Known secret values from the site's private configuration are
replaced before any line leaves the server (docs/logs.md#secret-scrubbing).
"""

import base64
import binascii
import gzip
import json
import os
import pathlib
import pwd
import re
import stat
import sys
from collections.abc import Iterator
from datetime import UTC, datetime

from sites.bodies.logrotate import logrotate_present, logrotate_state

MAX_LINES = 500
# docs/logs.md#bounded-pages: a page carries at most 256 KiB of log text. The command's
# answer is compressed, because one SSH command may carry only 64 KiB.
MAX_PAGE_BYTES = 256 * 1024
COMPRESSED_LIMIT = 60 * 1024
PAGE_PREFIX = "barectl-log-page "
# One Caddy access line can carry whole request headers; a page keeps a readable prefix.
MAX_LINE_BYTES = 8192
# The window scanned for one page. Bounded, so a huge file never fills the controller.
SCAN_BYTES = 1024 * 1024
# Site log sources this reader knows. The controller's catalogue mirrors these names.
SOURCES = ("visits", "php_errors", "php_slow", "application", "wordpress")
SECRET_NAME = re.compile(r"(PASSWORD|SECRET|TOKEN|KEY|SALT)")
DEFINE = re.compile(r"^\s*define\(\s*'([A-Z][A-Z0-9_]{0,63})'\s*,\s*'((?:[^'\\]|\\.)*)'\s*\);")
STAMP = re.compile(r"^\[?(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})")
PHP_STAMP = re.compile(r"^\[(\d{2})-([A-Za-z]{3})-(\d{4}) (\d{2}:\d{2}:\d{2})")
MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}
REDACTED = "<secret>"


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        return 2
    identifier, source, raw = argv[1], argv[2], argv[3]
    try:
        options = json.loads(raw)
        page = read_page(identifier, source, **options)
    except ValueError, TypeError, KeyError:
        page = {
            "version": 1,
            "state": "unreadable",
            "lines": [],
            "cursor": "",
            "at_end": True,
            "files": (),
        }
    sys.stdout.write(encode(page) + "\n")
    return 0


def encode(page: dict[str, object]) -> str:
    """One page as the command's answer: gzip and base64, inside the SSH output bound."""
    packed = gzip.compress(json.dumps(page, ensure_ascii=True).encode(), mtime=0)
    return PAGE_PREFIX + base64.b64encode(packed).decode("ascii")


def decode(answer: str) -> dict[str, object]:
    """Read a page the command printed; raise ``ValueError`` when it is not one."""
    if not answer.startswith(PAGE_PREFIX):
        raise ValueError("Not a log page.")
    try:
        raw = gzip.decompress(base64.b64decode(answer[len(PAGE_PREFIX) :], validate=True))
        value = json.loads(raw)
    except (binascii.Error, OSError, ValueError) as error:
        raise ValueError("Not a log page.") from error
    if not isinstance(value, dict):
        raise ValueError("Not a log page.")
    return value


def read_page(
    identifier: str,
    source: str,
    *,
    root: str = "/var/www",
    term: str = "",
    since: str = "",
    until: str = "",
    cursor: str = "",
) -> dict[str, object]:
    """One page of ``source`` for ``identifier``, newest lines first in file order."""
    if (
        not re.fullmatch(r"[a-z][a-z0-9]{2,23}", identifier)
        or source not in SOURCES
        or len(term) > 100
        or "\x00" in term
        or len(cursor) > 200
    ):
        raise ValueError("Not a supported log read.")
    if source == "application":
        page = _application_page(identifier, root, term, since, until, cursor)
    else:
        path = _source_path(identifier, source, root)
        page = _file_page(identifier, path, source, term, since, until, cursor, root=root)
    page["rotation"], page["rotation_problem"], page["rotation_files"] = logrotate_state(identifier)
    page["log_files"] = list(logrotate_present(identifier))
    return page


def _source_path(identifier: str, source: str, root: str) -> str:
    directory = f"{root}/{identifier}/logs"
    return {
        "visits": directory + "/access.json",
        "php_errors": directory + "/php-error.log",
        "php_slow": directory + "/php-slow.log",
        "wordpress": directory + "/wp-debug.log",
    }[source]


def _application_page(
    identifier: str, root: str, term: str, since: str, until: str, cursor: str
) -> dict[str, object]:
    logs = pathlib.Path(root) / identifier / "private" / "storage" / "logs"
    try:
        names = sorted(
            entry.name
            for entry in logs.iterdir()
            if entry.is_file() and not entry.is_symlink() and _daily(entry.name)
        )
    except FileNotFoundError:
        return _state("missing", "The application log has not been created yet.")
    except OSError:
        return _state("unreadable", "The application log could not be read.")
    if not names:
        return _state("missing", "The application log has not been created yet.")
    selected = [name for name in names if _in_range(name, since, until)] or names[-1:]
    if cursor:
        chosen = _decode_cursor(cursor)
        if chosen is None or chosen.get("name") not in names:
            return _rotated()
        name = str(chosen["name"])
        path = str(logs / name)
        page = _file_page(identifier, path, "application", term, since, until, cursor, root=root)
        page["files"] = selected
        return page
    path = str(logs / selected[-1])
    page = _file_page(identifier, path, "application", term, since, until, "", root=root)
    page["files"] = selected
    return page


def _daily(name: str) -> bool:
    return re.fullmatch(r"laravel-\d{4}-\d{2}-\d{2}\.log", name) is not None


def _in_range(name: str, since: str, until: str) -> bool:
    day = name[len("laravel-") : -len(".log")]
    return (not since or day >= since[:10]) and (not until or day <= until[:10])


def _file_page(  # noqa: C901 - one bounded page path
    identifier: str,
    path: str,
    source: str,
    term: str,
    since: str,
    until: str,
    cursor: str,
    *,
    root: str,
) -> dict[str, object]:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return _state("missing", "This log does not exist yet.")
    except OSError:
        return _state("unreadable", "This log could not be read.")
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        return _state("unreadable", "This log is not a regular file.")
    if metadata.st_size == 0:
        return _state("empty", "This log exists and is empty.")
    offset = metadata.st_size
    if cursor:
        chosen = _decode_cursor(cursor)
        if (
            chosen is None
            or chosen.get("name") != pathlib.Path(path).name
            or chosen.get("dev") != metadata.st_dev
            or chosen.get("ino") != metadata.st_ino
            or not isinstance(chosen.get("offset"), int)
            or not 0 <= int(str(chosen["offset"])) <= metadata.st_size
        ):
            return _rotated()
        offset = int(str(chosen["offset"]))
        if offset == 0:
            return _state("empty", "There are no older lines in this log.", at_end=True)
    start = max(0, offset - SCAN_BYTES)
    try:
        with open(path, "rb") as stream:
            stream.seek(start)
            window = stream.read(offset - start)
    except PermissionError:
        return _state("unreadable", "This log exists but Barectl may not read it.")
    except OSError:
        return _state("unreadable", "This log could not be read.")
    if start > 0:
        boundary = window.find(b"\n")
        if boundary < 0:
            return _state("empty", "There are no readable lines in this log.", at_end=True)
        start += boundary + 1
        window = window[boundary + 1 :]
    secrets = _secret_values(identifier, root)
    kept: list[dict[str, object]] = []
    used = 0
    for raw, line_start in reversed(list(_lines(window, start))):
        scrubbed = _scrub(raw, secrets)
        if not _wanted(scrubbed, source, term, since, until):
            continue
        entry = _entry(scrubbed[:MAX_LINE_BYTES], source)
        entry["truncated"] = len(scrubbed.encode()) > MAX_LINE_BYTES
        size = len(str(entry["raw"]).encode()) + 80
        if len(kept) >= MAX_LINES or used + size > MAX_PAGE_BYTES:
            break
        entry["_offset"] = line_start
        kept.append(entry)
        used += size
    # Collected newest first; a page reads in file order, oldest of the kept lines first.
    kept.reverse()
    page = {
        "version": 1,
        "state": "observed",
        "lines": kept,
        "at_end": start == 0,
        "files": (path,),
        "file": path,
        "bytes": used,
    }
    return _fit(page, path, metadata)


def _fit(page: dict[str, object], path: str, metadata: os.stat_result) -> dict[str, object]:
    """Shrink the page until the compressed answer fits one SSH command's output."""
    lines = page["lines"]
    while isinstance(lines, list) and lines and len(encode(page)) > COMPRESSED_LIMIT:
        lines.pop(0)
    if isinstance(lines, list) and lines:
        oldest = lines[0]
        offset = int(str(oldest["_offset"]))
        page["at_end"] = offset == 0
        page["cursor"] = "" if offset == 0 else _encode_cursor(path, metadata, offset)
    else:
        page["state"] = "empty"
        page["note"] = "No lines in this log match the filter."
        page["at_end"] = True
        page["cursor"] = ""
    for line in lines if isinstance(lines, list) else []:
        line.pop("_offset", None)
    return page


def _lines(window: bytes, start: int) -> Iterator[tuple[str, int]]:
    position = 0
    for raw in window.split(b"\n"):
        if raw:
            yield raw.decode("utf-8", "replace"), start + position
        position += len(raw) + 1


def _state(name: str, note: str, *, at_end: bool = True) -> dict[str, object]:
    return {
        "version": 1,
        "state": name,
        "lines": [],
        "cursor": "",
        "at_end": at_end,
        "files": (),
        "note": note,
    }


def _rotated() -> dict[str, object]:
    return _state("rotated", "This log rotated since the last page. Read the newest lines again.")


def _wanted(raw: str, source: str, term: str, since: str, until: str) -> bool:
    if term and term.casefold() not in raw.casefold():
        return False
    moment = _moment(raw, source)
    if moment is None:
        return True
    return (not since or moment >= _parse(since)) and (not until or moment <= _parse(until))


def _parse(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _moment(raw: str, source: str) -> datetime | None:
    if source == "visits":
        try:
            value = json.loads(raw)
            stamp = value.get("ts") if isinstance(value, dict) else None
            if isinstance(stamp, int | float):
                return datetime.fromtimestamp(float(stamp), UTC)
        except ValueError, OSError:
            return None
    match = STAMP.match(raw)
    if match is not None:
        try:
            return datetime.fromisoformat(match.group(1) + "T" + match.group(2)).replace(tzinfo=UTC)
        except ValueError:
            return None
    php = PHP_STAMP.match(raw)
    if php is not None and php.group(2) in MONTHS:
        try:
            return datetime(
                int(php.group(3)),
                MONTHS[php.group(2)],
                int(php.group(1)),
                int(php.group(4)[:2]),
                int(php.group(4)[3:5]),
                int(php.group(4)[6:8]),
                tzinfo=UTC,
            )
        except ValueError:
            return None
    return None


def _entry(raw: str, source: str) -> dict[str, object]:
    entry: dict[str, object] = {
        "raw": raw,
        "time": "",
        "method": "",
        "path": "",
        "status": None,
        "duration": "",
    }
    moment = _moment(raw, "visits" if source == "visits" else source)
    if moment is not None:
        entry["time"] = moment.strftime("%Y-%m-%d %H:%M:%S")
    if source != "visits":
        return entry
    try:
        value = json.loads(raw)
    except ValueError:
        return entry
    request = value.get("request") if isinstance(value, dict) else None
    if isinstance(request, dict):
        entry["method"] = str(request.get("method", ""))[:10]
        entry["path"] = str(request.get("uri", ""))[:2000]
    status = value.get("status") if isinstance(value, dict) else None
    if isinstance(status, int):
        entry["status"] = status
    duration = value.get("duration") if isinstance(value, dict) else None
    if isinstance(duration, int | float):
        entry["duration"] = f"{float(duration) * 1000:.0f} ms"
    return entry


def _encode_cursor(path: str, metadata: os.stat_result, offset: int) -> str:
    value = {
        "name": pathlib.Path(path).name,
        "dev": metadata.st_dev,
        "ino": metadata.st_ino,
        "offset": max(0, offset),
    }
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode("ascii")[:200]


def _decode_cursor(cursor: str) -> dict[str, object] | None:
    try:
        value = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")))
    except ValueError, binascii.Error, UnicodeEncodeError:
        return None
    return value if isinstance(value, dict) else None


def _secret_values(identifier: str, root: str) -> tuple[str, ...]:
    """Known secret values from the site's private configuration, longest first."""
    values: set[str] = set()
    for path in (
        f"{root}/{identifier}/private/laravel.env",
        f"{root}/{identifier}/private/wp-config.php",
    ):
        try:
            if not _private(path):
                continue
            text = pathlib.Path(path).read_text()[: 64 * 1024]
        except OSError, UnicodeDecodeError:
            continue
        values.update(_secrets(text, path.endswith(".env")))
    ordered = sorted((value for value in values if 4 <= len(value) <= 512), key=len, reverse=True)
    return tuple(ordered[:32])


def _private(path: str) -> bool:
    try:
        metadata = os.lstat(path)
    except OSError:
        return False
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        return False
    try:
        account = pwd.getpwnam("s" + path.split("/")[3])
    except KeyError, IndexError:
        # No account: the file is still private to root, and the path is a validated site.
        return True
    return metadata.st_uid == account.pw_uid


def _secrets(text: str, environment: bool) -> set[str]:
    found: set[str] = set()
    for line in text.splitlines():
        if environment:
            key, separator, raw = line.partition("=")
            if not separator or not SECRET_NAME.search(key):
                continue
            value = raw.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            found.add(value)
        else:
            match = DEFINE.match(line)
            if match is not None and SECRET_NAME.search(match.group(1)):
                found.add(match.group(2).replace("\\'", "'").replace("\\\\", "\\"))
    return found


def _scrub(raw: str, secrets: tuple[str, ...]) -> str:
    for secret in secrets:
        if secret and secret in raw:
            raw = raw.replace(secret, REDACTED)
    return raw


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
