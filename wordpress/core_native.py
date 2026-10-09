"""WordPress core's pins and the installation review's fixed reads.

docs/wordpress-native-design.md#compatibility-and-supply owns the literal pins and limits;
docs/wordpress.md#installation-review describes what the review reads. Every read here is
a fixed, read-only script run as root; none starts WordPress, WP-CLI or application PHP,
and none prints a secret.
"""

import re
import shlex
from dataclasses import dataclass, field
from typing import Final

from sites import native as site_native

from . import convention

# The qualified core release and its official archive, observed 2026-10-07.
VERSION: Final = convention.CORE_VERSION
LOCALE: Final = "en_US"
ARCHIVE_URL: Final = f"https://wordpress.org/wordpress-{VERSION}.tar.gz"
ARCHIVE_BYTES: Final = 35_368_461
ARCHIVE_SHA256: Final = "d2a09acb6a15e3b9c471d72557753c266d6f41a79ed19bfe04cbfe49e283b2a5"
# Pre-download limits the apply run enforces natively (systemd LimitFSIZE/MemoryMax and the
# archive admission); a profile beyond them is refused.
MAX_ARCHIVE_BYTES: Final = 64 * 1024 * 1024
MAX_TREE_BYTES: Final = 256 * 1024 * 1024
MAX_ENTRIES: Final = 10_000
MAX_FILE_BYTES: Final = 64 * 1024 * 1024
MEMORY_MAX_BYTES: Final = 512 * 1024 * 1024
RUNTIME_LIMIT_SECONDS: Final = 30 * 60
# The archive, the staged tree and the published tree can coexist on the site's filesystem.
REQUIRED_FREE_BYTES: Final = MAX_ARCHIVE_BYTES + 2 * MAX_TREE_BYTES
# The top-level entries of the pinned archive's release, observed 2026-10-09, with their kind
# ("d" directory, "f" file). A Finish publishes the entries the public root lacks and requires
# every other entry of the public root to be one of these, the loader or the placeholder.
RELEASE_ENTRIES: Final = {
    "index.php": "f",
    "license.txt": "f",
    "readme.html": "f",
    "wp-activate.php": "f",
    "wp-admin": "d",
    "wp-blog-header.php": "f",
    "wp-comments-post.php": "f",
    "wp-config-sample.php": "f",
    "wp-content": "d",
    "wp-cron.php": "f",
    "wp-includes": "d",
    "wp-links-opml.php": "f",
    "wp-load.php": "f",
    "wp-login.php": "f",
    "wp-mail.php": "f",
    "wp-settings.php": "f",
    "wp-signup.php": "f",
    "wp-trackback.php": "f",
    "xmlrpc.php": "f",
}
# docs/wordpress.md#installation-review: the largest listing the files read returns.
MAX_LISTED: Final = 50

_ENV: Final = "export LC_ALL=C PATH=/usr/sbin:/usr/bin"
# WordPress release names whose presence makes content an existing application.
APPLICATION_NAMES: Final = frozenset(
    {
        "wp-config.php",
        "wp-load.php",
        "wp-settings.php",
        "wp-admin",
        "wp-includes",
        "wp-content",
    }
)


def _checked(identifier: str) -> str:
    if not convention.IDENTIFIER.fullmatch(identifier):
        raise ValueError("Not a valid site identifier.")
    return identifier


def files_argv(identifier: str, *, shallow: bool = False) -> list[str]:
    """The site's directory entries, the public and private trees' entries and the
    placeholder's digest, as root. A tree that cannot be listed prints ``error`` and every
    complete listing ends with ``end``. A ``shallow`` read lists only the trees' top level,
    which is what a Finish review needs of a published release."""
    base = f"{convention.WEB_ROOT}/{_checked(identifier)}"
    listing = (
        'l(){ o=$(find "$2" -mindepth 1 $3 -printf "$1 %y %m %U %G %n %s %P\\n" 2>/dev/null) '
        '|| { echo "error $1"; return; }; '
        '[ -z "$o" ] || printf "%s\\n" "$o" | sort | head -n ' + str(MAX_LISTED + 2) + "; "
        'echo "end $1"; }'
    )
    placeholder = f"{base}/public/index.html"
    depth = "'-maxdepth 1'" if shallow else "''"
    return site_native.script(
        "; ".join(
            (
                _ENV,
                listing,
                f"l site {base} '-maxdepth 1'",
                f"l public {base}/public {depth}",
                f"l private {base}/private {depth}",
                (
                    f"[ -f {placeholder} ] && [ ! -L {placeholder} ] && "
                    f"echo \"sha $(sha256sum < {placeholder} | cut -d' ' -f1)\""
                ),
                "true",
            )
        )
    )


def database_argv(identifier: str) -> list[str]:
    """How many tables, routines, events and triggers the site's database holds, the first
    few table names and whether the database exists; names and counts, no row of any table."""
    name = f"s{_checked(identifier)}"
    sql = (
        f"SELECT 'S',COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='{name}';"  # noqa: S608 - fixed, checked name
        f"SELECT 'T',COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='{name}';"
        f"SELECT 'R',COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA='{name}';"
        f"SELECT 'E',COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA='{name}';"
        f"SELECT 'G',COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='{name}';"
        f"SELECT 'N',TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='{name}' "
        "ORDER BY TABLE_NAME LIMIT 5"
    )
    return site_native.script(f"{_ENV}; {convention.MARIADB_CLIENT} {shlex.quote(sql)}")


def supply_argv() -> list[str]:
    """The native tools the run needs, the free space on the site filesystem and the
    pinned archive's size as the official server announces it (a HEAD request; nothing is
    downloaded)."""
    head = (
        "curl --silent --show-error --head --location --max-redirs 3 --proto =https "
        "--proto-redir =https --connect-timeout 10 --max-time 30 --output /dev/null "
        "--write-out 'archive %{http_code} %header{content-length}\\n' "
        f"{shlex.quote(ARCHIVE_URL)}"
    )
    return site_native.script(
        "; ".join(
            (
                _ENV,
                (
                    'for t in curl tar sha256sum; do [ -x /usr/bin/$t ] && echo "tool $t ok" '
                    '|| echo "tool $t missing"; done'
                ),
                f"df -P -B1 {convention.WEB_ROOT} | awk 'NR==2{{print \"free \" $4}}'",
                f"(command -v curl >/dev/null && {head}) 2>/dev/null || echo 'archive 000 '",
                "true",
            )
        )
    )


@dataclass(frozen=True)
class Entry:
    kind: str
    mode: str
    uid: int
    gid: int
    links: int
    size: int
    path: str


@dataclass
class FileState:
    site: list[Entry] = field(default_factory=list)
    public: list[Entry] = field(default_factory=list)
    private: list[Entry] = field(default_factory=list)
    placeholder_sha256: str = ""
    ended: set[str] = field(default_factory=set)
    errors: set[str] = field(default_factory=set)

    @property
    def complete(self) -> bool:
        return self.ended == {"site", "public", "private"} and not self.errors


class Unreadable(Exception):
    pass


_ENTRY = re.compile(
    r"(site|public|private) ([a-zA-Z]) ([0-7]{1,4}) ([0-9]{1,10}) ([0-9]{1,10}) "
    r"([0-9]{1,6}) ([0-9]{1,15}) (.{1,255})"
)
_NAMES = frozenset({"site", "public", "private"})


def parse_files(text: str) -> FileState:
    """The files read's lines; any other line is an unreadable answer."""
    state = FileState()
    for line in text.splitlines():
        words = line.split(" ")
        if words[0] == "end" and len(words) == 2 and words[1] in _NAMES:
            state.ended.add(words[1])
        elif words[0] == "error" and len(words) == 2 and words[1] in _NAMES:
            state.errors.add(words[1])
        elif words[0] == "sha" and len(words) == 2 and re.fullmatch(r"[0-9a-f]{64}", words[1]):
            state.placeholder_sha256 = words[1]
        elif match := _ENTRY.fullmatch(line):
            entry = Entry(
                match[2],
                match[3],
                int(match[4]),
                int(match[5]),
                int(match[6]),
                int(match[7]),
                match[8],
            )
            getattr(state, match[1]).append(entry)
        else:
            raise Unreadable("The application files read is not in its expected form.")
    return state


@dataclass(frozen=True)
class DatabaseState:
    exists: bool
    tables: int
    routines: int
    events: int
    triggers: int
    names: tuple[str, ...]

    @property
    def empty(self) -> bool:
        return self.exists and not (self.tables or self.routines or self.events or self.triggers)


_TABLE_NAME = re.compile(r"[A-Za-z0-9_$-]{1,64}")


def parse_database(text: str) -> DatabaseState:
    counts: dict[str, int] = {}
    names: list[str] = []
    for line in text.splitlines():
        match line.split("\t"):
            case [kind, value] if kind in "STREG" and len(kind) == 1 and value.isdigit():
                if kind in counts:
                    raise Unreadable("The application database read is not in its expected form.")
                counts[kind] = int(value)
            case ["N", name] if _TABLE_NAME.fullmatch(name) and len(names) < 5:
                names.append(name)
            case _:
                raise Unreadable("The application database read is not in its expected form.")
    if set(counts) != set("STREG"):
        raise Unreadable("The application database read is not in its expected form.")
    return DatabaseState(
        counts["S"] == 1, counts["T"], counts["R"], counts["E"], counts["G"], tuple(names)
    )


@dataclass(frozen=True)
class Supply:
    tools: dict[str, bool]
    free_bytes: int
    # The announced archive: the HTTP status and Content-Length, 0 when absent.
    archive_status: int
    archive_bytes: int


def parse_supply(text: str) -> Supply:
    tools: dict[str, bool] = {}
    free = -1
    status = -1
    announced = 0
    for line in text.splitlines():
        match line.split(" "):
            case ["tool", name, state] if name in {"curl", "tar", "sha256sum"} and state in {
                "ok",
                "missing",
            }:
                tools[name] = state == "ok"
            case ["free", value] if value.isdigit():
                free = int(value)
            case ["archive", code, *rest] if code.isdigit() and len(rest) <= 1:
                status = int(code)
                length = rest[0].strip() if rest else ""
                announced = int(length) if length.isdigit() else 0
            case _:
                raise Unreadable("The supply read is not in its expected form.")
    if set(tools) != {"curl", "tar", "sha256sum"} or free < 0 or status < 0:
        raise Unreadable("The supply read is not in its expected form.")
    return Supply(tools, free, status, announced)
