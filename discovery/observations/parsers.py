"""Parsers for the Nginx and PHP-FPM configuration text discovery reads.

docs/ssh-connections.md#nginx-site-file-and-php-fpm-pool-observations
"""

import re
from typing import NamedTuple

SERVER_NAME = re.compile(r"[A-Za-z0-9.*_-]{1,200}")
LISTEN_ADDRESS = re.compile(r"(?:unix:)?[A-Za-z0-9._:/\[\]*-]{1,200}")
POOL_NAME = re.compile(r"[A-Za-z0-9._-]{1,100}")
POOL_LISTEN = re.compile(r"[A-Za-z0-9._:/\[\]-]{1,200}")
# Bounds that keep a hostile file from holding the worker: nginx statements and tokens,
# and the pools one file may declare.
MAX_TOKEN = 200
MAX_TOKENS_PER_STATEMENT = 100
MAX_STATEMENTS = 2000
MAX_BLOCK_DEPTH = 50
MAX_LISTEN_FLAGS = 20
MAX_SERVER_NAMES = 100
MAX_POOLS_PER_FILE = 50

# One nginx lexical token. Whitespace and # comments are skipped; quoted values become
# one token. Anything the regex cannot account for leaves a gap between matches, which
# makes the text unsupported.
NGINX_TOKEN = re.compile(
    r"""
      (?P<skipped>\s+|\#[^\n]*)
    | (?P<quoted>'[^']*'|"[^"]*")
    | (?P<word>[^{};'"\s#]+)
    | (?P<end>;)
    | (?P<open>\{)
    | (?P<close>\})
    """,
    re.VERBOSE,
)


def _add_token(current: list[str], token: str) -> bool:
    if len(token) > MAX_TOKEN or len(current) >= MAX_TOKENS_PER_STATEMENT:
        return False
    current.append(token)
    return True


type _NginxEvent = tuple[str, tuple[str, ...], tuple[str, ...]]


def _nginx_statement(current: list[str], blocks: list[str], events: list[_NginxEvent]) -> bool:
    if current:
        if len(events) >= MAX_STATEMENTS:
            return False
        events.append(("stmt", tuple(blocks), tuple(current)))
        current.clear()
    return True


def _nginx_open(current: list[str], blocks: list[str], events: list[_NginxEvent]) -> bool:
    # nginx blocks are named by a leading token, such as "server" or "location /".
    if not current or len(blocks) >= MAX_BLOCK_DEPTH or len(events) >= MAX_STATEMENTS:
        return False
    blocks.append(current[0])
    events.append(("block", tuple(blocks[:-1]), (current[0],)))
    current.clear()
    return True


def _nginx_close(current: list[str], blocks: list[str]) -> bool:
    if current or not blocks:
        return False
    blocks.pop()
    return True


def _nginx_event(
    kind: str,
    token: str,
    current: list[str],
    blocks: list[str],
    events: list[_NginxEvent],
) -> bool:
    if kind == "end":
        return _nginx_statement(current, blocks, events)
    if kind == "open":
        return _nginx_open(current, blocks, events)
    if kind == "close":
        return _nginx_close(current, blocks)
    return _add_token(current, token)


def _nginx_events(text: str) -> list[_NginxEvent] | None:
    """Split nginx configuration into "block" and "stmt" events, or ``None``.

    A "block" event carries the enclosing block names and the new block's name. A "stmt"
    event carries the enclosing block names and the directive's tokens.
    """
    events: list[_NginxEvent] = []
    blocks: list[str] = []
    current: list[str] = []
    pos = 0
    for match in NGINX_TOKEN.finditer(text):
        if match.start() != pos:
            return None
        pos = match.end()
        kind = match.lastgroup or ""
        if kind == "skipped":
            continue
        token = match.group()
        if kind == "quoted":
            token = token[1:-1]
        if not _nginx_event(kind, token, current, blocks, events):
            return None
    if pos != len(text) or current or blocks:
        return None
    return events


def _site_directive(tokens: tuple[str, ...], names: list[str], listens: list[str]) -> bool:
    """Record one server block directive's supported values, or refuse the file."""
    match tokens:
        case ("listen", address, *flags):
            if LISTEN_ADDRESS.fullmatch(address) is None or len(flags) > MAX_LISTEN_FLAGS:
                return False
            if address not in listens:
                listens.append(address)
        case ("server_name", *args):
            declared = [name for name in args if name]
            if (
                (not declared and any(args))
                or len(args) > MAX_SERVER_NAMES
                or any(SERVER_NAME.fullmatch(name) is None for name in declared)
            ):
                return False
            names.extend(name for name in declared if name not in names)
        case _:
            pass
    return True


class NginxSite(NamedTuple):
    server_names: tuple[str, ...]
    listens: tuple[str, ...]
    # The file includes other files where server blocks or their server_name and listen
    # directives may live. Barectl does not read them.
    includes: bool


def parse_nginx_site(text: str) -> NginxSite | None:
    """The site's server names and listen addresses, or ``None`` when unsupported."""
    events = _nginx_events(text)
    if events is None:
        return None
    names: list[str] = []
    listens: list[str] = []
    server_blocks = 0
    includes = False
    for kind, blocks, tokens in events:
        if kind == "block":
            if tokens[0] == "server":
                server_blocks += 1
            continue
        # Directives of a server block: the innermost enclosing block names it.
        at_server_level = not blocks or blocks[-1] == "server"
        if at_server_level and tokens[0] == "include":
            includes = True
        if not blocks or blocks[-1] != "server":
            continue
        if not _site_directive(tokens, names, listens):
            return None
    if server_blocks == 0:
        return None
    return NginxSite(tuple(names), tuple(listens), includes)


def _nginx_http_includes(text: str) -> set[str] | None:
    """The values of the ``include`` directives directly inside nginx's ``http`` block."""
    events = _nginx_events(text)
    if events is None:
        return None
    return {
        tokens[1]
        for kind, blocks, tokens in events
        if kind == "stmt" and blocks == ("http",) and len(tokens) == 2 and tokens[0] == "include"
    }


def _pool_section(line: str) -> str | None:
    if not line.endswith("]"):
        return None
    section = line[1:-1]
    return section if POOL_NAME.fullmatch(section) is not None else None


def _flush_pool(
    pools: list[tuple[str, str]], seen: set[str], name: str | None, listen: str | None
) -> bool:
    if name is None:
        return True
    # PHP-FPM matches section names case-insensitively and merges repeated sections;
    # Barectl does not merge them, so a repeated pool makes the file unsupported.
    if name.casefold() in seen:
        return False
    seen.add(name.casefold())
    pools.append((name, listen or ""))
    return len(pools) <= MAX_POOLS_PER_FILE


def _pool_section_start(
    line: str,
    pools: list[tuple[str, str]],
    seen: set[str],
    name: str | None,
    listen: str | None,
) -> tuple[str | None, str | None] | None:
    """Start the section a ``[name]`` header names, closing the previous pool."""
    section = _pool_section(line)
    if section is None or not _flush_pool(pools, seen, name, listen):
        return None
    # Global directives live in php-fpm.conf, not in a pool file. PHP-FPM matches the
    # section name case-insensitively.
    return (None, None) if section.casefold() == "global" else (section, None)


def _ini_unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _pool_listen(line: str, name: str | None, listen: str | None) -> tuple[str | None, bool]:
    """One ``key = value`` line's effect on the current pool's listen address."""
    key, _, value = line.partition("=")
    if key.strip() != "listen" or name is None:
        # Other directives, including env[...] entries that may hold secrets, are
        # discarded here, before anything is stored.
        return listen, True
    # INI values may be quoted, and PHP-FPM expands $pool to the pool's name.
    value = _ini_unquote(value.strip()).replace("$pool", name)
    if listen is not None or POOL_LISTEN.fullmatch(value) is None:
        return listen, False
    return value, True


class PoolFile(NamedTuple):
    # (pool name, listen address) pairs in file order.
    pools: tuple[tuple[str, str], ...]
    # The file includes other files where more pools may be declared. Barectl does not
    # read them.
    includes: bool


def parse_pool_file(text: str) -> PoolFile | None:
    """The file's pool names and listen addresses, or ``None`` when unsupported.

    PHP-FPM pool files are INI-style: a ``[name]`` section starts a pool and ``key =
    value`` lines configure it. A pool without a listen address is kept with an empty one.
    """
    pools: list[tuple[str, str]] = []
    seen: set[str] = set()
    name: str | None = None
    listen: str | None = None
    includes = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in ";#":
            continue
        if line[0] == "[":
            if (started := _pool_section_start(line, pools, seen, name, listen)) is None:
                return None
            name, listen = started
        elif "=" in line:
            includes = includes or line.partition("=")[0].strip() == "include"
            value, ok = _pool_listen(line, name, listen)
            if not ok:
                return None
            listen = value
        else:
            return None
    if not _flush_pool(pools, seen, name, listen):
        return None
    return PoolFile(tuple(pools), includes)


def _fpm_includes(text: str) -> set[str] | None:
    """The values of the ``include`` directives in a PHP-FPM main configuration file."""
    found: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in ";#" or (line[0] == "[" and line[-1] == "]"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            return None
        if key.strip() == "include":
            found.add(_ini_unquote(value.strip()))
    return found
