"""Parsers for the Nginx and PHP-FPM configuration text discovery reads.

docs/ssh-connections.md#nginx-site-file-and-php-fpm-pool-observations
"""

import re
from dataclasses import dataclass, field
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
    events.append(("block", tuple(blocks[:-1]), tuple(current)))
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

    A "block" event carries the enclosing block names and the new block's header tokens,
    its name first. A "stmt" event carries the enclosing block names and the directive's
    tokens.
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


class NginxBlock(NamedTuple):
    """One block of nginx configuration: its header tokens, directives and nested blocks.

    The file itself is a block with an empty header.
    """

    header: tuple[str, ...]
    directives: tuple[tuple[str, ...], ...]
    blocks: tuple[NginxBlock, ...]


@dataclass
class _OpenBlock:
    header: tuple[str, ...]
    directives: list[tuple[str, ...]] = field(default_factory=list)
    blocks: list[_OpenBlock] = field(default_factory=list)

    def frozen(self) -> NginxBlock:
        return NginxBlock(
            self.header, tuple(self.directives), tuple(block.frozen() for block in self.blocks)
        )


def parse_nginx_tree(text: str) -> NginxBlock | None:
    """The file's blocks and directives, or ``None`` when it cannot be tokenized.

    Events arrive in file order, so a directive belongs to the block most recently opened
    at the depth that encloses it.
    """
    events = _nginx_events(text)
    if events is None:
        return None
    root = _OpenBlock(())
    open_at = [root]
    for kind, blocks, tokens in events:
        parent = open_at[len(blocks)]
        if kind == "stmt":
            parent.directives.append(tokens)
            continue
        block = _OpenBlock(tokens)
        parent.blocks.append(block)
        del open_at[len(blocks) + 1 :]
        open_at.append(block)
    return root.frozen()


class NginxReferences(NamedTuple):
    """The filesystem paths and FastCGI endpoints a site file refers to.

    Discovery compares them with a site's own resources and keeps none of them.
    """

    # root and alias values anywhere in the file.
    paths: tuple[str, ...]
    fastcgi_passes: tuple[str, ...]
    # An include or a value with a variable leaves the references unknown.
    dynamic: bool
    # The listen addresses the file marks default_server (or default), as written.
    defaults: tuple[str, ...] = ()


def _walk(block: NginxBlock) -> list[tuple[str, ...]]:
    found = list(block.directives)
    for nested in block.blocks:
        found += _walk(nested)
    return found


def _walk_in_context(
    block: NginxBlock, context: tuple[str, ...] = ()
) -> list[tuple[tuple[str, ...], tuple[str, ...]]]:
    """Each directive with the names of the blocks that enclose it."""
    found = [(context, tokens) for tokens in block.directives]
    for nested in block.blocks:
        found += _walk_in_context(nested, (*context, nested.header[0]))
    return found


def _blocks_named(block: NginxBlock, name: str) -> int:
    return sum((nested.header[0] == name) + _blocks_named(nested, name) for nested in block.blocks)


def nginx_main_extras(text: str, packaged: frozenset[tuple[str, str]]) -> tuple[str, ...] | None:
    """What nginx.conf declares beyond ``packaged``, or ``None`` when it is unsupported.

    ``packaged`` holds the (context, path) pairs of the includes the packaged file has, the
    context being the enclosing block's name or empty at the main level. Other includes
    and server blocks are returned as they are worded for the operator.
    """
    tree = parse_nginx_tree(text)
    if tree is None:
        return None
    extras = [
        f"include {tokens[1] if len(tokens) == 2 and INCLUDED.fullmatch(tokens[1]) else '...'}"
        for context, tokens in _walk_in_context(tree)
        if tokens[0] == "include"
        and not (len(tokens) == 2 and (context[-1] if context else "", tokens[1]) in packaged)
    ]
    if servers := _blocks_named(tree, "server"):
        extras.append(f"{servers} server block{'s' if servers > 1 else ''}")
    return tuple(dict.fromkeys(extras))


def fpm_main_extras(text: str, pool_include: str) -> tuple[str, ...] | None:
    """What a php-fpm.conf declares beyond its global section and its pool include.

    ``None`` when the file is not in a supported form.
    """
    extras: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in ";#":
            continue
        if line[0] == "[":
            section = _pool_section(line)
            if section is None:
                return None
            if section.casefold() != "global":
                extras.append(f"the pool section [{section}]")
            continue
        key, separator, value = line.partition("=")
        if not separator:
            return None
        included = _ini_unquote(value.strip())
        if key.strip() == "include" and included != pool_include:
            extras.append(f"include={included if INCLUDED.fullmatch(included) else '...'}")
    return tuple(dict.fromkeys(extras))


# Included paths Barectl names in warnings; others are named "...".
INCLUDED = re.compile(r"[A-Za-z0-9._/*-]{1,200}")


def nginx_references(text: str, known: frozenset[str] = frozenset()) -> NginxReferences | None:
    """``known`` names included files that declare none of the references."""
    tree = parse_nginx_tree(text)
    if tree is None:
        return None
    paths: list[str] = []
    passes: list[str] = []
    defaults: list[str] = []
    dynamic = False
    for name, *values in _walk(tree):
        if name == "include":
            dynamic = dynamic or len(values) != 1 or values[0] not in known
        elif name in {"root", "alias", "fastcgi_pass"}:
            dynamic = dynamic or len(values) != 1 or "$" in values[0]
            (passes if name == "fastcgi_pass" else paths).extend(values)
        elif name == "listen" and values and {"default_server", "default"} & set(values[1:]):
            defaults.append(values[0])
    return NginxReferences(tuple(paths), tuple(passes), dynamic, tuple(defaults))


# A site pool's settings (docs/site-conventions.md#supported-configuration-grammar): the
# identity that depends on the site, and the fixed values. Their values are kept only while
# discovery compares them; other settings, such as env[...] entries, are counted and never
# kept.
SITE_POOL_IDENTITY = ("user", "group", "listen")
SITE_POOL_FIXED = {
    "listen.owner": "www-data",
    "listen.group": "www-data",
    "listen.mode": "0600",
    "pm": "ondemand",
    "pm.max_children": "5",
    "pm.process_idle_timeout": "10s",
    "clear_env": "yes",
    "security.limit_extensions": ".php",
}
POOL_SETTINGS = frozenset((*SITE_POOL_IDENTITY, *SITE_POOL_FIXED))
POOL_SETTING_VALUE = re.compile(r"[A-Za-z0-9._:/@ -]{1,200}")
MAX_POOL_LINES = 2000


class PoolSection(NamedTuple):
    name: str
    settings: tuple[tuple[str, str], ...]
    # How many settings outside POOL_SETTINGS the section declares.
    others: int
    includes: bool


@dataclass
class _Section:
    name: str
    settings: dict[str, str] = field(default_factory=dict)
    others: int = 0
    includes: bool = False

    def add(self, line: str) -> bool:
        key, _, raw = line.partition("=")
        key = key.strip()
        if key == "include":
            self.includes = True
        elif key not in POOL_SETTINGS:
            self.others += 1
        else:
            # PHP-FPM expands $pool to the pool's name.
            value = _ini_unquote(raw.strip()).replace("$pool", self.name)
            if key in self.settings or POOL_SETTING_VALUE.fullmatch(value) is None:
                return False
            self.settings[key] = value
        return True


def parse_pool_sections(text: str) -> tuple[PoolSection, ...] | None:
    """Each section of a pool file with its supported settings, or ``None`` when unsupported.

    Settings before the first section, repeated settings and values outside the
    supported characters make the file unsupported.
    """
    lines = text.splitlines()
    if len(lines) > MAX_POOL_LINES:
        return None
    sections: list[_Section] = []
    for raw in lines:
        line = raw.strip()
        if not line or line[0] in ";#":
            continue
        if line[0] == "[":
            name = _pool_section(line)
            if name is None or len(sections) >= MAX_POOLS_PER_FILE:
                return None
            sections.append(_Section(name))
        elif "=" not in line or not sections or not sections[-1].add(line):
            return None
    return tuple(
        PoolSection(section.name, tuple(section.settings.items()), section.others, section.includes)
        for section in sections
    )
