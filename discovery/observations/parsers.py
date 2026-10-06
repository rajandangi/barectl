"""A bounded Nginx tokenizer for the server names of enabled site files.

docs/ssh-connections.md#site-observations
"""

import re

SERVER_NAME = re.compile(r"[A-Za-z0-9.*_-]{1,200}")
# Bounds that keep a hostile file from holding the worker.
MAX_TOKEN = 200
MAX_TOKENS_PER_STATEMENT = 100
MAX_STATEMENTS = 2000
MAX_BLOCK_DEPTH = 50
MAX_SERVER_NAMES = 100

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


def declared_server_names(text: str) -> tuple[str, ...] | None:
    """The server names the file's server blocks declare, or ``None`` when unsupported.

    Only ``server_name`` values directly inside a ``server`` block are read; every other
    directive and value is ignored (docs/adr/0015-recognize-only-the-convention.md).
    """
    events = _nginx_events(text)
    if events is None:
        return None
    names: list[str] = []
    for kind, blocks, tokens in events:
        if kind != "stmt" or not blocks or blocks[-1] != "server":
            continue
        if tokens[0] != "server_name":
            continue
        declared = [name for name in tokens[1:] if name]
        if len(tokens) - 1 > MAX_SERVER_NAMES:
            return None
        if any(SERVER_NAME.fullmatch(name) is None for name in declared):
            return None
        names.extend(name for name in declared if name not in names)
    return tuple(names)


# A site pool's fixed settings (docs/site-conventions.md#supported-configuration-grammar).
# The identity values depend on the identifier; render_pool composes them with these.
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
