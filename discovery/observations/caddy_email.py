"""The certificate contact email as Caddy's main configuration renders it (#444).

docs/tls.md#certificate-contact-email. Discovery reads the one non-secret global option
Barectl manages; the change kind renders it back. This module stays independent of the
change engine so a full discovery can read it without importing the kinds.
"""

import re
from typing import Final

from ..ssh import RemoteShell

MAIN_PATH: Final = "/etc/caddy/Caddyfile"
# The main configuration is a few hundred bytes; this bound keeps a review and its native
# argument small.
MAX_TEXT: Final = 8192

ABSENT: Final = "absent"
SET: Final = "set"
OUTSIDE: Final = "outside"
UNREADABLE: Final = "unreadable"

# One optional address. Only characters that cannot alter a Caddyfile token are accepted:
# the local part is bounded, and every domain label starts and ends with an alphanumeric.
EMAIL = re.compile(
    r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
)


def valid_email(value: str) -> bool:
    """An empty value removes the line; otherwise a single bare address."""
    return not value or (len(value) <= 254 and EMAIL.fullmatch(value) is not None)


def read_main(shell: RemoteShell) -> str | None:
    """The rendered main configuration, a small world-readable native file."""
    result = shell.run(f"cat {MAIN_PATH}")
    if result.exit_status != 0 or result.truncated:
        return None
    return result.stdout


def read(shell: RemoteShell) -> tuple[str, str]:
    """The setting's discovery state and value from the rendered main configuration."""
    text = read_main(shell)
    if text is None:
        return UNREADABLE, ""
    return email_state(text)


def _block(lines: list[str]) -> tuple[int, int] | None:
    """The bounds of the leading global options block, or ``None`` for another shape.

    The supported main configuration indents every global option and closes the global
    block with ``}`` at column zero. A top-level line inside the block is foreign text or
    the start of a site, so the shape is refused rather than guessed.
    """
    if not lines or lines[0].strip() != "{":
        return None
    depth = 0
    for index in range(len(lines)):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#"):
            continue
        if index and depth == 1 and not lines[index][0].isspace() and stripped != "}":
            return None
        if stripped.endswith("{"):
            depth += 1
        elif stripped.startswith("}"):
            depth -= 1
            if depth == 0:
                return (0, index) if stripped == "}" else None
    return None


def email_lines(lines: list[str]) -> tuple[int, int, list[int]] | None:
    """The block's bounds and the indices of its top-level ``email`` lines."""
    bounds = _block(lines)
    if bounds is None:
        return None
    start, end = bounds
    depth = 0
    found: list[int] = []
    for index in range(start, end + 1):
        stripped = lines[index].strip()
        if stripped.startswith("#"):
            continue
        if stripped.endswith("{"):
            depth += 1
        elif stripped.startswith("}"):
            depth -= 1
        elif depth == 1 and re.match(r"email(?:\s|$)", stripped):
            found.append(index)
    return start, end, found


def email_state(text: str) -> tuple[str, str]:
    """``(state, value)`` from the rendered main configuration."""
    if len(text.encode()) > MAX_TEXT:
        return OUTSIDE, ""
    lines = text.splitlines(keepends=True)
    found = email_lines(lines)
    if found is None:
        return OUTSIDE, ""
    _, _, indices = found
    if not indices:
        return ABSENT, ""
    if len(indices) > 1:
        return OUTSIDE, ""
    match = re.fullmatch(r"[ \t]*email[ \t]+(\S+)[ \t]*", lines[indices[0]].rstrip("\r\n"))
    if match is None:
        return OUTSIDE, ""
    value = match[1]
    return (SET, value) if valid_email(value) else (OUTSIDE, "")
