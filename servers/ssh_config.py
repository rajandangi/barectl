"""Read the controller host's SSH aliases as Barectl's SSH backend will resolve them.

The planned backend is pyinfra's SSH connector. pyinfra 3.10 reads a single user
configuration file (``~/.ssh/config`` unless another file is given), expands ``Include``
and strips inline comments itself, then parses and looks up hosts with paramiko's
``SSHConfig``. This adapter mirrors that pre-processing and uses paramiko for parsing and
lookup, so every alias it offers resolves the same way when the connector uses it.

Barectl only reads the configuration. It never writes SSH configuration, trust records or
key files. See docs/ssh-aliases.md for supported and unsupported features.
"""

import glob
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import TextIO

from paramiko import SSHConfig
from paramiko.ssh_exception import ConfigParseError, CouldNotCanonicalize

# paramiko's own keyword pattern, which pyinfra also uses to find Include lines.
SETTING = re.compile(r"(\w+)(?:\s*=\s*|\s+)(.+)")
# Aliases are later passed to the SSH backend as host names. Refuse anything that could be
# read as an option or needs quoting.
ALIAS = re.compile(r"\A[A-Za-z0-9_][A-Za-z0-9._-]*\Z")
ALIAS_MAX_LENGTH = 253
PATTERN_CHARACTERS = frozenset("*?!")
MAX_PORT = 65535


class _ConfigProblem(Exception):
    """A sanitized, operator-facing description of an unusable configuration."""


@dataclass(frozen=True)
class SkippedEntry:
    """A Host entry that is not offered as a server, with the reason."""

    name: str
    reason: str


@dataclass(frozen=True)
class AliasCatalog:
    """Concrete aliases offered for registration, read at one point in time."""

    source: str
    aliases: tuple[str, ...] = ()
    skipped: tuple[SkippedEntry, ...] = ()
    # Set when the configuration as a whole cannot be used; then no aliases are offered.
    problem: str = ""
    _lookup: frozenset[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_lookup", frozenset(self.aliases))

    def __contains__(self, alias: object) -> bool:
        return alias in self._lookup


def load_aliases(source: str) -> AliasCatalog:
    """Read the SSH configuration at ``source`` (``~`` is expanded).

    ``source`` is shown to the operator in guidance, so pass the configured value rather
    than an expanded home directory path.
    """
    try:
        config = _parse(Path(source).expanduser(), source)
        aliases, skipped = _classify(config)
    except _ConfigProblem as problem:
        return AliasCatalog(source=source, problem=str(problem))
    return AliasCatalog(source=source, aliases=aliases, skipped=skipped)


def _parse(path: Path, source: str) -> SSHConfig:
    try:
        with path.open(encoding="utf-8") as file:
            lines = list(_expand(file, path, []))
    except FileNotFoundError:
        raise _ConfigProblem(f"No SSH configuration file exists at {source}.") from None
    except OSError, UnicodeDecodeError:
        raise _ConfigProblem(f"Barectl cannot read the SSH configuration at {source}.") from None
    if any(_keyword(line) == "match" for line in lines):
        # paramiko evaluates Match conditions during every lookup, including `Match exec`
        # commands, and cannot list the hosts they select.
        raise _ConfigProblem(
            f"The SSH configuration at {source} uses Match blocks, which Barectl does not "
            "support. Define each server in a Host block instead."
        )
    config = SSHConfig()
    try:
        config.parse(lines)
    except ConfigParseError:
        # The message quotes the configuration line; do not repeat it to the browser.
        raise _ConfigProblem(
            f"The SSH configuration at {source} contains a line Barectl cannot parse."
        ) from None
    return config


def _expand(file: TextIO, path: Path, included: list[Path]) -> Iterator[str]:
    """Yield configuration lines with includes expanded, as pyinfra 3.10 does.

    Relative include paths are resolved against the including file's directory, matches
    are read in directory order, and a file included twice is rejected as a loop.
    """
    for raw in file:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = _strip_inline_comment(line)
        match = SETTING.match(line)
        if not match or match.group(1).lower() != "include":
            yield line
            continue
        pattern = match.group(2)
        if not pattern.startswith(("/", "~")):
            pattern = str(path.parent / pattern)
        for name in glob.iglob(str(Path(pattern).expanduser())):
            child = Path(name)
            if not child.is_file():
                continue
            if child in included:
                raise _ConfigProblem("The SSH configuration includes the same file more than once.")
            included.append(child)
            with child.open(encoding="utf-8") as child_file:
                yield from _expand(child_file, child, included)


def _strip_inline_comment(line: str) -> str:
    """Remove a `` #`` comment outside quotes, matching pyinfra 3.10."""
    quote = ""
    for index, character in enumerate(line):
        if character in "\"'" and not quote:
            quote = character
        elif character == quote:
            quote = ""
        elif character == "#" and not quote and index and line[index - 1] in " \t":
            return line[:index].rstrip()
    return line


def _keyword(line: str) -> str:
    match = SETTING.match(line)
    return match.group(1).lower() if match else ""


def _classify(config: SSHConfig) -> tuple[tuple[str, ...], tuple[SkippedEntry, ...]]:
    names = config.get_hostnames()
    negations = [name[1:] for name in names if name.startswith("!")]
    aliases: list[str] = []
    skipped: list[SkippedEntry] = []
    for name in sorted(names - {"*"}):
        reason = _unusable_reason(config, name, negations)
        if reason:
            skipped.append(SkippedEntry(name, reason))
        else:
            aliases.append(name)
    return tuple(aliases), tuple(skipped)


def _unusable_reason(config: SSHConfig, name: str, negations: Iterable[str]) -> str:
    if PATTERN_CHARACTERS.intersection(name):
        return "A pattern, not a single server."
    if len(name) > ALIAS_MAX_LENGTH or not ALIAS.match(name):
        return "Contains characters Barectl does not accept in an alias."
    if any(fnmatch(name, pattern) for pattern in negations):
        return "Excluded by a negated Host pattern."
    try:
        options = config.lookup(name)
    except ConfigParseError, CouldNotCanonicalize:
        return "Its settings could not be resolved."
    port = options.get("port", "22")
    if not port.isdigit() or not 1 <= int(port) <= MAX_PORT:
        return "Its Port setting is not a valid port number."
    return ""
