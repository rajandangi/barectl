"""Read the controller host's SSH aliases as Barectl's SSH backend will resolve them.

The planned backend is pyinfra's SSH connector. pyinfra 3.10 reads a single user
configuration file (``~/.ssh/config`` unless another file is given), expands ``Include``
and strips inline comments itself, then parses and looks up hosts with paramiko's
``SSHConfig``. This adapter mirrors that pre-processing and uses paramiko for parsing and
lookup, so every alias it offers resolves the same way when the connector uses it.

Barectl only reads the configuration. It never writes SSH configuration, trust records or
key files. See docs/ssh-aliases.md for supported and unsupported features, and
docs/ssh-connections.md for the settings a connection uses.
"""

import glob
from collections.abc import Collection, Iterable, Iterator
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import TextIO

from paramiko import SSHConfig, SSHConfigDict
from paramiko.ssh_exception import ConfigParseError, CouldNotCanonicalize

from .aliases import ALIAS, ALIAS_MAX_LENGTH

# paramiko's keyword pattern, which pyinfra also uses to find Include lines.
SETTING = SSHConfig.SETTINGS_REGEX
PATTERN_CHARACTERS = frozenset("*?!")
MAX_PORT = 65535
# OpenSSH's default user trust records.
DEFAULT_KNOWN_HOSTS = ("~/.ssh/known_hosts", "~/.ssh/known_hosts2")
# Settings that change how OpenSSH reaches or authenticates a server, which Barectl's
# connection does not implement. An alias using one is refused rather than connected
# differently from `ssh`. Each maps to the values that mean OpenSSH's default behavior.
UNSUPPORTED_SETTINGS = {
    "certificatefile": ("CertificateFile", ()),
    "hostkeyalias": ("HostKeyAlias", ()),
    "identitiesonly": ("IdentitiesOnly", ("no",)),
    "identityagent": ("IdentityAgent", ("ssh_auth_sock",)),
    "pkcs11provider": ("PKCS11Provider", ("none",)),
    "proxycommand": ("ProxyCommand", ("none",)),
    "proxyjump": ("ProxyJump", ("none",)),
    "securitykeyprovider": ("SecurityKeyProvider", ("internal",)),
}


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

    def __contains__(self, alias: object) -> bool:
        return alias in self.aliases


@dataclass(frozen=True)
class ConnectionTarget:
    """Where and as whom an alias connects, resolved from the controller configuration."""

    alias: str
    hostname: str
    port: int
    # None lets the SSH client use the controller account's user name, as OpenSSH does.
    user: str | None
    identity_files: tuple[Path, ...]
    known_hosts_files: tuple[Path, ...]


class AliasUnusable(Exception):
    """A sanitized, operator-facing reason an alias cannot be used to connect."""


def load_aliases(source: str, names: Collection[str] | None = None) -> AliasCatalog:
    """Read the SSH configuration at ``source`` (``~`` is expanded).

    ``source`` is shown to the operator in guidance, so pass the configured value rather
    than an expanded home directory path. Pass ``names`` to classify only those Host
    entries: each lookup expands tokens and can query DNS, so checking a few registered
    aliases should not resolve every entry.
    """
    try:
        config = _parse(Path(source).expanduser(), source)
        aliases, skipped = _classify(config, names)
    except _ConfigProblem as problem:
        return AliasCatalog(source=source, problem=str(problem))
    return AliasCatalog(source=source, aliases=aliases, skipped=skipped)


def resolve_alias(source: str, alias: str) -> ConnectionTarget:
    """Resolve one registered alias for connecting, reading the configuration again.

    Raises ``AliasUnusable`` when the alias is no longer offered for registration or uses a
    setting the connection does not implement.
    """
    try:
        config = _parse(Path(source).expanduser(), source)
        aliases, skipped = _classify(config, {alias})
    except _ConfigProblem as problem:
        raise AliasUnusable(str(problem)) from None
    if not aliases:
        reason = skipped[0].reason if skipped else "It is no longer a Host entry."
        raise AliasUnusable(f"The SSH alias {alias} in {source} cannot be used. {reason}")
    options = config.lookup(alias)
    unsupported = [
        name
        for key, (name, defaults) in UNSUPPORTED_SETTINGS.items()
        if key in options and options[key].lower() not in defaults
    ]
    if unsupported:
        raise AliasUnusable(
            f"The SSH alias {alias} uses {', '.join(unsupported)}, which Barectl cannot "
            "connect with. Define a Host entry without these settings."
        )
    return ConnectionTarget(
        alias=alias,
        hostname=options["hostname"],
        port=int(options.get("port", "22")),
        user=options.get("user"),
        identity_files=_identity_files(options),
        known_hosts_files=_known_hosts_files(options.get("userknownhostsfile"), alias, source),
    )


def _identity_files(options: SSHConfigDict) -> tuple[Path, ...]:
    # paramiko collects every IdentityFile value in a list, though its stubs declare str.
    values: object = options.get("identityfile")
    return _paths([str(name) for name in values] if isinstance(values, list) else [])


def _known_hosts_files(setting: str | None, alias: str, source: str) -> tuple[Path, ...]:
    names = setting.split() if setting else DEFAULT_KNOWN_HOSTS
    if any("%" in name for name in names):
        raise AliasUnusable(
            f"The SSH alias {alias} in {source} sets UserKnownHostsFile with tokens, which "
            "Barectl does not expand. Use plain file paths."
        )
    return _paths(names)


def _paths(names: Iterable[str]) -> tuple[Path, ...]:
    # "none" disables the setting in OpenSSH.
    return tuple(Path(name).expanduser() for name in names if name.lower() != "none")


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


def _classify(
    config: SSHConfig, only: Collection[str] | None
) -> tuple[tuple[str, ...], tuple[SkippedEntry, ...]]:
    names = config.get_hostnames()
    negations = [name[1:] for name in names if name.startswith("!")]
    candidates = names - {"*"} if only is None else names.intersection(only)
    aliases: list[str] = []
    skipped: list[SkippedEntry] = []
    for name in sorted(candidates):
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
