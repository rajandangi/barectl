"""The site identifier and DNS names an operator may request (docs/sites.md#names).

The form, the worker before any read and the payload builder each validate them again.
"""

import re
from collections.abc import Sequence

IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}")
# docs/sites.md#names: the distribution's own names, Barectl's and the TLS convention's.
RESERVED_IDENTIFIERS = frozenset(
    {
        "www",
        "html",
        "default",
        "php",
        "fpm",
        "nginx",
        "root",
        "admin",
        "localhost",
        "letsencrypt",
        "acme",
        "barectl",
        "apply",
        "site",
        "repo",
        "backup",
        "diagnostic",
    }
)
# docs/sites.md#names
SYSTEM_ACCOUNTS = frozenset(
    {
        "sshd",
        "syslog",
        "statd",
        "saned",
        "sssd",
        "snmp",
        "squid",
        "sddm",
        "stunnel4",
        "sasl",
        "sgx",
    }
)
MAX_NAMES = 10
MAX_NAME_OCTETS = 253
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
RESERVED_NAMES = frozenset({"localhost", "invalid"})
_ALLOWED = re.compile(r"[A-Za-z0-9.-]+")
# docs/sites.md#readiness: an absolute application path, never a URL or query.
READINESS_PATH = re.compile(r"/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)?")
MAX_READINESS_PATH = 200


class InvalidInput(ValueError):
    def __init__(self, problems: Sequence[str]) -> None:
        super().__init__(" ".join(problems))
        self.problems = tuple(problems)


def valid_identifier(identifier: str) -> bool:
    """Whether ``identifier`` is a name Barectl may record or address."""
    return not identifier_problems(identifier)


def identifier_problems(identifier: str) -> list[str]:
    if not IDENTIFIER.fullmatch(identifier):
        return [
            "Enter 3 to 24 lowercase letters and digits, starting with a letter, such as shop2."
        ]
    if identifier in RESERVED_IDENTIFIERS or f"s{identifier}" in SYSTEM_ACCOUNTS:
        return [f"{identifier} is reserved; choose another identifier."]
    return []


def readiness_path(value: str) -> tuple[str, str]:
    """The site's readiness path, or why it is refused.

    The path is non-secret serving evidence in the site's Caddy file. It is an absolute
    path with no query string, fragment or traversal segment, so every server that
    evaluates it addresses the same resource (docs/sites.md#readiness).
    """
    if len(value) > MAX_READINESS_PATH:
        return "", f"Use a readiness path of at most {MAX_READINESS_PATH} characters."
    if not READINESS_PATH.fullmatch(value):
        return "", (
            "Enter a readiness path that starts with /, such as /health. Use letters, "
            "digits, dots, underscores, tildes and hyphens, with no query string."
        )
    if any(part in {".", ".."} for part in value.split("/")):
        return "", "Enter a readiness path without . or .. segments."
    return value, ""


def readiness_ok(path: str, status: int) -> bool:
    """Whether a readiness response passes (docs/sites.md#readiness).

    The default path is the site's home page, so any answer below a server error proves
    the application responded. A path the operator chooses is deliberate, so it must
    answer exactly 200. A missing response is never a pass.
    """
    if status <= 0:
        return False
    return status == 200 if path != "/" else status < 500


def readiness_directive(path: str) -> str:
    """The Caddyfile entry that keeps the path as native evidence, empty for the default."""
    return "" if path == "/" else f'    vars readiness_path "{path}"\n'


def canonical_name(name: str) -> tuple[str, str]:
    """The canonical form of one requested DNS name, or why it is refused."""
    if not name.isascii():
        return "", f"{name}: enter the punycode (xn--) form of an international name."
    if "*" in name:
        return "", f"{name}: wildcards are not supported; list each name."
    if not _ALLOWED.fullmatch(name):
        return "", f"{name}: use only letters, digits, hyphens and dots."
    canonical = name.lower().removesuffix(".")
    labels = canonical.split(".")
    if len(canonical) > MAX_NAME_OCTETS:
        return "", f"{name}: names longer than {MAX_NAME_OCTETS} characters are not supported."
    if len(labels) < 2 or not all(LABEL.fullmatch(label) for label in labels):
        return "", f"{name}: enter a fully qualified name such as www.example.com."
    if labels[-1].isdigit():
        return "", f"{name}: IP addresses are not supported; enter a DNS name."
    if labels[-1] in RESERVED_NAMES or canonical in RESERVED_NAMES:
        return "", f"{name}: {labels[-1]} names are reserved and never reach a server."
    for label in labels:
        problem = _label_problem(label)
        if problem:
            return "", f"{name}: {problem}"
    return canonical, ""


def _label_problem(label: str) -> str:
    if label[2:4] != "--":
        return ""
    if not label.startswith("xn--"):
        return f"{label} has hyphens in the third and fourth positions, reserved for punycode."
    try:
        decoded = label[4:].encode("ascii").decode("punycode")
        valid = not decoded.isascii() and decoded.encode("idna") == label.encode("ascii")
    except UnicodeError:
        valid = False
    return "" if valid else f"{label} is not valid punycode."


def names(text: str) -> tuple[str, ...]:
    """The canonical names in ``text``, separated by whitespace, in the order given.

    Raises ``InvalidInput`` with every problem found.
    """
    requested = text.split()
    problems: list[str] = []
    found: list[str] = []
    for name in requested:
        canonical, problem = canonical_name(name)
        if problem:
            problems.append(problem)
        elif canonical in found:
            problems.append(f"{name}: listed more than once.")
        else:
            found.append(canonical)
    if not requested:
        problems.append("Enter at least one DNS name.")
    elif len(requested) > MAX_NAMES:
        problems.append(f"Enter at most {MAX_NAMES} names.")
    if problems:
        raise InvalidInput(problems)
    return tuple(found)


def request(identifier: str, text: str) -> tuple[str, tuple[str, ...]]:
    """A validated request, or ``InvalidInput`` with every problem found."""
    problems = identifier_problems(identifier)
    try:
        found = names(text)
    except InvalidInput as invalid:
        problems += invalid.problems
        found = ()
    if problems:
        raise InvalidInput(problems)
    return identifier, found
