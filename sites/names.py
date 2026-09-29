"""The site identifier and DNS names an operator may request (docs/sites.md#names).

The form, the worker before any read and the payload builder each validate them again.
"""

import re
from collections.abc import Sequence

from discovery.observations.sites import RESERVED as DISCOVERY_RESERVED

IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}")
# docs/sites.md#names: the distribution's own names, Barectl's and the TLS convention's.
RESERVED_IDENTIFIERS = DISCOVERY_RESERVED | frozenset(
    {
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
    }
)
# System accounts that Ubuntu's base-passwd or packages in main create; a site user
# s<identifier> must never take one of their names before the package does.
SYSTEM_ACCOUNTS = frozenset(
    {"sshd", "syslog", "statd", "saned", "sssd", "snmp", "squid", "sddm", "stunnel4", "sasl"}
)
MAX_NAMES = 10
# docs/sites.md#names: the longest name stock Nginx loads beside the default site.
MAX_NAME_OCTETS = 46
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
RESERVED_NAMES = frozenset({"localhost", "invalid"})
_ALLOWED = re.compile(r"[A-Za-z0-9.-]+")


class InvalidInput(ValueError):
    def __init__(self, problems: Sequence[str]) -> None:
        super().__init__(" ".join(problems))
        self.problems = tuple(problems)


def identifier_problems(identifier: str) -> list[str]:
    if not IDENTIFIER.fullmatch(identifier):
        return [
            "Enter 3 to 24 lowercase letters and digits, starting with a letter, such as shop2."
        ]
    if identifier in RESERVED_IDENTIFIERS or f"s{identifier}" in SYSTEM_ACCOUNTS:
        return [f"{identifier} is reserved; choose another identifier."]
    return []


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
