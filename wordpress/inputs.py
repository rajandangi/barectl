"""The bounded application metadata an installation review accepts.

docs/wordpress.md#installation-review. The form, the worker before any read and a later
apply each validate these again; no value here is a password, a version or a command.
"""

import re
import unicodedata
from dataclasses import dataclass
from typing import Final
from urllib.parse import SplitResult, urlsplit

from sites import names as site_names

MAX_TITLE: Final = 100
LOGIN: Final = re.compile(r"[a-z0-9][a-z0-9_.-]{2,59}")
EMAIL: Final = re.compile(
    r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
)
MAX_EMAIL: Final = 100
_FORBIDDEN_TITLE = frozenset("<>\\")


@dataclass(frozen=True)
class Metadata:
    canonical_name: str
    title: str
    admin_login: str
    admin_email: str


def https_name(text: str) -> tuple[str, str]:
    """The one canonical host name of a root-path HTTPS address, or why it is refused.

    A bare name is read as ``https://<name>``; credentials, ports, paths, queries and
    fragments are refused rather than trimmed.
    """
    text = text.strip()
    if not text:
        return "", "Enter the canonical HTTPS name, such as www.example.com."
    if any(character.isspace() or ord(character) < 32 for character in text):
        return "", "The address must not contain spaces or control characters."
    if "://" not in text:
        text = f"https://{text}"
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        return "", "Enter a valid HTTPS name such as www.example.com."
    problem = _address_problem(parts, text)
    if problem or not host:
        return "", problem or "Enter a DNS name; IP addresses are not supported."
    return site_names.canonical_name(host)


def _address_problem(parts: SplitResult, text: str) -> str:
    netloc = parts.netloc
    if parts.scheme.lower() != "https":
        return "WordPress is installed on an HTTPS address; enter https:// or only the name."
    if "@" in netloc:
        return "The address must not contain credentials."
    if "[" in netloc:
        return "Enter a DNS name; IP addresses are not supported."
    if ":" in netloc:
        return "Only the standard HTTPS port is supported; remove the port."
    if parts.query or "?" in text:
        return "The address must not contain a query."
    if parts.fragment or "#" in text:
        return "The address must not contain a fragment."
    if parts.path not in ("", "/"):
        return "WordPress is installed at the root of the name; remove the path."
    return ""


def title_problem(title: str) -> str:
    if title != title.strip() or not title:
        return "Enter a site title without leading or trailing spaces."
    if len(title) > MAX_TITLE:
        return f"Use at most {MAX_TITLE} characters."
    for character in title:
        if unicodedata.category(character).startswith("C") or character in _FORBIDDEN_TITLE:
            return "The title must not contain control characters, <, > or backslashes."
    return ""


def login_problem(login: str) -> str:
    if not LOGIN.fullmatch(login):
        return (
            "Enter 3 to 60 lowercase letters, digits, dots, underscores or hyphens, "
            "starting with a letter or digit."
        )
    return ""


def email_problem(email: str) -> str:
    if len(email) > MAX_EMAIL or not EMAIL.fullmatch(email):
        return f"Enter a plain email address of at most {MAX_EMAIL} characters."
    return ""


def problems(metadata: Metadata) -> list[str]:
    """Every problem with already-recorded metadata; empty when it is valid."""
    name, name_problem = https_name(metadata.canonical_name)
    found = [name_problem] if name_problem else []
    if not name_problem and name != metadata.canonical_name:
        found.append("The canonical name is not recorded in its canonical form.")
    found += [
        problem
        for problem in (
            title_problem(metadata.title),
            login_problem(metadata.admin_login),
            email_problem(metadata.admin_email),
        )
        if problem
    ]
    return found
