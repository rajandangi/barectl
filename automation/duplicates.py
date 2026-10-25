"""Recognise a second scheduler already running a site's WordPress cron.

Pure text matchers, shared by native discovery and the change review. Each returns a
one-sentence finding in plain words, or an empty string, and never parses a full crontab
into the controller: the native read evaluates them on the server.
"""

import re
from typing import Final

CRON_TOKENS: Final = ("wp-cron", "cron event run")
MAX_SCAN_BYTES: Final = 262144


def _site_tokens(identifier: str) -> tuple[re.Pattern[str], ...]:
    escaped = re.escape(identifier)
    return (
        re.compile(rf"(?<![\w-]){escaped}(?![\w-])"),
        re.compile(re.escape(f"/var/www/{identifier}")),
        re.compile(rf"(?<![\w-])s{escaped}(?![\w-])"),
    )


def names_site(text: str, identifier: str) -> bool:
    return any(token.search(text) for token in _site_tokens(identifier))


def names_cron(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in CRON_TOKENS)


def crontab_line_problem(line: str, identifier: str, *, own_crontab: bool) -> str:
    """A line that runs WordPress cron for this site, as a second scheduler."""
    if line.lstrip().startswith("#") or not names_cron(line):
        return ""
    if own_crontab or names_site(line, identifier):
        return "A hand-made crontab entry already runs WordPress cron for this site."
    return ""


def crontab_problem(text: str, identifier: str, *, own_crontab: bool) -> str:
    if len(text.encode("utf-8", "replace")) > MAX_SCAN_BYTES:
        return "Another schedule for this site could not be checked."
    for line in text.splitlines():
        if problem := crontab_line_problem(line, identifier, own_crontab=own_crontab):
            return problem
    return ""


def supervisor_problem(text: str, identifier: str) -> str:
    """A Supervisor program that runs WordPress cron for this site."""
    if len(text.encode("utf-8", "replace")) > MAX_SCAN_BYTES:
        return "Another schedule for this site could not be checked."
    header = ""
    block: list[str] = []
    for line in [*text.splitlines(), "[program:"]:
        if line.lstrip().startswith("[") and not line.lstrip().startswith("#"):
            if (
                header.lower().startswith("[program:")
                and any(names_cron(entry) for entry in block)
                and names_site("\n".join([header, *block]), identifier)
            ):
                return "A Supervisor program already runs WordPress cron for this site."
            header, block = line.strip(), []
            continue
        block.append(line)
    return ""


def foreign_unit_problem(name: str, text: str, identifier: str) -> str:
    """A unit outside Barectl's that runs in the site's own account."""
    if name.startswith(("barectl-site-", "barectl-apply-")) or not name.endswith(".service"):
        return ""
    if len(text.encode("utf-8", "replace")) > MAX_SCAN_BYTES:
        return "Another service for this site could not be checked."
    for raw in text.splitlines():
        key, separator, value = raw.partition("=")
        if separator and key.strip() == "User" and value.strip() == f"s{identifier}":
            return "Another service already runs as this site's account."
    return ""
