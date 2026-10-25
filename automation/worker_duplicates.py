"""Recognise a second queue worker already running a Laravel site's jobs.

Pure text matchers for the crontab and Supervisor files; the native read evaluates them on
the server and never sends a whole crontab to the controller. A unit outside Barectl's in
the site's identity is covered by :func:`automation.duplicates.foreign_unit_problem`.
"""

from typing import Final

from .duplicates import MAX_SCAN_BYTES, names_site

WORKER_TOKENS: Final = ("queue:work",)


def names_worker(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in WORKER_TOKENS)


def crontab_line_problem(line: str, identifier: str, *, own_crontab: bool) -> str:
    if line.lstrip().startswith("#") or not names_worker(line):
        return ""
    if own_crontab or names_site(line, identifier):
        return "A hand-made crontab entry already runs queue:work for this site."
    return ""


def crontab_problem(text: str, identifier: str, *, own_crontab: bool) -> str:
    if len(text.encode("utf-8", "replace")) > MAX_SCAN_BYTES:
        return "Another worker for this site could not be checked."
    for line in text.splitlines():
        if problem := crontab_line_problem(line, identifier, own_crontab=own_crontab):
            return problem
    return ""


def supervisor_problem(text: str, identifier: str) -> str:
    if len(text.encode("utf-8", "replace")) > MAX_SCAN_BYTES:
        return "Another worker for this site could not be checked."
    header = ""
    block: list[str] = []
    for line in [*text.splitlines(), "[program:"]:
        if line.lstrip().startswith("[") and not line.lstrip().startswith("#"):
            if (
                header.lower().startswith("[program:")
                and any(names_worker(entry) for entry in block)
                and names_site("\n".join([header, *block]), identifier)
            ):
                return "A Supervisor program already runs queue:work for this site."
            header, block = line.strip(), []
            continue
        block.append(line)
    return ""


__all__ = ["crontab_problem", "names_worker", "supervisor_problem"]
