"""Quarantine marker for intermittently failing tests (docs/quality.md#quarantine).

A test that fails intermittently is never retried automatically; it is marked with its
issue, owner and the date it was quarantined. The meta-test in ``disposable.test_quarantine``
fails when a marker's issue is closed, is not labelled ``flaky``, or is older than 14 days,
so a quarantine is fixed or the test deleted rather than left to run red forever.
"""

import datetime
import json
import subprocess
import unittest
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import TypeVar

Attribute = TypeVar("Attribute")
_MARKER = "_barectl_quarantine"
# docs/adr/0033-prove-real-behavior-in-two-test-layers.md: fixed or deleted within 14 days.
LIMIT = datetime.timedelta(days=14)
FLAKY_LABEL = "flaky"


@dataclass(frozen=True)
class Marker:
    issue: int
    owner: str
    since: datetime.date

    def age(self, today: datetime.date) -> datetime.timedelta:
        return today - self.since


def quarantine(issue: int, *, owner: str, since: str) -> Callable[[Attribute], Attribute]:
    """Mark a test class or method as quarantined; ``since`` is an ISO date."""

    def decorate(attribute: Attribute) -> Attribute:
        setattr(attribute, _MARKER, Marker(issue, owner, datetime.date.fromisoformat(since)))
        return attribute

    return decorate


def marker_of(attribute: object) -> Marker | None:
    value = getattr(attribute, _MARKER, None)
    return value if isinstance(value, Marker) else None


def marker_for(test: unittest.TestCase) -> Marker | None:
    return marker_of(type(test)) or marker_of(getattr(test, test._testMethodName, None))


def marked_tests(suite: unittest.TestSuite | unittest.TestCase) -> Iterator[tuple[str, Marker]]:
    if isinstance(suite, unittest.TestCase):
        marker = marker_for(suite)
        if marker is not None:
            yield suite.id(), marker
        return
    for member in suite:
        yield from marked_tests(member)


def issue_is_open_flaky(issue: int, *, repository: str) -> bool:
    """Whether GitHub reports ``issue`` open and labelled ``flaky``."""
    completed = subprocess.run(  # noqa: S603 - fixed gh invocation
        ["gh", "api", f"repos/{repository}/issues/{issue}"],  # noqa: S607 - gh on PATH
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"gh could not read issue {issue}: {completed.stderr.strip()}")
    document: object = json.loads(completed.stdout)
    if not isinstance(document, dict):
        raise RuntimeError(f"issue {issue} is not a JSON object.")
    labels = document.get("labels")
    names = {label.get("name") for label in labels or [] if isinstance(label, dict)}
    return document.get("state") == "open" and FLAKY_LABEL in names
