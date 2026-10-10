"""Test support for the qualification gate (docs/v0.4-qualification.md#supported-combinations)."""

import dataclasses
from contextlib import AbstractContextManager
from unittest import mock

from . import qualification


def source_candidate_qualified(
    version: str, architecture: str, branch: str
) -> AbstractContextManager[object]:
    """Admit one explicit source candidate to gather its native evidence."""
    if version not in {"24.04", "26.04"} or architecture not in {"amd64", "arm64"}:
        raise ValueError("Unknown native WordPress candidate.")
    if branch not in {"8.3", "8.4", "8.5"}:
        raise ValueError("Unknown native WordPress branch.")
    candidate = (version, architecture, branch, "sury")
    return mock.patch.object(
        qualification,
        "SOURCE_COMBINATIONS",
        qualification.SOURCE_COMBINATIONS
        if candidate in qualification.SOURCE_COMBINATIONS
        else (*qualification.SOURCE_COMBINATIONS, candidate),
    )


def simulated_servers_qualified() -> AbstractContextManager[object]:
    """Admit the listed candidate combinations while a simulated workflow runs.

    The simulated servers report amd64, which production admission disables. They exercise the
    workflows rather than the matrix, so the gate's own refusals are tested without this in
    ``test_qualification``.
    """
    return native_candidates_qualified()


def native_candidates_qualified() -> AbstractContextManager[object]:
    """Disabled candidates need admission to collect native qualification evidence.

    See docs/v0.4-qualification.md#supported-combinations for the production gate.
    """
    opened = tuple(dataclasses.replace(item, qualified=True) for item in qualification.COMBINATIONS)
    return mock.patch.object(qualification, "COMBINATIONS", opened)
