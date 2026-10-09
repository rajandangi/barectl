"""Test support for the qualification gate (docs/v0.4-qualification.md#supported-combinations)."""

import dataclasses
from contextlib import AbstractContextManager
from unittest import mock

from . import qualification


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
