"""Test support for the qualification gate (docs/v0.4-qualification.md#supported-combinations)."""

import dataclasses
from contextlib import AbstractContextManager
from unittest import mock

from . import qualification


def simulated_servers_qualified() -> AbstractContextManager[object]:
    """Open the gate for every architecture while a test runs.

    The simulated servers report amd64, which no native run qualifies yet. They exercise the
    workflows rather than the matrix, so the gate's own refusals are tested without this in
    ``test_qualification``.
    """
    opened = tuple(dataclasses.replace(item, qualified=True) for item in qualification.COMBINATIONS)
    return mock.patch.object(qualification, "COMBINATIONS", opened)
