"""Which observed contract versions this controller may act on (ADR 0042, #536).

Every change's result line carries the native contract version. A controller that reads a
version it does not recognize must report the server as outside supported settings and
refuse every change rather than guess at the native shape. This module is the one pure
rule; discovery and preparation only supply the observed versions and the host standing.
"""

from collections.abc import Iterable
from enum import StrEnum

from bootstrap.standing import Standing

from .version import VERSION


class Recognition(StrEnum):
    """How this controller reads the contract versions a server's runs recorded."""

    RECOGNIZED = "recognized"
    TOO_NEW = "too_new"
    TOO_OLD = "too_old"


def recognize(
    observed: Iterable[int],
    standing: str | None,
    *,
    version: int = VERSION,
) -> Recognition:
    """Whether ``observed`` versions contain a shape this controller cannot act on.

    A zero is a result line written before the field existed: v0.4.0 wrote none and is
    contract 1, so it is compatible. No result lines establish no version and are never
    unrecognized. A host that is already not manageable keeps its existing refusal, so
    the recognition rule does not replace it.
    """
    if standing == Standing.NOT_MANAGEABLE:
        return Recognition.RECOGNIZED
    contracts = tuple(observed)
    if any(value > version for value in contracts):
        return Recognition.TOO_NEW
    if any(0 < value < version for value in contracts):
        return Recognition.TOO_OLD
    return Recognition.RECOGNIZED
