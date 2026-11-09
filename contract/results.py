"""The result-line section of the native contract (docs/server-jobs.md, ADR 0035).

The result reader in :mod:`operations.engine` owns the line's fields, classes and site
grammar, and :mod:`operations.reasons` owns the reason vocabulary. This section reads both
rather than repeating them. Registered kinds and bodies appear only after Django app
loading, so :func:`build` imports the reader and asks for the vocabulary when the manifest
is built, never at module import.
"""

from dataclasses import fields
from typing import Final

# The stage marker is written and read by the engine's progress parser
# (operations.engine.parse_progress) and by every native body (operations.engine).
STAGE_PREFIX: Final = "barectl-stage "


def _wire_fields() -> list[str]:
    """The result line's reader fields, named as the JSON line names them."""
    from operations import engine

    names = [
        "class" if field.name == "result_class" else field.name
        for field in fields(engine.ResultLine)
    ]
    # #536 adds the version field to the reader and the engine's writer. The contract
    # already promises its name and value so a later ticket fills it in without a shape
    # change here.
    if "contract" not in names:
        names.append("contract")
    return names


def build() -> dict[str, object]:
    """The result line and its vocabulary as one JSON-serializable mapping."""
    from operations import engine, reasons

    from .manifest import VERSION

    return {
        "prefix": engine.RESULT_PREFIX,
        "stage_prefix": STAGE_PREFIX,
        "classes": sorted(engine.RESULT_CLASSES),
        "fields": _wire_fields(),
        "contract": VERSION,
        "site_pattern": engine.SITE_IDENTIFIER.pattern,
        "reasons": reasons.declared_reasons(),
    }
