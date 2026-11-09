"""The result-line section of the native contract (docs/server-jobs.md, ADR 0035).

The result reader in :mod:`operations.engine` owns the line's fields, classes and site
grammar, and :mod:`operations.reasons` owns the reason vocabulary. This section reads both
rather than repeating them. Registered kinds and bodies appear only after Django app
loading, so :func:`build` imports the reader and asks for the vocabulary when the manifest
is built, never at module import.
"""

from dataclasses import fields


def _wire_fields() -> list[str]:
    """The result line's reader fields, named as the JSON line names them."""
    from operations import engine

    return [
        "class" if field.name == "result_class" else field.name
        for field in fields(engine.ResultLine)
    ]


def build() -> dict[str, object]:
    """The result line and its vocabulary as one JSON-serializable mapping."""
    from operations import engine, reasons

    from .manifest import VERSION

    return {
        "prefix": engine.RESULT_PREFIX,
        "stage_prefix": engine.STAGE_PREFIX,
        "classes": sorted(engine.RESULT_CLASSES),
        "fields": _wire_fields(),
        "contract": VERSION,
        "site_pattern": engine.SITE_IDENTIFIER.pattern,
        "reasons": reasons.declared_reasons(),
    }
