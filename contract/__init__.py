"""Barectl's versioned native contract (docs/contracts.md, ADR 0042).

The contract version names the native shapes a controller reads and writes. It is carried
in the ``barectl-result`` line, never in a file on the managed server. This package's
``__init__`` stays import-light so the change engine can read :data:`VERSION` without
loading the manifest's section builders, which import the apps the engine belongs to.
"""

from .version import VERSION

__all__ = ["VERSION"]
