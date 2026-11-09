"""Barectl's versioned native contract (docs/contracts.md, ADR 0042).

The contract version names the native shapes a controller reads and writes. It is carried
in the ``barectl-result`` line, never in a file on the managed server.
"""

from .manifest import VERSION, manifest

__all__ = ["VERSION", "manifest"]
