"""The native contract version (docs/contracts.md, ADR 0042).

This module has no imports so the change engine and the contract manifest can both read
the version without loading the manifest's section builders.
"""

from typing import Final

VERSION: Final = 1
