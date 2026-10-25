"""The automation body helpers, assembled into every staged body that needs them.

A body runs as one standalone Python program on the server, so the helpers it shares with
:mod:`automation.bodies.units` arrive as source text rather than an import (the site bodies'
assembled programs do the same). Every kind that fences or publishes units appends
:data:`AUTOMATION_SOURCE` to its own body source.
"""

import importlib.resources
from typing import Final

# Modules the assembled program receives from its own concatenated neighbours.
_IMPORTS: Final = ("sites.bodies.common", "automation.convention", "automation.bodies.units")


def without_imports(text: str, modules: tuple[str, ...] = _IMPORTS) -> str:
    """Drop the imports the assembled body receives from its concatenated neighbours."""
    kept: list[str] = []
    skipping = False
    for line in text.splitlines():
        if any(line.startswith(f"from {module} import") for module in modules):
            skipping = line.rstrip().endswith("(")
            continue
        if skipping:
            skipping = not line.strip().endswith(")")
            continue
        kept.append(line)
    return "\n".join(kept)


AUTOMATION_SOURCE: Final = (
    importlib.resources.files("automation").joinpath("convention.py").read_text()
    + "\n"
    + without_imports(
        importlib.resources.files("automation.bodies").joinpath("units.py").read_text()
    )
)
