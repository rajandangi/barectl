"""The machine-readable native contract and its section registry (ADR 0042).

Each section is one module that states the shapes that module owns in the native
convention it implements. Add a section by writing one ``contract/<area>.py`` module that
exposes ``build() -> dict[str, object]`` and appending one :class:`Section` entry to
:data:`SECTIONS`; no other code changes. The later backend/result and application-surface
sections follow that seam. ``contract/manifest.json`` pins the result for review, and
``contract/test_contract.py`` fails a change to a promised shape unless the version and
the pinned file change together.

The contract is not a server-side inventory. It describes the native shapes discovered on
a managed server, and it never becomes fallback authority when discovery cannot read one.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from . import foundation, site_convention

VERSION: Final = 1


@dataclass(frozen=True)
class Section:
    """One named part of the contract, built by the module that owns its area."""

    name: str
    build: Callable[[], dict[str, object]]


SECTIONS: Final[tuple[Section, ...]] = (
    Section("site_convention", site_convention.build),
    Section("foundation", foundation.build),
)


def manifest() -> dict[str, object]:
    """The complete contract: the version plus one entry per registered section."""
    return {"version": VERSION, **{section.name: section.build() for section in SECTIONS}}
