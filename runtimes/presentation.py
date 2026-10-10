from dataclasses import dataclass

from .catalog import Architecture, Build, Kind, architecture_of, load

_LANGUAGES = {Kind.PHP: "PHP", Kind.NODE: "Node.js", Kind.TOOL: "Tool"}


@dataclass(frozen=True)
class ShownBuild:
    entry: str
    language: str
    version: str
    download_size: int
    unpacked_size: int


@dataclass(frozen=True)
class ShownCatalog:
    """The runtime catalog for one server, read from the lock alone."""

    architecture: Architecture | None
    nixpkgs: str
    runtimes: tuple[ShownBuild, ...]
    tools: tuple[ShownBuild, ...]
    # Why nothing is offered, when nothing is.
    reason: str


def shown_catalog(*, checked: bool, machine: str | None) -> ShownCatalog:
    """What this Barectl release offers a server whose ``uname -m`` reported ``machine``;
    ``checked`` is whether any connection check has published an observation."""
    catalog = load()
    if not machine:
        return ShownCatalog(
            None,
            catalog.nixpkgs,
            (),
            (),
            "The last connection check did not identify the server's architecture, which "
            "the catalog depends on."
            if checked
            else "Check the connection first: the catalog depends on the server's architecture.",
        )
    architecture = architecture_of(machine)
    if architecture is None:
        return ShownCatalog(
            None,
            catalog.nixpkgs,
            (),
            (),
            f"Barectl offers no runtimes for the {machine} architecture.",
        )
    builds = catalog.offered(architecture)
    return ShownCatalog(
        architecture,
        catalog.nixpkgs,
        tuple(_shown(b) for b in builds if b.kind != Kind.TOOL),
        tuple(_shown(b) for b in builds if b.kind == Kind.TOOL),
        "",
    )


def _shown(build: Build) -> ShownBuild:
    return ShownBuild(
        build.entry, _LANGUAGES[build.kind], build.version, build.download_size, build.closure_size
    )
