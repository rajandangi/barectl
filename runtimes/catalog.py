"""Barectl's runtime catalog lock: docs/adr/0028-supply-runtimes-and-tools-from-pinned-nix.md.

The lock is generated, never edited by hand (docs/quality.md#runtime-catalog-lock). Every
build it names is either offered, from the current nixpkgs revision, or retired: kept so
that servers still running it are recognized, but never offered again.
"""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from pathlib import Path

LOCK_PATH = Path(__file__).with_name("catalog_lock.json")
FORMAT = 1


class Architecture(StrEnum):
    X86_64 = "x86_64-linux"
    AARCH64 = "aarch64-linux"


_MACHINES = {"x86_64": Architecture.X86_64, "aarch64": Architecture.AARCH64}


def architecture_of(machine: str) -> Architecture | None:
    """The catalog architecture of ``uname -m``'s machine name, if Barectl supplies it."""
    return _MACHINES.get(machine)


class Kind(StrEnum):
    PHP = "php"
    NODE = "node"
    TOOL = "tool"


@dataclass(frozen=True)
class Build:
    entry: str
    kind: Kind
    architecture: Architecture
    path: str
    version: str
    # Bytes of the unpacked closure, and of the compressed archives a server downloads
    # when nothing in the closure is present yet.
    closure_size: int
    download_size: int
    nixpkgs: str
    retired: bool


@dataclass(frozen=True)
class Installer:
    version: str
    architecture: Architecture
    url: str
    sha256: str


class CatalogLockError(ValueError):
    pass


@dataclass(frozen=True)
class Catalog:
    nixpkgs: str
    builds: tuple[Build, ...]
    installers: tuple[Installer, ...]

    def offered(self, architecture: Architecture) -> tuple[Build, ...]:
        """The builds a server of ``architecture`` may install, by kind and entry name."""
        return tuple(
            sorted(
                (b for b in self.builds if b.architecture == architecture and not b.retired),
                key=lambda build: (list(Kind).index(build.kind), build.entry),
            )
        )

    def identify(self, architecture: Architecture, path: str) -> Build | None:
        """The offered or retired build at ``path``; ``None`` when Barectl does not know it."""
        return next(
            (b for b in self.builds if b.architecture == architecture and b.path == path), None
        )

    def installer(self, architecture: Architecture) -> Installer:
        return next(i for i in self.installers if i.architecture == architecture)


@cache
def load() -> Catalog:
    return parse(LOCK_PATH.read_text(encoding="utf-8"))


_ENTRY = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_REVISION = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
# https://nix.dev/manual/nix/latest/store/store-path
_STORE_PATH = re.compile(r"/nix/store/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]{1,180}")
_VERSION = re.compile(r"[0-9A-Za-z.+_-]{1,64}")
_INSTALLER_URL = "https://releases.nixos.org/nix/nix-{version}/nix-{version}-{architecture}.tar.xz"


def installer_url(version: str, architecture: Architecture) -> str:
    return _INSTALLER_URL.format(version=version, architecture=architecture)


def parse(text: str) -> Catalog:
    """The catalog in ``text``, refused with :class:`CatalogLockError` unless well formed."""
    try:
        data: object = json.loads(text)
    except ValueError as error:
        raise CatalogLockError(f"The catalog lock is not JSON: {error}") from error
    lock = _fields(data, "the catalog lock", ("format", "nixpkgs", "nix", "entries", "retired"))
    if lock["format"] != FORMAT:
        raise CatalogLockError(f"The catalog lock format is not {FORMAT}.")
    nixpkgs = _matching(lock["nixpkgs"], _REVISION, "nixpkgs")
    installers = _installers(lock["nix"])
    builds = [*_offered(lock["entries"], nixpkgs), *_retired(lock["retired"])]
    seen: set[tuple[Architecture, str]] = set()
    for build in builds:
        key = (build.architecture, build.path)
        if key in seen:
            raise CatalogLockError(f"{build.path} is listed more than once.")
        seen.add(key)
    return Catalog(nixpkgs, tuple(builds), installers)


def _installers(value: object) -> tuple[Installer, ...]:
    nix = _fields(value, "nix", ("version", "installers"))
    version = _matching(nix["version"], _VERSION, "the Nix version")
    by_architecture = _per_architecture(nix["installers"], "the Nix installers")
    installers = []
    for architecture, item in by_architecture.items():
        fields = _fields(item, f"the {architecture} Nix installer", ("url", "sha256"))
        if fields["url"] != installer_url(version, architecture):
            raise CatalogLockError(f"The {architecture} Nix installer URL is not the release's.")
        installers.append(
            Installer(
                version,
                architecture,
                installer_url(version, architecture),
                _matching(fields["sha256"], _SHA256, f"the {architecture} installer SHA-256"),
            )
        )
    return tuple(installers)


def _offered(value: object, nixpkgs: str) -> list[Build]:
    builds = []
    for entry, item in _mapping(value, "entries").items():
        _matching(entry, _ENTRY, "an entry name")
        fields = _fields(item, entry, ("kind", "builds"))
        kind = _kind(fields["kind"], entry)
        for architecture, build in _per_architecture(fields["builds"], entry).items():
            builds.append(_build(build, entry, kind, architecture, nixpkgs, retired=False))
    return builds


def _retired(value: object) -> list[Build]:
    if not isinstance(value, list):
        raise CatalogLockError("retired must be a list.")
    builds = []
    for item in value:
        fields = _mapping(item, "a retired build")
        entry = _matching(fields.get("entry"), _ENTRY, "a retired entry name")
        kind = _kind(fields.get("kind"), entry)
        architecture = _architecture(fields.get("architecture"))
        nixpkgs = _matching(fields.get("nixpkgs"), _REVISION, f"{entry}'s nixpkgs")
        rest = {k: v for k, v in fields.items() if k not in ("entry", "kind", "architecture")}
        builds.append(_build(rest, entry, kind, architecture, nixpkgs, retired=True))
    return builds


_BUILD_FIELDS = ("path", "version", "closure_size", "download_size")


def _build(
    value: object,
    entry: str,
    kind: Kind,
    architecture: Architecture,
    nixpkgs: str,
    *,
    retired: bool,
) -> Build:
    what = f"{entry} for {architecture}"
    fields = _fields(value, what, (*_BUILD_FIELDS, "nixpkgs") if retired else _BUILD_FIELDS)
    return Build(
        entry,
        kind,
        architecture,
        _matching(fields["path"], _STORE_PATH, f"{what}'s store path"),
        _matching(fields["version"], _VERSION, f"{what}'s version"),
        _size(fields["closure_size"], f"{what}'s closure size"),
        _size(fields["download_size"], f"{what}'s download size"),
        nixpkgs,
        retired,
    )


def _per_architecture(value: object, what: str) -> dict[Architecture, object]:
    items = _mapping(value, what)
    if set(items) != set(Architecture):
        raise CatalogLockError(f"{what} must name exactly {', '.join(Architecture)}.")
    return {Architecture(name): item for name, item in items.items()}


def _mapping(value: object, what: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise CatalogLockError(f"{what} must be an object.")
    return {str(key): item for key, item in value.items()}


def _fields(value: object, what: str, names: tuple[str, ...]) -> Mapping[str, object]:
    fields = _mapping(value, what)
    if set(fields) != set(names):
        raise CatalogLockError(f"{what} must have exactly the fields {', '.join(names)}.")
    return fields


def _matching(value: object, pattern: re.Pattern[str], what: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise CatalogLockError(f"{what} is not valid.")
    return value


def _kind(value: object, entry: str) -> Kind:
    if value not in tuple(Kind):
        raise CatalogLockError(f"{entry}'s kind is not one of {', '.join(Kind)}.")
    return Kind(str(value))


def _architecture(value: object) -> Architecture:
    if value not in tuple(Architecture):
        raise CatalogLockError(f"{value!r} is not a catalog architecture.")
    return Architecture(str(value))


def _size(value: object, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise CatalogLockError(f"{what} must be a positive whole number of bytes.")
    return value
