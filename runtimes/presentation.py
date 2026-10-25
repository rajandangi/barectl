from dataclasses import dataclass

from discovery.snapshot import CollectedSnapshot

from .catalog import Architecture, Build, Kind, architecture_of, load
from .observation import RuntimeObservation
from .updates import SERVICE_ENTRIES, CatalogUpdate, updates, usage_by_entry

_LANGUAGES = {Kind.PHP: "PHP", Kind.NODE: "Node.js", Kind.TOOL: "Tool"}
PHP_ENTRIES: tuple[str, ...] = ("php84", "php85")


def runtime_label(entry: str) -> str:
    """The version-only name Settings uses for a runtime entry (PHP 8.5, Node.js 24)."""
    if entry.startswith("php") and len(entry) == 5 and entry[3:].isdigit():
        return f"PHP {entry[3]}.{entry[4]}"
    if entry.startswith("nodejs_"):
        return f"Node.js {entry.removeprefix('nodejs_').replace('_', '.')}"
    return entry


def download_label(size: int) -> str:
    """The plain-words size Settings shows before adding a version."""
    return f"Adds about {max(1, round(size / 1_000_000))} MB"


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


@dataclass(frozen=True)
class ShownRuntime:
    """One observed runtime profile, with what this release can do to it."""

    entry: str
    version: str
    path: str
    generation: str
    master_state: str
    extensions: tuple[str, ...]
    protections: tuple[tuple[str, str], ...]
    problem: str
    sites: tuple[str, ...] = ()
    default: str = ""
    update_version: str = ""
    update_path: str = ""
    update_sites: tuple[str, ...] = ()
    update_reason: str = ""
    remove_reason: str = ""

    @property
    def can_remove(self) -> bool:
        return not self.remove_reason


def shown_runtimes(snapshot: CollectedSnapshot) -> tuple[ShownRuntime, ...]:
    """Every observed runtime profile, matched to the catalog release and its users."""
    machine = snapshot.architecture.value or ""
    architecture = architecture_of(machine)
    if architecture is None:
        return tuple(_shown_runtime(row) for row in snapshot.runtimes)
    usage = usage_by_entry(snapshot.sites.value)
    profiles = {row.entry: row.path for row in snapshot.runtimes if row.path}
    found = {row.entry: row for row in updates(architecture, profiles, usage)}
    defaults = snapshot.runtime_defaults
    default_entries = {
        entry
        for entry in (
            defaults.php if defaults is not None else "",
            defaults.node if defaults is not None else "",
        )
        if entry
    }
    manageable = {
        row.entry for row in snapshot.runtimes if not row.problem and _recognised(architecture, row)
    }
    return tuple(
        _shown_runtime(
            row,
            update=found.get(row.entry),
            sites=usage.get(row.entry, ()),
            default=row.entry if row.entry in default_entries else "",
            other_installed=any(entry != row.entry and entry in manageable for entry in PHP_ENTRIES)
            if row.entry in PHP_ENTRIES
            else False,
        )
        for row in snapshot.runtimes
    )


def _recognised(architecture: Architecture, row: RuntimeObservation) -> bool:
    build = load().identify(architecture, row.path) if row.path else None
    return build is not None and build.entry == row.entry


def _shown_runtime(
    row: RuntimeObservation,
    *,
    update: CatalogUpdate | None = None,
    sites: tuple[str, ...] = (),
    default: str = "",
    other_installed: bool = False,
) -> ShownRuntime:
    update_reason = ""
    if row.entry in PHP_ENTRIES and update is not None and update.sites:
        if row.problem:
            update_reason = row.problem
        elif not other_installed:
            update_reason = (
                "Install and verify the other PHP runtime first: moving this runtime's sites "
                "through the request-preserving switch needs a second one."
            )
    remove_reason = ""
    if row.entry not in PHP_ENTRIES:
        remove_reason = "Only PHP runtimes are removed from this page."
    elif not row.path:
        remove_reason = "This runtime is not installed."
    elif row.problem and not _identity_known(row):
        remove_reason = row.problem
    elif sites:
        remove_reason = "Used by " + _sites_phrase(sites) + "."
    elif default:
        remove_reason = (
            f"The server default {'PHP' if row.entry in PHP_ENTRIES else 'Node.js'} "
            "uses this runtime."
        )
    return ShownRuntime(
        row.entry,
        row.version,
        row.path,
        row.generation,
        row.master_state,
        row.extensions,
        row.protections,
        row.problem,
        sites,
        default,
        update.offered.version if update else "",
        update.offered.path if update else "",
        update.sites if update else (),
        update_reason,
        remove_reason,
    )


def _identity_known(row: RuntimeObservation) -> bool:
    # An unknown path cannot be removed by identity; a live protection fault still can,
    # because the profile's build is the native identity the review binds.
    return bool(row.path) and row.problem.startswith("Protection fault")


def _sites_phrase(sites: tuple[str, ...]) -> str:
    return f"{len(sites)} site{'s' if len(sites) != 1 else ''} ({', '.join(sites)})"


@dataclass(frozen=True)
class ShownPhpVersion:
    """One installed PHP version and the sites that selected it (Server Settings)."""

    entry: str
    label: str
    version: str
    sites: tuple[str, ...]
    default: bool
    problem: bool

    @property
    def sites_phrase(self) -> str:
        return _sites_phrase(self.sites)


@dataclass(frozen=True)
class ShownPhpAddition:
    """One catalog PHP version this server does not have, offered from Server Settings."""

    entry: str
    label: str
    download_size: int

    @property
    def download_phrase(self) -> str:
        return download_label(self.download_size)


def settings_php_versions(snapshot: CollectedSnapshot) -> tuple[ShownPhpVersion, ...]:
    """Installed PHP versions from the last observation, with the sites using each."""
    usage = usage_by_entry(snapshot.sites.value)
    defaults = snapshot.runtime_defaults
    default = defaults.php if defaults is not None else ""
    return tuple(
        ShownPhpVersion(
            row.entry,
            runtime_label(row.entry),
            row.version,
            usage.get(row.entry, ()),
            row.entry == default,
            bool(row.problem),
        )
        for row in sorted(snapshot.runtimes, key=lambda row: row.entry)
        if row.entry in PHP_ENTRIES and row.path
    )


def settings_php_additions(snapshot: CollectedSnapshot) -> tuple[ShownPhpAddition, ...]:
    """Catalog PHP versions absent from the server, for Add PHP version."""
    present = {row.entry for row in snapshot.runtimes if row.path}
    catalog = shown_catalog(checked=True, machine=snapshot.architecture.value or None)
    return tuple(
        ShownPhpAddition(build.entry, runtime_label(build.entry), build.download_size)
        for build in sorted(catalog.runtimes, key=lambda build: build.entry)
        if build.entry in PHP_ENTRIES and build.entry not in present
    )


@dataclass(frozen=True)
class ShownUpdate:
    """One catalog build this release replaces, and what the replacement reaches."""

    entry: str
    version: str
    update_version: str
    sites: tuple[str, ...] = ()
    reason: str = ""


def shown_updates(
    snapshot: CollectedSnapshot, rows: tuple[ShownRuntime, ...]
) -> tuple[ShownUpdate, ...]:
    """Every installed entry with an older build, including the stack's tools."""
    architecture = architecture_of(snapshot.architecture.value or "")
    if architecture is None:
        return ()
    profiles = {row.entry: row.path for row in rows if row.path}
    if snapshot.standing is not None:
        profiles.update(dict(snapshot.standing.profiles))
    usage = usage_by_entry(snapshot.sites.value)
    row_by_entry = {row.entry: row for row in rows}
    sites = tuple(sorted({site.identifier for site in snapshot.sites.value if site.identifier}))
    found = []
    for update in updates(architecture, profiles, usage):
        row = row_by_entry.get(update.entry)
        if row is not None:
            found.append(
                ShownUpdate(
                    update.entry,
                    row.version,
                    row.update_version or update.offered.version,
                    row.update_sites or update.sites,
                    row.update_reason,
                )
            )
        else:
            found.append(
                ShownUpdate(
                    update.entry,
                    update.installed.version,
                    update.offered.version,
                    sites if update.entry in SERVICE_ENTRIES else (),
                )
            )
    return tuple(found)
