"""What Create site needs on the server before it can prepare a site review.

docs/sites.md#step-1-a-missing-runtime-or-database-engine. Create site never sends the
operator away to another section: a missing PHP runtime or database engine is offered as
Step 1, prepared through the existing Add runtime and Install database engine kinds, and the
create form keeps the operator's answers until the step finishes.
"""

from dataclasses import dataclass

from databases import observation as database_observation
from runtimes.presentation import PHP_ENTRIES, shown_catalog
from servers.discovery_state import DiscoveryState

MARIADB = database_observation.MARIADB
POSTGRESQL = database_observation.POSTGRESQL


def version_label(entry: str) -> str:
    """The version-only label the create form and its Step 1 name (PHP 8.5)."""
    return f"PHP {entry[3]}.{entry[4]}"


@dataclass(frozen=True)
class PhpChoice:
    """One PHP option the create form offers: verified and installed, or installable first."""

    entry: str
    installed: bool
    download_size: int

    @property
    def version_label(self) -> str:
        return version_label(self.entry)


@dataclass(frozen=True)
class EngineStep:
    """Whether the platform's database is missing, and the engines Step 1 may install."""

    engines: tuple[tuple[str, str], ...] = ()
    reason: str = ""

    @property
    def needed(self) -> bool:
        return bool(self.engines) and not self.reason

    @property
    def engine(self) -> str:
        return self.engines[0][0] if self.engines else ""

    @property
    def label(self) -> str:
        return self.engines[0][1] if len(self.engines) == 1 else "database engine"


def verified_versions(state: DiscoveryState) -> tuple[str, ...]:
    """The installed PHP entries whose master the current observation verified."""
    snapshot = state.snapshot
    if snapshot is None or state.snapshot_notice is not None:
        return ()
    return tuple(
        row.entry
        for row in snapshot.collected.runtimes
        if row.entry in PHP_ENTRIES and row.manageable and row.master_state == "active"
    )


def php_choices(state: DiscoveryState) -> tuple[PhpChoice, ...]:
    """Verified runtimes, then catalog PHP builds this server does not have at all.

    A runtime that is present but whose master failed is neither usable nor installable by
    Add runtime, so it is offered nowhere. Nothing is offered without a fresh observation.
    """
    snapshot = state.snapshot
    if snapshot is None or state.snapshot_notice is not None:
        return ()
    installed = verified_versions(state)
    present = {row.entry for row in snapshot.collected.runtimes if row.path}
    catalog = shown_catalog(checked=True, machine=snapshot.collected.architecture.value or None)
    offered = {build.entry: build for build in catalog.runtimes if build.entry in PHP_ENTRIES}
    choices = [PhpChoice(entry, True, 0) for entry in PHP_ENTRIES if entry in installed]
    choices.extend(
        PhpChoice(entry, False, offered[entry].download_size)
        for entry in sorted(offered)
        if entry not in installed and entry not in present
    )
    return tuple(choices)


def installable(choices: tuple[PhpChoice, ...]) -> tuple[tuple[str, int], ...]:
    return tuple((choice.entry, choice.download_size) for choice in choices if not choice.installed)


def preselected(state: DiscoveryState, choices: tuple[PhpChoice, ...]) -> str:
    """The PHP version Create site preselects: the server default, else the newest
    installed, else the newest offered (docs/dashboard-workflows.md)."""
    snapshot = state.snapshot
    defaults = snapshot.collected.runtime_defaults if snapshot is not None else None
    installed = [choice.entry for choice in choices if choice.installed]
    if defaults is not None and not defaults.php_problem and defaults.php in installed:
        return defaults.php
    if installed:
        return max(installed)
    return max((choice.entry for choice in choices), default="")


def download_label(size: int) -> str:
    """The create page's wording for a version this server installs first."""
    megabytes = max(1, round(size / 1_000_000))
    return f"Installed first, adds about {megabytes} MB"


def engine_step(state: DiscoveryState, platform: str) -> EngineStep:
    """The database prerequisite for one platform; WordPress needs MariaDB alone."""
    if platform == "http":
        return EngineStep()
    snapshot = state.snapshot
    if snapshot is None or state.snapshot_notice is not None:
        return EngineStep()
    installed = database_observation.installed_engines(snapshot.collected)
    allowed = (MARIADB,) if platform == "wordpress" else (MARIADB, POSTGRESQL)
    subject = "WordPress" if platform == "wordpress" else "Laravel"
    if len(installed) > 1:
        return EngineStep(
            reason=f"{subject} needs one database engine; this server runs more than one."
        )
    if not installed:
        return EngineStep(
            tuple((engine, database_observation.specs()[engine].label) for engine in allowed)
        )
    current = installed[0]
    if platform == "wordpress" and current.engine == POSTGRESQL:
        return EngineStep(reason="WordPress needs MariaDB. This server runs PostgreSQL.")
    if not current.managed:
        return EngineStep(reason=f"{current.label} is Outside supported settings.")
    return EngineStep()
