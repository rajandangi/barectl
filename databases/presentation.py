"""The Database setting's presentation: what the server's last observation proves.

docs/dashboard-workflows.md and #179's Server Settings journey. Templates read these view
dataclasses and never decide native state themselves.
"""

from dataclasses import dataclass

from discovery.snapshot import CollectedSnapshot

from . import observation


@dataclass(frozen=True)
class EngineView:
    engine: str
    label: str
    version: str
    active: bool
    state: str


@dataclass(frozen=True)
class DatabasePanel:
    """The server's engine choice, from its last observation alone."""

    engines: tuple[EngineView, ...]
    # (engine, label) offered for installation; empty once an engine is present.
    installable: tuple[tuple[str, str], ...]
    # Why the installed engines are outside supported settings; empty when they are inside.
    outside: tuple[str, ...]
    note: str


def _engine_view(engine: observation.EngineObservation) -> EngineView:
    spec = observation.specs()[engine.engine]
    active = any(unit.active_state == "active" for unit in engine.units)
    state = "running" if active else "installed but not running" if engine.units else "installed"
    return EngineView(engine.engine, spec.label, engine.version, active, state)


def panel(collected: CollectedSnapshot) -> DatabasePanel:
    engines = tuple(_engine_view(engine) for engine in observation.installed_engines(collected))
    chosen = {view.engine for view in engines}
    installable = tuple(
        (engine, observation.specs()[engine].label)
        for engine in observation.ENGINES
        if engine not in chosen
    )
    outside = observation.outside_supported_engines(collected)
    if outside:
        note = "Database changes are unavailable until the named evidence is resolved."
    elif engines:
        note = (
            "One engine per server. Site databases are created with their sites; Barectl "
            "refuses to remove an engine while any site uses it."
        )
    else:
        note = (
            "Installing an engine is one reviewed change that names every package and "
            "version and hardens the engine to its local socket."
        )
    return DatabasePanel(engines, installable, outside, note)
