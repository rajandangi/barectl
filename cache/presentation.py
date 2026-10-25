"""The Object cache setting's presentation: what the server's last observation proves.

docs/dashboard-workflows.md and #179's Server Settings journey. Templates read these view
dataclasses and never decide native state themselves.
"""

from dataclasses import dataclass

from django.urls import reverse

from discovery.snapshot import CollectedSnapshot

from . import observation


@dataclass(frozen=True)
class CachePanel:
    """The server's Valkey install, from its last observation alone."""

    installed: bool
    version: str
    state: str
    # Why the installed packages are outside supported settings; empty when they are inside.
    outside: tuple[str, ...]
    # Whether Server Settings offers the install action.
    installable: bool
    note: str


def panel(collected: CollectedSnapshot) -> CachePanel:
    current = observation.installed(collected)
    outside = list(observation.outside_supported(collected))
    if current is not None and current.version and not (current.masked and current.inactive):
        outside.append(
            "The shared cache is running. Stop and mask valkey-server.service through "
            "ordinary administration, then run discovery again."
        )
    installed = current is not None and bool(current.version)
    if outside:
        note = "Object cache changes are unavailable until the named evidence is resolved."
    elif installed:
        note = "Each site that uses the object cache gets its own private cache."
    else:
        note = (
            "Installing Valkey is one change that names the package and version. Each site "
            "that uses the object cache later gets its own private cache."
        )
    state = (
        "installed, and no shared cache is running"
        if installed and current is not None and current.masked and current.inactive
        else "installed"
    )
    return CachePanel(
        installed,
        current.version if current is not None else "",
        state,
        tuple(outside),
        installable=current is None and not outside,
        note=note,
    )


@dataclass(frozen=True)
class CachePrerequisite:
    """The "install first, then continue" hook a site screen uses (#392/#393)."""

    message: str
    action: str
    url: str


def prerequisite(collected: CollectedSnapshot, *, server: int) -> CachePrerequisite | None:
    """What a site screen shows before it can offer an object cache, or ``None``."""
    if observation.installed(collected) is not None:
        return None
    return CachePrerequisite(
        "This server has no object cache yet. Install Valkey in Server Settings first.",
        "Install Valkey",
        reverse("object_cache_prepare", kwargs={"pk": server}),
    )
