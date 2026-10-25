"""The Object cache setting's presentation: the server panel, the site card and the line.

docs/dashboard-workflows.md and #179. Templates read these view dataclasses and never
decide native state themselves. Nothing here opens a connection: the stored snapshot
carries the cache's state, and the numbers come from a reading an operator asked for.
"""

from dataclasses import dataclass
from datetime import datetime

from django.contrib.auth.models import AnonymousUser, User
from django.urls import reverse
from django.utils import timezone

from bootstrap.standing import Standing
from discovery.models import SiteState
from discovery.presentation import VIEW_SITES
from discovery.snapshot import CollectedSnapshot, ObservedCache, ObservedSite
from operations import services
from operations.consent import PREPARE_PERMISSIONS
from servers.discovery_state import DiscoveryState, server_state
from servers.models import Server
from sites.names import valid_identifier

from . import convention, observation, reading
from .plugin import PLUGIN_NAME, PLUGIN_VERSION


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


STATE_LABELS = {
    "on": "On",
    "off": "Off",
    "partial": "Partly on",
    "unsupported": "Outside supported settings",
}


def size_label(memory_mib: int) -> str:
    return f"{memory_mib} MiB"


def memory_label(value_bytes: int) -> str:
    if value_bytes >= 1024**3:
        return f"{value_bytes / 1024**3:.1f} GiB"
    if value_bytes >= 1024**2:
        return f"{value_bytes / 1024**2:.1f} MiB"
    return f"{value_bytes / 1024:.0f} KiB"


def checked_label(value: datetime | None) -> str:
    if value is None:
        return "not checked yet"
    return timezone.localtime(value).strftime("%b %-d, %Y, %H:%M:%S %Z")


@dataclass(frozen=True)
class ReadingView:
    state: str
    state_label: str
    line: str


def reading_view(value: dict[str, object] | None) -> ReadingView | None:
    if value is None:
        return None
    state = str(value.get("state", "unreadable"))
    label = {"running": "Running", "stopped": "Not running", "unreadable": "Not readable"}.get(
        state, "Not readable"
    )
    if state != "running":
        return ReadingView(state, label, label + ".")
    used = int(str(value.get("used_memory", 0)))
    limit = int(str(value.get("maxmemory", 0)))
    evicted = int(str(value.get("evicted_keys", 0)))
    clients = int(str(value.get("connected_clients", 0)))
    plural = "s" if clients != 1 else ""
    return ReadingView(
        state,
        label,
        (
            f"{memory_label(used)} of {memory_label(limit)} used, {evicted} evicted, "
            f"{clients} connected client{plural}."
        ),
    )


def _site(state: DiscoveryState, identifier: str) -> ObservedSite | None:
    snapshot = state.snapshot
    if snapshot is None:
        return None
    return next(
        (site for site in snapshot.collected.sites.value if site.identifier == identifier),
        None,
    )


def _cache_row(state: DiscoveryState, identifier: str) -> ObservedCache | None:
    snapshot = state.snapshot
    if snapshot is None:
        return None
    return next(
        (row for row in snapshot.collected.cache.value if row.identifier == identifier),
        None,
    )


def _allowed(server: Server, state: DiscoveryState, site: ObservedSite | None) -> bool:
    snapshot = state.snapshot
    return (
        site is not None
        and state.can_prepare_changes
        and not services.read_changes(server).polling
        and snapshot is not None
        and snapshot.collected.standing is not None
        and snapshot.collected.standing.standing == Standing.TARGET_STACK
    )


def site_context(server: Server, identifier: str, user: User | AnonymousUser) -> dict[str, object]:
    """The Settings card and Overview line for one site."""
    state = server_state(server)
    site = _site(state, identifier)
    row = _cache_row(state, identifier)
    snapshot = state.snapshot
    collected = snapshot.collected if snapshot is not None else None
    view = reading_view(reading.latest_reading(server, identifier))
    applicable = site is not None and site.application == "wordpress"
    current = row.state if row is not None else "off"
    problem = row.problem if row is not None else ""
    memory = (row.memory_mib if row is not None and row.memory_mib else None) or (
        convention.DEFAULT_MAXMEMORY_MIB
    )
    client = site.client if site is not None else ""
    can_prepare = (
        applicable
        and site is not None
        and site.state == SiteState.MANAGED
        and _allowed(server, state, site)
        and user.has_perms((*PREPARE_PERMISSIONS, VIEW_SITES))
    )
    can_read = (
        applicable and _allowed(server, state, site) and user.has_perms(reading.READ_PERMISSIONS)
    )
    checked = snapshot.collected_at if snapshot is not None else None
    return {
        "object_cache_applicable": applicable,
        "object_cache_state": current,
        "object_cache_state_label": STATE_LABELS.get(current, current),
        "object_cache_problem": problem,
        "object_cache_enabled": current == "on",
        "object_cache_memory_mib": memory,
        "object_cache_memory_choices": tuple(
            (size, size_label(size)) for size in convention.MAXMEMORY_MIB
        ),
        "object_cache_plugin_version": (row.plugin_version if row is not None else "")
        or PLUGIN_VERSION,
        "object_cache_plugin_name": PLUGIN_NAME,
        "object_cache_client": client,
        "object_cache_client_missing": applicable and not client,
        "object_cache_prerequisite": (
            prerequisite(collected, server=server.pk)
            if collected is not None and applicable
            else None
        ),
        "object_cache_can_prepare": can_prepare,
        "object_cache_can_read": can_read,
        "object_cache_reading": view,
        "object_cache_checked_at": checked,
        "object_cache_line": line_for(applicable, current, problem, view, checked),
    }


def line_for(
    applicable: bool,
    state: str,
    problem: str,
    view: ReadingView | None,
    checked: datetime | None,
) -> str:
    """One plain Overview sentence: state, and the last reading when there is one."""
    if not applicable:
        return ""
    if state == "on":
        if view is not None and view.state == "running":
            return f"On. {view.line} Checked {checked_label(checked)}."
        return (
            "On. Check the cache for its memory use and evictions, last checked "
            f"{checked_label(checked)}."
        )
    if state == "partial":
        return f"Partly on. {problem or 'The cache is not fully connected.'}"
    if state == "unsupported":
        return f"Outside supported settings. {problem}"
    return "Off."


def reading_checked(server: Server, identifier: str) -> datetime | None:
    """When the latest reading was taken, for its own line."""
    from .models import CacheReading

    row = (
        CacheReading.objects.filter(server=server, identifier=identifier)
        .exclude(reading={})
        .order_by("-finished_at", "-pk")
        .first()
    )
    return row.reading_at if row is not None else None


def overview_context(
    server: Server, identifier: str, user: User | AnonymousUser
) -> dict[str, object]:
    """The Overview's one cache line, from the stored observation."""
    if not valid_identifier(identifier):
        return {}
    state = server_state(server)
    site = _site(state, identifier)
    if site is None or site.application != "wordpress":
        return {}
    row = _cache_row(state, identifier)
    current = row.state if row is not None else "off"
    problem = row.problem if row is not None else ""
    checked = reading_checked(server, identifier)
    view = reading_view(reading.latest_reading(server, identifier))
    snapshot = state.snapshot
    if checked is None and snapshot is not None:
        checked = snapshot.collected_at
    can_read = (
        snapshot is not None
        and snapshot.collected.standing is not None
        and snapshot.collected.standing.standing == Standing.TARGET_STACK
        and state.can_prepare_changes
        and not services.read_changes(server).polling
        and user.has_perms(reading.READ_PERMISSIONS)
    )
    return {
        "site_cache_line": line_for(True, current, problem, view, checked),
        "site_cache_can_read": can_read,
        "site_cache_checked_at": checked,
    }
