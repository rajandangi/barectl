"""Automatic work rows for Jobs, from Phase C's stored projection (#289).

Jobs lists each site's scheduled tasks, queue workers and object cache beside Barectl's own
changes. Every sentence and attention flag comes from the existing Phase C presentation, so
the site's Overview and Jobs read the same observation the same way. This module reads only
the stored snapshot: it opens no connection, runs no PHP, Artisan or WP-CLI, and never reads
a queue item or an application log.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar, Final

from django.urls import reverse

from automation import presentation as schedule_presentation
from automation.observation import ObservedSchedule
from automation.worker_observation import ObservedWorker
from automation.worker_presentation import worker_view
from cache.presentation import STATE_LABELS
from discovery.snapshot import (
    Observation,
    ObservedCache,
    ObservedSetting,
    ObservedSite,
    Snapshot,
)
from servers.models import Server

SCHEDULED_TASK: Final = "scheduled_task"
QUEUE_WORKER: Final = "queue_worker"
OBJECT_CACHE: Final = "object_cache"

WORK_TITLE: Final[dict[str, str]] = {
    SCHEDULED_TASK: "Scheduled tasks",
    QUEUE_WORKER: "Queue workers",
    OBJECT_CACHE: "Object cache",
}
ORDER: Final[dict[str, int]] = {
    SCHEDULED_TASK: 0,
    QUEUE_WORKER: 1,
    OBJECT_CACHE: 2,
}
ANCHOR: Final[dict[str, str]] = {
    SCHEDULED_TASK: "scheduled-tasks",
    QUEUE_WORKER: "queue-workers",
    OBJECT_CACHE: "site-object-cache-heading",
}
LINK_LABEL: Final[dict[str, str]] = {
    SCHEDULED_TASK: "Open scheduled tasks",
    QUEUE_WORKER: "Open queue workers",
    OBJECT_CACHE: "Open object cache",
}
NO_WORK: Final = "No scheduled tasks, queue workers or object cache were found on this server."
UNREADABLE: Final[dict[str, str]] = {
    SCHEDULED_TASK: "Barectl could not read this server's scheduled tasks.",
    QUEUE_WORKER: "Barectl could not read this server's queue workers.",
    OBJECT_CACHE: "Barectl could not read this server's object cache.",
}
# The cache states that need the operator. Off is a deliberate setting, not an alarm.
CACHE_ATTENTION: Final = frozenset({"partial", "unsupported"})


@dataclass(frozen=True)
class AutomaticRow:
    """One site's work, with the values #291's filters consume kept structured.

    ``state`` is Phase C's sentence unchanged. ``identifier`` and ``work_type`` are the
    site and work-type values a filter compares, never prose parsed from the row.
    """

    key: str
    identifier: str
    role: str
    work_type: str
    state: str
    next_run_at: datetime | None = None
    next_run_unknown: bool = False
    link_url: str = ""
    link_label: str = ""
    needs_attention: bool = False
    attention_sentence: str = ""
    units: tuple[str, ...] = ()
    facts: tuple[tuple[str, str], ...] = ()

    # Templates branch on this without importing the row types (jobs/presentation.py).
    is_automatic: ClassVar[bool] = True

    @property
    def title(self) -> str:
        return WORK_TITLE[self.work_type]

    @property
    def sites(self) -> tuple[str, ...]:
        return (self.identifier,)

    @property
    def summary(self) -> str:
        return self.attention_sentence or self.state

    @property
    def result_class(self) -> str:
        """Empty: automatic work has no change result, so a generic Jobs report still reads."""
        return ""

    @property
    def detail_lines(self) -> tuple[tuple[str, str], ...]:
        lines: list[tuple[str, str]] = [
            ("Site", self.identifier),
            ("Type of work", self.title),
        ]
        if self.units:
            lines.append(("Units", ", ".join(self.units)))
        lines.extend(self.facts)
        return tuple(lines)


@dataclass(frozen=True)
class AutomaticWork:
    """Every automatic-work row, the provider warnings, and the empty sentence."""

    rows: tuple[AutomaticRow, ...]
    warnings: tuple[str, ...]
    empty: str


def automatic_work(snapshot: Snapshot, server: Server) -> AutomaticWork:
    """Read the snapshot's existing automation, worker and cache observations."""
    collected = snapshot.collected
    rows: list[AutomaticRow] = []
    warnings: list[str] = []
    if collected.automation.observed:
        rows.extend(_schedule_row(row, server) for row in collected.automation.value)
    else:
        warnings.append(collected.automation.warning or UNREADABLE[SCHEDULED_TASK])
    if collected.workers.observed:
        rows.extend(_worker_row(row, server) for row in collected.workers.value)
    else:
        warnings.append(collected.workers.warning or UNREADABLE[QUEUE_WORKER])
    if collected.cache.observed:
        applications = _cache_applications(collected.sites, collected.settings)
        rows.extend(
            _cache_row(row, server)
            for row in collected.cache.value
            if row.state != "off" or row.identifier in applications
        )
    else:
        warnings.append(collected.cache.warning or UNREADABLE[OBJECT_CACHE])
    rows.sort(key=lambda row: (row.identifier, ORDER[row.work_type], row.role))
    return AutomaticWork(
        tuple(rows),
        tuple(warnings),
        NO_WORK if not rows and not warnings else "",
    )


def _cache_applications(
    sites: Observation[tuple[ObservedSite, ...]],
    settings: Observation[tuple[ObservedSetting, ...]],
) -> frozenset[str]:
    """Sites whose application can own an object cache, from the same snapshot.

    A site with no cache reads Off; only a WordPress or Laravel site lists that deliberate
    Off. Any site with an observed cache instance is listed whatever its application.
    """
    wordpress = {site.identifier for site in sites.value if site.application == "wordpress"}
    laravel = {setting.identifier for setting in settings.value if setting.application == "laravel"}
    return frozenset(wordpress | laravel)


def _schedule_row(row: ObservedSchedule, server: Server) -> AutomaticRow:
    view = schedule_presentation.schedule_view(row.identifier, row, None)
    next_run = _moment(row.next_elapse_us)
    return AutomaticRow(
        key=f"{row.identifier}:{row.role}:scheduled",
        identifier=row.identifier,
        role=row.role,
        work_type=SCHEDULED_TASK,
        state=view.state,
        next_run_at=next_run,
        next_run_unknown=next_run is None,
        link_url=_settings_url(server, row.identifier, SCHEDULED_TASK),
        link_label=LINK_LABEL[SCHEDULED_TASK],
        needs_attention=view.attention,
        attention_sentence=view.detail if view.attention else "",
        units=(
            f"barectl-site-{row.identifier}-{row.role}.timer",
            f"barectl-site-{row.identifier}-{row.role}.service",
        ),
    )


def _worker_row(row: ObservedWorker, server: Server) -> AutomaticRow:
    view = worker_view(row.identifier, row, None)
    definition = row.definition
    return AutomaticRow(
        key=f"{row.identifier}:queue",
        identifier=row.identifier,
        role="queue",
        work_type=QUEUE_WORKER,
        state=view.state,
        link_url=_settings_url(server, row.identifier, QUEUE_WORKER),
        link_label=LINK_LABEL[QUEUE_WORKER],
        needs_attention=view.attention,
        attention_sentence=view.detail if view.attention else "",
        units=(
            tuple(f"barectl-site-{row.identifier}-{role}.service" for role in definition.roles)
            if definition is not None
            else ()
        ),
        facts=(
            (
                ("Queues", ", ".join(definition.queues)),
                ("Processes", str(definition.processes)),
            )
            if definition is not None
            else ()
        ),
    )


def _cache_row(row: ObservedCache, server: Server) -> AutomaticRow:
    label = STATE_LABELS.get(row.state, row.state)
    needs_attention = row.state in CACHE_ATTENTION
    return AutomaticRow(
        key=f"{row.identifier}:cache",
        identifier=row.identifier,
        role="cache",
        work_type=OBJECT_CACHE,
        state=label,
        link_url=_settings_url(server, row.identifier, OBJECT_CACHE),
        link_label=LINK_LABEL[OBJECT_CACHE],
        needs_attention=needs_attention,
        attention_sentence=_cache_attention(row) if needs_attention else "",
        units=(f"valkey-server@{row.identifier}.service",),
        facts=(("Problem", row.problem),) if row.problem else (),
    )


def _cache_attention(row: ObservedCache) -> str:
    """Plain words for a cache that is only partly on or outside supported settings."""
    if row.state == "partial":
        return f"The object cache for {row.identifier} is only partly on."
    return f"The object cache for {row.identifier} is outside supported settings."


def _settings_url(server: Server, identifier: str, work_type: str) -> str:
    return reverse("site_settings", args=(server.pk, identifier)) + "#" + ANCHOR[work_type]


def _moment(microseconds: int) -> datetime | None:
    """The server's next elapse as UTC, or ``None`` when it reported none."""
    if not microseconds:
        return None
    try:
        return datetime.fromtimestamp(microseconds / 1_000_000, tz=UTC)
    except OverflowError, OSError, ValueError:
        return None
