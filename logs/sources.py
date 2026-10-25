"""The fixed log catalogue of a site (Phase C #389, docs/logs.md#catalogue)."""

from dataclasses import dataclass

from discovery.snapshot import ObservedSite

# Kept identical to logs.bodies.read.SOURCES: the worker's fixed command knows these names.
VISITS = "visits"
PHP_ERRORS = "php_errors"
PHP_SLOW = "php_slow"
APPLICATION = "application"
WORDPRESS = "wordpress"
SCHEDULED_TASKS = "scheduled_tasks"
QUEUE_WORKERS = "queue_workers"
OBJECT_CACHE = "object_cache"


@dataclass(frozen=True)
class LogSource:
    """One named log an operator can read, never a path they must know."""

    slug: str
    label: str
    summary: str
    # One journal source reads the fixed units its owning convention names, by cursor.
    journal: bool = False


CATALOGUE = (
    LogSource(VISITS, "Visits", "Every request this site served."),
    LogSource(PHP_ERRORS, "PHP errors", "Errors the site's PHP requests reported."),
    LogSource(PHP_SLOW, "Slow PHP requests", "Requests that took longer than five seconds."),
    LogSource(APPLICATION, "Application log", "The application's own daily log."),
    LogSource(
        SCHEDULED_TASKS,
        "Scheduled tasks",
        "What this site's scheduled work reported.",
        journal=True,
    ),
    LogSource(
        QUEUE_WORKERS,
        "Queue workers",
        "What this site's queue workers reported.",
        journal=True,
    ),
    LogSource(
        OBJECT_CACHE,
        "Object cache",
        "What this site's cache instance reported.",
        journal=True,
    ),
    LogSource(WORDPRESS, "WordPress debug log", "Messages WordPress recorded while debugging."),
)


def catalogue(site: ObservedSite | None, application: str = "") -> tuple[LogSource, ...]:
    """Every log the site can have, in the operator's fixed order.

    The WordPress debug log is listed only for WordPress. Scheduled tasks, queue workers
    and the object cache are Phase C background work: a WordPress site can have scheduled
    tasks and a cache, a Laravel site all three, and a plain PHP site none. A source whose
    unit is absent still reads as not configured rather than disappearing.
    """
    if not application and site is not None:
        application = site.application
    if application == "wordpress_partial":
        application = "wordpress"
    shown = _SHOWN_BY_APPLICATION
    return tuple(
        entry for entry in CATALOGUE if entry.slug not in shown or application in shown[entry.slug]
    )


_SHOWN_BY_APPLICATION = {
    WORDPRESS: frozenset({"wordpress"}),
    SCHEDULED_TASKS: frozenset({"wordpress", "laravel"}),
    QUEUE_WORKERS: frozenset({"laravel"}),
    OBJECT_CACHE: frozenset({"wordpress", "laravel"}),
}


def source(slug: str) -> LogSource | None:
    return next((entry for entry in CATALOGUE if entry.slug == slug), None)
