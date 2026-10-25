"""The fixed log catalogue of a site (Phase C #389, docs/logs.md#catalogue)."""

from dataclasses import dataclass

from discovery.snapshot import ObservedSite

# Kept identical to logs.bodies.read.SOURCES: the worker's fixed command knows these names.
VISITS = "visits"
PHP_ERRORS = "php_errors"
PHP_SLOW = "php_slow"
APPLICATION = "application"
WORDPRESS = "wordpress"


@dataclass(frozen=True)
class LogSource:
    """One named log an operator can read, never a path they must know."""

    slug: str
    label: str
    summary: str


CATALOGUE = (
    LogSource(VISITS, "Visits", "Every request this site served."),
    LogSource(PHP_ERRORS, "PHP errors", "Errors the site's PHP requests reported."),
    LogSource(PHP_SLOW, "Slow PHP requests", "Requests that took longer than five seconds."),
    LogSource(APPLICATION, "Application log", "The application's own daily log."),
    LogSource(WORDPRESS, "WordPress debug log", "Messages WordPress recorded while debugging."),
)


def catalogue(site: ObservedSite | None) -> tuple[LogSource, ...]:
    """Every log the site can have, with the WordPress debug log only for WordPress.

    The log itself is listed only when the site runs WordPress; a read then reports it as
    missing until the operator enables WordPress debugging into the site's log directory.
    """
    if site is not None and site.application in ("wordpress", "wordpress_partial"):
        return CATALOGUE
    return CATALOGUE[:4]


def source(slug: str) -> LogSource | None:
    return next((entry for entry in CATALOGUE if entry.slug == slug), None)
