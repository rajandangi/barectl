"""Queuing, running and presenting a site's log reads (Phase C #389).

A read is a Read-consent remote operation: it occupies the server's one operation slot,
runs in the worker through ``discovery.ssh`` and ``logs.read``, and stores a bounded,
server-scrubbed page on its own row. Page GETs only read stored rows and clear expired
pages; they never connect.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta

from django.contrib.auth.models import AnonymousUser, User
from django.db import transaction
from django.utils import timezone

from discovery.models import SiteState
from discovery.presentation import VIEW_SITES
from discovery.snapshot import CollectedSnapshot, ObservedSite
from operations import lifecycle
from operations.lifecycle import OperationBusy, OperationRefused, recovers_first
from operations.models import VIEW_CHANGES, VIEW_EVIDENCE, RemoteOperation
from servers.discovery_state import server_state
from servers.models import Server
from sites.names import valid_identifier

from . import read as log_read
from .models import PAGE_LIFETIME, LogRead
from .sources import (
    CATALOGUE,
    OBJECT_CACHE,
    QUEUE_WORKERS,
    SCHEDULED_TASKS,
    LogSource,
    catalogue,
    source,
)

logger = logging.getLogger(__name__)

READ_PERMISSIONS: tuple[str, ...] = ("servers.view_server", VIEW_SITES, VIEW_EVIDENCE)
READ_FAILURE = (
    "The log read stopped before a page was stored. Barectl recorded no remote output. "
    "Ask for the log again."
)
UNEXPECTED_FAILURE = (
    "The log read stopped because of an unexpected error. Barectl recorded no remote output."
)
STALE_AFTER = timedelta(minutes=5)


@dataclass(frozen=True)
class SourceView:
    """One catalogue entry with its newest stored page, if any."""

    source: LogSource
    read: LogRead | None = None
    # ``None`` when discovery has no evidence for this source's units; ``True``/``False``
    # when the stored observation can say configured or not without a read.
    configured: bool | None = None

    @property
    def page(self) -> log_read.LogPage | None:
        if self.read is None:
            return None
        return log_read.LogPage.from_document(self.read.page)

    @property
    def active(self) -> bool:
        return self.read is not None and self.read.status in RemoteOperation.ACTIVE


@recovers_first
def context_for_site(
    server: Server,
    identifier: str,
    user: User | AnonymousUser,
    *,
    selected: str = "",
    live: bool = False,
) -> dict[str, object]:
    """The Logs section from stored rows only; no SSH, no queued operation."""
    _expire()
    site = _observed_site(server, identifier)
    allowed = user.has_perm(VIEW_EVIDENCE)
    target = site is not None and site.file.startswith("/etc/caddy/sites/")
    application = _application(server, identifier, site)
    sources = catalogue(site, application) if allowed and target else ()
    snapshot = server_state(server).snapshot
    views = tuple(
        SourceView(
            entry,
            _latest(server, identifier, entry.slug),
            _configured(snapshot.collected if snapshot is not None else None, identifier, entry),
        )
        for entry in sources
    )
    chosen = next((view for view in views if view.source.slug == selected), None)
    active = any(view.active for view in views)
    rotation, rotation_files = _rotation_evidence(server, identifier, chosen, site)
    from .forms import LogFilterForm

    page = chosen.page if chosen is not None else None
    following = live and chosen is not None and chosen.source.journal
    return {
        "logs_allowed": allowed,
        "logs_target": target,
        "logs_application": application,
        "logs_sources": views,
        "logs_selected": chosen,
        "logs_active": active,
        "logs_live": following,
        "logs_can_follow": bool(
            chosen is not None
            and chosen.source.journal
            and page is not None
            and page.newest
            and not chosen.active
        ),
        "logs_can_read": allowed and target and user.has_perm(VIEW_CHANGES),
        "logs_rotation": rotation,
        "logs_rotation_note": _rotation_note(rotation),
        "logs_rotation_files": rotation_files,
        "logs_rotation_can_prepare": rotation_can_prepare(server, identifier, user, rotation),
        "logs_filter": LogFilterForm(
            initial={
                "term": chosen.read.term if chosen is not None and chosen.read else "",
                "since": chosen.read.since if chosen is not None and chosen.read else None,
                "until": chosen.read.until if chosen is not None and chosen.read else None,
            }
        ),
    }


def _application(server: Server, identifier: str, site: ObservedSite | None) -> str:
    """The site's application for the catalogue, from stored evidence only."""
    if site is None:
        return ""
    if site.application in ("wordpress", "wordpress_partial"):
        return "wordpress"
    snapshot = server_state(server).snapshot
    if snapshot is None:
        return "plain"
    collected = snapshot.collected
    if collected.settings.observed and any(
        row.identifier == identifier and row.application == "laravel"
        for row in collected.settings.value
    ):
        return "laravel"
    if any(row.identifier == identifier for row in collected.releases.value):
        return "laravel"
    return "plain"


def _configured(
    collected: CollectedSnapshot | None, identifier: str, entry: LogSource
) -> bool | None:
    """Whether the stored observation says this journal source has its unit.

    The controller never guesses from a missing row alone: when discovery did not read the
    automation or cache evidence, the catalogue says it has not been read yet and the
    server-side read decides.
    """
    if collected is None or not entry.journal:
        return None
    if entry.slug == OBJECT_CACHE:
        caches = collected.cache
        if not caches.observed:
            return None
        row = next((item for item in caches.value if item.identifier == identifier), None)
        return row is not None and row.state != "off"
    automation = collected.automation
    if not automation.observed:
        return None
    installed = tuple(
        row for row in automation.value if row.identifier == identifier and row.installed
    )
    if entry.slug == SCHEDULED_TASKS:
        from automation.convention import ROLE_SCHEDULE, ROLE_WPCRON

        return any(row.role in (ROLE_WPCRON, ROLE_SCHEDULE) for row in installed)
    if entry.slug == QUEUE_WORKERS:
        from automation.convention import queue_index

        return any(queue_index(row.role) is not None for row in installed)
    return None


def available_source(server: Server, identifier: str, slug: str) -> LogSource | None:
    """One catalogue entry this site can read, from stored evidence only."""
    entry = source(slug)
    site = _observed_site(server, identifier)
    if entry is None or site is None:
        return None
    entries = catalogue(site, _application(server, identifier, site))
    return next((item for item in entries if item.slug == slug), None)


def _rotation_evidence(
    server: Server,
    identifier: str,
    chosen: SourceView | None,
    site: ObservedSite | None,
) -> tuple[str, tuple[str, ...]]:
    """Discovery's rotation state, or the newest read's evidence when discovery has none.

    A transcript recorded before the typed field has no state; the page then supplies it.
    """
    files: tuple[str, ...] = ()
    for view in (chosen,):
        page = view.page if view is not None else None
        if page is not None:
            files = page.rotation_files
    if site is not None and site.log_rotation:
        return site.log_rotation, files
    if chosen is not None:
        page = chosen.page
        if page is not None:
            return page.rotation, page.rotation_files
    newest = (
        LogRead.objects.filter(server=server, identifier=identifier)
        .exclude(page={})
        .order_by("-queued_at", "-pk")
        .first()
    )
    page = log_read.LogPage.from_document(newest.page) if newest is not None else None
    if page is None:
        return "", ()
    return page.rotation, page.rotation_files


def _rotation_note(state: str) -> str:
    if state == "":
        return "Log rotation has not been checked yet."
    if state == "supported":
        return "Log rotation is set up."
    if state == "missing":
        return "Log rotation is not set up for this site yet."
    if state == "partial":
        return "Log rotation covers only some of this site's logs."
    if state == "unavailable":
        return "This server does not run logrotate, so Barectl cannot rotate these logs."
    return "This site's log rotation file was edited outside the supported settings."


def rotation_can_prepare(
    server: Server, identifier: str, user: User | AnonymousUser, state: str = ""
) -> bool:
    """Whether the reviewed Log rotation action is offered for an existing site."""
    site = _observed_site(server, identifier)
    return (
        site is not None
        and state != "supported"
        and site.state == SiteState.MANAGED
        and user.has_perm(VIEW_CHANGES)
        and lifecycle.active_operation(server) is None
    )


def _observed_site(server: Server, identifier: str) -> ObservedSite | None:
    snapshot = server_state(server).snapshot
    if snapshot is None:
        return None
    return next(
        (site for site in snapshot.collected.sites.value if site.identifier == identifier),
        None,
    )


def _latest(server: Server, identifier: str, source: str) -> LogRead | None:
    return (
        LogRead.objects.filter(server=server, identifier=identifier, source=source)
        .order_by("-queued_at", "-pk")
        .first()
    )


def _expire() -> None:
    now = timezone.now()
    LogRead.objects.filter(page_expires_at__lt=now).exclude(page={}).update(
        page={}, page_expires_at=None
    )


@recovers_first
def request_read(
    server: Server,
    user: User,
    identifier: str,
    source: str,
    *,
    term: str = "",
    since: str = "",
    until: str = "",
    cursor: str = "",
) -> LogRead | None:
    """Queue one explicit read; ``None`` when another operation holds the server.

    The previous page of this same log is removed first: a page lives only until the next
    read of that log or for 24 hours, whichever comes first.
    """
    if not valid_identifier(identifier) or not any(entry.slug == source for entry in CATALOGUE):
        raise ValueError("Not a supported log.")
    _expire()
    LogRead.objects.filter(server=server, identifier=identifier, source=source).exclude(
        page={}
    ).update(page={}, page_expires_at=None)
    try:
        return lifecycle.queue(
            LogRead,
            server,
            requested_by=user,
            identifier=identifier,
            source=source,
            term=term[:100],
            since=_moment(since),
            until=_moment(until),
            cursor=cursor[:200],
        )
    except OperationBusy:
        return None


def _moment(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if timezone.is_aware(parsed) else timezone.make_aware(parsed)


def follow_read(
    server: Server,
    user: User,
    identifier: str,
    slug: str,
) -> LogRead | None:
    """Queue the next live page of one journal source, or ``None`` when the server is busy.

    The continuation is the newest stored page's live cursor; with no page yet the newest
    lines are read first, so a live view starts from what is on screen.
    """
    entry = source(slug)
    if entry is None or not entry.journal:
        raise ValueError("Not a live log.")
    if lifecycle.active_operation(server) is not None:
        return None
    previous = _latest(server, identifier, slug)
    cursor = ""
    if previous is not None and previous.page:
        page = log_read.LogPage.from_document(previous.page)
        if page is not None and page.newest:
            cursor = page.newest
    return request_read(server, user, identifier, slug, cursor=cursor)


def _authorize(read: LogRead) -> None:
    if not lifecycle.connection_current(read):
        raise OperationRefused("The saved connection changed. Request a new read.")
    if read.requested_by_id is None:
        raise OperationRefused("Permission to read this site's logs is no longer available.")
    user = User.objects.filter(pk=read.requested_by_id).first()
    if user is None or not user.is_active or not user.has_perms(READ_PERMISSIONS):
        raise OperationRefused("Permission to read this site's logs is no longer available.")


def _read(read: LogRead) -> None:
    from discovery import ssh

    _authorize(read)
    with ssh.connect_operation(read) as shell:
        page = log_read.read(
            shell,
            read.identifier,
            read.source,
            term=read.term,
            since=_iso(read.since),
            until=_iso(read.until),
            cursor=read.cursor,
        )
        host_key = shell.host_key
    # The controller-side second pass: a read carries no submitted secret, so the values are
    # empty today; every stored line still passes the one scrubber chokepoint.
    page = log_read.scrubbed(page, ())
    now = timezone.now()
    operation_id = read.pk or 0
    with transaction.atomic():
        if not operation_id or not lifecycle.succeed(operation_id, now, host_key=host_key):
            return
        # The page and its lifetime are the read's own fields; the shared lifecycle only
        # knows the base operation row.
        LogRead.objects.filter(pk=operation_id).update(
            collected_at=now,
            outcome=page.state,
            page=page.document(),
            page_expires_at=now + PAGE_LIFETIME,
        )
    logger.info("Log read %s of %s/%s succeeded", read.pk, read.identifier, read.source)


def _iso(value: datetime | None) -> str:
    return value.isoformat() if value is not None else ""


@recovers_first
def forget_log_reads(server: Server) -> None:
    """Delete a removed server's finished log reads and their temporary pages.

    Call inside the transaction that deletes the server. Active reads protect the server, so
    the database refuses the removal while one remains.
    """
    lifecycle.forget(
        RemoteOperation.objects.filter(server=server, kind=RemoteOperation.Kind.LOG_READ)
    )


lifecycle.register(
    LogRead,
    _read,
    interrupted=READ_FAILURE,
    unexpected=UNEXPECTED_FAILURE,
    stale_after=STALE_AFTER,
)
