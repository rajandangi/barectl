"""Stored log pages and site log evidence for page and browser tests (Phase C #389)."""

from dataclasses import replace
from datetime import timedelta

from django.utils import timezone

from automation.convention import ROLE_SCHEDULE, ROLE_WPCRON, queue_role
from automation.observation import ObservedSchedule
from automation.status import ScheduleStatus
from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome, SiteState
from discovery.snapshot import (
    Observation,
    ObservedCache,
    ObservedSetting,
    current_snapshot,
    save_snapshot,
)
from logs.models import LogRead
from logs.read import LogLine, LogPage
from servers.models import Server
from sites.ui_testing import attach_current_connection, record_http_sites


def record_log_site(
    server: Server,
    *,
    identifier: str = "alpha",
    application: str = "plain",
    log_rotation: str = "supported",
    page: LogPage | None = None,
    source: str = "php_errors",
    expires_in: timedelta | None = timedelta(hours=23),
) -> LogRead | None:
    """A managed site with log evidence and, optionally, one stored page."""
    record_http_sites(server)
    snapshot = current_snapshot(server)
    if snapshot is None:
        raise AssertionError("No snapshot.")
    sites = tuple(
        replace(row, application=application, log_rotation=log_rotation)
        if row.identifier == identifier
        else row
        for row in snapshot.collected.sites.value
    )
    if not any(row.identifier == identifier for row in sites):
        from discovery.snapshot import ObservedSite
        from sites.bodies.pool import SitePool

        sites += (
            ObservedSite(
                identifier,
                (f"{identifier}.example.com",),
                "php84",
                None,
                SiteState.MANAGED,
                snapshot.collected.sites.value[0].outcome,
                file=f"/etc/caddy/sites/{identifier}.caddy",
                pool=SitePool(),
                application=application,
                log_rotation=log_rotation,
            ),
        )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    attach_current_connection(server, attempt)
    save_snapshot(
        attempt,
        replace(snapshot.collected, sites=replace(snapshot.collected.sites, value=sites)),
        timezone.now(),
    )
    if page is None:
        return None
    now = timezone.now()
    return LogRead.objects.create(
        server=server,
        ssh_alias=server.ssh_alias,
        requested_by=None,
        identifier=identifier,
        source=source,
        status=DiscoveryAttempt.Status.SUCCEEDED,
        outcome=page.state,
        page=page.document(),
        page_expires_at=None if expires_in is None else now + expires_in,
        collected_at=now,
        finished_at=now,
    )


def php_error_page(*lines: str) -> LogPage:
    return LogPage(
        "observed",
        tuple(LogLine(raw=line) for line in lines),
        cursor="next-page",
        at_end=False,
    )


def record_background_site(
    server: Server,
    *,
    identifier: str = "alpha",
    application: str = "laravel",
    scheduled: bool = True,
    workers: int = 0,
    cache: str = "off",
    page: LogPage | None = None,
    source: str = "queue_workers",
    expires_in: timedelta | None = timedelta(hours=23),
) -> LogRead | None:
    """A site with stored background-work evidence and, optionally, one stored page.

    ``application`` decides which journal sources the catalogue lists; the automation and
    cache observations then decide whether each one is configured.
    """
    record_http_sites(server)
    snapshot = current_snapshot(server)
    if snapshot is None:
        raise AssertionError("No snapshot.")
    sites = tuple(
        replace(row, application="plain" if application == "laravel" else application)
        if row.identifier == identifier
        else row
        for row in snapshot.collected.sites.value
    )
    rows: list[ObservedSchedule] = []
    if scheduled:
        role = ROLE_SCHEDULE if application == "laravel" else ROLE_WPCRON
        rows.append(ObservedSchedule(identifier, role, ScheduleStatus.OFF, installed=True))
    rows.extend(
        ObservedSchedule(identifier, queue_role(index), ScheduleStatus.OFF, installed=True)
        for index in range(1, workers + 1)
    )
    settings = (
        (ObservedSetting(identifier, "laravel", "APP_ENV", "a" * 64, "production"),)
        if application == "laravel"
        else ()
    )
    collected = replace(
        snapshot.collected,
        sites=replace(snapshot.collected.sites, value=sites),
        settings=Observation(ObservationOutcome.OBSERVED, ("/var/www",), "", settings),
        automation=Observation(ObservationOutcome.OBSERVED, ("systemctl show",), "", tuple(rows)),
        cache=Observation(
            ObservationOutcome.OBSERVED,
            ("/etc/valkey",),
            "",
            (ObservedCache(identifier, cache),),
        ),
    )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    attach_current_connection(server, attempt)
    save_snapshot(attempt, collected, timezone.now())
    if page is None:
        return None
    now = timezone.now()
    return LogRead.objects.create(
        server=server,
        ssh_alias=server.ssh_alias,
        requested_by=None,
        identifier=identifier,
        source=source,
        status=DiscoveryAttempt.Status.SUCCEEDED,
        outcome=page.state,
        page=page.document(),
        page_expires_at=None if expires_in is None else now + expires_in,
        collected_at=now,
        finished_at=now,
    )
