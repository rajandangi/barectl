"""Browser-test support: a stored snapshot with one site's backups (#396)."""

from dataclasses import replace
from datetime import datetime

from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome, SiteState
from discovery.snapshot import Observation, ObservedSite, SiteAccount, save_snapshot
from servers.models import Server
from sites.bodies.common import SITE_GATED

from .models import BackupCheck
from .observation import BackupResult, ObservedBackup


def record_backups(
    server: Server,
    *,
    identifier: str = "shop",
    enabled: bool = True,
    database: bool = True,
    last: BackupResult | None = None,
    checked_at: datetime | None = None,
    gated: bool = False,
) -> None:
    """A target site whose stored snapshot carries the backup observation."""
    site = ObservedSite(
        identifier,
        (f"{identifier}.example.com",),
        "php84",
        SiteAccount(1001, 1001, f"/var/www/{identifier}", "/usr/sbin/nologin"),
        SiteState.PARTLY_APPLIED if gated else SiteState.MANAGED,
        ObservationOutcome.OBSERVED,
        file=f"/etc/caddy/sites/{identifier}.caddy",
        missing=(SITE_GATED,) if gated else (),
        https=True,
    )
    backup = ObservedBackup(
        identifier,
        "/nix/store/rac858616ds2w2z3db69kp80vr9s8mkp-restic-0.18.1" if enabled else "",
        enabled,
        enabled,
        (),
        database,
        "" if database else "This site has no site database.",
        last,
    )
    collected = replace(
        COLLECTED,
        components=(),
        sites=Observation(ObservationOutcome.OBSERVED, ("caddy adapt",), "", (site,)),
        standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
        backups=Observation(
            ObservationOutcome.OBSERVED,
            ("/var/lib/barectl-backups",),
            "",
            (backup,),
        ),
    )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    from sites.ui_testing import attach_current_connection

    attach_current_connection(server, attempt)
    save_snapshot(attempt, collected, checked_at or timezone.now())


def result(
    *,
    result_class: str = "succeeded",
    scope: str = "database",
    point: str = "0123456789abcdef",
    reason: str = "",
) -> BackupResult:
    return BackupResult(
        result_class,
        reason,
        scope,
        "manual",
        timezone.now().replace(microsecond=0).isoformat(),
        point,
        1,
        4096,
    )


def point(
    *,
    point: str = "0123456789abcdef",
    time: str = "2026-10-27T11:00:00Z",
    scope: str = "database",
    parts: tuple[str, ...] = ("database",),
    complete: bool = True,
    live: bool = True,
) -> dict[str, object]:
    return {
        "id": "a" * 64,
        "short": "a" * 8,
        "time": time,
        "point": point,
        "scope": scope,
        "parts": list(parts),
        "missing": [],
        "incomplete": [],
        "origin": "manual",
        "live": live,
        "keep": False,
        "complete": complete,
    }


def record_points(
    server: Server,
    points: tuple[dict[str, object], ...] = (),
    *,
    identifier: str = "shop",
    checked_at: datetime | None = None,
) -> BackupCheck:
    """One stored Check backups listing, as the Backups section reads it."""
    BackupCheck.objects.filter(server=server, identifier=identifier).delete()
    return BackupCheck.objects.create(
        server=server,
        identifier=identifier,
        ssh_alias=server.ssh_alias,
        status="succeeded",
        finished_at=timezone.now(),
        checked_at=checked_at or timezone.now(),
        listing={
            "version": 1,
            "identifier": identifier,
            "outcome": "observed",
            "problem": "",
            "points": list(points),
        },
    )
