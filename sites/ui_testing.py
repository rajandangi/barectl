"""Stored target-site observations for page and browser tests."""

from dataclasses import replace

from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome, SiteState
from discovery.snapshot import Observation, ObservedSite, SiteAccount, save_snapshot
from runtimes.observation import RuntimeObservation
from servers.models import Server
from sites.observation import PHP_TRANSITION_INCOMPLETE
from sites.recognition import CADDY_OUTSIDE, POOL_OUTSIDE, ROUTE_ABSENT


def record_http_sites(server: Server, *, problem: str = "") -> None:
    sites = tuple(
        ObservedSite(
            identifier,
            (f"{identifier}.example.com",),
            "php84",
            SiteAccount(uid, uid, f"/var/www/{identifier}", "/bin/bash"),
            SiteState.MANAGED,
            ObservationOutcome.OBSERVED,
            file=f"/etc/caddy/sites/{identifier}.caddy",
        )
        for identifier, uid in (("alpha", 1001), ("beta", 1002))
    )
    runtimes = (
        RuntimeObservation(
            "php84",
            "/nix/store/observed-php",
            "1",
            "8.4.26",
            ("opcache",),
            "active",
            (("opcache.validate_permission", "1"), ("expose_php", "0")),
            problem,
        ),
        RuntimeObservation("php85", "", "", "8.5.11", (), "failed", (), "Master failed"),
    )
    collected = replace(
        COLLECTED,
        components=(),
        sites=Observation(ObservationOutcome.OBSERVED, ("caddy adapt",), "", sites),
        standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
        runtimes=runtimes,
    )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    save_snapshot(attempt, collected, timezone.now())


def record_shaped_sites(server: Server, standing: Standing = Standing.TARGET_STACK) -> None:
    """A target host with one site per recognition outcome."""

    def site(identifier: str, state: SiteState, problem: str = "") -> ObservedSite:
        return ObservedSite(
            identifier,
            (f"{identifier}.example.com",) if problem != ROUTE_ABSENT else (),
            "php85" if identifier == "delta" else "php84",
            SiteAccount(1001, 1001, f"/var/www/{identifier}", "/usr/sbin/nologin"),
            state,
            ObservationOutcome.OBSERVED,
            file=f"/etc/caddy/sites/{identifier}.caddy",
            missing=(problem,) if problem else (),
            convention_revision=5,
        )

    sites = (
        site("alpha", SiteState.MANAGED),
        site("beta", SiteState.NOT_FOLLOWING, POOL_OUTSIDE),
        site("gamma", SiteState.NOT_FOLLOWING, CADDY_OUTSIDE),
        site("delta", SiteState.PARTLY_APPLIED, PHP_TRANSITION_INCOMPLETE),
        site("omega", SiteState.PARTLY_APPLIED, ROUTE_ABSENT),
    )
    runtimes = (
        RuntimeObservation(
            "php84", "/nix/store/observed-php84", "1", "8.4.26", ("opcache",), "active", (), ""
        ),
        RuntimeObservation("php85", "", "", "8.5.11", (), "failed", (), "Master failed"),
    )
    collected = replace(
        COLLECTED,
        components=(),
        sites=Observation(ObservationOutcome.OBSERVED, ("caddy adapt",), "", sites),
        standing=HostJudgment(standing, (), (), ()),
        runtimes=runtimes,
    )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    save_snapshot(attempt, collected, timezone.now())
