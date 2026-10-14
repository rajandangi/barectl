"""Stored target-site observations for page and browser tests."""

from dataclasses import replace

from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome, SiteState
from discovery.snapshot import Observation, ObservedSite, SiteAccount, save_snapshot
from runtimes.observation import RuntimeObservation
from servers.models import Server


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
