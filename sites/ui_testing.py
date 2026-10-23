"""Stored target-site observations for page and browser tests."""

from dataclasses import replace

from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from databases import observation as database_observation
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome, SiteState
from discovery.snapshot import (
    Observation,
    ObservedRelease,
    ObservedSetting,
    ObservedSite,
    Package,
    ServiceUnit,
    SiteAccount,
    WebStackComponentObservation,
    save_snapshot,
)
from runtimes.observation import RuntimeObservation
from servers.models import Server
from sites.bodies.common import CADDY_OUTSIDE, POOL_OUTSIDE, ROUTE_ABSENT
from sites.bodies.pool import SitePool
from sites.observation import PHP_TRANSITION_INCOMPLETE


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
            pool=SitePool(),
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


def record_laravel_releases(server: Server, *, identifier: str = "alpha", count: int = 7) -> None:
    """A target host whose site ``identifier`` has ``count`` retained releases."""

    sites = (
        ObservedSite(
            identifier,
            (f"{identifier}.example.com",),
            "php84",
            SiteAccount(1001, 1001, f"/var/www/{identifier}", "/usr/sbin/nologin"),
            SiteState.MANAGED,
            ObservationOutcome.OBSERVED,
            file=f"/etc/caddy/sites/{identifier}.caddy",
        ),
    )
    releases = tuple(
        ObservedRelease(
            identifier,
            f"{index:040x}-{'a' * 16}",
            f"{index:040x}",
            1_700_000_000 - index,
            SiteState.MANAGED,
            index == 0,
        )
        for index in range(count)
    )
    runtimes = (
        RuntimeObservation(
            "php84", "/nix/store/observed-php84", "1", "8.4.26", ("opcache",), "active", (), ""
        ),
    )
    collected = replace(
        COLLECTED,
        components=(),
        sites=Observation(ObservationOutcome.OBSERVED, ("caddy adapt",), "", sites),
        standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
        runtimes=runtimes,
        releases=Observation(ObservationOutcome.OBSERVED, ("/var/www",), "", releases),
    )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    save_snapshot(attempt, collected, timezone.now())


def record_site_settings(
    server: Server,
    *,
    identifier: str = "alpha",
    application: str = "laravel",
    settings: tuple[ObservedSetting, ...] = (),
) -> None:
    """A target host with one site whose private settings the dashboard may show."""
    sites = (
        ObservedSite(
            identifier,
            (f"{identifier}.example.com",),
            "php84",
            SiteAccount(1001, 1001, f"/var/www/{identifier}", "/usr/sbin/nologin"),
            SiteState.MANAGED,
            ObservationOutcome.OBSERVED,
            file=f"/etc/caddy/sites/{identifier}.caddy",
            application=application,
            application_version="7.1.3" if application == "wordpress" else "",
        ),
    )
    runtimes = (
        RuntimeObservation(
            "php84",
            "/nix/store/observed-php84",
            "1",
            "8.4.26",
            ("opcache",),
            "active",
            (),
            "",
        ),
    )
    collected = replace(
        COLLECTED,
        components=(),
        sites=Observation(ObservationOutcome.OBSERVED, ("caddy adapt",), "", sites),
        standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
        runtimes=runtimes,
        settings=Observation(ObservationOutcome.OBSERVED, ("/var/www",), "", settings),
    )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    save_snapshot(attempt, collected, timezone.now())


def record_wordpress_sites(
    server: Server,
    *,
    engine: str = "mariadb",
    application: str = "wordpress",
    version: str = "7.1.3",
    state: SiteState = SiteState.MANAGED,
) -> None:
    """A target host whose site can receive a Create WordPress site review."""

    def component(engine_name: str) -> WebStackComponentObservation:
        spec = database_observation.specs()[engine_name]
        return WebStackComponentObservation(
            spec.component,
            Observation(
                ObservationOutcome.OBSERVED,
                ("dpkg-query",),
                "",
                (Package(spec.versioned, "1.0"),),
            ),
            Observation(
                ObservationOutcome.OBSERVED,
                ("systemctl",),
                "",
                (ServiceUnit(spec.units[0], "loaded", "active", "running", "enabled"),),
            ),
        )

    sites = (
        ObservedSite(
            "shop",
            ("shop.example.com",),
            "php84",
            SiteAccount(1001, 1001, "/var/www/shop", "/usr/sbin/nologin"),
            state,
            ObservationOutcome.OBSERVED,
            file="/etc/caddy/sites/shop.caddy",
            application=application,
            application_version=version if application == "wordpress" else "",
            application_problem=(
                "The WordPress core version file is missing or unreadable."
                if application == "wordpress_partial"
                else ""
            ),
        ),
    )
    runtimes = (
        RuntimeObservation(
            "php84", "/nix/store/observed-php84", "1", "8.4.26", ("opcache",), "active", (), ""
        ),
        RuntimeObservation("php85", "", "", "8.5.11", (), "failed", (), "Master failed"),
    )
    collected = replace(
        COLLECTED,
        components=(component(engine),) if engine else (),
        sites=Observation(ObservationOutcome.OBSERVED, ("caddy adapt",), "", sites),
        standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
        runtimes=runtimes,
    )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    save_snapshot(attempt, collected, timezone.now())
