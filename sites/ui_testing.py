"""Stored target-site observations for page and browser tests."""

from dataclasses import replace

from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from databases import observation as database_observation
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome, SiteState, WebStackComponent
from discovery.snapshot import (
    Observation,
    ObservedCache,
    ObservedRelease,
    ObservedSetting,
    ObservedSite,
    Package,
    ServiceUnit,
    SiteAccount,
    SiteCertificate,
    WebStackComponentObservation,
    current_snapshot,
    save_snapshot,
)
from operations.consent import DeclaredEffect, Scope
from operations.engine import ReviewDraft, save_review
from operations.models import (
    ChangePreparation,
    ChangeReview,
    ChangeRun,
    RemoteOperation,
    Result,
    Verification,
)
from runtimes.observation import RuntimeObservation
from servers.models import Server
from sites.bodies.common import CADDY_OUTSIDE, POOL_OUTSIDE, ROUTE_ABSENT
from sites.bodies.pool import SitePool
from sites.observation import PHP_TRANSITION_INCOMPLETE

BOOT_ID = "6f1c4e1a-3a8e-4b5f-9d2e-7c0b8a9d1e23"


def _engine_component(engine_name: str) -> WebStackComponentObservation:
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


def record_http_sites(
    server: Server,
    *,
    problem: str = "",
    engine: str = "",
    installed_php: bool = True,
    present_php85: bool = True,
) -> None:
    """A target host whose observed sites can receive a Create site review."""
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
        (
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
        )
        if installed_php
        else ()
    ) + (
        (RuntimeObservation("php85", "", "", "8.5.11", (), "failed", (), "Master failed"),)
        if present_php85
        else ()
    )
    collected = replace(
        COLLECTED,
        components=(_engine_component(engine),) if engine else (),
        sites=Observation(ObservationOutcome.OBSERVED, ("caddy adapt",), "", sites),
        standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
        runtimes=runtimes,
    )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    attach_current_connection(server, attempt)
    save_snapshot(attempt, collected, timezone.now())


def attach_current_connection(server: Server, attempt: DiscoveryAttempt) -> None:
    """A recorded observation belongs to the server's current connection revision."""
    from servers.models import ConnectionDefinition

    attempt.connection = ConnectionDefinition.objects.filter(
        server=server, revision=server.connection_revision
    ).first()
    attempt.save(update_fields=["connection"])


def record_php85_installed(server: Server) -> None:
    """A host where PHP 8.5 was installed and discovery verified its service."""
    record_http_sites(server)
    snapshot = current_snapshot(server)
    if snapshot is None:
        raise AssertionError("No snapshot.")
    runtimes = tuple(
        replace(row, path="/nix/store/observed-php85", master_state="active", problem="")
        if row.entry == "php85"
        else row
        for row in snapshot.collected.runtimes
    )
    collected = replace(snapshot.collected, runtimes=runtimes)
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    attach_current_connection(server, attempt)
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


def valkey_component() -> WebStackComponentObservation:
    """An installed, masked and inactive distribution Valkey (Phase C #391)."""
    return WebStackComponentObservation(
        WebStackComponent.VALKEY,
        Observation(
            ObservationOutcome.OBSERVED,
            ("dpkg-query",),
            "",
            (
                Package("valkey-server", "9.0.4-0ubuntu0.2"),
                Package("valkey-tools", "9.0.4-0ubuntu0.2"),
            ),
        ),
        Observation(
            ObservationOutcome.OBSERVED,
            ("systemctl show valkey-server.service",),
            "",
            (ServiceUnit("valkey-server.service", "masked", "inactive", "dead", "masked"),),
        ),
    )


def record_site_settings(
    server: Server,
    *,
    identifier: str = "alpha",
    application: str = "laravel",
    settings: tuple[ObservedSetting, ...] = (),
    certificate: SiteCertificate | None = None,
    releases: tuple[ObservedRelease, ...] = (),
    https: bool | None = None,
    cache: tuple[ObservedCache, ...] = (),
    installed_valkey: bool = False,
    client: str = "",
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
            https=(certificate is not None) if https is None else https,
            certificate=certificate,
            application=application,
            application_version="7.1.3" if application == "wordpress" else "",
            client=client,
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
        components=(valkey_component(),) if installed_valkey else (),
        sites=Observation(ObservationOutcome.OBSERVED, ("caddy adapt",), "", sites),
        standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
        runtimes=runtimes,
        settings=Observation(ObservationOutcome.OBSERVED, ("/var/www",), "", settings),
        cache=Observation(ObservationOutcome.OBSERVED, ("/etc/valkey",), "", cache),
        releases=Observation(
            ObservationOutcome.OBSERVED,
            ("/var/www",),
            "",
            releases,
        ),
    )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    save_snapshot(attempt, collected, timezone.now())


def record_step_run(preparation: ChangePreparation) -> ChangeRun:
    """A finished Step 1 run, as the worker would record it after applying the review."""
    RemoteOperation.objects.filter(pk=preparation.pk).update(
        status=RemoteOperation.Status.SUCCEEDED
    )
    review = save_review(
        preparation,
        ReviewDraft(
            kind=preparation.kind_slug,
            intent="Install the missing prerequisite.",
            effects=(DeclaredEffect(Scope.SERVER, "Install the prerequisite."),),
            stages=("preflight", "install", "verify"),
            boot_id=BOOT_ID,
            uptime_centiseconds=500000,
        ),
        host_key="ssh-ed25519 key",
        collected_at=timezone.now(),
        sites_digest="",
    )
    return ChangeRun.objects.create(
        server=preparation.server,
        review=review,
        requested_by=preparation.requested_by,
        requested_by_name="operator",
        server_name=preparation.server.name if preparation.server is not None else "Web",
        unit_name="barectl-apply-" + "c" * 32 + ".service",
        status=RemoteOperation.Status.SUCCEEDED,
        execution=Result.SUCCEEDED,
        verification=Verification.PASSED,
    )


def record_wordpress_sites(
    server: Server,
    *,
    engine: str = "mariadb",
    application: str = "wordpress",
    version: str = "7.1.3",
    state: SiteState = SiteState.MANAGED,
    installed_php: bool = True,
) -> None:
    """A target host whose site can receive a Create WordPress site review."""

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
        (
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
        if installed_php
        else ()
    ) + (RuntimeObservation("php85", "", "", "8.5.11", (), "failed", (), "Master failed"),)
    collected = replace(
        COLLECTED,
        components=(_engine_component(engine),) if engine else (),
        sites=Observation(ObservationOutcome.OBSERVED, ("caddy adapt",), "", sites),
        standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
        runtimes=runtimes,
    )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    save_snapshot(attempt, collected, timezone.now())


def record_review(preparation: ChangePreparation, draft: ReviewDraft) -> ChangeReview:
    """A finished preparation and the review the worker would publish for it."""
    RemoteOperation.objects.filter(pk=preparation.pk).update(
        status=RemoteOperation.Status.SUCCEEDED
    )
    return save_review(
        preparation,
        draft,
        host_key="ssh-ed25519 key",
        collected_at=timezone.now(),
        sites_digest="",
    )


def _recorded_inputs(preparation: ChangePreparation) -> dict[str, object]:
    value = preparation.inputs
    return value if isinstance(value, dict) else {}


def record_deploy_review(preparation: ChangePreparation) -> ChangeReview:
    from laravel.review_testing import deploy_draft

    inputs = _recorded_inputs(preparation)
    return record_review(
        preparation,
        deploy_draft(
            str(inputs.get("identifier", "")),
            migrations=bool(inputs.get("migrations", True)),
        ),
    )


def record_rollback_review(preparation: ChangePreparation) -> ChangeReview:
    from laravel.review_testing import rollback_draft

    inputs = _recorded_inputs(preparation)
    return record_review(
        preparation,
        rollback_draft(str(inputs.get("identifier", "")), str(inputs.get("release", ""))),
    )


def record_removal_review(preparation: ChangePreparation) -> ChangeReview:
    from sites.removal_testing import removal_draft

    return record_review(preparation, removal_draft())
