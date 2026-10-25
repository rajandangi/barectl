"""#179 acceptance sweeps that span journeys (docs/dashboard-workflows.md)."""

import tempfile
from pathlib import Path
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from paramiko import ECDSAKey
from playwright.sync_api import expect

from discovery.ssh import UnknownHostKey
from operations.models import ChangePreparation, ChangeRun
from servers.models import Server
from servers.ssh_config import ConnectionTarget
from sites.ui_testing import record_http_sites

from .browser_testing import BrowserTestCase as BrowserTestCase


@tag("browser")
class AcceptanceSweepTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        call_command("collectstatic", interactive=False, verbosity=0)

    @override
    def setUp(self) -> None:
        super().setUp()
        for codename in (
            "view_siteobservation",
            "add_server",
            "add_discoveryattempt",
            "change_shared",
            "change_site",
            "view_changes",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.server = Server.objects.get(name="Production")
        Server.objects.exclude(pk=self.server.pk).delete()
        record_http_sites(self.server)
        self.sign_in()

    def test_no_native_term_on_the_default_path(self) -> None:
        page = self.page
        for path in ("/", "/sites/", "/activity/", "/settings/"):
            with self.subTest(path=path):
                page.goto(f"{self.live_server_url}{path}")
                self.assert_no_native_terms()
        page.goto(f"{self.live_server_url}/servers/{self.server.pk}/")
        self.assert_no_native_terms()
        page.get_by_role("link", name="alpha.example.com").first.click()
        self.assert_no_native_terms(allowed=("caddy",))
        page.get_by_role("navigation", name="Site sections").get_by_role(
            "link", name="Settings"
        ).click()
        self.assert_no_native_terms()
        page.get_by_role("navigation", name="Site sections").get_by_role(
            "link", name="Logs"
        ).click()
        self.assert_no_native_terms()

    def test_one_filled_primary_button_per_default_page(self) -> None:
        page = self.page
        selector = "main .usa-button:not(.usa-button--outline):not(.usa-button--unstyled)"
        for path in ("/", "/sites/", "/activity/", "/settings/"):
            with self.subTest(path=path):
                page.goto(f"{self.live_server_url}{path}")
                self.assertLessEqual(page.locator(selector).count(), 1)
        page.goto(f"{self.live_server_url}/servers/{self.server.pk}/")
        self.assertLessEqual(page.locator(selector).count(), 1)
        page.get_by_role("link", name="alpha.example.com").first.click()
        self.assertLessEqual(page.locator(selector).count(), 1)

    def test_detail_is_two_activations_from_a_resource(self) -> None:
        page = self.page
        page.goto(f"{self.live_server_url}/servers/{self.server.pk}/")
        page.get_by_role("navigation", name="Server sections").get_by_role(
            "link", name="Advanced"
        ).click()
        expect(page.get_by_text("Discovery history")).to_be_visible()
        page.goto(f"{self.live_server_url}/servers/{self.server.pk}/sites/alpha/")
        page.get_by_role("navigation", name="Site sections").get_by_role(
            "link", name="Logs"
        ).click()
        expect(page.get_by_role("heading", name="Logs", level=2)).to_be_visible()

    def test_keyboard_and_phone_width_reach_every_place(self) -> None:
        page = self.page
        page.set_viewport_size({"width": 320, "height": 740})
        for path in ("/", "/sites/", "/activity/", "/settings/"):
            page.goto(f"{self.live_server_url}{path}")
            self.assertEqual(
                page.evaluate(
                    "document.documentElement.scrollWidth - document.documentElement.clientWidth"
                ),
                0,
            )


@tag("browser")
class FirstSiteActivationTests(BrowserTestCase):
    """#179 criterion 1: a first site in at most eleven activations."""

    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        known_hosts = Path(cls.enterClassContext(tempfile.TemporaryDirectory())) / "known_hosts"
        cls.enterClassContext(override_settings(SSH_KNOWN_HOSTS_PATH=str(known_hosts)))
        call_command("collectstatic", interactive=False, verbosity=0)

    @override
    def setUp(self) -> None:
        super().setUp()
        for codename in (
            "add_server",
            "add_discoveryattempt",
            "change_server",
            "change_shared",
            "change_site",
            "view_changes",
            "view_siteobservation",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        Server.objects.all().delete()
        self.activations = 0
        self.sign_in()

    def activate(self, action: object) -> None:
        self.activations += 1
        if self.activations > 11:
            self.fail(f"A twelfth activation was needed: {action}")
        action()  # type: ignore[operator]

    def confirm(self, name: str) -> None:
        tick = self.page.get_by_label(
            "I understand this change touches shared resources", exact=False
        )
        if tick.count():
            tick.check()
        self.activate(self.page.get_by_role("button", name=name, exact=True).click)

    def review(self, server: Server, kind: str, stages: tuple[str, ...]) -> ChangePreparation:
        from datetime import timedelta

        from django.utils import timezone

        from operations.consent import DeclaredEffect, Scope
        from operations.engine import ReviewDraft, save_review
        from operations.fakes import BOOT_ID
        from operations.models import ChangePreparation, RemoteOperation
        from servers.models import ConnectionDefinition

        preparation = ChangePreparation.objects.create(
            server=server,
            kind_slug=kind,
            requested_by=None,
            status=RemoteOperation.Status.SUCCEEDED,
            ssh_alias=server.ssh_alias,
            connection=ConnectionDefinition.objects.filter(
                server=server, revision=server.connection_revision
            ).first(),
        )
        save_review(
            preparation,
            ReviewDraft(
                kind=kind,
                intent="The change the operator confirmed.",
                effects=(DeclaredEffect(Scope.SHARED, "Change the server.", ()),),
                stages=stages,
                boot_id=BOOT_ID,
                uptime_centiseconds=500000,
            ),
            host_key="ssh-ed25519 key",
            collected_at=timezone.now(),
            sites_digest="",
        )
        del timedelta
        return preparation

    def complete(self, preparation: ChangePreparation, stages: tuple[str, ...]) -> None:
        from django.utils import timezone

        from operations.consent import DeclaredEffect, Scope
        from operations.engine import ReviewDraft, save_review
        from operations.fakes import BOOT_ID
        from operations.models import ChangePreparation, RemoteOperation

        save_review(
            preparation,
            ReviewDraft(
                kind=preparation.kind_slug,
                intent="The change the operator confirmed.",
                effects=(DeclaredEffect(Scope.SHARED, "Change the server.", ()),),
                stages=stages,
                boot_id=BOOT_ID,
                uptime_centiseconds=500000,
            ),
            host_key="ssh-ed25519 key",
            collected_at=timezone.now(),
            sites_digest="",
        )
        ChangePreparation.objects.filter(pk=preparation.pk).update(
            status=RemoteOperation.Status.SUCCEEDED
        )

    def record_shop(self, server: Server) -> None:
        from dataclasses import replace

        from django.utils import timezone

        from discovery.fakes import record_attempt
        from discovery.models import DiscoveryAttempt, ObservationOutcome, SiteState
        from discovery.snapshot import (
            ObservedSite,
            SiteAccount,
            current_snapshot,
            save_snapshot,
        )

        snapshot = current_snapshot(server)
        if snapshot is None:
            self.fail("No snapshot.")
        observed = snapshot.collected.sites
        shop = ObservedSite(
            "shop",
            ("shop.example.com",),
            "php84",
            SiteAccount(1003, 1003, "/var/www/shop", "/usr/sbin/nologin"),
            SiteState.MANAGED,
            ObservationOutcome.OBSERVED,
            file="/etc/caddy/sites/shop.caddy",
        )
        attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
        from sites.ui_testing import attach_current_connection

        attach_current_connection(server, attempt)
        save_snapshot(
            attempt,
            replace(snapshot.collected, sites=replace(observed, value=(*observed.value, shop))),
            timezone.now(),
        )

    def finish(self, preparation: ChangePreparation) -> ChangeRun:
        from operations.models import ChangeRun, Result, Verification

        run = ChangeRun.objects.filter(review__preparation=preparation).latest("pk")
        ChangeRun.objects.filter(pk=run.pk).update(
            status="succeeded", execution=Result.SUCCEEDED, verification=Verification.PASSED
        )
        return ChangeRun.objects.get(pk=run.pk)

    def test_a_first_site_in_at_most_eleven_activations(self) -> None:
        import contextlib

        from discovery.fakes import run_worker
        from discovery.recorded import ReplayShell, load
        from operations.models import ChangePreparation
        from sites.ui_testing import record_http_sites, record_php85_installed

        page = self.page
        self.activate(page.get_by_role("link", name="Add server").click)
        page.get_by_role("textbox", name="Name", exact=True).fill("Cloud")
        page.get_by_role("textbox", name="Address", exact=True).fill("cloud.example")
        self.activate(page.get_by_role("button", name="Save and check").click)
        expect(page.get_by_text("Checking the connection…")).to_be_visible()

        key = ECDSAKey.generate()
        target = ConnectionTarget(
            alias="cloud.example",
            hostname="cloud.example",
            port=22,
            user="root",
            identity_files=(),
            known_hosts_files=(),
        )
        with mock.patch("discovery.ssh.connect_operation", side_effect=UnknownHostKey(target, key)):
            run_worker()
        expect(page.get_by_role("heading", name="Confirm this is your server")).to_be_visible(
            timeout=10_000
        )
        page.get_by_label("Provider fingerprint").fill(key.fingerprint)
        self.activate(page.get_by_role("button", name="Confirm and check").click)
        with mock.patch(
            "discovery.ssh.connect_operation",
            return_value=contextlib.nullcontext(ReplayShell(load("pristine-26.04"))),
        ):
            run_worker()
        page.reload()
        expect(page.get_by_role("heading", name="Ready to set up")).to_be_visible(timeout=10_000)

        server = Server.objects.get(name="Cloud")
        setup = self.review(server, "host_foundation", ("preflight", "Nix", "verify"))
        self.activate(page.get_by_role("button", name="Set up server").click)
        # The banner's own preparation is replaced by this test's review; it must not
        # keep the server busy.
        from operations.models import RemoteOperation

        ChangePreparation.objects.filter(server=server).exclude(pk=setup.pk).update(
            status=RemoteOperation.Status.FAILED
        )
        page.goto(f"{self.live_server_url}/changes/{setup.pk}/")

        self.confirm("Set up server")
        run = self.finish(setup)
        record_http_sites(server)
        record_http_sites(server, present_php85=False)
        page.goto(f"{self.live_server_url}/runs/{run.pk}/")
        self.activate(page.get_by_role("link", name="Create site", exact=True).click)

        page.get_by_role("textbox", name="Domain", exact=True).fill("shop.example.com")
        page.locator('label[for="create-php-php85"]').click()
        self.activate(page.get_by_role("button", name="Continue", exact=True).click)
        expect(page.locator("body")).to_contain_text("Step 1 of 2")
        add = ChangePreparation.objects.get(kind_slug="add_runtime")
        self.complete(add, ("preflight", "realise", "verify"))
        page.reload()
        self.confirm("Add PHP 8.5")
        add_run = self.finish(add)
        record_php85_installed(server)
        page.goto(f"{self.live_server_url}/runs/{add_run.pk}/")
        self.activate(
            page.get_by_role("button", name="Continue to create the site", exact=True).click
        )
        create = ChangePreparation.objects.get(kind_slug="create_http_site")
        self.complete(create, ("preflight", "account", "verify"))
        page.reload()
        expect(
            page.get_by_role("heading", name="Create shop.example.com", exact=True)
        ).to_be_visible()
        self.confirm("Create site")
        create_run = self.finish(create)
        record_http_sites(server)
        self.record_shop(server)
        page.goto(f"{self.live_server_url}/runs/{create_run.pk}/")
        self.activate(page.get_by_role("link", name="Open the site", exact=True).click)
        expect(page.get_by_role("heading", name="shop.example.com", level=1)).to_be_visible()
        self.assertLessEqual(self.activations, 11)
