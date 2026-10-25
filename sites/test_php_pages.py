"""Journey 5: a site's PHP version is changed from Settings (docs/dashboard-workflows.md)."""

import re
from dataclasses import replace
from typing import override
from unittest import mock

from django.test import Client
from django.utils import timezone

from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome, SiteState
from discovery.snapshot import current_snapshot, save_snapshot
from operations.engine import ReviewDraft, save_review
from operations.fakes import BOOT_ID
from operations.models import ChangeRun, RemoteOperation
from operations.services import read_changes
from servers.connections import saved_alias
from servers.models import Server
from servers.testing import ControllerConfigTestCase

from .observation import PHP_TRANSITION_INCOMPLETE
from .php_change import SLUG
from .ui_testing import record_http_sites, record_php85_installed, record_step_run

BANNED = (
    "master",
    "pool",
    "fpm",
    "haproxy",
    "admission",
    "caddy",
    "nix",
    "store path",
    "catalog",
    "socket",
    "opcache",
    "systemd",
    "unit",
    "invocation",
    "journal",
    "stage",
    "standing",
    "foundation",
    "evidence",
    "consent level",
    "review",
    "plan",
    "digest",
    "known_hosts",
)


class SitePhpSettingsTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="PHP", ssh_alias="php.example.com")
        record_http_sites(self.server)
        self.settings_url = f"/servers/{self.server.pk}/sites/alpha/settings/"
        self.url = f"/servers/{self.server.pk}/sites/alpha/runtime/php/prepare/"

    def record_incomplete_switch(self) -> None:
        record_php85_installed(self.server)
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("No snapshot.")
        observed = snapshot.collected.sites
        sites = tuple(
            replace(
                site,
                php_version="php85",
                state=SiteState.PARTLY_APPLIED,
                missing=(PHP_TRANSITION_INCOMPLETE,),
            )
            if site.identifier == "alpha"
            else site
            for site in observed.value
        )
        save_snapshot(
            record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED),
            replace(snapshot.collected, sites=replace(observed, value=sites)),
            timezone.now(),
        )

    def test_an_incomplete_switch_offers_finish_or_stay_on_the_site_page(self) -> None:
        self.record_incomplete_switch()
        page = self.client.get(f"/servers/{self.server.pk}/sites/alpha/")
        content = page.content.decode()
        self.assertIn("from 8.4 to 8.5", content)
        self.assertIn("did not finish.", content)
        self.assertIn("Finish the switch", content)
        self.assertIn("Stay on PHP 8.4", content)
        for label, selection in (
            ("Finish the switch", "php85"),
            ("Stay on PHP 8.4", "php84"),
        ):
            with self.subTest(action=label):
                response = self.client.post(self.url, {"selection": selection})
                self.assertEqual(response.status_code, 302)
                rows = read_changes(self.server).rows
                self.assertEqual(rows[0].preparation.kind_slug, SLUG)
                self.assertEqual(rows[0].preparation.inputs["selection"], selection)
                RemoteOperation.objects.filter(pk=rows[0].preparation.pk).update(
                    status=RemoteOperation.Status.SUCCEEDED
                )

    def test_settings_shows_the_current_version_and_the_change_action_without_ssh(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(self.settings_url)
        self.assertContains(response, "PHP version:")
        self.assertContains(response, "<strong>8.4</strong>")
        self.assertContains(response, "Change PHP version")
        self.assertContains(response, "?change=php#change-php")
        self.assertContains(response, "PHP settings")
        self.assertContains(response, "Readiness check")

    def test_the_choice_offers_the_other_versions_and_not_the_current_one(self) -> None:
        response = self.client.get(f"{self.settings_url}?change=php")
        self.assertContains(response, 'id="site-php-php85"')
        self.assertContains(response, "PHP 8.5")
        self.assertContains(response, "Installed first, adds about")
        self.assertNotContains(response, 'id="site-php-php84"')

    def test_an_installed_version_queues_the_site_switch(self) -> None:
        record_php85_installed(self.server)
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            response = self.client.post(
                self.url, {"selection": "php85", "path": "/untrusted/program"}
            )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].preparation.kind_slug, SLUG)
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(
            rows[0].preparation.inputs,
            {"version": 1, "identifier": "alpha", "selection": "php85"},
        )

    def test_a_forged_prepare_for_the_current_version_is_refused(self) -> None:
        response = self.client.post(self.url, {"selection": "php84"})
        self.assertRedirects(response, self.settings_url)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_a_forged_prepare_outside_the_catalog_is_refused(self) -> None:
        response = self.client.post(self.url, {"selection": "php86"})
        self.assertRedirects(response, self.settings_url)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_a_missing_version_is_step_one_and_keeps_the_choice(self) -> None:
        response = self.client.post(self.url, {"selection": "php85"})
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        preparation = rows[0].preparation
        self.assertEqual(preparation.kind_slug, "add_runtime")
        self.assertEqual(preparation.inputs, {"version": 1, "selection": "php85"})
        self.assertRedirects(response, f"/changes/{preparation.pk}/")
        page = self.client.get(f"/changes/{preparation.pk}/")
        self.assertContains(page, "Step 1 of 2: add PHP 8.5 to this server")
        run = record_step_run(preparation)
        run_page = self.client.get(f"/runs/{run.pk}/")
        self.assertContains(run_page, "Continue to switch the site")
        self.assertContains(
            run_page,
            f'href="/servers/{self.server.pk}/sites/alpha/settings/'
            "?change=php&amp;selection=php85#change-php",
        )
        choice = self.client.get(f"{self.settings_url}?change=php&selection=php85")
        self.assertRegex(
            choice.content.decode(),
            r'id="site-php-php85"\s+value="php85"\s+checked',
        )
        record_php85_installed(self.server)
        response = self.client.post(self.url, {"selection": "php85"})
        rows = read_changes(self.server).rows
        self.assertEqual(rows[0].preparation.kind_slug, SLUG)
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")

    def test_the_settings_default_text_avoids_native_terms(self) -> None:
        response = self.client.get(f"{self.settings_url}?change=php")
        text = re.sub(r"<[^>]+>", " ", response.content.decode()).lower()
        for word in BANNED:
            with self.subTest(word=word):
                self.assertNotRegex(text, rf"\b{re.escape(word)}\b")

    def test_viewer_cannot_submit_a_php_change(self) -> None:
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(self.url, {"selection": "php85"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_csrf_is_required(self) -> None:
        csrf = Client(enforce_csrf_checks=True)
        csrf.force_login(self.user)
        self.assertEqual(csrf.post(self.url, {"selection": "php85"}).status_code, 403)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_a_failed_refresh_cannot_reuse_old_choices(self) -> None:
        record_attempt(self.server, DiscoveryAttempt.Status.FAILED)
        response = self.client.post(self.url, {"selection": "php85"})
        self.assertRedirects(response, self.settings_url)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_busy_server_does_not_queue_another_preparation(self) -> None:
        record_php85_installed(self.server)
        self.client.post(self.url, {"selection": "php85"})
        response = self.client.post(self.url, {"selection": "php85"})
        self.assertRedirects(response, self.settings_url)
        self.assertEqual(len(read_changes(self.server).rows), 1)

    def test_a_reconciling_run_explains_why_no_choice_is_offered(self) -> None:
        self.client.post(self.url, {"selection": "php85"})
        preparation = read_changes(self.server).rows[0].preparation
        RemoteOperation.objects.filter(pk=preparation.pk).update(
            status=RemoteOperation.Status.SUCCEEDED
        )
        review = save_review(
            preparation,
            ReviewDraft(
                SLUG, "Switch the site's PHP version", boot_id=BOOT_ID, uptime_centiseconds=1
            ),
            host_key="ssh-ed25519 key",
            collected_at=timezone.now(),
            sites_digest="",
        )
        run = ChangeRun.objects.create(
            server=self.server,
            review=review,
            unit_name="barectl-apply-" + "b" * 32 + ".service",
            status=RemoteOperation.Status.RECONCILING,
        )
        response = self.client.get(self.settings_url)
        self.assertNotContains(response, "Change PHP version</a>")
        self.assertContains(response, f'href="/runs/{run.pk}/"')
        self.assertContains(response, "Nothing else can be prepared for this server")

    def test_the_settings_page_names_the_saved_address_not_its_internal_alias(self) -> None:
        Server.objects.filter(pk=self.server.pk).update(
            connection_mode="agent",
            address="203.0.113.7",
            ssh_alias=saved_alias("203.0.113.7", "root", 22),
        )
        response = self.client.get(self.settings_url)
        self.assertNotContains(response, "saved-")

    def test_unmanaged_site_cannot_queue_a_php_switch(self) -> None:
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("No setup snapshot.")
        observed = snapshot.collected.sites
        sites = tuple(replace(site, state=SiteState.NOT_FOLLOWING) for site in observed.value)
        save_snapshot(
            record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED),
            replace(snapshot.collected, sites=replace(observed, value=sites)),
            timezone.now(),
        )
        response = self.client.post(self.url, {"selection": "php85"})
        self.assertRedirects(response, self.settings_url)
        self.assertEqual(read_changes(self.server).rows, [])

    def record_transition(
        self, *, problem: str = "The PHP runtime transition is incomplete."
    ) -> None:
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("No setup snapshot.")
        observed = snapshot.collected.sites
        sites = tuple(
            replace(site, state=SiteState.PARTLY_APPLIED, missing=(problem,))
            for site in observed.value
        )
        save_snapshot(
            record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED),
            replace(snapshot.collected, sites=replace(observed, value=sites)),
            timezone.now(),
        )

    def test_native_recognized_transition_offers_finish_or_reverse_in_settings(self) -> None:
        self.record_transition()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            response = self.client.get(self.settings_url)
            queued = self.client.post(self.url, {"selection": "php84"})
        self.assertContains(response, "Finish or reverse the PHP change")
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].preparation.kind_slug, SLUG)
        self.assertRedirects(queued, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(
            rows[0].preparation.inputs, {"version": 1, "identifier": "alpha", "selection": "php84"}
        )

    def test_other_partial_findings_cannot_request_recovery(self) -> None:
        for problem in (
            "The site's independent PHP service or socket is absent.",
            "The private PHP admission evidence is unavailable.",
        ):
            with self.subTest(problem=problem):
                self.record_transition(problem=problem)
                response = self.client.post(self.url, {"selection": "php84"})
                self.assertRedirects(response, self.settings_url)
                self.assertEqual(read_changes(self.server).rows, [])

    def test_failed_refresh_still_blocks_transition_recovery(self) -> None:
        self.record_transition()
        record_attempt(self.server, DiscoveryAttempt.Status.FAILED)
        response = self.client.post(self.url, {"selection": "php84"})
        self.assertRedirects(response, self.settings_url)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_recovery_can_review_either_installed_final_version(self) -> None:
        self.record_transition()
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("No setup snapshot.")
        runtimes = tuple(
            replace(
                runtime,
                path=runtime.path or "/nix/store/observed-php85",
                master_state="active",
                problem="",
            )
            for runtime in snapshot.collected.runtimes
        )
        save_snapshot(
            record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED),
            replace(snapshot.collected, runtimes=runtimes),
            timezone.now(),
        )
        response = self.client.post(self.url, {"selection": "php85"})
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(
            rows[0].preparation.inputs, {"version": 1, "identifier": "alpha", "selection": "php85"}
        )

    def test_recovery_refuses_unobserved_or_additionally_changed_site(self) -> None:
        self.record_transition()
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("No setup snapshot.")
        observed = snapshot.collected.sites
        site = observed.value[0]
        for changed in (
            replace(site, outcome=ObservationOutcome.INACCESSIBLE),
            replace(site, missing=(*site.missing, "The deploy lock is unsafe.")),
            replace(site, file="/etc/caddy/sites/foreign.caddy"),
        ):
            with self.subTest(changed=changed):
                save_snapshot(
                    record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED),
                    replace(snapshot.collected, sites=replace(observed, value=(changed,))),
                    timezone.now(),
                )
                response = self.client.post(self.url, {"selection": "php84"})
                self.assertRedirects(response, self.settings_url)
                self.assertEqual(read_changes(self.server).rows, [])
