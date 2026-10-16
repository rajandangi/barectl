from dataclasses import replace
from typing import override
from unittest import mock

from django.utils import timezone

from discovery.fakes import record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome, SiteState
from discovery.snapshot import current_snapshot, save_snapshot
from operations.services import read_changes
from servers.models import Server
from servers.testing import ControllerConfigTestCase

from .ui_testing import record_http_sites


class SitePhpPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="PHP", ssh_alias="php.example.com")
        record_http_sites(self.server)
        self.url = f"/servers/{self.server.pk}/sites/alpha/runtime/php/prepare/"

    def test_post_queues_only_versioned_site_selection_without_ssh(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            response = self.client.post(
                self.url, {"selection": "php84", "path": "/untrusted/program"}
            )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(
            rows[0].preparation.inputs,
            {"version": 1, "identifier": "alpha", "selection": "php84"},
        )

    def test_unverified_target_cannot_be_queued(self) -> None:
        response = self.client.post(self.url, {"selection": "php85"})
        self.assertRedirects(response, f"/servers/{self.server.pk}/sites/alpha/runtime/")
        self.assertEqual(read_changes(self.server).rows, [])

    def test_failed_refresh_cannot_reuse_old_runtime_choices(self) -> None:
        record_attempt(self.server, DiscoveryAttempt.Status.FAILED)
        response = self.client.post(self.url, {"selection": "php84"})
        self.assertRedirects(response, f"/servers/{self.server.pk}/sites/alpha/runtime/")
        self.assertEqual(read_changes(self.server).rows, [])

    def test_viewer_cannot_submit_php_selection(self) -> None:
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(self.url, {"selection": "php84"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(read_changes(self.server).rows, [])

    def test_busy_server_does_not_queue_another_preparation(self) -> None:
        self.client.post(self.url, {"selection": "php84"})
        response = self.client.post(self.url, {"selection": "php84"})
        self.assertRedirects(response, f"/servers/{self.server.pk}/sites/alpha/runtime/")
        self.assertEqual(len(read_changes(self.server).rows), 1)

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
        response = self.client.post(self.url, {"selection": "php84"})
        self.assertRedirects(response, f"/servers/{self.server.pk}/sites/alpha/runtime/")
        self.assertEqual(read_changes(self.server).rows, [])

    def record_transition(
        self, *, problem: str = "The PHP runtime transition is incomplete."
    ) -> None:
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("No setup snapshot.")
        observed = snapshot.collected.sites
        sites = tuple(
            replace(
                site,
                state=SiteState.PARTLY_APPLIED,
                missing=(problem,),
            )
            for site in observed.value
        )
        save_snapshot(
            record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED),
            replace(snapshot.collected, sites=replace(observed, value=sites)),
            timezone.now(),
        )

    def test_native_recognized_transition_offers_finish_or_reverse_review(self) -> None:
        self.record_transition()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/runtime/")
            queued = self.client.post(self.url, {"selection": "php84"})
        self.assertContains(response, "Finish or reverse the PHP transition")
        self.assertContains(response, "Select site PHP runtime")
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
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
                self.assertRedirects(response, f"/servers/{self.server.pk}/sites/alpha/runtime/")
                self.assertEqual(read_changes(self.server).rows, [])

    def test_failed_refresh_still_blocks_transition_recovery(self) -> None:
        self.record_transition()
        record_attempt(self.server, DiscoveryAttempt.Status.FAILED)
        response = self.client.post(self.url, {"selection": "php84"})
        self.assertRedirects(response, f"/servers/{self.server.pk}/sites/alpha/runtime/")
        self.assertEqual(read_changes(self.server).rows, [])

    def test_recovery_can_review_either_installed_final_runtime(self) -> None:
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
                self.assertRedirects(response, f"/servers/{self.server.pk}/sites/alpha/runtime/")
                self.assertEqual(read_changes(self.server).rows, [])
