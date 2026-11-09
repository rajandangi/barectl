"""Check feedback is visible while the worker still holds its SSH connection."""

from datetime import timedelta

from django.utils import timezone

from discovery import services
from discovery.models import DiscoveryAttempt, DiscoverySnapshot
from discovery.ssh import CommandResult
from servers.discovery_state import server_state
from servers.testing import HTMX_FRAGMENT

from .check_progress import CheckProgress, CheckStage
from .fakes import PREPARE_PERMISSIONS, ChangeTestCase
from .models import ChangePreparation, ChangeReview, RemoteOperation


class CheckProgressTests(ChangeTestCase):
    def test_preparation_publishes_reads_before_its_confirmation_is_ready(self) -> None:
        self.sign_in_with(*PREPARE_PERMISSIONS)
        self.client.post(f"/servers/{self.server.pk}/changes/prepare/", {"kind": "cleanup_runs"})
        preparation = ChangePreparation.objects.get()
        counts: list[int] = []

        def observe(command: str) -> CommandResult | None:
            preparation.refresh_from_db()
            self.assertEqual(preparation.status, RemoteOperation.Status.RUNNING)
            self.assertFalse(ChangeReview.objects.filter(preparation=preparation).exists())
            counts.append(preparation.check_reads)
            if len(counts) == 2:
                RemoteOperation.objects.filter(pk=preparation.pk).update(
                    check_updated_at=timezone.now() - timedelta(seconds=30)
                )
                page = self.client.get(f"/changes/{preparation.pk}/", headers=HTMX_FRAGMENT)
                self.assertContains(page, "Read server configuration")
                self.assertContains(page, "1 server read finished")
                self.assertContains(page, 'aria-current="step"')
                self.assertContains(page, "Waiting for the server to respond.")
                self.assertNotContains(page, f'action="/changes/{preparation.pk}/apply/"')
            return None

        self.remote.answers.insert(0, observe)
        self.run_worker()
        preparation.refresh_from_db()
        self.assertEqual(counts, list(range(len(counts))))
        self.assertGreater(len(counts), 1)
        self.assertEqual(preparation.status, RemoteOperation.Status.SUCCEEDED)
        self.assertEqual(preparation.check_reads, len(counts))
        before = preparation.check_updated_at
        CheckProgress(preparation).report(CheckStage.CONNECT)
        preparation.refresh_from_db()
        self.assertEqual(preparation.check_stage, CheckStage.SAVE)
        self.assertEqual(preparation.check_updated_at, before)

    def test_discovery_publishes_sections_without_publishing_a_partial_snapshot(self) -> None:
        self.sign_in_with("view_server", "add_discoveryattempt")
        attempt = services.queue_discovery(self.server)
        states: list[str] = []
        shown = ""

        def observe(command: str) -> CommandResult | None:
            nonlocal shown
            current = DiscoveryAttempt.objects.get(pk=attempt.pk)
            if states and current.check_stage == states[-1]:
                return None
            states.append(current.check_stage)
            self.assertEqual(current.status, RemoteOperation.Status.RUNNING)
            self.assertFalse(DiscoverySnapshot.objects.filter(attempt=current).exists())
            state = server_state(self.server)
            self.assertTrue(state.changed_since(shown))
            page = self.client.get(
                f"/servers/{self.server.pk}/status/", {"shown": shown}, headers=HTMX_FRAGMENT
            )
            self.assertContains(page, 'aria-label="Server check progress"')
            self.assertContains(page, 'aria-current="step"')
            self.assertContains(page, state.announcement)
            shown = state.poll_token
            self.assertFalse(state.changed_since(shown))
            return None

        self.remote.answers.insert(0, observe)
        self.run_worker()
        self.assertEqual(states, [CheckStage.SYSTEM, CheckStage.SOFTWARE, CheckStage.PROTECTION])
        self.assertTrue(DiscoverySnapshot.objects.filter(attempt=attempt).exists())
        page = self.client.get(f"/servers/{self.server.pk}/status/", headers=HTMX_FRAGMENT)
        self.assertNotContains(page, 'hx-trigger="every 2s"')
        self.assertNotContains(page, 'aria-label="Server check progress"')
