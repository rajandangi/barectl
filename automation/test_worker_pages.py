"""The Queue workers settings section, the Overview line and the attention banner."""

from datetime import UTC, datetime
from typing import override
from unittest import mock

from django.test import SimpleTestCase

from automation.testing import observed_worker, record_worker
from automation.worker_status import WorkerStatus
from automation.workers import WorkerDefinition
from discovery.snapshot import current_snapshot
from servers.attention import needs_attention
from servers.models import Server
from servers.testing import ControllerConfigTestCase

CHECKED = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
LAST_RUN = 1_761_393_600_000_000


class QueueWorkerPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def settings_page(self) -> str:
        response = self.client.get(f"/servers/{self.server.pk}/sites/shop/settings/")
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_the_section_shows_the_definition_and_state_without_contacting_anyone(self) -> None:
        record_worker(
            self.server,
            row=observed_worker(
                definition=WorkerDefinition(("default", "mail"), 2, 60),
                active_processes=2,
                last_start_us=LAST_RUN,
                last_exit_us=LAST_RUN + 5_000_000,
            ),
            checked_at=CHECKED,
        )
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            html = self.settings_page()
        for expected in (
            "Queue workers",
            "On, running",
            "default, mail",
            "2",
            "60 seconds",
            "Stop",
            "Restart",
            "Apply settings",
            "Oct 25, 2026",
        ):
            self.assertIn(expected, html)
        for native in ("systemd", "unit", "slice", "timer", "journal", "socket"):
            self.assertNotIn(native, html.lower())

    def test_a_viewer_reads_the_state_and_is_not_offered_the_action(self) -> None:
        record_worker(self.server)
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        html = self.settings_page()
        self.assertIn("Queue workers", html)
        self.assertIn("permission to", html)
        self.assertNotIn("site_queue_workers_prepare", html)

    def test_preparing_needs_the_site_change_permission(self) -> None:
        record_worker(self.server)
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/shop/settings/queue-workers/prepare/",
            {"action": "stop"},
        )
        self.assertEqual(response.status_code, 403)

    def test_start_queues_one_site_review_with_the_validated_definition(self) -> None:
        from operations.services import read_changes

        record_worker(self.server, row=observed_worker(status=WorkerStatus.OFF, installed=False))
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/shop/settings/queue-workers/prepare/",
            {"action": "start", "queues": "default, mail", "processes": "2", "timeout": "120"},
        )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0].preparation.inputs,
            {
                "version": 1,
                "identifier": "shop",
                "action": "start",
                "queues": ["default", "mail"],
                "processes": 2,
                "timeout": 120,
            },
        )
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")

    def test_stop_queues_only_the_action(self) -> None:
        from operations.services import read_changes

        record_worker(self.server)
        self.client.post(
            f"/servers/{self.server.pk}/sites/shop/settings/queue-workers/prepare/",
            {"action": "stop"},
        )
        rows = read_changes(self.server).rows
        self.assertEqual(
            rows[0].preparation.inputs,
            {"version": 1, "identifier": "shop", "action": "stop"},
        )

    def test_an_invalid_definition_is_refused_without_queuing_anything(self) -> None:
        from operations.services import read_changes

        record_worker(self.server, row=observed_worker(status=WorkerStatus.OFF, installed=False))
        for data in (
            {"action": "start", "queues": "Default", "processes": "1", "timeout": "60"},
            {"action": "start", "queues": "default", "processes": "5", "timeout": "60"},
            {"action": "start", "queues": "default", "processes": "1", "timeout": "5"},
            {"action": "start", "queues": "", "processes": "1", "timeout": "60"},
            {"action": "maybe"},
        ):
            with self.subTest(data=data):
                self.client.post(
                    f"/servers/{self.server.pk}/sites/shop/settings/queue-workers/prepare/",
                    data,
                )
        self.assertEqual(read_changes(self.server).rows, [])

    def test_a_site_with_no_laravel_evidence_has_no_section(self) -> None:
        from sites.ui_testing import record_site_settings

        record_site_settings(self.server, identifier="alpha", application="plain")
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/settings/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Queue workers", response.content.decode())

    def test_the_overview_shows_one_plain_line_with_the_checked_time(self) -> None:
        record_worker(self.server, checked_at=CHECKED)
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/shop/")
        html = response.content.decode()
        self.assertIn("Queue workers: On, running", html)
        self.assertIn("Checked", html)
        self.assertIn("Oct 25, 2026", html)

    def test_a_crash_loop_marks_the_overview_and_the_server_attention(self) -> None:
        record_worker(
            self.server,
            row=observed_worker(
                status=WorkerStatus.STOPPED_AFTER_CRASHES,
                result="start-limit-hit",
                active_processes=0,
                nrestarts=5,
            ),
            checked_at=CHECKED,
        )
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            overview = self.client.get(f"/servers/{self.server.pk}/sites/shop/")
        self.assertIn("Stopped after repeated crashes", overview.content.decode())
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("No snapshot.")
        findings = needs_attention(self.server.pk, snapshot.collected, can_set_up=True)
        workers = [finding for finding in findings if finding.kind == "Queue workers"]
        self.assertEqual(len(workers), 1)
        self.assertIn("repeated crashes", workers[0].finding)
        self.assertTrue(workers[0].action_url.endswith("#queue-workers"))

    def test_a_deliberate_stop_is_not_an_alarm(self) -> None:
        record_worker(
            self.server,
            row=observed_worker(status=WorkerStatus.OFF, enabled=False, active_processes=0),
        )
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("No snapshot.")
        self.assertEqual(
            [
                row
                for row in needs_attention(self.server.pk, snapshot.collected, can_set_up=True)
                if row.kind == "Queue workers"
            ],
            [],
        )


class FreshControllerTests(ControllerConfigTestCase):
    def test_the_snapshot_reconstructs_the_definition_and_state(self) -> None:
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        record_worker(
            server,
            row=observed_worker(
                definition=WorkerDefinition(("critical", "mail"), 2, 120),
                active_processes=2,
                last_start_us=LAST_RUN,
                last_exit_us=LAST_RUN + 1_000_000,
            ),
            checked_at=CHECKED,
        )
        snapshot = current_snapshot(server)
        if snapshot is None:
            self.fail("The snapshot was stored.")
        row = next(iter(snapshot.collected.workers.value))
        self.assertEqual(row.definition, WorkerDefinition(("critical", "mail"), 2, 120))
        self.assertEqual(row.status, WorkerStatus.RUNNING)
        self.assertEqual(row.queues, ("critical", "mail"))
        self.assertEqual(row.evidence.identifier, "shop")


class WorkerInputTests(SimpleTestCase):
    def test_the_input_decoder_round_trips_and_refuses_other_values(self) -> None:
        from operations.inputs import InputShape, decode_inputs

        decoded = decode_inputs(
            {
                "version": 1,
                "identifier": "shop",
                "action": "start",
                "queues": ["default", "mail"],
                "processes": 2,
                "timeout": 60,
            },
            (),
            InputShape.LARAVEL_QUEUE_WORKERS,
        )
        self.assertEqual(
            decoded.document(),
            {
                "version": 1,
                "identifier": "shop",
                "action": "start",
                "queues": ["default", "mail"],
                "processes": 2,
                "timeout": 60,
            },
        )
        stopped = decode_inputs(
            {"version": 1, "identifier": "shop", "action": "stop"},
            (),
            InputShape.LARAVEL_QUEUE_WORKERS,
        )
        self.assertEqual(stopped.document(), {"version": 1, "identifier": "shop", "action": "stop"})
        for value in (
            {
                "version": 1,
                "identifier": "shop",
                "action": "start",
                "queues": ["Default"],
                "processes": 1,
                "timeout": 60,
            },
            {
                "version": 1,
                "identifier": "shop",
                "action": "start",
                "queues": ["default"],
                "processes": 5,
                "timeout": 60,
            },
            {"version": 1, "identifier": "SHOP", "action": "stop"},
            {"version": 1, "identifier": "shop", "action": "maybe"},
            {"version": 1, "identifier": "shop", "action": "start", "queues": ["default"]},
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decode_inputs(value, (), InputShape.LARAVEL_QUEUE_WORKERS)
