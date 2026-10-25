"""The Scheduled tasks settings section, the Overview line and the attention banner."""

from datetime import UTC, datetime
from typing import override
from unittest import mock

from django.test import SimpleTestCase

from automation.observation import ObservedSchedule
from automation.status import ScheduleStatus
from automation.testing import record_schedule, schedule
from discovery.snapshot import current_snapshot
from servers.attention import needs_attention
from servers.models import Server
from servers.testing import ControllerConfigTestCase

CHECKED = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
LAST_RUN = 1_761_393_600_000_000


def on() -> tuple[ObservedSchedule, ...]:
    return (
        schedule(
            status=ScheduleStatus.SUCCEEDED,
            installed=True,
            disable="true",
            timer_active=True,
            timer_enabled=True,
            result="success",
            last_start_us=LAST_RUN,
            last_exit_us=LAST_RUN + 5_000_000,
        ),
    )


def failing() -> tuple[ObservedSchedule, ...]:
    return (
        schedule(
            status=ScheduleStatus.FAILED,
            installed=True,
            disable="true",
            timer_active=True,
            timer_enabled=True,
            result="exit-code",
            last_start_us=LAST_RUN,
            last_exit_us=LAST_RUN + 5_000_000,
        ),
    )


class ScheduledTasksPageTests(ControllerConfigTestCase):
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

    def test_the_section_shows_the_state_and_last_result_without_contacting_anyone(self) -> None:
        record_schedule(self.server, rows=on(), disable="true", checked_at=CHECKED)
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            html = self.settings_page()
        self.assertIn("Scheduled tasks", html)
        self.assertIn("On, the last run succeeded", html)
        self.assertIn("Turn off", html)
        self.assertIn("Oct 25, 2026", html)
        for native in ("systemd", "timer", "slice", "journal", "socket"):
            self.assertNotIn(native, html.lower())

    def test_a_viewer_reads_the_state_and_is_not_offered_the_action(self) -> None:
        record_schedule(self.server)
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        html = self.settings_page()
        self.assertIn("Scheduled tasks", html)
        self.assertIn("permission to change this site", html)
        self.assertNotIn("site_scheduled_tasks_prepare", html)

    def test_preparing_needs_the_site_change_permission(self) -> None:
        record_schedule(self.server)
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/shop/settings/scheduled-tasks/prepare/",
            {"state": "on"},
        )
        self.assertEqual(response.status_code, 403)

    def test_turning_on_queues_one_site_review_with_no_secret(self) -> None:
        from operations.services import read_changes

        record_schedule(self.server)
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/shop/settings/scheduled-tasks/prepare/",
            {"state": "on"},
        )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0].preparation.inputs,
            {"version": 1, "identifier": "shop", "state": "on"},
        )
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")

    def test_an_unknown_action_is_refused_without_queuing_anything(self) -> None:
        from operations.services import read_changes

        record_schedule(self.server)
        self.client.post(
            f"/servers/{self.server.pk}/sites/shop/settings/scheduled-tasks/prepare/",
            {"state": "maybe"},
        )
        self.assertEqual(read_changes(self.server).rows, [])

    def test_a_site_with_no_wordpress_evidence_has_no_section(self) -> None:
        from sites.ui_testing import record_site_settings

        record_site_settings(self.server, identifier="alpha", application="plain")
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/settings/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Scheduled tasks", response.content.decode())

    def test_the_overview_shows_one_plain_line_with_the_checked_time(self) -> None:
        record_schedule(self.server, rows=on(), disable="true", checked_at=CHECKED)
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/shop/")
        html = response.content.decode()
        self.assertIn("Scheduled tasks: On, the last run succeeded", html)
        self.assertIn("Checked", html)
        self.assertIn("Oct 25, 2026", html)

    def test_a_failed_run_marks_the_overview_and_the_server_attention(self) -> None:
        record_schedule(self.server, rows=failing(), disable="true", checked_at=CHECKED)
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            overview = self.client.get(f"/servers/{self.server.pk}/sites/shop/")
        self.assertIn("the last run failed", overview.content.decode())
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("No snapshot.")
        findings = needs_attention(self.server.pk, snapshot.collected, can_set_up=True)
        scheduled = [finding for finding in findings if finding.kind == "Scheduled tasks"]
        self.assertEqual(len(scheduled), 1)
        self.assertEqual(scheduled[0].name, "shop")
        self.assertIn("failed", scheduled[0].finding)
        self.assertTrue(scheduled[0].action_url.endswith("#scheduled-tasks"))


class ScheduleInputTests(SimpleTestCase):
    def test_the_input_decoder_round_trips_and_refuses_other_values(self) -> None:
        from operations.inputs import InputShape, decode_inputs

        decoded = decode_inputs(
            {"version": 1, "identifier": "shop", "state": "off"},
            (),
            InputShape.AUTOMATION_SCHEDULE,
        )
        self.assertEqual(decoded.document(), {"version": 1, "identifier": "shop", "state": "off"})
        for value in (
            {"version": 1, "identifier": "shop", "state": "maybe"},
            {"version": 1, "identifier": "SHOP", "state": "on"},
            {"version": 1, "identifier": "shop"},
            {"version": "1", "identifier": "shop", "state": "on"},
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decode_inputs(value, (), InputShape.AUTOMATION_SCHEDULE)


class AttentionTests(ControllerConfigTestCase):
    def test_a_deliberate_off_state_is_not_an_alarm(self) -> None:
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        record_schedule(self.server, rows=(schedule(),))
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("No snapshot.")
        self.assertEqual(
            [
                row
                for row in needs_attention(self.server.pk, snapshot.collected, can_set_up=True)
                if row.kind == "Scheduled tasks"
            ],
            [],
        )
