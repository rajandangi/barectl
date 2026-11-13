"""Server Settings shows the observed journal retention policy and offers its form (#549, #551)."""

from dataclasses import replace
from typing import override
from unittest import mock

from django.utils import timezone

from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt
from discovery.snapshot import CollectedSnapshot, save_snapshot
from logs.journal_retention import (
    MANAGED,
    NOT_CONFIGURED,
    OUTSIDE,
    RetentionObservation,
)
from operations.services import read_changes
from servers.models import Server
from servers.testing import ControllerConfigTestCase


def snapshot(
    server: Server,
    retention: RetentionObservation | None,
    standing: Standing = Standing.TARGET_STACK,
) -> None:
    collected: CollectedSnapshot = replace(
        COLLECTED,
        components=(),
        standing=HostJudgment(standing, (), (), ()),
        journal_retention=retention,
    )
    attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
    save_snapshot(attempt, collected, timezone.now())


class JournalRetentionCardTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Logs", ssh_alias="logs.example.com")

    def get(self) -> str:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/settings/")
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_no_observation_shows_not_checked_yet(self) -> None:
        self.assertIn("Not checked yet", self.get())

    def test_a_stored_retention_state_is_not_checked_while_a_later_check_is_stale(self) -> None:
        snapshot(self.server, RetentionObservation(MANAGED, "", "2G", "3months"))
        record_attempt(self.server, DiscoveryAttempt.Status.FAILED, failure="Connection failed.")
        self.assertIn("Not checked yet", self.get())
        self.assertNotIn("3 months", self.get())

    def test_a_missing_file_is_not_configured(self) -> None:
        snapshot(self.server, RetentionObservation(NOT_CONFIGURED))
        page = self.get()
        self.assertIn("Not configured", page)
        self.assertNotIn("Not checked yet", page)

    def test_a_managed_pair_shows_both_effective_values(self) -> None:
        snapshot(self.server, RetentionObservation(MANAGED, "", "2G", "3months"))
        page = self.get()
        self.assertIn("Log retention", page)
        self.assertIn("2 GiB", page)
        self.assertIn("2G", page)
        self.assertIn("3 months", page)
        self.assertIn("3months", page)
        self.assertNotIn("Outside supported settings", page)

    def test_an_outside_state_shows_its_reason_and_no_control(self) -> None:
        snapshot(
            self.server,
            RetentionObservation(OUTSIDE, "A later configuration overrides the retention setting."),
        )
        self.grant("change_shared")
        page = self.get()
        self.assertIn("Outside supported settings", page)
        self.assertIn("A later configuration overrides the retention setting.", page)
        self.assertNotIn("Change log retention", page)
        self.assertNotIn("set_journal_retention", page)
        self.assertNotIn('name="disk_cap"', page)
        response = self.client.post(
            f"/servers/{self.server.pk}/settings/journal-retention/prepare/",
            {"disk_cap": "1G", "max_age": "3months"},
        )
        self.assertRedirects(response, f"/servers/{self.server.pk}/settings/")
        self.assertEqual(read_changes(self.server).rows, [])

    def test_a_managed_pair_offers_the_form_with_the_current_pair_preselected(self) -> None:
        snapshot(self.server, RetentionObservation(MANAGED, "", "2G", "3months"))
        self.grant("change_shared")
        page = self.get()
        self.assertIn('name="disk_cap"', page)
        self.assertIn('name="max_age"', page)
        self.assertIn('<option value="2G" selected>2 GiB</option>', page)
        self.assertIn('<option value="3months" selected>3 months</option>', page)
        self.assertIn("Change log retention", page)

    def test_not_configured_offers_the_form_with_one_gib_and_three_months(self) -> None:
        snapshot(self.server, RetentionObservation(NOT_CONFIGURED))
        self.grant("change_shared")
        page = self.get()
        self.assertIn('<option value="1G" selected>1 GiB</option>', page)
        self.assertIn('<option value="3months" selected>3 months</option>', page)

    def test_the_form_submits_the_exact_pair_and_reaches_its_preparation(self) -> None:
        snapshot(self.server, RetentionObservation(NOT_CONFIGURED))
        self.grant("change_shared")
        page = self.get()
        self.assertIn('name="disk_cap"', page)
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            response = self.client.post(
                f"/servers/{self.server.pk}/settings/journal-retention/prepare/",
                {"disk_cap": "500M", "max_age": "6months"},
            )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(rows[0].preparation.kind_slug, "set_journal_retention")
        self.assertEqual(
            rows[0].preparation.inputs,
            {"version": 1, "disk_cap": "500M", "max_age": "6months"},
        )

    def test_free_text_boolean_and_out_of_list_posts_are_refused_before_ssh(self) -> None:
        snapshot(self.server, RetentionObservation(NOT_CONFIGURED))
        self.grant("change_shared")
        posts = (
            {"disk_cap": "5G", "max_age": "3months"},
            {"disk_cap": "1G", "max_age": "2weeks"},
            {"disk_cap": "true", "max_age": "3months"},
            {"disk_cap": "1", "max_age": "3months"},
            {"disk_cap": "", "max_age": "3months"},
        )
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            for post in posts:
                with self.subTest(post=post):
                    response = self.client.post(
                        f"/servers/{self.server.pk}/settings/journal-retention/prepare/", post
                    )
                    self.assertRedirects(response, f"/servers/{self.server.pk}/settings/")
        self.assertEqual(read_changes(self.server).rows, [])

    def test_a_viewer_sees_the_state_and_no_control(self) -> None:
        snapshot(self.server, RetentionObservation(MANAGED, "", "1G", "1month"))
        self.user.user_permissions.clear()
        self.grant("view_server")
        page = self.get()
        self.assertIn("1 GiB", page)
        self.assertNotIn("Change log retention", page)
        self.assertNotIn('name="disk_cap"', page)
        self.assertIn("does not have permission to prepare changes", page)

    def test_a_site_operator_without_shared_permission_sees_the_reason(self) -> None:
        snapshot(self.server, RetentionObservation(NOT_CONFIGURED))
        page = self.get()
        self.assertIn("Changing this needs the shared-change permission.", page)
        self.assertNotIn('name="disk_cap"', page)
        response = self.client.post(
            f"/servers/{self.server.pk}/settings/journal-retention/prepare/",
            {"disk_cap": "1G", "max_age": "3months"},
        )
        self.assertRedirects(response, f"/servers/{self.server.pk}/settings/")
        self.assertEqual(read_changes(self.server).rows, [])

    def test_a_user_with_shared_permission_sees_no_withheld_reason(self) -> None:
        snapshot(self.server, RetentionObservation(NOT_CONFIGURED))
        self.grant("change_shared")
        page = self.get()
        self.assertNotIn("Changing this needs the shared-change permission.", page)

    def test_a_missing_observation_refuses_a_direct_post(self) -> None:
        self.grant("change_shared")
        response = self.client.post(
            f"/servers/{self.server.pk}/settings/journal-retention/prepare/",
            {"disk_cap": "1G", "max_age": "3months"},
        )
        self.assertRedirects(response, f"/servers/{self.server.pk}/settings/")
        self.assertEqual(read_changes(self.server).rows, [])
