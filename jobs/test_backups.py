"""Backup runs and schedules in Jobs (#286)."""

from datetime import timedelta
from typing import override

from django.test import TestCase
from django.utils import timezone

from backups.observation import BackupRun, BackupTimer, OffsiteStorage
from discovery.fakes import current
from servers.models import Server

from . import presentation
from .backups import (
    BACKUP_SCHEDULE,
    CAPTURE,
    CLEANUP,
    COPY,
    BackupRunRow,
    BackupTimerRow,
)
from .filters import Selection
from .testing import backup, record_jobs, run, timer


class BackupJobsTests(TestCase):
    @override
    def setUp(self) -> None:
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        self.now = timezone.now().replace(microsecond=0)

    def view(
        self,
        *runs: BackupRun,
        timers: tuple[BackupTimer, ...] = (),
        warning: str = "",
        may_view_changes: bool = True,
        selection: Selection | None = None,
        offsite: OffsiteStorage | None = None,
    ) -> presentation.JobsView:
        record_jobs(
            self.server,
            backups=(backup(runs=runs, timers=timers, offsite=offsite),),
            backups_warning=warning,
        )
        return presentation.present(
            current(self.server),
            self.server,
            may_view_changes=may_view_changes,
            selection=selection,
        )

    def recent(self, view: presentation.JobsView) -> tuple[BackupRunRow, ...]:
        group = next(group for group in view.groups if group.key == "recent")
        return tuple(row for row in group.rows if isinstance(row, BackupRunRow))

    def attention(self, view: presentation.JobsView) -> tuple[BackupRunRow, ...]:
        if not view.groups or view.groups[0].key != "attention":
            return ()
        return tuple(row for row in view.groups[0].rows if isinstance(row, BackupRunRow))

    def automatic(self, view: presentation.JobsView) -> tuple[BackupTimerRow, ...]:
        group = next(group for group in view.groups if group.key == "automatic")
        return tuple(row for row in group.rows if isinstance(row, BackupTimerRow))

    def test_each_result_class_has_its_plain_result(self) -> None:
        expected = {
            "succeeded": "Finished",
            "partial": "Partly saved (some files unreadable)",
            "lock_busy": "Skipped because the repository was busy",
            "failed": "Failed: ",
            "refused": "Failed: ",
            "": "Could not confirm",
        }
        for result_class, sentence in expected.items():
            with self.subTest(result_class=result_class):
                view = self.view(run(result_class=result_class, at=self.now, reason="backup_dump"))
                row = self.recent(view)[0]
                if sentence.endswith(": "):
                    self.assertTrue(row.summary.startswith(sentence), row.summary)
                    self.assertIn("database dump failed", row.summary)
                else:
                    self.assertEqual(row.summary, sentence)
                self.assertEqual(row.result_class, result_class)

    def test_an_offsite_failure_keeps_the_onsite_finding_and_the_section_sentence(self) -> None:
        view = self.view(run(result_class="succeeded", offsite="failed", at=self.now))
        row = self.recent(view)[0]
        self.assertEqual(row.summary, "Finished")
        self.assertEqual(
            [label for label, _ in row.findings], ["On this server", "Offsite storage"]
        )
        self.assertIn("Saved", row.findings[0][1])
        self.assertIn("Copy failed", row.findings[1][1])
        self.assertTrue(row.needs_attention)
        self.assertIn("Saved here, offsite copy failed.", row.attention_sentence)
        attention = self.attention(view)
        self.assertEqual(attention[0].attention_sentence, row.attention_sentence)

    def test_a_lock_skip_is_never_shown_as_a_backup(self) -> None:
        view = self.view(run(result_class="lock_busy", at=self.now))
        row = self.recent(view)[0]
        self.assertEqual(row.summary, "Skipped because the repository was busy")
        self.assertNotIn("Finished", row.summary)
        self.assertIn(row, self.attention(view))

    def test_cleanup_counts_are_separate_onsite_and_offsite_findings(self) -> None:
        view = self.view(
            run(
                kind="cleanup",
                location="onsite",
                at=self.now,
                onsite=(2, 1, 3, 4),
                offsite_counts=(0, 0, 0, 0),
            )
        )
        row = self.recent(view)[0]
        self.assertEqual(row.work_type, CLEANUP)
        self.assertIn("Deleted 2, kept 1, skipped 3, failed 4", row.findings[0][1])
        self.assertIn("Deleted 0, kept 0, skipped 0, failed 0", row.findings[1][1])

    def test_a_missing_result_line_is_could_not_confirm_and_needs_attention(self) -> None:
        view = self.view(run(result_class="", at=self.now))
        row = self.recent(view)[0]
        self.assertEqual(row.summary, "Could not confirm")
        self.assertIn(row, self.attention(view))
        self.assertIn("kept no result line", row.attention_sentence)

    def test_timers_are_on_or_off_with_only_systemds_next_elapse(self) -> None:
        next_elapse = int((self.now + timedelta(hours=4)).timestamp() * 1_000_000)
        view = self.view(
            timers=(
                timer(work="backup", on=True, next_elapse_us=next_elapse),
                timer(work="check", location="onsite", on=False, next_elapse_us=0),
            )
        )
        rows = self.automatic(view)
        backup_row = next(row for row in rows if row.work_type == BACKUP_SCHEDULE)
        check_row = next(row for row in rows if row.work_type != BACKUP_SCHEDULE)
        self.assertEqual(backup_row.state, "On")
        self.assertEqual(backup_row.next_run_at, self.now + timedelta(hours=4))
        self.assertFalse(backup_row.next_run_unknown)
        self.assertEqual(check_row.state, "Off")
        self.assertFalse(check_row.next_run_unknown)
        self.assertFalse(check_row.needs_attention)

    def test_a_missing_timer_is_unknown_and_is_not_an_off_schedule(self) -> None:
        view = self.view()
        rows = self.automatic(view)
        self.assertTrue(rows)
        self.assertEqual({row.state for row in rows}, {"Not reported"})
        self.assertTrue(all(row.next_run_unknown for row in rows))

    def test_offsite_timers_are_unknown_when_storage_is_configured(self) -> None:
        view = self.view(
            offsite=OffsiteStorage(
                "s3",
                "bucket",
                "us-east-1",
                "https://s3.us-east-1.amazonaws.com",
                "barectl",
                False,
                "",
            )
        )
        rows = self.automatic(view)
        self.assertTrue(any(row.location == "offsite" for row in rows))
        self.assertEqual({row.state for row in rows if row.location == "offsite"}, {"Not reported"})

    def test_backup_rows_link_to_the_sites_backups_section(self) -> None:
        view = self.view(run(at=self.now))
        row = self.recent(view)[0]
        self.assertEqual(
            row.link_url,
            f"/servers/{self.server.pk}/sites/alpha/backups/#backups-heading",
        )
        self.assertNotIn("Run now", row.link_url)

    def test_rows_carry_the_site_and_work_type_for_the_filters(self) -> None:
        view = self.view(
            run(kind="capture", at=self.now),
            run(kind="copy", at=self.now - timedelta(minutes=1)),
        )
        rows = self.recent(view)
        self.assertEqual(
            [(row.identifier, row.work_type) for row in rows],
            [("alpha", CAPTURE), ("alpha", COPY)],
        )
        if view.filters is None:
            self.fail("No filters were built.")
        self.assertEqual(
            [option.label for option in view.filters.works if option.count],
            ["Backup", "Offsite copy"],
        )
        filtered = self.view(
            run(kind="capture", at=self.now),
            run(kind="copy", at=self.now - timedelta(minutes=1)),
            selection=Selection(work=CAPTURE),
        )
        self.assertEqual([row.work_type for row in self.recent(filtered)], [CAPTURE])

    def test_backup_rows_are_visible_without_change_permission(self) -> None:
        view = self.view(run(at=self.now), may_view_changes=False)
        self.assertFalse(view.may_view_changes)
        self.assertEqual([row.work_type for row in self.recent(view)], [CAPTURE])
        self.assertIsNone(view.filters)
        self.assertEqual(self.attention(view), ())

    def test_an_unreadable_backup_observation_keeps_its_warning_and_no_claim(self) -> None:
        view = self.view(warning="Barectl could not read this server's backups.")
        self.assertEqual(self.recent(view), ())
        self.assertEqual(
            [notice.text for notice in view.notices],
            ["Barectl could not read this server's backups."],
        )
        automatic = next(group for group in view.groups if group.key == "automatic")
        self.assertEqual(automatic.empty, "")
        self.assertNotIn("were found", automatic.empty)

    def test_no_path_repository_credential_or_dump_content_reaches_a_row(self) -> None:
        canary = "seeded-secret-value"
        view = self.view(run(at=self.now, reason=canary))
        rendered = " ".join(
            [
                *(row.summary for row in self.recent(view)),
                *(str(row.detail_lines) for row in self.recent(view)),
                *(str(row.findings) for row in self.recent(view)),
            ]
        )
        self.assertNotIn("/var/lib/barectl-backups", rendered)
        self.assertNotIn("/etc/barectl/backups", rendered)
        self.assertNotIn("/nix/store", rendered)
        self.assertNotIn("s3:", rendered)
        self.assertNotIn(canary, rendered)

    def test_a_fresh_snapshot_reconstructs_the_same_rows(self) -> None:
        view = self.view(run(at=self.now), timers=(timer(),))
        record_jobs(
            self.server,
            backups=(backup(runs=(run(at=self.now),), timers=(timer(),)),),
        )
        again = presentation.present(current(self.server), self.server, may_view_changes=True)
        self.assertEqual(
            [row.summary for row in self.recent(view)],
            [row.summary for row in self.recent(again)],
        )
        self.assertEqual(
            [row.state for row in self.automatic(view)],
            [row.state for row in self.automatic(again)],
        )
