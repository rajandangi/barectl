"""The Jobs read's groups, plain words, links and coverage (#285)."""

from datetime import timedelta
from typing import override

from django.test import TestCase
from django.utils import timezone

from automation.observation import ObservedSchedule
from automation.status import ScheduleStatus
from automation.worker_observation import ObservedWorker
from automation.worker_status import WorkerStatus
from discovery.snapshot import ObservedCache
from operations.activity_testing import record_change, record_run
from servers.models import Server

from . import presentation
from .automatic import AutomaticRow
from .filters import Selection
from .models import Coverage
from .observation import ObservedChange, ProviderCoverage
from .testing import change
from .timezones import resolve_zone


class JobsPresentationTests(TestCase):
    @override
    def setUp(self) -> None:
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        self.now = timezone.now()

    def view(
        self,
        *changes: ObservedChange,
        coverage: tuple[ProviderCoverage, ...] = (),
        schedules: tuple[ObservedSchedule, ...] = (),
        workers: tuple[ObservedWorker, ...] = (),
        cache: tuple[ObservedCache, ...] = (),
        automation_warning: str = "",
        workers_warning: str = "",
        cache_warning: str = "",
        may_view_changes: bool = True,
        full_read: bool = True,
        selection: Selection | None = None,
        zone: str | None = None,
    ) -> presentation.JobsView:
        from dataclasses import replace

        from bootstrap.standing import HostJudgment, Standing
        from discovery.fakes import COLLECTED
        from discovery.models import ObservationOutcome
        from discovery.snapshot import Observation, Snapshot

        from .observation import JobReading

        def observed[T](value: T, warning: str) -> Observation[T]:
            if warning:
                return Observation(ObservationOutcome.INACCESSIBLE, (), warning, value)
            return Observation(ObservationOutcome.OBSERVED, (), "", value)

        collected = replace(
            COLLECTED,
            components=(),
            standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
            automation=observed(schedules, automation_warning),
            workers=observed(workers, workers_warning),
            cache=observed(cache, cache_warning),
            jobs=Observation(
                ObservationOutcome.OBSERVED if full_read else ObservationOutcome.ABSENT,
                ("journalctl",),
                "",
                JobReading(
                    changes,
                    coverage or (ProviderCoverage("barectl_changes", Coverage.COMPLETE),),
                ),
            ),
        )
        snapshot = Snapshot(collected, self.now, "web.example.com")
        return presentation.present(
            snapshot,
            self.server,
            may_view_changes=may_view_changes,
            selection=selection,
            zone=resolve_zone(zone),
        )

    def change_row(self, group: presentation.JobGroup, index: int = 0) -> presentation.JobRow:
        row = group.rows[index]
        if not isinstance(row, presentation.JobRow):
            self.fail("Expected a change row.")
        return row

    def automatic_row(self, group: presentation.JobGroup, index: int = 0) -> AutomaticRow:
        row = group.rows[index]
        if not isinstance(row, AutomaticRow):
            self.fail("Expected an automatic work row.")
        return row

    def test_a_finished_change_is_named_by_its_kind_and_sites(self) -> None:
        view = self.view(
            change(
                unit="barectl-apply-" + "a" * 32 + ".service",
                kind_slug="create_http_site",
                sites=("alpha",),
                finished_at=self.now,
            )
        )
        recent = view.groups[-1]
        self.assertEqual(recent.title, "Recent results")
        (row,) = recent.rows
        self.assertEqual(row.title, "Create PHP site")
        self.assertEqual(row.sites, ("alpha",))
        self.assertEqual(row.summary, "Finished")

    def test_a_line_without_kind_or_site_names_a_generic_change(self) -> None:
        (row,) = (
            self.view(
                change(
                    unit="barectl-apply-" + "a" * 32 + ".service",
                    kind_slug="",
                    sites=(),
                    finished_at=self.now,
                )
            )
            .groups[-1]
            .rows
        )
        self.assertEqual(row.title, "A Barectl change")
        self.assertEqual(row.sites, ())

    def test_the_result_wording_is_plain_and_distinguishes_the_outcomes(self) -> None:
        cases = {
            "succeeded": "Finished",
            "partial": "Partly applied",
            "failed": "Failed",
            "timed_out": "Timed out",
            "lock_busy": "Skipped because other work held the server",
            "": "Could not confirm",
        }
        for result_class, expected in cases.items():
            with self.subTest(result_class=result_class):
                view = self.view(
                    change(
                        unit="barectl-apply-" + "a" * 32 + ".service",
                        result_class=result_class,
                        finished_at=self.now,
                    )
                )
                self.assertEqual(view.groups[-1].rows[0].summary, expected)

    def test_a_refusal_names_its_plain_reason(self) -> None:
        (row,) = (
            self.view(
                change(
                    unit="barectl-apply-" + "a" * 32 + ".service",
                    result_class="refused",
                    reason="unsafe_lock",
                    finished_at=self.now,
                )
            )
            .groups[-1]
            .rows
        )
        self.assertTrue(row.summary.startswith("Refused: "))
        self.assertIn("root-owned private directory", row.summary)

    def test_failed_and_unconfirmed_runs_need_attention(self) -> None:
        view = self.view(
            change(
                unit="barectl-apply-" + "a" * 32 + ".service",
                result_class="failed",
                finished_at=self.now,
            ),
            change(
                unit="barectl-apply-" + "b" * 32 + ".service",
                result_class="",
                finished_at=self.now,
            ),
        )
        attention = view.groups[0]
        self.assertEqual(attention.title, "Needs attention")
        self.assertEqual(len(attention.rows), 2)
        self.assertEqual(attention.rows[0].summary, "Failed")

    def test_a_recorded_run_links_only_when_unit_and_invocation_match(self) -> None:
        units = "barectl-apply-" + "a" * 32 + ".service"
        invocation = "1" * 32
        run = record_run(record_change(self.server, kind_slug="create_http_site"))
        type(run).objects.filter(pk=run.pk).update(unit_name=units, invocation_id=invocation)
        linked = self.change_row(
            self.view(
                change(
                    unit=units,
                    invocation=invocation,
                    kind_slug="create_http_site",
                    sites=("alpha",),
                    finished_at=self.now,
                )
            ).groups[-1]
        )
        self.assertEqual(linked.run_url, f"/runs/{run.pk}/")
        self.assertFalse(linked.other_controller)

        other = self.change_row(
            self.view(
                change(
                    unit=units,
                    invocation="2" * 32,
                    kind_slug="create_http_site",
                    finished_at=self.now,
                )
            ).groups[-1]
        )
        self.assertEqual(other.run_url, "")
        self.assertTrue(other.other_controller)

    def test_running_rows_are_running_when_checked(self) -> None:
        view = self.view(
            change(
                unit="barectl-apply-" + "a" * 32 + ".service",
                running=True,
                started_at=self.now - timedelta(minutes=2),
            )
        )
        self.assertEqual(view.groups[0].rows, ())
        self.assertEqual(len(view.groups[1].rows), 1)
        self.assertEqual(
            view.groups[1].rows[0].summary, "Running when the server was last checked."
        )

    def test_an_empty_read_does_not_claim_that_nothing_ran(self) -> None:
        view = self.view(
            coverage=(
                ProviderCoverage(
                    "barectl_changes",
                    Coverage.NO_EVIDENCE,
                    "The server has no available Barectl change results.",
                ),
            )
        )
        self.assertEqual(view.groups[-1].rows, ())
        self.assertIn("No available Barectl change results.", view.groups[-1].empty)
        self.assertIn("no available", view.notices[0].text)

    def test_coverage_notices_name_denial_truncation_and_the_oldest_time(self) -> None:
        view = self.view(
            coverage=(
                ProviderCoverage(
                    "barectl_changes",
                    Coverage.TRUNCATED,
                    "The server keeps more finished changes than Barectl reads at once.",
                    self.now - timedelta(days=10),
                ),
            )
        )
        self.assertEqual(
            view.notices[0].text,
            "The server keeps more finished changes than Barectl reads at once.",
        )
        oldest = view.notices[1].oldest_at
        if oldest is None:
            self.fail("The notice kept the oldest held time.")
        self.assertEqual(oldest.date(), (self.now - timedelta(days=10)).date())

    def test_without_change_permission_no_change_rows_or_counts_are_exposed(self) -> None:
        view = self.view(
            change(
                unit="barectl-apply-" + "a" * 32 + ".service",
                finished_at=self.now,
            ),
            may_view_changes=False,
        )
        self.assertFalse(view.may_view_changes)
        self.assertEqual([group.key for group in view.groups], ["automatic"])
        self.assertEqual(view.groups[0].rows, ())
        self.assertEqual(view.notices, ())
        self.assertIsNone(view.filters)

    def test_without_change_permission_automatic_work_is_still_shown(self) -> None:
        from .testing import scheduled

        view = self.view(
            change(
                unit="barectl-apply-" + "a" * 32 + ".service",
                finished_at=self.now,
            ),
            schedules=(scheduled(),),
            may_view_changes=False,
        )
        self.assertEqual([group.key for group in view.groups], ["automatic"])
        row = self.automatic_row(view.groups[0])
        self.assertEqual(row.state, "On, the last run succeeded")
        self.assertEqual(row.identifier, "alpha")
        self.assertEqual([group for group in view.groups if group.key == "recent"], [])

    def test_automatic_work_is_the_third_group_and_keeps_phase_c_wording(self) -> None:
        from .testing import scheduled

        view = self.view(schedules=(scheduled(),))
        self.assertEqual(
            [group.key for group in view.groups],
            ["attention", "running", "automatic", "recent"],
        )
        automatic = view.groups[2]
        self.assertEqual(automatic.title, "Automatic work")
        row = self.automatic_row(automatic)
        self.assertEqual(row.identifier, "alpha")
        self.assertEqual(row.work_type, "scheduled_task")
        self.assertEqual(row.state, "On, the last run succeeded")
        self.assertEqual(
            row.link_url, f"/servers/{self.server.pk}/sites/alpha/settings/#scheduled-tasks"
        )

    def test_a_crash_looping_worker_is_in_needs_attention_with_the_overview_sentence(
        self,
    ) -> None:
        from .testing import worker

        view = self.view(workers=(worker(status=WorkerStatus.STOPPED_AFTER_CRASHES),))
        attention = view.groups[0]
        row = self.automatic_row(attention)
        self.assertTrue(row.needs_attention)
        self.assertEqual(row.summary, "Queue workers for alpha stopped after repeated crashes.")
        automatic = next(group for group in view.groups if group.key == "automatic")
        self.assertEqual(self.automatic_row(automatic).state, "Stopped after repeated crashes")

    def test_a_deliberately_off_timer_is_not_flagged(self) -> None:
        from .testing import scheduled

        view = self.view(schedules=(scheduled(status=ScheduleStatus.OFF),))
        self.assertEqual(view.groups[0].rows, ())
        row = self.automatic_row(view.groups[2])
        self.assertEqual(row.state, "Off")
        self.assertFalse(row.needs_attention)

    def test_a_missing_next_elapse_is_unknown(self) -> None:
        from .testing import scheduled

        view = self.view(schedules=(scheduled(next_elapse_us=0),))
        row = self.automatic_row(view.groups[2])
        self.assertIsNone(row.next_run_at)
        self.assertTrue(row.next_run_unknown)

    def test_an_unreadable_provider_warns_and_never_claims_there_is_no_work(self) -> None:
        view = self.view(automation_warning="The scheduled tasks could not be read.")
        self.assertEqual(view.groups[0].rows, ())
        self.assertEqual(view.groups[2].rows, ())
        self.assertEqual(
            [notice.text for notice in view.notices],
            ["The scheduled tasks could not be read."],
        )
        self.assertEqual(view.automatic_empty, "")

    def test_a_partial_check_does_not_claim_there_is_no_automatic_work(self) -> None:
        view = self.view(full_read=False)
        self.assertEqual([group.key for group in view.groups], ["automatic"])
        automatic = view.groups[0]
        self.assertEqual(automatic.rows, ())
        self.assertEqual(automatic.empty, presentation.NOT_READ)
        self.assertNotIn("were found", automatic.empty)
        self.assertIn("No Barectl change observations", view.empty)

    def test_a_server_off_the_target_stack_gets_one_sentence_instead_of_rows(self) -> None:
        from dataclasses import replace

        from bootstrap.standing import HostJudgment, Standing
        from discovery.fakes import COLLECTED
        from discovery.snapshot import Snapshot

        collected = replace(
            COLLECTED, standing=HostJudgment(Standing.NOT_MANAGEABLE, ("Other stack.",), (), ())
        )
        view = presentation.present(
            Snapshot(collected, self.now, "web.example.com"),
            self.server,
            may_view_changes=True,
        )
        self.assertFalse(view.target_stack)
        self.assertEqual(view.groups, ())

    def test_range_and_filters_narrow_recent_results_only(self) -> None:
        old = self.now - timedelta(days=20)
        view = self.view(
            change(
                unit="barectl-apply-" + "a" * 32 + ".service",
                sites=("alpha",),
                result_class="failed",
                finished_at=self.now,
            ),
            change(
                unit="barectl-apply-" + "b" * 32 + ".service",
                sites=("beta",),
                result_class="failed",
                finished_at=self.now,
            ),
            change(
                unit="barectl-apply-" + "c" * 32 + ".service",
                sites=("beta",),
                finished_at=self.now,
            ),
            change(
                unit="barectl-apply-" + "d" * 32 + ".service",
                sites=("alpha",),
                running=True,
                started_at=self.now,
            ),
            change(
                unit="barectl-apply-" + "e" * 32 + ".service",
                sites=("alpha",),
                finished_at=old,
            ),
            selection=Selection.parse({"site": "beta"}),
        )
        attention, running, _, recent = view.groups
        self.assertEqual(len(attention.rows), 2)
        self.assertEqual(len(running.rows), 1)
        self.assertEqual([row.sites for row in recent.rows], [("beta",), ("beta",)])
        self.assertEqual(view.filters.shown if view.filters else None, 2)

    def test_recent_results_are_newest_first(self) -> None:
        view = self.view(
            change(
                unit="barectl-apply-" + "a" * 32 + ".service",
                finished_at=self.now - timedelta(hours=2),
            ),
            change(
                unit="barectl-apply-" + "b" * 32 + ".service",
                finished_at=self.now,
            ),
            change(
                unit="barectl-apply-" + "c" * 32 + ".service",
                finished_at=self.now - timedelta(hours=1),
            ),
        )
        recent = view.groups[-1]
        rows = [self.change_row(recent, index) for index in range(len(recent.rows))]
        self.assertEqual(
            [row.finished_at for row in rows],
            [self.now, self.now - timedelta(hours=1), self.now - timedelta(hours=2)],
        )

    def test_a_row_without_a_usable_time_is_counted_in_a_notice(self) -> None:
        view = self.view(
            change(unit="barectl-apply-" + "a" * 32 + ".service", finished_at=self.now),
            change(unit="barectl-apply-" + "b" * 32 + ".service"),
            change(unit="barectl-apply-" + "c" * 32 + ".service"),
        )
        self.assertEqual(len(view.groups[-1].rows), 1)
        self.assertIn("2 results have no usable time", "\n".join(n.text for n in view.notices))

    def test_one_untimed_row_is_worded_in_the_singular(self) -> None:
        view = self.view(change(unit="barectl-apply-" + "a" * 32 + ".service"))
        self.assertIn("1 result has no usable time", "\n".join(n.text for n in view.notices))

    def test_a_filtered_empty_list_says_no_available_results_match(self) -> None:
        view = self.view(
            change(
                unit="barectl-apply-" + "a" * 32 + ".service",
                sites=("beta",),
                finished_at=self.now,
            ),
            selection=Selection.parse({"site": "alpha"}),
        )
        recent = view.groups[-1]
        self.assertEqual(recent.rows, ())
        self.assertIn("No available Barectl change results match", recent.empty)
        self.assertNotIn("nothing ran", recent.empty.lower())

    def test_the_view_names_the_selected_zone_and_its_filter_choices(self) -> None:
        view = self.view(
            change(
                unit="barectl-apply-" + "a" * 32 + ".service",
                sites=("alpha",),
                finished_at=self.now,
            ),
            selection=Selection.parse({"range": "30d", "site": "alpha"}),
            zone="Asia/Tokyo",
        )
        self.assertEqual(view.zone.label, "Asia/Tokyo")
        self.assertEqual(
            [option.value for option in view.filters.ranges if option.selected]
            if view.filters
            else [],
            ["30d"],
        )
