"""The Jobs read's groups, plain words, links and coverage (#285)."""

from datetime import timedelta
from typing import override

from django.test import TestCase
from django.utils import timezone

from operations.activity_testing import record_change, record_run
from servers.models import Server

from . import presentation
from .models import Coverage
from .observation import ObservedChange, ProviderCoverage
from .testing import change


class JobsPresentationTests(TestCase):
    @override
    def setUp(self) -> None:
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        self.now = timezone.now()

    def view(
        self, *changes: ObservedChange, coverage: tuple[ProviderCoverage, ...] = ()
    ) -> presentation.JobsView:
        from dataclasses import replace

        from bootstrap.standing import HostJudgment, Standing
        from discovery.fakes import COLLECTED
        from discovery.models import ObservationOutcome
        from discovery.snapshot import Observation, Snapshot

        from .observation import JobReading

        collected = replace(
            COLLECTED,
            components=(),
            standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
            jobs=Observation(
                ObservationOutcome.OBSERVED,
                ("journalctl",),
                "",
                JobReading(
                    changes,
                    coverage or (ProviderCoverage("barectl_changes", Coverage.COMPLETE),),
                ),
            ),
        )
        snapshot = Snapshot(collected, self.now, "web.example.com")
        return presentation.present(snapshot, self.server, may_view_changes=True)

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
            self.view(change(unit="barectl-apply-" + "a" * 32 + ".service", kind_slug="", sites=()))
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
        linked = (
            self.view(
                change(
                    unit=units,
                    invocation=invocation,
                    kind_slug="create_http_site",
                    sites=("alpha",),
                    finished_at=self.now,
                )
            )
            .groups[-1]
            .rows[0]
        )
        self.assertEqual(linked.run_url, f"/runs/{run.pk}/")
        self.assertFalse(linked.other_controller)

        other = (
            self.view(
                change(
                    unit=units,
                    invocation="2" * 32,
                    kind_slug="create_http_site",
                    finished_at=self.now,
                )
            )
            .groups[-1]
            .rows[0]
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

    def test_without_change_permission_no_rows_or_counts_are_exposed(self) -> None:
        from dataclasses import replace

        from bootstrap.standing import HostJudgment, Standing
        from discovery.fakes import COLLECTED
        from discovery.models import ObservationOutcome
        from discovery.snapshot import Observation, Snapshot

        from .observation import JobReading

        collected = replace(
            COLLECTED,
            standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
            jobs=Observation(
                ObservationOutcome.OBSERVED,
                (),
                "",
                JobReading(
                    (
                        change(
                            unit="barectl-apply-" + "a" * 32 + ".service",
                            finished_at=self.now,
                        ),
                    ),
                    (ProviderCoverage("barectl_changes", Coverage.COMPLETE),),
                ),
            ),
        )
        view = presentation.present(
            Snapshot(collected, self.now, "web.example.com"),
            self.server,
            may_view_changes=False,
        )
        self.assertFalse(view.may_view_changes)
        self.assertEqual(view.groups, ())
        self.assertEqual(view.notices, ())

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
