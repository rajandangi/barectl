"""Recent results ranges, filters, counts and ordering (#291)."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from django.test import SimpleTestCase

from .filters import (
    DEFAULT_RANGE,
    Selection,
    filter_recent,
)
from .results import RESULT_CHOICES


@dataclass(frozen=True)
class Row:
    when: datetime | None = None
    sites: tuple[str, ...] = ("alpha",)
    work_type: str = "create_http_site"
    result_class: str = "succeeded"
    running: bool = False


NOW = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)
LONDON = ZoneInfo("Europe/London")


class SelectionTests(SimpleTestCase):
    def test_no_filter_is_applied_by_default(self) -> None:
        selection = Selection.parse({})
        self.assertEqual(selection.range, DEFAULT_RANGE)
        self.assertEqual(selection.range, "7d")
        self.assertFalse(selection.active)
        self.assertEqual((selection.site, selection.work, selection.result), ("", "", ""))

    def test_unknown_range_filters_and_sites_are_ignored(self) -> None:
        selection = Selection.parse(
            {"range": "90d", "site": "Not A Site", "work": "not_a_kind", "result": "maybe"}
        )
        self.assertEqual(selection.range, DEFAULT_RANGE)
        self.assertEqual(selection.site, "")
        self.assertEqual(selection.work, "")
        self.assertEqual(selection.result, "")
        self.assertFalse(selection.active)

    def test_every_established_choice_is_kept(self) -> None:
        selection = Selection.parse(
            {"range": "today", "site": "alpha", "work": "create_http_site", "result": "failed"}
        )
        self.assertEqual(
            (selection.range, selection.site, selection.work, selection.result),
            ("today", "alpha", "create_http_site", "failed"),
        )
        self.assertTrue(selection.active)


class RangeTests(SimpleTestCase):
    def test_today_starts_at_local_midnight(self) -> None:
        rows = (
            Row(when=datetime(2026, 11, 2, 23, 30, tzinfo=UTC)),
            Row(when=datetime(2026, 11, 3, 0, 0, tzinfo=UTC)),
        )
        filtered = filter_recent(rows, Selection.parse({"range": "today"}), now=NOW, zone=LONDON)
        self.assertEqual(
            [row.when for row in filtered.rows], [datetime(2026, 11, 3, 0, 0, tzinfo=UTC)]
        )

    def test_the_default_range_includes_today_and_the_previous_six_calendar_days(self) -> None:
        rows = (
            Row(when=datetime(2026, 10, 27, 23, 59, tzinfo=UTC)),
            Row(when=datetime(2026, 10, 28, 0, 0, tzinfo=UTC)),
        )
        filtered = filter_recent(rows, Selection.parse({}), now=NOW, zone=LONDON)
        self.assertEqual(len(filtered.rows), 1)
        self.assertEqual(filtered.rows[0].when, datetime(2026, 10, 28, 0, 0, tzinfo=UTC))

    def test_past_thirty_days_include_today_and_the_previous_twenty_nine_calendar_days(
        self,
    ) -> None:
        rows = (
            Row(when=datetime(2026, 10, 4, 22, 59, tzinfo=UTC)),
            Row(when=datetime(2026, 10, 4, 23, 0, tzinfo=UTC)),
        )
        filtered = filter_recent(rows, Selection.parse({"range": "30d"}), now=NOW, zone=LONDON)
        self.assertEqual(len(filtered.rows), 1)
        self.assertEqual(filtered.rows[0].when, datetime(2026, 10, 4, 23, 0, tzinfo=UTC))

    def test_the_range_uses_the_run_time_not_the_check_time(self) -> None:
        filtered = filter_recent(
            (Row(when=NOW - timedelta(days=8)),), Selection.parse({}), now=NOW, zone=LONDON
        )
        self.assertEqual(filtered.rows, ())


class FilterTests(SimpleTestCase):
    def test_site_matches_an_established_affected_site(self) -> None:
        rows = (
            Row(when=NOW, sites=("alpha", "beta")),
            Row(when=NOW, sites=("beta",)),
            Row(when=NOW, sites=()),
        )
        filtered = filter_recent(rows, Selection.parse({"site": "alpha"}), now=NOW, zone=LONDON)
        self.assertEqual(len(filtered.rows), 1)
        self.assertEqual(filtered.rows[0].sites, ("alpha", "beta"))

    def test_work_type_matches_the_established_kind_slug_only(self) -> None:
        rows = (
            Row(when=NOW, work_type="create_http_site"),
            Row(when=NOW, work_type="set_default_php"),
            Row(when=NOW, work_type=""),
        )
        filtered = filter_recent(
            rows, Selection.parse({"work": "set_default_php"}), now=NOW, zone=LONDON
        )
        self.assertEqual(len(filtered.rows), 1)
        self.assertEqual(filtered.rows[0].work_type, "set_default_php")

    def test_each_result_choice_matches_its_result_class(self) -> None:
        rows = tuple(
            Row(when=NOW, result_class=result_class) for _, _, result_class in RESULT_CHOICES
        )
        for key, _, result_class in RESULT_CHOICES:
            with self.subTest(key=key):
                filtered = filter_recent(
                    rows, Selection.parse({"result": key}), now=NOW, zone=LONDON
                )
                self.assertEqual([row.result_class for row in filtered.rows], [result_class])

    def test_an_unconfirmed_run_matches_could_not_confirm(self) -> None:
        rows = (Row(when=NOW, result_class=""),)
        filtered = filter_recent(
            rows, Selection.parse({"result": "unconfirmed"}), now=NOW, zone=LONDON
        )
        self.assertEqual(len(filtered.rows), 1)

    def test_filters_combine(self) -> None:
        rows = (
            Row(when=NOW, sites=("alpha",), work_type="create_http_site", result_class="failed"),
            Row(when=NOW, sites=("alpha",), work_type="create_http_site", result_class="succeeded"),
            Row(when=NOW, sites=("beta",), work_type="create_http_site", result_class="failed"),
        )
        filtered = filter_recent(
            rows,
            Selection.parse({"site": "alpha", "work": "create_http_site", "result": "failed"}),
            now=NOW,
            zone=LONDON,
        )
        self.assertEqual(len(filtered.rows), 1)
        self.assertEqual(filtered.rows[0].result_class, "failed")


class UntimedAndOrderTests(SimpleTestCase):
    def test_rows_without_a_usable_time_are_excluded_and_counted(self) -> None:
        rows = (
            Row(when=NOW),
            Row(when=None),
            Row(when=None, running=True),
        )
        filtered = filter_recent(rows, Selection.parse({}), now=NOW, zone=LONDON)
        self.assertEqual(len(filtered.rows), 1)
        self.assertEqual(filtered.untimed, 1)

    def test_recent_results_are_newest_first(self) -> None:
        rows = (
            Row(when=NOW - timedelta(hours=3)),
            Row(when=NOW),
            Row(when=NOW - timedelta(hours=1)),
        )
        filtered = filter_recent(rows, Selection.parse({}), now=NOW, zone=LONDON)
        self.assertEqual(
            [row.when for row in filtered.rows],
            [NOW, NOW - timedelta(hours=1), NOW - timedelta(hours=3)],
        )


class OptionTests(SimpleTestCase):
    def test_site_and_work_options_come_only_from_visible_established_rows(self) -> None:
        rows = (
            Row(when=NOW, sites=("alpha", "beta"), work_type="create_http_site"),
            Row(when=NOW, sites=("beta",), work_type="set_default_php"),
            Row(when=NOW, sites=(), work_type=""),
        )
        options = filter_recent(rows, Selection.parse({}), now=NOW, zone=LONDON).filters
        self.assertEqual(
            [(option.value, option.label, option.count) for option in options.sites],
            [("alpha", "alpha", 1), ("beta", "beta", 2)],
        )
        self.assertEqual(
            [(option.value, option.label, option.count) for option in options.works],
            [
                ("create_http_site", "Create PHP site", 1),
                ("set_default_php", "Set default PHP", 1),
            ],
        )

    def test_result_options_are_the_seven_plain_choices_with_counts(self) -> None:
        rows = (
            Row(when=NOW, result_class="succeeded"),
            Row(when=NOW, result_class="succeeded"),
            Row(when=NOW, result_class=""),
        )
        options = filter_recent(rows, Selection.parse({}), now=NOW, zone=LONDON).filters
        self.assertEqual(
            [(option.label, option.count) for option in options.results],
            [
                ("Finished", 2),
                ("Partly applied", 0),
                ("Refused", 0),
                ("Failed", 0),
                ("Timed out", 0),
                ("Skipped", 0),
                ("Could not confirm", 1),
            ],
        )

    def test_options_name_the_current_selection(self) -> None:
        selection = Selection.parse({"range": "30d", "site": "alpha", "result": "failed"})
        options = filter_recent(
            (Row(when=NOW, sites=("alpha",)),), selection, now=NOW, zone=LONDON
        ).filters
        self.assertEqual([option.value for option in options.ranges if option.selected], ["30d"])
        self.assertEqual([option.value for option in options.sites if option.selected], ["alpha"])
        self.assertEqual(
            [option.value for option in options.results if option.selected], ["failed"]
        )
        self.assertEqual(options.shown, 0)
