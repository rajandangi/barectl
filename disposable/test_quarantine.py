import datetime

from django.test import SimpleTestCase

from . import quarantine


class MarkerTests(SimpleTestCase):
    def test_records_the_issue_owner_and_date(self) -> None:
        @quarantine.quarantine(329, owner="rajandangi", since="2026-10-13")
        class Marked(SimpleTestCase):
            def test_ok(self) -> None:
                pass

        marker = quarantine.marker_of(Marked)
        if marker is None:
            self.fail("the decorator did not record a marker")
        self.assertEqual(marker.issue, 329)
        self.assertEqual(marker.owner, "rajandangi")
        self.assertEqual(marker.since, datetime.date(2026, 10, 13))
        self.assertEqual(marker.age(datetime.date(2026, 10, 20)), datetime.timedelta(days=7))

    def test_an_unmarked_test_has_no_marker(self) -> None:
        class Plain(SimpleTestCase):
            def test_ok(self) -> None:
                pass

        self.assertIsNone(quarantine.marker_of(Plain))


class QuarantineMetaTests(SimpleTestCase):
    def test_every_marker_names_an_open_flaky_issue_within_fourteen_days(self) -> None:
        from django.test.runner import DiscoverRunner

        from disposable.scenarios import setup_django

        setup_django()
        suite = DiscoverRunner(verbosity=0).build_suite(None)
        today = datetime.datetime.now(datetime.UTC).date()
        for test_id, marker in quarantine.marked_tests(suite):
            with self.subTest(test=test_id):
                self.assertTrue(marker.owner, f"{test_id} has no owner")
                self.assertLessEqual(
                    marker.age(today),
                    quarantine.LIMIT,
                    f"{test_id} has been quarantined for over 14 days; fix or delete it",
                )
                self.assertTrue(
                    quarantine.issue_is_open_flaky(marker.issue, repository="rajandangi/barectl"),
                    f"{test_id}: issue {marker.issue} is not open and labelled flaky",
                )
